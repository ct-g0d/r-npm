//! Extreme borderline cryptographic, attestation, and registry HTTP client stress tests.
//! Covers Sigstore / X.509 / Rekor / DSSE edge cases, multi-signature envelopes,
//! forged PURL subjects, key expiry, redirect auth stripping, Retry-After, and circuit breaker.

use data_encoding::{BASE64, HEXLOWER};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

use rnpm_registry::asn1::{
    create_test_x509_certificate, decode_oid, der_tlv, encode_oid, parse_der_time, parse_spki,
    parse_x509_certificate, read_tlv, TAG_BIT_STRING, TAG_GENERALIZED_TIME, TAG_OID, TAG_SEQUENCE,
    TAG_UTC_TIME,
};
use rnpm_registry::circuit_breaker::{CircuitBreaker, CircuitBreakerState};
use rnpm_registry::client::{parse_http_date_to_seconds_from_now, parse_retry_after_str};
use rnpm_registry::metadata::DistSignature;
use rnpm_registry::provenance::{
    assemble_sigstore_bundle, decode_base64, normalize_repository_url, sign_dsse_envelope,
    validate_dist_signatures, AttestationItem, AttestationResponse, DsseEnvelope, DsseSignature,
    EphemeralSigner, InTotoStatement, InTotoSubject, LogId, ProvenancePolicy, ProvenanceVerifier,
    PublicKeyHint, SigstoreBundle, SlsaBuilder, SlsaConfigSource, SlsaInvocation, SlsaPredicate,
    TlogEntry, VerificationMaterial, REKOR_DEFAULT_LOG_ID, TEST_MOCK_CA_PRIV_PKCS8_B64,
    TEST_MOCK_REKOR_PRIV_PKCS8_B64,
};
use rnpm_registry::{RegistryClient, RegistryClientConfig, RegistryError};

// ============================================================================
// TEST FIXTURES & HELPERS
// ============================================================================

fn make_test_spki(algo_oid: &str, curve_oid: Option<&str>, public_key_point: &[u8]) -> Vec<u8> {
    let mut algo_parts = vec![der_tlv(TAG_OID, &encode_oid(algo_oid))];
    if let Some(c) = curve_oid {
        algo_parts.push(der_tlv(TAG_OID, &encode_oid(c)));
    }
    let algo_seq = der_tlv(TAG_SEQUENCE, &algo_parts.concat());
    let mut pk_bitstring = vec![0x00]; // 0 unused bits
    pk_bitstring.extend_from_slice(public_key_point);
    der_tlv(
        TAG_SEQUENCE,
        &[algo_seq, der_tlv(TAG_BIT_STRING, &pk_bitstring)].concat(),
    )
}

fn make_test_bundle_custom(
    subject_name: &str,
    sha512_hex: &str,
    repo_uri: &str,
    commit_sha: &str,
    tlog_time: i64,
    has_inclusion_promise: bool,
) -> (SigstoreBundle, Vec<u8>, EphemeralSigner) {
    let mut digest = HashMap::new();
    digest.insert("sha512".to_string(), sha512_hex.to_string());

    let mut cs_digest = HashMap::new();
    cs_digest.insert("sha1".to_string(), commit_sha.to_string());

    let statement = InTotoStatement {
        statement_type: "https://in-toto.io/Statement/v0.1".into(),
        subject: vec![InTotoSubject {
            name: subject_name.to_string(),
            digest,
        }],
        predicate_type: "https://slsa.dev/provenance/v0.2".into(),
        predicate: SlsaPredicate {
            builder: Some(SlsaBuilder {
                id: "https://github.com/actions/runner/v2".into(),
            }),
            build_type: Some("https://actions.github.com/Workflow@v1".into()),
            invocation: Some(SlsaInvocation {
                config_source: Some(SlsaConfigSource {
                    uri: Some(repo_uri.to_string()),
                    digest: cs_digest,
                    entry_point: Some(".github/workflows/deploy.yml".into()),
                }),
                parameters: None,
                environment: None,
            }),
            recipe: None,
            materials: Vec::new(),
            build_definition: None,
            run_details: None,
        },
    };

    let signer = EphemeralSigner::new().unwrap();
    let envelope = sign_dsse_envelope(&statement, &signer).unwrap();

    let repo_norm = normalize_repository_url(repo_uri);
    let fulcio_exts = [
        (
            rnpm_registry::asn1::OID_FULCIO_ISSUER,
            "https://token.actions.githubusercontent.com",
        ),
        (
            rnpm_registry::asn1::OID_FULCIO_GITHUB_WORKFLOW_REPOSITORY,
            repo_norm.as_str(),
        ),
        (rnpm_registry::asn1::OID_FULCIO_RUN_COMMIT_SHA, commit_sha),
    ];

    let rng = ring::rand::SystemRandom::new();
    let ca_priv = decode_base64(TEST_MOCK_CA_PRIV_PKCS8_B64).unwrap();
    let ca_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &ca_priv,
        &rng,
    )
    .unwrap();

    let cert_der = create_test_x509_certificate(
        "test-signer",
        "sigstore",
        signer.public_key_uncompressed(),
        Some("https://github.com/actions/runner"),
        &fulcio_exts,
        tlog_time - 60,
        tlog_time + 600,
        &|tbs| ca_key_pair.sign(&rng, tbs).unwrap().as_ref().to_vec(),
    );

    let payload_bytes = decode_base64(&envelope.payload).unwrap();
    let payload_hash_hex = HEXLOWER.encode(&Sha256::digest(&payload_bytes));
    let leaf_b64 = BASE64.encode(&cert_der);
    let canonical_body_json = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "payloadHash": {
                "algorithm": "sha256",
                "value": payload_hash_hex,
            },
            "signatures": [
                {
                    "signature": envelope.signatures[0].sig,
                    "verifier": leaf_b64,
                }
            ]
        }
    });
    let canonical_body_str = serde_json::to_string(&canonical_body_json).unwrap();
    let body_b64 = BASE64.encode(canonical_body_str.as_bytes());

    let inclusion_promise = if has_inclusion_promise {
        let rekor_priv = decode_base64(TEST_MOCK_REKOR_PRIV_PKCS8_B64).unwrap();
        let rekor_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rekor_priv,
            &rng,
        )
        .unwrap();

        let set_canonical_json = format!(
            r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
            body_b64, tlog_time, REKOR_DEFAULT_LOG_ID, 12345
        );
        let rekor_sig = rekor_key_pair
            .sign(&rng, set_canonical_json.as_bytes())
            .unwrap();

        Some(rnpm_registry::provenance::InclusionPromise {
            signed_entry_timestamp: BASE64.encode(rekor_sig.as_ref()),
        })
    } else {
        None
    };

    let tlog_entry = TlogEntry {
        log_index: 12345,
        log_id: LogId {
            key_id: REKOR_DEFAULT_LOG_ID.into(),
        },
        integrated_time: tlog_time,
        inclusion_promise,
        inclusion_proof: None,
        canonicalized_body: Some(body_b64),
    };

    let bundle = assemble_sigstore_bundle(envelope, &cert_der, tlog_entry);
    (bundle, cert_der, signer)
}

struct MockHttpServer {
    addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl MockHttpServer {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&str, usize) -> (u16, Vec<(&'static str, String)>, Vec<u8>) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let request_counter = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(handler);
        let req_cnt = request_counter.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            let h = handler.clone();
                            let cnt = req_cnt.clone();
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let n = stream.read(&mut buf).await.unwrap_or(0);
                                if n > 0 {
                                    let req_idx = cnt.fetch_add(1, Ordering::SeqCst);
                                    let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let (status, headers, body) = h(&req_str, req_idx);

                                    let status_text = match status {
                                        200 => "OK",
                                        301 => "Moved Permanently",
                                        302 => "Found",
                                        429 => "Too Many Requests",
                                        503 => "Service Unavailable",
                                        _ => "Response",
                                    };

                                    let mut response = format!(
                                        "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\nConnection: close\r\n",
                                        body.len()
                                    );
                                    for (k, v) in headers {
                                        response.push_str(&format!("{k}: {v}\r\n"));
                                    }
                                    response.push_str("\r\n");

                                    let _ = stream.write_all(response.as_bytes()).await;
                                    let _ = stream.write_all(&body).await;
                                    let _ = stream.flush().await;
                                }
                            });
                        }
                    }
                }
            }
        });

        Self {
            addr,
            shutdown: shutdown_tx,
        }
    }

    fn url(&self) -> Url {
        Url::parse(&format!("http://{}/", self.addr)).unwrap()
    }

    fn stop(self) {
        let _ = self.shutdown.send(());
    }
}

// ============================================================================
// 1. ASN.1 / DER / SPKI / X.509 CRYPTOGRAPHIC TORTURE
// ============================================================================

#[test]
fn test_asn1_der_empty_and_truncated_lengths() {
    // Empty DER input
    let err = read_tlv(&[]).unwrap_err();
    assert!(matches!(err, RegistryError::InvalidSigstoreBundle(_)));

    // Truncated at length byte
    let err = read_tlv(&[0x30]).unwrap_err();
    assert!(matches!(err, RegistryError::InvalidSigstoreBundle(_)));

    // Truncated multi-byte length
    let err = read_tlv(&[0x30, 0x82, 0x01]).unwrap_err();
    assert!(matches!(err, RegistryError::InvalidSigstoreBundle(_)));

    // Multi-byte length count = 0 (0x80 is indefinite, forbidden in DER)
    let err = read_tlv(&[0x30, 0x80]).unwrap_err();
    assert!(matches!(err, RegistryError::InvalidSigstoreBundle(_)));

    // Multi-byte length count > 4 (0x85)
    let err = read_tlv(&[0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05]).unwrap_err();
    assert!(matches!(err, RegistryError::InvalidSigstoreBundle(_)));
}

#[test]
fn test_asn1_der_non_canonical_encoding_rejected() {
    // Redundant leading zeros in multi-byte length: [0x30, 0x82, 0x00, 0x05, ...]
    let non_canonical_zero = [0x30, 0x82, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
    let err = read_tlv(&non_canonical_zero).unwrap_err();
    assert!(
        matches!(err, RegistryError::InvalidSigstoreBundle(ref msg) if msg.contains("leading zero")),
        "Expected leading zero rejection, got: {err:?}"
    );

    // Multi-byte encoding used for length < 128: [0x30, 0x81, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]
    let non_canonical_short = [0x30, 0x81, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
    let err = read_tlv(&non_canonical_short).unwrap_err();
    assert!(
        matches!(err, RegistryError::InvalidSigstoreBundle(ref msg) if msg.contains("length < 128")),
        "Expected length < 128 rejection, got: {err:?}"
    );
}

#[test]
fn test_asn1_der_element_length_exceeds_available_bytes() {
    // Declares 20 bytes payload but only 3 available
    let truncated_element = [0x30, 0x14, 0x01, 0x02, 0x03];
    let err = read_tlv(&truncated_element).unwrap_err();
    assert!(matches!(err, RegistryError::InvalidSigstoreBundle(_)));
}

#[test]
fn test_asn1_trailing_garbage_rejection() {
    let rng = ring::rand::SystemRandom::new();
    let ca_priv = decode_base64(TEST_MOCK_CA_PRIV_PKCS8_B64).unwrap();
    let ca_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &ca_priv,
        &rng,
    )
    .unwrap();
    let signer = EphemeralSigner::new().unwrap();

    let cert_der = create_test_x509_certificate(
        "test",
        "test-ca",
        signer.public_key_uncompressed(),
        None,
        &[],
        1000,
        2000,
        &|tbs| ca_key_pair.sign(&rng, tbs).unwrap().as_ref().to_vec(),
    );

    // Valid certificate parses without error
    let parsed = parse_x509_certificate(&cert_der);
    assert!(parsed.is_ok());

    // Appending trailing garbage MUST fail with InvalidSigstoreBundle
    let mut corrupted = cert_der.clone();
    corrupted.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let err = parse_x509_certificate(&corrupted).unwrap_err();
    assert!(
        matches!(err, RegistryError::InvalidSigstoreBundle(ref msg) if msg.contains("Trailing garbage")),
        "Expected trailing garbage error, got: {err:?}"
    );

    // SPKI with trailing garbage MUST also fail
    let valid_spki = signer.public_key_spki();
    assert!(parse_spki(valid_spki).is_ok());

    let mut spki_with_garbage = valid_spki.to_vec();
    spki_with_garbage.push(0x00);
    let spki_err = parse_spki(&spki_with_garbage).unwrap_err();
    assert!(
        matches!(spki_err, RegistryError::InvalidSigstoreBundle(ref msg) if msg.contains("Trailing garbage")),
        "Expected trailing garbage on SPKI, got: {spki_err:?}"
    );
}

#[test]
fn test_asn1_spki_truncated_sequence_and_empty_keys() {
    // Truncated SPKI sequence (only 1 element instead of 2)
    let spki_one_elem = der_tlv(TAG_SEQUENCE, &der_tlv(TAG_SEQUENCE, &[]));
    let err = parse_spki(&spki_one_elem).unwrap_err();
    assert!(matches!(err, RegistryError::InvalidSigstoreBundle(_)));

    // SPKI with BIT STRING containing 0 bytes of key
    let empty_pk_bitstring = der_tlv(TAG_BIT_STRING, &[0x00]); // 0 unused bits, but no bytes
    let algo_seq = der_tlv(
        TAG_SEQUENCE,
        &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
    );
    let mut spki_val = algo_seq;
    spki_val.extend_from_slice(&empty_pk_bitstring);
    let spki_empty_pk = der_tlv(TAG_SEQUENCE, &spki_val);
    let err = parse_spki(&spki_empty_pk).unwrap_err();
    assert!(matches!(err, RegistryError::InvalidSigstoreBundle(_)));

    // SPKI with invalid unused bits count (e.g. 7 unused bits)
    let invalid_unused_bits = der_tlv(TAG_BIT_STRING, &[0x07, 0xAA]);
    let mut spki_val2 = der_tlv(
        TAG_SEQUENCE,
        &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
    );
    spki_val2.extend_from_slice(&invalid_unused_bits);
    let spki_invalid_bits = der_tlv(TAG_SEQUENCE, &spki_val2);
    let err = parse_spki(&spki_invalid_bits).unwrap_err();
    assert!(matches!(err, RegistryError::InvalidSigstoreBundle(_)));
}

#[test]
fn test_asn1_time_parsing_edge_cases() {
    // Non-ASCII characters MUST be rejected cleanly without panic
    let non_ascii_utc = b"2601011200\xFF\xFEZ";
    let err = parse_der_time(TAG_UTC_TIME, non_ascii_utc).unwrap_err();
    assert!(matches!(err, RegistryError::InvalidSigstoreBundle(_)));

    // Invalid month 13
    let err_month = parse_der_time(TAG_UTC_TIME, b"261301120000Z").unwrap_err();
    assert!(
        matches!(err_month, RegistryError::InvalidSigstoreBundle(ref msg) if msg.contains("month"))
    );

    // Invalid day 32
    let err_day = parse_der_time(TAG_UTC_TIME, b"260132120000Z").unwrap_err();
    assert!(
        matches!(err_day, RegistryError::InvalidSigstoreBundle(ref msg) if msg.contains("day"))
    );

    // Invalid hour 25
    let err_hour = parse_der_time(TAG_UTC_TIME, b"260101250000Z").unwrap_err();
    assert!(
        matches!(err_hour, RegistryError::InvalidSigstoreBundle(ref msg) if msg.contains("hour"))
    );

    // Valid GeneralizedTime and UTCTime parse correctly
    let utc_secs = parse_der_time(TAG_UTC_TIME, b"260101000000Z").unwrap();
    let gen_secs = parse_der_time(TAG_GENERALIZED_TIME, b"20260101000000Z").unwrap();
    assert_eq!(utc_secs, gen_secs);
}

#[test]
fn test_asn1_oid_overflow_and_malformed_termination() {
    // Unterminated OID: last byte has continuation bit set (0x80)
    let unterminated = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x82];
    let decoded = decode_oid(&unterminated);
    assert!(decoded.is_empty(), "Malformed OID must return empty string");

    // Overflow attempt: multiple 0xFF bytes shifting beyond u64
    let overflow_oid = [
        0x2A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
    ];
    let decoded_overflow = decode_oid(&overflow_oid);
    assert!(
        decoded_overflow.is_empty(),
        "Overflowing OID must return empty string"
    );

    // Valid OID roundtrips cleanly
    let valid_oid = "1.2.840.10045.3.1.7";
    let encoded = encode_oid(valid_oid);
    let decoded_back = decode_oid(&encoded);
    assert_eq!(valid_oid, decoded_back);
}

#[test]
fn test_asn1_wrong_key_types_and_unsupported_curves() {
    // SPKI with RSA OID (1.2.840.113549.1.1.1)
    let rsa_spki = make_test_spki("1.2.840.113549.1.1.1", None, &[0x01; 64]);
    let (algo_oid, curve_oid, pk) = parse_spki(&rsa_spki).unwrap();
    assert_eq!(algo_oid, "1.2.840.113549.1.1.1");
    assert!(curve_oid.is_none());
    assert_eq!(pk.len(), 64);

    // SPKI with unsupported curve (e.g. secp256k1: 1.3.132.0.10)
    let k1_spki = make_test_spki(
        rnpm_registry::asn1::OID_EC_PUBLIC_KEY,
        Some("1.3.132.0.10"),
        &[0x04; 65],
    );
    let (algo, curve, _) = parse_spki(&k1_spki).unwrap();
    assert_eq!(algo, rnpm_registry::asn1::OID_EC_PUBLIC_KEY);
    assert_eq!(curve.as_deref(), Some("1.3.132.0.10"));
}

// ============================================================================
// 2. MULTI-SIGNATURE DSSE ENVELOPE TORTURE
// ============================================================================

#[test]
fn test_dsse_empty_signatures_rejected() {
    let empty_envelope = DsseEnvelope {
        payload_type: "application/vnd.in-toto+json".into(),
        payload: BASE64.encode(b"{}"),
        signatures: vec![],
    };

    let signer = EphemeralSigner::new().unwrap();
    let err = rnpm_registry::provenance::verify_dsse_signatures(
        &empty_envelope,
        signer.public_key_spki(),
    )
    .unwrap_err();
    assert!(matches!(err, RegistryError::InvalidSignature(_)));
}

#[test]
fn test_dsse_mixed_valid_and_invalid_signatures_succeeds() {
    let statement = InTotoStatement {
        statement_type: "https://in-toto.io/Statement/v0.1".into(),
        subject: vec![],
        predicate_type: "https://slsa.dev/provenance/v0.2".into(),
        predicate: SlsaPredicate::default(),
    };

    let signer = EphemeralSigner::new().unwrap();
    let mut envelope = sign_dsse_envelope(&statement, &signer).unwrap();
    let valid_sig = envelope.signatures[0].clone();

    // Inject empty signature, invalid base64, and wrong signature
    envelope.signatures.insert(
        0,
        DsseSignature {
            keyid: Some("bogus-1".into()),
            sig: "".into(), // empty string
        },
    );
    envelope.signatures.insert(
        1,
        DsseSignature {
            keyid: Some("bogus-2".into()),
            sig: "not-valid-base64!@#$".into(), // invalid base64
        },
    );
    envelope.signatures.push(DsseSignature {
        keyid: Some("bogus-3".into()),
        sig: BASE64.encode(&[0xAA; 64]), // cryptographically invalid signature
    });

    // Verification must find the valid signature and succeed!
    let verified = rnpm_registry::provenance::verify_dsse_signatures(
        &envelope,
        signer.public_key_spki(),
    )
    .unwrap();

    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].sig, valid_sig.sig);
}

#[test]
fn test_dsse_multiple_signatures_different_keyids_candidate_matching() {
    let statement = InTotoStatement {
        statement_type: "https://in-toto.io/Statement/v0.1".into(),
        subject: vec![InTotoSubject {
            name: "pkg:npm/foo@1.0.0".into(),
            digest: HashMap::from([("sha512".to_string(), "abc".to_string())]),
        }],
        predicate_type: "https://slsa.dev/provenance/v0.2".into(),
        predicate: SlsaPredicate::default(),
    };

    let signer1 = EphemeralSigner::new().unwrap();
    let signer2 = EphemeralSigner::new().unwrap();

    let envelope1 = sign_dsse_envelope(&statement, &signer1).unwrap();
    let envelope2 = sign_dsse_envelope(&statement, &signer2).unwrap();

    // Combine signatures with different keyids: key1 first, key2 second
    let combined_envelope = DsseEnvelope {
        payload_type: envelope1.payload_type,
        payload: envelope1.payload,
        signatures: vec![
            DsseSignature {
                keyid: Some("key-1".into()),
                sig: envelope1.signatures[0].sig.clone(),
            },
            DsseSignature {
                keyid: Some("key-2".into()),
                sig: envelope2.signatures[0].sig.clone(),
            },
        ],
    };

    // If candidate registry keys contains key-2, verifier must resolve key-2 and verify!
    let bundle = SigstoreBundle {
        media_type: Some("application/vnd.dev.sigstore.bundle+json;version=0.1".into()),
        verification_material: Some(VerificationMaterial {
            public_key: Some(PublicKeyHint {
                hint: Some("key-2".into()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        dsse_envelope: Some(combined_envelope.clone()),
    };

    let mut keys = HashMap::new();
    keys.insert("key-2".into(), signer2.public_key_spki().to_vec());

    let verifier =
        ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_registry_keys(keys.clone());
    // Package name / digest verification step will proceed because signature matched key-2
    let res = verifier.verify("foo", &bundle, None, None);
    // It should proceed past signature verification (fails on digest mismatch or succeeds)
    assert!(!matches!(res, Err(RegistryError::InvalidSignature(_))));

    // If keyid hint is missing, candidate search scans envelope keyids
    let bundle_no_hint = SigstoreBundle {
        media_type: Some("application/vnd.dev.sigstore.bundle+json;version=0.1".into()),
        verification_material: Some(VerificationMaterial {
            public_key: None,
            ..Default::default()
        }),
        dsse_envelope: Some(combined_envelope),
    };
    let res2 = verifier.verify("foo", &bundle_no_hint, None, None);
    assert!(!matches!(res2, Err(RegistryError::InvalidSignature(_))));
}

#[test]
fn test_dsse_tampered_payload_rejected() {
    let statement = InTotoStatement {
        statement_type: "https://in-toto.io/Statement/v0.1".into(),
        subject: vec![],
        predicate_type: "https://slsa.dev/provenance/v0.2".into(),
        predicate: SlsaPredicate::default(),
    };

    let signer = EphemeralSigner::new().unwrap();
    let mut envelope = sign_dsse_envelope(&statement, &signer).unwrap();

    // Tamper payload byte
    let mut payload_bytes = decode_base64(&envelope.payload).unwrap();
    payload_bytes.push(b' ');
    envelope.payload = BASE64.encode(&payload_bytes);

    let err = rnpm_registry::provenance::verify_dsse_signatures(
        &envelope,
        signer.public_key_spki(),
    )
    .unwrap_err();
    assert!(matches!(err, RegistryError::InvalidSignature(_)));
}

// ============================================================================
// 3. PURL SUBJECT FORGERY & MALFORMED ATTESTATIONS
// ============================================================================

#[test]
fn test_purl_scoped_and_unscoped_subject_matching() {
    let dummy_sha = "ba3253876aed6bc22d4a6ff53d8406e6ad00226cb520fadd0e941f31078720b69da5ba4b3198e22c010e66cedb808837a5a46db8b24b5a3f7270f4f9714fffb1";
    let now = 1700000000i64;

    // 1. Scoped package: "@scope/pkg"
    // Accepts unencoded "@scope/pkg", "%40scope/pkg", "%40scope%2Fpkg", "%40scope%2fpkg"
    let valid_purls = [
        "pkg:npm/%40scope/pkg@1.0.0",
        "pkg:npm/@scope/pkg@1.0.0",
        "pkg:npm/%40scope%2Fpkg@1.0.0",
        "pkg:npm/%40scope%2fpkg@1.0.0",
    ];

    for purl in valid_purls {
        let (bundle, _, _) = make_test_bundle_custom(
            purl,
            dummy_sha,
            "https://github.com/scope/pkg",
            "abcdef1234567890abcdef1234567890abcdef12",
            now,
            true,
        );

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
        let res = verifier.verify(
            "@scope/pkg",
            &bundle,
            Some(&format!("sha512-{dummy_sha}")),
            None,
        );
        assert!(
            res.is_ok(),
            "PURL '{purl}' should match '@scope/pkg', got: {res:?}"
        );
    }

    // 2. Forged unscoped subject for scoped package MUST be rejected!
    let forged_unscoped = "pkg:npm/pkg@1.0.0";
    let (bundle_forged, _, _) = make_test_bundle_custom(
        forged_unscoped,
        dummy_sha,
        "https://github.com/scope/pkg",
        "abcdef1234567890abcdef1234567890abcdef12",
        now,
        true,
    );

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
    let res = verifier.verify(
        "@scope/pkg",
        &bundle_forged,
        Some(&format!("sha512-{dummy_sha}")),
        None,
    );
    assert!(
        matches!(res, Err(RegistryError::ProvenanceVerificationFailed(_))),
        "Unscoped subject MUST NOT match scoped package"
    );

    // 3. Forged scoped subject for unscoped package MUST be rejected!
    let (bundle_forged2, _, _) = make_test_bundle_custom(
        "pkg:npm/%40scope/pkg@1.0.0",
        dummy_sha,
        "https://github.com/scope/pkg",
        "abcdef1234567890abcdef1234567890abcdef12",
        now,
        true,
    );
    let res2 = verifier.verify(
        "pkg",
        &bundle_forged2,
        Some(&format!("sha512-{dummy_sha}")),
        None,
    );
    assert!(
        matches!(res2, Err(RegistryError::ProvenanceVerificationFailed(_))),
        "Scoped subject MUST NOT match unscoped package"
    );
}

#[test]
fn test_purl_extra_path_segments_and_qualifiers_rejected() {
    let dummy_sha = "ba3253876aed6bc22d4a6ff53d8406e6ad00226cb520fadd0e941f31078720b69da5ba4b3198e22c010e66cedb808837a5a46db8b24b5a3f7270f4f9714fffb1";
    let now = 1700000000i64;

    let malformed_purls = [
        // Extra subpath segment in scoped package
        "pkg:npm/%40scope/pkg/evil@1.0.0",
        // Extra subpath segment in unscoped package
        "pkg:npm/foo/bar@1.0.0",
        // Qualifier query parameter
        "pkg:npm/%40scope/pkg@1.0.0?repository_url=https://evil.com",
        // Fragment hash
        "pkg:npm/%40scope/pkg@1.0.0#subpath",
        // Missing version
        "pkg:npm/%40scope/pkg",
        // Wrong prefix
        "pkg:pypi/pkg@1.0.0",
    ];

    for purl in malformed_purls {
        let (bundle, _, _) = make_test_bundle_custom(
            purl,
            dummy_sha,
            "https://github.com/scope/pkg",
            "abcdef1234567890abcdef1234567890abcdef12",
            now,
            true,
        );

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
        let res = verifier.verify(
            "@scope/pkg",
            &bundle,
            Some(&format!("sha512-{dummy_sha}")),
            None,
        );
        assert!(
            matches!(res, Err(RegistryError::ProvenanceVerificationFailed(_))),
            "Malformed PURL '{purl}' MUST be rejected"
        );
    }
}

#[test]
fn test_subject_digest_mismatch_and_empty_digest_rejected() {
    let dummy_sha = "ba3253876aed6bc22d4a6ff53d8406e6ad00226cb520fadd0e941f31078720b69da5ba4b3198e22c010e66cedb808837a5a46db8b24b5a3f7270f4f9714fffb1";
    let now = 1700000000i64;

    let (bundle, _, _) = make_test_bundle_custom(
        "pkg:npm/foo@1.0.0",
        dummy_sha,
        "https://github.com/foo/foo",
        "abcdef1234567890abcdef1234567890abcdef12",
        now,
        true,
    );

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();

    // Mismatched integrity sha512
    let wrong_sha = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let res = verifier.verify(
        "foo",
        &bundle,
        Some(&format!("sha512-{wrong_sha}")),
        None,
    );
    assert!(
        matches!(res, Err(RegistryError::AttestationDigestMismatch { .. })),
        "Mismatched sha512 must trigger AttestationDigestMismatch"
    );

    // Empty digest in subject
    let (mut bundle_empty, _, _) = make_test_bundle_custom(
        "pkg:npm/foo@1.0.0",
        "",
        "https://github.com/foo/foo",
        "abcdef1234567890abcdef1234567890abcdef12",
        now,
        true,
    );
    // Replace envelope payload with empty digest map
    let empty_digest_stmt = InTotoStatement {
        statement_type: "https://in-toto.io/Statement/v0.1".into(),
        subject: vec![InTotoSubject {
            name: "pkg:npm/foo@1.0.0".into(),
            digest: HashMap::from([("sha512".to_string(), "".to_string())]),
        }],
        predicate_type: "https://slsa.dev/provenance/v0.2".into(),
        predicate: SlsaPredicate::default(),
    };
    let signer = EphemeralSigner::new().unwrap();
    let new_env = sign_dsse_envelope(&empty_digest_stmt, &signer).unwrap();
    bundle_empty.dsse_envelope = Some(new_env);

    let res_empty = verifier.verify(
        "foo",
        &bundle_empty,
        Some(&format!("sha512-{dummy_sha}")),
        None,
    );
    assert!(res_empty.is_err());
}

// ============================================================================
// 4. REGISTRY KEY EXPIRY & REKOR RESUSCITATION
// ============================================================================

#[test]
fn test_registry_key_expired_and_checkpoint_only_resuscitation_rejected() {
    let statement = InTotoStatement {
        statement_type: "https://in-toto.io/Statement/v0.1".into(),
        subject: vec![InTotoSubject {
            name: "pkg:npm/foo@1.0.0".into(),
            digest: HashMap::from([(
                "sha512".to_string(),
                "ba3253876aed6bc22d4a6ff53d8406e6ad00226cb520fadd0e941f31078720b69da5ba4b3198e22c010e66cedb808837a5a46db8b24b5a3f7270f4f9714fffb1".to_string(),
            )]),
        }],
        predicate_type: "https://slsa.dev/provenance/v0.2".into(),
        predicate: SlsaPredicate::default(),
    };

    let signer = EphemeralSigner::new().unwrap();
    let mut envelope = sign_dsse_envelope(&statement, &signer).unwrap();
    envelope.signatures[0].keyid = Some("npm-key-2023".into());

    let payload_bytes = decode_base64(&envelope.payload).unwrap();
    let payload_hash_hex = HEXLOWER.encode(&Sha256::digest(&payload_bytes));
    let canonical_body_json = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "payloadHash": {
                "algorithm": "sha256",
                "value": payload_hash_hex,
            },
            "signatures": [
                {
                    "signature": envelope.signatures[0].sig,
                    "verifier": BASE64.encode(signer.public_key_spki()),
                }
            ]
        }
    });
    let canonical_body_str = serde_json::to_string(&canonical_body_json).unwrap();
    let body_b64 = BASE64.encode(canonical_body_str.as_bytes());

    // 1. Bundle has NO inclusion promise (checkpoint-only bundle)
    let tlog_entry_no_set = TlogEntry {
        log_index: 999,
        log_id: LogId {
            key_id: REKOR_DEFAULT_LOG_ID.into(),
        },
        integrated_time: 1650000000, // time before expiry
        inclusion_promise: None,      // Missing SET!
        inclusion_proof: None,
        canonicalized_body: Some(body_b64.clone()),
    };

    let bundle_checkpoint_only = SigstoreBundle {
        media_type: Some("application/vnd.dev.sigstore.bundle+json;version=0.1".into()),
        verification_material: Some(VerificationMaterial {
            public_key: Some(PublicKeyHint {
                hint: Some("npm-key-2023".into()),
                ..Default::default()
            }),
            tlog_entries: vec![tlog_entry_no_set],
            ..Default::default()
        }),
        dsse_envelope: Some(envelope.clone()),
    };

    let mut keys = HashMap::new();
    keys.insert("npm-key-2023".into(), signer.public_key_spki().to_vec());
    let mut expiries = HashMap::new();
    // Key expired in 2024
    expiries.insert(
        "npm-key-2023".into(),
        ("2024-01-01T00:00:00Z".into(), 1704067200000i64),
    );

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny)
        .with_test_mock_roots()
        .with_registry_keys(keys.clone())
        .with_registry_key_expiries(expiries.clone());

    // Verification must reject: checkpoint-only bundle cannot authenticate historical signing time to resurrect key!
    let res = verifier.verify("foo", &bundle_checkpoint_only, None, None);
    assert!(
        matches!(res, Err(RegistryError::InvalidSignature(ref msg)) if msg.contains("expired")),
        "Checkpoint-only bundle without SET cannot resurrect an expired key, got: {res:?}"
    );

    // 2. Future integratedTime (> now + 5m) attempting to claim key was active
    let future_time = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64)
        + 3600; // 1 hour in the future

    let rng = ring::rand::SystemRandom::new();
    let rekor_priv = decode_base64(TEST_MOCK_REKOR_PRIV_PKCS8_B64).unwrap();
    let rekor_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rekor_priv,
        &rng,
    )
    .unwrap();

    let set_future_json = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        body_b64, future_time, REKOR_DEFAULT_LOG_ID, 1000
    );
    let rekor_sig = rekor_key_pair
        .sign(&rng, set_future_json.as_bytes())
        .unwrap();

    let tlog_future = TlogEntry {
        log_index: 1000,
        log_id: LogId {
            key_id: REKOR_DEFAULT_LOG_ID.into(),
        },
        integrated_time: future_time,
        inclusion_promise: Some(rnpm_registry::provenance::InclusionPromise {
            signed_entry_timestamp: BASE64.encode(rekor_sig.as_ref()),
        }),
        inclusion_proof: None,
        canonicalized_body: Some(body_b64),
    };

    let bundle_future = SigstoreBundle {
        media_type: Some("application/vnd.dev.sigstore.bundle+json;version=0.1".into()),
        verification_material: Some(VerificationMaterial {
            public_key: Some(PublicKeyHint {
                hint: Some("npm-key-2023".into()),
                ..Default::default()
            }),
            tlog_entries: vec![tlog_future],
            ..Default::default()
        }),
        dsse_envelope: Some(envelope),
    };

    let res_future = verifier.verify("foo", &bundle_future, None, None);
    assert!(
        matches!(res_future, Err(RegistryError::InvalidSignature(ref msg)) if msg.contains("expired")),
        "Future integratedTime must be rejected from key validity evaluation"
    );
}

#[test]
fn test_fulcio_checkpoint_only_bundle_without_set_rejected() {
    let dummy_sha = "ba3253876aed6bc22d4a6ff53d8406e6ad00226cb520fadd0e941f31078720b69da5ba4b3198e22c010e66cedb808837a5a46db8b24b5a3f7270f4f9714fffb1";
    let now = 1700000000i64;

    // Bundle with has_inclusion_promise = false (checkpoint only)
    let (bundle_no_set, _, _) = make_test_bundle_custom(
        "pkg:npm/foo@1.0.0",
        dummy_sha,
        "https://github.com/foo/foo",
        "abcdef1234567890abcdef1234567890abcdef12",
        now,
        false, // NO inclusion promise!
    );

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
    let res = verifier.verify(
        "foo",
        &bundle_no_set,
        Some(&format!("sha512-{dummy_sha}")),
        None,
    );
    assert!(
        matches!(res, Err(RegistryError::InvalidSigstoreBundle(ref msg)) if msg.contains("inclusionPromise")),
        "Fulcio certificate validity requires authenticated signing time (SET), got: {res:?}"
    );
}

// ============================================================================
// 5. MALFORMED ATTESTATION JSON RESPONSES
// ============================================================================

#[test]
fn test_attestation_malformed_json_edge_cases() {
    // Empty string
    let err_empty = SigstoreBundle::from_json("").unwrap_err();
    assert!(matches!(err_empty, RegistryError::InvalidSigstoreBundle(_)));

    // Whitespace only
    let err_ws = SigstoreBundle::from_json("   \n\t  ").unwrap_err();
    assert!(matches!(err_ws, RegistryError::InvalidSigstoreBundle(_)));

    // Empty attestations array
    let err_empty_array = SigstoreBundle::from_json(r#"{"attestations": []}"#).unwrap_err();
    assert!(matches!(err_empty_array, RegistryError::InvalidSigstoreBundle(_)));

    // Attestation with null bundle
    let err_null_bundle =
        SigstoreBundle::from_json(r#"{"attestations": [{"bundle": null}]}"#).unwrap_err();
    assert!(matches!(err_null_bundle, RegistryError::InvalidSigstoreBundle(_)));

    // Nested random JSON without dsseEnvelope
    let err_no_envelope =
        SigstoreBundle::from_json(r#"{"bundle": {"verificationMaterial": {}}}"#).unwrap_err();
    assert!(matches!(err_no_envelope, RegistryError::InvalidSigstoreBundle(_)));

    // Deeply nested JSON
    let deeply_nested = r#"{"a":{"b":{"c":{"d":{"e":{"f":123}}}}}}"#;
    let err_nested = SigstoreBundle::from_json(deeply_nested).unwrap_err();
    assert!(matches!(err_nested, RegistryError::InvalidSigstoreBundle(_)));
}

#[test]
fn test_attestation_from_json_all_filters_valid_bundles() {
    let dummy_sha = "ba3253876aed6bc22d4a6ff53d8406e6ad00226cb520fadd0e941f31078720b69da5ba4b3198e22c010e66cedb808837a5a46db8b24b5a3f7270f4f9714fffb1";
    let now = 1700000000i64;
    let (bundle, _, _) = make_test_bundle_custom(
        "pkg:npm/foo@1.0.0",
        dummy_sha,
        "https://github.com/foo/foo",
        "abcdef1234567890abcdef1234567890abcdef12",
        now,
        true,
    );

    let attestation_resp = AttestationResponse {
        attestations: vec![
            AttestationItem {
                predicate_type: Some("https://slsa.dev/provenance/v0.2".into()),
                bundle: Some(bundle.clone()),
            },
            AttestationItem {
                predicate_type: Some("empty".into()),
                bundle: None,
            },
        ],
    };

    let json_str = serde_json::to_string(&attestation_resp).unwrap();
    let bundles = SigstoreBundle::from_json_all(&json_str).unwrap();
    assert_eq!(bundles.len(), 1);
    assert_eq!(bundles[0].dsse_envelope, bundle.dsse_envelope);
}

#[test]
fn test_validate_dist_signatures_edge_cases() {
    // Empty array
    let err_empty = validate_dist_signatures(&[], None).unwrap_err();
    assert!(matches!(err_empty, RegistryError::InvalidSignature(_)));

    // Empty keyid
    let sigs_empty_keyid = vec![DistSignature {
        keyid: "".into(),
        sig: "MEQCIA==".into(),
    }];
    let err_keyid = validate_dist_signatures(&sigs_empty_keyid, None).unwrap_err();
    assert!(matches!(err_keyid, RegistryError::InvalidSignature(_)));

    // Empty sig
    let sigs_empty_sig = vec![DistSignature {
        keyid: "key-1".into(),
        sig: "".into(),
    }];
    let err_sig = validate_dist_signatures(&sigs_empty_sig, None).unwrap_err();
    assert!(matches!(err_sig, RegistryError::InvalidSignature(_)));

    // Invalid base64 in sig
    let sigs_bad_b64 = vec![DistSignature {
        keyid: "key-1".into(),
        sig: "invalid b64!@#".into(),
    }];
    let err_b64 = validate_dist_signatures(&sigs_bad_b64, None).unwrap_err();
    assert!(matches!(err_b64, RegistryError::InvalidSignature(_)));

    // Valid sigs with trusted keyids check
    let valid_sigs = vec![
        DistSignature {
            keyid: "key-1".into(),
            sig: "MEQCIA==".into(),
        },
        DistSignature {
            keyid: "key-2".into(),
            sig: "MEQCIA==".into(),
        },
    ];
    let res = validate_dist_signatures(&valid_sigs, Some(&["key-2"])).unwrap();
    assert_eq!(res.len(), 2);

    let untrusted_res = validate_dist_signatures(&valid_sigs, Some(&["key-999"]));
    assert!(matches!(untrusted_res, Err(RegistryError::InvalidSignature(_))));
}

// ============================================================================
// 6. REGISTRY HTTP CLIENT REDIRECT SECURITY & AUTH STRIPPING
// ============================================================================

#[tokio::test]
async fn test_http_same_origin_redirect_retains_authorization() {
    let auth_header_received_on_redirect = Arc::new(tokio::sync::Mutex::new(None));
    let auth_clone = auth_header_received_on_redirect.clone();

    let server = MockHttpServer::start(move |req, idx| {
        if idx == 0 {
            // First request: redirect to same origin /final-path
            (302, vec![("Location", "/final-path".to_string())], vec![])
        } else {
            // Second request: record Authorization header
            let auth_line = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                .map(|l| l.to_string());
            let mut stored = auth_clone.try_lock().unwrap();
            *stored = auth_line;
            (200, vec![("Content-Type", "application/json".into())], b"{}".to_vec())
        }
    })
    .await;

    let base_url = server.url();
    let host_port = format!("{}:{}", base_url.host_str().unwrap(), base_url.port().unwrap());

    let mut auth_tokens = BTreeMap::new();
    auth_tokens.insert(format!("//{host_port}/"), "secret-token-123".to_string());

    let mut trusted_hosts = HashSet::new();
    trusted_hosts.insert(host_port);

    let config = RegistryClientConfig {
        default_registry: base_url.clone(),
        auth_tokens,
        trusted_hosts,
        max_retries: 0,
        circuit_breaker_enabled: false,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let (resp, _permit) = client
        .execute_with_permit(
            reqwest::Method::GET,
            base_url.join("/initial").unwrap(),
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let auth_val = auth_header_received_on_redirect.lock().await.clone();
    assert!(
        auth_val.is_some() && auth_val.unwrap().contains("secret-token-123"),
        "Same-origin redirect MUST retain Authorization header"
    );

    server.stop();
}

#[tokio::test]
async fn test_http_cross_host_redirect_strips_authorization() {
    let auth_header_received_on_target = Arc::new(tokio::sync::Mutex::new(None));
    let auth_clone = auth_header_received_on_target.clone();

    // Target server representing untrusted external host
    let target_server = MockHttpServer::start(move |req, _| {
        let auth_line = req
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
            .map(|l| l.to_string());
        let mut stored = auth_clone.try_lock().unwrap();
        *stored = auth_line;
        (200, vec![("Content-Type", "application/json".into())], b"{}".to_vec())
    })
    .await;

    let target_url = target_server.url();

    // Origin server redirects to target server
    let target_url_str = target_url.to_string();
    let origin_server = MockHttpServer::start(move |_, _| {
        (302, vec![("Location", target_url_str.clone())], vec![])
    })
    .await;

    let origin_url = origin_server.url();
    let origin_host_port = format!(
        "{}:{}",
        origin_url.host_str().unwrap(),
        origin_url.port().unwrap()
    );

    let mut auth_tokens = BTreeMap::new();
    auth_tokens.insert(
        format!("//{origin_host_port}/"),
        "super-secret-token".to_string(),
    );

    let mut trusted_hosts = HashSet::new();
    trusted_hosts.insert(origin_host_port); // target is NOT in trusted_hosts!

    let config = RegistryClientConfig {
        default_registry: origin_url.clone(),
        auth_tokens,
        trusted_hosts,
        max_retries: 0,
        circuit_breaker_enabled: false,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let (resp, _permit) = client
        .execute_with_permit(
            reqwest::Method::GET,
            origin_url.join("/pkg").unwrap(),
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let auth_val = auth_header_received_on_target.lock().await.clone();
    assert!(
        auth_val.is_none(),
        "Cross-host redirect to untrusted target MUST strip Authorization header! Got: {auth_val:?}"
    );

    origin_server.stop();
    target_server.stop();
}

#[tokio::test]
async fn test_http_cross_port_redirect_strips_authorization() {
    let auth_header_received_on_different_port = Arc::new(tokio::sync::Mutex::new(None));
    let auth_clone = auth_header_received_on_different_port.clone();

    // Server on port B
    let server_b = MockHttpServer::start(move |req, _| {
        let auth_line = req
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
            .map(|l| l.to_string());
        let mut stored = auth_clone.try_lock().unwrap();
        *stored = auth_line;
        (200, vec![("Content-Type", "application/json".into())], b"{}".to_vec())
    })
    .await;

    let url_b = server_b.url();
    let url_b_str = url_b.to_string();

    // Server on port A redirects to port B
    let server_a = MockHttpServer::start(move |_, _| {
        (302, vec![("Location", url_b_str.clone())], vec![])
    })
    .await;

    let url_a = server_a.url();
    let host_a = format!("{}:{}", url_a.host_str().unwrap(), url_a.port().unwrap());

    let mut auth_tokens = BTreeMap::new();
    auth_tokens.insert(format!("//{host_a}/"), "port-a-token".to_string());

    let mut trusted_hosts = HashSet::new();
    trusted_hosts.insert(host_a); // Port B is NOT in trusted_hosts!

    let config = RegistryClientConfig {
        default_registry: url_a.clone(),
        auth_tokens,
        trusted_hosts,
        max_retries: 0,
        circuit_breaker_enabled: false,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let (resp, _permit) = client
        .execute_with_permit(
            reqwest::Method::GET,
            url_a.join("/pkg").unwrap(),
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let auth_val = auth_header_received_on_different_port.lock().await.clone();
    assert!(
        auth_val.is_none(),
        "Cross-port redirect without explicit trust MUST strip Authorization header!"
    );

    server_a.stop();
    server_b.stop();
}

#[tokio::test]
async fn test_http_redirect_loop_detected() {
    // Server redirects /loop-a -> /loop-b -> /loop-a
    let server = MockHttpServer::start(|req, _| {
        if req.contains("GET /loop-a") {
            (302, vec![("Location", "/loop-b".to_string())], vec![])
        } else {
            (302, vec![("Location", "/loop-a".to_string())], vec![])
        }
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        max_retries: 0,
        circuit_breaker_enabled: false,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();
    let err = client
        .execute_with_permit(
            reqwest::Method::GET,
            server.url().join("/loop-a").unwrap(),
            None,
            None,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, RegistryError::SecurityViolation(ref msg) if msg.contains("loop detected")),
        "Expected redirect loop security violation, got: {err:?}"
    );

    server.stop();
}

#[tokio::test]
async fn test_http_unsupported_redirect_scheme_rejected() {
    let server = MockHttpServer::start(|_, _| {
        (
            302,
            vec![("Location", "javascript:alert(document.cookie)".to_string())],
            vec![],
        )
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        max_retries: 0,
        circuit_breaker_enabled: false,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();
    let err = client
        .execute_with_permit(
            reqwest::Method::GET,
            server.url().join("/start").unwrap(),
            None,
            None,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, RegistryError::SecurityViolation(ref msg) if msg.contains("unsupported scheme")),
        "Expected unsupported scheme rejection, got: {err:?}"
    );

    server.stop();
}

#[tokio::test]
async fn test_http_invalid_characters_in_redirect_location_rejected() {
    let server = MockHttpServer::start(|_, _| {
        // Non-ASCII characters in Location header (causes HeaderValue::to_str() to fail)
        (
            302,
            vec![("Location", "/path/测试".to_string())],
            vec![],
        )
    })
    .await;

    let config = RegistryClientConfig {
        default_registry: server.url(),
        max_retries: 0,
        circuit_breaker_enabled: false,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();
    let err = client
        .execute_with_permit(
            reqwest::Method::GET,
            server.url().join("/start").unwrap(),
            None,
            None,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, RegistryError::SecurityViolation(ref msg) if msg.contains("Invalid characters") || msg.contains("CR/LF")),
        "Expected invalid characters rejection, got: {err:?}"
    );

    server.stop();
}

// ============================================================================
// 7. RETRY-AFTER & CIRCUIT BREAKER EDGE CASES
// ============================================================================

#[test]
fn test_retry_after_edge_cases() {
    // Negative integer: per RFC 7231 / RFC 9110, negative delay is in the past -> returns Some(0)
    assert_eq!(parse_retry_after_str("-10"), Some(0));
    assert_eq!(parse_retry_after_str("-1"), Some(0));

    // Zero seconds
    assert_eq!(parse_retry_after_str("0"), Some(0));

    // Valid positive seconds
    assert_eq!(parse_retry_after_str("120"), Some(120));

    // Huge integer string overflowing u64 -> must return Some(u64::MAX) to exceed max budget cap
    let huge_overflow = "99999999999999999999999999999999999999999999999999999";
    assert_eq!(parse_retry_after_str(huge_overflow), Some(u64::MAX));

    // Non-numeric garbage string
    assert_eq!(parse_retry_after_str("garbage-invalid-delay"), None);

    // HTTP-date in the past -> 0 seconds
    let past_date = "Wed, 21 Oct 2015 07:28:00 GMT";
    assert_eq!(parse_retry_after_str(past_date), Some(0));
    assert_eq!(parse_http_date_to_seconds_from_now(past_date), Some(0));

    // HTTP-date in the future (far ahead in 2038)
    let future_date = "Tue, 19 Jan 2038 03:14:07 GMT";
    let secs = parse_retry_after_str(future_date).unwrap();
    assert!(secs > 0, "Future HTTP-date must produce positive seconds");
}

#[tokio::test]
async fn test_circuit_breaker_transitions_and_half_open_recovery() {
    let cb = CircuitBreaker::new(3, Duration::from_millis(50));
    let host = "registry.example.org";

    // 1. Initial state is Closed
    assert_eq!(cb.check_state(host).await, CircuitBreakerState::Closed);

    // 2. 1 failure -> still Closed
    let s1 = cb.record_failure(host).await;
    assert_eq!(s1, CircuitBreakerState::Closed);
    assert_eq!(cb.check_state(host).await, CircuitBreakerState::Closed);

    // 3. 2nd failure -> still Closed
    let s2 = cb.record_failure(host).await;
    assert_eq!(s2, CircuitBreakerState::Closed);

    // 4. 3rd failure (reaches threshold 3) -> trips to Open
    let s3 = cb.record_failure(host).await;
    assert_eq!(s3, CircuitBreakerState::Open);
    assert_eq!(cb.check_state(host).await, CircuitBreakerState::Open);

    // 5. Cooldown has not elapsed yet -> stays Open
    assert_eq!(cb.check_state(host).await, CircuitBreakerState::Open);

    // 6. Wait for reset timeout (50ms) to elapse -> transitions to HalfOpen
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert_eq!(cb.check_state(host).await, CircuitBreakerState::HalfOpen);

    // 7. Successful probe in HalfOpen -> closes circuit and resets failure counter
    cb.record_success(host).await;
    assert_eq!(cb.check_state(host).await, CircuitBreakerState::Closed);

    // 8. Trip it again to test failure in HalfOpen
    cb.trip(host).await;
    assert_eq!(cb.check_state(host).await, CircuitBreakerState::Open);

    tokio::time::sleep(Duration::from_millis(70)).await;
    assert_eq!(cb.check_state(host).await, CircuitBreakerState::HalfOpen);

    // 9. Failure during probe in HalfOpen -> immediately trips back to Open!
    let s_reopen = cb.record_failure(host).await;
    assert_eq!(s_reopen, CircuitBreakerState::Open);
    assert_eq!(cb.check_state(host).await, CircuitBreakerState::Open);
}

#[tokio::test]
async fn test_circuit_breaker_disabled_never_trips() {
    let cb = CircuitBreaker::new(0, Duration::from_millis(100)); // threshold 0 disables circuit breaker
    let host = "disabled.example.org";

    assert_eq!(cb.check_state(host).await, CircuitBreakerState::Closed);
    for _ in 0..10 {
        let s = cb.record_failure(host).await;
        assert_eq!(s, CircuitBreakerState::Closed);
    }
    assert_eq!(cb.check_state(host).await, CircuitBreakerState::Closed);
}

#[test]
fn test_pem_decoding_edge_cases() {
    use rnpm_registry::provenance::{decode_pem_to_der, der_to_pem_cert};

    // Valid roundtrip
    let raw_bytes = vec![0x30, 0x0A, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x01, 0x05, 0x00];
    let pem = der_to_pem_cert(&raw_bytes);
    let decoded = decode_pem_to_der(&pem).unwrap();
    assert_eq!(raw_bytes, decoded);

    // Mismatched labels: BEGIN CERTIFICATE with END RSA PRIVATE KEY
    let mismatched = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END RSA PRIVATE KEY-----\n";
    let err_mismatch = decode_pem_to_der(mismatched).unwrap_err();
    assert!(
        matches!(err_mismatch, RegistryError::InvalidSigstoreBundle(ref msg) if msg.contains("matching PEM END header")),
        "Expected mismatched PEM labels rejection, got: {err_mismatch:?}"
    );

    // Empty body
    let empty_pem = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n";
    let err_empty = decode_pem_to_der(empty_pem).unwrap_err();
    assert!(matches!(err_empty, RegistryError::InvalidSigstoreBundle(_)));

    // Missing headers
    let missing_begin = "MIIC...\n-----END CERTIFICATE-----\n";
    assert!(matches!(decode_pem_to_der(missing_begin).unwrap_err(), RegistryError::InvalidSigstoreBundle(_)));

    let missing_end = "-----BEGIN CERTIFICATE-----\nMIIC...\n";
    assert!(matches!(decode_pem_to_der(missing_end).unwrap_err(), RegistryError::InvalidSigstoreBundle(_)));
}

#[tokio::test]
async fn test_http_cross_origin_with_explicit_auth_token_sends_target_token() {
    let auth_header_received_on_target = Arc::new(tokio::sync::Mutex::new(None));
    let auth_clone = auth_header_received_on_target.clone();

    // Target server
    let target_server = MockHttpServer::start(move |req, _| {
        let auth_line = req
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
            .map(|l| l.to_string());
        let mut stored = auth_clone.try_lock().unwrap();
        *stored = auth_line;
        (200, vec![("Content-Type", "application/json".into())], b"{}".to_vec())
    })
    .await;

    let target_url = target_server.url();
    let target_host_port = format!("{}:{}", target_url.host_str().unwrap(), target_url.port().unwrap());
    let target_url_str = target_url.to_string();

    // Origin server redirects to target server
    let origin_server = MockHttpServer::start(move |_, _| {
        (302, vec![("Location", target_url_str.clone())], vec![])
    })
    .await;

    let origin_url = origin_server.url();
    let origin_host_port = format!("{}:{}", origin_url.host_str().unwrap(), origin_url.port().unwrap());

    let mut auth_tokens = BTreeMap::new();
    auth_tokens.insert(format!("//{origin_host_port}/"), "origin-token".to_string());
    // Explicit token configured for target host & port
    auth_tokens.insert(format!("//{target_host_port}/"), "explicit-target-token".to_string());

    let mut trusted_hosts = HashSet::new();
    trusted_hosts.insert(origin_host_port);

    let config = RegistryClientConfig {
        default_registry: origin_url.clone(),
        auth_tokens,
        trusted_hosts,
        max_retries: 0,
        circuit_breaker_enabled: false,
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let (resp, _permit) = client
        .execute_with_permit(
            reqwest::Method::GET,
            origin_url.join("/pkg").unwrap(),
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let auth_val = auth_header_received_on_target.lock().await.clone();
    assert!(
        auth_val.is_some() && auth_val.unwrap().contains("explicit-target-token"),
        "Cross-origin redirect with explicit auth_tokens entry for target MUST send target's token"
    );

    origin_server.stop();
    target_server.stop();
}

#[tokio::test]
async fn test_http_https_to_http_downgrade_strictly_strips_authorization() {
    let config = RegistryClientConfig {
        auth_token: Some("secret".into()),
        ..Default::default()
    };
    let client = RegistryClient::with_config(config).unwrap();

    let https_url = Url::parse("https://registry.npmjs.org/pkg").unwrap();
    let http_url = Url::parse("http://registry.npmjs.org/pkg").unwrap();

    // Directly verify security policy method
    assert!(
        !client.is_trusted_target(&https_url, &http_url),
        "HTTPS -> HTTP downgrade MUST NEVER be trusted to receive Authorization header!"
    );
}
