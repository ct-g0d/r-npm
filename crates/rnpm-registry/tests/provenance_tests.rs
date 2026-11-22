use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;

use rnpm_registry::metadata::AbbreviatedPackageMetadata;
use rnpm_registry::provenance::{
    assemble_sigstore_bundle, decode_base64, format_registry_signature_payload,
    normalize_repository_url, sign_dsse_envelope, AttestationItem, AttestationResponse,
    EphemeralSigner, InTotoStatement, InTotoSubject, LogId, ProvenancePolicy, ProvenanceVerifier,
    PublicKeyHint, SigstoreBundle, SlsaBuilder, SlsaConfigSource, SlsaInvocation, SlsaPredicate,
    TlogEntry, VerificationMaterial, FULCIO_INTERMEDIATE_CA_2_DER_B64, FULCIO_ROOT_CA_1_DER_B64,
    FULCIO_ROOT_CA_2_DER_B64, NPM_REGISTRY_KEYID, REKOR_DEFAULT_LOG_ID,
    REKOR_DEFAULT_PUBKEY_SPKI_B64, TEST_MOCK_CA_PRIV_PKCS8_B64, TEST_MOCK_REKOR_PRIV_PKCS8_B64,
};
use rnpm_registry::RegistryError;

fn make_test_bundle_with_subject(
    subject_name: &str,
    sha512_hex: &str,
    repo_uri: &str,
    commit_sha: &str,
) -> SigstoreBundle {
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

    let now = 1700000000i64;
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
    let ca_priv = rnpm_registry::provenance::decode_base64(TEST_MOCK_CA_PRIV_PKCS8_B64).unwrap();
    let ca_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &ca_priv,
        &rng,
    )
    .unwrap();

    let cert_der = rnpm_registry::asn1::create_test_x509_certificate(
        "test-signer",
        "sigstore",
        signer.public_key_uncompressed(),
        Some("https://github.com/actions/runner"),
        &fulcio_exts,
        now - 60,
        now + 600,
        &|tbs| ca_key_pair.sign(&rng, tbs).unwrap().as_ref().to_vec(),
    );

    let payload_bytes = rnpm_registry::provenance::decode_base64(&envelope.payload).unwrap();
    let payload_hash_hex = HEXLOWER.encode(&Sha256::digest(&payload_bytes));
    let leaf_b64 = data_encoding::BASE64.encode(&cert_der);
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
    let body_b64 = data_encoding::BASE64.encode(canonical_body_str.as_bytes());

    let rekor_priv =
        rnpm_registry::provenance::decode_base64(TEST_MOCK_REKOR_PRIV_PKCS8_B64).unwrap();
    let rekor_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rekor_priv,
        &rng,
    )
    .unwrap();

    let set_canonical_json = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        body_b64, now, REKOR_DEFAULT_LOG_ID, 998877
    );
    let rekor_sig = rekor_key_pair
        .sign(&rng, set_canonical_json.as_bytes())
        .unwrap();

    let tlog_entry = TlogEntry {
        log_index: 998877,
        log_id: LogId {
            key_id: REKOR_DEFAULT_LOG_ID.into(),
        },
        integrated_time: now,
        inclusion_promise: Some(rnpm_registry::provenance::InclusionPromise {
            signed_entry_timestamp: data_encoding::BASE64.encode(rekor_sig.as_ref()),
        }),
        inclusion_proof: None,
        canonicalized_body: Some(body_b64),
    };

    assemble_sigstore_bundle(envelope, &cert_der, tlog_entry)
}

fn make_test_bundle(
    pkg_name: &str,
    sha512_hex: &str,
    repo_uri: &str,
    commit_sha: &str,
) -> SigstoreBundle {
    let purl_name = if let Some(stripped) = pkg_name.strip_prefix('@') {
        format!("pkg:npm/%40{stripped}@1.0.0")
    } else {
        format!("pkg:npm/{pkg_name}@1.0.0")
    };
    make_test_bundle_with_subject(&purl_name, sha512_hex, repo_uri, commit_sha)
}

#[test]
fn test_packument_with_signatures_and_attestations() {
    let packument_json = r#"{
        "name": "@fastify/cors",
        "dist-tags": { "latest": "9.0.1" },
        "versions": {
            "9.0.1": {
                "name": "@fastify/cors",
                "version": "9.0.1",
                "dist": {
                    "tarball": "https://registry.npmjs.org/@fastify/cors/-/@fastify/cors-9.0.1.tgz",
                    "shasum": "abcdef1234567890abcdef1234567890abcdef12",
                    "integrity": "sha512-test==",
                    "signatures": [
                        {
                            "keyid": "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
                            "sig": "MEQCIA=="
                        }
                    ],
                    "attestations": {
                        "url": "https://registry.npmjs.org/-/npm/v1/attestations/@fastify%2Fcors@9.0.1",
                        "provenance": {
                            "predicateType": "https://slsa.dev/provenance/v0.2"
                        }
                    }
                }
            }
        }
    }"#;

    let meta: AbbreviatedPackageMetadata = serde_json::from_str(packument_json).unwrap();
    assert_eq!(meta.name, "@fastify/cors");
    let v = meta.versions.get("9.0.1").unwrap();
    assert_eq!(v.dist.signatures.len(), 1);
    assert_eq!(v.dist.signatures[0].keyid, NPM_REGISTRY_KEYID);
    assert_eq!(v.dist.signatures[0].sig, "MEQCIA==");

    let att = v.dist.attestations.as_ref().unwrap();
    assert!(att.url.as_ref().unwrap().contains("@fastify%2Fcors@9.0.1"));
    assert_eq!(
        att.provenance.as_ref().unwrap().predicate_type.as_deref(),
        Some("https://slsa.dev/provenance/v0.2")
    );
}

#[test]
fn test_scoped_package_provenance_verification() {
    let tarball_bytes = b"tarball for scoped fastify cors";
    let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));

    let bundle = make_test_bundle(
        "@fastify/cors",
        &sha512_hex,
        "git+https://github.com/fastify/fastify-cors.git@refs/heads/main",
        "abcdef11223344556677889900aabbccddeeff00",
    );

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::RequireRepository {
        expected_repository: "fastify/fastify-cors".into(),
    })
    .with_test_mock_roots();

    let verified = verifier
        .verify("@fastify/cors", &bundle, None, Some(tarball_bytes))
        .unwrap();

    assert_eq!(verified.package_name, "@fastify/cors");
    assert_eq!(
        verified.build.source_repository.as_deref(),
        Some("fastify/fastify-cors")
    );
    assert!(verified.build.is_github_actions());
}

#[test]
fn test_attestation_response_json_parsing() {
    let tarball_bytes = b"sample content";
    let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));

    let bundle = make_test_bundle(
        "pkg-sample",
        &sha512_hex,
        "https://github.com/org/pkg-sample",
        "commit-sha-12345",
    );

    let response = AttestationResponse {
        attestations: vec![AttestationItem {
            predicate_type: Some("https://slsa.dev/provenance/v0.2".into()),
            bundle: Some(bundle),
        }],
    };

    let response_json = serde_json::to_string(&response).unwrap();
    let parsed_bundle = SigstoreBundle::from_json(&response_json).unwrap();

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
    let verified = verifier
        .verify("pkg-sample", &parsed_bundle, None, Some(tarball_bytes))
        .unwrap();
    assert_eq!(verified.package_name, "pkg-sample");
    assert_eq!(verified.tlog_entry.log_index, 998877);
}

#[test]
fn test_verify_version_policies() {
    let packument_json = r#"{
        "name": "sample-pkg",
        "version": "1.0.0",
        "dist": {
            "tarball": "https://registry.npmjs.org/sample-pkg/-/sample-pkg-1.0.0.tgz",
            "integrity": "sha512-test=="
        }
    }"#;
    let ver: rnpm_registry::metadata::AbbreviatedVersion =
        serde_json::from_str(packument_json).unwrap();

    // AllowAny allows missing provenance
    let allow_any = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
    assert!(allow_any
        .verify_version(&ver, None, None)
        .unwrap()
        .is_none());

    // RequireProvenance rejects missing provenance
    let req_prov = ProvenanceVerifier::new(ProvenancePolicy::RequireProvenance);
    let err1 = req_prov.verify_version(&ver, None, None).unwrap_err();
    assert!(matches!(
        err1,
        RegistryError::ProvenanceVerificationFailed(_)
    ));

    // RequireRepository rejects missing provenance
    let req_repo = ProvenanceVerifier::new(ProvenancePolicy::RequireRepository {
        expected_repository: "owner/repo".into(),
    });
    let err2 = req_repo.verify_version(&ver, None, None).unwrap_err();
    assert!(matches!(
        err2,
        RegistryError::UntrustedSourceRepository { .. }
    ));
}

#[test]
fn test_missing_tlog_entries_rejected() {
    let tarball_bytes = b"sample";
    let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));
    let mut bundle = make_test_bundle("pkg", &sha512_hex, "https://github.com/org/pkg", "sha123");

    bundle
        .verification_material
        .as_mut()
        .unwrap()
        .tlog_entries
        .clear();

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
    let err = verifier
        .verify("pkg", &bundle, None, Some(tarball_bytes))
        .unwrap_err();
    assert!(matches!(err, RegistryError::InvalidSigstoreBundle(_)));
}

#[test]
fn test_normalize_repository_url_edge_cases() {
    assert_eq!(
        normalize_repository_url("git+https://github.com/chalk/chalk.git#main"),
        "chalk/chalk.git#main"
    );
    assert_eq!(
        normalize_repository_url("git+https://github.com/chalk/chalk.git@refs/tags/v5.0.0"),
        "chalk/chalk"
    );
    assert_eq!(
        normalize_repository_url("git@github.com:facebook/react.git"),
        "facebook/react"
    );
    assert_eq!(
        normalize_repository_url("https://github.com/facebook/react/"),
        "facebook/react"
    );
}

#[test]
fn test_format_signature_payload() {
    let payload = format_registry_signature_payload(
        "chalk",
        "5.0.0",
        "sha512-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
    );
    assert_eq!(
        payload,
        "chalk@5.0.0:sha512-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    );
}

#[test]
fn test_self_signed_leaf_certificate_rejected() {
    let tarball_bytes = b"self-signed leaf payload";
    let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));

    let mut digest = HashMap::new();
    digest.insert("sha512".to_string(), sha512_hex);

    let statement = InTotoStatement {
        statement_type: "https://in-toto.io/Statement/v0.1".into(),
        subject: vec![InTotoSubject {
            name: "self-signed-pkg-1.0.0.tgz".into(),
            digest,
        }],
        predicate_type: "https://slsa.dev/provenance/v0.2".into(),
        predicate: SlsaPredicate {
            builder: Some(SlsaBuilder {
                id: "https://github.com/actions/runner/v2".into(),
            }),
            build_type: Some("https://actions.github.com/Workflow@v1".into()),
            invocation: None,
            recipe: None,
            materials: Vec::new(),
            build_definition: None,
            run_details: None,
        },
    };

    let signer = EphemeralSigner::new().unwrap();
    let envelope = sign_dsse_envelope(&statement, &signer).unwrap();

    let now = 1700000000i64;
    // Sign leaf cert with ITSELF (ephemeral signer's own private key), NOT the CA
    let cert_der = rnpm_registry::asn1::create_test_x509_certificate(
        "test-signer",
        "sigstore",
        signer.public_key_uncompressed(),
        Some("https://github.com/actions/runner"),
        &[],
        now - 60,
        now + 600,
        &|tbs| signer.sign(tbs).unwrap(),
    );

    let tlog_entry = TlogEntry {
        log_index: 100,
        log_id: LogId {
            key_id: REKOR_DEFAULT_LOG_ID.into(),
        },
        integrated_time: now,
        inclusion_promise: Some(rnpm_registry::provenance::InclusionPromise {
            signed_entry_timestamp: "dummy".into(),
        }),
        inclusion_proof: None,
        canonicalized_body: Some(data_encoding::BASE64.encode(b"body")),
    };

    let bundle = assemble_sigstore_bundle(envelope, &cert_der, tlog_entry);
    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
    let err = verifier
        .verify("self-signed-pkg", &bundle, None, Some(tarball_bytes))
        .unwrap_err();

    match err {
        RegistryError::InvalidSigstoreBundle(msg) => {
            assert!(
                msg.contains("Certificate chain does not terminate in a trusted Fulcio root CA"),
                "Expected Fulcio root CA trust failure, got: {msg}"
            );
        }
        other => panic!("Expected InvalidSigstoreBundle error, got: {:?}", other),
    }
}

#[test]
fn test_untrusted_ca_root_rejected() {
    let tarball_bytes = b"untrusted ca root payload";
    let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));

    let mut digest = HashMap::new();
    digest.insert("sha512".to_string(), sha512_hex);

    let statement = InTotoStatement {
        statement_type: "https://in-toto.io/Statement/v0.1".into(),
        subject: vec![InTotoSubject {
            name: "untrusted-ca-pkg-1.0.0.tgz".into(),
            digest,
        }],
        predicate_type: "https://slsa.dev/provenance/v0.2".into(),
        predicate: SlsaPredicate {
            builder: Some(SlsaBuilder {
                id: "https://github.com/actions/runner/v2".into(),
            }),
            build_type: Some("https://actions.github.com/Workflow@v1".into()),
            invocation: None,
            recipe: None,
            materials: Vec::new(),
            build_definition: None,
            run_details: None,
        },
    };

    let signer = EphemeralSigner::new().unwrap();
    let envelope = sign_dsse_envelope(&statement, &signer).unwrap();

    let now = 1700000000i64;
    // Generate an unknown, untrusted CA
    let unknown_ca_signer = EphemeralSigner::new().unwrap();
    let cert_der = rnpm_registry::asn1::create_test_x509_certificate(
        "test-signer",
        "untrusted-ca",
        signer.public_key_uncompressed(),
        Some("https://github.com/actions/runner"),
        &[],
        now - 60,
        now + 600,
        &|tbs| unknown_ca_signer.sign(tbs).unwrap(),
    );

    let tlog_entry = TlogEntry {
        log_index: 101,
        log_id: LogId {
            key_id: REKOR_DEFAULT_LOG_ID.into(),
        },
        integrated_time: now,
        inclusion_promise: Some(rnpm_registry::provenance::InclusionPromise {
            signed_entry_timestamp: "dummy".into(),
        }),
        inclusion_proof: None,
        canonicalized_body: Some(data_encoding::BASE64.encode(b"body")),
    };

    let bundle = assemble_sigstore_bundle(envelope, &cert_der, tlog_entry);
    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
    let err = verifier
        .verify("untrusted-ca-pkg", &bundle, None, Some(tarball_bytes))
        .unwrap_err();

    match err {
        RegistryError::InvalidSigstoreBundle(msg) => {
            assert!(
                msg.contains("Certificate chain does not terminate in a trusted Fulcio root CA"),
                "Expected Fulcio root CA trust failure, got: {msg}"
            );
        }
        other => panic!("Expected InvalidSigstoreBundle error, got: {:?}", other),
    }
}

#[test]
fn test_unauthenticated_rekor_set_rejected() {
    let tarball_bytes = b"unauthenticated rekor set payload";
    let (mut bundle, _) = rnpm_registry::provenance::generate_valid_signed_test_bundle(
        "tampered-set-pkg",
        "1.0.0",
        tarball_bytes,
        "org/repo",
        "sha123",
    );

    // Tamper the SET signature
    bundle
        .verification_material
        .as_mut()
        .unwrap()
        .tlog_entries[0]
        .inclusion_promise
        .as_mut()
        .unwrap()
        .signed_entry_timestamp = data_encoding::BASE64.encode(b"corrupted-rekor-signature");

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
    let err = verifier
        .verify("tampered-set-pkg", &bundle, None, Some(tarball_bytes))
        .unwrap_err();

    match err {
        RegistryError::InvalidSigstoreBundle(msg) => {
            assert!(
                msg.contains("Rekor transparency log evidence missing or unauthenticated"),
                "Expected unauthenticated Rekor SET error, got: {msg}"
            );
        }
        other => panic!("Expected InvalidSigstoreBundle error, got: {:?}", other),
    }
}

#[test]
fn test_rekor_body_payload_hash_mismatch_rejected() {
    let tarball_bytes = b"rekor body mismatch payload";
    let (mut bundle, _) = rnpm_registry::provenance::generate_valid_signed_test_bundle(
        "mismatch-pkg",
        "1.0.0",
        tarball_bytes,
        "org/repo",
        "sha123",
    );

    let rng = ring::rand::SystemRandom::new();
    let rekor_priv =
        rnpm_registry::provenance::decode_base64(TEST_MOCK_REKOR_PRIV_PKCS8_B64).unwrap();
    let rekor_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rekor_priv,
        &rng,
    )
    .unwrap();

    let cert_raw = bundle.verification_material.as_ref().unwrap().certificate.as_ref().unwrap().raw_bytes.clone();
    let sig_str = bundle.dsse_envelope.as_ref().unwrap().signatures[0].sig.clone();

    // Change payload hash in Rekor body
    let wrong_body_json = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "payloadHash": {
                "algorithm": "sha256",
                "value": "0000000000000000000000000000000000000000000000000000000000000000",
            },
            "signatures": [
                {
                    "signature": sig_str,
                    "verifier": cert_raw,
                }
            ]
        }
    });
    let wrong_body_str = serde_json::to_string(&wrong_body_json).unwrap();
    let wrong_body_b64 = data_encoding::BASE64.encode(wrong_body_str.as_bytes());

    let now = 1700000000i64;
    let set_canonical_json = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        wrong_body_b64, now, REKOR_DEFAULT_LOG_ID, 42
    );
    let rekor_sig = rekor_key_pair
        .sign(&rng, set_canonical_json.as_bytes())
        .unwrap();

    let tlog = &mut bundle.verification_material.as_mut().unwrap().tlog_entries[0];
    tlog.canonicalized_body = Some(wrong_body_b64);
    tlog.inclusion_promise = Some(rnpm_registry::provenance::InclusionPromise {
        signed_entry_timestamp: data_encoding::BASE64.encode(rekor_sig.as_ref()),
    });

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
    let err = verifier
        .verify("mismatch-pkg", &bundle, None, Some(tarball_bytes))
        .unwrap_err();

    match err {
        RegistryError::InvalidSigstoreBundle(msg) => {
            assert!(
                msg.contains("payloadHash mismatch"),
                "Expected Rekor body payload hash mismatch, got: {msg}"
            );
        }
        other => panic!("Expected InvalidSigstoreBundle error, got: {:?}", other),
    }
}

#[test]
fn test_rekor_body_signature_mismatch_rejected() {
    let tarball_bytes = b"rekor body signature mismatch payload";
    let (mut bundle, _) = rnpm_registry::provenance::generate_valid_signed_test_bundle(
        "mismatch-sig-pkg",
        "1.0.0",
        tarball_bytes,
        "org/repo",
        "sha123",
    );

    let rng = ring::rand::SystemRandom::new();
    let rekor_priv =
        rnpm_registry::provenance::decode_base64(TEST_MOCK_REKOR_PRIV_PKCS8_B64).unwrap();
    let rekor_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rekor_priv,
        &rng,
    )
    .unwrap();

    let cert_raw = bundle.verification_material.as_ref().unwrap().certificate.as_ref().unwrap().raw_bytes.clone();
    let payload_bytes = rnpm_registry::provenance::decode_base64(&bundle.dsse_envelope.as_ref().unwrap().payload).unwrap();
    let payload_hash_hex = HEXLOWER.encode(&Sha256::digest(&payload_bytes));

    // Change signature in Rekor body
    let wrong_body_json = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "payloadHash": {
                "algorithm": "sha256",
                "value": payload_hash_hex,
            },
            "signatures": [
                {
                    "signature": "V3Jvbmcgc2lnbmF0dXJl",
                    "verifier": cert_raw,
                }
            ]
        }
    });
    let wrong_body_str = serde_json::to_string(&wrong_body_json).unwrap();
    let wrong_body_b64 = data_encoding::BASE64.encode(wrong_body_str.as_bytes());

    let now = 1700000000i64;
    let set_canonical_json = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        wrong_body_b64, now, REKOR_DEFAULT_LOG_ID, 42
    );
    let rekor_sig = rekor_key_pair
        .sign(&rng, set_canonical_json.as_bytes())
        .unwrap();

    let tlog = &mut bundle.verification_material.as_mut().unwrap().tlog_entries[0];
    tlog.canonicalized_body = Some(wrong_body_b64);
    tlog.inclusion_promise = Some(rnpm_registry::provenance::InclusionPromise {
        signed_entry_timestamp: data_encoding::BASE64.encode(rekor_sig.as_ref()),
    });

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
    let err = verifier
        .verify("mismatch-sig-pkg", &bundle, None, Some(tarball_bytes))
        .unwrap_err();

    match err {
        RegistryError::InvalidSigstoreBundle(msg) => {
            assert!(
                msg.contains("signature mismatch"),
                "Expected Rekor signature mismatch, got: {msg}"
            );
        }
        other => panic!("Expected InvalidSigstoreBundle error, got: {:?}", other),
    }
}

#[test]
fn test_exact_purl_subject_mismatch_rejected() {
    let tarball_bytes = b"exact purl test bytes";
    let (bundle, _) = rnpm_registry::provenance::generate_valid_signed_test_bundle(
        "@scope/my-pkg",
        "1.2.3",
        tarball_bytes,
        "org/my-pkg",
        "sha123",
    );

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();

    // Verify with different version
    let err_ver = verifier
        .verify_package("@scope/my-pkg", Some("2.0.0"), &bundle, None, Some(tarball_bytes))
        .unwrap_err();
    assert!(
        err_ver.to_string().contains("Attestation subject name mismatch"),
        "Expected version mismatch error, got: {err_ver}"
    );

    // Verify with different package name
    let err_pkg = verifier
        .verify_package("@scope/other-pkg", Some("1.2.3"), &bundle, None, Some(tarball_bytes))
        .unwrap_err();
    assert!(
        err_pkg.to_string().contains("Attestation subject name mismatch"),
        "Expected package name mismatch error, got: {err_pkg}"
    );
}

#[test]
fn test_tarball_digest_mismatch_rejected() {
    let tarball_bytes = b"original tarball bytes";
    let (bundle, _) = rnpm_registry::provenance::generate_valid_signed_test_bundle(
        "digest-pkg",
        "1.0.0",
        tarball_bytes,
        "org/repo",
        "sha123",
    );

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
    let corrupted_tarball_bytes = b"corrupted tarball bytes";
    let err = verifier
        .verify("digest-pkg", &bundle, None, Some(corrupted_tarball_bytes))
        .unwrap_err();

    assert!(
        err.to_string().contains("Attestation digest mismatch"),
        "Expected tarball digest mismatch, got: {err}"
    );
}

#[test]
fn test_rekor_string_and_numeric_deserialization() {
    let json_str = r#"{
        "logIndex": "12345",
        "logId": { "keyId": "rekor-key-id" },
        "integratedTime": "1700000000",
        "inclusionPromise": {
            "signedEntryTimestamp": "dGVzdC1zaWc="
        },
        "inclusionProof": {
            "logIndex": "12345",
            "treeSize": "67890",
            "rootHash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "hashes": []
        },
        "canonicalizedBody": "dGVzdC1ib2R5"
    }"#;

    let tlog: TlogEntry = serde_json::from_str(json_str).expect("deserialize string numbers");
    assert_eq!(tlog.log_index, 12345);
    assert_eq!(tlog.integrated_time, 1700000000);
    assert_eq!(tlog.log_id.key_id, "rekor-key-id");
}

#[test]
fn test_keyed_publish_attestation_verified_against_registry_keys() {
    let tarball_bytes = b"keyed attestation tarball";
    let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));

    let mut digest = HashMap::new();
    digest.insert("sha512".to_string(), sha512_hex);

    let purl = "pkg:npm/%40scoped%2Fkeyed-pkg@1.0.0".to_string();
    let statement = InTotoStatement {
        statement_type: "https://in-toto.io/Statement/v1".into(),
        subject: vec![InTotoSubject { name: purl, digest }],
        predicate_type: "https://slsa.dev/provenance/v1".into(),
        predicate: SlsaPredicate {
            builder: Some(SlsaBuilder {
                id: "https://registry.npmjs.org".into(),
            }),
            build_type: Some("https://registry.npmjs.org/attestation/v1".into()),
            invocation: None,
            recipe: None,
            materials: Vec::new(),
            build_definition: None,
            run_details: None,
        },
    };

    let signer = EphemeralSigner::new().unwrap();
    let mut envelope = sign_dsse_envelope(&statement, &signer).unwrap();
    let keyid = "SHA256:custom-registry-key-1";
    envelope.signatures[0].keyid = Some(keyid.to_string());

    let bundle = SigstoreBundle {
        media_type: Some("application/vnd.sigstore.bundle+json;version=0.1".into()),
        verification_material: Some(VerificationMaterial {
            x509_certificate_chain: None,
            certificate: None,
            public_key: Some(PublicKeyHint {
                hint: Some(keyid.to_string()),
                raw_bytes: None,
            }),
            tlog_entries: Vec::new(),
            timestamp_verification_data: None,
        }),
        dsse_envelope: Some(envelope),
    };

    let mut reg_keys = HashMap::new();
    reg_keys.insert(keyid.to_string(), signer.public_key_spki().to_vec());

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_registry_keys(reg_keys);
    let verified = verifier
        .verify_package(
            "@scoped/keyed-pkg",
            Some("1.0.0"),
            &bundle,
            None,
            Some(tarball_bytes),
        )
        .expect("Verification with registry key should succeed");

    assert_eq!(verified.package_name, "@scoped/keyed-pkg");
}

#[test]
fn test_embedded_sigstore_public_good_rekor_and_fulcio_roots() {
    // Verify Rekor default key SPKI hashes to REKOR_DEFAULT_LOG_ID
    let rekor_spki = decode_base64(REKOR_DEFAULT_PUBKEY_SPKI_B64).expect("valid base64 Rekor SPKI");
    let rekor_log_id = HEXLOWER.encode(&Sha256::digest(&rekor_spki));
    assert_eq!(
        rekor_log_id, REKOR_DEFAULT_LOG_ID,
        "Rekor default public key must hash to official logID"
    );

    // Verify P-256 SPKI parsing with ring
    let (_, _, pk_bytes) = rnpm_registry::asn1::parse_spki(&rekor_spki).expect("parse Rekor SPKI");
    assert_eq!(pk_bytes.len(), 65, "P-256 uncompressed public key is 65 bytes");

    // Verify Fulcio root certificates parse as valid X.509
    let c1 = decode_base64(FULCIO_ROOT_CA_1_DER_B64).expect("valid Fulcio Root 1");
    let parsed1 = rnpm_registry::asn1::parse_x509_certificate(&c1).expect("parse Fulcio Root 1");
    assert!(parsed1.not_before < parsed1.not_after, "Fulcio Root 1 validity window");
    assert!(!parsed1.spki_bytes.is_empty(), "Fulcio Root 1 SPKI");

    let c2 = decode_base64(FULCIO_ROOT_CA_2_DER_B64).expect("valid Fulcio Root 2");
    let parsed2 = rnpm_registry::asn1::parse_x509_certificate(&c2).expect("parse Fulcio Root 2");
    assert!(parsed2.not_before < parsed2.not_after, "Fulcio Root 2 validity window");
    assert!(!parsed2.spki_bytes.is_empty(), "Fulcio Root 2 SPKI");

    let ci2 = decode_base64(FULCIO_INTERMEDIATE_CA_2_DER_B64).expect("valid Fulcio Intermediate 2");
    let parsed_i2 =
        rnpm_registry::asn1::parse_x509_certificate(&ci2).expect("parse Fulcio Intermediate 2");
    assert!(parsed_i2.not_before < parsed_i2.not_after, "Fulcio Intermediate 2 validity window");
    assert!(!parsed_i2.spki_bytes.is_empty(), "Fulcio Intermediate 2 SPKI");
}

#[test]
fn test_checkpoint_only_bundle_without_authenticated_set_rejected() {
    let tarball_bytes = b"checkpoint only test payload";
    let (mut bundle, _) = rnpm_registry::provenance::generate_valid_signed_test_bundle(
        "checkpoint-pkg",
        "1.0.0",
        tarball_bytes,
        "org/checkpoint-repo",
        "abcdef1234567890abcdef1234567890abcdef12",
    );

    let tlog = &mut bundle.verification_material.as_mut().unwrap().tlog_entries[0];
    // Remove inclusion promise (SET)
    tlog.inclusion_promise = None;
    // Add mock inclusion proof
    tlog.inclusion_proof = Some(serde_json::json!({
        "logIndex": 42,
        "treeSize": 100,
        "rootHash": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "hashes": [],
        "checkpoint": {
            "envelope": "rekor.sigstore.dev - 12345\n100\n00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"
        }
    }));

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
    let err = verifier
        .verify_package(
            "checkpoint-pkg",
            Some("1.0.0"),
            &bundle,
            None,
            Some(tarball_bytes),
        )
        .unwrap_err();

    match err {
        RegistryError::InvalidSigstoreBundle(msg) => {
            assert!(
                msg.contains("Fulcio certificate validity requires an authenticated signing time")
                    || msg.contains("checkpoint-only bundles without an authenticated timestamp are rejected"),
                "Expected rejection of checkpoint-only bundle without authenticated timestamp, got: {msg}"
            );
        }
        other => panic!("Expected InvalidSigstoreBundle error, got: {other:?}"),
    }
}

#[test]
fn test_rekor_body_unknown_schema_kind_rejected() {
    let tarball_bytes = b"unknown schema payload";
    let (mut bundle, _) = rnpm_registry::provenance::generate_valid_signed_test_bundle(
        "unknown-kind-pkg",
        "1.0.0",
        tarball_bytes,
        "org/repo",
        "sha123",
    );

    let rng = ring::rand::SystemRandom::new();
    let rekor_priv =
        rnpm_registry::provenance::decode_base64(TEST_MOCK_REKOR_PRIV_PKCS8_B64).unwrap();
    let rekor_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rekor_priv,
        &rng,
    )
    .unwrap();

    let cert_raw = bundle.verification_material.as_ref().unwrap().certificate.as_ref().unwrap().raw_bytes.clone();
    let sig_str = bundle.dsse_envelope.as_ref().unwrap().signatures[0].sig.clone();
    let payload_bytes = rnpm_registry::provenance::decode_base64(&bundle.dsse_envelope.as_ref().unwrap().payload).unwrap();
    let payload_hash_hex = HEXLOWER.encode(&Sha256::digest(&payload_bytes));

    let unsupported_body_json = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "unsupported_rekor_kind",
        "spec": {
            "payloadHash": {
                "algorithm": "sha256",
                "value": payload_hash_hex,
            },
            "signatures": [{ "signature": sig_str, "verifier": cert_raw }]
        }
    });
    let body_str = serde_json::to_string(&unsupported_body_json).unwrap();
    let body_b64 = data_encoding::BASE64.encode(body_str.as_bytes());

    let now = 1700000000i64;
    let set_canonical_json = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        body_b64, now, REKOR_DEFAULT_LOG_ID, 42
    );
    let rekor_sig = rekor_key_pair
        .sign(&rng, set_canonical_json.as_bytes())
        .unwrap();

    let tlog = &mut bundle.verification_material.as_mut().unwrap().tlog_entries[0];
    tlog.canonicalized_body = Some(body_b64);
    tlog.inclusion_promise = Some(rnpm_registry::provenance::InclusionPromise {
        signed_entry_timestamp: data_encoding::BASE64.encode(rekor_sig.as_ref()),
    });

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
    let err = verifier
        .verify_package("unknown-kind-pkg", Some("1.0.0"), &bundle, None, Some(tarball_bytes))
        .unwrap_err();

    match err {
        RegistryError::InvalidSigstoreBundle(msg) => {
            assert!(
                msg.contains("Unsupported Rekor entry kind: 'unsupported_rekor_kind'"),
                "Expected Unsupported Rekor entry kind error, got: {msg}"
            );
        }
        other => panic!("Expected InvalidSigstoreBundle error, got: {other:?}"),
    }
}

#[test]
fn test_rekor_body_missing_binding_fields_rejected() {
    let tarball_bytes = b"missing fields payload";
    let (bundle_base, _) = rnpm_registry::provenance::generate_valid_signed_test_bundle(
        "missing-fields-pkg",
        "1.0.0",
        tarball_bytes,
        "org/repo",
        "sha123",
    );

    let rng = ring::rand::SystemRandom::new();
    let rekor_priv =
        rnpm_registry::provenance::decode_base64(TEST_MOCK_REKOR_PRIV_PKCS8_B64).unwrap();
    let rekor_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rekor_priv,
        &rng,
    )
    .unwrap();

    let cert_raw = bundle_base.verification_material.as_ref().unwrap().certificate.as_ref().unwrap().raw_bytes.clone();
    let sig_str = bundle_base.dsse_envelope.as_ref().unwrap().signatures[0].sig.clone();
    let payload_bytes = rnpm_registry::provenance::decode_base64(&bundle_base.dsse_envelope.as_ref().unwrap().payload).unwrap();
    let payload_hash_hex = HEXLOWER.encode(&Sha256::digest(&payload_bytes));

    // Case 1: Missing payloadHash
    {
        let mut bundle = bundle_base.clone();
        let body_json = serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": {
                "signatures": [{ "signature": &sig_str, "verifier": &cert_raw }]
            }
        });
        let body_str = serde_json::to_string(&body_json).unwrap();
        let body_b64 = data_encoding::BASE64.encode(body_str.as_bytes());
        let now = 1700000000i64;
        let set_canonical_json = format!(
            r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
            body_b64, now, REKOR_DEFAULT_LOG_ID, 42
        );
        let rekor_sig = rekor_key_pair.sign(&rng, set_canonical_json.as_bytes()).unwrap();
        let tlog = &mut bundle.verification_material.as_mut().unwrap().tlog_entries[0];
        tlog.canonicalized_body = Some(body_b64);
        tlog.inclusion_promise = Some(rnpm_registry::provenance::InclusionPromise {
            signed_entry_timestamp: data_encoding::BASE64.encode(rekor_sig.as_ref()),
        });

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
        let err = verifier
            .verify_package("missing-fields-pkg", Some("1.0.0"), &bundle, None, Some(tarball_bytes))
            .unwrap_err();
        assert!(matches!(err, RegistryError::InvalidSigstoreBundle(msg) if msg.contains("Missing or empty payloadHash")));
    }

    // Case 2: Missing signatures
    {
        let mut bundle = bundle_base.clone();
        let body_json = serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": {
                "payloadHash": { "algorithm": "sha256", "value": &payload_hash_hex },
                "signatures": []
            }
        });
        let body_str = serde_json::to_string(&body_json).unwrap();
        let body_b64 = data_encoding::BASE64.encode(body_str.as_bytes());
        let now = 1700000000i64;
        let set_canonical_json = format!(
            r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
            body_b64, now, REKOR_DEFAULT_LOG_ID, 42
        );
        let rekor_sig = rekor_key_pair.sign(&rng, set_canonical_json.as_bytes()).unwrap();
        let tlog = &mut bundle.verification_material.as_mut().unwrap().tlog_entries[0];
        tlog.canonicalized_body = Some(body_b64);
        tlog.inclusion_promise = Some(rnpm_registry::provenance::InclusionPromise {
            signed_entry_timestamp: data_encoding::BASE64.encode(rekor_sig.as_ref()),
        });

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
        let err = verifier
            .verify_package("missing-fields-pkg", Some("1.0.0"), &bundle, None, Some(tarball_bytes))
            .unwrap_err();
        assert!(matches!(err, RegistryError::InvalidSigstoreBundle(msg) if msg.contains("Missing or empty signatures")));
    }

    // Case 3: Missing verifier
    {
        let mut bundle = bundle_base.clone();
        let body_json = serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": {
                "payloadHash": { "algorithm": "sha256", "value": &payload_hash_hex },
                "signatures": [{ "signature": &sig_str }]
            }
        });
        let body_str = serde_json::to_string(&body_json).unwrap();
        let body_b64 = data_encoding::BASE64.encode(body_str.as_bytes());
        let now = 1700000000i64;
        let set_canonical_json = format!(
            r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
            body_b64, now, REKOR_DEFAULT_LOG_ID, 42
        );
        let rekor_sig = rekor_key_pair.sign(&rng, set_canonical_json.as_bytes()).unwrap();
        let tlog = &mut bundle.verification_material.as_mut().unwrap().tlog_entries[0];
        tlog.canonicalized_body = Some(body_b64);
        tlog.inclusion_promise = Some(rnpm_registry::provenance::InclusionPromise {
            signed_entry_timestamp: data_encoding::BASE64.encode(rekor_sig.as_ref()),
        });

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
        let err = verifier
            .verify_package("missing-fields-pkg", Some("1.0.0"), &bundle, None, Some(tarball_bytes))
            .unwrap_err();
        assert!(matches!(err, RegistryError::InvalidSigstoreBundle(msg) if msg.contains("Missing or empty verifier")));
    }
}

#[test]
fn test_rekor_body_hashedrekord_schema_accepted() {
    let tarball_bytes = b"hashedrekord valid payload";
    let (mut bundle, _) = rnpm_registry::provenance::generate_valid_signed_test_bundle(
        "hashedrekord-pkg",
        "1.0.0",
        tarball_bytes,
        "org/repo",
        "sha123",
    );

    let rng = ring::rand::SystemRandom::new();
    let rekor_priv =
        rnpm_registry::provenance::decode_base64(TEST_MOCK_REKOR_PRIV_PKCS8_B64).unwrap();
    let rekor_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rekor_priv,
        &rng,
    )
    .unwrap();

    let cert_raw = bundle.verification_material.as_ref().unwrap().certificate.as_ref().unwrap().raw_bytes.clone();
    let sig_str = bundle.dsse_envelope.as_ref().unwrap().signatures[0].sig.clone();
    let payload_bytes = rnpm_registry::provenance::decode_base64(&bundle.dsse_envelope.as_ref().unwrap().payload).unwrap();
    let payload_hash_hex = HEXLOWER.encode(&Sha256::digest(&payload_bytes));

    let hashedrekord_body_json = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": payload_hash_hex,
                }
            },
            "signature": {
                "content": sig_str,
                "publicKey": {
                    "content": cert_raw,
                }
            }
        }
    });
    let body_str = serde_json::to_string(&hashedrekord_body_json).unwrap();
    let body_b64 = data_encoding::BASE64.encode(body_str.as_bytes());

    let now = 1700000000i64;
    let set_canonical_json = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        body_b64, now, REKOR_DEFAULT_LOG_ID, 42
    );
    let rekor_sig = rekor_key_pair
        .sign(&rng, set_canonical_json.as_bytes())
        .unwrap();

    let tlog = &mut bundle.verification_material.as_mut().unwrap().tlog_entries[0];
    tlog.canonicalized_body = Some(body_b64);
    tlog.inclusion_promise = Some(rnpm_registry::provenance::InclusionPromise {
        signed_entry_timestamp: data_encoding::BASE64.encode(rekor_sig.as_ref()),
    });

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();
    let res = verifier.verify_package("hashedrekord-pkg", Some("1.0.0"), &bundle, None, Some(tarball_bytes));
    assert!(res.is_ok(), "hashedrekord schema should be successfully verified: {:?}", res.err());
}

#[test]
fn test_keyed_attestation_empty_registry_keys_unsafe_fallback_rejected() {
    let tarball_bytes = b"keyed attestation payload";
    let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));
    let signer = EphemeralSigner::new().unwrap();

    let mut digest = HashMap::new();
    digest.insert("sha512".to_string(), sha512_hex);
    let statement = InTotoStatement {
        statement_type: "https://in-toto.io/Statement/v1".into(),
        subject: vec![InTotoSubject {
            name: "pkg:npm/keyed-fallback-pkg@1.0.0".into(),
            digest,
        }],
        predicate_type: "https://slsa.dev/provenance/v1".into(),
        predicate: SlsaPredicate::default(),
    };
    let mut envelope = sign_dsse_envelope(&statement, &signer).unwrap();
    let keyid = "SHA256:untrusted-attacker-key";
    envelope.signatures[0].keyid = Some(keyid.to_string());

    let bundle = SigstoreBundle {
        media_type: Some("application/vnd.sigstore.bundle+json;version=0.1".into()),
        verification_material: Some(VerificationMaterial {
            x509_certificate_chain: None,
            certificate: None,
            public_key: Some(PublicKeyHint {
                hint: Some(keyid.to_string()),
                raw_bytes: Some(data_encoding::BASE64.encode(signer.public_key_spki())),
            }),
            tlog_entries: Vec::new(),
            timestamp_verification_data: None,
        }),
        dsse_envelope: Some(envelope),
    };

    // Verifier with EMPTY registry_keys (attacker supplies own key in bundle.verificationMaterial.publicKey.raw_bytes)
    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
    let err = verifier
        .verify_package("keyed-fallback-pkg", Some("1.0.0"), &bundle, None, Some(tarball_bytes))
        .unwrap_err();

    match err {
        RegistryError::InvalidSignature(msg) => {
            assert!(
                msg.contains("No corresponding public key found for attestation keyid"),
                "Unsafe fallback must be eliminated; expected missing key error, got: {msg}"
            );
        }
        other => panic!("Expected InvalidSignature error, got: {other:?}"),
    }
}

#[test]
fn test_keyed_attestation_expired_registry_key_rejected() {
    let tarball_bytes = b"keyed attestation expired payload";
    let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));
    let signer = EphemeralSigner::new().unwrap();

    let mut digest = HashMap::new();
    digest.insert("sha512".to_string(), sha512_hex);
    let statement = InTotoStatement {
        statement_type: "https://in-toto.io/Statement/v1".into(),
        subject: vec![InTotoSubject {
            name: "pkg:npm/expired-key-pkg@1.0.0".into(),
            digest,
        }],
        predicate_type: "https://slsa.dev/provenance/v1".into(),
        predicate: SlsaPredicate::default(),
    };
    let mut envelope = sign_dsse_envelope(&statement, &signer).unwrap();
    let keyid = "SHA256:expired-registry-key";
    envelope.signatures[0].keyid = Some(keyid.to_string());

    let bundle = SigstoreBundle {
        media_type: Some("application/vnd.sigstore.bundle+json;version=0.1".into()),
        verification_material: Some(VerificationMaterial {
            x509_certificate_chain: None,
            certificate: None,
            public_key: Some(PublicKeyHint {
                hint: Some(keyid.to_string()),
                raw_bytes: None,
            }),
            tlog_entries: Vec::new(),
            timestamp_verification_data: None,
        }),
        dsse_envelope: Some(envelope),
    };

    let mut reg_keys = HashMap::new();
    reg_keys.insert(keyid.to_string(), signer.public_key_spki().to_vec());

    let mut expiries = HashMap::new();
    // Expired in 2020
    expiries.insert(keyid.to_string(), ("2020-01-01T00:00:00Z".to_string(), 1577836800000i64));

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny)
        .with_registry_keys(reg_keys)
        .with_registry_key_expiries(expiries);

    let err = verifier
        .verify_package("expired-key-pkg", Some("1.0.0"), &bundle, None, Some(tarball_bytes))
        .unwrap_err();

    match err {
        RegistryError::InvalidSignature(msg) => {
            assert!(
                msg.contains("expired"),
                "Expected expired key error, got: {msg}"
            );
        }
        other => panic!("Expected InvalidSignature error, got: {other:?}"),
    }
}

#[test]
fn test_strict_versioned_purl_subject_matching_rules() {
    let tarball_bytes = b"purl matching test bytes";
    let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));
    let bundle = make_test_bundle_with_subject(
        "pkg:npm/%40my-scope/foo@1.2.3",
        &sha512_hex,
        "org/repo",
        "sha123",
    );

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).with_test_mock_roots();

    // 1. Scoped package verified with exact PURL pkg:npm/%40my-scope/foo@1.2.3 -> SUCCEEDS
    let res = verifier.verify_package("@my-scope/foo", Some("1.2.3"), &bundle, None, Some(tarball_bytes));
    assert!(res.is_ok(), "Exact scoped PURL verification should pass: {:?}", res.err());

    // 2. Unscoped package name matching against scoped subject -> REJECTED
    let err_unscoped = verifier
        .verify_package("foo", Some("1.2.3"), &bundle, None, Some(tarball_bytes))
        .unwrap_err();
    assert!(matches!(err_unscoped, RegistryError::ProvenanceVerificationFailed(msg) if msg.contains("Attestation subject name mismatch")));

    // 3. Subject missing version '@<version>' -> REJECTED
    let unversioned_bundle = make_test_bundle_with_subject(
        "pkg:npm/%40my-scope/foo",
        &sha512_hex,
        "org/repo",
        "sha123",
    );
    let err_unversioned = verifier
        .verify_package("@my-scope/foo", Some("1.2.3"), &unversioned_bundle, None, Some(tarball_bytes))
        .unwrap_err();
    assert!(matches!(err_unversioned, RegistryError::ProvenanceVerificationFailed(msg) if msg.contains("Attestation subject name mismatch")));

    // 4. Legacy .tgz subject without PURL -> REJECTED
    let tgz_bundle = make_test_bundle_with_subject(
        "foo-1.2.3.tgz",
        &sha512_hex,
        "org/repo",
        "sha123",
    );
    let err_tgz = verifier
        .verify_package("@my-scope/foo", Some("1.2.3"), &tgz_bundle, None, Some(tarball_bytes))
        .unwrap_err();
    assert!(matches!(err_tgz, RegistryError::ProvenanceVerificationFailed(msg) if msg.contains("Attestation subject name mismatch")));
}

#[test]
fn test_rekor_response_parser_verification_shape() {
    let rekor_resp = serde_json::json!({
        "65d4b83b": {
            "logIndex": 42,
            "logID": "c0d3cafe",
            "integratedTime": 1700000000,
            "body": "eyJraW5kIjoiZHNzZSJ9",
            "verification": {
                "signedEntryTimestamp": "c2lnbmVkLXRpbWVzdGFtcA==",
                "inclusionProof": {
                    "logIndex": 42,
                    "treeSize": 100,
                    "rootHash": "11223344",
                    "hashes": ["aabbcc"],
                    "checkpoint": "checkpoint-data"
                }
            }
        }
    });

    let tlog = rnpm_registry::provenance::parse_rekor_log_entry_json(&rekor_resp).unwrap();
    assert_eq!(tlog.log_index, 42);
    assert_eq!(tlog.log_id.key_id, "c0d3cafe");
    assert_eq!(tlog.integrated_time, 1700000000);
    assert_eq!(
        tlog.inclusion_promise.as_ref().unwrap().signed_entry_timestamp,
        "c2lnbmVkLXRpbWVzdGFtcA=="
    );
    assert!(tlog.inclusion_proof.is_some());
    assert_eq!(tlog.canonicalized_body.as_deref(), Some("eyJraW5kIjoiZHNzZSJ9"));

    // Also test fallback to top-level fields
    let rekor_resp_fallback = serde_json::json!({
        "65d4b83c": {
            "logIndex": 43,
            "logID": "c0d3cafe",
            "integratedTime": 1700000001,
            "body": "eyJraW5kIjoiZHNzZSJ9",
            "signedEntryTimestamp": "ZmFsbGJhY2stdGltZXN0YW1w",
            "inclusionProof": {
                "logIndex": 43,
                "treeSize": 101,
                "rootHash": "55667788"
            }
        }
    });
    let tlog_fb = rnpm_registry::provenance::parse_rekor_log_entry_json(&rekor_resp_fallback).unwrap();
    assert_eq!(
        tlog_fb.inclusion_promise.as_ref().unwrap().signed_entry_timestamp,
        "ZmFsbGJhY2stdGltZXN0YW1w"
    );
    assert!(tlog_fb.inclusion_proof.is_some());
}

#[test]
fn test_publish_sigstore_attachment_data_is_raw_json_string() {
    let bundle = SigstoreBundle {
        media_type: Some("application/vnd.sigstore.bundle+json;version=0.1".into()),
        verification_material: None,
        dsse_envelope: None,
    };
    let bundle_serialized = serde_json::to_string(&bundle).unwrap();

    let manifest = serde_json::json!({
        "name": "publish-raw-json-pkg",
        "version": "1.0.0"
    });
    let tarball = rnpm_registry::PublishTarballData {
        filename: "publish-raw-json-pkg-1.0.0.tgz",
        bytes: b"tarball bytes",
        integrity: "sha512-test",
        shasum: "shasum-test",
    };
    let reg_url = reqwest::Url::parse("https://registry.npmjs.org").unwrap();

    let opts = rnpm_registry::PublishPayloadOptions {
        name: "publish-raw-json-pkg",
        version: "1.0.0",
        description: Some("test package"),
        tag: "latest",
        access: None,
        manifest: &manifest,
        tarball,
        registry_url: &reg_url,
        provenance_attestation: None,
        provenance_bundle: Some(&bundle),
    };

    let payload = rnpm_registry::create_publish_payload(&opts);
    let att = &payload["_attachments"]["publish-raw-json-pkg-1.0.0.sigstore"];

    assert!(!att.is_null());
    assert_eq!(
        att["content_type"].as_str().unwrap(),
        "application/vnd.sigstore.bundle+json;version=0.1"
    );

    // CRITICAL: Attachment data MUST be a raw JSON string (matching libnpmpublish/lib/publish.js:169), NOT base64-encoded!
    let data_str = att["data"].as_str().expect("data must be a JSON string");
    assert_eq!(data_str, bundle_serialized);
    assert_eq!(att["length"].as_u64().unwrap(), bundle_serialized.len() as u64);
}
