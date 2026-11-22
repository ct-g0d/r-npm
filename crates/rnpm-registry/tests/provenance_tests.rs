use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;

use rnpm_registry::metadata::AbbreviatedPackageMetadata;
use rnpm_registry::provenance::{
    assemble_sigstore_bundle, format_registry_signature_payload, normalize_repository_url,
    sign_dsse_envelope, AttestationItem, AttestationResponse, EphemeralSigner, InTotoStatement,
    InTotoSubject, LogId, ProvenancePolicy, ProvenanceVerifier, PublicKeyHint, SigstoreBundle,
    SlsaBuilder, SlsaConfigSource, SlsaInvocation, SlsaPredicate, TlogEntry,
    VerificationMaterial, NPM_REGISTRY_KEYID, REKOR_DEFAULT_LOG_ID,
    TEST_MOCK_CA_PRIV_PKCS8_B64, TEST_MOCK_REKOR_PRIV_PKCS8_B64,
};
use rnpm_registry::RegistryError;

fn make_test_bundle(
    pkg_name: &str,
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
            name: format!("{pkg_name}-1.0.0.tgz"),
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
        "cors",
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
