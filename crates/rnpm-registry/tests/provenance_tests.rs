use data_encoding::{BASE64, HEXLOWER};
use sha2::{Digest, Sha512};
use std::collections::HashMap;

use rnpm_registry::metadata::AbbreviatedPackageMetadata;
use rnpm_registry::provenance::{
    format_registry_signature_payload, normalize_repository_url, AttestationItem,
    AttestationResponse, DsseEnvelope, DsseSignature, InTotoStatement, InTotoSubject,
    ProvenancePolicy, ProvenanceVerifier, SigstoreBundle, SlsaBuilder, SlsaConfigSource,
    SlsaInvocation, SlsaPredicate, TlogEntry, VerificationMaterial, X509Certificate,
    X509CertificateChain, NPM_REGISTRY_KEYID,
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

    let statement_bytes = serde_json::to_vec(&statement).unwrap();
    let payload_b64 = BASE64.encode(&statement_bytes);

    SigstoreBundle {
        media_type: Some("application/vnd.dev.sigstore.bundle+json;version=0.1".into()),
        verification_material: Some(VerificationMaterial {
            x509_certificate_chain: Some(X509CertificateChain {
                certificates: vec![X509Certificate {
                    raw_bytes: BASE64.encode(b"mock-certificate-bytes"),
                }],
            }),
            certificate: None,
            tlog_entries: vec![TlogEntry {
                log_index: 998877,
                log_id: rnpm_registry::provenance::LogId {
                    key_id: "test-log-key".into(),
                },
                integrated_time: 1700000000,
                inclusion_promise: None,
                inclusion_proof: None,
                canonicalized_body: None,
            }],
            timestamp_verification_data: None,
        }),
        dsse_envelope: Some(DsseEnvelope {
            payload_type: "application/vnd.in-toto+json".into(),
            payload: payload_b64,
            signatures: vec![DsseSignature {
                keyid: Some("key-1".into()),
                sig: BASE64.encode(b"sig-bytes"),
            }],
        }),
    }
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
    });

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

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
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

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
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
