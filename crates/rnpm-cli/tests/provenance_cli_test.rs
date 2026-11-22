use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use data_encoding::{BASE64, BASE64_NOPAD, HEXLOWER};
use rnpm_registry::provenance::{
    assemble_sigstore_bundle, build_slsa_v1_statement, sign_dsse_envelope,
    CiEnvironmentInfo, EphemeralSigner, LogId, ProvenancePolicy, ProvenanceVerifier,
    SigstoreBundle, TlogEntry, REKOR_DEFAULT_LOG_ID,
};
use sha2::{Digest, Sha512};

#[derive(Debug, Clone)]
struct RecordedReq {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RecordedReq {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

struct TestMockServer {
    addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    pub requests: Arc<Mutex<Vec<RecordedReq>>>,
}

impl TestMockServer {
    async fn start<F>(handler: F) -> Self
    where
        F: Fn(&RecordedReq) -> (u16, Vec<(&'static str, String)>, Vec<u8>) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(handler);

        let reqs = requests.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => {
                        break;
                    }
                    accept_res = listener.accept() => {
                        if let Ok((mut stream, _)) = accept_res {
                            let handler_clone = handler.clone();
                            let reqs_clone = reqs.clone();
                            tokio::spawn(async move {
                                let mut buffer = Vec::new();
                                let mut temp = [0u8; 4096];

                                'conn: loop {
                                    let mut header_end = None;
                                    let mut content_len = 0;

                                    loop {
                                        if header_end.is_none() {
                                            if let Some(idx) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                                                header_end = Some(idx + 4);
                                                let header_text = String::from_utf8_lossy(&buffer[..idx]);
                                                for line in header_text.lines() {
                                                    if let Some((k, v)) = line.split_once(':') {
                                                        if k.trim().eq_ignore_ascii_case("content-length") {
                                                            content_len = v.trim().parse::<usize>().unwrap_or(0);
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if let Some(end) = header_end {
                                            if buffer.len() >= end + content_len {
                                                break;
                                            }
                                        }

                                        let n = match stream.read(&mut temp).await {
                                            Ok(0) => break 'conn,
                                            Ok(n) => n,
                                            Err(_) => break 'conn,
                                        };
                                        buffer.extend_from_slice(&temp[..n]);
                                    }

                                    let Some(end) = header_end else { break 'conn; };
                                    let header_text = String::from_utf8_lossy(&buffer[..end - 4]);
                                    let mut lines = header_text.lines();
                                    let req_line = lines.next().unwrap_or_default();
                                    let parts: Vec<&str> = req_line.split_whitespace().collect();
                                    let method = parts.first().copied().unwrap_or("GET").to_string();
                                    let full_path = parts.get(1).copied().unwrap_or("/").to_string();
                                    let (path, query) = match full_path.split_once('?') {
                                        Some((p, q)) => (p.to_string(), q.to_string()),
                                        None => (full_path, String::new()),
                                    };

                                    let mut headers = Vec::new();
                                    for line in lines {
                                        if let Some((k, v)) = line.split_once(':') {
                                            headers.push((k.trim().to_string(), v.trim().to_string()));
                                        }
                                    }

                                    let body = buffer[end..end + content_len].to_vec();
                                    buffer.drain(..end + content_len);

                                    let req = RecordedReq {
                                        method,
                                        path,
                                        query,
                                        headers,
                                        body,
                                    };

                                    reqs_clone.lock().await.push(req.clone());

                                    let (status, resp_headers, resp_body) = handler_clone(&req);
                                    let status_text = match status {
                                        200 => "OK",
                                        201 => "Created",
                                        400 => "Bad Request",
                                        401 => "Unauthorized",
                                        403 => "Forbidden",
                                        404 => "Not Found",
                                        _ => "Response",
                                    };

                                    let mut resp = format!(
                                        "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\n",
                                        resp_body.len()
                                    );
                                    for (k, v) in resp_headers {
                                        resp.push_str(&format!("{k}: {v}\r\n"));
                                    }
                                    resp.push_str("\r\n");

                                    if stream.write_all(resp.as_bytes()).await.is_err() { break 'conn; }
                                    if stream.write_all(&resp_body).await.is_err() { break 'conn; }
                                    if stream.flush().await.is_err() { break 'conn; }
                                }
                            });
                        }
                    }
                }
            }
        });

        TestMockServer {
            addr,
            shutdown: Some(tx),
            requests,
        }
    }
}

impl Drop for TestMockServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

fn rnpm_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rnpm"))
}

fn isolated_rnpm(dir: &std::path::Path) -> Command {
    let mut cmd = Command::new(rnpm_bin());
    let fake_home = dir.join(".fake_home");
    let fake_appdata = fake_home.join("AppData").join("Roaming");
    let fake_localappdata = fake_home.join("AppData").join("Local");
    let fake_global = dir.join(".fake_global");
    let _ = std::fs::create_dir_all(&fake_home);
    let _ = std::fs::create_dir_all(&fake_appdata);
    let _ = std::fs::create_dir_all(&fake_localappdata);
    let _ = std::fs::create_dir_all(&fake_global);

    cmd.current_dir(dir);
    cmd.env("USERPROFILE", &fake_home);
    cmd.env("HOME", &fake_home);
    cmd.env("APPDATA", &fake_appdata);
    cmd.env("LOCALAPPDATA", &fake_localappdata);
    cmd.env("PREFIX", &fake_global);
    cmd.env("NO_PROXY", "127.0.0.1,localhost");
    cmd.env_remove("HTTP_PROXY");
    cmd.env_remove("HTTPS_PROXY");
    cmd.env_remove("ALL_PROXY");
    cmd.env_remove("http_proxy");
    cmd.env_remove("https_proxy");
    cmd.env_remove("all_proxy");
    cmd
}

fn generate_valid_signed_test_bundle(
    pkg: &str,
    version: &str,
    tarball_bytes: &[u8],
    repo: &str,
    commit: &str,
) -> SigstoreBundle {
    let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));
    let signer = EphemeralSigner::new().unwrap();

    let ci = CiEnvironmentInfo {
        ci_name: "GitHub Actions".into(),
        server_url: "https://github.com".into(),
        repository: repo.into(),
        commit_sha: commit.into(),
        workflow_path: ".github/workflows/release.yml".into(),
        workflow_ref: "refs/heads/main".into(),
        ..Default::default()
    };

    let statement = build_slsa_v1_statement(pkg, version, &sha512_hex, &ci);
    let envelope = sign_dsse_envelope(&statement, &signer).unwrap();

    let now = 1700000000i64;
    let fulcio_exts = [
        (
            rnpm_registry::asn1::OID_FULCIO_ISSUER,
            "https://token.actions.githubusercontent.com",
        ),
        (
            rnpm_registry::asn1::OID_FULCIO_GITHUB_WORKFLOW_REPOSITORY,
            repo,
        ),
        (rnpm_registry::asn1::OID_FULCIO_RUN_COMMIT_SHA, commit),
    ];

    let cert_der = rnpm_registry::asn1::create_test_x509_certificate(
        "test-signer",
        "sigstore",
        signer.public_key_uncompressed(),
        Some("https://github.com/actions/runner"),
        &fulcio_exts,
        now - 60,
        now + 600,
        &|tbs| signer.sign(tbs).unwrap(),
    );

    let tlog_entry = TlogEntry {
        log_index: 42,
        log_id: LogId {
            key_id: REKOR_DEFAULT_LOG_ID.into(),
        },
        integrated_time: now,
        inclusion_promise: None,
        inclusion_proof: None,
        canonicalized_body: Some(BASE64.encode(b"canonical-body")),
    };

    assemble_sigstore_bundle(envelope, &cert_der, tlog_entry)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_publish_provenance_dry_run_outside_ci_fails() {
    let dir = tempdir().unwrap();
    let pkg_json = r#"{
        "name": "test-outside-ci-pkg",
        "version": "1.0.0",
        "description": "test provenance dry run outside ci"
    }"#;
    std::fs::write(dir.path().join("package.json"), pkg_json).unwrap();

    let mut cmd = isolated_rnpm(dir.path());
    cmd.env_remove("GITHUB_ACTIONS");
    cmd.env_remove("GITLAB_CI");
    cmd.env_remove("SIGSTORE_ID_TOKEN");
    cmd.env_remove("ACTIONS_ID_TOKEN_REQUEST_URL");
    cmd.args(["publish", "--provenance", "--dry-run"]);

    let output = tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap();
    assert!(
        !output.status.success(),
        "publish --provenance --dry-run outside CI must fail!"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Automatic provenance generation not supported for provider: null")
            || stderr.contains("EUSAGE"),
        "stderr should mention unsupported provider outside CI, got:\n{stderr}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_publish_provenance_full_generation_and_cryptographic_verification() {
    let server = TestMockServer::start(|req| {
        if req.path == "/oidc-token" {
            let header_b64 = BASE64_NOPAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
            let payload_b64 = BASE64_NOPAD.encode(
                b"{\"sub\":\"repo:test-org/prov-pkg:ref:refs/heads/main\",\"iss\":\"https://token.actions.githubusercontent.com\"}",
            );
            let sig_b64 = BASE64_NOPAD.encode(b"dummy-sig");
            let jwt = format!("{header_b64}.{payload_b64}.{sig_b64}");
            let body = serde_json::json!({ "value": jwt });
            return (
                200,
                vec![("Content-Type", "application/json".into())],
                serde_json::to_vec(&body).unwrap(),
            );
        }

        if req.path == "/api/v2/signingCert" {
            let body_json = req.json();
            let pubkey_pem = body_json["publicKeyRequest"]["publicKey"]["content"]
                .as_str()
                .unwrap_or_default();
            let spki = rnpm_registry::provenance::decode_pem_to_der(pubkey_pem).unwrap();
            let (_, _, pk_bytes) = rnpm_registry::asn1::parse_spki(&spki).unwrap();

            let now = 1700000000i64;
            let fulcio_exts = [
                (
                    rnpm_registry::asn1::OID_FULCIO_ISSUER,
                    "https://token.actions.githubusercontent.com",
                ),
                (
                    rnpm_registry::asn1::OID_FULCIO_GITHUB_WORKFLOW_REPOSITORY,
                    "test-org/prov-pkg",
                ),
                (
                    rnpm_registry::asn1::OID_FULCIO_RUN_COMMIT_SHA,
                    "abcdef1234567890abcdef1234567890abcdef12",
                ),
            ];

            let cert_der = rnpm_registry::asn1::create_test_x509_certificate(
                "test-subject",
                "sigstore",
                &pk_bytes,
                Some("https://github.com/test-org/prov-pkg"),
                &fulcio_exts,
                now - 60,
                now + 600,
                &|tbs| {
                    let s = EphemeralSigner::new().unwrap();
                    s.sign(tbs).unwrap()
                },
            );

            let cert_pem = format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                BASE64.encode(&cert_der)
            );
            let resp = serde_json::json!({
                "signedCertificateEmbeddedSct": {
                    "chain": {
                        "certificates": [cert_pem]
                    }
                }
            });
            return (
                200,
                vec![("Content-Type", "application/json".into())],
                serde_json::to_vec(&resp).unwrap(),
            );
        }

        if req.path == "/api/v1/log/entries" {
            let resp = serde_json::json!({
                "entry-uuid-1": {
                    "logIndex": 4242,
                    "logID": REKOR_DEFAULT_LOG_ID,
                    "integratedTime": 1700000000,
                    "body": BASE64.encode(b"canonical-body"),
                    "inclusionPromise": {
                        "signedEntryTimestamp": ""
                    }
                }
            });
            return (
                201,
                vec![("Content-Type", "application/json".into())],
                serde_json::to_vec(&resp).unwrap(),
            );
        }

        if req.path == "/prov-pkg" {
            if req.method == "GET" {
                return (
                    404,
                    vec![("Content-Type", "application/json".into())],
                    b"{\"error\": \"not found\"}".to_vec(),
                );
            }
            if req.method == "PUT" {
                return (
                    201,
                    vec![("Content-Type", "application/json".into())],
                    b"{\"ok\": true}".to_vec(),
                );
            }
        }

        (404, vec![], b"not found".to_vec())
    })
    .await;

    let dir = tempdir().unwrap();
    let pkg_json = r#"{
        "name": "prov-pkg",
        "version": "1.0.0",
        "description": "test provenance generation publish"
    }"#;
    std::fs::write(dir.path().join("package.json"), pkg_json).unwrap();

    let npmrc = format!(
        "registry=http://127.0.0.1:{}/\n//127.0.0.1:{}/:_authToken=test-token\n",
        server.addr.port(),
        server.addr.port()
    );
    std::fs::write(dir.path().join(".npmrc"), npmrc).unwrap();

    let mut cmd = isolated_rnpm(dir.path());
    cmd.env("GITHUB_ACTIONS", "true");
    cmd.env("GITHUB_SERVER_URL", "https://github.com");
    cmd.env("GITHUB_REPOSITORY", "test-org/prov-pkg");
    cmd.env(
        "GITHUB_SHA",
        "abcdef1234567890abcdef1234567890abcdef12",
    );
    cmd.env("GITHUB_REF", "refs/heads/main");
    cmd.env(
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        format!("http://127.0.0.1:{}/oidc-token", server.addr.port()),
    );
    cmd.env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "mock-gha-token");
    cmd.env(
        "SIGSTORE_FULCIO_URL",
        format!("http://127.0.0.1:{}", server.addr.port()),
    );
    cmd.env(
        "SIGSTORE_REKOR_URL",
        format!("http://127.0.0.1:{}", server.addr.port()),
    );
    cmd.args(["publish", "--provenance"]);

    let output = tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "Publish with --provenance failed:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );

    // Verify mock server received the requests
    let reqs = server.requests.lock().await;
    let oidc_req = reqs
        .iter()
        .find(|r| r.path == "/oidc-token" && r.query.contains("audience=sigstore"));
    assert!(
        oidc_req.is_some(),
        "Expected OIDC token request with audience=sigstore"
    );

    let fulcio_req = reqs.iter().find(|r| r.path == "/api/v2/signingCert");
    assert!(fulcio_req.is_some(), "Expected Fulcio cert request");

    let rekor_req = reqs.iter().find(|r| r.path == "/api/v1/log/entries");
    assert!(rekor_req.is_some(), "Expected Rekor entry request");

    let put_req = reqs
        .iter()
        .find(|r| r.path == "/prov-pkg" && r.method == "PUT");
    assert!(put_req.is_some(), "Expected PUT /prov-pkg publish request");

    // Cryptographically verify the attached provenance bundle!
    let put_json = put_req.unwrap().json();
    let version_entry = &put_json["versions"]["1.0.0"];
    let attestation_bundle_val = &version_entry["dist"]["attestations"]["bundle"];
    assert!(
        !attestation_bundle_val.is_null(),
        "dist.attestations.bundle must be present in published payload"
    );

    let bundle: SigstoreBundle = serde_json::from_value(attestation_bundle_val.clone()).unwrap();

    // Verify tarball bytes from attachment
    let tarball_b64 = put_json["_attachments"]["prov-pkg-1.0.0.tgz"]["data"]
        .as_str()
        .unwrap();
    let tarball_bytes = BASE64.decode(tarball_b64.as_bytes()).unwrap();

    let verifier = ProvenanceVerifier::new(ProvenancePolicy::RequireRepository {
        expected_repository: "test-org/prov-pkg".into(),
    });
    let verified = verifier
        .verify("prov-pkg", &bundle, None, Some(&tarball_bytes))
        .unwrap();

    assert_eq!(verified.package_name, "prov-pkg");
    assert_eq!(
        verified.build.source_repository.as_deref(),
        Some("test-org/prov-pkg")
    );
    assert_eq!(
        verified.build.commit_sha.as_deref(),
        Some("abcdef1234567890abcdef1234567890abcdef12")
    );
    assert_eq!(verified.tlog_entry.log_index, 4242);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_audit_signatures_verifies_attestations_pass_and_tampered_fail() {
    let tarball_bytes = b"real package tarball content";
    let sha512_b64 = BASE64.encode(&Sha512::digest(tarball_bytes));
    let integrity_str = format!("sha512-{sha512_b64}");

    let valid_bundle = generate_valid_signed_test_bundle(
        "audit-pkg",
        "1.0.0",
        tarball_bytes,
        "test-org/audit-pkg",
        "11223344556677889900aabbccddeeff11223344",
    );

    let valid_bundle_val = serde_json::to_value(&valid_bundle).unwrap();
    let mut tampered_bundle_val = valid_bundle_val.clone();
    // Tamper the payload in DSSE envelope
    tampered_bundle_val["dsseEnvelope"]["payload"] =
        serde_json::json!(BASE64.encode(b"{\"tampered\": true}"));

    let server = TestMockServer::start(move |req| {
        if req.path == "/-/npm/v1/keys" {
            return (
                200,
                vec![("Content-Type", "application/json".into())],
                b"{\"keys\": []}".to_vec(),
            );
        }

        if req.path == "/audit-pkg" {
            let host = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("127.0.0.1");
            let packument = serde_json::json!({
                "name": "audit-pkg",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "audit-pkg",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("http://{host}/audit-pkg/-/audit-pkg-1.0.0.tgz"),
                            "integrity": integrity_str,
                            "signatures": [],
                            "attestations": {
                                "url": format!("http://{host}/attestations-endpoint"),
                                "provenance": {
                                    "predicateType": "https://slsa.dev/provenance/v1"
                                }
                            }
                        }
                    }
                }
            });
            return (
                200,
                vec![("Content-Type", "application/json".into())],
                serde_json::to_vec(&packument).unwrap(),
            );
        }

        if req.path == "/attestations-endpoint" {
            let resp = serde_json::json!({
                "attestations": [
                    {
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "bundle": &valid_bundle_val
                    }
                ]
            });
            return (
                200,
                vec![("Content-Type", "application/json".into())],
                serde_json::to_vec(&resp).unwrap(),
            );
        }

        (404, vec![], b"not found".to_vec())
    })
    .await;

    let dir = tempdir().unwrap();
    let pkg_json = r#"{
        "name": "audit-project",
        "version": "1.0.0",
        "dependencies": {
            "audit-pkg": "1.0.0"
        }
    }"#;
    std::fs::write(dir.path().join("package.json"), pkg_json).unwrap();

    let npmrc = format!(
        "registry=http://127.0.0.1:{}/\n",
        server.addr.port()
    );
    std::fs::write(dir.path().join(".npmrc"), npmrc).unwrap();

    // Create installed node_modules/audit-pkg
    let node_modules_pkg = dir.path().join("node_modules").join("audit-pkg");
    std::fs::create_dir_all(&node_modules_pkg).unwrap();
    std::fs::write(
        node_modules_pkg.join("package.json"),
        r#"{"name": "audit-pkg", "version": "1.0.0"}"#,
    )
    .unwrap();

    // 1. Run audit signatures (PASS)
    let mut cmd = isolated_rnpm(dir.path());
    cmd.args(["audit", "signatures"]);
    let output = tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "audit signatures should succeed on valid attestation:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        stdout.contains("1 package has a verified attestation"),
        "stdout should report verified attestation:\n{stdout}"
    );

    // Run audit signatures --json (PASS)
    let mut cmd_json = isolated_rnpm(dir.path());
    cmd_json.args(["audit", "signatures", "--json", "--include-attestations"]);
    let output_json = tokio::task::spawn_blocking(move || cmd_json.output().unwrap())
        .await
        .unwrap();
    assert!(output_json.status.success());
    let json_val: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("Valid JSON");
    assert_eq!(json_val["verified_attestations"], 1);
    assert_eq!(json_val["invalid"].as_array().unwrap().len(), 0);

    // 2. Tampered attestation (FAIL)
    let tampered_server = TestMockServer::start(move |req| {
        if req.path == "/-/npm/v1/keys" {
            return (
                200,
                vec![("Content-Type", "application/json".into())],
                b"{\"keys\": []}".to_vec(),
            );
        }

        if req.path == "/tampered-pkg" {
            let host = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("127.0.0.1");
            let packument = serde_json::json!({
                "name": "tampered-pkg",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "tampered-pkg",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": format!("http://{host}/tampered-pkg/-/tampered-pkg-1.0.0.tgz"),
                            "integrity": format!("sha512-{}", BASE64.encode(&Sha512::digest(b"bytes"))),
                            "signatures": [],
                            "attestations": {
                                "url": format!("http://{host}/attestations-tampered"),
                                "provenance": {
                                    "predicateType": "https://slsa.dev/provenance/v1"
                                }
                            }
                        }
                    }
                }
            });
            return (
                200,
                vec![("Content-Type", "application/json".into())],
                serde_json::to_vec(&packument).unwrap(),
            );
        }

        if req.path == "/attestations-tampered" {
            let mut tampered_b = generate_valid_signed_test_bundle(
                "tampered-pkg",
                "1.0.0",
                b"bytes",
                "test-org/tampered-pkg",
                "abcdef",
            );
            // Tamper the payload
            tampered_b.dsse_envelope.as_mut().unwrap().payload = BASE64.encode(b"{\"tampered\":true}");
            let resp = serde_json::json!({
                "attestations": [
                    {
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "bundle": tampered_b
                    }
                ]
            });
            return (
                200,
                vec![("Content-Type", "application/json".into())],
                serde_json::to_vec(&resp).unwrap(),
            );
        }

        (404, vec![], b"not found".to_vec())
    }).await;

    let dir2 = tempdir().unwrap();
    let pkg_json2 = r#"{
        "name": "tampered-project",
        "version": "1.0.0",
        "dependencies": {
            "tampered-pkg": "1.0.0"
        }
    }"#;
    std::fs::write(dir2.path().join("package.json"), pkg_json2).unwrap();
    std::fs::write(
        dir2.path().join(".npmrc"),
        format!("registry=http://127.0.0.1:{}/\n", tampered_server.addr.port()),
    )
    .unwrap();
    let nm_tampered = dir2.path().join("node_modules").join("tampered-pkg");
    std::fs::create_dir_all(&nm_tampered).unwrap();
    std::fs::write(
        nm_tampered.join("package.json"),
        r#"{"name": "tampered-pkg", "version": "1.0.0"}"#,
    )
    .unwrap();

    let mut cmd_fail = isolated_rnpm(dir2.path());
    cmd_fail.args(["audit", "signatures"]);
    let output_fail = tokio::task::spawn_blocking(move || cmd_fail.output().unwrap())
        .await
        .unwrap();
    assert!(
        !output_fail.status.success(),
        "audit signatures must fail on tampered attestation!"
    );
    let stdout_fail = String::from_utf8_lossy(&output_fail.stdout);
    assert!(
        stdout_fail.contains("invalid attestation")
            || stdout_fail.contains("Someone might have tampered"),
        "stdout should report invalid attestation:\n{stdout_fail}"
    );

    let mut cmd_fail_json = isolated_rnpm(dir2.path());
    cmd_fail_json.args(["audit", "signatures", "--json"]);
    let output_fail_json = tokio::task::spawn_blocking(move || cmd_fail_json.output().unwrap())
        .await
        .unwrap();
    assert!(!output_fail_json.status.success());
    let json_fail: serde_json::Value =
        serde_json::from_slice(&output_fail_json.stdout).expect("Valid JSON");
    let invalid_arr = json_fail["invalid"].as_array().unwrap();
    assert!(
        !invalid_arr.is_empty(),
        "invalid array in json must be non-empty"
    );
    assert_eq!(invalid_arr[0]["code"], "EINTEGRITYATTESTATION");
}
