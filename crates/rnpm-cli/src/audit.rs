#[path = "audit_graph.rs"]
mod graph;

use reqwest::Url;
use rnpm_core::semver::{Op, Range, Version};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;

/// Vulnerability severity levels conforming to npm's classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info = 0,
    Low = 1,
    Moderate = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Moderate => "moderate",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Error returned when vulnerabilities match or exceed the configured `--audit-level` threshold.
#[derive(Debug)]
pub struct AuditThresholdError {
    pub highest: Severity,
    pub threshold: Severity,
}

impl std::fmt::Display for AuditThresholdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Vulnerabilities found above audit threshold (highest: {:?}, threshold: {:?})",
            self.highest, self.threshold
        )
    }
}

impl std::error::Error for AuditThresholdError {}

impl FromStr for Severity {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "moderate" | "medium" | "mod" => Ok(Severity::Moderate),
            "high" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            other => Err(anyhow::anyhow!("Invalid severity '{other}'")),
        }
    }
}

/// Parse `--audit-level` value into an optional threshold. `none` disables error exits.
/// Unrecognized strings return an error rather than falling back.
pub fn parse_audit_level(s: &str) -> anyhow::Result<Option<Severity>> {
    match s.trim().to_lowercase().as_str() {
        "none" => Ok(None),
        "info" => Ok(Some(Severity::Info)),
        "low" => Ok(Some(Severity::Low)),
        "moderate" | "medium" | "mod" => Ok(Some(Severity::Moderate)),
        "high" => Ok(Some(Severity::High)),
        "critical" | "crit" => Ok(Some(Severity::Critical)),
        other => Err(anyhow::anyhow!(
            "Invalid audit-level '{other}'. Valid values are: info, low, moderate, high, critical, none"
        )),
    }
}

/// Vulnerability advisory payload returned by registry or mock advisory database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryPayload {
    #[serde(default)]
    pub id: serde_json::Value,

    #[serde(default)]
    pub name: Option<String>,

    #[serde(default)]
    pub url: Option<String>,

    #[serde(default)]
    pub title: Option<String>,

    #[serde(default)]
    pub severity: Option<String>,

    #[serde(default)]
    pub vulnerable_versions: Option<String>,

    #[serde(default)]
    pub patched_versions: Option<String>,

    #[serde(default)]
    pub cwe: Option<Vec<String>>,

    #[serde(default)]
    pub cvss: Option<serde_json::Value>,
}

/// Vulnerability advisory record matched during audit scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAdvisory {
    pub id: serde_json::Value,
    pub name: String,
    pub title: String,
    pub url: String,
    pub severity: Severity,
    pub severity_str: String,
    pub vulnerable_versions: String,
    pub patched_versions: Option<String>,
    pub installed_version: String,
    pub is_direct: bool,
    pub node_path: String,
}

/// Parse and determine the target non-vulnerable patched version from an advisory.
pub fn resolve_target_patched_version(
    patched_versions: Option<&str>,
    vulnerable_versions: &str,
) -> Option<Version> {
    // 1. Try patched_versions if provided
    if let Some(pv) = patched_versions {
        let trimmed = pv.trim();
        let cleaned = trimmed.trim_start_matches(['^', '~', '=', '>', ' ']);
        if let Ok(v) = Version::parse(cleaned) {
            return Some(v);
        }
        if let Ok(r) = Range::parse(trimmed) {
            for set in &r.sets {
                for comp in &set.comparators {
                    if comp.op == Op::Gte || comp.op == Op::Eq {
                        return Some(comp.version.clone());
                    } else if comp.op == Op::Gt {
                        let mut v = comp.version.clone();
                        v.patch += 1;
                        return Some(v);
                    }
                }
            }
        }
    }

    // 2. Infer from vulnerable_versions (e.g. "<4.17.21" or ">=1.0.0 <1.2.6")
    if let Ok(r) = Range::parse(vulnerable_versions) {
        for set in &r.sets {
            for comp in &set.comparators {
                if comp.op == Op::Lt {
                    return Some(comp.version.clone());
                } else if comp.op == Op::Lte {
                    let mut v = comp.version.clone();
                    v.patch += 1;
                    return Some(v);
                }
            }
        }
    }

    // 3. Fallback extraction: look for version pattern after '<'
    if let Some(pos) = vulnerable_versions.find('<') {
        let after = vulnerable_versions[pos + 1..].trim();
        let num_str: String = after
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-' || c.is_ascii_alphabetic())
            .collect();
        if let Ok(v) = Version::parse(&num_str) {
            return Some(v);
        }
    }

    None
}

/// Detailed advisory reference within a vulnerability report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViaItem {
    pub source: serde_json::Value,
    pub name: String,
    pub dependency: String,
    pub title: String,
    pub url: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss: Option<serde_json::Value>,
    pub range: String,
}

/// Vulnerability record for an affected package node in the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageVulnerability {
    pub name: String,
    pub severity: String,
    pub is_direct: bool,
    #[serde(serialize_with = "serialize_via")]
    pub via: Vec<serde_json::Value>,
    pub effects: Vec<String>,
    pub range: String,
    pub nodes: Vec<String>,
    #[serde(serialize_with = "serialize_fix")]
    pub fix_available: serde_json::Value,
}

/// Vulnerabilities count summary breakdown.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnerabilitiesCount {
    pub info: usize,
    pub low: usize,
    pub moderate: usize,
    pub high: usize,
    pub critical: usize,
    pub total: usize,
}

/// Dependencies count summary breakdown.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DependenciesCount {
    pub prod: usize,
    pub dev: usize,
    pub optional: usize,
    #[serde(skip_serializing_if = "is_zero_usize", default)]
    pub dev_optional: usize,
    pub peer: usize,
    pub peer_optional: usize,
    pub total: usize,
}

fn is_zero_usize(val: &usize) -> bool {
    *val == 0
}

/// Metadata section of npm audit report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditMetadata {
    pub vulnerabilities: VulnerabilitiesCount,
    pub dependencies: DependenciesCount,
}

/// Complete npm audit report matching npm v7/8/9/10/11 schema version 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditReport {
    pub audit_report_version: u32,
    pub vulnerabilities: BTreeMap<String, PackageVulnerability>,
    pub metadata: AuditMetadata,
}

/// Helper to parse package name from lockfile package key.
/// Arborist inventory counts for an audit report's `metadata.dependencies`.
pub(crate) fn dependency_counts(lockfile: &rnpm_lockfile::LockfileV3) -> DependenciesCount {
    let root_pkg = lockfile.packages.get("");
    let root_peer_deps: BTreeSet<String> = root_pkg
        .and_then(|root| root.peer_dependencies.as_ref())
        .map(|deps| deps.keys().cloned().collect())
        .unwrap_or_default();
    let root_peer_meta = root_pkg.and_then(|root| root.peer_dependencies_meta.as_ref());

    // Arborist's inventory includes the project root in prod, while total
    // excludes it. This also applies to an otherwise empty project.
    let mut dep_counts = DependenciesCount {
        prod: 1,
        ..Default::default()
    };

    for (key, pkg) in &lockfile.packages {
        if key.is_empty() {
            continue;
        }
        if !key.starts_with("node_modules/") || pkg.link.unwrap_or(false) {
            continue;
        }

        let name = extract_pkg_name(key, pkg.name.as_deref());

        dep_counts.total += 1;
        let is_dev = pkg.dev.unwrap_or(false)
            || pkg
                .extra
                .get("dev")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
        let is_optional = pkg.optional.unwrap_or(false)
            || pkg
                .extra
                .get("optional")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
        let is_dev_optional = pkg.dev_optional.unwrap_or(false)
            || pkg
                .extra
                .get("devOptional")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            || (is_dev && is_optional);

        let is_declared_peer = root_peer_deps.contains(&name)
            || pkg.peer.unwrap_or(false)
            || pkg
                .extra
                .get("peer")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

        let is_declared_peer_optional = pkg.peer_optional.unwrap_or(false)
            || pkg
                .extra
                .get("peerOptional")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            || (root_peer_deps.contains(&name)
                && root_peer_meta
                    .and_then(|m| m.get(&name))
                    .and_then(|v| v.get("optional"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false));

        if is_declared_peer_optional {
            dep_counts.peer_optional += 1;
        }
        if is_declared_peer {
            dep_counts.peer += 1;
        }
        if is_dev {
            dep_counts.dev += 1;
        }
        if is_optional {
            dep_counts.optional += 1;
        }
        if is_dev_optional {
            dep_counts.dev_optional += 1;
        }
        if !is_dev
            && !is_optional
            && !is_dev_optional
            && !is_declared_peer
            && !is_declared_peer_optional
        {
            dep_counts.prod += 1;
        }
    }
    dep_counts
}

fn extract_pkg_name(key: &str, declared_name: Option<&str>) -> String {
    if let Some(n) = declared_name {
        return n.to_string();
    }
    let stripped = key.strip_prefix("node_modules/").unwrap_or(key);
    // If nested (e.g. node_modules/foo/node_modules/bar), take after last node_modules/
    if let Some(pos) = stripped.rfind("node_modules/") {
        stripped[pos + "node_modules/".len()..].to_string()
    } else {
        stripped.to_string()
    }
}

/// Load advisory database from registry or local mock storage.
static AUDIT_HTTP_CLIENT: std::sync::OnceLock<Result<reqwest::Client, String>> =
    std::sync::OnceLock::new();
static AUDIT_DIRECT_HTTP_CLIENT: std::sync::OnceLock<Result<reqwest::Client, String>> =
    std::sync::OnceLock::new();

fn audit_http_client(bypass_proxy: bool) -> anyhow::Result<&'static reqwest::Client> {
    let slot = if bypass_proxy {
        &AUDIT_DIRECT_HTTP_CLIENT
    } else {
        &AUDIT_HTTP_CLIENT
    };
    let cached = slot.get_or_init(|| {
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .tcp_nodelay(true);
        if bypass_proxy {
            builder = builder.no_proxy();
        }
        builder
            .build()
            .map_err(|e| format!("Failed to build HTTP client for audit: {e}"))
    });
    cached.as_ref().map_err(|msg| anyhow::anyhow!("{msg}"))
}

#[allow(dead_code)]
enum FastHttpResponse {
    Fallback,
    Status { status: u16, body: Vec<u8> },
}

fn has_configured_http_proxy(config: &rnpm_config::Config, url: &Url) -> bool {
    if config.should_bypass_proxy(url) {
        return false;
    }
    for key in ["proxy", "http-proxy", "https-proxy"] {
        if let Some(v) = config.get(key) {
            let trimmed = v.trim();
            if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("null") && trimmed != "false" {
                return true;
            }
        }
    }
    for key in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        if let Some(v) = std::env::var_os(key) {
            if !v.is_empty() {
                return true;
            }
        }
    }
    false
}

fn decode_chunked_body(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let line_rel = raw[pos..].windows(2).position(|w| w == b"\r\n")?;
        let line = std::str::from_utf8(&raw[pos..pos + line_rel]).ok()?;
        let size_hex = line.split(';').next()?.trim();
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        pos += line_rel + 2;
        if size == 0 {
            return Some(out);
        }
        if pos + size + 2 > raw.len() {
            return None;
        }
        out.extend_from_slice(&raw[pos..pos + size]);
        pos += size + 2;
    }
}

fn build_fast_http_post_request(
    target_parsed: &Url,
    body_bytes: &[u8],
    user_agent: &str,
    auth_token: Option<&str>,
) -> Option<(String, String)> {
    if target_parsed.scheme() != "http" {
        return None;
    }
    let host = target_parsed.host_str()?;
    let port = target_parsed.port_or_known_default().unwrap_or(80);
    let addr = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let host_header = if target_parsed.port().is_some() {
        addr.as_str()
    } else {
        host
    };

    let mut path_and_query = target_parsed.path().to_string();
    if path_and_query.is_empty() {
        path_and_query.push('/');
    }
    if let Some(q) = target_parsed.query() {
        path_and_query.push('?');
        path_and_query.push_str(q);
    }

    let mut head = format!(
        "POST {path_and_query} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {user_agent}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body_bytes.len()
    );
    if let Some(token) = auth_token {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    head.push_str("\r\n");
    Some((addr, head))
}

fn parse_fast_http_response(raw: &[u8]) -> FastHttpResponse {
    let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return FastHttpResponse::Fallback;
    };
    let Ok(hdr_str) = std::str::from_utf8(&raw[..hdr_end]) else {
        return FastHttpResponse::Fallback;
    };
    let mut lines = hdr_str.split("\r\n");
    let Some(status_line) = lines.next() else {
        return FastHttpResponse::Fallback;
    };
    let Some(status) = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
    else {
        return FastHttpResponse::Fallback;
    };

    // Let reqwest handle redirects or unexpected status nuances if needed.
    if (300..400).contains(&status) {
        return FastHttpResponse::Fallback;
    }

    let mut is_chunked = false;
    let mut is_gzip = false;
    let mut content_len: Option<usize> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            } else if key.eq_ignore_ascii_case("content-encoding")
                && val.to_ascii_lowercase().contains("gzip")
            {
                is_gzip = true;
            } else if key.eq_ignore_ascii_case("content-length") {
                content_len = val.parse::<usize>().ok();
            }
        }
    }

    let raw_body = &raw[hdr_end + 4..];
    let mut body = if is_chunked {
        match decode_chunked_body(raw_body) {
            Some(b) => b,
            None => return FastHttpResponse::Fallback,
        }
    } else if let Some(len) = content_len {
        if raw_body.len() < len {
            return FastHttpResponse::Fallback;
        }
        raw_body[..len].to_vec()
    } else {
        raw_body.to_vec()
    };

    if is_gzip {
        use std::io::Read;
        let mut decoder = flate2::read::GzDecoder::new(&body[..]);
        let mut decoded = Vec::new();
        if decoder.read_to_end(&mut decoded).is_err() {
            return FastHttpResponse::Fallback;
        }
        body = decoded;
    }

    FastHttpResponse::Status { status, body }
}

async fn try_fast_http_post(
    target_parsed: &Url,
    target_url: &str,
    body_bytes: &[u8],
    user_agent: &str,
    auth_token: Option<&str>,
) -> anyhow::Result<FastHttpResponse> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Some((addr, head)) =
        build_fast_http_post_request(target_parsed, body_bytes, user_agent, auth_token)
    else {
        return Ok(FastHttpResponse::Fallback);
    };

    let io_fut = async {
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Request to security advisory registry timed out"))?
        .map_err(|e| {
            anyhow::anyhow!("Failed to connect to security advisory registry {target_url}: {e}")
        })?;
        let _ = stream.set_nodelay(true);
        stream.write_all(head.as_bytes()).await.map_err(|e| {
            anyhow::anyhow!("Failed to send advisory request to {target_url}: {e}")
        })?;
        stream.write_all(body_bytes).await.map_err(|e| {
            anyhow::anyhow!("Failed to send advisory request to {target_url}: {e}")
        })?;
        stream.flush().await.map_err(|e| {
            anyhow::anyhow!("Failed to send advisory request to {target_url}: {e}")
        })?;

        let mut raw = Vec::with_capacity(4096);
        stream.read_to_end(&mut raw).await.map_err(|e| {
            anyhow::anyhow!("Failed to read advisory response from {target_url}: {e}")
        })?;
        Ok::<Vec<u8>, anyhow::Error>(raw)
    };

    let raw = tokio::time::timeout(std::time::Duration::from_secs(30), io_fut)
        .await
        .map_err(|_| anyhow::anyhow!("Request to security advisory registry timed out"))??;

    Ok(parse_fast_http_response(&raw))
}

fn try_fast_http_post_sync(
    target_parsed: &Url,
    body_bytes: &[u8],
    user_agent: &str,
    auth_token: Option<&str>,
) -> Option<FastHttpResponse> {
    use std::io::{Read, Write};
    let (addr, head) =
        build_fast_http_post_request(target_parsed, body_bytes, user_agent, auth_token)?;
    let sock_addrs: Vec<std::net::SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(&*addr)
        .ok()?
        .collect();
    let mut stream = None;
    for sa in sock_addrs {
        if let Ok(s) = std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(10))
        {
            stream = Some(s);
            break;
        }
    }
    let mut stream = stream?;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
    stream.write_all(head.as_bytes()).ok()?;
    stream.write_all(body_bytes).ok()?;
    stream.flush().ok()?;
    let mut raw = Vec::with_capacity(4096);
    stream.read_to_end(&mut raw).ok()?;
    Some(parse_fast_http_response(&raw))
}

async fn fetch_advisories(
    registry_url: &str,
    bulk_request: &BTreeMap<String, Vec<String>>,
    project_dir: &Path,
    config: &rnpm_config::Config,
) -> anyhow::Result<BTreeMap<String, Vec<AdvisoryPayload>>> {
    // Arborist does not contact the advisory endpoint for an empty inventory.
    if bulk_request.is_empty() {
        return Ok(BTreeMap::new());
    }
    // 1. If local mock fixture advisories.json exists in project_dir and test mocking is enabled, load it
    let allow_mock_fixture = cfg!(test) || std::env::var("RNPM_TEST_MOCK_ADVISORIES").is_ok();
    if allow_mock_fixture {
        let local_fixture = project_dir.join("advisories.json");
        if local_fixture.exists() {
            if let Ok(data) = std::fs::read_to_string(&local_fixture) {
                if let Ok(map) =
                    serde_json::from_str::<BTreeMap<String, Vec<AdvisoryPayload>>>(&data)
                {
                    return Ok(map);
                }
            }
        }
    }

    let target_url = format!(
        "{}/-/npm/v1/security/advisories/bulk",
        registry_url.trim_end_matches('/')
    );
    let target_parsed = Url::parse(&target_url)
        .map_err(|e| anyhow::anyhow!("Invalid registry URL '{target_url}': {e}"))?;

    let user_agent = rnpm_registry::default_user_agent();
    let auth_token = config.npmrc.get_auth_token(&target_parsed);

    if target_parsed.scheme() == "http" && !has_configured_http_proxy(config, &target_parsed) {
        let payload = serde_json::to_vec(bulk_request)
            .map_err(|e| anyhow::anyhow!("Failed to serialize advisory request: {e}"))?;
        if let FastHttpResponse::Status { status, body } =
            try_fast_http_post(&target_parsed, &target_url, &payload, &user_agent, auth_token).await?
        {
            if !(200..300).contains(&status) {
                match status {
                    401 => {
                        return Err(anyhow::anyhow!(
                            "Authentication failed for {target_url} (HTTP 401)"
                        ));
                    }
                    403 => {
                        return Err(anyhow::anyhow!(
                            "Access forbidden for {target_url} (HTTP 403)"
                        ));
                    }
                    429 => {
                        return Err(anyhow::anyhow!("Registry rate limit exceeded (HTTP 429)"));
                    }
                    _ => {
                        return Err(anyhow::anyhow!(
                            "Security advisory registry returned HTTP {status} for {target_url}"
                        ));
                    }
                }
            }
            let map = serde_json::from_slice::<BTreeMap<String, Vec<AdvisoryPayload>>>(&body)
                .map_err(|e| anyhow::anyhow!("Failed to parse security advisories response: {e}"))?;
            return Ok(map);
        }
    }

    let client = audit_http_client(config.should_bypass_proxy(&target_parsed))?;

    let mut req = client
        .post(&target_url)
        .header(reqwest::header::USER_AGENT, user_agent)
        .header(reqwest::header::ACCEPT, "application/json");

    if let Some(token) = auth_token {
        req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
    }

    let resp = req.json(bulk_request).send().await.map_err(|e| {
        if e.is_timeout() {
            anyhow::anyhow!("Request to security advisory registry timed out: {e}")
        } else if e.is_connect() {
            anyhow::anyhow!("Failed to connect to security advisory registry {target_url}: {e}")
        } else {
            anyhow::anyhow!("Failed to send advisory request to {target_url}: {e}")
        }
    })?;

    let status = resp.status();
    if !status.is_success() {
        match status.as_u16() {
            401 => {
                return Err(anyhow::anyhow!(
                    "Authentication failed for {target_url} (HTTP 401)"
                ));
            }
            403 => {
                return Err(anyhow::anyhow!(
                    "Access forbidden for {target_url} (HTTP 403)"
                ));
            }
            429 => {
                return Err(anyhow::anyhow!("Registry rate limit exceeded (HTTP 429)"));
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Security advisory registry returned HTTP {status} for {target_url}"
                ));
            }
        }
    }

    let map = resp
        .json::<BTreeMap<String, Vec<AdvisoryPayload>>>()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse security advisories response: {e}"))?;

    Ok(map)
}

/// Builds the audit report scanning lockfile dependencies against security advisories.
pub async fn build_audit_report_with_advisories(
    project_dir: &Path,
    registry_url: Option<String>,
) -> anyhow::Result<(AuditReport, Option<Severity>, Vec<AuditAdvisory>)> {
    build_audit_report_with_advisories_and_config(project_dir, registry_url, None, None).await
}

pub(crate) struct AuditInventory {
    pub bulk_request: BTreeMap<String, Vec<String>>,
    pub installed_packages: Vec<(String, String, String, bool)>,
    pub dep_counts: DependenciesCount,
}

pub(crate) fn collect_audit_inventory(lockfile: &rnpm_lockfile::LockfileV3) -> AuditInventory {
    let root_pkg = lockfile.packages.get("");
    let mut direct_deps: BTreeSet<String> = BTreeSet::new();
    if let Some(root) = root_pkg {
        if let Some(ref deps) = root.dependencies {
            direct_deps.extend(deps.keys().cloned());
        }
        if let Some(ref dev_deps) = root.dev_dependencies {
            direct_deps.extend(dev_deps.keys().cloned());
        }
        if let Some(ref opt_deps) = root.optional_dependencies {
            direct_deps.extend(opt_deps.keys().cloned());
        }
        if let Some(ref peer_deps) = root.peer_dependencies {
            direct_deps.extend(peer_deps.keys().cloned());
        }
    }

    let mut bulk_request: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut installed_packages: Vec<(String, String, String, bool)> = Vec::new();
    let dep_counts = dependency_counts(lockfile);

    for (key, pkg) in &lockfile.packages {
        if key.is_empty() {
            continue;
        }
        if !key.starts_with("node_modules/") || pkg.link.unwrap_or(false) {
            continue;
        }
        let name = extract_pkg_name(key, pkg.name.as_deref());
        let version_str = match &pkg.version {
            Some(v) => v.clone(),
            None => continue,
        };
        let is_direct = direct_deps.contains(&name);
        bulk_request
            .entry(name.clone())
            .or_default()
            .push(version_str.clone());
        installed_packages.push((key.clone(), name, version_str, is_direct));
    }

    for versions in bulk_request.values_mut() {
        versions.sort();
        versions.dedup();
    }

    AuditInventory {
        bulk_request,
        installed_packages,
        dep_counts,
    }
}

pub(crate) async fn finalize_audit_report(
    lockfile: &rnpm_lockfile::LockfileV3,
    inventory: AuditInventory,
    advisories_by_pkg: &BTreeMap<String, Vec<AdvisoryPayload>>,
    registry: &str,
    config: &rnpm_config::Config,
) -> anyhow::Result<(AuditReport, Option<Severity>, Vec<AuditAdvisory>)> {
    let mut vulnerabilities: BTreeMap<String, PackageVulnerability> = BTreeMap::new();
    let mut highest_severity: Option<Severity> = None;
    let mut advisories_found: Vec<AuditAdvisory> = Vec::new();

    for (node_path, pkg_name, ver_str, is_direct) in &inventory.installed_packages {
        if let Some(advisories) = advisories_by_pkg.get(pkg_name) {
            let parsed_ver = match Version::parse(ver_str) {
                Ok(v) => v,
                Err(_) => continue,
            };

            for adv in advisories {
                let range_str = adv.vulnerable_versions.as_deref().unwrap_or("*");
                let is_vulnerable = match Range::parse(range_str) {
                    Ok(r) => r.satisfies(&parsed_ver),
                    Err(_) => false,
                };

                if is_vulnerable {
                    let sev_str = adv.severity.clone().unwrap_or_else(|| "high".to_string());
                    let sev = Severity::from_str(&sev_str).unwrap_or(Severity::High);

                    highest_severity = match highest_severity {
                        Some(current) => Some(current.max(sev)),
                        None => Some(sev),
                    };

                    advisories_found.push(AuditAdvisory {
                        id: adv.id.clone(),
                        name: pkg_name.clone(),
                        title: adv
                            .title
                            .clone()
                            .unwrap_or_else(|| format!("Vulnerability in {pkg_name}")),
                        url: adv.url.clone().unwrap_or_default(),
                        severity: sev,
                        severity_str: sev_str.clone(),
                        vulnerable_versions: range_str.to_string(),
                        patched_versions: adv.patched_versions.clone(),
                        installed_version: ver_str.clone(),
                        is_direct: *is_direct,
                        node_path: node_path.clone(),
                    });

                    let via_item = ViaItem {
                        source: adv.id.clone(),
                        name: pkg_name.clone(),
                        dependency: pkg_name.clone(),
                        title: adv
                            .title
                            .clone()
                            .unwrap_or_else(|| format!("Vulnerability in {pkg_name}")),
                        url: adv.url.clone().unwrap_or_default(),
                        severity: sev_str.clone(),
                        cwe: adv.cwe.clone(),
                        cvss: adv.cvss.clone(),
                        range: range_str.to_string(),
                    };

                    let entry = vulnerabilities.entry(pkg_name.clone()).or_insert_with(|| {
                        PackageVulnerability {
                            name: pkg_name.clone(),
                            severity: sev_str.clone(),
                            is_direct: *is_direct,
                            via: Vec::new(),
                            effects: Vec::new(),
                            range: range_str.to_string(),
                            nodes: Vec::new(),
                            fix_available: serde_json::json!(true),
                        }
                    });

                    let existing_sev = Severity::from_str(&entry.severity).unwrap_or(Severity::Low);
                    if sev > existing_sev {
                        entry.severity = sev_str;
                    }

                    if !entry.nodes.contains(node_path) {
                        entry.nodes.push(node_path.clone());
                    }
                    if !entry.via.iter().any(|v| v["source"] == via_item.source) {
                        entry.via.push(serde_json::to_value(via_item)?);
                    }
                }
            }
        }
    }

    graph::complete_graph(&mut vulnerabilities, lockfile, registry, config).await?;

    let mut pkg_vuln_counts = VulnerabilitiesCount::default();
    for pkg_vuln in vulnerabilities.values() {
        match pkg_vuln.severity.as_str() {
            "info" => pkg_vuln_counts.info += 1,
            "low" => pkg_vuln_counts.low += 1,
            "moderate" => pkg_vuln_counts.moderate += 1,
            "high" => pkg_vuln_counts.high += 1,
            "critical" => pkg_vuln_counts.critical += 1,
            _ => pkg_vuln_counts.low += 1,
        }
        pkg_vuln_counts.total += 1;
    }

    let report = AuditReport {
        audit_report_version: 2,
        vulnerabilities,
        metadata: AuditMetadata {
            vulnerabilities: pkg_vuln_counts,
            dependencies: inventory.dep_counts,
        },
    };

    Ok((report, highest_severity, advisories_found))
}

pub(crate) async fn build_audit_report_with_advisories_and_config(
    project_dir: &Path,
    registry_url: Option<String>,
    preloaded_config: Option<&rnpm_config::Config>,
    preloaded_lockfile: Option<&rnpm_lockfile::LockfileV3>,
) -> anyhow::Result<(AuditReport, Option<Severity>, Vec<AuditAdvisory>)> {
    let owned_lockfile;
    let lockfile = if let Some(lock) = preloaded_lockfile {
        lock
    } else {
        let (lock_path, is_shrinkwrap) = rnpm_install::resolve_lockfile_path(project_dir);
        if !lock_path.exists() {
            return Err(anyhow::anyhow!(
                "npm error code ENOLOCK\n\
                 npm error This command requires an existing lockfile.\n\
                 npm error Try creating one with `rnpm install`."
            ));
        }
        owned_lockfile = rnpm_lockfile::load_and_migrate_readonly(&lock_path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse {}: {e}",
                if is_shrinkwrap {
                    "npm-shrinkwrap.json"
                } else {
                    "package-lock.json"
                }
            )
        })?;
        &owned_lockfile
    };

    let owned_config;
    let config = match preloaded_config {
        Some(cfg) => cfg,
        None => {
            owned_config = rnpm_config::Config::load(Some(project_dir)).unwrap_or_default();
            &owned_config
        }
    };

    let inventory = collect_audit_inventory(lockfile);
    let registry = registry_url
        .or_else(|| config.npmrc.settings.get("registry").cloned())
        .unwrap_or_else(|| config.npmrc.registry.to_string());

    let advisories_by_pkg =
        fetch_advisories(&registry, &inventory.bulk_request, project_dir, config).await?;
    finalize_audit_report(lockfile, inventory, &advisories_by_pkg, &registry, config).await
}

pub(crate) async fn build_audit_report_with_config_and_lockfile(
    project_dir: &Path,
    registry_url: Option<String>,
    preloaded_config: Option<&rnpm_config::Config>,
    preloaded_lockfile: Option<&rnpm_lockfile::LockfileV3>,
) -> anyhow::Result<(AuditReport, Option<Severity>)> {
    let (report, highest, _) = build_audit_report_with_advisories_and_config(
        project_dir,
        registry_url,
        preloaded_config,
        preloaded_lockfile,
    )
    .await?;
    Ok((report, highest))
}

type SyncAuditResult =
    Option<(rnpm_lockfile::LockfileV3, AuditInventory, BTreeMap<String, Vec<AdvisoryPayload>>)>;
type AsyncAuditResult = Option<(rnpm_lockfile::LockfileV3, AuditReport)>;

pub(crate) enum SpeculativeAuditInner {
    SyncHttpThread(std::thread::JoinHandle<SyncAuditResult>),
    AsyncTask(tokio::task::JoinHandle<AsyncAuditResult>),
}

pub(crate) struct SpeculativeAuditHandle {
    lock_path: std::path::PathBuf,
    lock_len: u64,
    lock_mtime: Option<std::time::SystemTime>,
    registry: String,
    inner: SpeculativeAuditInner,
}

impl SpeculativeAuditHandle {
    pub(crate) fn is_lockfile_unchanged(&self) -> bool {
        let Ok(meta) = std::fs::metadata(&self.lock_path) else {
            return false;
        };
        meta.len() == self.lock_len && meta.modified().ok() == self.lock_mtime
    }

    pub(crate) async fn finish(
        self,
        config: &rnpm_config::Config,
    ) -> Option<(rnpm_lockfile::LockfileV3, AuditReport)> {
        match self.inner {
            SpeculativeAuditInner::SyncHttpThread(handle) => {
                let (lockfile, inventory, advisories_by_pkg) = handle.join().ok().flatten()?;
                if advisories_by_pkg.is_empty() {
                    let report = AuditReport {
                        audit_report_version: 2,
                        vulnerabilities: BTreeMap::new(),
                        metadata: AuditMetadata {
                            vulnerabilities: VulnerabilitiesCount::default(),
                            dependencies: inventory.dep_counts,
                        },
                    };
                    return Some((lockfile, report));
                }
                let (report, _, _) = finalize_audit_report(
                    &lockfile,
                    inventory,
                    &advisories_by_pkg,
                    &self.registry,
                    config,
                )
                .await
                .ok()?;
                Some((lockfile, report))
            }
            SpeculativeAuditInner::AsyncTask(handle) => handle.await.ok().flatten(),
        }
    }
}

pub(crate) fn spawn_speculative_post_install_audit(
    project_dir: &Path,
    registry_url: Option<&str>,
    config: &rnpm_config::Config,
) -> Option<SpeculativeAuditHandle> {
    let (lock_path, _) = rnpm_install::resolve_lockfile_path(project_dir);
    let meta = std::fs::metadata(&lock_path).ok()?;
    let lock_len = meta.len();
    let lock_mtime = meta.modified().ok();

    let registry = registry_url
        .map(str::to_string)
        .or_else(|| config.npmrc.settings.get("registry").cloned())
        .unwrap_or_else(|| config.npmrc.registry.to_string());

    let target_url = format!(
        "{}/-/npm/v1/security/advisories/bulk",
        registry.trim_end_matches('/')
    );
    let target_parsed = Url::parse(&target_url).ok()?;
    let mock_possible = cfg!(test) || std::env::var_os("RNPM_TEST_MOCK_ADVISORIES").is_some();

    if target_parsed.scheme() == "http"
        && !mock_possible
        && !has_configured_http_proxy(config, &target_parsed)
    {
        let lp = lock_path.clone();
        let user_agent = rnpm_registry::default_user_agent();
        let auth_token = config.npmrc.get_auth_token(&target_parsed).map(str::to_string);
        let handle = std::thread::spawn(move || {
            let lockfile = rnpm_lockfile::load_and_migrate_readonly(&lp).ok()?;
            let inventory = collect_audit_inventory(&lockfile);
            if inventory.bulk_request.is_empty() {
                return Some((lockfile, inventory, BTreeMap::new()));
            }
            let payload = serde_json::to_vec(&inventory.bulk_request).ok()?;
            if let Some(FastHttpResponse::Status { status, body }) = try_fast_http_post_sync(
                &target_parsed,
                &payload,
                &user_agent,
                auth_token.as_deref(),
            ) {
                if (200..300).contains(&status) {
                    let map =
                        serde_json::from_slice::<BTreeMap<String, Vec<AdvisoryPayload>>>(&body)
                            .ok()?;
                    return Some((lockfile, inventory, map));
                }
            }
            None
        });
        return Some(SpeculativeAuditHandle {
            lock_path,
            lock_len,
            lock_mtime,
            registry,
            inner: SpeculativeAuditInner::SyncHttpThread(handle),
        });
    }

    if tokio::runtime::Handle::try_current()
        .is_ok_and(|h| h.metrics().num_workers() > 1)
    {
        let lp = lock_path.clone();
        let pdir = project_dir.to_path_buf();
        let cfg_clone = config.clone();
        let reg_clone = Some(registry.clone());
        let handle = tokio::spawn(async move {
            let lockfile = rnpm_lockfile::load_and_migrate_readonly(&lp).ok()?;
            let (report, _) = build_audit_report_with_config_and_lockfile(
                &pdir,
                reg_clone,
                Some(&cfg_clone),
                Some(&lockfile),
            )
            .await
            .ok()?;
            Some((lockfile, report))
        });
        return Some(SpeculativeAuditHandle {
            lock_path,
            lock_len,
            lock_mtime,
            registry,
            inner: SpeculativeAuditInner::AsyncTask(handle),
        });
    }

    None
}

/// Execute the audit workflow (full report).
#[allow(dead_code)]
pub async fn run_audit(
    project_dir: &Path,
    registry_url: Option<String>,
    json_output: bool,
    audit_level: &str,
) -> anyhow::Result<()> {
    run_audit_with_config(project_dir, registry_url, json_output, audit_level, None).await
}

pub(crate) async fn run_audit_with_config(
    project_dir: &Path,
    registry_url: Option<String>,
    json_output: bool,
    audit_level: &str,
    preloaded_config: Option<&rnpm_config::Config>,
) -> anyhow::Result<()> {
    let threshold_opt = parse_audit_level(audit_level)?;
    let (report, highest_severity) =
        build_audit_report_with_config_and_lockfile(project_dir, registry_url, preloaded_config, None)
            .await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_audit_report(&report);
    }

    if let Some(threshold) = threshold_opt {
        if let Some(highest) = highest_severity {
            if highest >= threshold {
                return Err(anyhow::Error::from(AuditThresholdError {
                    highest,
                    threshold,
                }));
            }
        }
    }

    Ok(())
}

/// Prints concise one-line summary matching npm audit on install/ci
pub fn print_concise_audit_summary(report: &AuditReport) {
    let total = report.metadata.vulnerabilities.total;
    if total == 0 {
        println!("found 0 vulnerabilities");
        return;
    }

    let vuln_word = if total == 1 {
        "vulnerability"
    } else {
        "vulnerabilities"
    };
    let mut parts = Vec::new();
    if report.metadata.vulnerabilities.info > 0 {
        parts.push(format!("{} info", report.metadata.vulnerabilities.info));
    }
    if report.metadata.vulnerabilities.low > 0 {
        parts.push(format!("{} low", report.metadata.vulnerabilities.low));
    }
    if report.metadata.vulnerabilities.moderate > 0 {
        parts.push(format!(
            "{} moderate",
            report.metadata.vulnerabilities.moderate
        ));
    }
    if report.metadata.vulnerabilities.high > 0 {
        parts.push(format!("{} high", report.metadata.vulnerabilities.high));
    }
    if report.metadata.vulnerabilities.critical > 0 {
        parts.push(format!(
            "{} critical",
            report.metadata.vulnerabilities.critical
        ));
    }

    let details = if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    };
    println!("found {total} {vuln_word}{details}");
    println!("  run `npm audit fix` to fix them, or `npm audit` for details");
}

pub fn print_human_audit_report(report: &AuditReport) {
    if report.vulnerabilities.is_empty() {
        println!("found 0 vulnerabilities");
        return;
    }
    println!("# npm audit report\n");
    let mut printed = BTreeSet::new();
    for (name, vuln) in &report.vulnerabilities {
        if vuln.via.iter().any(serde_json::Value::is_object) {
            if let Some(text) = format_vulnerability(name, report, &mut printed, "") {
                println!("{text}");
            }
        }
    }
    let counts = &report.metadata.vulnerabilities;
    let severities: Vec<_> = [
        ("low", counts.low),
        ("moderate", counts.moderate),
        ("high", counts.high),
        ("critical", counts.critical),
    ]
    .into_iter()
    .filter(|(_, count)| *count > 0)
    .collect();
    if severities.len() == 1 {
        let (severity, count) = severities[0];
        println!(
            "{count} {severity} severity vulnerabilit{}",
            if count == 1 { "y" } else { "ies" }
        );
    } else {
        println!(
            "{} vulnerabilities ({})",
            counts.total,
            severities
                .iter()
                .map(|(s, c)| format!("{c} {s}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let some_fixable = report
        .vulnerabilities
        .values()
        .any(|v| v.fix_available == serde_json::json!(true));
    let some_force = report
        .vulnerabilities
        .values()
        .any(|v| v.fix_available.is_object());
    let some_unfixable = report
        .vulnerabilities
        .values()
        .any(|v| v.fix_available == serde_json::json!(false));
    let breaking = report
        .vulnerabilities
        .values()
        .any(|v| v.fix_available["isSemVerMajor"] == serde_json::json!(true));
    if some_fixable {
        println!(
            "\nTo address {}, run:\n  npm audit fix",
            if some_force || some_unfixable {
                "issues that do not require attention"
            } else {
                "all issues"
            }
        );
    }
    if some_force {
        println!(
            "\nTo address all issues{}{}, run:\n  npm audit fix --force",
            if some_unfixable { " possible" } else { "" },
            if breaking {
                " (including breaking changes)"
            } else {
                ""
            }
        );
    }
    if some_unfixable {
        println!("\nSome issues need review, and may require choosing\na different dependency.");
    }
}

fn format_vulnerability(
    name: &str,
    report: &AuditReport,
    printed: &mut BTreeSet<String>,
    indent: &str,
) -> Option<String> {
    if !printed.insert(name.to_string()) {
        return None;
    }
    let vuln = &report.vulnerabilities[name];
    let mut lines = vec![format!("{name}  {}", vuln.range)];
    if indent.is_empty() && vuln.severity != "low" {
        lines.push(format!("Severity: {}", vuln.severity));
    }
    for via in &vuln.via {
        if let Some(dep) = via.as_str() {
            lines.push(format!("Depends on vulnerable versions of {dep}"));
        } else if indent.is_empty() {
            lines.push(format!(
                "{} - {}",
                via["title"].as_str().unwrap_or(""),
                via["url"].as_str().unwrap_or("")
            ));
        }
    }
    if indent.is_empty() {
        match &vuln.fix_available {
            serde_json::Value::Bool(false) => lines.push("No fix available".to_string()),
            serde_json::Value::Bool(true) => {
                lines.push("fix available via `npm audit fix`".to_string())
            }
            fix => {
                lines.push("fix available via `npm audit fix --force`".to_string());
                lines.push(format!(
                    "Will install {}@{}, which is {}",
                    fix["name"].as_str().unwrap_or(""),
                    fix["version"].as_str().unwrap_or(""),
                    if fix["isSemVerMajor"] == serde_json::json!(true) {
                        "a breaking change"
                    } else {
                        "outside the stated dependency range"
                    }
                ));
            }
        }
    }
    lines.extend(vuln.nodes.iter().cloned());
    for effect in &vuln.effects {
        if let Some(text) = format_vulnerability(effect, report, printed, "  ") {
            lines.push(text);
        }
    }
    if indent.is_empty() {
        lines.push(String::new());
    }
    Some(
        lines
            .iter()
            .map(|line| format!("{indent}{}", line.replace('\n', &format!("\n{indent}"))))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// Runs a post-install vulnerability audit check emitting only a concise summary.
#[allow(dead_code)]
pub async fn run_post_install_audit(
    project_dir: &Path,
    registry_url: Option<String>,
) -> anyhow::Result<()> {
    run_post_install_audit_with_config(project_dir, registry_url, None, None).await
}

pub(crate) async fn run_post_install_audit_with_config(
    project_dir: &Path,
    registry_url: Option<String>,
    preloaded_config: Option<&rnpm_config::Config>,
    preloaded_lockfile: Option<&rnpm_lockfile::LockfileV3>,
) -> anyhow::Result<()> {
    if preloaded_lockfile.is_none() {
        let (lock_path, _) = rnpm_install::resolve_lockfile_path(project_dir);
        if !lock_path.exists() {
            return Ok(());
        }
    }
    if let Ok((report, _)) = build_audit_report_with_config_and_lockfile(
        project_dir,
        registry_url,
        preloaded_config,
        preloaded_lockfile,
    )
    .await
    {
        let owned_config;
        let config = match preloaded_config {
            Some(cfg) => cfg,
            None => {
                owned_config = rnpm_config::Config::load(Some(project_dir))?;
                &owned_config
            }
        };
        if config.get("loglevel") != Some("silent") {
            print_concise_audit_summary(&report);
        }
    }
    Ok(())
}

pub(crate) fn count_funding_packages_with_lockfile(
    project_dir: &Path,
    preloaded_lockfile: Option<&rnpm_lockfile::LockfileV3>,
) -> usize {
    let loaded_lockfile = if preloaded_lockfile.is_none() {
        let (lock_path, _) = rnpm_install::resolve_lockfile_path(project_dir);
        if lock_path.exists() {
            rnpm_lockfile::load_and_migrate_readonly(&lock_path).ok()
        } else {
            None
        }
    } else {
        None
    };
    if let Some(lockfile) = preloaded_lockfile.or(loaded_lockfile.as_ref()) {
        let count = lockfile
            .packages
            .iter()
            .filter(|(k, p)| !k.is_empty() && p.extra.contains_key("funding"))
            .count();
        if count > 0 {
            return count;
        }
    }
    count_funding_packages_in_node_modules(project_dir)
}

pub(crate) fn count_funding_packages_in_node_modules(project_dir: &Path) -> usize {
    let nm_dir = project_dir.join("node_modules");
    if !nm_dir.exists() {
        return 0;
    }

    #[derive(Default)]
    struct Present(bool);
    impl<'de> serde::Deserialize<'de> for Present {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            serde::de::IgnoredAny::deserialize(deserializer)?;
            Ok(Present(true))
        }
    }
    #[derive(serde::Deserialize)]
    struct FundingProbe {
        #[serde(default)]
        funding: Present,
    }

    let has_funding_field = |manifest_p: &Path| -> bool {
        let Ok(bytes) = std::fs::read(manifest_p) else {
            return false;
        };
        if !bytes.windows(9).any(|w| w == b"\"funding\"") && !bytes.windows(2).any(|w| w == b"\\u") {
            return false;
        }
        serde_json::from_slice::<FundingProbe>(&bytes).is_ok_and(|probe| probe.funding.0)
    };

    let mut manifest_paths = Vec::new();
    let mut scope_dirs = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&nm_dir) {
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            let p = entry.path();
            if ft.is_dir() || (ft.is_symlink() && p.is_dir()) {
                let name = entry.file_name();
                let bytes = name.as_encoded_bytes();
                if bytes.starts_with(b"@") {
                    scope_dirs.push(p);
                } else if !bytes.starts_with(b".") {
                    manifest_paths.push(p.join("package.json"));
                }
            }
        }
    }
    for scope_dir in scope_dirs {
        if let Ok(sub_entries) = std::fs::read_dir(&scope_dir) {
            for sub_entry in sub_entries.flatten() {
                manifest_paths.push(sub_entry.path().join("package.json"));
            }
        }
    }

    if manifest_paths.len() <= 8 {
        return manifest_paths
            .iter()
            .filter(|p| has_funding_field(p))
            .count();
    }

    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16)
        .min(manifest_paths.len());
    let next_idx = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            handles.push(scope.spawn(|| {
                let mut local = 0usize;
                loop {
                    let idx = next_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if idx >= manifest_paths.len() {
                        break;
                    }
                    if has_funding_field(&manifest_paths[idx]) {
                        local += 1;
                    }
                }
                local
            }));
        }
        handles.into_iter().filter_map(|h| h.join().ok()).sum()
    })
}

fn serialize_via<S: serde::Serializer>(
    via: &[serde_json::Value],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::{Error, SerializeSeq};
    let mut seq = serializer.serialize_seq(Some(via.len()))?;
    for item in via {
        if item.is_object() {
            let advisory: ViaItem =
                serde_json::from_value(item.clone()).map_err(S::Error::custom)?;
            seq.serialize_element(&advisory)?;
        } else {
            seq.serialize_element(item)?;
        }
    }
    seq.end()
}

fn serialize_fix<S: serde::Serializer>(
    fix: &serde_json::Value,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    if fix.is_object() {
        let mut map = serializer.serialize_map(Some(3))?;
        for key in ["name", "version", "isSemVerMajor"] {
            map.serialize_entry(key, &fix[key])?;
        }
        map.end()
    } else {
        fix.serialize(serializer)
    }
}

pub fn check_report_threshold(report: &AuditReport, level: &str) -> anyhow::Result<()> {
    if let Some(threshold) = parse_audit_level(level)? {
        let highest = report
            .vulnerabilities
            .values()
            .filter_map(|v| Severity::from_str(&v.severity).ok())
            .max();
        if let Some(highest) = highest.filter(|v| *v >= threshold) {
            return Err(AuditThresholdError { highest, threshold }.into());
        }
    }
    Ok(())
}
