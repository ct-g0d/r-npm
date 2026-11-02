use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use reqwest::Url;
use rnpm_core::semver::{Range, Version};

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
    pub cwe: Option<Vec<String>>,

    #[serde(default)]
    pub cvss: Option<serde_json::Value>,
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
    pub via: Vec<ViaItem>,
    pub effects: Vec<String>,
    pub range: String,
    pub nodes: Vec<String>,
    pub fix_available: bool,
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
async fn fetch_advisories(
    registry_url: &str,
    bulk_request: &BTreeMap<String, Vec<String>>,
    project_dir: &Path,
    config: &rnpm_config::Config,
) -> anyhow::Result<BTreeMap<String, Vec<AdvisoryPayload>>> {
    // 1. If local mock fixture advisories.json exists in project_dir, load it
    let local_fixture = project_dir.join("advisories.json");
    if local_fixture.exists() {
        if let Ok(data) = std::fs::read_to_string(&local_fixture) {
            if let Ok(map) = serde_json::from_str::<BTreeMap<String, Vec<AdvisoryPayload>>>(&data) {
                return Ok(map);
            }
        }
    }

    let target_url = format!("{}/-/npm/v1/security/advisories/bulk", registry_url.trim_end_matches('/'));
    let target_parsed = Url::parse(&target_url)
        .map_err(|e| anyhow::anyhow!("Invalid registry URL '{target_url}': {e}"))?;

    let mut client_config = rnpm_registry::RegistryClientConfig::default();
    client_config.default_registry = target_parsed.clone();
    client_config.auth_tokens = config.npmrc.auth_tokens.clone();
    client_config.scoped_registries = config.npmrc.scoped_registries.clone();
    if let Some(token) = config.npmrc.get_auth_token(&target_parsed) {
        client_config.auth_token = Some(token.to_string());
    }
    if let Some(host) = target_parsed.host_str() {
        client_config.trusted_hosts.insert(host.to_ascii_lowercase());
        if let Some(port) = target_parsed.port_or_known_default() {
            client_config.trusted_hosts.insert(format!("{}:{}", host.to_ascii_lowercase(), port));
        }
    }
    for (_, scoped_reg) in &config.npmrc.scoped_registries {
        if let Some(h) = scoped_reg.host_str() {
            client_config.trusted_hosts.insert(h.to_ascii_lowercase());
            if let Some(p) = scoped_reg.port_or_known_default() {
                client_config.trusted_hosts.insert(format!("{}:{}", h.to_ascii_lowercase(), p));
            }
        }
    }

    let reg_client = rnpm_registry::RegistryClient::with_config(client_config);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP client for audit: {e}"))?;

    let mut req = client.post(&target_url)
        .header(reqwest::header::USER_AGENT, rnpm_registry::default_user_agent())
        .header(reqwest::header::ACCEPT, "application/json");

    if let Ok(ref rc) = reg_client {
        if let Some(token) = rc.auth_token_for_url(&target_parsed) {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
    } else if let Some(token) = config.npmrc.get_auth_token(&target_parsed) {
        req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
    }

    let resp = req.json(bulk_request).send().await
        .map_err(|e| {
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
                return Err(anyhow::anyhow!(
                    "Registry rate limit exceeded (HTTP 429)"
                ));
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Security advisory registry returned HTTP {status} for {target_url}"
                ));
            }
        }
    }

    let map = resp.json::<BTreeMap<String, Vec<AdvisoryPayload>>>().await
        .map_err(|e| anyhow::anyhow!("Failed to parse security advisories response: {e}"))?;

    Ok(map)
}

/// Execute the audit workflow.
pub async fn run_audit(
    project_dir: &Path,
    registry_url: Option<String>,
    json_output: bool,
    audit_level: &str,
) -> anyhow::Result<()> {
    let lock_path = project_dir.join("package-lock.json");
    if !lock_path.exists() {
        return Err(anyhow::anyhow!(
            "npm error code ENOLOCK\n\
             npm error This command requires an existing lockfile.\n\
             npm error Try creating one with `rnpm install`."
        ));
    }

    let lockfile = rnpm_lockfile::load_and_migrate(&lock_path)
        .map_err(|e| anyhow::anyhow!("Failed to parse package-lock.json: {e}"))?;

    let threshold_opt = parse_audit_level(audit_level)?;

    let config = rnpm_config::Config::load(Some(project_dir)).unwrap_or_default();

    // Direct dependencies of the root project
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

    let root_peer_deps: BTreeSet<String> = root_pkg
        .and_then(|root| root.peer_dependencies.as_ref())
        .map(|deps| deps.keys().cloned().collect())
        .unwrap_or_default();

    let root_peer_meta = root_pkg.and_then(|root| root.peer_dependencies_meta.as_ref());

    // Map: package name -> list of installed versions
    let mut bulk_request: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut installed_packages: Vec<(String, String, String, bool)> = Vec::new(); // (key, name, version, is_direct)

    let mut dep_counts = DependenciesCount::default();

    for (key, pkg) in &lockfile.packages {
        if key.is_empty() {
            continue;
        }

        // Skip workspace members (e.g. "packages/*") or workspace symlinks from advisory lookup
        if !key.starts_with("node_modules/") || pkg.link.unwrap_or(false) {
            continue;
        }

        let name = extract_pkg_name(key, pkg.name.as_deref());

        dep_counts.total += 1;
        let is_dev = pkg.dev.unwrap_or(false)
            || pkg.extra.get("dev").and_then(|v| v.as_bool()).unwrap_or(false);
        let is_optional = pkg.optional.unwrap_or(false)
            || pkg.extra.get("optional").and_then(|v| v.as_bool()).unwrap_or(false);
        let is_dev_optional = pkg.dev_optional.unwrap_or(false)
            || pkg.extra.get("devOptional").and_then(|v| v.as_bool()).unwrap_or(false)
            || (is_dev && is_optional);

        let is_declared_peer = root_peer_deps.contains(&name)
            || pkg.peer.unwrap_or(false)
            || pkg.extra.get("peer").and_then(|v| v.as_bool()).unwrap_or(false);

        let is_declared_peer_optional = pkg.peer_optional.unwrap_or(false)
            || pkg.extra.get("peerOptional").and_then(|v| v.as_bool()).unwrap_or(false)
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
        if !is_dev && !is_optional && !is_dev_optional && !is_declared_peer && !is_declared_peer_optional {
            dep_counts.prod += 1;
        }

        let version_str = match &pkg.version {
            Some(v) => v.clone(),
            None => continue,
        };

        let is_direct = direct_deps.contains(&name);
        bulk_request.entry(name.clone()).or_default().push(version_str.clone());
        installed_packages.push((key.clone(), name, version_str, is_direct));
    }

    // Deduplicate versions in bulk request
    for versions in bulk_request.values_mut() {
        versions.sort();
        versions.dedup();
    }

    let registry = registry_url
        .or_else(|| config.npmrc.settings.get("registry").cloned())
        .unwrap_or_else(|| config.npmrc.registry.to_string());

    let advisories_by_pkg = fetch_advisories(&registry, &bulk_request, project_dir, &config).await?;

    // Scan for vulnerabilities
    let mut vulnerabilities: BTreeMap<String, PackageVulnerability> = BTreeMap::new();
    let mut vuln_counts = VulnerabilitiesCount::default();
    let mut highest_severity: Option<Severity> = None;

    for (node_path, pkg_name, ver_str, is_direct) in &installed_packages {
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

                    match sev {
                        Severity::Info => vuln_counts.info += 1,
                        Severity::Low => vuln_counts.low += 1,
                        Severity::Moderate => vuln_counts.moderate += 1,
                        Severity::High => vuln_counts.high += 1,
                        Severity::Critical => vuln_counts.critical += 1,
                    }
                    vuln_counts.total += 1;

                    let via_item = ViaItem {
                        source: adv.id.clone(),
                        name: pkg_name.clone(),
                        dependency: pkg_name.clone(),
                        title: adv.title.clone().unwrap_or_else(|| format!("Vulnerability in {pkg_name}")),
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
                            fix_available: true,
                        }
                    });

                    // Update severity if this advisory is higher
                    let existing_sev = Severity::from_str(&entry.severity).unwrap_or(Severity::Low);
                    if sev > existing_sev {
                        entry.severity = sev_str;
                    }

                    if !entry.nodes.contains(node_path) {
                        entry.nodes.push(node_path.clone());
                    }
                    if !entry.via.iter().any(|v| v.source == via_item.source) {
                        entry.via.push(via_item);
                    }
                }
            }
        }
    }

    let report = AuditReport {
        audit_report_version: 2,
        vulnerabilities,
        metadata: AuditMetadata {
            vulnerabilities: vuln_counts.clone(),
            dependencies: dep_counts,
        },
    };

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

fn print_human_audit_report(report: &AuditReport) {
    if report.vulnerabilities.is_empty() {
        println!("found 0 vulnerabilities");
        return;
    }

    println!("# npm audit report\n");

    for (name, vuln) in &report.vulnerabilities {
        println!("{name}  {}", vuln.range);
        println!("Severity: {}", vuln.severity);
        for via in &vuln.via {
            println!("{} - {}", via.title, via.url);
        }
        println!("fix available via `rnpm update`");
        for node in &vuln.nodes {
            println!("{node}");
        }
        println!();
    }

    let mut summary_parts = Vec::new();
    if report.metadata.vulnerabilities.critical > 0 {
        summary_parts.push(format!("{} critical", report.metadata.vulnerabilities.critical));
    }
    if report.metadata.vulnerabilities.high > 0 {
        summary_parts.push(format!("{} high", report.metadata.vulnerabilities.high));
    }
    if report.metadata.vulnerabilities.moderate > 0 {
        summary_parts.push(format!("{} moderate", report.metadata.vulnerabilities.moderate));
    }
    if report.metadata.vulnerabilities.low > 0 {
        summary_parts.push(format!("{} low", report.metadata.vulnerabilities.low));
    }
    if report.metadata.vulnerabilities.info > 0 {
        summary_parts.push(format!("{} info", report.metadata.vulnerabilities.info));
    }

    println!(
        "{} severity {}\n\nTo address issues, run:\n  rnpm update",
        summary_parts.join(", "),
        if report.metadata.vulnerabilities.total == 1 { "vulnerability" } else { "vulnerabilities" }
    );
}
