use super::{PackageVulnerability, Severity};
use rnpm_core::semver::{Range, Version};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::str::FromStr;

fn satisfies(version: &str, spec: &str) -> bool {
    Version::parse(version)
        .ok()
        .zip(Range::parse(spec).ok())
        .is_some_and(|(v, r)| r.satisfies(&v))
}

fn versions(packument: &Value) -> Vec<String> {
    let mut versions: Vec<_> = packument["versions"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(v, _)| Version::parse(v).ok().map(|parsed| (parsed, v.clone())))
        .collect();
    versions.sort_by(|a, b| a.0.cmp(&b.0));
    versions.into_iter().map(|(_, v)| v).collect()
}

// Port of semver/ranges/simplify: simplify only relative to published versions,
// and retain the supplied range when its spelling is shorter.
fn simplify(versions: &[String], affected: &BTreeSet<String>, original: &str) -> String {
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < versions.len() {
        if !affected.contains(&versions[i]) {
            i += 1;
            continue;
        }
        let first = i;
        while i + 1 < versions.len() && affected.contains(&versions[i + 1]) {
            i += 1;
        }
        let last = i;
        ranges.push(if last + 1 == versions.len() {
            if first == 0 {
                "*".to_string()
            } else {
                format!(">={}", versions[first])
            }
        } else if first == last {
            versions[first].clone()
        } else if first == 0 {
            format!("<={}", versions[last])
        } else {
            format!("{} - {}", versions[first], versions[last])
        });
        i += 1;
    }
    let simplified = ranges.join(" || ");
    if simplified.len() < original.len() {
        simplified
    } else {
        original.to_string()
    }
}

fn dep_spec<'a>(manifest: &'a Value, name: &str) -> Option<&'a str> {
    // Same precedence as metavuln-calculator/get-dep-spec.js.
    manifest["dependencies"][name]
        .as_str()
        .or_else(|| manifest["optionalDependencies"][name].as_str())
        .or_else(|| manifest["peerDependencies"][name].as_str())
}

fn resolved_location(packages: &Value, from: &str, name: &str) -> Option<String> {
    let mut parent = from;
    loop {
        let candidate = if parent.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{parent}/node_modules/{name}")
        };
        if packages.get(&candidate).is_some() {
            return Some(candidate);
        }
        if parent.is_empty() {
            return None;
        }
        parent = parent.rsplit_once('/').map_or("", |(head, _)| head);
    }
}

#[derive(Clone)]
struct Cause {
    name: String,
    range: String,
    severity: String,
}

async fn load_packument(
    client: &rnpm_registry::RegistryClient,
    name: &str,
    cache: &mut BTreeMap<String, Value>,
) -> anyhow::Result<Value> {
    if let Some(value) = cache.get(name) {
        return Ok(value.clone());
    }
    let url = client
        .registry_for_package(name)
        .join(&rnpm_registry::client::encode_package_name(name))?;
    let (response, _permit) = client
        .execute_with_permit(reqwest::Method::GET, url, Some("application/json"), None)
        .await?;
    let value = response.error_for_status()?.json::<Value>().await?;
    cache.insert(name.to_string(), value.clone());
    Ok(value)
}

pub(super) async fn complete_graph(
    vulnerabilities: &mut BTreeMap<String, PackageVulnerability>,
    lockfile: &rnpm_lockfile::LockfileV3,
    registry: &str,
    config: &rnpm_config::Config,
) -> anyhow::Result<()> {
    if vulnerabilities.is_empty() {
        return Ok(());
    }
    let registry = reqwest::Url::parse(registry)?;
    let mut client_config = rnpm_registry::RegistryClientConfig {
        default_registry: registry.clone(),
        auth_tokens: config.npmrc.auth_tokens.clone(),
        scoped_registries: config.npmrc.scoped_registries.clone(),
        ..Default::default()
    };
    if let Some(token) = config.npmrc.get_auth_token(&registry) {
        client_config.auth_token = Some(token.to_string());
    }
    for url in std::iter::once(&registry).chain(config.npmrc.scoped_registries.values()) {
        if let Some(host) = url.host_str() {
            client_config
                .trusted_hosts
                .insert(host.to_ascii_lowercase());
            if let Some(port) = url.port_or_known_default() {
                client_config.trusted_hosts.insert(format!("{host}:{port}"));
            }
        }
    }
    rnpm_install::apply_npmrc_to_client_config(&mut client_config, &config.npmrc);
    let client = rnpm_registry::RegistryClient::with_config(client_config)?;
    let packages = serde_json::to_value(&lockfile.packages)?;
    let mut packuments = BTreeMap::new();
    let mut causes = VecDeque::new();
    let mut ranges: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, vuln) in vulnerabilities.iter() {
        for via in &vuln.via {
            if let Some(range) = via.get("range").and_then(Value::as_str) {
                causes.push_back(Cause {
                    name: name.clone(),
                    range: range.to_string(),
                    severity: via["severity"].as_str().unwrap_or("high").to_string(),
                });
                ranges
                    .entry(name.clone())
                    .or_default()
                    .push(range.to_string());
            }
        }
    }
    let mut seen = BTreeSet::new();
    let mut traversed_nodes = BTreeSet::new();
    while let Some(cause) = causes.pop_front() {
        if !seen.insert((cause.name.clone(), cause.range.clone())) {
            continue;
        }
        let source = load_packument(&client, &cause.name, &mut packuments).await?;
        let source_versions = versions(&source);
        // Incoming edges from installed nodes determine which metavulns matter.
        let source_nodes: BTreeSet<_> = packages
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(_, pkg)| {
                pkg["version"]
                    .as_str()
                    .is_some_and(|v| satisfies(v, &cause.range))
            })
            .filter(|(loc, _)| loc.ends_with(&format!("node_modules/{}", cause.name)))
            // Arborist visits incoming edges once per affected installed node,
            // even when later advisories also affect that node.
            .filter(|(loc, _)| traversed_nodes.insert((cause.name.clone(), (*loc).clone())))
            .map(|(loc, _)| loc.clone())
            .collect();
        let mut dependents = BTreeMap::<String, Vec<String>>::new();
        for (loc, pkg) in packages.as_object().into_iter().flatten() {
            if loc.is_empty() || dep_spec(pkg, &cause.name).is_none() {
                continue;
            }
            if !resolved_location(&packages, loc, &cause.name)
                .is_some_and(|target| source_nodes.contains(&target))
            {
                continue;
            }
            let name = pkg["name"].as_str().map(str::to_string).unwrap_or_else(|| {
                loc.rsplit("node_modules/")
                    .next()
                    .unwrap_or(loc)
                    .to_string()
            });
            dependents.entry(name).or_default().push(loc.clone());
        }
        for (name, locations) in dependents {
            if name == cause.name {
                continue;
            }
            let packument = load_packument(&client, &name, &mut packuments).await?;
            let published = versions(&packument);
            let test_spec = |spec: &str| {
                // A dependency is a metavulnerability only when every available
                // version satisfying its edge is vulnerable (not merely the installed one).
                !source_versions
                    .iter()
                    .any(|v| satisfies(v, spec) && !satisfies(v, &cause.range))
            };
            let affected: BTreeSet<_> = published
                .iter()
                .filter(|v| {
                    let mani = &packument["versions"][*v];
                    dep_spec(mani, &cause.name).is_some_and(|spec| {
                        if mani["bundleDependencies"].as_array().is_some_and(|deps| deps.iter().any(|d| d == &cause.name)) {
                            source_versions.iter().any(|version| satisfies(version, spec) && satisfies(version, &cause.range))
                        } else { test_spec(spec) }
                    })
                })
                .cloned()
                .collect();
            let nodes: Vec<_> = locations
                .into_iter()
                .filter(|loc| {
                    let pkg = &packages[loc];
                    let version = pkg["version"].as_str().unwrap_or("");
                    affected.contains(version)
                        || (packument["versions"].get(version).is_none()
                            && dep_spec(pkg, &cause.name).is_some_and(test_spec))
                })
                .collect();
            if nodes.is_empty() {
                continue;
            }
            let original = affected.iter().cloned().collect::<Vec<_>>().join(" || ");
            let range = simplify(&published, &affected, &original);
            let direct = nodes.iter().any(|loc| {
                dep_spec(&packages[""], &name).is_some()
                    && resolved_location(&packages, "", &name).as_ref() == Some(loc)
                    || packages[""]["devDependencies"].get(&name).is_some()
            });
            let vuln =
                vulnerabilities
                    .entry(name.clone())
                    .or_insert_with(|| PackageVulnerability {
                        name: name.clone(),
                        severity: cause.severity.clone(),
                        is_direct: direct,
                        via: Vec::new(),
                        effects: Vec::new(),
                        range: range.clone(),
                        nodes: Vec::new(),
                        fix_available: json!(true),
                    });
            if Severity::from_str(&cause.severity)? > Severity::from_str(&vuln.severity)? {
                vuln.severity = cause.severity.clone();
            }
            let via = json!(cause.name);
            if !vuln.via.contains(&via) {
                vuln.via.push(via);
            }
            for loc in nodes {
                if !vuln.nodes.contains(&loc) {
                    vuln.nodes.push(loc);
                }
            }
            ranges.entry(name.clone()).or_default().push(range.clone());
            if let Some(source) = vulnerabilities.get_mut(&cause.name) {
                if !source.effects.contains(&name) {
                    source.effects.push(name.clone());
                }
            }
            causes.push_back(Cause {
                name,
                range,
                severity: cause.severity.clone(),
            });
        }
    }
    for (name, vuln) in vulnerabilities.iter_mut() {
        let packument = load_packument(&client, name, &mut packuments).await?;
        let published = versions(&packument);
        let range = ranges[name].join(" || ");
        let affected = published
            .iter()
            .filter(|v| satisfies(v, &range))
            .cloned()
            .collect();
        vuln.range = simplify(&published, &affected, &range);
        vuln.nodes.sort();
        vuln.effects.sort();
        vuln.via
            .sort_by_key(|v| v.get("source").unwrap_or(v).to_string());
        // A top-level range with no safe published candidate requires --force.
        let root = &packages[""];
        let spec = dep_spec(root, name).or_else(|| root["devDependencies"][name].as_str());
        if let Some(spec) = spec {
            if !published
                .iter()
                .any(|v| satisfies(v, spec) && !satisfies(v, &vuln.range))
            {
                let current = published
                    .iter()
                    .rev()
                    .find(|v| satisfies(v, spec))
                    .and_then(|v| Version::parse(v).ok());
                let safe: Vec<_> = published
                    .iter()
                    .filter(|v| !satisfies(v, &vuln.range))
                    .collect();
                // npm-pick-manifest prefers a nonbreaking escape before latest.
                let target = safe
                    .iter()
                    .rev()
                    .find(|v| {
                        current
                            .as_ref()
                            .zip(Version::parse(v).ok())
                            .is_some_and(|(c, t)| satisfies(&t.to_string(), &format!("^{c}")))
                    })
                    .copied()
                    .or_else(|| safe.last().copied());
                vuln.fix_available = target.map_or(json!(false), |v| json!({"name":name,"version":v,"isSemVerMajor":current.as_ref().zip(Version::parse(v).ok()).is_none_or(|(c,t)| !satisfies(&t.to_string(), &format!("^{c}")))}));
            }
        }
    }
    // Propagate the strictest top-level remediation back down its via graph.
    let mut queue: VecDeque<_> = vulnerabilities
        .iter()
        .filter(|(_, v)| v.fix_available != json!(true))
        .map(|(n, v)| (n.clone(), v.fix_available.clone()))
        .collect();
    let mut seen = BTreeSet::new();
    while let Some((name, fix)) = queue.pop_front() {
        if !seen.insert((name.clone(), fix.to_string())) {
            continue;
        }
        let via = vulnerabilities[&name].via.clone();
        for dep in via.iter().filter_map(Value::as_str) {
            let vuln = vulnerabilities
                .get_mut(dep)
                .expect("via references a vulnerability");
            if fix == json!(false)
                || vuln.fix_available == json!(true)
                || (fix.is_object() && vuln.fix_available["isSemVerMajor"] != json!(true))
            {
                vuln.fix_available = fix.clone();
                queue.push_back((dep.to_string(), fix.clone()));
            }
        }
    }
    Ok(())
}
