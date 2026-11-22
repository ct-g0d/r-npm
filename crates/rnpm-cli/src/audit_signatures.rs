//! `npm audit signatures`: verify the registry signatures of installed
//! packages, as npm's lib/utils/verify-signatures.js does.
//!
//! Attestations (`dist.attestations`) are not verified: that needs Sigstore
//! bundle verification against the TUF trust root.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

use anyhow::anyhow;
use rnpm_core::spec::PackageTarget;
use rnpm_registry::metadata::AbbreviatedPackageMetadata;
use rnpm_registry::RegistryClient;
use serde_json::{json, Value};

use crate::inspect_tree::{candidate_locations, scan_disk_packages};

/// Some signatures are invalid or missing: the report is printed, exit 1.
#[derive(Debug)]
pub struct SignaturesFailed;

impl std::fmt::Display for SignaturesFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid or missing registry signatures")
    }
}

impl std::error::Error for SignaturesFailed {}

/// npm's `MISSING_TIME_CUTOFF` for packuments without publish times.
const MISSING_TIME_CUTOFF: &str = "2015-01-01T00:00:00.000Z";

struct RegistryKey {
    keyid: String,
    spki: Vec<u8>,
    expires: Option<String>,
}

struct VerifiedPkg {
    name: String,
    version: String,
    location: String,
    registry: String,
    has_signature: bool,
    has_attestation: bool,
}

struct Package {
    name: String,
    version: String,
    location: String,
    registry: String,
    edge_type: &'static str,
}

/// An installed node's dependency edges, keyed by name. Later dependency
/// types replace earlier ones, as arborist's `#loadDeps` does.
fn edges_out(pkg: &Value, is_root: bool, legacy_peer_deps: bool) -> Vec<(String, String, &'static str)> {
    let mut edges: BTreeMap<String, (String, &'static str)> = BTreeMap::new();
    let mut load = |section: &str, edge_type: &dyn Fn(&str) -> &'static str| {
        for (name, spec) in pkg.get(section).and_then(Value::as_object).into_iter().flatten() {
            let spec = spec.as_str().unwrap_or_default().to_string();
            edges.insert(name.clone(), (spec, edge_type(name)));
        }
    };
    if !legacy_peer_deps {
        let meta = pkg.get("peerDependenciesMeta");
        load("peerDependencies", &|name| {
            // An optional peer is an optional edge.
            if meta.and_then(|m| m[name]["optional"].as_bool()) == Some(true) {
                "optionalDependencies"
            } else {
                "peerDependencies"
            }
        });
    }
    load("dependencies", &|_| "dependencies");
    load("optionalDependencies", &|_| "optionalDependencies");
    if is_root {
        load("devDependencies", &|_| "devDependencies");
    }
    edges.into_iter().map(|(name, (spec, t))| (name, spec, t)).collect()
}

/// The registry package name an edge spec resolves through, if any.
fn registry_name(name: &str, spec: &str) -> Option<String> {
    match PackageTarget::parse(spec).ok()? {
        PackageTarget::Version(_) | PackageTarget::Range(_) | PackageTarget::Tag(_) => {
            Some(name.to_string())
        }
        PackageTarget::Alias { name, .. } => Some(name),
        _ => None,
    }
}

fn is_link(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink())
        || rnpm_fs::junction::is_junction(dir).unwrap_or(false)
}

pub async fn run(project_dir: &Path, json_output: bool) -> anyhow::Result<()> {
    let start = Instant::now();
    let config = rnpm_config::Config::load(Some(project_dir)).unwrap_or_default();
    if config.get_bool("global") == Some(true) {
        return Err(anyhow!(
            "npm error code EAUDITGLOBAL\nnpm error `npm audit signatures` does not support global packages"
        ));
    }
    let legacy_peer_deps = config.get_bool("legacy-peer-deps").unwrap_or(false);
    let disk = scan_disk_packages(project_dir);
    let root: Value = std::fs::read_to_string(project_dir.join("package.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);

    let mut nodes: Vec<(&str, &Value, bool)> = vec![("", &root, true)];
    let mut locations: Vec<&String> = disk.keys().collect();
    locations.sort();
    for loc in locations {
        let pkg = &disk[loc];
        if let Some(raw) = pkg.raw_json.as_ref().filter(|_| !is_link(&pkg.dir_path)) {
            nodes.push((loc.as_str(), raw, false));
        }
    }

    let client = registry_client(&config)?;
    let mut edge_count = 0usize;
    let mut registries = BTreeSet::new();
    let mut packages = Vec::new();
    let mut checked = HashSet::new();
    for (from, pkg, is_root) in nodes {
        for (name, spec, edge_type) in edges_out(pkg, is_root, legacy_peer_deps) {
            edge_count += 1;
            let Some(real_name) = registry_name(&name, &spec) else {
                // Any npa-valid spec still names a registry to fetch keys from.
                registries.insert(client.registry_for_package(&name).to_string());
                continue;
            };
            let registry = client.registry_for_package(&real_name).to_string();
            registries.insert(registry.clone());
            let Some(target) = candidate_locations(from, &name)
                .into_iter()
                .find_map(|loc| disk.get(&loc))
            else {
                continue;
            };
            let Some(version) = target.version.clone() else {
                continue;
            };
            if is_link(&target.dir_path) || !checked.insert(target.location.clone()) {
                continue;
            }
            packages.push(Package {
                name: real_name,
                version,
                location: target.location.clone(),
                registry,
                edge_type,
            });
        }
    }
    if edge_count == 0 {
        return Err(anyhow!("npm error found no installed dependencies to audit"));
    }

    let warn = !matches!(config.get("loglevel"), Some("silent" | "error"));
    let mut keys: HashMap<String, Vec<RegistryKey>> = HashMap::new();
    for registry in &registries {
        // npm reads registry.npmjs.org's keys from Sigstore's TUF repository
        // and any other registry's from its keys endpoint.
        let url = reqwest::Url::parse(registry)?;
        if warn && url.host_str() != Some("registry.npmjs.org") {
            eprintln!(
                "npm warn Fetching verification keys using TUF failed.  Fetching directly from {registry}."
            );
        }
        if let Some(found) = fetch_keys(&client, &url).await? {
            keys.insert(registry.clone(), found);
        }
    }

    let mut audited = 0usize;
    let mut verified_signatures = 0usize;
    let mut verified_attestations = 0usize;
    let mut verified_pkgs: Vec<VerifiedPkg> = Vec::new();
    let mut invalid: Vec<Value> = Vec::new();
    let mut missing: Vec<Value> = Vec::new();
    let mut packuments: HashMap<String, AbbreviatedPackageMetadata> = HashMap::new();
    for pkg in &packages {
        if !packuments.contains_key(&pkg.name) {
            let packument = client.get_package_metadata_full(&pkg.name).await?;
            packuments.insert(pkg.name.clone(), packument);
        }
        let packument = &packuments[&pkg.name];
        let Some(manifest) = packument.versions.get(&pkg.version) else {
            return Err(anyhow!(
                "npm error code ETARGET\nnpm error notarget No matching version found for {}@{}.\nnpm error notarget In most cases you or one of your dependencies are requesting\nnpm error notarget a package version that doesn't exist.",
                pkg.name,
                pkg.version
            ));
        };
        let registry_keys = keys.get(&pkg.registry).map(Vec::as_slice).unwrap_or_default();
        if !registry_keys.is_empty() || manifest.dist.attestations.is_some() {
            audited += 1;
        }
        let integrity = manifest.dist.integrity.clone().or_else(|| {
            let hex = manifest.dist.shasum.as_deref()?;
            let bytes = data_encoding::HEXLOWER_PERMISSIVE.decode(hex.as_bytes()).ok()?;
            Some(format!("sha1-{}", data_encoding::BASE64.encode(&bytes)))
        });
        let resolved = manifest.dist.tarball.clone();
        let id = format!("{}@{}", manifest.name, manifest.version);
        let signatures = match integrity.as_ref() {
            Some(_) => manifest.dist.signatures.as_slice(),
            None => &[],
        };
        let published = packument
            .time
            .get(&manifest.version)
            .map(String::as_str)
            .unwrap_or(MISSING_TIME_CUTOFF);
        let published = rnpm_config::date::parse_js_date(published).unwrap_or(i64::MIN);
        let mut bad = None;
        for signature in signatures {
            let Some(key) = registry_keys.iter().find(|k| k.keyid == signature.keyid) else {
                return Err(anyhow!(
                    "npm error code EMISSINGSIGNATUREKEY\nnpm error {id} has a registry signature with keyid: {} but no corresponding public key can be found",
                    signature.keyid
                ));
            };
            if let Some(expires) = key.expires.as_deref() {
                if rnpm_config::date::parse_js_date(expires).is_some_and(|end| published >= end) {
                    return Err(anyhow!(
                        "npm error code EEXPIREDSIGNATUREKEY\nnpm error {id} has a registry signature with keyid: {} but the corresponding public key has expired {expires}",
                        signature.keyid
                    ));
                }
            }
            let message = format!("{id}:{}", integrity.as_deref().unwrap_or_default());
            if !verify_ecdsa(&key.spki, message.as_bytes(), &signature.sig) {
                bad = Some((key.keyid.clone(), signature.sig.clone()));
                break;
            }
        }
        let mut has_verified_sig = false;
        if let Some((keyid, sig)) = bad {
            invalid.push(json!({
                "code": "EINTEGRITYSIGNATURE",
                "message": format!("{id} has an invalid registry signature with keyid: {keyid} and signature: {sig}"),
                "integrity": integrity,
                "keyid": keyid,
                "location": pkg.location,
                "name": pkg.name,
                "registry": pkg.registry,
                "resolved": resolved,
                "signature": sig,
                "type": pkg.edge_type,
                "version": pkg.version,
            }));
        } else if !signatures.is_empty() {
            verified_signatures += 1;
            has_verified_sig = true;
        } else if !registry_keys.is_empty() {
            let mut entry = serde_json::Map::new();
            if let Some(integrity) = &integrity {
                entry.insert("integrity".into(), json!(integrity));
            }
            entry.insert("location".into(), json!(pkg.location));
            entry.insert("name".into(), json!(pkg.name));
            entry.insert("registry".into(), json!(pkg.registry));
            entry.insert("resolved".into(), json!(resolved));
            entry.insert("version".into(), json!(pkg.version));
            missing.push(Value::Object(entry));
        }

        let mut has_verified_att = false;
        if let Some(att) = &manifest.dist.attestations {
            let mut bundles: Vec<(Option<String>, rnpm_registry::SigstoreBundle)> = Vec::new();
            if let Some(bundle_val) = &att.bundle {
                if let Ok(b) = serde_json::from_value::<rnpm_registry::SigstoreBundle>(bundle_val.clone()) {
                    bundles.push((att.provenance.as_ref().and_then(|p| p.predicate_type.clone()), b));
                }
            } else if let Some(att_url_str) = &att.url {
                let fetch_url = if let Ok(u) = reqwest::Url::parse(att_url_str) {
                    Some(u)
                } else if let Ok(base) = reqwest::Url::parse(&pkg.registry) {
                    base.join(att_url_str).ok()
                } else {
                    None
                };
                if let Some(url) = fetch_url {
                    let fetch_res = client
                        .execute_with_permit(reqwest::Method::GET, url, Some("application/json"), None)
                        .await;
                    match fetch_res {
                        Ok((resp, _permit)) if resp.status().is_success() => {
                            if let Ok(text) = resp.text().await {
                                if let Ok(resp_doc) = serde_json::from_str::<rnpm_registry::AttestationResponse>(&text) {
                                    for item in resp_doc.attestations {
                                        if let Some(b) = item.bundle {
                                            bundles.push((item.predicate_type, b));
                                        }
                                    }
                                } else if let Ok(single) = serde_json::from_str::<rnpm_registry::SigstoreBundle>(&text) {
                                    bundles.push((None, single));
                                } else if let Ok(single) = rnpm_registry::SigstoreBundle::from_json(&text) {
                                    bundles.push((None, single));
                                }
                            }
                        }
                        Ok((resp, _permit)) => {
                            invalid.push(json!({
                                "code": "EINTEGRITYATTESTATION",
                                "message": format!("{id} failed to fetch attestation from {att_url_str}: HTTP {}", resp.status()),
                                "integrity": integrity,
                                "location": pkg.location,
                                "name": pkg.name,
                                "registry": pkg.registry,
                                "resolved": resolved,
                                "type": pkg.edge_type,
                                "version": pkg.version,
                            }));
                        }
                        Err(e) => {
                            invalid.push(json!({
                                "code": "EINTEGRITYATTESTATION",
                                "message": format!("{id} failed to fetch attestation from {att_url_str}: {e}"),
                                "integrity": integrity,
                                "location": pkg.location,
                                "name": pkg.name,
                                "registry": pkg.registry,
                                "resolved": resolved,
                                "type": pkg.edge_type,
                                "version": pkg.version,
                            }));
                        }
                    }
                }
            }

            if !bundles.is_empty() {
                let verifier = rnpm_registry::ProvenanceVerifier::new(rnpm_registry::ProvenancePolicy::AllowAny);
                let mut att_err = None;
                for (pred_type, bundle) in &bundles {
                    if let Err(e) = verifier.verify(&pkg.name, bundle, integrity.as_deref(), None) {
                        att_err = Some((pred_type.clone(), e.to_string()));
                        break;
                    }
                }
                if let Some((pred_type, err_msg)) = att_err {
                    invalid.push(json!({
                        "code": "EINTEGRITYATTESTATION",
                        "message": format!("{id} has an invalid attestation: {err_msg}"),
                        "integrity": integrity,
                        "predicateType": pred_type,
                        "location": pkg.location,
                        "name": pkg.name,
                        "registry": pkg.registry,
                        "resolved": resolved,
                        "type": pkg.edge_type,
                        "version": pkg.version,
                    }));
                } else {
                    verified_attestations += 1;
                    has_verified_att = true;
                }
            }
        }

        if has_verified_sig || has_verified_att {
            verified_pkgs.push(VerifiedPkg {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                location: pkg.location.clone(),
                registry: pkg.registry.clone(),
                has_signature: has_verified_sig,
                has_attestation: has_verified_att,
            });
        }
    }
    if audited == 0 {
        return Err(anyhow!(
            "npm error found no dependencies to audit that were installed from a supported registry"
        ));
    }

    let by_name = |a: &Value, b: &Value| {
        let (a, b) = (a["name"].as_str().unwrap_or(""), b["name"].as_str().unwrap_or(""));
        a.to_lowercase().cmp(&b.to_lowercase()).then_with(|| a.cmp(b))
    };
    invalid.sort_by(by_name);
    missing.sort_by(by_name);
    let failed = !invalid.is_empty() || !missing.is_empty();

    if json_output {
        let mut out = serde_json::Map::new();
        out.insert("invalid".into(), Value::Array(invalid));
        out.insert("missing".into(), Value::Array(missing));
        if config.get_bool("include-attestations") == Some(true) {
            out.insert("verified_signatures".into(), json!(verified_signatures));
            out.insert("verified_attestations".into(), json!(verified_attestations));
            let verified_list: Vec<Value> = verified_pkgs
                .into_iter()
                .map(|p| {
                    json!({
                        "name": p.name,
                        "version": p.version,
                        "location": p.location,
                        "registry": p.registry,
                        "has_signature": p.has_signature,
                        "has_attestation": p.has_attestation,
                    })
                })
                .collect();
            out.insert("verified".into(), Value::Array(verified_list));
        }
        println!("{}", serde_json::to_string_pretty(&Value::Object(out))?);
    } else {
        print_report(
            audited,
            verified_signatures,
            verified_attestations,
            &invalid,
            &missing,
            start,
        );
    }
    if failed {
        return Err(SignaturesFailed.into());
    }
    Ok(())
}

fn print_report(
    audited: usize,
    verified_signatures: usize,
    verified_attestations: usize,
    invalid: &[Value],
    missing: &[Value],
    start: Instant,
) {
    let plural = if audited > 1 { "s" } else { "" };
    println!(
        "audited {audited} package{plural} in {}s\n",
        start.elapsed().as_secs()
    );
    if verified_signatures == 1 {
        println!("1 package has a verified registry signature\n");
    } else if verified_signatures > 1 {
        println!("{verified_signatures} packages have verified registry signatures\n");
    }
    if verified_attestations == 1 {
        println!("1 package has a verified attestation\n");
    } else if verified_attestations > 1 {
        println!("{verified_attestations} packages have verified attestations\n");
    }
    let id = |v: &Value| {
        format!(
            "{}@{} ({})",
            v["name"].as_str().unwrap_or_default(),
            v["version"].as_str().unwrap_or_default(),
            v["registry"].as_str().unwrap_or_default()
        )
    };
    if !missing.is_empty() {
        if missing.len() == 1 {
            println!("1 package has a missing registry signature but the registry is providing signing keys:\n");
        } else {
            println!(
                "{} packages have missing registry signatures but the registry is providing signing keys:\n",
                missing.len()
            );
        }
        for m in missing {
            println!("{}", id(m));
        }
    }
    if !invalid.is_empty() {
        if !missing.is_empty() {
            println!();
        }
        let sig_invalid: Vec<&Value> = invalid
            .iter()
            .filter(|i| i["code"].as_str() == Some("EINTEGRITYSIGNATURE"))
            .collect();
        let att_invalid: Vec<&Value> = invalid
            .iter()
            .filter(|i| i["code"].as_str() == Some("EINTEGRITYATTESTATION"))
            .collect();

        if !sig_invalid.is_empty() {
            if sig_invalid.len() == 1 {
                println!("1 package has an invalid registry signature:\n");
            } else {
                println!("{} packages have invalid registry signatures:\n", sig_invalid.len());
            }
            for i in &sig_invalid {
                println!("{}", id(i));
            }
            println!();
        }

        if !att_invalid.is_empty() {
            if att_invalid.len() == 1 {
                println!("1 package has an invalid attestation:\n");
            } else {
                println!("{} packages have invalid attestations:\n", att_invalid.len());
            }
            for i in &att_invalid {
                println!("{}", id(i));
            }
            println!();
        }

        if invalid.len() == 1 {
            println!("Someone might have tampered with this package since it was published on the registry!\n");
        } else {
            println!("Someone might have tampered with these packages since they were published on the registry!\n");
        }
    }
}

fn registry_client(config: &rnpm_config::Config) -> anyhow::Result<RegistryClient> {
    let registry = config.npmrc.registry.clone();
    let mut client_config = rnpm_registry::RegistryClientConfig {
        default_registry: registry.clone(),
        auth_tokens: config.npmrc.auth_tokens.clone(),
        basic_auths: config.npmrc.basic_auths(),
        scoped_registries: config.npmrc.scoped_registries.clone(),
        ..Default::default()
    };
    if let Some(token) = config.npmrc.get_auth_token(&registry) {
        client_config.auth_token = Some(token.to_string());
    }
    for url in std::iter::once(&registry).chain(config.npmrc.scoped_registries.values()) {
        if let Some(host) = url.host_str() {
            client_config.trusted_hosts.insert(host.to_ascii_lowercase());
            if let Some(port) = url.port_or_known_default() {
                client_config.trusted_hosts.insert(format!("{host}:{port}"));
            }
        }
    }
    rnpm_install::apply_npmrc_to_client_config(&mut client_config, &config.npmrc);
    Ok(RegistryClient::with_config(client_config)?)
}

/// `GET /-/npm/v1/keys`; a registry answering 404 or 400 has no keys.
async fn fetch_keys(
    client: &RegistryClient,
    registry: &reqwest::Url,
) -> anyhow::Result<Option<Vec<RegistryKey>>> {
    let url = registry.join("-/npm/v1/keys")?;
    let (resp, _permit) = client
        .execute_with_permit(reqwest::Method::GET, url, Some("application/json"), None)
        .await?;
    let status = resp.status().as_u16();
    if status == 404 || status == 400 {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(anyhow!(
            "npm error code E{status}\nnpm error {status} {} - GET {}",
            resp.status().canonical_reason().unwrap_or_default(),
            resp.url()
        ));
    }
    let body: Value = resp.json().await?;
    let keys = body["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|k| {
            Some(RegistryKey {
                keyid: k["keyid"].as_str()?.to_string(),
                spki: data_encoding::BASE64.decode(k["key"].as_str()?.as_bytes()).ok()?,
                expires: k["expires"].as_str().map(str::to_string),
            })
        })
        .collect();
    Ok(Some(keys))
}

/// ECDSA P-256 / SHA-256 over `message` with an ASN.1 DER signature, the
/// scheme of npm registry keys (`ecdsa-sha2-nistp256`).
fn verify_ecdsa(spki: &[u8], message: &[u8], signature_b64: &str) -> bool {
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
    // A P-256 SubjectPublicKeyInfo ends in the 65-byte uncompressed point.
    const P256_SPKI_LEN: usize = 91;
    let Ok(signature) = data_encoding::BASE64.decode(signature_b64.as_bytes()) else {
        return false;
    };
    if spki.len() != P256_SPKI_LEN {
        return false;
    }
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &spki[spki.len() - 65..])
        .verify(message, &signature)
        .is_ok()
}
