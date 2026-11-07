use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Options controlling SBOM generation.
#[derive(Debug, Clone)]
pub struct SbomOptions {
    pub format: String,
    pub sbom_type: String,
    pub package_lock_only: bool,
    pub omit: Vec<String>,
}

impl Default for SbomOptions {
    fn default() -> Self {
        Self {
            format: "spdx".to_string(),
            sbom_type: "application".to_string(),
            package_lock_only: false,
            omit: Vec::new(),
        }
    }
}

/// Helper to sanitize a string for SPDX identifier (letters, numbers, '.', '-').
pub fn sanitize_spdx(s: &str) -> String {
    let sanitized: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches('-');
    if trimmed.is_empty() {
        "item".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Convert npm package name and version to standard purl.
pub fn make_purl(name: &str, version: &str) -> String {
    let encoded_name = if let Some(stripped) = name.strip_prefix('@') {
        format!("%40{}", stripped)
    } else {
        name.to_string()
    };
    format!("pkg:npm/{encoded_name}@{version}")
}

/// Decode base64 lockfile integrity string and return (algorithm, lowercase_hex).
pub fn integrity_to_hex(integrity: &str) -> Option<(String, String)> {
    let (algo_part, b64_part) = integrity.split_once('-')?;
    let b64_clean = b64_part.trim();
    let bytes = data_encoding::BASE64
        .decode(b64_clean.as_bytes())
        .or_else(|_| data_encoding::BASE64_NOPAD.decode(b64_clean.as_bytes()))
        .ok()?;
    let hex = data_encoding::HEXLOWER.encode(&bytes);
    Some((algo_part.to_ascii_lowercase(), hex))
}

/// Generate a valid RFC 4122 v4 UUID string without external dependencies.
pub fn generate_uuid() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let r1 = (nanos ^ 0x9e3779b97f4a7c15) as u64;
    let r2 = (nanos.rotate_left(32) ^ 0xbf58476d1ce4e5b9) as u64;
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (r1 >> 32) as u32,
        (r1 >> 16) as u16,
        (r1 & 0x0fff) as u16,
        ((r2 >> 48) as u16 & 0x3fff) | 0x8000,
        r2 & 0xffffffffffff
    )
}

/// Format current UTC time into RFC 3339 string.
pub fn current_rfc3339_time() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = secs / 86400;
    let rem_secs = secs % 86400;
    let hours = rem_secs / 3600;
    let mins = (rem_secs % 3600) / 60;
    let s = rem_secs % 60;

    let z = days as i64 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, mins, s
    )
}

fn derive_package_name(path: &str) -> String {
    let clean = path.replace('\\', "/");
    let parts: Vec<&str> = clean.split('/').collect();
    if let Some(idx) = parts.iter().rposition(|&p| p == "node_modules") {
        if idx + 1 < parts.len() {
            if parts[idx + 1].starts_with('@') && idx + 2 < parts.len() {
                return format!("{}/{}", parts[idx + 1], parts[idx + 2]);
            }
            return parts[idx + 1].to_string();
        }
    }
    clean
}

// -------------------------------------------------------------------------
// SPDX 2.3 Model
// -------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxDocument {
    pub spdx_version: String,
    pub data_license: String,
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    pub name: String,
    pub document_namespace: String,
    pub creation_info: SpdxCreationInfo,
    pub document_describes: Vec<String>,
    pub packages: Vec<SpdxPackage>,
    pub relationships: Vec<SpdxRelationship>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxCreationInfo {
    pub creators: Vec<String>,
    pub created: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxPackage {
    pub name: String,
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    pub version_info: String,
    pub package_file_name: String,
    pub download_location: String,
    pub license_declared: String,
    pub external_refs: Vec<SpdxExternalRef>,
    pub checksums: Vec<SpdxChecksum>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxExternalRef {
    pub reference_category: String,
    pub reference_type: String,
    pub reference_locator: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxChecksum {
    pub algorithm: String,
    pub checksum_value: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxRelationship {
    pub spdx_element_id: String,
    pub relationship_type: String,
    pub related_spdx_element: String,
}

// -------------------------------------------------------------------------
// CycloneDX 1.5 Model
// -------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxDocument {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub metadata: CycloneDxMetadata,
    pub components: Vec<CycloneDxComponent>,
    pub dependencies: Vec<CycloneDxDependency>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxMetadata {
    pub timestamp: String,
    pub tools: Vec<CycloneDxTool>,
    pub lifecycles: Vec<CycloneDxLifecycle>,
    pub component: CycloneDxRootComponent,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxTool {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxLifecycle {
    pub phase: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CycloneDxRootComponent {
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
    pub purl: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxComponent {
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
    pub purl: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub external_references: Vec<CycloneDxExternalReference>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hashes: Vec<CycloneDxHash>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CycloneDxExternalReference {
    #[serde(rename = "type")]
    pub ref_type: String,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CycloneDxHash {
    pub alg: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxDependency {
    #[serde(rename = "ref")]
    pub component_ref: String,
    pub depends_on: Vec<String>,
}

// -------------------------------------------------------------------------
// Core SBOM Generator Logic
// -------------------------------------------------------------------------

/// Generate SBOM data structure from project directory.
pub fn generate_sbom(
    project_dir: &Path,
    options: &SbomOptions,
) -> anyhow::Result<serde_json::Value> {
    let manifest_path = project_dir.join("package.json");
    if !manifest_path.is_file() {
        return Err(anyhow::anyhow!(
            "npm error code ENOENT\nnpm error package.json not found in {}",
            project_dir.display()
        ));
    }

    let lockfile_path = project_dir.join("package-lock.json");
    if !lockfile_path.is_file() {
        return Err(anyhow::anyhow!(
            "npm error code ENOENT\nnpm error package-lock.json not found in {}",
            project_dir.display()
        ));
    }

    let manifest = rnpm_core::manifest::Manifest::from_file(&manifest_path)?;
    let root_name = manifest.name.unwrap_or_else(|| "project".to_string());
    let root_version = manifest.version.unwrap_or_else(|| "1.0.0".to_string());

    let lockfile = rnpm_lockfile::load_and_migrate(&lockfile_path)
        .map_err(|e| anyhow::anyhow!("Failed to load lockfile: {e}"))?;

    let root_license = manifest
        .extra
        .get("license")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .or_else(|| lockfile.packages.get("").and_then(|r| r.license.clone()))
        .unwrap_or_else(|| "NOASSERTION".to_string());

    let (omit_dev, omit_optional, omit_peer) = crate::parse_omit_options(&options.omit);

    // 1. Filter packages
    let mut included_paths: BTreeSet<String> = BTreeSet::new();
    for (path, pkg) in &lockfile.packages {
        if path.is_empty() {
            included_paths.insert(path.clone());
            continue;
        }
        if omit_dev && pkg.is_effective_dev() {
            continue;
        }
        if omit_optional && pkg.is_effective_optional() {
            continue;
        }
        if omit_peer && pkg.is_peer() {
            continue;
        }
        included_paths.insert(path.clone());
    }

    // 2. Compute parent -> children dependency map
    let mut parent_to_children: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for parent_path in &included_paths {
        let pkg = match lockfile.packages.get(parent_path) {
            Some(p) => p,
            None => continue,
        };

        let mut dep_names = BTreeSet::new();
        if let Some(deps) = &pkg.dependencies {
            for k in deps.keys() {
                dep_names.insert(k.clone());
            }
        }
        if parent_path.is_empty() && !omit_dev {
            if let Some(dev_deps) = &pkg.dev_dependencies {
                for k in dev_deps.keys() {
                    dep_names.insert(k.clone());
                }
            }
        }
        if !omit_optional {
            if let Some(opt_deps) = &pkg.optional_dependencies {
                for k in opt_deps.keys() {
                    dep_names.insert(k.clone());
                }
            }
        }

        let mut children = Vec::new();
        for dep in dep_names {
            let nested_path = if parent_path.is_empty() {
                format!("node_modules/{dep}")
            } else {
                format!("{parent_path}/node_modules/{dep}")
            };

            if included_paths.contains(&nested_path) {
                children.push(nested_path);
            } else {
                let hoisted_path = format!("node_modules/{dep}");
                if included_paths.contains(&hoisted_path) {
                    children.push(hoisted_path);
                }
            }
        }
        children.sort();
        parent_to_children.insert(parent_path.clone(), children);
    }

    // 3. Render format
    match options.format.to_ascii_lowercase().as_str() {
        "spdx" => {
            let root_spdx_id = format!("SPDXRef-Package-{}", sanitize_spdx(&root_name));
            let mut packages = Vec::new();

            // Root package
            let root_purl = make_purl(&root_name, &root_version);
            packages.push(SpdxPackage {
                name: root_name.clone(),
                spdx_id: root_spdx_id.clone(),
                version_info: root_version.clone(),
                package_file_name: "package.json".to_string(),
                download_location: "NONE".to_string(),
                license_declared: root_license,
                external_refs: vec![SpdxExternalRef {
                    reference_category: "PACKAGE-MANAGER".to_string(),
                    reference_type: "purl".to_string(),
                    reference_locator: root_purl,
                }],
                checksums: Vec::new(),
            });

            // Dependency packages
            let mut path_to_spdx_id = BTreeMap::new();
            path_to_spdx_id.insert("".to_string(), root_spdx_id.clone());

            for path in &included_paths {
                if path.is_empty() {
                    continue;
                }
                let pkg = match lockfile.packages.get(path) {
                    Some(p) => p,
                    None => continue,
                };
                let name = pkg
                    .name
                    .clone()
                    .unwrap_or_else(|| derive_package_name(path));
                let version = pkg.version.clone().unwrap_or_else(|| "0.0.0".to_string());
                let spdx_id = format!("SPDXRef-Package-{}", sanitize_spdx(path));
                path_to_spdx_id.insert(path.clone(), spdx_id.clone());

                let purl = make_purl(&name, &version);
                let license = pkg
                    .license
                    .clone()
                    .unwrap_or_else(|| "NOASSERTION".to_string());
                let download = pkg
                    .resolved
                    .clone()
                    .unwrap_or_else(|| "NOASSERTION".to_string());

                let mut checksums = Vec::new();
                if let Some(integrity) = &pkg.integrity {
                    if let Some((algo, hex)) = integrity_to_hex(integrity) {
                        let spdx_algo = match algo.as_str() {
                            "sha512" => "SHA512".to_string(),
                            "sha1" => "SHA1".to_string(),
                            "sha256" => "SHA256".to_string(),
                            other => other.to_ascii_uppercase(),
                        };
                        checksums.push(SpdxChecksum {
                            algorithm: spdx_algo,
                            checksum_value: hex,
                        });
                    }
                }

                packages.push(SpdxPackage {
                    name,
                    spdx_id,
                    version_info: version,
                    package_file_name: path.clone(),
                    download_location: download,
                    license_declared: license,
                    external_refs: vec![SpdxExternalRef {
                        reference_category: "PACKAGE-MANAGER".to_string(),
                        reference_type: "purl".to_string(),
                        reference_locator: purl,
                    }],
                    checksums,
                });
            }

            // Relationships
            let mut relationships = Vec::new();
            relationships.push(SpdxRelationship {
                spdx_element_id: "SPDXRef-DOCUMENT".to_string(),
                relationship_type: "DESCRIBES".to_string(),
                related_spdx_element: root_spdx_id.clone(),
            });

            for (parent_path, children) in &parent_to_children {
                let parent_id = match path_to_spdx_id.get(parent_path) {
                    Some(id) => id,
                    None => continue,
                };
                for child_path in children {
                    let child_id = match path_to_spdx_id.get(child_path) {
                        Some(id) => id,
                        None => continue,
                    };
                    relationships.push(SpdxRelationship {
                        spdx_element_id: child_id.clone(),
                        relationship_type: "DEPENDENCY_OF".to_string(),
                        related_spdx_element: parent_id.clone(),
                    });
                }
            }

            let doc = SpdxDocument {
                spdx_version: "SPDX-2.3".to_string(),
                data_license: "CC0-1.0".to_string(),
                spdx_id: "SPDXRef-DOCUMENT".to_string(),
                name: format!("{root_name}@{root_version}"),
                document_namespace: format!(
                    "http://spdx.org/spdxdocs/{}-{}-{}",
                    sanitize_spdx(&root_name),
                    sanitize_spdx(&root_version),
                    generate_uuid()
                ),
                creation_info: SpdxCreationInfo {
                    creators: vec!["Tool: rnpm".to_string()],
                    created: current_rfc3339_time(),
                },
                document_describes: vec![root_spdx_id],
                packages,
                relationships,
            };

            Ok(serde_json::to_value(doc)?)
        }
        "cyclonedx" => {
            let root_purl = make_purl(&root_name, &root_version);
            let root_bom_ref = root_purl.clone();

            let mut components = Vec::new();
            let mut path_to_bom_ref = BTreeMap::new();
            let mut seen_bom_refs = BTreeSet::new();

            path_to_bom_ref.insert("".to_string(), root_bom_ref.clone());
            seen_bom_refs.insert(root_bom_ref.clone());

            for path in &included_paths {
                if path.is_empty() {
                    continue;
                }
                let pkg = match lockfile.packages.get(path) {
                    Some(p) => p,
                    None => continue,
                };
                let name = pkg
                    .name
                    .clone()
                    .unwrap_or_else(|| derive_package_name(path));
                let version = pkg.version.clone().unwrap_or_else(|| "0.0.0".to_string());
                let purl = make_purl(&name, &version);

                let bom_ref = if seen_bom_refs.insert(purl.clone()) {
                    purl.clone()
                } else {
                    format!("{}#{}", purl, sanitize_spdx(path))
                };
                path_to_bom_ref.insert(path.clone(), bom_ref.clone());

                let mut external_references = Vec::new();
                if let Some(resolved) = &pkg.resolved {
                    external_references.push(CycloneDxExternalReference {
                        ref_type: "distribution".to_string(),
                        url: resolved.clone(),
                    });
                }

                let mut hashes = Vec::new();
                if let Some(integrity) = &pkg.integrity {
                    if let Some((algo, hex)) = integrity_to_hex(integrity) {
                        let cdx_algo = match algo.as_str() {
                            "sha512" => "SHA-512".to_string(),
                            "sha1" => "SHA-1".to_string(),
                            "sha256" => "SHA-256".to_string(),
                            other => other.to_ascii_uppercase(),
                        };
                        hashes.push(CycloneDxHash {
                            alg: cdx_algo,
                            content: hex,
                        });
                    }
                }

                components.push(CycloneDxComponent {
                    bom_ref,
                    component_type: "library".to_string(),
                    name,
                    version,
                    purl,
                    external_references,
                    hashes,
                });
            }

            // Dependencies
            let mut dependencies = Vec::new();
            for (parent_path, children) in &parent_to_children {
                let parent_ref = match path_to_bom_ref.get(parent_path) {
                    Some(r) => r,
                    None => continue,
                };
                let child_refs: Vec<String> = children
                    .iter()
                    .filter_map(|c| path_to_bom_ref.get(c).cloned())
                    .collect();

                dependencies.push(CycloneDxDependency {
                    component_ref: parent_ref.clone(),
                    depends_on: child_refs,
                });
            }

            // Ensure every component is represented in dependencies
            let registered_refs: BTreeSet<String> = dependencies
                .iter()
                .map(|d| d.component_ref.clone())
                .collect();
            for comp in &components {
                if !registered_refs.contains(&comp.bom_ref) {
                    dependencies.push(CycloneDxDependency {
                        component_ref: comp.bom_ref.clone(),
                        depends_on: Vec::new(),
                    });
                }
            }

            let doc = CycloneDxDocument {
                schema: "http://cyclonedx.org/schema/bom-1.5.schema.json".to_string(),
                bom_format: "CycloneDX".to_string(),
                spec_version: "1.5".to_string(),
                serial_number: format!("urn:uuid:{}", generate_uuid()),
                version: 1,
                metadata: CycloneDxMetadata {
                    timestamp: current_rfc3339_time(),
                    tools: vec![CycloneDxTool {
                        vendor: "rnpm".to_string(),
                        name: "rnpm".to_string(),
                        version: "0.1.0".to_string(),
                    }],
                    lifecycles: vec![CycloneDxLifecycle {
                        phase: "build".to_string(),
                    }],
                    component: CycloneDxRootComponent {
                        bom_ref: root_bom_ref,
                        component_type: options.sbom_type.clone(),
                        name: root_name,
                        version: root_version,
                        purl: root_purl,
                    },
                },
                components,
                dependencies,
            };

            Ok(serde_json::to_value(doc)?)
        }
        other => Err(anyhow::anyhow!(
            "Unsupported SBOM format '{}'. Supported formats: spdx, cyclonedx",
            other
        )),
    }
}

/// Execute `rnpm sbom` workflow.
pub async fn run_sbom(project_dir: &Path, options: SbomOptions) -> anyhow::Result<()> {
    let sbom_json = generate_sbom(project_dir, &options)?;
    let rendered = serde_json::to_string_pretty(&sbom_json)?;
    println!("{rendered}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integrity_to_hex_sha512() {
        let b64 = "sha512-MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxflJlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==";
        let (algo, hex) = integrity_to_hex(b64).expect("Failed to parse integrity");
        assert_eq!(algo, "sha512");
        assert_eq!(
            hex,
            "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5f9499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
        );
    }

    #[test]
    fn test_make_purl() {
        assert_eq!(make_purl("express", "4.18.2"), "pkg:npm/express@4.18.2");
        assert_eq!(
            make_purl("@types/node", "18.0.0"),
            "pkg:npm/%40types/node@18.0.0"
        );
    }

    #[test]
    fn test_sanitize_spdx() {
        assert_eq!(sanitize_spdx("@types/node"), "types-node");
        assert_eq!(
            sanitize_spdx("node_modules/foo/node_modules/bar"),
            "node-modules-foo-node-modules-bar"
        );
    }

    #[test]
    fn test_generate_uuid_format() {
        let uuid = generate_uuid();
        assert_eq!(uuid.len(), 36);
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert!(parts[2].starts_with('4')); // version 4
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
    }
}
