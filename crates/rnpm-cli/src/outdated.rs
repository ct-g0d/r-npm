use reqwest::Url;
use rnpm_core::manifest::Manifest;
use rnpm_core::semver::{Range, Version};
use rnpm_lockfile::LockfileV3;
use rnpm_registry::metadata::AbbreviatedVersion;
use rnpm_registry::{RegistryClient, RegistryClientConfig};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

#[derive(Debug)]
pub struct OutdatedStatus;
impl std::fmt::Display for OutdatedStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("outdated dependencies found")
    }
}
impl std::error::Error for OutdatedStatus {}

/// Options for outdated command.
#[derive(Debug, Clone, Default)]
pub struct OutdatedOptions {
    /// Filter specific package names if provided
    pub packages: Vec<String>,
    /// Show all dependencies, including transitive dependencies
    pub all: bool,
    /// Output in JSON format
    pub json: bool,
    /// Show extended information
    pub long: bool,
    /// Output in parseable format
    pub parseable: bool,
    /// Custom npm registry URL
    pub registry: Option<String>,
    pub global: bool,
    pub workspace: Vec<String>,
    pub workspaces: bool,
    pub include_workspace_root: bool,
}

/// Outdated package record holding inspection and registry resolution results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutdatedPackage {
    pub name: String,
    pub current: String,
    pub wanted: String,
    pub latest: String,
    pub location: String, // Relative location, e.g. "node_modules/chalk"
    pub absolute_location: String, // Absolute path, e.g. "C:\path\to\node_modules\chalk"
    pub dependent: String, // Depended by, e.g. "my-app"
    pub package_type: String, // e.g. "dependencies", "devDependencies", etc.
    pub homepage: Option<String>,
    pub dependent_location: String, // Path of the dependent package
}

impl OutdatedPackage {
    /// A package is outdated if `current != wanted || current != latest` (or `current == "MISSING"`).
    /// If `current == wanted && current == latest`, it is NOT outdated.
    pub fn is_outdated(&self) -> bool {
        self.current == "MISSING" || self.current != self.wanted || self.current != self.latest
    }
}

/// JSON output structure for each outdated package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutdatedJsonEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    pub wanted: String,
    pub latest: String,
    pub dependent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub package_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
}

/// Discovered dependency declaration before querying registry.
#[derive(Debug, Clone)]
struct DeclaredDep {
    name: String,
    declared_spec: String,
    package_type: String,
    depended_by: String,
    location_rel: String,
    depended_by_location: String,
}

/// Main function to execute outdated command.
///
/// Returns exit code:
/// - `0`: All packages are up to date (no outdated packages found).
/// - `1`: One or more outdated packages exist.
pub async fn run_outdated(project_dir: &Path, options: &OutdatedOptions) -> anyhow::Result<i32> {
    let (code, output) = run_outdated_inner(project_dir, options).await?;
    if !output.is_empty() {
        print!("{output}");
    }
    Ok(code)
}

/// Internal execution helper returning `(exit_code, formatted_output_string)`.
pub async fn run_outdated_inner(
    project_dir: &Path,
    options: &OutdatedOptions,
) -> anyhow::Result<(i32, String)> {
    let manifest_path = project_dir.join("package.json");
    if !manifest_path.exists() && !options.global {
        return Err(anyhow::anyhow!(
            "package.json not found in {}",
            project_dir.display()
        ));
    }

    let manifest_content = if options.global {
        "{}".to_string()
    } else {
        std::fs::read_to_string(&manifest_path)?
    };
    let manifest: Manifest = serde_json::from_str(&manifest_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse package.json: {e}"))?;

    let root_name = if options.global {
        "global".to_string()
    } else {
        project_dir
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "project".to_string())
    };

    let abs_project_dir = if project_dir.is_absolute() {
        project_dir.to_path_buf()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(project_dir)
    } else {
        project_dir.to_path_buf()
    };
    let root_location_str = abs_project_dir.display().to_string();

    // 1. Collect dependencies to inspect from root package.json
    let mut declared_deps: Vec<DeclaredDep> = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    // Precedence order: dependencies -> devDependencies -> optionalDependencies -> peerDependencies
    let sections = [
        (&manifest.dependencies, "dependencies"),
        (&manifest.dev_dependencies, "devDependencies"),
        (&manifest.optional_dependencies, "optionalDependencies"),
        (&manifest.peer_dependencies, "peerDependencies"),
    ];

    for (dep_map, pkg_type) in sections {
        for (name, spec) in dep_map {
            if seen_names.insert(name.clone()) {
                declared_deps.push(DeclaredDep {
                    name: name.clone(),
                    declared_spec: spec.clone(),
                    package_type: pkg_type.to_string(),
                    depended_by: root_name.clone(),
                    location_rel: format!("node_modules/{name}"),
                    depended_by_location: root_location_str.clone(),
                });
            }
        }
    }

    let mut workspace_ids = BTreeMap::new();
    if options.global {
        for (loc, pkg) in crate::inspect_tree::scan_disk_packages(project_dir) {
            if loc.matches("node_modules/").count() != 1 {
                continue;
            }
            declared_deps.push(DeclaredDep {
                name: pkg.name,
                declared_spec: "*".to_string(),
                package_type: "dependencies".to_string(),
                depended_by: "global".to_string(),
                location_rel: loc,
                depended_by_location: "global".to_string(),
            });
        }
    } else {
        let members = if options.workspaces || !options.workspace.is_empty() {
            crate::select_workspace_members(project_dir, &options.workspace, false)?
        } else {
            rnpm_core::workspace::discover_workspaces(project_dir).unwrap_or_default()
        };
        if (options.workspaces || !options.workspace.is_empty()) && !options.include_workspace_root
        {
            declared_deps.clear();
        }
        let disk = crate::inspect_tree::scan_disk_packages(project_dir);
        for member in members {
            let member_path = member.path;
            let member_loc = member_path
                .strip_prefix(project_dir)
                .unwrap_or(&member_path)
                .to_string_lossy()
                .replace('\\', "/");
            workspace_ids.insert(
                member.name.clone(),
                format!(
                    "{}@{}",
                    member.name,
                    member.version.as_deref().unwrap_or("")
                ),
            );
            for (deps, kind) in [
                (&member.manifest.dependencies, "dependencies"),
                (&member.manifest.dev_dependencies, "devDependencies"),
                (
                    &member.manifest.optional_dependencies,
                    "optionalDependencies",
                ),
                (&member.manifest.peer_dependencies, "peerDependencies"),
            ] {
                for (name, spec) in deps {
                    if Range::parse(spec).is_err() {
                        continue;
                    }
                    let mut parent = member_loc.as_str();
                    let location = loop {
                        let loc = if parent.is_empty() {
                            format!("node_modules/{name}")
                        } else {
                            format!("{parent}/node_modules/{name}")
                        };
                        if disk.contains_key(&loc)
                            || project_dir.join(&loc).join("package.json").is_file()
                        {
                            break loc;
                        }
                        if parent.is_empty() {
                            break format!("node_modules/{name}");
                        }
                        parent = parent.rsplit_once('/').map_or("", |(p, _)| p);
                    };
                    declared_deps.push(DeclaredDep {
                        name: name.clone(),
                        declared_spec: spec.clone(),
                        package_type: kind.to_string(),
                        depended_by: member.name.clone(),
                        location_rel: location,
                        depended_by_location: member_loc.clone(),
                    });
                }
            }
        }
    }

    // If options.all is true, also scan lockfile or nested node_modules for transitive dependencies
    let lockfile_path = project_dir.join("package-lock.json");
    let lockfile = if lockfile_path.exists() {
        LockfileV3::load_from_file(&lockfile_path).ok()
    } else {
        None
    };

    if options.all {
        if let Some(ref lock) = lockfile {
            for (path_key, lock_pkg) in &lock.packages {
                if path_key.is_empty() || !path_key.starts_with("node_modules/") {
                    continue;
                }
                let pkg_name = if let Some(n) = &lock_pkg.name {
                    n.clone()
                } else {
                    extract_pkg_name_from_node_modules_path(path_key)
                };

                if seen_names.insert(pkg_name.clone()) {
                    let parent_name = extract_parent_name_from_path(path_key)
                        .unwrap_or_else(|| root_name.clone());
                    let spec = lock_pkg.version.clone().unwrap_or_else(|| "*".to_string());
                    let pkg_type = if lock_pkg.is_dev() {
                        "devDependencies".to_string()
                    } else if lock_pkg.is_optional() {
                        "optionalDependencies".to_string()
                    } else {
                        "dependencies".to_string()
                    };

                    declared_deps.push(DeclaredDep {
                        name: pkg_name,
                        declared_spec: spec,
                        package_type: pkg_type,
                        depended_by: parent_name,
                        location_rel: path_key.clone(),
                        depended_by_location: root_location_str.clone(),
                    });
                }
            }
        }
    }

    // 2. Filter specific packages if options.packages is non-empty
    if !options.packages.is_empty() {
        declared_deps.retain(|dep| {
            options
                .packages
                .iter()
                .any(|filter| matches_package_filter(&dep.name, filter))
        });
    }

    if declared_deps.is_empty() {
        if options.json {
            return Ok((0, "{}\n".to_string()));
        }
        return Ok((0, String::new()));
    }

    // 3. Inspect installed versions for each dependency
    let mut installed_info: Vec<(DeclaredDep, String, Option<String>)> = Vec::new();
    for dep in declared_deps {
        let (disk_ver, disk_hp) = find_installed_on_disk(project_dir, &dep.location_rel);
        let (current_ver, hp) = if let Some(v) = disk_ver {
            (v, disk_hp)
        } else if let Some(v) = find_installed_in_lockfile(
            lockfile.as_ref(),
            &lockfile_path,
            &dep.name,
            &dep.location_rel,
        ) {
            (v, disk_hp)
        } else {
            ("MISSING".to_string(), disk_hp)
        };

        installed_info.push((dep, current_ver, hp));
    }

    // 4. Registry client setup
    let config = rnpm_config::Config::load(Some(project_dir)).unwrap_or_default();
    let registry_url = if let Some(reg) = &options.registry {
        Url::parse(reg)?
    } else if let Some(reg) = config.npmrc.settings.get("registry") {
        Url::parse(reg)?
    } else {
        Url::parse("https://registry.npmjs.org/")?
    };

    let mut client_config = RegistryClientConfig::default();
    client_config.default_registry = registry_url.clone();
    client_config.auth_tokens = config.npmrc.auth_tokens.clone();
    client_config.scoped_registries = config.npmrc.scoped_registries.clone();
    if let Some(token) = config.npmrc.get_auth_token(&registry_url) {
        client_config.auth_token = Some(token.to_string());
    }
    if let Some(host) = registry_url.host_str() {
        client_config
            .trusted_hosts
            .insert(host.to_ascii_lowercase());
        if let Some(port) = registry_url.port_or_known_default() {
            client_config
                .trusted_hosts
                .insert(format!("{}:{}", host.to_ascii_lowercase(), port));
        }
    }
    for scoped_reg in config.npmrc.scoped_registries.values() {
        if let Some(h) = scoped_reg.host_str() {
            client_config.trusted_hosts.insert(h.to_ascii_lowercase());
            if let Some(p) = scoped_reg.port_or_known_default() {
                client_config
                    .trusted_hosts
                    .insert(format!("{}:{}", h.to_ascii_lowercase(), p));
            }
        }
    }

    let client = std::sync::Arc::new(
        RegistryClient::with_config(client_config)
            .map_err(|e| anyhow::anyhow!("Failed to initialize registry client: {e}"))?,
    );

    // 5. Fetch packument metadata concurrently and determine wanted / latest
    let mut join_set = tokio::task::JoinSet::new();

    for (dep, current, homepage) in installed_info {
        let client_clone = client.clone();
        join_set.spawn(async move {
            let res = client_clone.get_package_metadata(&dep.name).await;
            (dep, current, homepage, res)
        });
    }

    let mut outdated_packages: Vec<OutdatedPackage> = Vec::new();

    while let Some(res) = join_set.join_next().await {
        let (dep, current, homepage, packument_res) = res?;
        let packument = packument_res
            .map_err(|e| anyhow::anyhow!("Failed to fetch metadata for {}: {e}", dep.name))?;

        let (wanted, latest) = resolve_wanted_and_latest(
            &dep.declared_spec,
            &current,
            &packument.dist_tags,
            &packument.versions,
        );

        let mut abs_loc = abs_project_dir.clone();
        for part in dep.location_rel.split('/') {
            abs_loc = abs_loc.join(part);
        }

        let pkg = OutdatedPackage {
            name: dep.name,
            current,
            wanted,
            latest,
            location: dep.location_rel,
            absolute_location: abs_loc.display().to_string(),
            dependent: dep.depended_by,
            package_type: dep.package_type,
            homepage,
            dependent_location: dep.depended_by_location,
        };

        if pkg.is_outdated() {
            outdated_packages.push(pkg);
        }
    }

    // Sort alphabetically by package name
    outdated_packages.sort_by(|a, b| a.name.cmp(&b.name));

    // 6. Output formatting
    if outdated_packages.is_empty() {
        if options.json {
            return Ok((0, "{}\n".to_string()));
        }
        return Ok((0, String::new()));
    }

    let formatted = if options.json {
        let json_val = ordered_json(&outdated_packages, options.long);
        format!("{}\n", serde_json::to_string_pretty(&json_val)?)
    } else if options.parseable {
        let lines = format_parseable(&outdated_packages);
        format!("{}\n", lines.join("\n"))
    } else if options.long {
        for pkg in &mut outdated_packages {
            if let Some(id) = workspace_ids.get(&pkg.dependent) {
                pkg.dependent = id.clone();
            }
        }
        format!("{}\n", format_long(&outdated_packages))
    } else {
        for pkg in &mut outdated_packages {
            if let Some(id) = workspace_ids.get(&pkg.dependent) {
                pkg.dependent = id.clone();
            }
        }
        format!("{}\n", format_tabular(&outdated_packages))
    };

    Ok((1, formatted))
}

/// Resolves `wanted` and `latest` versions from registry packument metadata.
pub fn resolve_wanted_and_latest(
    declared_spec: &str,
    current: &str,
    dist_tags: &HashMap<String, String>,
    versions: &BTreeMap<String, AbbreviatedVersion>,
) -> (String, String) {
    // 1. Determine `latest`
    let latest = dist_tags
        .get("latest")
        .cloned()
        .or_else(|| {
            let mut max_ver: Option<(Version, String)> = None;
            for v_str in versions.keys() {
                if let Ok(v) = Version::parse(v_str) {
                    if max_ver.as_ref().is_none_or(|(m, _)| &v > m) {
                        max_ver = Some((v, v_str.clone()));
                    }
                }
            }
            max_ver.map(|(_, s)| s)
        })
        .unwrap_or_else(|| {
            if current != "MISSING" {
                current.to_string()
            } else {
                declared_spec.to_string()
            }
        });

    // 2. Determine `wanted`
    let wanted = if let Some(tag_ver) = dist_tags.get(declared_spec) {
        tag_ver.clone()
    } else if let Ok(range) = Range::parse(declared_spec) {
        let mut max_satisfying: Option<(Version, String)> = None;
        for v_str in versions.keys() {
            if let Ok(v) = Version::parse(v_str) {
                if range.satisfies(&v) && max_satisfying.as_ref().is_none_or(|(m, _)| &v > m) {
                    max_satisfying = Some((v, v_str.clone()));
                }
            }
        }
        if let Some((_, v_str)) = max_satisfying {
            v_str
        } else if current != "MISSING" {
            current.to_string()
        } else {
            latest.clone()
        }
    } else if current != "MISSING" {
        current.to_string()
    } else {
        latest.clone()
    };

    (wanted, latest)
}

/// Format tabular mode.
///
/// Header: `Package  Current  Wanted  Latest  Location  Depended by`
/// Space aligned with columns matching npm layout.
pub fn format_tabular(packages: &[OutdatedPackage]) -> String {
    let headers = [
        "Package",
        "Current",
        "Wanted",
        "Latest",
        "Location",
        "Depended by",
    ];
    let is_right_aligned = [false, true, true, true, false, false];

    let mut col_widths = [
        headers[0].len(),
        headers[1].len(),
        headers[2].len(),
        headers[3].len(),
        headers[4].len(),
        headers[5].len(),
    ];

    for pkg in packages {
        let loc = if pkg.current == "MISSING" {
            "-"
        } else {
            pkg.location.as_str()
        };
        col_widths[0] = col_widths[0].max(pkg.name.len());
        col_widths[1] = col_widths[1].max(pkg.current.len());
        col_widths[2] = col_widths[2].max(pkg.wanted.len());
        col_widths[3] = col_widths[3].max(pkg.latest.len());
        col_widths[4] = col_widths[4].max(loc.len());
        col_widths[5] = col_widths[5].max(pkg.dependent.len());
    }

    let mut lines = Vec::new();

    // Format header
    let header_line = headers
        .iter()
        .enumerate()
        .map(|(i, &h)| {
            if i == headers.len() - 1 {
                h.to_string()
            } else if is_right_aligned[i] {
                format!("{:>width$}", h, width = col_widths[i])
            } else {
                format!("{:<width$}", h, width = col_widths[i])
            }
        })
        .collect::<Vec<_>>()
        .join("  ");
    lines.push(header_line);

    // Format rows
    for pkg in packages {
        let loc = if pkg.current == "MISSING" {
            "-"
        } else {
            pkg.location.as_str()
        };
        let cols = [
            pkg.name.as_str(),
            pkg.current.as_str(),
            pkg.wanted.as_str(),
            pkg.latest.as_str(),
            loc,
            pkg.dependent.as_str(),
        ];

        let row_line = cols
            .iter()
            .enumerate()
            .map(|(i, &val)| {
                if i == cols.len() - 1 {
                    val.to_string()
                } else if is_right_aligned[i] {
                    format!("{:>width$}", val, width = col_widths[i])
                } else {
                    format!("{:<width$}", val, width = col_widths[i])
                }
            })
            .collect::<Vec<_>>()
            .join("  ");
        lines.push(row_line);
    }

    lines.join("\n")
}

/// Format long tabular mode (`--long` / `-l`).
///
/// Header: `Package  Current  Wanted  Latest  Location  Depended by  Package Type  Homepage`
pub fn format_long(packages: &[OutdatedPackage]) -> String {
    let headers = [
        "Package",
        "Current",
        "Wanted",
        "Latest",
        "Location",
        "Depended by",
        "Package Type",
        "Homepage",
    ];
    let is_right_aligned = [false, true, true, true, false, false, false, false];

    let mut col_widths = [
        headers[0].len(),
        headers[1].len(),
        headers[2].len(),
        headers[3].len(),
        headers[4].len(),
        headers[5].len(),
        headers[6].len(),
        headers[7].len(),
    ];

    for pkg in packages {
        let loc = if pkg.current == "MISSING" {
            "-"
        } else {
            pkg.location.as_str()
        };
        col_widths[0] = col_widths[0].max(pkg.name.len());
        col_widths[1] = col_widths[1].max(pkg.current.len());
        col_widths[2] = col_widths[2].max(pkg.wanted.len());
        col_widths[3] = col_widths[3].max(pkg.latest.len());
        col_widths[4] = col_widths[4].max(loc.len());
        col_widths[5] = col_widths[5].max(pkg.dependent.len());
        col_widths[6] = col_widths[6].max(pkg.package_type.len());
        col_widths[7] = col_widths[7].max(pkg.homepage.as_deref().unwrap_or("").len());
    }

    let mut lines = Vec::new();

    // Format header
    let header_line = headers
        .iter()
        .enumerate()
        .map(|(i, &h)| {
            if i == headers.len() - 1 {
                h.to_string()
            } else if is_right_aligned[i] {
                format!("{:>width$}", h, width = col_widths[i])
            } else {
                format!("{:<width$}", h, width = col_widths[i])
            }
        })
        .collect::<Vec<_>>()
        .join("  ");
    lines.push(header_line);

    // Format rows
    for pkg in packages {
        let loc = if pkg.current == "MISSING" {
            "-"
        } else {
            pkg.location.as_str()
        };
        let hp_str = pkg.homepage.as_deref().unwrap_or("");
        let cols = [
            pkg.name.as_str(),
            pkg.current.as_str(),
            pkg.wanted.as_str(),
            pkg.latest.as_str(),
            loc,
            pkg.dependent.as_str(),
            pkg.package_type.as_str(),
            hp_str,
        ];

        let row_line = cols
            .iter()
            .enumerate()
            .map(|(i, &val)| {
                if i == cols.len() - 1 {
                    val.to_string()
                } else if is_right_aligned[i] {
                    format!("{:>width$}", val, width = col_widths[i])
                } else {
                    format!("{:<width$}", val, width = col_widths[i])
                }
            })
            .collect::<Vec<_>>()
            .join("  ");
        lines.push(row_line);
    }

    lines.join("\n")
}

/// Format JSON output.
pub fn format_json(packages: &[OutdatedPackage], long: bool) -> serde_json::Value {
    let mut map = serde_json::Map::new();

    for pkg in packages {
        let (current, location) = if pkg.current == "MISSING" {
            (None, None)
        } else {
            (
                Some(pkg.current.clone()),
                Some(pkg.absolute_location.clone()),
            )
        };

        let entry = OutdatedJsonEntry {
            current,
            wanted: pkg.wanted.clone(),
            latest: pkg.latest.clone(),
            dependent: pkg.dependent.clone(),
            location,
            package_type: if long {
                Some(pkg.package_type.clone())
            } else {
                None
            },
            homepage: if long { pkg.homepage.clone() } else { None },
        };

        if let Ok(val) = serde_json::to_value(entry) {
            map.insert(pkg.name.clone(), val);
        }
    }

    serde_json::Value::Object(map)
}

/// Format parseable mode (`--parseable` / `-p`).
///
/// Output line format:
/// `<location>:<name>@<wanted>:<name>@<current>:<name>@<latest>:<depended_by>`
pub fn format_parseable(packages: &[OutdatedPackage]) -> Vec<String> {
    packages
        .iter()
        .map(|pkg| {
            let current_spec = if pkg.current == "MISSING" {
                format!("{}@MISSING", pkg.name)
            } else {
                format!("{}@{}", pkg.name, pkg.current)
            };
            format!(
                "{}:{}@{}:{}:{}@{}:{}",
                pkg.absolute_location,
                pkg.name,
                pkg.wanted,
                current_spec,
                pkg.name,
                pkg.latest,
                pkg.dependent
            )
        })
        .collect()
}

/// Check if a package name matches a filter string.
/// Supports exact name `"chalk"`, scoped `"@scope/pkg"`, and name@spec `"chalk@^2.0.0"`.
fn matches_package_filter(pkg_name: &str, filter: &str) -> bool {
    if pkg_name == filter {
        return true;
    }
    if let Some(rest) = filter.strip_prefix('@') {
        if let Some((scope_and_name, _version)) = rest.split_once('@') {
            return pkg_name == format!("@{scope_and_name}");
        }
    } else if let Some((name, _version)) = filter.split_once('@') {
        return pkg_name == name;
    }
    false
}

/// Look for installed package on disk at `<location_rel>/package.json`.
/// Returns `(version, homepage)`.
fn find_installed_on_disk(
    project_dir: &Path,
    location_rel: &str,
) -> (Option<String>, Option<String>) {
    let mut pkg_json_path = project_dir.to_path_buf();
    for part in location_rel.split('/') {
        pkg_json_path = pkg_json_path.join(part);
    }
    pkg_json_path = pkg_json_path.join("package.json");

    if pkg_json_path.is_file() {
        if let Ok(content) = std::fs::read_to_string(&pkg_json_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                let version = val
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let homepage = val
                    .get("homepage")
                    .and_then(|h| h.as_str())
                    .map(|s| s.to_string());
                return (version, homepage);
            }
        }
    }
    (None, None)
}

/// Look for installed package in `package-lock.json`.
fn find_installed_in_lockfile(
    lockfile: Option<&LockfileV3>,
    lockfile_path: &Path,
    pkg_name: &str,
    location_rel: &str,
) -> Option<String> {
    if let Some(lock) = lockfile {
        if let Some(pkg) = lock.packages.get(location_rel) {
            if let Some(v) = &pkg.version {
                return Some(v.clone());
            }
        }
        let fallback_key = format!("node_modules/{pkg_name}");
        if let Some(pkg) = lock.packages.get(&fallback_key) {
            if let Some(v) = &pkg.version {
                return Some(v.clone());
            }
        }
    }

    // Fallback for v1 lockfile if parsed as JSON Value
    if lockfile_path.is_file() {
        if let Ok(content) = std::fs::read_to_string(lockfile_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(deps) = val.get("dependencies").and_then(|d| d.as_object()) {
                    if let Some(dep_val) = deps.get(pkg_name) {
                        if let Some(v) = dep_val.get("version").and_then(|v| v.as_str()) {
                            return Some(v.to_string());
                        }
                    }
                }
            }
        }
    }

    None
}

/// Extract package name from a path like `node_modules/chalk` or `node_modules/@scope/pkg`.
fn extract_pkg_name_from_node_modules_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if let Some(pos) = parts.iter().rposition(|&p| p == "node_modules") {
        if pos + 2 < parts.len() && parts[pos + 1].starts_with('@') {
            return format!("{}/{}", parts[pos + 1], parts[pos + 2]);
        } else if pos + 1 < parts.len() {
            return parts[pos + 1].to_string();
        }
    }
    path.to_string()
}

/// Extract parent package name from a nested path like `node_modules/foo/node_modules/bar`.
fn extract_parent_name_from_path(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    let mut nm_indices = Vec::new();
    for (idx, &part) in parts.iter().enumerate() {
        if part == "node_modules" {
            nm_indices.push(idx);
        }
    }

    if nm_indices.len() > 1 {
        let parent_nm = nm_indices[nm_indices.len() - 2];
        let parent_pkg_idx = parent_nm + 1;
        if parent_pkg_idx < parts.len() {
            if parts[parent_pkg_idx].starts_with('@') && parent_pkg_idx + 1 < parts.len() {
                return Some(format!(
                    "{}/{}",
                    parts[parent_pkg_idx],
                    parts[parent_pkg_idx + 1]
                ));
            } else {
                return Some(parts[parent_pkg_idx].to_string());
            }
        }
    }

    None
}

fn ordered_json(
    packages: &[OutdatedPackage],
    long: bool,
) -> rnpm_core::ordered_json::OrderedJsonValue {
    use rnpm_core::ordered_json::{OrderedJsonMap as Map, OrderedJsonValue as Value};
    let mut result = Map::new();
    for pkg in packages {
        let mut item = Map::new();
        if pkg.current != "MISSING" {
            item.insert("current".into(), Value::String(pkg.current.clone()));
        }
        for (key, value) in [
            ("wanted", &pkg.wanted),
            ("latest", &pkg.latest),
            ("dependent", &pkg.dependent),
        ] {
            item.insert(key.into(), Value::String(value.clone()));
        }
        if pkg.current != "MISSING" {
            item.insert(
                "location".into(),
                Value::String(pkg.absolute_location.clone()),
            );
        }
        if long {
            item.insert("type".into(), Value::String(pkg.package_type.clone()));
            if let Some(homepage) = &pkg.homepage {
                item.insert("homepage".into(), Value::String(homepage.clone()));
            }
            item.insert(
                "dependedByLocation".into(),
                Value::String(pkg.dependent_location.clone()),
            );
        }
        let value = Value::Object(item);
        if let Some(previous) = result.get_mut(&pkg.name) {
            if let Value::Array(items) = previous {
                items.push(value);
            } else {
                *previous = Value::Array(vec![previous.clone(), value]);
            }
        } else {
            result.insert(pkg.name.clone(), value);
        }
    }
    Value::Object(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rnpm_registry::metadata::DistInfo;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    /// Helper to construct dummy AbbreviatedVersion for resolution tests.
    fn make_abbreviated_version(name: &str, version: &str) -> AbbreviatedVersion {
        AbbreviatedVersion {
            name: name.to_string(),
            version: version.to_string(),
            dist: DistInfo {
                tarball: format!("https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"),
                shasum: None,
                integrity: None,
                signatures: Vec::new(),
                attestations: None,
            },
            dependencies: Default::default(),
            dev_dependencies: Default::default(),
            peer_dependencies: Default::default(),
            peer_dependencies_meta: HashMap::new(),
            optional_dependencies: Default::default(),
            bundle_dependencies: Vec::new(),
            bin: None,
            license: None,
            engines: HashMap::new(),
            engines_raw: None,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            has_install_script: false,
            deprecated: None,
            extra: BTreeMap::new(),
        }
    }

    // 1. Version resolution tests
    #[test]
    fn test_version_resolution_semver_range_and_dist_tags() {
        let mut versions = BTreeMap::new();
        versions.insert(
            "2.4.0".to_string(),
            make_abbreviated_version("chalk", "2.4.0"),
        );
        versions.insert(
            "2.4.1".to_string(),
            make_abbreviated_version("chalk", "2.4.1"),
        );
        versions.insert(
            "2.4.2".to_string(),
            make_abbreviated_version("chalk", "2.4.2"),
        );
        versions.insert(
            "4.1.2".to_string(),
            make_abbreviated_version("chalk", "4.1.2"),
        );
        versions.insert(
            "5.3.0".to_string(),
            make_abbreviated_version("chalk", "5.3.0"),
        );
        versions.insert(
            "6.0.1".to_string(),
            make_abbreviated_version("chalk", "6.0.1"),
        );

        let mut dist_tags = HashMap::new();
        dist_tags.insert("latest".to_string(), "6.0.1".to_string());
        dist_tags.insert("next".to_string(), "7.0.0-beta.0".to_string());

        // Range ^2.4.0 -> wanted should be max matching 2.x (2.4.2), latest 6.0.1
        let (wanted, latest) = resolve_wanted_and_latest("^2.4.0", "2.4.2", &dist_tags, &versions);
        assert_eq!(wanted, "2.4.2");
        assert_eq!(latest, "6.0.1");

        // Range ~2.4.0 -> wanted should be max matching 2.4.x (2.4.2), latest 6.0.1
        let (wanted, latest) = resolve_wanted_and_latest("~2.4.0", "2.4.0", &dist_tags, &versions);
        assert_eq!(wanted, "2.4.2");
        assert_eq!(latest, "6.0.1");

        // Wildcard * -> wanted should be max matching (6.0.1)
        let (wanted, latest) = resolve_wanted_and_latest("*", "2.4.2", &dist_tags, &versions);
        assert_eq!(wanted, "6.0.1");
        assert_eq!(latest, "6.0.1");

        // Declared spec is dist-tag "next"
        let (wanted, latest) = resolve_wanted_and_latest("next", "2.4.2", &dist_tags, &versions);
        assert_eq!(wanted, "7.0.0-beta.0");
        assert_eq!(latest, "6.0.1");

        // Declared spec is invalid semver / git URL
        let (wanted, latest) = resolve_wanted_and_latest(
            "git+https://github.com/foo/bar.git",
            "2.4.2",
            &dist_tags,
            &versions,
        );
        assert_eq!(wanted, "2.4.2");
        assert_eq!(latest, "6.0.1");
    }

    // 2. Outdated classification logic tests
    #[test]
    fn test_outdated_classification_rules() {
        let pkg_up_to_date = OutdatedPackage {
            name: "react".to_string(),
            current: "18.2.0".to_string(),
            wanted: "18.2.0".to_string(),
            latest: "18.2.0".to_string(),
            location: "node_modules/react".to_string(),
            absolute_location: "/app/node_modules/react".to_string(),
            dependent: "my-app".to_string(),
            package_type: "dependencies".to_string(),
            homepage: None,
            dependent_location: "/app".to_string(),
        };
        assert!(
            !pkg_up_to_date.is_outdated(),
            "Package should NOT be outdated when current == wanted == latest"
        );

        let pkg_outdated_wanted = OutdatedPackage {
            current: "18.1.0".to_string(),
            wanted: "18.2.0".to_string(),
            latest: "18.2.0".to_string(),
            ..pkg_up_to_date.clone()
        };
        assert!(
            pkg_outdated_wanted.is_outdated(),
            "Package is outdated when current != wanted"
        );

        let pkg_outdated_latest = OutdatedPackage {
            current: "2.4.2".to_string(),
            wanted: "2.4.2".to_string(),
            latest: "6.0.1".to_string(),
            ..pkg_up_to_date.clone()
        };
        assert!(
            pkg_outdated_latest.is_outdated(),
            "Package is outdated when current != latest"
        );

        let pkg_missing = OutdatedPackage {
            current: "MISSING".to_string(),
            wanted: "2.4.2".to_string(),
            latest: "6.0.1".to_string(),
            ..pkg_up_to_date.clone()
        };
        assert!(
            pkg_missing.is_outdated(),
            "Package is outdated when current is MISSING"
        );
    }

    // 3. Tabular formatting tests
    #[test]
    fn test_format_tabular_alignment() {
        let pkgs = vec![OutdatedPackage {
            name: "chalk".to_string(),
            current: "2.4.2".to_string(),
            wanted: "2.4.2".to_string(),
            latest: "6.0.1".to_string(),
            location: "node_modules/chalk".to_string(),
            absolute_location: "C:\\path\\to\\node_modules\\chalk".to_string(),
            dependent: "my-app".to_string(),
            package_type: "dependencies".to_string(),
            homepage: Some("https://github.com/chalk/chalk#readme".to_string()),
            dependent_location: "C:\\path\\to".to_string(),
        }];

        let table = format_tabular(&pkgs);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "Package  Current  Wanted  Latest  Location            Depended by"
        );
        assert_eq!(
            lines[1],
            "chalk      2.4.2   2.4.2   6.0.1  node_modules/chalk  my-app"
        );
    }

    // 4. Long format tests
    #[test]
    fn test_format_long() {
        let pkgs = vec![OutdatedPackage {
            name: "chalk".to_string(),
            current: "2.4.2".to_string(),
            wanted: "2.4.2".to_string(),
            latest: "6.0.1".to_string(),
            location: "node_modules/chalk".to_string(),
            absolute_location: "C:\\path\\to\\node_modules\\chalk".to_string(),
            dependent: "my-app".to_string(),
            package_type: "dependencies".to_string(),
            homepage: Some("https://github.com/chalk/chalk#readme".to_string()),
            dependent_location: "C:\\path\\to".to_string(),
        }];

        let output = format_long(&pkgs);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("Package  Current  Wanted  Latest  Location            Depended by  Package Type  Homepage"));
        assert!(lines[0].ends_with("Homepage"));
        assert!(lines[1].contains("chalk"));
        assert!(lines[1].contains("dependencies"));
        assert!(lines[1].contains("https://github.com/chalk/chalk#readme"));
    }

    // 5. JSON format tests
    #[test]
    fn test_format_json() {
        let pkgs = vec![OutdatedPackage {
            name: "chalk".to_string(),
            current: "2.4.2".to_string(),
            wanted: "2.4.2".to_string(),
            latest: "6.0.1".to_string(),
            location: "node_modules/chalk".to_string(),
            absolute_location: "C:\\path\\to\\node_modules\\chalk".to_string(),
            dependent: "my-app".to_string(),
            package_type: "dependencies".to_string(),
            homepage: Some("https://github.com/chalk/chalk#readme".to_string()),
            dependent_location: "C:\\path\\to".to_string(),
        }];

        // Standard JSON
        let json_val = format_json(&pkgs, false);
        assert!(json_val.is_object());
        let chalk_entry = &json_val["chalk"];
        assert_eq!(chalk_entry["current"], "2.4.2");
        assert_eq!(chalk_entry["wanted"], "2.4.2");
        assert_eq!(chalk_entry["latest"], "6.0.1");
        assert_eq!(chalk_entry["dependent"], "my-app");
        assert_eq!(chalk_entry["location"], "C:\\path\\to\\node_modules\\chalk");
        assert!(chalk_entry.get("type").is_none());
        assert!(chalk_entry.get("homepage").is_none());

        // Long JSON
        let json_long = format_json(&pkgs, true);
        assert_eq!(json_long["chalk"]["type"], "dependencies");
        assert_eq!(
            json_long["chalk"]["homepage"],
            "https://github.com/chalk/chalk#readme"
        );
    }

    // 6. Parseable format tests
    #[test]
    fn test_format_parseable() {
        let pkgs = vec![
            OutdatedPackage {
                name: "chalk".to_string(),
                current: "2.4.2".to_string(),
                wanted: "2.4.2".to_string(),
                latest: "6.0.1".to_string(),
                location: "node_modules/chalk".to_string(),
                absolute_location: "C:\\path\\to\\node_modules\\chalk".to_string(),
                dependent: "my-app".to_string(),
                package_type: "dependencies".to_string(),
                homepage: None,
                dependent_location: "C:\\path\\to".to_string(),
            },
            OutdatedPackage {
                name: "glob".to_string(),
                current: "MISSING".to_string(),
                wanted: "7.2.0".to_string(),
                latest: "10.0.0".to_string(),
                location: "node_modules/glob".to_string(),
                absolute_location: "C:\\path\\to\\node_modules\\glob".to_string(),
                dependent: "my-app".to_string(),
                package_type: "devDependencies".to_string(),
                homepage: None,
                dependent_location: "C:\\path\\to".to_string(),
            },
        ];

        let parseable = format_parseable(&pkgs);
        assert_eq!(parseable.len(), 2);
        assert_eq!(
            parseable[0],
            "C:\\path\\to\\node_modules\\chalk:chalk@2.4.2:chalk@2.4.2:chalk@6.0.1:my-app"
        );
        assert_eq!(
            parseable[1],
            "C:\\path\\to\\node_modules\\glob:glob@7.2.0:glob@MISSING:glob@10.0.0:my-app"
        );
    }

    /// Mock HTTP server for integration tests of `run_outdated`.
    struct MockHttpServer {
        addr: std::net::SocketAddr,
        shutdown: tokio::sync::oneshot::Sender<()>,
    }

    impl MockHttpServer {
        async fn start<F>(handler: F) -> Self
        where
            F: Fn(&str) -> (u16, Vec<(&'static str, String)>, Vec<u8>) + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
            let handler = Arc::new(handler);

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut rx => break,
                        accept_res = listener.accept() => {
                            if let Ok((mut stream, _)) = accept_res {
                                let handler_clone = handler.clone();
                                tokio::spawn(async move {
                                    let mut buf = vec![0u8; 4096];
                                    let n = stream.read(&mut buf).await.unwrap_or(0);
                                    if n > 0 {
                                        let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                                        let (status, headers, body) = handler_clone(&req_str);
                                        let status_text = match status {
                                            200 => "OK",
                                            404 => "Not Found",
                                            _ => "Response",
                                        };
                                        let mut resp = format!(
                                            "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\nConnection: close\r\n",
                                            body.len()
                                        );
                                        for (k, v) in headers {
                                            resp.push_str(&format!("{k}: {v}\r\n"));
                                        }
                                        resp.push_str("\r\n");
                                        let mut bytes = resp.into_bytes();
                                        bytes.extend_from_slice(&body);
                                        let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, &bytes).await;
                                    }
                                });
                            }
                        }
                    }
                }
            });

            Self { addr, shutdown: tx }
        }
    }

    // 7. Test exit code 0 when all packages are up to date
    #[tokio::test]
    async fn test_run_outdated_exit_code_0_when_up_to_date() {
        let mock_server = MockHttpServer::start(|_req| {
            let json = serde_json::json!({
                "name": "foo",
                "dist-tags": { "latest": "1.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "foo",
                        "version": "1.0.0",
                        "dist": { "tarball": "http://127.0.0.1/foo.tgz" }
                    }
                }
            });
            let bytes = serde_json::to_vec(&json).unwrap();
            (
                200,
                vec![("Content-Type", "application/json".to_string())],
                bytes,
            )
        })
        .await;

        let tmp = tempdir().unwrap();
        let project_dir = tmp.path();

        // package.json declaring foo: ^1.0.0
        let pkg_json = serde_json::json!({
            "name": "my-app",
            "version": "1.0.0",
            "dependencies": {
                "foo": "^1.0.0"
            }
        });
        std::fs::write(project_dir.join("package.json"), pkg_json.to_string()).unwrap();

        // node_modules/foo/package.json installed at 1.0.0
        let foo_dir = project_dir.join("node_modules").join("foo");
        std::fs::create_dir_all(&foo_dir).unwrap();
        let foo_pkg = serde_json::json!({
            "name": "foo",
            "version": "1.0.0"
        });
        std::fs::write(foo_dir.join("package.json"), foo_pkg.to_string()).unwrap();

        let options = OutdatedOptions {
            registry: Some(format!("http://{}/", mock_server.addr)),
            ..Default::default()
        };

        let (code, output) = run_outdated_inner(project_dir, &options).await.unwrap();
        assert_eq!(
            code, 0,
            "Exit code must be 0 when all packages are up to date"
        );
        assert!(
            output.is_empty(),
            "Output should be empty for text mode when up to date"
        );

        // JSON mode returns `{}`
        let json_options = OutdatedOptions {
            json: true,
            registry: Some(format!("http://{}/", mock_server.addr)),
            ..Default::default()
        };
        let (code_json, output_json) = run_outdated_inner(project_dir, &json_options)
            .await
            .unwrap();
        assert_eq!(code_json, 0);
        assert_eq!(output_json.trim(), "{}");

        let _ = mock_server.shutdown.send(());
    }

    // 8. Test exit code 1 when outdated packages exist
    #[tokio::test]
    async fn test_run_outdated_exit_code_1_when_outdated() {
        let mock_server = MockHttpServer::start(|_req| {
            let json = serde_json::json!({
                "name": "chalk",
                "dist-tags": { "latest": "6.0.1" },
                "versions": {
                    "2.4.0": {
                        "name": "chalk",
                        "version": "2.4.0",
                        "dist": { "tarball": "http://127.0.0.1/chalk-2.4.0.tgz" }
                    },
                    "2.4.2": {
                        "name": "chalk",
                        "version": "2.4.2",
                        "dist": { "tarball": "http://127.0.0.1/chalk-2.4.2.tgz" }
                    },
                    "6.0.1": {
                        "name": "chalk",
                        "version": "6.0.1",
                        "dist": { "tarball": "http://127.0.0.1/chalk-6.0.1.tgz" }
                    }
                }
            });
            let bytes = serde_json::to_vec(&json).unwrap();
            (
                200,
                vec![("Content-Type", "application/json".to_string())],
                bytes,
            )
        })
        .await;

        let tmp = tempdir().unwrap();
        let project_dir = tmp.path();

        let pkg_json = serde_json::json!({
            "name": "my-app",
            "version": "1.0.0",
            "dependencies": {
                "chalk": "^2.4.0"
            }
        });
        std::fs::write(project_dir.join("package.json"), pkg_json.to_string()).unwrap();

        // Installed at 2.4.0, wanted is 2.4.2, latest is 6.0.1
        let chalk_dir = project_dir.join("node_modules").join("chalk");
        std::fs::create_dir_all(&chalk_dir).unwrap();
        let chalk_pkg = serde_json::json!({
            "name": "chalk",
            "version": "2.4.0",
            "homepage": "https://github.com/chalk/chalk#readme"
        });
        std::fs::write(chalk_dir.join("package.json"), chalk_pkg.to_string()).unwrap();

        let options = OutdatedOptions {
            registry: Some(format!("http://{}/", mock_server.addr)),
            ..Default::default()
        };

        let (code, output) = run_outdated_inner(project_dir, &options).await.unwrap();
        assert_eq!(code, 1, "Exit code must be 1 when outdated packages exist");
        assert!(output.contains("chalk"));
        assert!(output.contains("2.4.0"));
        assert!(output.contains("2.4.2"));
        assert!(output.contains("6.0.1"));

        // JSON mode returns structured JSON with exit code 1
        let json_options = OutdatedOptions {
            json: true,
            registry: Some(format!("http://{}/", mock_server.addr)),
            ..Default::default()
        };
        let (code_json, output_json) = run_outdated_inner(project_dir, &json_options)
            .await
            .unwrap();
        assert_eq!(code_json, 1);
        let parsed: serde_json::Value = serde_json::from_str(&output_json).unwrap();
        assert_eq!(parsed["chalk"]["current"], "2.4.0");
        assert_eq!(parsed["chalk"]["wanted"], "2.4.2");
        assert_eq!(parsed["chalk"]["latest"], "6.0.1");
        assert_eq!(
            parsed["chalk"]["dependent"],
            project_dir.file_name().unwrap().to_str().unwrap()
        );

        // Parseable mode returns colon-delimited output with exit code 1
        let parseable_options = OutdatedOptions {
            parseable: true,
            registry: Some(format!("http://{}/", mock_server.addr)),
            ..Default::default()
        };
        let (code_p, output_p) = run_outdated_inner(project_dir, &parseable_options)
            .await
            .unwrap();
        assert_eq!(code_p, 1);
        assert!(output_p.contains(&format!(
            "chalk@2.4.2:chalk@2.4.0:chalk@6.0.1:{}",
            project_dir.file_name().unwrap().to_str().unwrap()
        )));

        let _ = mock_server.shutdown.send(());
    }

    // 9. Test missing package detection
    #[tokio::test]
    async fn test_run_outdated_missing_package() {
        let mock_server = MockHttpServer::start(|_req| {
            let json = serde_json::json!({
                "name": "foo",
                "dist-tags": { "latest": "2.0.0" },
                "versions": {
                    "1.0.0": {
                        "name": "foo",
                        "version": "1.0.0",
                        "dist": { "tarball": "http://127.0.0.1/foo.tgz" }
                    },
                    "2.0.0": {
                        "name": "foo",
                        "version": "2.0.0",
                        "dist": { "tarball": "http://127.0.0.1/foo-2.tgz" }
                    }
                }
            });
            let bytes = serde_json::to_vec(&json).unwrap();
            (
                200,
                vec![("Content-Type", "application/json".to_string())],
                bytes,
            )
        })
        .await;

        let tmp = tempdir().unwrap();
        let project_dir = tmp.path();

        let pkg_json = serde_json::json!({
            "name": "my-app",
            "dependencies": {
                "foo": "^1.0.0"
            }
        });
        std::fs::write(project_dir.join("package.json"), pkg_json.to_string()).unwrap();

        let options = OutdatedOptions {
            registry: Some(format!("http://{}/", mock_server.addr)),
            ..Default::default()
        };

        let (code, output) = run_outdated_inner(project_dir, &options).await.unwrap();
        assert_eq!(code, 1);
        assert!(output.contains("MISSING"));
        assert!(output.contains("1.0.0"));
        assert!(output.contains("2.0.0"));

        let _ = mock_server.shutdown.send(());
    }

    // 10. Test package-lock.json fallback when node_modules not on disk
    #[tokio::test]
    async fn test_run_outdated_package_lock_fallback() {
        let mock_server = MockHttpServer::start(|_req| {
            let json = serde_json::json!({
                "name": "locked-pkg",
                "dist-tags": { "latest": "1.1.0" },
                "versions": {
                    "1.0.5": {
                        "name": "locked-pkg",
                        "version": "1.0.5",
                        "dist": { "tarball": "http://127.0.0.1/locked-pkg.tgz" }
                    },
                    "1.1.0": {
                        "name": "locked-pkg",
                        "version": "1.1.0",
                        "dist": { "tarball": "http://127.0.0.1/locked-pkg-1.1.0.tgz" }
                    }
                }
            });
            let bytes = serde_json::to_vec(&json).unwrap();
            (
                200,
                vec![("Content-Type", "application/json".to_string())],
                bytes,
            )
        })
        .await;

        let tmp = tempdir().unwrap();
        let project_dir = tmp.path();

        let pkg_json = serde_json::json!({
            "name": "lockfile-app",
            "dependencies": {
                "locked-pkg": "^1.0.0"
            }
        });
        std::fs::write(project_dir.join("package.json"), pkg_json.to_string()).unwrap();

        let lock_json = serde_json::json!({
            "name": "lockfile-app",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "lockfile-app",
                    "dependencies": {
                        "locked-pkg": "^1.0.0"
                    }
                },
                "node_modules/locked-pkg": {
                    "version": "1.0.5"
                }
            }
        });
        std::fs::write(project_dir.join("package-lock.json"), lock_json.to_string()).unwrap();

        let options = OutdatedOptions {
            registry: Some(format!("http://{}/", mock_server.addr)),
            ..Default::default()
        };

        let (code, output) = run_outdated_inner(project_dir, &options).await.unwrap();
        assert_eq!(code, 1);
        assert!(
            output.contains("1.0.5"),
            "Should read 1.0.5 from package-lock.json"
        );
        assert!(output.contains("1.1.0"));

        let _ = mock_server.shutdown.send(());
    }

    // 11. Test package name filtering
    #[tokio::test]
    async fn test_run_outdated_package_filter() {
        let mock_server = MockHttpServer::start(|req| {
            if req.contains("GET /chalk") {
                let json = serde_json::json!({
                    "name": "chalk",
                    "dist-tags": { "latest": "6.0.0" },
                    "versions": {
                        "2.4.2": {
                            "name": "chalk",
                            "version": "2.4.2",
                            "dist": { "tarball": "http://127.0.0.1/chalk.tgz" }
                        },
                        "6.0.0": {
                            "name": "chalk",
                            "version": "6.0.0",
                            "dist": { "tarball": "http://127.0.0.1/chalk-6.tgz" }
                        }
                    }
                });
                let bytes = serde_json::to_vec(&json).unwrap();
                (
                    200,
                    vec![("Content-Type", "application/json".to_string())],
                    bytes,
                )
            } else {
                (404, vec![], b"Not Found".to_vec())
            }
        })
        .await;

        let tmp = tempdir().unwrap();
        let project_dir = tmp.path();

        let pkg_json = serde_json::json!({
            "name": "filter-app",
            "dependencies": {
                "chalk": "^2.0.0",
                "ignored-pkg": "^1.0.0"
            }
        });
        std::fs::write(project_dir.join("package.json"), pkg_json.to_string()).unwrap();

        let chalk_dir = project_dir.join("node_modules").join("chalk");
        std::fs::create_dir_all(&chalk_dir).unwrap();
        let chalk_pkg = serde_json::json!({
            "name": "chalk",
            "version": "2.4.2"
        });
        std::fs::write(chalk_dir.join("package.json"), chalk_pkg.to_string()).unwrap();

        let options = OutdatedOptions {
            packages: vec!["chalk".to_string()],
            registry: Some(format!("http://{}/", mock_server.addr)),
            ..Default::default()
        };

        let (code, output) = run_outdated_inner(project_dir, &options).await.unwrap();
        assert_eq!(code, 1);
        assert!(output.contains("chalk"));
        assert!(
            !output.contains("ignored-pkg"),
            "Filtered-out package must not appear in output"
        );

        let _ = mock_server.shutdown.send(());
    }
}
