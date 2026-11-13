use anyhow::Context;
use reqwest::Url;
use rnpm_registry::{RegistryClient, RegistryClientConfig};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Options controlling diff generation and formatting.
#[derive(Debug, Clone)]
pub struct DiffOptions {
    pub name_only: bool,
    pub unified: usize,
    pub ignore_all_space: bool,
    pub no_prefix: bool,
    pub src_prefix: Option<String>,
    pub dst_prefix: Option<String>,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            name_only: false,
            unified: 3,
            ignore_all_space: false,
            no_prefix: false,
            src_prefix: None,
            dst_prefix: None,
        }
    }
}

/// Represents an edit operation in Myers difference algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOp {
    Equal(usize, usize), // (a_index, b_index)
    Delete(usize),       // a_index
    Insert(usize),       // b_index
}

/// Check if two lines are equal, respecting the ignore_all_space flag.
fn lines_equal(a: &str, b: &str, ignore_all_space: bool) -> bool {
    if ignore_all_space {
        let a_chars = a.chars().filter(|c| !c.is_whitespace());
        let b_chars = b.chars().filter(|c| !c.is_whitespace());
        a_chars.eq(b_chars)
    } else {
        a == b
    }
}

/// Compute the shortest edit script (SES) using Myers O(ND) diff algorithm.
pub fn myers_diff(a: &[&str], b: &[&str], ignore_all_space: bool) -> Vec<DiffOp> {
    let n = a.len();
    let m = b.len();

    if n == 0 && m == 0 {
        return Vec::new();
    }
    if n == 0 {
        return (0..m).map(DiffOp::Insert).collect();
    }
    if m == 0 {
        return (0..n).map(DiffOp::Delete).collect();
    }

    let max = n + m;
    let mut v = vec![0isize; 2 * max + 1];
    let offset = max as isize;
    let mut trace: Vec<Vec<isize>> = Vec::new();

    let mut found = false;
    for d in 0..=max {
        trace.push(v.clone());
        let d_isize = d as isize;
        for k in (-d_isize..=d_isize).step_by(2) {
            let mut x = if k == -d_isize
                || (k != d_isize && v[(k - 1 + offset) as usize] < v[(k + 1 + offset) as usize])
            {
                v[(k + 1 + offset) as usize]
            } else {
                v[(k - 1 + offset) as usize] + 1
            };
            let mut y = x - k;

            while (x as usize) < n
                && (y as usize) < m
                && lines_equal(a[x as usize], b[y as usize], ignore_all_space)
            {
                x += 1;
                y += 1;
            }

            v[(k + offset) as usize] = x;

            if (x as usize) >= n && (y as usize) >= m {
                found = true;
                break;
            }
        }
        if found {
            break;
        }
    }

    let mut ops = Vec::new();
    let mut x = n as isize;
    let mut y = m as isize;

    for d in (1..trace.len()).rev() {
        let v_prev = &trace[d];
        let k = x - y;
        let d_isize = d as isize;

        let prev_k = if k == -d_isize
            || (k != d_isize
                && v_prev[(k - 1 + offset) as usize] < v_prev[(k + 1 + offset) as usize])
        {
            k + 1
        } else {
            k - 1
        };

        let prev_x = v_prev[(prev_k + offset) as usize];
        let prev_y = prev_x - prev_k;

        while x > prev_x && y > prev_y {
            x -= 1;
            y -= 1;
            ops.push(DiffOp::Equal(x as usize, y as usize));
        }

        if d > 0 {
            if x == prev_x {
                y -= 1;
                ops.push(DiffOp::Insert(y as usize));
            } else {
                x -= 1;
                ops.push(DiffOp::Delete(x as usize));
            }
        }
    }

    while x > 0 && y > 0 {
        x -= 1;
        y -= 1;
        ops.push(DiffOp::Equal(x as usize, y as usize));
    }

    ops.reverse();
    ops
}

/// A single hunk in a unified diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffHunk {
    pub header: String,
    pub lines: Vec<String>,
}

fn format_range(start: usize, count: usize) -> String {
    if count == 1 {
        format!("{start}")
    } else {
        format!("{start},{count}")
    }
}

/// Group diff operations into unified diff hunks with the specified context lines.
pub fn build_hunks(
    a_lines: &[&str],
    b_lines: &[&str],
    ops: &[DiffOp],
    context_lines: usize,
) -> Vec<DiffHunk> {
    let change_indices: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| !matches!(op, DiffOp::Equal(_, _)))
        .map(|(i, _)| i)
        .collect();

    if change_indices.is_empty() {
        return Vec::new();
    }

    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut cur_start = change_indices[0].saturating_sub(context_lines);
    let mut cur_end = (change_indices[0] + context_lines + 1).min(ops.len());

    for &idx in &change_indices[1..] {
        let change_start = idx.saturating_sub(context_lines);
        let change_end = (idx + context_lines + 1).min(ops.len());

        if change_start <= cur_end {
            cur_end = change_end;
        } else {
            groups.push((cur_start, cur_end));
            cur_start = change_start;
            cur_end = change_end;
        }
    }
    groups.push((cur_start, cur_end));

    let mut hunks = Vec::with_capacity(groups.len());

    for (start_idx, end_idx) in groups {
        let mut a_count = 0;
        let mut b_count = 0;
        let mut lines = Vec::new();

        let mut lines_a_before = 0;
        let mut lines_b_before = 0;

        for op in &ops[..start_idx] {
            match op {
                DiffOp::Equal(_, _) => {
                    lines_a_before += 1;
                    lines_b_before += 1;
                }
                DiffOp::Delete(_) => {
                    lines_a_before += 1;
                }
                DiffOp::Insert(_) => {
                    lines_b_before += 1;
                }
            }
        }

        for op in &ops[start_idx..end_idx] {
            match op {
                DiffOp::Equal(a_i, _) => {
                    a_count += 1;
                    b_count += 1;
                    lines.push(format!(" {}", a_lines[*a_i]));
                }
                DiffOp::Delete(a_i) => {
                    a_count += 1;
                    lines.push(format!("-{}", a_lines[*a_i]));
                }
                DiffOp::Insert(b_i) => {
                    b_count += 1;
                    lines.push(format!("+{}", b_lines[*b_i]));
                }
            }
        }

        let a_start = if a_count == 0 {
            lines_a_before
        } else {
            lines_a_before + 1
        };

        let b_start = if b_count == 0 {
            lines_b_before
        } else {
            lines_b_before + 1
        };

        let header = format!(
            "@@ -{} +{} @@",
            format_range(a_start, a_count),
            format_range(b_start, b_count)
        );

        hunks.push(DiffHunk { header, lines });
    }

    hunks
}

/// Detect if byte slice contains binary data (e.g. null bytes).
pub fn is_binary(bytes: &[u8]) -> bool {
    let sample = if bytes.len() > 8000 {
        &bytes[..8000]
    } else {
        bytes
    };
    sample.contains(&0)
}

/// Unpack files from a gzipped or plain tarball in-memory archive.
pub fn extract_tarball_files(bytes: &[u8]) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let is_gzip = bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b;

    if is_gzip {
        let gz = flate2::read::GzDecoder::new(bytes);
        let mut archive = tar::Archive::new(gz);
        for entry in archive.entries()? {
            let mut entry = entry?;
            if entry.header().entry_type().is_file() {
                let path = entry.path()?;
                let path_str = path.to_string_lossy().replace('\\', "/");
                let clean_path = path_str.strip_prefix("./").unwrap_or(&path_str);
                let rel_path = clean_path.strip_prefix("package/").unwrap_or(clean_path);
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                files.insert(rel_path.to_string(), data);
            }
        }
    } else {
        let mut archive = tar::Archive::new(bytes);
        for entry in archive.entries()? {
            let mut entry = entry?;
            if entry.header().entry_type().is_file() {
                let path = entry.path()?;
                let path_str = path.to_string_lossy().replace('\\', "/");
                let clean_path = path_str.strip_prefix("./").unwrap_or(&path_str);
                let rel_path = clean_path.strip_prefix("package/").unwrap_or(clean_path);
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                files.insert(rel_path.to_string(), data);
            }
        }
    }

    Ok(files)
}

/// Read publishable files from a local directory.
pub fn read_directory_files(dir: &Path) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let manifest_path = dir.join("package.json");
    if manifest_path.is_file() {
        let manifest = rnpm_core::manifest::Manifest::from_file(&manifest_path)?;
        let pack_files = rnpm_fs::collect_pack_files(dir, &manifest)?;
        for (rel_path, full_path) in pack_files {
            let data = std::fs::read(&full_path)?;
            files.insert(rel_path.replace('\\', "/"), data);
        }
    } else {
        walk_dir_files(dir, dir, &mut files)?;
    }
    Ok(files)
}

fn walk_dir_files(
    base: &Path,
    current: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> anyhow::Result<()> {
    if !current.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let p = entry.path();
        let fname = entry.file_name().to_string_lossy().to_string();
        if fname == ".git" || fname == "node_modules" {
            continue;
        }
        if p.is_dir() {
            walk_dir_files(base, &p, files)?;
        } else if p.is_file() {
            if let Ok(rel) = p.strip_prefix(base) {
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                let data = std::fs::read(&p)?;
                files.insert(rel_str, data);
            }
        }
    }
    Ok(())
}

/// Fetch a package tarball from npm registry and unpack it into files map.
async fn fetch_registry_package_files(
    pkg_name: &str,
    version_req: &str,
    registry_url: Option<&str>,
) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    let mut client_config = RegistryClientConfig::default();
    if let Some(reg) = registry_url {
        let parsed = Url::parse(reg).context("Invalid registry URL")?;
        client_config.default_registry = parsed.clone();
        if let Some(host) = parsed.host_str() {
            client_config
                .trusted_hosts
                .insert(host.to_ascii_lowercase());
            if let Some(port) = parsed.port_or_known_default() {
                client_config.trusted_hosts.insert(format!(
                    "{}:{}",
                    host.to_ascii_lowercase(),
                    port
                ));
            }
        }
    }

    let client = RegistryClient::with_config(client_config)
        .map_err(|e| anyhow::anyhow!("Failed to initialize registry client: {e}"))?;

    let packument = client
        .get_package_metadata(pkg_name)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch metadata for '{}': {e}", pkg_name))?;

    let resolved_version = if version_req == "latest" {
        packument
            .dist_tags
            .get("latest")
            .cloned()
            .or_else(|| packument.versions.keys().last().cloned())
            .ok_or_else(|| anyhow::anyhow!("No version available for package '{}'", pkg_name))?
    } else if let Some(tag_ver) = packument.dist_tags.get(version_req) {
        tag_ver.clone()
    } else if packument.versions.contains_key(version_req) {
        version_req.to_string()
    } else {
        let range = rnpm_core::semver::Range::parse(version_req)
            .map_err(|e| anyhow::anyhow!("Invalid version range '{}': {e}", version_req))?;
        let mut matching: Vec<rnpm_core::semver::Version> = packument
            .versions
            .keys()
            .filter_map(|v| rnpm_core::semver::Version::parse(v).ok())
            .filter(|v| range.satisfies(v))
            .collect();
        matching.sort();
        let highest = matching.last().ok_or_else(|| {
            anyhow::anyhow!(
                "npm error code ETARGET\nnpm error No matching version found for '{}@{}'",
                pkg_name,
                version_req
            )
        })?;
        highest.to_string()
    };

    let ver_info = packument.versions.get(&resolved_version).ok_or_else(|| {
        anyhow::anyhow!(
            "Version '{}' not found in packument for '{}'",
            resolved_version,
            pkg_name
        )
    })?;

    let tarball_url = &ver_info.dist.tarball;
    let tarball_bytes = client
        .download_tarball_bytes(tarball_url)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to download tarball from {}: {e}", tarball_url))?;

    extract_tarball_files(&tarball_bytes)
}

/// Resolve any target spec into a map of relative path -> file contents.
pub async fn resolve_spec_files(
    spec: &str,
    current_dir: &Path,
    registry_url: Option<&str>,
) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    let local_path = if Path::new(spec).is_absolute() {
        PathBuf::from(spec)
    } else {
        current_dir.join(spec)
    };

    // 1. Local directory
    if local_path.is_dir() {
        return read_directory_files(&local_path);
    }

    // 2. Local tarball archive (or existing file)
    if local_path.is_file() {
        let bytes = std::fs::read(&local_path)?;
        return extract_tarball_files(&bytes);
    }

    // 3. Spec ended in tarball extension but file does not exist
    if spec.ends_with(".tgz") || spec.ends_with(".tar.gz") || spec.ends_with(".tar") {
        return Err(anyhow::anyhow!(
            "npm error code ENOENT\nnpm error Tarball file not found: {}",
            local_path.display()
        ));
    }

    // 4. Version string for the current package (e.g. "1.0.0", "v1.0.0", "^1.0.0")
    let is_pure_version = (!spec.contains('/') && !spec.contains('@'))
        && (spec.starts_with('^')
            || spec.starts_with('~')
            || spec.starts_with('*')
            || (spec.starts_with('v')
                && spec.len() > 1
                && spec.chars().nth(1).is_some_and(|c| c.is_ascii_digit()))
            || spec.chars().next().is_some_and(|c| c.is_ascii_digit()));

    if is_pure_version {
        let manifest_path = current_dir.join("package.json");
        if !manifest_path.is_file() {
            return Err(anyhow::anyhow!(
                "npm error code ENOENT\nnpm error Cannot resolve version spec '{}': package.json not found in {}",
                spec,
                current_dir.display()
            ));
        }
        let manifest = rnpm_core::manifest::Manifest::from_file(&manifest_path)?;
        let pkg_name = manifest.name.ok_or_else(|| {
            anyhow::anyhow!("npm error package.json has no 'name' field to resolve version spec")
        })?;
        let ver = spec.strip_prefix('v').unwrap_or(spec);
        return fetch_registry_package_files(&pkg_name, ver, registry_url).await;
    }

    // 5. Package spec (e.g. "pkg@1.0.0", "@scope/pkg@1.0.0", "pkg")
    let (pkg_name, version_req) = if let Some(stripped) = spec.strip_prefix('@') {
        if let Some(idx) = stripped.find('@') {
            (format!("@{}", &stripped[..idx]), &stripped[idx + 1..])
        } else {
            (spec.to_string(), "latest")
        }
    } else if let Some(idx) = spec.find('@') {
        (spec[..idx].to_string(), &spec[idx + 1..])
    } else {
        (spec.to_string(), "latest")
    };

    let ver = version_req.strip_prefix('v').unwrap_or(version_req);
    fetch_registry_package_files(&pkg_name, ver, registry_url).await
}

/// Compute unified diff string between two sets of files.
pub fn generate_diff(
    files_a: &BTreeMap<String, Vec<u8>>,
    files_b: &BTreeMap<String, Vec<u8>>,
    options: &DiffOptions,
) -> String {
    let (src_prefix, dst_prefix) = if options.no_prefix {
        ("".to_string(), "".to_string())
    } else {
        (
            options
                .src_prefix
                .clone()
                .unwrap_or_else(|| "a/".to_string()),
            options
                .dst_prefix
                .clone()
                .unwrap_or_else(|| "b/".to_string()),
        )
    };

    let all_paths: BTreeSet<String> = files_a.keys().chain(files_b.keys()).cloned().collect();
    let mut output = String::new();

    for path in all_paths {
        let a_bytes = files_a.get(&path);
        let b_bytes = files_b.get(&path);

        if a_bytes == b_bytes {
            continue;
        }

        let is_a_bin = a_bytes.is_some_and(|b| is_binary(b));
        let is_b_bin = b_bytes.is_some_and(|b| is_binary(b));

        if is_a_bin || is_b_bin {
            if options.name_only {
                output.push_str(&format!("{path}\n"));
            } else {
                let src_desc = if a_bytes.is_some() {
                    format!("{src_prefix}{path}")
                } else {
                    "/dev/null".to_string()
                };
                let dst_desc = if b_bytes.is_some() {
                    format!("{dst_prefix}{path}")
                } else {
                    "/dev/null".to_string()
                };
                output.push_str(&format!(
                    "diff --git {src_prefix}{path} {dst_prefix}{path}\n"
                ));
                output.push_str(&format!("Binary files {src_desc} and {dst_desc} differ\n"));
            }
            continue;
        }

        let a_str = a_bytes
            .map(|b| String::from_utf8_lossy(b).to_string())
            .unwrap_or_default();
        let b_str = b_bytes
            .map(|b| String::from_utf8_lossy(b).to_string())
            .unwrap_or_default();

        let a_lines: Vec<&str> = if a_bytes.is_some() {
            a_str
                .lines()
                .map(|l| l.strip_suffix('\r').unwrap_or(l))
                .collect()
        } else {
            Vec::new()
        };

        let b_lines: Vec<&str> = if b_bytes.is_some() {
            b_str
                .lines()
                .map(|l| l.strip_suffix('\r').unwrap_or(l))
                .collect()
        } else {
            Vec::new()
        };

        let ops = myers_diff(&a_lines, &b_lines, options.ignore_all_space);
        let hunks = build_hunks(&a_lines, &b_lines, &ops, options.unified);

        if hunks.is_empty() {
            continue;
        }

        if options.name_only {
            output.push_str(&format!("{path}\n"));
        } else {
            let src_hdr = if a_bytes.is_some() {
                format!("{src_prefix}{path}")
            } else {
                "/dev/null".to_string()
            };
            let dst_hdr = if b_bytes.is_some() {
                format!("{dst_prefix}{path}")
            } else {
                "/dev/null".to_string()
            };

            output.push_str(&format!(
                "diff --git {src_prefix}{path} {dst_prefix}{path}\n"
            ));
            let version = |files: &BTreeMap<String, Vec<u8>>| {
                files
                    .get("package.json")
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok())
                    .and_then(|json| {
                        json.get("version")
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                    })
            };
            if let (Some(from), Some(to)) = (version(files_a), version(files_b)) {
                output.push_str(&format!("index v{from}..v{to} 100644\n"));
            }
            output.push_str(&format!("--- {src_hdr}\n"));
            output.push_str(&format!("+++ {dst_hdr}\n"));

            for hunk in hunks {
                output.push_str(&format!("{}\n", hunk.header));
                for line in hunk.lines {
                    output.push_str(&format!("{}\n", line));
                }
            }
        }
    }

    output
}

/// Execute `rnpm diff` workflow.
pub async fn run_diff(
    current_dir: &Path,
    specs: Vec<String>,
    diff_specs: Vec<String>,
    options: DiffOptions,
    registry_url: Option<String>,
) -> anyhow::Result<()> {
    let registry_url = registry_url.or_else(|| {
        rnpm_config::Config::load(Some(current_dir))
            .ok()
            .map(|config| config.npmrc.registry.to_string())
    });
    let mut all_specs = diff_specs;
    all_specs.extend(specs);

    let (files_a, files_b) = match all_specs.len() {
        0 => {
            // Compare current directory vs registry tarball of current version from package.json
            let manifest_path = current_dir.join("package.json");
            if !manifest_path.is_file() {
                return Err(anyhow::anyhow!(
                    "npm error code ENOENT\nnpm error package.json not found in {}",
                    current_dir.display()
                ));
            }
            let manifest = rnpm_core::manifest::Manifest::from_file(&manifest_path)?;
            let name = manifest
                .name
                .ok_or_else(|| anyhow::anyhow!("npm error package.json has no 'name' field"))?;
            let version = manifest
                .version
                .ok_or_else(|| anyhow::anyhow!("npm error package.json has no 'version' field"))?;
            let spec_a = format!("{}@{}", name, version);
            let files_a = resolve_spec_files(&spec_a, current_dir, registry_url.as_deref()).await?;
            let files_b = read_directory_files(current_dir)?;
            (files_a, files_b)
        }
        1 => {
            // Compare spec vs current directory
            let files_a =
                resolve_spec_files(&all_specs[0], current_dir, registry_url.as_deref()).await?;
            let files_b = read_directory_files(current_dir)?;
            (files_a, files_b)
        }
        2 => {
            // Compare spec1 vs spec2
            let files_a =
                resolve_spec_files(&all_specs[0], current_dir, registry_url.as_deref()).await?;
            let files_b =
                resolve_spec_files(&all_specs[1], current_dir, registry_url.as_deref()).await?;
            (files_a, files_b)
        }
        n => {
            return Err(anyhow::anyhow!(
                "npm error code EDIFF\nnpm error Cannot diff {} specs, at most 2 allowed",
                n
            ));
        }
    };

    let diff_output = generate_diff(&files_a, &files_b, &options);
    if !diff_output.is_empty() {
        print!("{diff_output}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_diff_parse() {
        let parsed = crate::Cli::try_parse_from(["rnpm", "diff", "a", "b"]);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_myers_diff_identical() {
        let a = ["line 1", "line 2", "line 3"];
        let ops = myers_diff(&a, &a, false);
        assert_eq!(
            ops,
            vec![
                DiffOp::Equal(0, 0),
                DiffOp::Equal(1, 1),
                DiffOp::Equal(2, 2)
            ]
        );
        let hunks = build_hunks(&a, &a, &ops, 3);
        assert!(hunks.is_empty());
    }

    #[test]
    fn test_myers_diff_modifications() {
        let a = ["a", "b", "c"];
        let b = ["a", "x", "c"];
        let ops = myers_diff(&a, &b, false);
        let hunks = build_hunks(&a, &b, &ops, 3);
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0].header, "@@ -1,3 +1,3 @@");
        assert_eq!(hunks[0].lines, vec![" a", "-b", "+x", " c"]);
    }

    #[test]
    fn test_diff_ignore_all_space() {
        let a = ["const x = 1;"];
        let b = ["const   x  =  1;  "];
        let ops_exact = myers_diff(&a, &b, false);
        assert_eq!(build_hunks(&a, &b, &ops_exact, 3).len(), 1);

        let ops_ignore = myers_diff(&a, &b, true);
        assert_eq!(build_hunks(&a, &b, &ops_ignore, 3).len(), 0);
    }

    #[test]
    fn test_generate_diff_text_and_name_only() {
        let mut files_a = BTreeMap::new();
        files_a.insert("foo.txt".to_string(), b"hello\nworld\n".to_vec());

        let mut files_b = BTreeMap::new();
        files_b.insert("foo.txt".to_string(), b"hello\neveryone\n".to_vec());
        files_b.insert("bar.txt".to_string(), b"new file\n".to_vec());

        let diff_text = generate_diff(&files_a, &files_b, &DiffOptions::default());
        assert!(diff_text.contains("diff --git a/foo.txt b/foo.txt"));
        assert!(diff_text.contains("-world"));
        assert!(diff_text.contains("+everyone"));
        assert!(diff_text.contains("diff --git a/bar.txt b/bar.txt"));
        assert!(diff_text.contains("--- /dev/null"));
        assert!(diff_text.contains("+++ b/bar.txt"));

        let diff_names = generate_diff(
            &files_a,
            &files_b,
            &DiffOptions {
                name_only: true,
                ..Default::default()
            },
        );
        assert_eq!(diff_names, "bar.txt\nfoo.txt\n");
    }

    #[test]
    fn test_generate_diff_custom_prefix_and_no_prefix() {
        let mut files_a = BTreeMap::new();
        files_a.insert("app.js".to_string(), b"v1\n".to_vec());

        let mut files_b = BTreeMap::new();
        files_b.insert("app.js".to_string(), b"v2\n".to_vec());

        // Custom prefixes
        let diff_custom = generate_diff(
            &files_a,
            &files_b,
            &DiffOptions {
                src_prefix: Some("src/".to_string()),
                dst_prefix: Some("dst/".to_string()),
                ..Default::default()
            },
        );
        assert!(diff_custom.contains("diff --git src/app.js dst/app.js"));
        assert!(diff_custom.contains("--- src/app.js"));
        assert!(diff_custom.contains("+++ dst/app.js"));

        // No prefix
        let diff_noprefix = generate_diff(
            &files_a,
            &files_b,
            &DiffOptions {
                no_prefix: true,
                ..Default::default()
            },
        );
        assert!(diff_noprefix.contains("diff --git app.js app.js"));
        assert!(diff_noprefix.contains("--- app.js"));
        assert!(diff_noprefix.contains("+++ app.js"));
    }

    #[test]
    fn test_generate_diff_binary() {
        let mut files_a = BTreeMap::new();
        files_a.insert("bin.dat".to_string(), vec![0, 1, 2, 3]);

        let mut files_b = BTreeMap::new();
        files_b.insert("bin.dat".to_string(), vec![0, 1, 9, 3]);

        let diff_bin = generate_diff(&files_a, &files_b, &DiffOptions::default());
        assert!(diff_bin.contains("Binary files a/bin.dat and b/bin.dat differ"));
    }
}
