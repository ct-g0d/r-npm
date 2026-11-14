use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
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
            sbom_type: "library".to_string(),
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

/// Current UTC time as `Date.prototype.toISOString()` renders it.
pub fn current_iso_time_millis() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_millis();
    let base = current_rfc3339_time();
    format!("{}.{millis:03}Z", base.trim_end_matches('Z'))
}

const SBOM_USAGE: &str = "Generate a Software Bill of Materials (SBOM)

Usage:
npm sbom

Options:
[--omit <dev|optional|peer> [--omit <dev|optional|peer> ...]]
[--package-lock-only] [--sbom-format <cyclonedx|spdx>]
[--sbom-type <library|application|framework>]
[-w|--workspace <workspace-name> [-w|--workspace <workspace-name> ...]]
[--workspaces]

  --omit
    Dependency types to omit from the installation tree on disk.

  --package-lock-only
    If set to true, the current operation will only use the `package-lock.json`,

  --sbom-format
    SBOM format to use when generating SBOMs.

  --sbom-type
    The type of package described by the generated SBOM. For SPDX, this is the

  -w|--workspace
    Enable running a command in the context of the configured workspaces of the

  --workspaces
    Set to true to run the command in the context of **all** configured


Run \"npm help sbom\" for more info";

fn usage_error(message: &str) -> anyhow::Error {
    let mut out = format!("npm error code EUSAGE\nnpm error\nnpm error {message}\nnpm error");
    for line in SBOM_USAGE.lines() {
        out.push('\n');
        if line.is_empty() {
            out.push_str("npm error");
        } else {
            out.push_str(&format!("npm error {line}"));
        }
    }
    anyhow::anyhow!(out)
}

// -------------------------------------------------------------------------
// SPDX license expressions (port of spdx-expression-parse)
// -------------------------------------------------------------------------

static SPDX_LICENSE_IDS: &str = include_str!("data/spdx-license-ids.txt");
static SPDX_EXCEPTIONS: &str = include_str!("data/spdx-exceptions.txt");

#[derive(Debug, PartialEq)]
enum LicenseToken {
    Op(String),
    License(String),
    Exception(String),
    LicenseRef(String),
    DocumentRef(String),
}

fn scan_license(source: &str) -> Option<Vec<LicenseToken>> {
    let bytes = source.as_bytes();
    let idstring = |i: usize| {
        let mut j = i;
        while j < bytes.len()
            && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'-' || bytes[j] == b'.')
        {
            j += 1;
        }
        j
    };
    let mut i = 0;
    let mut tokens = Vec::new();
    'outer: while i < bytes.len() {
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let rest = &source[i..];
        let upper = rest.to_ascii_uppercase();
        for op in ["WITH", "AND", "OR"] {
            if upper.starts_with(op) {
                tokens.push(LicenseToken::Op(op.to_string()));
                i += op.len();
                continue 'outer;
            }
        }
        if let c @ (b'(' | b')' | b':' | b'+') = bytes[i] {
            if c == b'+' && i > 1 && bytes[i - 1] == b' ' {
                return None;
            }
            tokens.push(LicenseToken::Op((c as char).to_string()));
            i += 1;
            continue;
        }
        for (prefix, is_doc) in [("DocumentRef-", true), ("LicenseRef-", false)] {
            if rest.starts_with(prefix) {
                let start = i + prefix.len();
                let end = idstring(start);
                if end == start {
                    return None;
                }
                let value = source[start..end].to_string();
                tokens.push(if is_doc {
                    LicenseToken::DocumentRef(value)
                } else {
                    LicenseToken::LicenseRef(value)
                });
                i = end;
                continue 'outer;
            }
        }
        let end = idstring(i);
        let id = &source[i..end];
        if end > i && SPDX_LICENSE_IDS.lines().any(|l| l == id) {
            tokens.push(LicenseToken::License(id.to_string()));
        } else if end > i && SPDX_EXCEPTIONS.lines().any(|l| l == id) {
            tokens.push(LicenseToken::Exception(id.to_string()));
        } else {
            return None;
        }
        i = end;
    }
    Some(tokens)
}

/// Shape of a parsed license expression, as the SBOM writers use it.
#[derive(Debug, PartialEq)]
enum ParsedLicense {
    Single(String),
    Conjunction,
}

fn parse_license(source: &str) -> Option<ParsedLicense> {
    let tokens = scan_license(source)?;
    let mut pos = 0;
    let node = parse_or(&tokens, &mut pos)?;
    (pos == tokens.len()).then_some(node)
}

fn is_op(tokens: &[LicenseToken], pos: usize, op: &str) -> bool {
    matches!(tokens.get(pos), Some(LicenseToken::Op(o)) if o == op)
}

fn parse_or(tokens: &[LicenseToken], pos: &mut usize) -> Option<ParsedLicense> {
    let left = parse_and(tokens, pos)?;
    if !is_op(tokens, *pos, "OR") {
        return Some(left);
    }
    *pos += 1;
    parse_or(tokens, pos)?;
    Some(ParsedLicense::Conjunction)
}

fn parse_and(tokens: &[LicenseToken], pos: &mut usize) -> Option<ParsedLicense> {
    let left = parse_atom(tokens, pos)?;
    if !is_op(tokens, *pos, "AND") {
        return Some(left);
    }
    *pos += 1;
    parse_and(tokens, pos)?;
    Some(ParsedLicense::Conjunction)
}

fn parse_atom(tokens: &[LicenseToken], pos: &mut usize) -> Option<ParsedLicense> {
    if is_op(tokens, *pos, "(") {
        *pos += 1;
        let expr = parse_or(tokens, pos)?;
        if !is_op(tokens, *pos, ")") {
            return None;
        }
        *pos += 1;
        return Some(expr);
    }
    let mut prefix = String::new();
    if let Some(LicenseToken::DocumentRef(doc)) = tokens.get(*pos) {
        if !is_op(tokens, *pos + 1, ":") {
            return None;
        }
        prefix = format!("DocumentRef-{doc}:");
        *pos += 2;
    }
    match tokens.get(*pos) {
        Some(LicenseToken::LicenseRef(r)) => {
            *pos += 1;
            Some(ParsedLicense::Single(format!("{prefix}LicenseRef-{r}")))
        }
        Some(LicenseToken::License(id)) if prefix.is_empty() => {
            *pos += 1;
            if is_op(tokens, *pos, "+") {
                *pos += 1;
            }
            if is_op(tokens, *pos, "WITH") {
                *pos += 1;
                match tokens.get(*pos) {
                    Some(LicenseToken::Exception(_)) => *pos += 1,
                    _ => return None,
                }
            }
            Some(ParsedLicense::Single(id.clone()))
        }
        _ => None,
    }
}

// -------------------------------------------------------------------------
// Dependency tree: the subset of Arborist's loadActual / loadVirtual the
// SBOM needs (edges with types, calc-dep-flags).
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EdgeType {
    Prod,
    Dev,
    Optional,
    Peer,
    PeerOptional,
}

impl EdgeType {
    fn is_peer(self) -> bool {
        matches!(self, EdgeType::Peer | EdgeType::PeerOptional)
    }
    fn is_optional(self) -> bool {
        matches!(self, EdgeType::Optional | EdgeType::PeerOptional)
    }
}

#[derive(Debug)]
struct Edge {
    name: String,
    spec: String,
    kind: EdgeType,
    to: Option<usize>,
}

#[derive(Debug)]
struct Node {
    /// Folder name (`node.name` in Arborist).
    name: String,
    location: String,
    package: Value,
    resolved: Option<String>,
    integrity: Option<String>,
    in_bundle: bool,
    edges: Vec<Edge>,
    dev: bool,
    optional: bool,
    dev_optional: bool,
    peer: bool,
    extraneous: bool,
}

impl Node {
    fn package_name(&self) -> String {
        self.package
            .get("name")
            .and_then(Value::as_str)
            .filter(|n| !n.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| self.name.clone())
    }

    fn version(&self) -> String {
        self.package
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }

    fn is_root(&self) -> bool {
        self.location.is_empty()
    }

    /// Arborist `node.pkgid`.
    fn pkgid(&self) -> String {
        let pkg_name = self.package.get("name").and_then(Value::as_str).unwrap_or("");
        let version = self.version();
        if self.is_root() {
            let name = if pkg_name.is_empty() { &self.name } else { pkg_name };
            return format!("{name}@{version}");
        }
        if !pkg_name.is_empty() && pkg_name != self.name {
            format!("{}@npm:{pkg_name}@{version}", self.name)
        } else {
            format!("{}@{version}", self.name)
        }
    }

    /// `${packageName}@${version}`, the CycloneDX bom-ref.
    fn id(&self) -> String {
        format!("{}@{}", self.package_name(), self.version())
    }
}

fn folder_name(location: &str) -> String {
    location
        .rsplit("node_modules/")
        .next()
        .unwrap_or(location)
        .to_string()
}

fn edges_from_package(pkg: &Value, is_root: bool) -> Vec<(String, String, EdgeType)> {
    // Arborist's #loadDeps order; a later type replaces an earlier edge.
    let mut edges: Vec<(String, String, EdgeType)> = Vec::new();
    let mut put = |name: &str, spec: &str, kind: EdgeType| {
        let edge = (name.to_string(), spec.to_string(), kind);
        match edges.iter_mut().find(|e| e.0 == name) {
            Some(existing) => *existing = edge,
            None => edges.push(edge),
        }
    };
    let section = |key: &str| -> Vec<(String, String)> {
        pkg.get(key)
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default()
    };
    let peer_optional = |name: &str| {
        pkg.get("peerDependenciesMeta")
            .and_then(|m| m.get(name))
            .and_then(|m| m.get("optional"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    let peers = section("peerDependencies");
    for (n, s) in peers.iter().filter(|(n, _)| !peer_optional(n)) {
        put(n, s, EdgeType::Peer);
    }
    for (n, s) in peers.iter().filter(|(n, _)| peer_optional(n)) {
        put(n, s, EdgeType::PeerOptional);
    }
    for (n, s) in section("dependencies") {
        put(&n, &s, EdgeType::Prod);
    }
    for (n, s) in section("optionalDependencies") {
        put(&n, &s, EdgeType::Optional);
    }
    if is_root {
        for (n, s) in section("devDependencies") {
            put(&n, &s, EdgeType::Dev);
        }
    }
    edges
}

fn read_json(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)).ok()
}

fn new_node(project_dir: &Path, location: String, package: Value) -> Node {
    let name = if location.is_empty() {
        project_dir
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default()
    } else {
        folder_name(&location)
    };
    Node {
        name,
        location,
        package,
        resolved: None,
        integrity: None,
        in_bundle: false,
        edges: Vec::new(),
        dev: true,
        optional: true,
        dev_optional: true,
        peer: true,
        extraneous: true,
    }
}

fn load_actual_nodes(project_dir: &Path, root_pkg: Value) -> Vec<Node> {
    let lock = read_json(&project_dir.join("node_modules/.package-lock.json"))
        .or_else(|| read_json(&project_dir.join("package-lock.json")));
    let mut disk: Vec<_> = crate::inspect_tree::scan_disk_packages(project_dir)
        .into_values()
        .collect();
    disk.sort_by(|a, b| a.location.cmp(&b.location));
    let mut nodes = vec![new_node(project_dir, String::new(), root_pkg)];
    for pkg in disk {
        let raw = pkg.raw_json.clone().unwrap_or_else(|| json!({}));
        let mut node = new_node(project_dir, pkg.location.clone(), raw);
        let entry = lock
            .as_ref()
            .and_then(|l| l.get("packages"))
            .and_then(|p| p.get(&pkg.location));
        let field = |lock_key: &str, pkg_key: &str| {
            entry
                .and_then(|e| e.get(lock_key))
                .or_else(|| node.package.get(pkg_key))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        node.resolved = field("resolved", "_resolved");
        node.integrity = field("integrity", "_integrity");
        node.in_bundle = entry
            .and_then(|e| e.get("inBundle"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        nodes.push(node);
    }
    nodes
}

fn load_virtual_nodes(project_dir: &Path, root_pkg: Value, lock: &Value) -> Vec<Node> {
    let mut nodes = vec![new_node(project_dir, String::new(), root_pkg)];
    let Some(packages) = lock.get("packages").and_then(Value::as_object) else {
        return nodes;
    };
    for (loc, entry) in packages {
        if !loc.contains("node_modules/") {
            continue;
        }
        let mut pkg = entry.clone();
        if let Some(obj) = pkg.as_object_mut() {
            obj.entry("name")
                .or_insert_with(|| Value::String(folder_name(loc)));
        }
        let mut node = new_node(project_dir, loc.clone(), pkg);
        node.resolved = entry.get("resolved").and_then(Value::as_str).map(str::to_string);
        node.integrity = entry.get("integrity").and_then(Value::as_str).map(str::to_string);
        node.in_bundle = entry.get("inBundle").and_then(Value::as_bool).unwrap_or(false);
        let flag = |k: &str| entry.get(k).and_then(Value::as_bool).unwrap_or(false);
        node.dev = flag("dev");
        node.optional = flag("optional");
        node.dev_optional = flag("devOptional") || node.dev || node.optional;
        node.peer = flag("peer");
        node.extraneous = flag("extraneous");
        nodes.push(node);
    }
    nodes
}

fn link_edges(nodes: &mut [Node]) {
    let index: HashMap<String, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.location.clone(), i))
        .collect();
    for node in nodes.iter_mut() {
        let loc = node.location.clone();
        node.edges = edges_from_package(&node.package, node.is_root())
            .into_iter()
            .map(|(name, spec, kind)| {
                let to = crate::inspect_tree::candidate_locations(&loc, &name)
                    .iter()
                    .find_map(|c| index.get(c).copied());
                Edge { name, spec, kind, to }
            })
            .collect();
    }
}

/// Port of Arborist's calc-dep-flags.
fn calc_dep_flags(nodes: &mut [Node]) {
    {
        let root = &mut nodes[0];
        root.dev = false;
        root.optional = false;
        root.dev_optional = false;
        root.peer = false;
        root.extraneous = false;
    }
    let mut seen = HashSet::new();
    let mut queue = vec![0usize];
    while let Some(i) = queue.pop() {
        seen.insert(i);
        let (dev, optional, dev_optional, peer, extraneous) = {
            let n = &nodes[i];
            (n.dev, n.optional, n.dev_optional, n.peer, n.extraneous)
        };
        let targets: Vec<(usize, EdgeType)> = nodes[i]
            .edges
            .iter()
            .filter_map(|e| e.to.map(|t| (t, e.kind)))
            .collect();
        for (t, kind) in targets {
            let to = &mut nodes[t];
            let mut changed = false;
            if to.extraneous && !extraneous && !(kind.is_peer() && kind.is_optional()) {
                to.extraneous = false;
                changed = true;
            }
            if to.dev && !dev && kind != EdgeType::Dev {
                to.dev = false;
                changed = true;
            }
            if to.optional && !optional && !kind.is_optional() {
                to.optional = false;
                changed = true;
            }
            if to.dev_optional
                && !dev_optional
                && !dev
                && !optional
                && kind != EdgeType::Dev
                && !kind.is_optional()
            {
                to.dev_optional = false;
                changed = true;
            }
            if to.peer && !peer && !kind.is_peer() {
                to.peer = false;
                changed = true;
            }
            if changed {
                queue.push(t);
            }
        }
    }
    for i in seen.into_iter().filter(|i| *i != 0) {
        let n = &mut nodes[i];
        if n.dev_optional && (n.dev || n.optional) {
            n.dev_optional = false;
        }
    }
}

/// Arborist `depValid` for the spec kinds that can be checked from disk.
fn edge_valid(edge: &Edge, target: &Node) -> bool {
    let (want_name, range) = match edge.spec.strip_prefix("npm:") {
        Some(alias) => match alias.rfind('@').filter(|i| *i > 0) {
            Some(i) => (alias[..i].to_string(), alias[i + 1..].to_string()),
            None => (alias.to_string(), "*".to_string()),
        },
        None => (target.package_name(), edge.spec.clone()),
    };
    if target.package_name() != want_name {
        return false;
    }
    let range = if range.trim().is_empty() {
        "*".to_string()
    } else {
        range
    };
    match (
        rnpm_core::semver::Range::parse(&range),
        rnpm_core::semver::Version::parse(&target.version()),
    ) {
        (Ok(r), Ok(v)) => r.satisfies(&v),
        (Ok(_), Err(_)) => false,
        // Tags, git, file and URL specs cannot be checked against disk.
        (Err(_), _) => true,
    }
}

// -------------------------------------------------------------------------
// normalize-package-data (only the fields the SBOM writers read)
// -------------------------------------------------------------------------

fn hosted_github(spec: &str) -> Option<(String, String)> {
    let s = spec.trim();
    let s = s
        .strip_prefix("github:")
        .or_else(|| s.strip_prefix("git+https://github.com/"))
        .or_else(|| s.strip_prefix("https://github.com/"))
        .or_else(|| s.strip_prefix("git://github.com/"))
        .or_else(|| s.strip_prefix("git+ssh://git@github.com/"))
        .or_else(|| s.strip_prefix("git@github.com:"))
        .or_else(|| {
            (!s.contains(':')
                && s.matches('/').count() == 1
                && !s.starts_with('.')
                && !s.starts_with('@'))
            .then_some(s)
        })?;
    let s = s.split('#').next().unwrap_or(s);
    let (user, project) = s.split_once('/')?;
    let project = project.trim_end_matches('/').trim_end_matches(".git");
    if user.is_empty() || project.is_empty() || project.contains('/') {
        return None;
    }
    Some((user.to_string(), project.to_string()))
}

fn parse_person(person: &str) -> Value {
    let name_end = person.find(['<', '(']).unwrap_or(person.len());
    let mut out = Map::new();
    let name = person[..name_end].trim();
    if !name.is_empty() {
        out.insert("name".into(), Value::String(name.to_string()));
    }
    let between = |open: char, close: char| {
        let start = person.find(open)? + 1;
        let end = person[start..].find(close)? + start;
        Some(person[start..end].to_string())
    };
    if let Some(email) = between('<', '>') {
        out.insert("email".into(), Value::String(email));
    }
    if let Some(url) = between('(', ')') {
        out.insert("url".into(), Value::String(url));
    }
    Value::Object(out)
}

fn normalize_package(pkg: &mut Value) {
    let Some(obj) = pkg.as_object_mut() else {
        return;
    };
    if let Some(Value::String(repo)) = obj.get("repository").cloned() {
        obj.insert("repository".into(), json!({ "type": "git", "url": repo }));
    }
    let repo_url = obj
        .get("repository")
        .and_then(|r| r.get("url"))
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some((user, project)) = repo_url.as_deref().and_then(hosted_github) {
        if let Some(repo) = obj.get_mut("repository").and_then(Value::as_object_mut) {
            repo.insert(
                "url".into(),
                Value::String(format!("git+https://github.com/{user}/{project}.git")),
            );
        }
        obj.entry("bugs").or_insert_with(
            || json!({ "url": format!("https://github.com/{user}/{project}/issues") }),
        );
        obj.entry("homepage").or_insert_with(|| {
            Value::String(format!("https://github.com/{user}/{project}#readme"))
        });
    }
    if let Some(Value::String(bugs)) = obj.get("bugs").cloned() {
        let value = if bugs.contains('@') && !bugs.contains("://") {
            json!({ "email": bugs })
        } else {
            json!({ "url": bugs })
        };
        obj.insert("bugs".into(), value);
    }
    if let Some(Value::String(author)) = obj.get("author").cloned() {
        obj.insert("author".into(), parse_person(&author));
    }
}

fn declared_license(pkg: &Value) -> Option<String> {
    match pkg.get("license") {
        Some(Value::String(s)) if !s.is_empty() => return Some(s.clone()),
        Some(Value::Object(o)) => {
            return o.get("type").and_then(Value::as_str).map(str::to_string)
        }
        _ => {}
    }
    let list = pkg.get("licenses")?.as_array()?;
    let joined = list
        .iter()
        .filter_map(|l| match l {
            Value::String(s) => Some(s.clone()),
            Value::Object(o) => o.get("type").and_then(Value::as_str).map(str::to_string),
            _ => None,
        })
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" OR ");
    Some(joined)
}

fn is_git_resolved(resolved: Option<&str>) -> bool {
    resolved.is_some_and(|r| {
        ["git+", "git://", "git@", "github:", "gitlab:", "bitbucket:"]
            .iter()
            .any(|p| r.starts_with(p))
    })
}

fn encode_uri_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn purl(node: &Node) -> String {
    let base = make_purl(&node.package_name(), &node.version());
    match node.resolved.as_deref() {
        Some(r) if is_git_resolved(Some(r)) => format!("{base}?vcs_url={}", encode_uri_component(r)),
        _ => base,
    }
}

fn spdx_id(node: &Node) -> String {
    let name = node.package_name();
    let name = name.strip_prefix('@').unwrap_or(&name).replace('/', ".");
    format!("SPDXRef-Package-{name}-{}", node.version())
}

fn non_empty_str<'a>(pkg: &'a Value, key: &str) -> Option<&'a str> {
    pkg.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn cyclonedx_item(node: &Node, package_type: &str) -> Value {
    let pkg = &node.package;
    let mut c = Map::new();
    c.insert("bom-ref".into(), Value::String(node.id()));
    c.insert("type".into(), Value::String(package_type.to_string()));
    c.insert("name".into(), Value::String(node.name.clone()));
    c.insert("version".into(), Value::String(node.version()));
    let scope = if node.optional || node.dev_optional {
        "optional"
    } else {
        "required"
    };
    c.insert("scope".into(), Value::String(scope.into()));
    let author = match pkg.get("author") {
        Some(Value::Object(o)) => o.get("name").and_then(Value::as_str).map(str::to_string),
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    };
    if let Some(a) = author.filter(|a| !a.is_empty()) {
        c.insert("author".into(), Value::String(a));
    }
    if let Some(d) = non_empty_str(pkg, "description") {
        c.insert("description".into(), Value::String(d.to_string()));
    }
    c.insert("purl".into(), Value::String(purl(node)));
    c.insert("properties".into(), json!([]));
    c.insert("externalReferences".into(), json!([]));
    if let Some((algo, hex)) = node.integrity.as_deref().and_then(integrity_to_hex) {
        let alg = match algo.as_str() {
            "sha1" => "SHA-1",
            "sha256" => "SHA-256",
            "sha384" => "SHA-384",
            _ => "SHA-512",
        };
        c.insert("hashes".into(), json!([{ "alg": alg, "content": hex }]));
    }
    let mut properties = Vec::new();
    let prop = |name: &str| json!({ "name": name, "value": "true" });
    if node.dev && !node.is_root() {
        properties.push(prop("cdx:npm:package:development"));
    }
    if pkg.get("private") == Some(&Value::Bool(true)) {
        properties.push(prop("cdx:npm:package:private"));
    }
    if node.extraneous && !node.is_root() {
        properties.push(prop("cdx:npm:package:extraneous"));
    }
    if node.in_bundle {
        properties.push(prop("cdx:npm:package:bundled"));
    }
    let mut refs = Vec::new();
    let ext = |t: &str, url: &str| json!({ "type": t, "url": url });
    if let Some(r) = &node.resolved {
        refs.push(ext("distribution", r));
    }
    if let Some(u) = pkg.get("repository").and_then(|r| r.get("url")).and_then(Value::as_str) {
        refs.push(ext("vcs", u));
    }
    if let Some(h) = non_empty_str(pkg, "homepage") {
        refs.push(ext("website", h));
    }
    if let Some(u) = pkg.get("bugs").and_then(|b| b.get("url")).and_then(Value::as_str) {
        refs.push(ext("issue-tracker", u));
    }
    c.insert("properties".into(), Value::Array(properties));
    c.insert("externalReferences".into(), Value::Array(refs));
    let license = declared_license(pkg);
    match license.as_deref().and_then(parse_license) {
        Some(ParsedLicense::Single(id)) => {
            c.insert("licenses".into(), json!([{ "license": { "id": id } }]));
        }
        Some(ParsedLicense::Conjunction) => {
            c.insert("licenses".into(), json!([{ "expression": license }]));
        }
        None => {}
    }
    Value::Object(c)
}

fn spdx_item(node: &Node, package_type: Option<&str>) -> Value {
    let pkg = &node.package;
    let mut p = Map::new();
    p.insert("name".into(), Value::String(node.package_name()));
    p.insert("SPDXID".into(), Value::String(spdx_id(node)));
    p.insert("versionInfo".into(), Value::String(node.version()));
    p.insert("packageFileName".into(), Value::String(node.location.clone()));
    if let Some(d) = non_empty_str(pkg, "description") {
        p.insert("description".into(), Value::String(d.to_string()));
    }
    if let Some(t) = package_type {
        p.insert("primaryPackagePurpose".into(), Value::String(t.to_uppercase()));
    }
    let download = node.resolved.clone().unwrap_or_else(|| "NOASSERTION".into());
    p.insert("downloadLocation".into(), Value::String(download));
    p.insert("filesAnalyzed".into(), Value::Bool(false));
    let homepage = non_empty_str(pkg, "homepage").unwrap_or("NOASSERTION");
    p.insert("homepage".into(), Value::String(homepage.to_string()));
    let license = declared_license(pkg)
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| "NOASSERTION".into());
    p.insert("licenseDeclared".into(), Value::String(license));
    p.insert(
        "externalRefs".into(),
        json!([{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl(node),
        }]),
    );
    if let Some((algo, hex)) = node.integrity.as_deref().and_then(integrity_to_hex) {
        p.insert(
            "checksums".into(),
            json!([{ "algorithm": algo.to_uppercase(), "checksumValue": hex }]),
        );
    }
    Value::Object(p)
}

fn detect_errors(nodes: &[Node], items: &[usize]) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();
    let mut push = |e: String| {
        if !errors.contains(&e) {
            errors.push(e);
        }
    };
    for &i in items {
        let from = &nodes[i];
        for edge in &from.edges {
            match edge.to {
                None if !edge.kind.is_optional() => push(format!(
                    "missing: {}@{}, required by {}",
                    edge.name,
                    edge.spec,
                    from.pkgid()
                )),
                Some(t) if !edge_valid(edge, &nodes[t]) => {
                    let spec = if edge.spec.is_empty() { "*" } else { &edge.spec };
                    push(format!(
                        "invalid: {}, {spec} required by {}",
                        nodes[t].pkgid(),
                        from.pkgid()
                    ));
                }
                _ => {}
            }
        }
    }
    errors
}

// -------------------------------------------------------------------------
// Core SBOM Generator Logic
// -------------------------------------------------------------------------

/// Generate the SBOM document for a project, matching `npm sbom`.
pub fn generate_sbom(project_dir: &Path, options: &SbomOptions) -> anyhow::Result<Value> {
    let format = options.format.to_ascii_lowercase();
    if format.is_empty() {
        return Err(usage_error(
            "Must specify --sbom-format flag with one of: cyclonedx, spdx.",
        ));
    }
    if format != "cyclonedx" && format != "spdx" {
        return Err(anyhow::anyhow!(
            "npm error code EUSAGE\nnpm error Invalid value for sbom-format: {format}"
        ));
    }
    let root_pkg = read_json(&project_dir.join("package.json")).unwrap_or_else(|| json!({}));
    let mut nodes = if options.package_lock_only {
        let lock = read_json(&project_dir.join("npm-shrinkwrap.json"))
            .or_else(|| read_json(&project_dir.join("package-lock.json")))
            .ok_or_else(|| {
                usage_error(
                    "A package lock or shrinkwrap file is required in package-lock-only mode",
                )
            })?;
        load_virtual_nodes(project_dir, root_pkg, &lock)
    } else {
        load_actual_nodes(project_dir, root_pkg)
    };
    link_edges(&mut nodes);
    if options.package_lock_only {
        let root = &mut nodes[0];
        root.dev = false;
        root.optional = false;
        root.dev_optional = false;
        root.peer = false;
        root.extraneous = false;
    } else {
        calc_dep_flags(&mut nodes);
    }
    for node in &mut nodes {
        normalize_package(&mut node.package);
    }

    // Selector `:root,:root *<omits>,:extraneous`.
    let (omit_dev, omit_optional, omit_peer) = crate::parse_omit_options(&options.omit);
    let mut reachable = vec![false; nodes.len()];
    let mut stack = vec![0usize];
    while let Some(i) = stack.pop() {
        for t in nodes[i].edges.iter().filter_map(|e| e.to) {
            if !reachable[t] {
                reachable[t] = true;
                stack.push(t);
            }
        }
    }
    let mut items: Vec<usize> = (0..nodes.len())
        .filter(|&i| {
            let n = &nodes[i];
            i == 0
                || n.extraneous
                || (reachable[i]
                    && !(omit_dev && n.dev)
                    && !(omit_optional && n.optional)
                    && !(omit_peer && n.peer))
        })
        .collect();

    let errors = detect_errors(&nodes, &items);
    if !errors.is_empty() {
        let body = errors
            .iter()
            .map(|e| format!("npm error {e}"))
            .collect::<Vec<_>>()
            .join("\n");
        return Err(anyhow::anyhow!("npm error code ESBOMPROBLEMS\n{body}"));
    }

    items.sort_by(|a, b| {
        rnpm_lockfile::model::npm_key_compare(&nodes[*a].location, &nodes[*b].location)
    });
    let in_items: HashSet<usize> = items.iter().copied().collect();
    let mut seen_ids = HashSet::new();
    let unique_children: Vec<usize> = items
        .iter()
        .copied()
        .filter(|&i| i != 0)
        .filter(|&i| {
            let id = if format == "spdx" {
                spdx_id(&nodes[i])
            } else {
                nodes[i].id()
            };
            seen_ids.insert(id)
        })
        .collect();
    let root = &nodes[0];
    let package_type = options.sbom_type.as_str();

    if format == "cyclonedx" {
        let dependency = |i: usize| {
            let mut depends_on: Vec<String> = Vec::new();
            for t in nodes[i].edges.iter().filter_map(|e| e.to) {
                let id = nodes[t].id();
                if in_items.contains(&t) && !depends_on.contains(&id) {
                    depends_on.push(id);
                }
            }
            json!({ "ref": nodes[i].id(), "dependsOn": depends_on })
        };
        let phase = if options.package_lock_only {
            "pre-build"
        } else {
            "build"
        };
        let components: Vec<Value> = unique_children
            .iter()
            .map(|&i| cyclonedx_item(&nodes[i], "library"))
            .collect();
        let dependencies: Vec<Value> = std::iter::once(0)
            .chain(unique_children.iter().copied())
            .map(dependency)
            .collect();
        return Ok(json!({
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": format!("urn:uuid:{}", generate_uuid()),
            "version": 1,
            "metadata": {
                "timestamp": current_iso_time_millis(),
                "lifecycles": [{ "phase": phase }],
                "tools": [{
                    "vendor": "npm",
                    "name": "cli",
                    "version": crate::version::NPM_VERSION,
                }],
                "component": cyclonedx_item(root, package_type),
            },
            "components": components,
            "dependencies": dependencies,
        }));
    }

    let rel = |from: &Node, to: &Node, kind: EdgeType| {
        let t = match kind {
            EdgeType::Peer => "PREREQUISITE_FOR",
            EdgeType::Optional => "OPTIONAL_DEPENDENCY_OF",
            EdgeType::Dev => "DEV_DEPENDENCY_OF",
            _ => "DEPENDENCY_OF",
        };
        json!({
            "spdxElementId": spdx_id(to),
            "relatedSpdxElement": spdx_id(from),
            "relationshipType": t,
        })
    };
    let mut relationships = vec![json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relatedSpdxElement": spdx_id(root),
        "relationshipType": "DESCRIBES",
    })];
    for &i in &items {
        let mut seen = HashSet::new();
        for edge in &nodes[i].edges {
            let Some(t) = edge.to.filter(|t| in_items.contains(t)) else {
                continue;
            };
            let r = rel(&nodes[i], &nodes[t], edge.kind);
            if seen.insert(r.to_string()) {
                relationships.push(r);
            }
        }
    }
    for &i in items.iter().filter(|&&i| i != 0 && nodes[i].extraneous) {
        relationships.push(rel(root, &nodes[i], EdgeType::Optional));
    }
    let mut packages = vec![spdx_item(root, Some(package_type))];
    packages.extend(unique_children.iter().map(|&i| spdx_item(&nodes[i], None)));
    Ok(json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": root.pkgid(),
        "documentNamespace": format!(
            "http://spdx.org/spdxdocs/{}-{}-{}",
            root.package_name().replace('/', "%2f"),
            root.version(),
            generate_uuid()
        ),
        "creationInfo": {
            "created": current_iso_time_millis(),
            "creators": [format!("Tool: npm/cli-{}", crate::version::NPM_VERSION)],
        },
        "documentDescribes": [spdx_id(root)],
        "packages": packages,
        "relationships": relationships,
    }))
}

/// Execute `rnpm sbom` workflow.
pub async fn run_sbom(project_dir: &Path, options: SbomOptions) -> anyhow::Result<()> {
    let sbom_json = generate_sbom(project_dir, &options)?;
    println!("{}", serde_json::to_string_pretty(&sbom_json)?);
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
    fn test_parse_license_matches_spdx_expression_parse() {
        assert_eq!(parse_license("MIT"), Some(ParsedLicense::Single("MIT".into())));
        assert_eq!(parse_license("(MIT)"), Some(ParsedLicense::Single("MIT".into())));
        assert_eq!(parse_license("GPL-2.0+"), Some(ParsedLicense::Single("GPL-2.0".into())));
        assert_eq!(
            parse_license("GPL-2.0-only WITH Classpath-exception-2.0"),
            Some(ParsedLicense::Single("GPL-2.0-only".into()))
        );
        assert_eq!(parse_license("MIT OR Apache-2.0"), Some(ParsedLicense::Conjunction));
        assert_eq!(parse_license("(MIT AND ISC) OR 0BSD"), Some(ParsedLicense::Conjunction));
        assert_eq!(
            parse_license("LicenseRef-Proprietary"),
            Some(ParsedLicense::Single("LicenseRef-Proprietary".into()))
        );
        assert_eq!(parse_license("UNLICENSED"), None);
        assert_eq!(parse_license("SEE LICENSE IN LICENSE.md"), None);
        assert_eq!(parse_license("MIT OR"), None);
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
