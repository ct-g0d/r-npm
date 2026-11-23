//! npm's linked install strategy (`--install-strategy=linked`), as arborist's
//! isolated-reifier.js builds it from the hoisted ideal tree (RFC 0042).
//!
//! Every registry package is unpacked once into
//! `node_modules/.store/<name>@<version>-<hash>/node_modules/<name>`, where the
//! hash covers its whole dependency subtree, and each dependency edge becomes
//! a link next to it. package-lock.json keeps the hoisted tree; the hidden
//! lockfile records the isolated one.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use anyhow::{anyhow, Result};
use rnpm_lockfile::{LockfilePackage, LockfileV3};
use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------
// SHAKE256 (FIPS 202), the XOF arborist keys store folders with.

const KECCAK_RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
const KECCAK_ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const KECCAK_PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccak_f(st: &mut [u64; 25]) {
    for rc in KECCAK_RC {
        let mut bc = [0u64; 5];
        for i in 0..5 {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for j in (0..25).step_by(5) {
                st[j + i] ^= t;
            }
        }
        let mut t = st[1];
        for i in 0..24 {
            let j = KECCAK_PILN[i];
            let tmp = st[j];
            st[j] = t.rotate_left(KECCAK_ROTC[i]);
            t = tmp;
        }
        for j in (0..25).step_by(5) {
            let row = [st[j], st[j + 1], st[j + 2], st[j + 3], st[j + 4]];
            for i in 0..5 {
                st[j + i] = row[i] ^ (!row[(i + 1) % 5] & row[(i + 2) % 5]);
            }
        }
        st[0] ^= rc;
    }
}

/// SHAKE256 with a 16-byte output (`createHash('shake256', { outputLength: 16 })`).
pub fn shake256_16(data: &[u8]) -> [u8; 16] {
    const RATE: usize = 136;
    let mut st = [0u64; 25];
    let absorb = |st: &mut [u64; 25], block: &[u8]| {
        for (i, lane) in block.chunks(8).enumerate() {
            let mut b = [0u8; 8];
            b[..lane.len()].copy_from_slice(lane);
            st[i] ^= u64::from_le_bytes(b);
        }
        keccak_f(st);
    };
    let (blocks, rest) = data.as_chunks::<RATE>();
    for block in blocks {
        absorb(&mut st, block);
    }
    let mut last = [0u8; RATE];
    last[..rest.len()].copy_from_slice(rest);
    last[rest.len()] ^= 0x1f;
    last[RATE - 1] ^= 0x80;
    absorb(&mut st, &last);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&st[0].to_le_bytes());
    out[8..].copy_from_slice(&st[1].to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// The isolated graph.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Target {
    /// A registry (or tarball) package, by its hoisted lockfile location.
    External(String),
    /// A workspace or `file:` directory, by its project-relative location.
    Local(String),
}

#[derive(Debug, Clone)]
struct Dep {
    name: String,
    target: Target,
    optional: bool,
}

/// A planned link: `location` (project-relative) points at `target`.
#[derive(Debug, Clone)]
pub struct PlannedLink {
    pub location: String,
    pub target: String,
}

/// A package unpacked into the store.
#[derive(Debug, Clone)]
pub struct StoreEntry {
    /// `node_modules/.store/<key>/node_modules/<name>`.
    pub location: String,
    /// `node_modules/.store/<key>`.
    pub store_dir: String,
    pub package_name: String,
    pub resolved: Option<String>,
    pub integrity: Option<String>,
    pub optional: bool,
    pub bin: Vec<(String, String)>,
    /// Location of the package in the hoisted lockfile.
    pub hoisted: String,
}

#[derive(Debug, Default)]
pub struct IsolatedPlan {
    pub store: Vec<StoreEntry>,
    pub links: Vec<PlannedLink>,
    /// Workspace (and local directory) folders: their `node_modules` hold links.
    pub local_dirs: Vec<String>,
    pub hidden_lock: Value,
}

pub struct Omit {
    pub dev: bool,
    pub optional: bool,
    pub peer: bool,
    /// Lockfile locations skipped for this platform (os/cpu/libc), with
    /// the subtrees only they need.
    pub skipped: HashSet<String>,
}

fn is_external_location(loc: &str) -> bool {
    loc.starts_with("node_modules/") || loc.contains("/node_modules/")
}

fn package_name(loc: &str, pkg: &LockfilePackage) -> String {
    pkg.name.clone().unwrap_or_else(|| {
        loc.rsplit_once("node_modules/")
            .map(|(_, n)| n.to_string())
            .unwrap_or_else(|| loc.rsplit('/').next().unwrap_or(loc).to_string())
    })
}

fn bin_entries(pkg: &LockfilePackage, name: &str) -> Vec<(String, String)> {
    let Some(bin) = pkg.bin.as_ref() else {
        return Vec::new();
    };
    match serde_json::to_value(bin).unwrap_or(Value::Null) {
        Value::String(path) => {
            let bin_name = name.rsplit('/').next().unwrap_or(name).to_string();
            vec![(bin_name, path)]
        }
        Value::Object(map) => map
            .into_iter()
            .filter_map(|(k, v)| v.as_str().map(|p| (k, p.to_string())))
            .collect(),
        _ => Vec::new(),
    }
}

fn should_omit(pkg: &LockfilePackage, omit: &Omit) -> bool {
    let dev = pkg.dev == Some(true);
    let optional = pkg.optional == Some(true);
    let dev_optional = pkg.dev_optional == Some(true);
    (dev && omit.dev)
        || (optional && omit.optional)
        || (dev_optional && omit.dev && omit.optional)
        || (pkg.peer == Some(true) && omit.peer)
}

struct Builder<'a> {
    lock: &'a LockfileV3,
    omit: Omit,
    deps: HashMap<Target, Vec<Dep>>,
    /// package.json documents by lockfile location: edge order follows their
    /// key order, which the lockfile (sorted) does not keep.
    manifests: &'a HashMap<String, Value>,
}

impl<'a> Builder<'a> {
    /// Resolves `name` from `from` as node_modules lookup does, following a
    /// link entry to its target folder.
    fn resolve(&self, from: &str, name: &str) -> Option<Target> {
        let (key, pkg) = crate::linked::resolve_lockfile_dep(self.lock, from, name)?;
        if pkg.link == Some(true) {
            let target = pkg.resolved.clone()?;
            return Some(Target::Local(target));
        }
        if pkg.in_bundle == Some(true)
            || should_omit(pkg, &self.omit)
            || self.omit.skipped.contains(&key)
        {
            return None;
        }
        Some(Target::External(key))
    }

    /// arborist's edgesOut order: peer, peerOptional, prod, optional (and
    /// dev for a top); a later type replaces an earlier one by name.
    fn edges(&self, loc: &str, is_top: bool, is_root: bool) -> Vec<Dep> {
        let Some(pkg) = self.lock.packages.get(loc) else {
            return Vec::new();
        };
        let mut order: Vec<String> = Vec::new();
        let mut kinds: HashMap<String, bool> = HashMap::new();
        let manifest = self.manifests.get(loc);
        let mut add = |section: &str, deps: Option<&BTreeMap<String, String>>, optional: bool, keep: &dyn Fn(&str) -> bool| {
            let mut names: Vec<&String> = deps.into_iter().flat_map(|d| d.keys()).collect();
            if let Some(keys) = manifest.and_then(|m| m.get(section)).and_then(Value::as_object) {
                let position = |n: &str| keys.keys().position(|k| k == n).unwrap_or(usize::MAX);
                names.sort_by_key(|n| position(n));
            }
            for name in names {
                if !keep(name) {
                    continue;
                }
                if kinds.insert(name.clone(), optional).is_some() {
                    order.retain(|n| n != name);
                }
                order.push(name.clone());
            }
        };
        let meta_optional = |name: &str| {
            pkg.peer_dependencies_meta
                .as_ref()
                .and_then(|m| m.get(name))
                .and_then(|v| v.get("optional"))
                .and_then(Value::as_bool)
                == Some(true)
        };
        let top_omit = is_root || is_top;
        if !(top_omit && self.omit.peer) {
            add("peerDependencies", pkg.peer_dependencies.as_ref(), false, &|n| !meta_optional(n));
            add("peerDependencies", pkg.peer_dependencies.as_ref(), true, &|n| meta_optional(n));
        }
        add("dependencies", pkg.dependencies.as_ref(), false, &|_| true);
        if !(top_omit && self.omit.optional) {
            add("optionalDependencies", pkg.optional_dependencies.as_ref(), true, &|_| true);
        }
        if is_top && !(top_omit && self.omit.dev) {
            add("devDependencies", pkg.dev_dependencies.as_ref(), false, &|_| true);
        }
        let bundled: HashSet<String> = pkg
            .raw_value
            .as_ref()
            .and_then(|r| r.get("bundleDependencies").or_else(|| r.get("bundledDependencies")))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        order
            .into_iter()
            .filter(|name| !bundled.contains(name))
            .filter_map(|name| {
                let target = self.resolve(loc, &name)?;
                let optional = kinds[&name];
                Some(Dep { name, target, optional })
            })
            .collect()
    }

    fn walk(&mut self, start: Target) {
        let mut queue = vec![start];
        while let Some(node) = queue.pop() {
            if self.deps.contains_key(&node) {
                continue;
            }
            let deps = match &node {
                Target::External(loc) => self.edges(loc, false, false),
                Target::Local(loc) => self.edges(loc, true, loc.is_empty()),
            };
            queue.extend(deps.iter().map(|d| d.target.clone()));
            self.deps.insert(node, deps);
        }
    }

    /// arborist's `dependencies` order: external non-optional, local
    /// non-optional, then optional.
    fn children(&self, node: &Target) -> Vec<&Dep> {
        let deps = self.deps.get(node).map(Vec::as_slice).unwrap_or_default();
        let ext = deps
            .iter()
            .filter(|d| !d.optional && matches!(d.target, Target::External(_)));
        let local = deps
            .iter()
            .filter(|d| !d.optional && matches!(d.target, Target::Local(_)));
        let optional = deps.iter().filter(|d| d.optional);
        ext.chain(local).chain(optional).collect()
    }

    fn identity(&self, node: &Target) -> (String, String, String) {
        match node {
            Target::External(loc) => {
                let pkg = &self.lock.packages[loc];
                (
                    package_name(loc, pkg),
                    pkg.version.clone().unwrap_or_else(|| "undefined".into()),
                    pkg.resolved.clone().unwrap_or_else(|| "undefined".into()),
                )
            }
            Target::Local(loc) => {
                let pkg = self.lock.packages.get(loc);
                let name = pkg
                    .and_then(|p| p.name.clone())
                    .unwrap_or_else(|| loc.rsplit('/').next().unwrap_or(loc).to_string());
                // A workspace proxy carries no version, and its node no resolved.
                (name, "undefined".into(), "null".into())
            }
        }
    }

    /// arborist's getKey: a depth-first walk (each node visited once)
    /// recording `a@1->b@2::resolved`, sorted, hashed with SHAKE256.
    fn key(&self, start: &Target) -> String {
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        let mut branch: Vec<String> = Vec::new();
        self.key_visit(start, &mut seen, &mut branch, &mut entries);
        entries.sort();
        let digest = shake256_16(entries.join(",").as_bytes());
        let hash = data_encoding::BASE64URL_NOPAD.encode(&digest);
        let (name, version, _) = self.identity(start);
        format!("{name}@{version}-{hash}")
    }

    fn key_visit(
        &self,
        node: &Target,
        seen: &mut HashSet<Target>,
        branch: &mut Vec<String>,
        entries: &mut Vec<String>,
    ) {
        if !seen.insert(node.clone()) {
            return;
        }
        let (name, version, resolved) = self.identity(node);
        branch.push(format!("{name}@{version}"));
        entries.push(format!("{}::{resolved}", branch.join("->")));
        for dep in self.children(node) {
            self.key_visit(&dep.target, seen, branch, entries);
        }
        branch.pop();
    }
}

fn join(folder: &str, name: &str) -> String {
    if folder.is_empty() {
        name.to_string()
    } else {
        format!("{folder}/{name}")
    }
}

/// Builds npm's isolated tree from the hoisted lockfile.
pub fn plan(lock: &LockfileV3, omit: Omit, manifests: &HashMap<String, Value>) -> IsolatedPlan {
    let mut builder = Builder {
        lock,
        omit,
        deps: HashMap::new(),
        manifests,
    };
    builder.walk(Target::Local(String::new()));
    // Every workspace folder is part of the tree, declared by the root or not.
    let local_dirs: Vec<String> = lock
        .packages
        .iter()
        .filter(|(k, p)| !k.is_empty() && !is_external_location(k) && p.link != Some(true))
        .map(|(k, _)| k.clone())
        .collect();
    for dir in &local_dirs {
        builder.walk(Target::Local(dir.clone()));
    }

    let mut keys: HashMap<Target, String> = HashMap::new();
    let mut nodes: Vec<Target> = builder.deps.keys().cloned().collect();
    nodes.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    for node in &nodes {
        if let Target::External(_) = node {
            keys.insert(node.clone(), builder.key(node));
        }
    }

    let mut store: BTreeMap<String, StoreEntry> = BTreeMap::new();
    for node in &nodes {
        let Target::External(loc) = node else { continue };
        let key = &keys[node];
        let pkg = &lock.packages[loc];
        let name = package_name(loc, pkg);
        let store_dir = format!("node_modules/.store/{key}");
        let location = format!("{store_dir}/node_modules/{name}");
        store.entry(location.clone()).or_insert_with(|| StoreEntry {
            location,
            store_dir,
            bin: bin_entries(pkg, &name),
            package_name: name,
            resolved: pkg.resolved.clone(),
            integrity: pkg.integrity.clone(),
            optional: pkg.optional == Some(true),
            hoisted: loc.clone(),
        });
    }

    let target_location = |t: &Target| match t {
        Target::External(_) => {
            let key = &keys[t];
            let (name, _, _) = builder.identity(t);
            format!("node_modules/.store/{key}/node_modules/{name}")
        }
        Target::Local(loc) => loc.clone(),
    };

    // Links: from the root, each workspace, and each store package.
    let mut links: BTreeMap<String, PlannedLink> = BTreeMap::new();
    let mut from_nodes: Vec<(Target, String)> = vec![(Target::Local(String::new()), "node_modules".into())];
    for dir in &local_dirs {
        from_nodes.push((Target::Local(dir.clone()), format!("{dir}/node_modules")));
    }
    for node in &nodes {
        if let Target::External(_) = node {
            let key = &keys[node];
            from_nodes.push((node.clone(), format!("node_modules/.store/{key}/node_modules")));
        }
    }
    for (node, nm) in &from_nodes {
        for dep in builder.children(node) {
            let location = join(nm, &dep.name);
            let target = target_location(&dep.target);
            if location == target {
                continue;
            }
            links.insert(location.clone(), PlannedLink { location, target });
        }
    }

    // The hidden lockfile describes the isolated tree.
    let mut packages = Map::new();
    for entry in store.values() {
        packages.insert(entry.store_dir.clone(), json!({}));
        let pkg = &lock.packages[&entry.hoisted];
        let mut value = pkg
            .raw_value
            .clone()
            .unwrap_or_else(|| serde_json::to_value(pkg).unwrap_or(Value::Null));
        if let Some(obj) = value.as_object_mut() {
            for flag in ["name", "dev", "peer", "devOptional", "optional", "inBundle", "extraneous"] {
                obj.remove(flag);
            }
            // A store node's integrity comes from its fetched manifest
            // (`_integrity`); one loaded from the lockfile has none.
            if !manifests.contains_key(&entry.hoisted) {
                obj.remove("integrity");
            }
            if entry.optional {
                obj.insert("optional".into(), Value::Bool(true));
            }
        }
        packages.insert(entry.location.clone(), value);
    }
    for link in links.values() {
        packages.insert(
            link.location.clone(),
            json!({ "resolved": link.target, "link": true }),
        );
    }
    for dir in &local_dirs {
        let pkg = &lock.packages[dir];
        let value = pkg
            .raw_value
            .clone()
            .unwrap_or_else(|| serde_json::to_value(pkg).unwrap_or(Value::Null));
        packages.insert(dir.clone(), value);
    }
    let hidden_lock = json!({
        "lockfileVersion": 3,
        "requires": true,
        "packages": Value::Object(packages),
    });

    IsolatedPlan {
        store: store.into_values().collect(),
        links: links.into_values().collect(),
        local_dirs,
        hidden_lock,
    }
}

/// Makes `link` a directory link to `target`, replacing whatever is there.
pub fn ensure_link(link: &Path, target: &Path) -> Result<()> {
    if rnpm_fs::junction::junction_points_to(link, target) {
        return Ok(());
    }
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::linked::create_or_replace_junction(link, target)
        .map_err(|e| anyhow!("Failed to link {} to {}: {e}", link.display(), target.display()))
}

/// Tarball bytes for a store package: the cache first, then the registry.
async fn fetch_tarball(
    installer: &crate::Installer,
    project_dir: &Path,
    location: &str,
    pkg: &LockfilePackage,
) -> Result<Vec<u8>> {
    let resolved = pkg
        .resolved
        .as_deref()
        .ok_or_else(|| anyhow!("Package {location} missing resolved URL in lockfile"))?;
    let expected: Option<rnpm_core::integrity::Integrity> =
        pkg.integrity.as_deref().and_then(|i| i.parse().ok());
    if let Some(rel) = resolved.strip_prefix("file:") {
        return Ok(std::fs::read(project_dir.join(rel))?);
    }
    if let Some(exp) = &expected {
        if let Ok(Some(data)) = installer.cache.get_by_integrity(exp) {
            return Ok(data);
        }
    }
    if let Ok(Some((_, data))) = installer.cache.get(resolved) {
        if expected.as_ref().is_none_or(|e| e.verify(&data).is_ok()) {
            return Ok(data);
        }
    }
    if installer.options.offline {
        return Err(anyhow!(
            "npm error code ENOTCACHED\nnpm error request to {resolved} failed: cache mode is 'only-if-cached' but no cached response is available."
        ));
    }
    let data = installer
        .registry_client
        .download_tarball_bytes(resolved)
        .await
        .map_err(|e| anyhow!("Failed to download tarball from {resolved}: {e}"))?;
    if let Some(exp) = &expected {
        exp.verify(&data)
            .map_err(|e| anyhow!("Integrity verification failed for {location}: {e}"))?;
    }
    let _ = installer
        .cache
        .put_with_integrity(resolved, &data, expected.as_ref(), None);
    Ok(data)
}

impl crate::Installer {
    /// The root's own install scripts, after the tree is in place.
    pub(crate) async fn run_linked_root_hooks(
        &self,
        manifest: &rnpm_core::manifest::Manifest,
    ) -> Result<()> {
        if self.options.ignore_scripts {
            return Ok(());
        }
        let opts = self.lifecycle_options();
        rnpm_lifecycle::execute_root_hooks(manifest, &opts).await
    }

    /// Reifies npm's isolated tree for `lock` (the hoisted lockfile) and
    /// writes its hidden lockfile. Returns how many store packages were added.
    /// `previous` is the lockfile the tree was loaded from, if any.
    pub(crate) async fn reify_isolated(
        &mut self,
        lock: &LockfileV3,
        previous: Option<&LockfileV3>,
    ) -> Result<usize> {
        let project = self.options.project_dir.clone();
        // Edge order decides each store key. arborist takes it from the
        // package.json of a node it resolved from the registry, but from the
        // (sorted) lockfile for a node it loaded from one. So read manifests
        // only for nodes the previous lockfile did not already hold.
        let skipped = crate::lockfile_platform_skipped_packages(lock, &self.options.platform());
        let mut manifests: HashMap<String, Value> = HashMap::new();
        let mut tarballs: HashMap<String, Vec<u8>> = HashMap::new();
        for (loc, pkg) in &lock.packages {
            if pkg.link == Some(true) {
                continue;
            }
            if !is_external_location(loc) {
                if let Ok(text) = std::fs::read_to_string(project.join(loc).join("package.json")) {
                    if let Ok(value) = serde_json::from_str(&text) {
                        manifests.insert(loc.clone(), value);
                    }
                }
                continue;
            }
            if pkg.in_bundle == Some(true) || skipped.contains(loc) {
                continue;
            }
            let loaded = previous
                .and_then(|p| p.packages.get(loc))
                .is_some_and(|old| old.version == pkg.version && old.resolved == pkg.resolved);
            if loaded {
                continue;
            }
            let bytes = match fetch_tarball(self, &project, loc, pkg).await {
                Ok(bytes) => bytes,
                Err(_) if pkg.optional == Some(true) => continue,
                Err(e) => return Err(e),
            };
            if let Some(value) = rnpm_fs::read_tarball_text(&bytes, "package.json")
                .and_then(|t| serde_json::from_str(&t).ok())
            {
                manifests.insert(loc.clone(), value);
            }
            tarballs.insert(loc.clone(), bytes);
        }
        let plan = plan(
            lock,
            Omit {
                dev: self.options.omit_dev,
                optional: self.options.omit_optional,
                peer: self.options.omit_peer,
                skipped,
            },
            &manifests,
        );
        let nm = project.join("node_modules");
        std::fs::create_dir_all(&nm)?;

        // Remove what the isolated tree does not hold: a hoisted layout left
        // behind, and store folders for other trees.
        let mut keep: HashSet<String> = [".store", ".package-lock.json"]
            .into_iter()
            .map(str::to_string)
            .collect();
        if self.options.bin_links {
            keep.insert(".bin".to_string());
        }
        for link in &plan.links {
            if let Some(rest) = link.location.strip_prefix("node_modules/") {
                if !rest.starts_with(".store/") {
                    keep.insert(rest.split('/').next().unwrap_or(rest).to_string());
                }
            }
        }
        let remove = |path: &Path| {
            if rnpm_fs::junction::is_junction(path).unwrap_or(false) {
                let _ = rnpm_fs::junction::remove_junction(path);
            } else if path.is_dir() {
                let _ = std::fs::remove_dir_all(path);
            } else {
                let _ = std::fs::remove_file(path);
            }
        };
        for entry in std::fs::read_dir(&nm)?.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !keep.contains(&name) {
                remove(&entry.path());
            }
        }
        // Store folders by path under .store; a scoped one sits in its
        // scope folder (`.store/@scope/pkg@1.0.0-<hash>`).
        let store_dirs: HashSet<String> = plan
            .store
            .iter()
            .filter_map(|e| e.store_dir.strip_prefix("node_modules/.store/").map(str::to_string))
            .collect();
        if let Ok(entries) = std::fs::read_dir(nm.join(".store")) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('@') && entry.path().is_dir() {
                    for child in std::fs::read_dir(entry.path()).into_iter().flatten().flatten() {
                        let rel = format!("{name}/{}", child.file_name().to_string_lossy());
                        if !store_dirs.contains(&rel) {
                            remove(&child.path());
                        }
                    }
                    let _ = std::fs::remove_dir(entry.path());
                } else if !store_dirs.contains(&name) {
                    remove(&entry.path());
                }
            }
        }

        // Unpack the store.
        let writer_cfg = rnpm_fs::determine_writer_config(&project, None);
        let mut added = 0usize;
        let mut lifecycle_nodes = Vec::new();
        for entry in &plan.store {
            let dest = project.join(&entry.location);
            if !dest.join("package.json").is_file() {
                let bytes = match tarballs.remove(&entry.hoisted) {
                    Some(bytes) => bytes,
                    None => match fetch_tarball(self, &project, &entry.hoisted, &lock.packages[&entry.hoisted]).await {
                        Ok(bytes) => bytes,
                        Err(_) if entry.optional => continue,
                        Err(e) => return Err(e),
                    },
                };
                if dest.exists() {
                    let _ = std::fs::remove_dir_all(&dest);
                }
                std::fs::create_dir_all(&dest)?;
                rnpm_fs::extract_tarball_direct(
                    std::io::Cursor::new(&bytes),
                    &dest,
                    None,
                    Some(&writer_cfg),
                )
                .map_err(|e| anyhow!("Failed to extract {}: {e}", entry.hoisted))?;
                added += 1;
            }
            let pkg = &lock.packages[&entry.hoisted];
            if pkg.has_install_script == Some(true) {
                if let Ok(manifest) = rnpm_core::manifest::Manifest::from_file(dest.join("package.json")) {
                    lifecycle_nodes.push(rnpm_lifecycle::LifecyclePackageNode {
                        package_path: entry.location.clone(),
                        disk_path: dest.clone(),
                        manifest,
                        source: rnpm_lifecycle::PackageSource::Registry,
                        dependencies: pkg
                            .dependencies
                            .as_ref()
                            .map(|d| d.keys().cloned().collect())
                            .unwrap_or_default(),
                        optional: entry.optional,
                    });
                }
            }
        }

        // Link every edge.
        for link in &plan.links {
            let target = project.join(&link.target);
            if !target.exists() {
                continue;
            }
            ensure_link(&project.join(&link.location), &target)?;
        }

        // Bins go in the `.bin` beside each package and each link.
        if self.options.bin_links {
            let bins_of: HashMap<String, Vec<(String, String)>> = plan
                .store
                .iter()
                .map(|e| (e.location.clone(), e.bin.clone()))
                .chain(plan.local_dirs.iter().map(|d| {
                    let bins = lock
                        .packages
                        .get(d)
                        .map(|p| bin_entries(p, p.name.as_deref().unwrap_or(d)))
                        .unwrap_or_default();
                    (d.clone(), bins)
                }))
                .collect();
            let placed = plan
                .store
                .iter()
                .map(|e| (e.location.clone(), e.location.clone()))
                .chain(plan.links.iter().map(|l| (l.location.clone(), l.target.clone())));
            for (location, target) in placed {
                let Some(bins) = bins_of.get(&target).filter(|b| !b.is_empty()) else {
                    continue;
                };
                let Some((folder, name)) = location.rsplit_once("/node_modules/").or_else(|| {
                    location.strip_prefix("node_modules/").map(|n| ("", n))
                }) else {
                    continue;
                };
                let bin_dir = project.join(join(folder, "node_modules")).join(".bin");
                for (bin_name, script) in bins {
                    let script = script.trim_start_matches("./");
                    let _ = rnpm_shim::normalize_shebang(&project.join(&target).join(script));
                    rnpm_shim::create_shims_with_force(
                        &bin_dir,
                        bin_name,
                        &format!("{name}/{script}"),
                        self.options.force,
                    )?;
                }
            }
        } else {
            crate::link::remove_all_bin_dirs(&nm);
        }

        if !self.options.ignore_scripts && !lifecycle_nodes.is_empty() {
            let opts = self.lifecycle_options();
            rnpm_lifecycle::execute_dependency_hooks(&lifecycle_nodes, &opts).await?;
        }

        let mut text = serde_json::to_string_pretty(&plan.hidden_lock)?;
        text.push('\n');
        std::fs::write(nm.join(".package-lock.json"), text)?;
        Ok(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shake256_matches_node() {
        // node -p "require('crypto').createHash('shake256',{outputLength:16}).update('').digest('hex')"
        let hex = |b: [u8; 16]| data_encoding::HEXLOWER.encode(&b);
        assert_eq!(hex(shake256_16(b"")), "46b9dd2b0ba88d13233b3feb743eeb24");
        assert_eq!(hex(shake256_16(b"abc")), "483366601360a8771c6863080cc4114d");
        // Multi-block, exact-rate and rate-minus-one inputs.
        assert_eq!(hex(shake256_16(&[b'a'; 300])), "542e4338ca18e43776834307a2b6158f");
        assert_eq!(hex(shake256_16(&[b'a'; 136])), "8fcc5a08f0a1f6827c9cf64ee8d16e04");
        assert_eq!(hex(shake256_16(&[b'a'; 135])), "55b991ece1e567b6e7c2c714444dd201");
    }

    #[test]
    fn plan_links_each_edge_beside_its_store_package() {
        let lock = LockfileV3::from_json_str(
            r#"{"name":"r","lockfileVersion":3,"requires":true,"packages":{
              "":{"name":"r","dependencies":{"a":"1.0.0"}},
              "node_modules/a":{"version":"1.0.0","resolved":"https://r/a.tgz","dependencies":{"b":"^1.0.0"},"bin":{"a":"a.js"}},
              "node_modules/b":{"version":"1.0.0","resolved":"https://r/b.tgz"}}}"#,
        )
        .unwrap();
        let plan = plan(
            &lock,
            Omit { dev: false, optional: false, peer: false, skipped: HashSet::new() },
            &HashMap::new(),
        );
        // getKey of b: one entry, "b@1.0.0::https://r/b.tgz".
        let b_hash = data_encoding::BASE64URL_NOPAD.encode(&shake256_16(b"b@1.0.0::https://r/b.tgz"));
        let b = format!("node_modules/.store/b@1.0.0-{b_hash}/node_modules/b");
        assert!(plan.store.iter().any(|e| e.location == b));
        let a = plan.store.iter().find(|e| e.package_name == "a").unwrap();
        assert_eq!(a.bin, vec![("a".to_string(), "a.js".to_string())]);
        let link = |loc: &str| plan.links.iter().find(|l| l.location == loc).map(|l| l.target.clone());
        assert_eq!(link("node_modules/a"), Some(a.location.clone()));
        assert_eq!(link(&format!("{}/node_modules/b", a.store_dir)), Some(b.clone()));
        assert!(plan.hidden_lock["packages"].get("").is_none());

        // A platform-skipped package is neither stored nor linked.
        let skipped = plan_with_skipped(&lock, "node_modules/b");
        assert!(skipped.store.iter().all(|e| e.package_name != "b"));
        assert!(skipped.links.iter().all(|l| !l.location.ends_with("/b")));
    }

    fn plan_with_skipped(lock: &LockfileV3, loc: &str) -> IsolatedPlan {
        plan(
            lock,
            Omit {
                dev: false,
                optional: false,
                peer: false,
                skipped: [loc.to_string()].into_iter().collect(),
            },
            &HashMap::new(),
        )
    }
}
