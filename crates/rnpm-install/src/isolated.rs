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

#[inline(always)]
fn keccak_f(st: &mut [u64; 25]) {
    for &rc in &KECCAK_RC {
        let bc0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        let bc1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        let bc2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        let bc3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        let bc4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        let d0 = bc4 ^ bc1.rotate_left(1);
        let d1 = bc0 ^ bc2.rotate_left(1);
        let d2 = bc1 ^ bc3.rotate_left(1);
        let d3 = bc2 ^ bc4.rotate_left(1);
        let d4 = bc3 ^ bc0.rotate_left(1);

        st[0] ^= d0; st[5] ^= d0; st[10] ^= d0; st[15] ^= d0; st[20] ^= d0;
        st[1] ^= d1; st[6] ^= d1; st[11] ^= d1; st[16] ^= d1; st[21] ^= d1;
        st[2] ^= d2; st[7] ^= d2; st[12] ^= d2; st[17] ^= d2; st[22] ^= d2;
        st[3] ^= d3; st[8] ^= d3; st[13] ^= d3; st[18] ^= d3; st[23] ^= d3;
        st[4] ^= d4; st[9] ^= d4; st[14] ^= d4; st[19] ^= d4; st[24] ^= d4;

        let mut t = st[1];
        for i in 0..24 {
            let j = KECCAK_PILN[i];
            let tmp = st[j];
            st[j] = t.rotate_left(KECCAK_ROTC[i]);
            t = tmp;
        }

        for j in (0..25).step_by(5) {
            let s0 = st[j];
            let s1 = st[j + 1];
            let s2 = st[j + 2];
            let s3 = st[j + 3];
            let s4 = st[j + 4];
            st[j] = s0 ^ (!s1 & s2);
            st[j + 1] = s1 ^ (!s2 & s3);
            st[j + 2] = s2 ^ (!s3 & s4);
            st[j + 3] = s3 ^ (!s4 & s0);
            st[j + 4] = s4 ^ (!s0 & s1);
        }
        st[0] ^= rc;
    }
}

const RATE: usize = 136;

#[inline(always)]
fn absorb_block(st: &mut [u64; 25], block: &[u8]) {
    let (lanes, _) = block.as_chunks::<8>();
    for (i, lane) in lanes.iter().enumerate().take(17) {
        st[i] ^= u64::from_le_bytes(*lane);
    }
    keccak_f(st);
}

/// Streaming SHAKE256 hasher to avoid allocating intermediate strings when hashing entry lists.
#[derive(Clone)]
pub struct Shake256Stream {
    st: [u64; 25],
    buf: [u8; RATE],
    len: usize,
}

impl Shake256Stream {
    pub fn new() -> Self {
        Self {
            st: [0u64; 25],
            buf: [0u8; RATE],
            len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.len > 0 {
            let needed = RATE - self.len;
            if data.len() < needed {
                self.buf[self.len..self.len + data.len()].copy_from_slice(data);
                self.len += data.len();
                return;
            }
            self.buf[self.len..RATE].copy_from_slice(&data[..needed]);
            absorb_block(&mut self.st, &self.buf);
            self.len = 0;
            data = &data[needed..];
        }

        let (blocks, rest) = data.as_chunks::<RATE>();
        for block in blocks {
            absorb_block(&mut self.st, block);
        }
        self.buf[..rest.len()].copy_from_slice(rest);
        self.len = rest.len();
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let mut last = [0u8; RATE];
        last[..self.len].copy_from_slice(&self.buf[..self.len]);
        last[self.len] ^= 0x1f;
        last[RATE - 1] ^= 0x80;
        absorb_block(&mut self.st, &last);
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.st[0].to_le_bytes());
        out[8..].copy_from_slice(&self.st[1].to_le_bytes());
        out
    }
}

impl Default for Shake256Stream {
    fn default() -> Self {
        Self::new()
    }
}

/// SHAKE256 with a 16-byte output (`createHash('shake256', { outputLength: 16 })`).
pub fn shake256_16(data: &[u8]) -> [u8; 16] {
    let mut stream = Shake256Stream::new();
    stream.update(data);
    stream.finalize()
}

// ---------------------------------------------------------------------------
// The isolated graph.

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

fn package_name<'a>(loc: &'a str, pkg: &'a LockfilePackage) -> &'a str {
    if let Some(ref name) = pkg.name {
        name.as_str()
    } else if let Some((_, n)) = loc.rsplit_once("node_modules/") {
        n
    } else {
        loc.rsplit('/').next().unwrap_or(loc)
    }
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
        if self.deps.contains_key(&start) {
            return;
        }
        let mut queued: HashSet<Target> = HashSet::new();
        queued.insert(start.clone());
        let mut queue = vec![start];
        while let Some(node) = queue.pop() {
            if self.deps.contains_key(&node) {
                continue;
            }
            let deps = match &node {
                Target::External(loc) => self.edges(loc, false, false),
                Target::Local(loc) => self.edges(loc, true, loc.is_empty()),
            };
            // Pre-partition into arborist's `dependencies` order:
            // 1. external non-optional
            // 2. local non-optional
            // 3. optional
            // preserving relative order within each category.
            let mut partitioned = Vec::with_capacity(deps.len());
            for d in &deps {
                if !d.optional && matches!(d.target, Target::External(_)) {
                    partitioned.push(d.clone());
                }
            }
            for d in &deps {
                if !d.optional && matches!(d.target, Target::Local(_)) {
                    partitioned.push(d.clone());
                }
            }
            for d in &deps {
                if d.optional {
                    partitioned.push(d.clone());
                }
            }
            for d in &partitioned {
                if !self.deps.contains_key(&d.target) && queued.insert(d.target.clone()) {
                    queue.push(d.target.clone());
                }
            }
            self.deps.insert(node, partitioned);
        }
    }

    /// arborist's `dependencies` order: external non-optional, local
    /// non-optional, then optional.
    #[inline]
    fn children(&self, node: &Target) -> &[Dep] {
        self.deps.get(node).map(Vec::as_slice).unwrap_or(&[])
    }

    fn identity<'b>(&'b self, node: &'b Target) -> (&'b str, &'b str, &'b str) {
        match node {
            Target::External(loc) => {
                let pkg = &self.lock.packages[loc];
                (
                    package_name(loc, pkg),
                    pkg.version.as_deref().unwrap_or("undefined"),
                    pkg.resolved.as_deref().unwrap_or("undefined"),
                )
            }
            Target::Local(loc) => {
                let pkg = self.lock.packages.get(loc);
                let name = pkg
                    .and_then(|p| p.name.as_deref())
                    .unwrap_or_else(|| loc.rsplit('/').next().unwrap_or(loc));
                // A workspace proxy carries no version, and its node no resolved.
                (name, "undefined", "null")
            }
        }
    }

    /// arborist's getKey: a depth-first walk (each node visited once)
    /// recording `a@1->b@2::resolved`, sorted, hashed with SHAKE256.
    #[allow(dead_code)]
    pub fn key(&self, start: &Target) -> String {
        let mut nodes: Vec<Target> = self.deps.keys().cloned().collect();
        nodes.sort_unstable();
        let target_to_idx: HashMap<&Target, usize> =
            nodes.iter().enumerate().map(|(i, t)| (t, i)).collect();
        let mut computer = KeyComputer::new(self, &nodes, &target_to_idx);
        if let Some(&idx) = target_to_idx.get(start) {
            computer.compute_key(idx)
        } else {
            let (name, version, resolved) = self.identity(start);
            let entry = format!("{name}@{version}::{resolved}");
            let digest = shake256_16(entry.as_bytes());
            let hash = data_encoding::BASE64URL_NOPAD.encode(&digest);
            format!("{name}@{version}-{hash}")
        }
    }
}

struct NodeData<'a> {
    name: &'a str,
    version: &'a str,
    resolved: &'a str,
    pkg_id: String,
    children: Vec<usize>,
}

struct KeyComputer<'a> {
    node_data: Vec<NodeData<'a>>,
    seen_epoch: Vec<u32>,
    epoch: u32,
    branch_buf: String,
    entries: Vec<String>,
}

impl<'a> KeyComputer<'a> {
    fn new(
        builder: &'a Builder<'a>,
        nodes: &'a [Target],
        target_to_idx: &HashMap<&Target, usize>,
    ) -> Self {
        let mut node_data = Vec::with_capacity(nodes.len());
        for target in nodes {
            let (name, version, resolved) = builder.identity(target);
            let pkg_id = format!("{name}@{version}");
            let children: Vec<usize> = builder
                .children(target)
                .iter()
                .filter_map(|dep| target_to_idx.get(&dep.target).copied())
                .collect();
            node_data.push(NodeData {
                name,
                version,
                resolved,
                pkg_id,
                children,
            });
        }
        let num_nodes = nodes.len();
        Self {
            node_data,
            seen_epoch: vec![0; num_nodes],
            epoch: 0,
            branch_buf: String::with_capacity(256),
            entries: Vec::with_capacity(num_nodes),
        }
    }

    fn compute_key(&mut self, start_idx: usize) -> String {
        let node = &self.node_data[start_idx];
        if node.children.is_empty() {
            let mut entry = String::with_capacity(node.pkg_id.len() + 2 + node.resolved.len());
            entry.push_str(&node.pkg_id);
            entry.push_str("::");
            entry.push_str(node.resolved);
            let digest = shake256_16(entry.as_bytes());
            let hash = data_encoding::BASE64URL_NOPAD.encode(&digest);
            return format!("{}@{}-{}", node.name, node.version, hash);
        }

        self.epoch += 1;
        let current_epoch = self.epoch;
        self.entries.clear();
        self.branch_buf.clear();

        self.seen_epoch[start_idx] = current_epoch;
        self.dfs(start_idx, current_epoch);

        self.entries.sort_unstable();

        let mut hasher = Shake256Stream::new();
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                hasher.update(b",");
            }
            hasher.update(entry.as_bytes());
        }
        let digest = hasher.finalize();
        let hash = data_encoding::BASE64URL_NOPAD.encode(&digest);
        let node = &self.node_data[start_idx];
        format!("{}@{}-{}", node.name, node.version, hash)
    }

    fn dfs(&mut self, node_idx: usize, current_epoch: u32) {
        let prev_len = self.branch_buf.len();
        let node = &self.node_data[node_idx];
        if !self.branch_buf.is_empty() {
            self.branch_buf.push_str("->");
        }
        self.branch_buf.push_str(&node.pkg_id);

        let mut entry = String::with_capacity(self.branch_buf.len() + 2 + node.resolved.len());
        entry.push_str(&self.branch_buf);
        entry.push_str("::");
        entry.push_str(node.resolved);
        self.entries.push(entry);

        let num_children = self.node_data[node_idx].children.len();
        for c_i in 0..num_children {
            let child_idx = self.node_data[node_idx].children[c_i];
            if self.seen_epoch[child_idx] != current_epoch {
                self.seen_epoch[child_idx] = current_epoch;
                self.dfs(child_idx, current_epoch);
            }
        }

        self.branch_buf.truncate(prev_len);
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

    let mut nodes: Vec<Target> = builder.deps.keys().cloned().collect();
    // Zero-allocation comparator preserving exact Debug ordering
    nodes.sort_unstable();

    let target_to_idx: HashMap<&Target, usize> =
        nodes.iter().enumerate().map(|(i, t)| (t, i)).collect();
    let mut key_computer = KeyComputer::new(&builder, &nodes, &target_to_idx);

    let mut keys: HashMap<Target, String> = HashMap::with_capacity(nodes.len());
    for (idx, node) in nodes.iter().enumerate() {
        if let Target::External(_) = node {
            keys.insert(node.clone(), key_computer.compute_key(idx));
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
            bin: bin_entries(pkg, name),
            package_name: name.to_string(),
            resolved: pkg.resolved.clone(),
            integrity: pkg.integrity.clone(),
            optional: pkg.optional == Some(true),
            hoisted: loc.clone(),
        });
    }

    let target_location = |t: &Target| match t {
        Target::External(loc) => {
            let key = &keys[t];
            let pkg = &lock.packages[loc];
            let name = package_name(loc, pkg);
            format!("node_modules/.store/{key}/node_modules/{name}")
        }
        Target::Local(loc) => loc.clone(),
    };

    // Links: from the root, each workspace, and each store package.
    let mut links: BTreeMap<String, PlannedLink> = BTreeMap::new();
    let mut add_links_from = |node: &Target, nm: &str| {
        for dep in builder.children(node) {
            let location = join(nm, &dep.name);
            let target = target_location(&dep.target);
            if location != target {
                links.insert(location.clone(), PlannedLink { location, target });
            }
        }
    };

    add_links_from(&Target::Local(String::new()), "node_modules");
    for dir in &local_dirs {
        add_links_from(&Target::Local(dir.clone()), &format!("{dir}/node_modules"));
    }
    for node in &nodes {
        if let Target::External(_) = node {
            let key = &keys[node];
            add_links_from(node, &format!("node_modules/.store/{key}/node_modules"));
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
    if !target.exists() {
        anyhow::bail!(
            "Cannot link '{}' to nonexistent target '{}'",
            link.display(),
            target.display()
        );
    }
    if rnpm_fs::junction::junction_points_to(link, target) {
        return Ok(());
    }
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::linked::create_or_replace_junction(link, target)
}

/// Atomically unpacks a store package tarball into `dest`.
///
/// Extracts into a unique temporary sibling directory first, verifies that extraction
/// succeeded (producing a valid `package.json`), and then atomically renames the staging
/// directory into `dest`. On failure, the temporary directory is cleaned up immediately,
/// leaving zero partial or stray files inside `node_modules/.store/...`.
pub fn unpack_store_package(
    dest: &Path,
    tarball_bytes: &[u8],
    writer_cfg: Option<&rnpm_fs::ParallelWriterConfig>,
) -> Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| anyhow!("Invalid destination path '{}'", dest.display()))?;
    std::fs::create_dir_all(parent)?;

    let pkg_name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("pkg");
    let staging_temp = tempfile::Builder::new()
        .prefix(&format!(".{pkg_name}.tmp-"))
        .tempdir_in(parent)?;
    let staging_path = staging_temp.path();

    if let Err(e) = rnpm_fs::extract_tarball_direct(
        std::io::Cursor::new(tarball_bytes),
        staging_path,
        None,
        writer_cfg,
    ) {
        let _ = staging_temp.close();
        return Err(anyhow!("Failed to extract tarball: {e}"));
    }

    if !staging_path.join("package.json").is_file() {
        let _ = staging_temp.close();
        return Err(anyhow!(
            "Extraction produced incomplete package (missing package.json)"
        ));
    }

    if dest.join("package.json").is_file() {
        // Concurrently completed by another worker
        let _ = staging_temp.close();
        return Ok(());
    }

    if let Err(e) = rnpm_fs::replace_dir_with_retries(staging_path, dest, 10) {
        if dest.join("package.json").is_file() {
            let _ = staging_temp.close();
            return Ok(());
        }
        let _ = staging_temp.close();
        return Err(anyhow!(
            "Failed to atomically place store package into '{}': {e}",
            dest.display()
        ));
    }

    let _ = staging_temp.keep();
    Ok(())
}

/// Tarball bytes for a store package: the cache first, then the registry.
async fn fetch_tarball_parts(
    cache: &rnpm_cache::Cache,
    registry_client: &rnpm_registry::client::RegistryClient,
    offline: bool,
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
        if let Ok(Some(data)) = cache.get_by_integrity(exp) {
            return Ok(data);
        }
    }
    if let Ok(Some((_, data))) = cache.get(resolved) {
        if expected.as_ref().is_none_or(|e| e.verify(&data).is_ok()) {
            return Ok(data);
        }
    }
    if offline {
        return Err(anyhow!(
            "npm error code ENOTCACHED\nnpm error request to {resolved} failed: cache mode is 'only-if-cached' but no cached response is available."
        ));
    }
    let data = registry_client
        .download_tarball_bytes(resolved)
        .await
        .map_err(|e| anyhow!("Failed to download tarball from {resolved}: {e}"))?;
    if let Some(exp) = &expected {
        exp.verify(&data)
            .map_err(|e| anyhow!("Integrity verification failed for {location}: {e}"))?;
    }
    let _ = cache.put_with_integrity(resolved, &data, expected.as_ref(), None);
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
        if !self.options.force {
            crate::policy::check_engines(
                lock,
                &project,
                self.engine_strict,
                self.options.silent,
                &self.options.platform(),
            )?;
        }
        let mut manifests: HashMap<String, Value> = HashMap::new();
        let mut tarballs: HashMap<String, Vec<u8>> = HashMap::new();
        let mut to_fetch: Vec<(String, LockfilePackage)> = Vec::new();
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
            to_fetch.push((loc.clone(), pkg.clone()));
        }

        if !to_fetch.is_empty() {
            let sem = std::sync::Arc::clone(&self.io_semaphore);
            let cache = self.cache().clone();
            let registry_client = self.registry_client().clone();
            let offline = self.options.offline;
            let mut join_set = tokio::task::JoinSet::new();

            for (loc, pkg) in to_fetch {
                let sem = std::sync::Arc::clone(&sem);
                let cache = cache.clone();
                let registry_client = registry_client.clone();
                let proj = project.clone();
                join_set.spawn(async move {
                    let _permit = sem.acquire().await.map_err(|e| anyhow!("{e}"))?;
                    let bytes = match fetch_tarball_parts(
                        &cache,
                        &registry_client,
                        offline,
                        &proj,
                        &loc,
                        &pkg,
                    )
                    .await
                    {
                        Ok(bytes) => bytes,
                        Err(_) if pkg.optional == Some(true) => return Ok::<_, anyhow::Error>(None),
                        Err(e) => return Err(e),
                    };
                    let manifest_val = rnpm_fs::read_tarball_text(&bytes, "package.json")
                        .and_then(|t| serde_json::from_str::<Value>(&t).ok());
                    Ok(Some((loc, bytes, manifest_val)))
                });
            }

            while let Some(res) = join_set.join_next().await {
                if let Some((loc, bytes, manifest_val)) =
                    res.map_err(|e| anyhow!("Isolated tarball fetch worker panicked: {e}"))??
                {
                    if let Some(value) = manifest_val {
                        manifests.insert(loc.clone(), value);
                    }
                    tarballs.insert(loc, bytes);
                }
            }
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
        if !self.options.is_global
            && (rnpm_fs::junction::is_junction(&nm).unwrap_or(false)
                || std::fs::symlink_metadata(&nm).is_ok_and(|m| m.file_type().is_symlink()))
        {
            rnpm_fs::junction::remove_junction(&nm)?;
        }
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
                let _ = rnpm_fs::remove_dir_all_safe(path);
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

        // Unpack the store in parallel.
        let writer_cfg = std::sync::Arc::new(rnpm_fs::determine_writer_config(&project, None));
        let mut added = 0usize;
        let mut lifecycle_nodes = Vec::new();
        {
            let sem = std::sync::Arc::clone(&self.io_semaphore);
            let cache = self.cache().clone();
            let registry_client = self.registry_client().clone();
            let offline = self.options.offline;
            let mut join_set = tokio::task::JoinSet::new();

            for entry in &plan.store {
                let pkg = lock.packages[&entry.hoisted].clone();
                let preloaded_bytes = tarballs.remove(&entry.hoisted);
                let dest = project.join(&entry.location);
                let entry_hoisted = entry.hoisted.clone();
                let entry_optional = entry.optional;
                let sem = std::sync::Arc::clone(&sem);
                let cache = cache.clone();
                let registry_client = registry_client.clone();
                let writer_cfg = std::sync::Arc::clone(&writer_cfg);
                let proj = project.clone();

                join_set.spawn(async move {
                    let _permit = sem.acquire().await.map_err(|e| anyhow!("{e}"))?;
                    let mut was_added = false;
                    if !dest.join("package.json").is_file() {
                        let bytes = match preloaded_bytes {
                            Some(b) => b,
                            None => match fetch_tarball_parts(
                                &cache,
                                &registry_client,
                                offline,
                                &proj,
                                &entry_hoisted,
                                &pkg,
                            )
                            .await
                            {
                                Ok(b) => b,
                                Err(_) if entry_optional => return Ok::<_, anyhow::Error>(None),
                                Err(e) => return Err(e),
                            },
                        };
                        let dest_clone = dest.clone();
                        let cfg_clone = std::sync::Arc::clone(&writer_cfg);
                        let unpack_res = tokio::task::spawn_blocking(move || {
                            unpack_store_package(&dest_clone, &bytes, Some(&cfg_clone))
                        })
                        .await
                        .map_err(|e| anyhow!("Isolated store unpack panicked: {e}"))?;
                        match unpack_res {
                            Ok(()) => {
                                was_added = true;
                            }
                            Err(e) if entry_optional => {
                                tracing::warn!(
                                    "Failed to extract optional store package {}: {e}; skipping",
                                    entry_hoisted
                                );
                                return Ok(None);
                            }
                            Err(e) => return Err(anyhow!("Failed to extract {}: {e}", entry_hoisted)),
                        }
                    }

                    let lifecycle_node = if pkg.has_install_script == Some(true) {
                        rnpm_core::manifest::Manifest::from_file(dest.join("package.json"))
                            .ok()
                            .map(|manifest| rnpm_lifecycle::LifecyclePackageNode {
                                // Use the original hoisted lockfile key so `policy::apply_script_policy`
                                // finds the lockfile entry (URL/Git/registry rules) while keeping
                                // `disk_path` pointed at the isolated `.store` directory for execution.
                                package_path: entry_hoisted.clone(),
                                disk_path: dest,
                                manifest,
                                source: rnpm_lifecycle::PackageSource::Registry,
                                dependencies: pkg
                                    .dependencies
                                    .as_ref()
                                    .map(|d| d.keys().cloned().collect())
                                    .unwrap_or_default(),
                                optional: entry_optional,
                            })
                    } else {
                        None
                    };

                    Ok(Some((was_added, lifecycle_node)))
                });
            }

            while let Some(res) = join_set.join_next().await {
                if let Some((was_added, node_opt)) =
                    res.map_err(|e| anyhow!("Isolated store unpack task panicked: {e}"))??
                {
                    if was_added {
                        added += 1;
                    }
                    if let Some(node) = node_opt {
                        lifecycle_nodes.push(node);
                    }
                }
            }
        }

        // Link every edge with parent directory deduplication.
        let mut created_parents: HashSet<std::path::PathBuf> = HashSet::new();
        for link in &plan.links {
            let target = project.join(&link.target);
            if !target.exists() {
                continue;
            }
            let link_path = project.join(&link.location);
            if rnpm_fs::junction::junction_points_to(&link_path, &target) {
                continue;
            }
            if let Some(parent) = link_path.parent() {
                if created_parents.insert(parent.to_path_buf()) {
                    std::fs::create_dir_all(parent)?;
                }
            }
            crate::linked::create_or_replace_junction(&link_path, &target)?;
        }

        // Bins go in the `.bin` beside each package and each link.
        if self.options.bin_links {
            let local_bins: Vec<Vec<(String, String)>> = plan
                .local_dirs
                .iter()
                .map(|d| {
                    lock.packages
                        .get(d)
                        .map(|p| bin_entries(p, p.name.as_deref().unwrap_or(d)))
                        .unwrap_or_default()
                })
                .collect();
            let mut bins_of: HashMap<&str, &[(String, String)]> =
                HashMap::with_capacity(plan.store.len() + plan.local_dirs.len());
            for e in &plan.store {
                bins_of.insert(e.location.as_str(), &e.bin);
            }
            for (i, d) in plan.local_dirs.iter().enumerate() {
                bins_of.insert(d.as_str(), &local_bins[i]);
            }
            let placed = plan
                .store
                .iter()
                .map(|e| (e.location.as_str(), e.location.as_str()))
                .chain(plan.links.iter().map(|l| (l.location.as_str(), l.target.as_str())));
            for (location, target) in placed {
                let Some(bins) = bins_of.get(target).copied().filter(|b| !b.is_empty()) else {
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
                    let _ = rnpm_shim::normalize_shebang(&project.join(target).join(script));
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
            let lifecycle_nodes = crate::policy::apply_script_policy(
                lifecycle_nodes,
                lock,
                &project,
                &self.script_policy,
            )?;
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

    #[test]
    fn test_ensure_link_fails_hard_on_invalid_target() {
        let temp = tempfile::tempdir().unwrap();
        let link = temp.path().join("link_dir");
        let non_existent_target = temp.path().join("non_existent_target_dir");

        let res = ensure_link(&link, &non_existent_target);
        assert!(res.is_err(), "ensure_link must return Err when link creation fails");
        assert!(!link.exists(), "ensure_link must not silently copy or leave a directory");
    }

    #[test]
    fn test_unpack_store_package_atomic_staging_cleanup_on_error() {
        let temp = tempfile::tempdir().unwrap();
        let dest = temp.path().join("node_modules/.store/test-pkg@1.0.0/node_modules/test-pkg");

        // Corrupted / truncated tarball bytes
        let corrupt_bytes = b"not a valid tarball";
        let res = unpack_store_package(&dest, corrupt_bytes, None);
        assert!(res.is_err(), "corrupt tarball unpack must fail");
        assert!(!dest.exists(), "dest must not exist on failed extraction");

        // Verify no stray temporary directories or files in parent
        if let Some(parent) = dest.parent() {
            if parent.exists() {
                let entries: Vec<_> = std::fs::read_dir(parent).unwrap().flatten().collect();
                assert!(entries.is_empty(), "parent must have zero stray files or tempdirs on error");
            }
        }
    }

    #[test]
    fn test_unpack_store_package_success_leaves_no_stray_files() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use tar::Builder;

        let temp = tempfile::tempdir().unwrap();
        let dest = temp.path().join("node_modules/.store/my-pkg@1.0.0/node_modules/my-pkg");

        // Create valid npm tarball with "package/package.json"
        let enc = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = Builder::new(enc);
        let pkg_json = br#"{"name":"my-pkg","version":"1.0.0"}"#;
        let mut header = tar::Header::new_gnu();
        header.set_size(pkg_json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "package/package.json", &pkg_json[..]).unwrap();
        let tar_bytes = tar.into_inner().unwrap().finish().unwrap();

        let res = unpack_store_package(&dest, &tar_bytes, None);
        assert!(res.is_ok(), "unpacking valid package must succeed: {:?}", res.err());
        assert!(dest.join("package.json").is_file(), "package.json must exist in dest");

        // Check parent directory contains ONLY dest and zero stray files or temp dirs
        let parent = dest.parent().unwrap();
        let entries: Vec<_> = std::fs::read_dir(parent)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries, vec!["my-pkg".to_string()], "parent must contain ONLY dest with zero stray temp files");
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

    #[test]
    fn test_target_sort_matches_format_debug() {
        let mut targets = vec![
            Target::Local("".to_string()),
            Target::External("node_modules/z".to_string()),
            Target::External("node_modules/a".to_string()),
            Target::External("node_modules/@scope/pkg".to_string()),
            Target::Local("packages/nested".to_string()),
            Target::Local("packages/app".to_string()),
            Target::External("node_modules/b".to_string()),
        ];
        let mut debug_sorted = targets.clone();
        debug_sorted.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));

        targets.sort_unstable();
        assert_eq!(
            targets, debug_sorted,
            "Derived Ord on Target must match format debug order 100%"
        );
    }

    #[test]
    fn test_diamond_graph_deterministic_store_keys_and_layout() {
        let lock_json = r#"{
            "name": "diamond-root",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "diamond-root", "dependencies": { "a": "1.0.0" } },
                "node_modules/a": {
                    "version": "1.0.0",
                    "resolved": "https://r/a.tgz",
                    "dependencies": { "b": "1.0.0", "c": "1.0.0" }
                },
                "node_modules/b": {
                    "version": "1.0.0",
                    "resolved": "https://r/b.tgz",
                    "dependencies": { "d": "1.0.0" }
                },
                "node_modules/c": {
                    "version": "1.0.0",
                    "resolved": "https://r/c.tgz",
                    "dependencies": { "d": "1.0.0" }
                },
                "node_modules/d": {
                    "version": "1.0.0",
                    "resolved": "https://r/d.tgz",
                    "dependencies": { "e": "1.0.0" }
                },
                "node_modules/e": {
                    "version": "1.0.0",
                    "resolved": "https://r/e.tgz"
                }
            }
        }"#;
        let lock = LockfileV3::from_json_str(lock_json).unwrap();
        let plan1 = plan(
            &lock,
            Omit {
                dev: false,
                optional: false,
                peer: false,
                skipped: HashSet::new(),
            },
            &HashMap::new(),
        );
        let plan2 = plan(
            &lock,
            Omit {
                dev: false,
                optional: false,
                peer: false,
                skipped: HashSet::new(),
            },
            &HashMap::new(),
        );

        // Verify determinism across multiple runs
        assert_eq!(plan1.store.len(), 5);
        for (s1, s2) in plan1.store.iter().zip(plan2.store.iter()) {
            assert_eq!(s1.location, s2.location);
            assert_eq!(s1.store_dir, s2.store_dir);
        }
        assert_eq!(plan1.links.len(), plan2.links.len());
        for (l1, l2) in plan1.links.iter().zip(plan2.links.iter()) {
            assert_eq!(l1.location, l2.location);
            assert_eq!(l1.target, l2.target);
        }

        // Verify diamond structure
        let a = plan1.store.iter().find(|e| e.package_name == "a").unwrap();
        let b = plan1.store.iter().find(|e| e.package_name == "b").unwrap();
        let c = plan1.store.iter().find(|e| e.package_name == "c").unwrap();
        let d = plan1.store.iter().find(|e| e.package_name == "d").unwrap();
        let e = plan1.store.iter().find(|e| e.package_name == "e").unwrap();

        let link = |loc: &str| {
            plan1
                .links
                .iter()
                .find(|l| l.location == loc)
                .map(|l| l.target.as_str())
        };
        assert_eq!(link("node_modules/a"), Some(a.location.as_str()));
        assert_eq!(
            link(&format!("{}/node_modules/b", a.store_dir)),
            Some(b.location.as_str())
        );
        assert_eq!(
            link(&format!("{}/node_modules/c", a.store_dir)),
            Some(c.location.as_str())
        );
        assert_eq!(
            link(&format!("{}/node_modules/d", b.store_dir)),
            Some(d.location.as_str())
        );
        assert_eq!(
            link(&format!("{}/node_modules/d", c.store_dir)),
            Some(d.location.as_str())
        );
        assert_eq!(
            link(&format!("{}/node_modules/e", d.store_dir)),
            Some(e.location.as_str())
        );
    }

    #[test]
    fn test_cyclic_graph_deterministic_store_keys_and_layout() {
        let lock_json = r#"{
            "name": "cyclic-root",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "cyclic-root", "dependencies": { "a": "1.0.0" } },
                "node_modules/a": {
                    "version": "1.0.0",
                    "resolved": "https://r/a.tgz",
                    "dependencies": { "b": "1.0.0" }
                },
                "node_modules/b": {
                    "version": "1.0.0",
                    "resolved": "https://r/b.tgz",
                    "dependencies": { "c": "1.0.0" }
                },
                "node_modules/c": {
                    "version": "1.0.0",
                    "resolved": "https://r/c.tgz",
                    "dependencies": { "a": "1.0.0" }
                }
            }
        }"#;
        let lock = LockfileV3::from_json_str(lock_json).unwrap();
        let plan1 = plan(
            &lock,
            Omit {
                dev: false,
                optional: false,
                peer: false,
                skipped: HashSet::new(),
            },
            &HashMap::new(),
        );
        let plan2 = plan(
            &lock,
            Omit {
                dev: false,
                optional: false,
                peer: false,
                skipped: HashSet::new(),
            },
            &HashMap::new(),
        );

        assert_eq!(plan1.store.len(), 3);
        assert_eq!(plan1.links.len(), 4); // root -> a, a -> b, b -> c, c -> a
        for (s1, s2) in plan1.store.iter().zip(plan2.store.iter()) {
            assert_eq!(s1.location, s2.location);
            assert_eq!(s1.store_dir, s2.store_dir);
        }
        for (l1, l2) in plan1.links.iter().zip(plan2.links.iter()) {
            assert_eq!(l1.location, l2.location);
            assert_eq!(l1.target, l2.target);
        }

        let a = plan1.store.iter().find(|e| e.package_name == "a").unwrap();
        let b = plan1.store.iter().find(|e| e.package_name == "b").unwrap();
        let c = plan1.store.iter().find(|e| e.package_name == "c").unwrap();

        let link = |loc: &str| {
            plan1
                .links
                .iter()
                .find(|l| l.location == loc)
                .map(|l| l.target.as_str())
        };
        assert_eq!(link("node_modules/a"), Some(a.location.as_str()));
        assert_eq!(
            link(&format!("{}/node_modules/b", a.store_dir)),
            Some(b.location.as_str())
        );
        assert_eq!(
            link(&format!("{}/node_modules/c", b.store_dir)),
            Some(c.location.as_str())
        );
        assert_eq!(
            link(&format!("{}/node_modules/a", c.store_dir)),
            Some(a.location.as_str())
        );
    }

    #[test]
    fn test_200_node_diamond_graph_builds_fast() {
        let mut packages = serde_json::Map::new();
        packages.insert(
            "".to_string(),
            serde_json::json!({
                "name": "diamond-root",
                "dependencies": {
                    "layer_0_a": "1.0.0",
                    "layer_0_b": "1.0.0"
                }
            }),
        );

        // 100 layers of 2 nodes = 200 nodes total, plus 2 leaf nodes at layer 100 = 202 nodes.
        // Unpruned paths from top to bottom = 2^100!
        for i in 0..100 {
            let next_a = format!("layer_{}_a", i + 1);
            let next_b = format!("layer_{}_b", i + 1);
            for suffix in ["a", "b"] {
                let name = format!("layer_{i}_{suffix}");
                packages.insert(
                    format!("node_modules/{name}"),
                    serde_json::json!({
                        "version": "1.0.0",
                        "resolved": format!("https://r/{name}.tgz"),
                        "dependencies": {
                            next_a.clone(): "1.0.0",
                            next_b.clone(): "1.0.0"
                        }
                    }),
                );
            }
        }
        for suffix in ["a", "b"] {
            let name = format!("layer_100_{suffix}");
            packages.insert(
                format!("node_modules/{name}"),
                serde_json::json!({
                    "version": "1.0.0",
                    "resolved": format!("https://r/{name}.tgz")
                }),
            );
        }

        let lock_val = serde_json::json!({
            "name": "diamond-root",
            "lockfileVersion": 3,
            "requires": true,
            "packages": packages
        });
        let lock: LockfileV3 = serde_json::from_value(lock_val).unwrap();

        let start = std::time::Instant::now();
        let plan = plan(
            &lock,
            Omit {
                dev: false,
                optional: false,
                peer: false,
                skipped: HashSet::new(),
            },
            &HashMap::new(),
        );
        let elapsed = start.elapsed();

        assert_eq!(plan.store.len(), 202);
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "200-node diamond graph must build fast without exponential blowup, took {elapsed:?}"
        );
    }
}
