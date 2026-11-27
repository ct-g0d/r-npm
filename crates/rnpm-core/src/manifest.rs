use crate::error::ManifestError;
use crate::PlatformList;
use serde::{
    de::{self, Deserializer, MapAccess, SeqAccess, Visitor},
    Deserialize, Serialize,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub fn deserialize_opt_vec_or_string<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<PlatformList>::deserialize(deserializer).map(|list| list.map(PlatformList::into_vec))
}

fn parse_engine_entry_str(entry: &str) -> Option<(&str, &str)> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(idx) = trimmed.find(|c: char| c.is_whitespace() || c == '@') {
        let name = trimmed[..idx].trim();
        let range = trimmed[idx + 1..].trim();
        if !name.is_empty() && !range.is_empty() {
            return Some((name, range));
        }
    }
    if let Some(idx) = trimmed.find(['>', '<', '=', '~', '^']) {
        let name = trimmed[..idx].trim();
        let range = trimmed[idx..].trim();
        if !name.is_empty() && !range.is_empty() {
            return Some((name, range));
        }
    }
    None
}

fn parse_engine_entries_from_str(s: &str) -> Vec<(&str, &str)> {
    let mut res = Vec::new();
    if s.contains(',') {
        for part in s.split(',') {
            if let Some(pair) = parse_engine_entry_str(part) {
                res.push(pair);
            }
        }
    } else if let Some(pair) = parse_engine_entry_str(s) {
        res.push(pair);
    }
    res
}

struct EngineValue(Option<String>);

impl<'de> Deserialize<'de> for EngineValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EngineValVisitor;
        impl<'de> Visitor<'de> for EngineValVisitor {
            type Value = EngineValue;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a json value")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(EngineValue(Some(v.to_string())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(EngineValue(Some(v)))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(EngineValue(Some(if v { "true" } else { "false" }.to_string())))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(EngineValue(Some(v.to_string())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(EngineValue(Some(v.to_string())))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                let s = serde_json::Number::from_f64(v)
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| v.to_string());
                Ok(EngineValue(Some(s)))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(EngineValue(None))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(EngineValue(None))
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                while seq.next_element::<de::IgnoredAny>()?.is_some() {}
                Ok(EngineValue(None))
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                while map.next_entry::<de::IgnoredAny, de::IgnoredAny>()?.is_some() {}
                Ok(EngineValue(None))
            }
        }
        deserializer.deserialize_any(EngineValVisitor)
    }
}

pub fn deserialize_engines<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct EnginesVisitor;

    impl<'de> Visitor<'de> for EnginesVisitor {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a map, list, or string of engines")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut map = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, EngineValue>()? {
                if let Some(s) = value.0 {
                    map.insert(key, s);
                }
            }
            Ok(map)
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: SeqAccess<'de>,
        {
            let mut map = BTreeMap::new();
            while let Some(elem) = seq.next_element::<serde_json::Value>()? {
                if let Some(s) = elem.as_str() {
                    if let Some((name, range)) = parse_engine_entry_str(s) {
                        map.insert(name.to_string(), range.to_string());
                    }
                }
            }
            Ok(map)
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let mut map = BTreeMap::new();
            for (name, range) in parse_engine_entries_from_str(s) {
                map.insert(name.to_string(), range.to_string());
            }
            Ok(map)
        }

        fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&s)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(BTreeMap::new())
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(BTreeMap::new())
        }
    }

    deserializer.deserialize_any(EnginesVisitor)
}

/// Sanitizes a bin key according to npm-normalize-package-bin:
/// Replaces `\` and `:` with `/`, extracts basename (after last `/`),
/// and normalizes relative to root: path.join('/', basename).slice(1).
/// Drops empty, ".", "..", and root paths.
pub fn clean_bin_key(key: &str) -> String {
    let unixified = key.replace(['\\', ':'], "/");
    let base = match unixified.rfind('/') {
        Some(idx) => &unixified[idx + 1..],
        None => &unixified,
    };
    let mut segments = Vec::new();
    for seg in base.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    segments.join("/")
}

/// Sanitizes a bin target script path according to npm-normalize-package-bin:
/// Replaces `\` with `/`, normalizes relative to root (preventing path traversal `..`),
/// and strips leading `/`. Preserves leading `./` if originally relative.
pub fn clean_bin_target(target: &str) -> String {
    let unixified = target.replace('\\', "/");
    let had_dot_slash = unixified.starts_with("./");
    let mut segments = Vec::new();
    for seg in unixified.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    if segments.is_empty() {
        String::new()
    } else {
        let joined = segments.join("/");
        if had_dot_slash {
            format!("./{joined}")
        } else {
            joined
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum PackageBin {
    Single(String),
    Map(BTreeMap<String, String>),
}

impl<'de> Deserialize<'de> for PackageBin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PackageBinVisitor;

        impl<'de> Visitor<'de> for PackageBinVisitor {
            type Value = PackageBin;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string, an array of strings, or a map of strings")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(PackageBin::Single(v.to_string()))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(PackageBin::Single(v))
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let mut map = BTreeMap::new();
                while let Some(elem) = seq.next_element::<String>()? {
                    let key = clean_bin_key(&elem);
                    if !key.is_empty() {
                        map.insert(key, elem);
                    }
                }
                Ok(PackageBin::Map(map))
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = BTreeMap::new();
                while let Some((k, v)) = access.next_entry::<String, String>()? {
                    map.insert(k, v);
                }
                Ok(PackageBin::Map(map))
            }
        }

        deserializer.deserialize_any(PackageBinVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum BundledDependencies {
    Boolean(bool),
    List(Vec<String>),
}

impl<'de> Deserialize<'de> for BundledDependencies {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BundledVisitor;

        impl<'de> Visitor<'de> for BundledVisitor {
            type Value = BundledDependencies;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a boolean, a list of package names, or a map")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(BundledDependencies::Boolean(v))
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let mut list = Vec::new();
                while let Some(elem) = seq.next_element::<String>()? {
                    list.push(elem);
                }
                Ok(BundledDependencies::List(list))
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut list = access.size_hint().map_or_else(Vec::new, Vec::with_capacity);
                while let Some((k, _)) = access.next_entry::<String, de::IgnoredAny>()? {
                    list.push(k);
                }
                Ok(BundledDependencies::List(list))
            }
        }

        deserializer.deserialize_any(BundledVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PackageWorkspaces {
    List(Vec<String>),
    Config { packages: Vec<String> },
}

/// Formatting metadata detected from raw package.json content to preserve
/// exact indentation (spaces or tabs), newline style (CRLF or LF), trailing newline, and UTF-8 BOM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFormat {
    pub indent: String,
    pub newline: String,
    pub trailing_newline: bool,
    pub has_bom: bool,
}

impl Default for ManifestFormat {
    fn default() -> Self {
        Self {
            indent: "  ".to_string(),
            newline: "\n".to_string(),
            trailing_newline: true,
            has_bom: false,
        }
    }
}

impl ManifestFormat {
    pub fn detect(raw: &str) -> Self {
        let clean = raw.strip_prefix('\u{feff}').unwrap_or(raw);
        let has_bom = clean.len() != raw.len();
        let bytes = clean.as_bytes();
        let trailing_newline = bytes.last().is_some_and(|&b| b == b'\n' || b == b'\r');

        // Trim leading and trailing ASCII whitespace
        let mut start = 0usize;
        while start < bytes.len() && bytes[start].is_ascii_whitespace() {
            start += 1;
        }
        let mut end = bytes.len();
        while end > start && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        let trimmed_bytes = &bytes[start..end];

        let (indent, newline) = if let Some(nl_rel) = trimmed_bytes.iter().position(|&b| b == b'\n')
        {
            let nl = if nl_rel > 0 && trimmed_bytes[nl_rel - 1] == b'\r' {
                "\r\n".to_string()
            } else {
                "\n".to_string()
            };

            let ind = if matches!(trimmed_bytes.first(), Some(b'{' | b'[')) {
                let rest = &trimmed_bytes[nl_rel + 1..];
                let mut ws_len = 0usize;
                while ws_len < rest.len() && (rest[ws_len] == b' ' || rest[ws_len] == b'\t') {
                    ws_len += 1;
                }
                if ws_len == 0 {
                    "  ".to_string()
                } else {
                    clean[start + nl_rel + 1..start + nl_rel + 1 + ws_len].to_string()
                }
            } else {
                "  ".to_string()
            };
            (ind, nl)
        } else {
            (String::new(), String::new())
        };

        Self {
            indent,
            newline,
            trailing_newline,
            has_bom,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PeerDependencyMeta {
    #[serde(default)]
    pub optional: bool,
}

pub fn deserialize_opt_string_or_bool<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OptStringOrBoolVisitor;

    impl<'de> Visitor<'de> for OptStringOrBoolVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string, boolean, or null")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value.to_string()))
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value))
        }

        fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
        where
            D2: Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }
    }

    deserializer.deserialize_any(OptStringOrBoolVisitor)
}

pub type OrderedDeps = (BTreeMap<String, String>, Vec<String>);

pub fn deserialize_ordered_deps<'de, D>(
    deserializer: D,
) -> Result<OrderedDeps, D::Error>
where
    D: Deserializer<'de>,
{
    struct OrderedDepsVisitor;

    impl<'de> Visitor<'de> for OrderedDepsVisitor {
        type Value = OrderedDeps;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a map of dependencies or null")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut map = BTreeMap::new();
            let mut order = Vec::with_capacity(access.size_hint().unwrap_or(8));
            while let Some((k, v)) = access.next_entry::<String, String>()? {
                match map.entry(k) {
                    std::collections::btree_map::Entry::Vacant(e) => {
                        order.push(e.key().clone());
                        e.insert(v);
                    }
                    std::collections::btree_map::Entry::Occupied(mut e) => {
                        e.insert(v);
                    }
                }
            }
            Ok((map, order))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok((BTreeMap::new(), Vec::new()))
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok((BTreeMap::new(), Vec::new()))
        }
    }

    deserializer.deserialize_any(OrderedDepsVisitor)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_opt_string_or_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub main: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bin: Option<PackageBin>,

    #[serde(
        default,
        deserialize_with = "deserialize_opt_vec_or_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub files: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub scripts: BTreeMap<String, String>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, String>,

    /// Dependency key order as it appeared in package.json. npm's resolver
    /// uses manifest order when deciding which compatible package claims a
    /// shared hoisted slot; the sorted maps above remain the canonical data
    /// representation for deterministic serialization.
    #[serde(skip)]
    pub dependency_order: Vec<String>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dev_dependencies: BTreeMap<String, String>,

    #[serde(skip)]
    pub dev_dependency_order: Vec<String>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_dependencies: BTreeMap<String, String>,

    #[serde(skip)]
    pub peer_dependency_order: Vec<String>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_dependencies_meta: BTreeMap<String, PeerDependencyMeta>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub optional_dependencies: BTreeMap<String, String>,

    #[serde(skip)]
    pub optional_dependency_order: Vec<String>,

    #[serde(
        default,
        alias = "bundleDependencies",
        skip_serializing_if = "Option::is_none"
    )]
    pub bundled_dependencies: Option<BundledDependencies>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspaces: Option<PackageWorkspaces>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<PlatformList>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<PlatformList>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub libc: Option<PlatformList>,

    #[serde(
        default,
        deserialize_with = "deserialize_engines",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub engines: BTreeMap<String, String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,

    /// Format metadata for round-trip fidelity
    #[serde(skip)]
    pub format: ManifestFormat,

    /// Raw JSON representation preserving original key order and comments/fields
    #[serde(skip)]
    pub raw_json: Option<crate::ordered_json::OrderedJsonValue>,

    /// Raw JSON text preserving original formatting cheaply without building an IndexMap DOM on load
    #[serde(skip)]
    pub raw_text: Option<String>,
}

struct BorrowedKey<'a>(std::borrow::Cow<'a, str>);

impl<'de> Deserialize<'de> for BorrowedKey<'de> {
    #[inline]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeyVisitor;
        impl<'de> Visitor<'de> for KeyVisitor {
            type Value = BorrowedKey<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string key")
            }
            #[inline]
            fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
                Ok(BorrowedKey(std::borrow::Cow::Borrowed(v)))
            }
            #[inline]
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(BorrowedKey(std::borrow::Cow::Owned(v.to_string())))
            }
            #[inline]
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(BorrowedKey(std::borrow::Cow::Owned(v)))
            }
        }
        deserializer.deserialize_str(KeyVisitor)
    }
}

struct OptStringOrBoolSeed;
impl<'de> de::DeserializeSeed<'de> for OptStringOrBoolSeed {
    type Value = Option<String>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserialize_opt_string_or_bool(deserializer)
    }
}

struct OptVecOrStringSeed;
impl<'de> de::DeserializeSeed<'de> for OptVecOrStringSeed {
    type Value = Option<Vec<String>>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserialize_opt_vec_or_string(deserializer)
    }
}

struct OrderedDepsSeed;
impl<'de> de::DeserializeSeed<'de> for OrderedDepsSeed {
    type Value = OrderedDeps;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserialize_ordered_deps(deserializer)
    }
}

struct EnginesSeed;
impl<'de> de::DeserializeSeed<'de> for EnginesSeed {
    type Value = BTreeMap<String, String>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserialize_engines(deserializer)
    }
}

struct OrderedDepsWithRawSeed;
impl<'de> de::DeserializeSeed<'de> for OrderedDepsWithRawSeed {
    type Value = (OrderedDeps, crate::ordered_json::OrderedJsonValue);
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        use crate::ordered_json::{OrderedJsonMap, OrderedJsonValue};
        struct DualDepsVisitor;
        impl<'de> Visitor<'de> for DualDepsVisitor {
            type Value = (OrderedDeps, OrderedJsonValue);
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map of dependencies or null")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> Result<Self::Value, M::Error> {
                let cap = access.size_hint().unwrap_or(8);
                let mut map = BTreeMap::new();
                let mut order = Vec::with_capacity(cap);
                let mut raw_map = OrderedJsonMap::with_capacity(cap);
                while let Some((k, v)) = access.next_entry::<String, String>()? {
                    match map.entry(k.clone()) {
                        std::collections::btree_map::Entry::Vacant(e) => {
                            order.push(e.key().clone());
                            e.insert(v.clone());
                        }
                        std::collections::btree_map::Entry::Occupied(mut e) => {
                            e.insert(v.clone());
                        }
                    }
                    raw_map.insert(k, OrderedJsonValue::String(v));
                }
                Ok(((map, order), OrderedJsonValue::Object(raw_map)))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(((BTreeMap::new(), Vec::new()), OrderedJsonValue::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(((BTreeMap::new(), Vec::new()), OrderedJsonValue::Null))
            }
        }
        deserializer.deserialize_any(DualDepsVisitor)
    }
}

struct StringMapWithRawSeed;
impl<'de> de::DeserializeSeed<'de> for StringMapWithRawSeed {
    type Value = (BTreeMap<String, String>, crate::ordered_json::OrderedJsonValue);
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        use crate::ordered_json::{OrderedJsonMap, OrderedJsonValue};
        struct DualScriptsVisitor;
        impl<'de> Visitor<'de> for DualScriptsVisitor {
            type Value = (BTreeMap<String, String>, OrderedJsonValue);
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> Result<Self::Value, M::Error> {
                let mut map = BTreeMap::new();
                let mut raw_map = OrderedJsonMap::with_capacity(access.size_hint().unwrap_or(4));
                while let Some((k, v)) = access.next_entry::<String, String>()? {
                    map.insert(k.clone(), v.clone());
                    raw_map.insert(k, OrderedJsonValue::String(v));
                }
                Ok((map, OrderedJsonValue::Object(raw_map)))
            }
        }
        deserializer.deserialize_map(DualScriptsVisitor)
    }
}

fn decode_opt_string_from_ordered<E: de::Error>(
    v: &crate::ordered_json::OrderedJsonValue,
) -> Result<Option<String>, E> {
    use crate::ordered_json::OrderedJsonValue;
    match v {
        OrderedJsonValue::String(s) => Ok(Some(s.clone())),
        OrderedJsonValue::Bool(_) | OrderedJsonValue::Null => Ok(None),
        _ => Err(E::custom("expected string, boolean, or null")),
    }
}

fn decode_platform_list_from_ordered<E: de::Error>(
    v: &crate::ordered_json::OrderedJsonValue,
) -> Result<Option<PlatformList>, E> {
    use crate::ordered_json::OrderedJsonValue;
    match v {
        OrderedJsonValue::Null => Ok(None),
        OrderedJsonValue::String(s) => Ok(Some(PlatformList::from(s.clone()))),
        OrderedJsonValue::Array(arr) => {
            let mut vals = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item
                    .as_str()
                    .ok_or_else(|| E::custom("expected string element"))?;
                vals.push(s.to_string());
            }
            Ok(Some(PlatformList::from(vals)))
        }
        _ => Err(E::custom("expected string, array of strings, or null")),
    }
}

fn decode_bin_from_ordered<E: de::Error>(
    v: &crate::ordered_json::OrderedJsonValue,
) -> Result<Option<PackageBin>, E> {
    use crate::ordered_json::OrderedJsonValue;
    match v {
        OrderedJsonValue::Null => Ok(None),
        OrderedJsonValue::String(s) => Ok(Some(PackageBin::Single(s.clone()))),
        OrderedJsonValue::Array(arr) => {
            let mut map = BTreeMap::new();
            for item in arr {
                let s = item
                    .as_str()
                    .ok_or_else(|| E::custom("expected bin path string"))?;
                let key = clean_bin_key(s);
                if !key.is_empty() {
                    map.insert(key, s.to_string());
                }
            }
            Ok(Some(PackageBin::Map(map)))
        }
        OrderedJsonValue::Object(m) => {
            let mut map = BTreeMap::new();
            for (k, val) in m {
                let s = val
                    .as_str()
                    .ok_or_else(|| E::custom("expected bin path string"))?;
                map.insert(k.clone(), s.to_string());
            }
            Ok(Some(PackageBin::Map(map)))
        }
        _ => Err(E::custom("expected bin string or map")),
    }
}

fn decode_bundled_from_ordered<E: de::Error>(
    v: &crate::ordered_json::OrderedJsonValue,
) -> Result<Option<BundledDependencies>, E> {
    use crate::ordered_json::OrderedJsonValue;
    match v {
        OrderedJsonValue::Null => Ok(None),
        OrderedJsonValue::Bool(b) => Ok(Some(BundledDependencies::Boolean(*b))),
        OrderedJsonValue::Array(arr) => {
            let mut list = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item
                    .as_str()
                    .ok_or_else(|| E::custom("expected bundled dependency string"))?;
                list.push(s.to_string());
            }
            Ok(Some(BundledDependencies::List(list)))
        }
        OrderedJsonValue::Object(m) => Ok(Some(BundledDependencies::List(
            m.keys().cloned().collect(),
        ))),
        _ => Err(E::custom("expected boolean, array, or map")),
    }
}

fn decode_workspaces_from_ordered<E: de::Error>(
    v: &crate::ordered_json::OrderedJsonValue,
) -> Result<Option<PackageWorkspaces>, E> {
    use crate::ordered_json::OrderedJsonValue;
    match v {
        OrderedJsonValue::Null => Ok(None),
        OrderedJsonValue::Array(arr) => {
            let mut list = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item
                    .as_str()
                    .ok_or_else(|| E::custom("expected workspace pattern string"))?;
                list.push(s.to_string());
            }
            Ok(Some(PackageWorkspaces::List(list)))
        }
        OrderedJsonValue::Object(m) => {
            let pkgs_val = m
                .get("packages")
                .and_then(OrderedJsonValue::as_array)
                .ok_or_else(|| E::custom("expected packages array in workspaces object"))?;
            let mut packages = Vec::with_capacity(pkgs_val.len());
            for item in pkgs_val {
                let s = item
                    .as_str()
                    .ok_or_else(|| E::custom("expected workspace pattern string"))?;
                packages.push(s.to_string());
            }
            Ok(Some(PackageWorkspaces::Config { packages }))
        }
        _ => Err(E::custom("expected workspaces array or object")),
    }
}

fn decode_peer_meta_from_ordered<E: de::Error>(
    v: &crate::ordered_json::OrderedJsonValue,
) -> Result<BTreeMap<String, PeerDependencyMeta>, E> {
    use crate::ordered_json::OrderedJsonValue;
    let map = v
        .as_object()
        .ok_or_else(|| E::custom("expected peerDependenciesMeta object"))?;
    let mut out = BTreeMap::new();
    for (k, val) in map {
        let entry = val
            .as_object()
            .ok_or_else(|| E::custom("expected peerDependenciesMeta entry object"))?;
        let optional = match entry.get("optional") {
            None => false,
            Some(OrderedJsonValue::Bool(b)) => *b,
            Some(_) => return Err(E::custom("expected boolean optional flag")),
        };
        out.insert(k.clone(), PeerDependencyMeta { optional });
    }
    Ok(out)
}

fn decode_engines_from_ordered<E: de::Error>(
    v: &crate::ordered_json::OrderedJsonValue,
) -> Result<BTreeMap<String, String>, E> {
    use crate::ordered_json::OrderedJsonValue;
    let mut out = BTreeMap::new();
    match v {
        OrderedJsonValue::Null => {}
        OrderedJsonValue::String(s) => {
            for (name, range) in parse_engine_entries_from_str(s) {
                out.insert(name.to_string(), range.to_string());
            }
        }
        OrderedJsonValue::Array(arr) => {
            for elem in arr {
                if let Some(s) = elem.as_str() {
                    if let Some((name, range)) = parse_engine_entry_str(s) {
                        out.insert(name.to_string(), range.to_string());
                    }
                }
            }
        }
        OrderedJsonValue::Object(m) => {
            for (k, val) in m {
                match val {
                    OrderedJsonValue::String(s) => {
                        out.insert(k.clone(), s.clone());
                    }
                    OrderedJsonValue::Bool(b) => {
                        out.insert(k.clone(), if *b { "true" } else { "false" }.to_string());
                    }
                    OrderedJsonValue::Number(n) => {
                        out.insert(k.clone(), n.to_string());
                    }
                    _ => {}
                }
            }
        }
        _ => return Err(E::custom("expected a map, list, or string of engines")),
    }
    Ok(out)
}

struct ManifestVisitor {
    capture_raw: bool,
}

impl<'de> Visitor<'de> for ManifestVisitor {
    type Value = Manifest;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a package.json manifest object")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        use crate::ordered_json::{OrderedJsonMap, OrderedJsonValue};
        let mut m = Manifest::default();
        let mut raw_map = if self.capture_raw {
            Some(OrderedJsonMap::with_capacity(access.size_hint().unwrap_or(16)))
        } else {
            None
        };

        while let Some(key_wrap) = access.next_key::<BorrowedKey<'de>>()? {
            let key = key_wrap.0.as_ref();
            if let Some(ref mut rmap) = raw_map {
                let raw_val = match key {
                    "name" => {
                        let v: Option<String> = access.next_value()?;
                        let rv = match &v {
                            Some(s) => OrderedJsonValue::String(s.clone()),
                            None => OrderedJsonValue::Null,
                        };
                        m.name = v;
                        rv
                    }
                    "version" => {
                        let v: Option<String> = access.next_value()?;
                        let rv = match &v {
                            Some(s) => OrderedJsonValue::String(s.clone()),
                            None => OrderedJsonValue::Null,
                        };
                        m.version = v;
                        rv
                    }
                    "description" => {
                        let v: Option<String> = access.next_value()?;
                        let rv = match &v {
                            Some(s) => OrderedJsonValue::String(s.clone()),
                            None => OrderedJsonValue::Null,
                        };
                        m.description = v;
                        rv
                    }
                    "main" => {
                        let rv: OrderedJsonValue = access.next_value()?;
                        m.main = decode_opt_string_from_ordered(&rv)?;
                        rv
                    }
                    "bin" => {
                        let rv: OrderedJsonValue = access.next_value()?;
                        m.bin = decode_bin_from_ordered(&rv)?;
                        rv
                    }
                    "files" => {
                        let rv: OrderedJsonValue = access.next_value()?;
                        m.files = decode_platform_list_from_ordered(&rv)?.map(PlatformList::into_vec);
                        rv
                    }
                    "scripts" => {
                        let (scripts, rv) = access.next_value_seed(StringMapWithRawSeed)?;
                        m.scripts = scripts;
                        rv
                    }
                    "dependencies" => {
                        let ((map, order), rv) = access.next_value_seed(OrderedDepsWithRawSeed)?;
                        m.dependencies = map;
                        m.dependency_order = order;
                        rv
                    }
                    "devDependencies" => {
                        let ((map, order), rv) = access.next_value_seed(OrderedDepsWithRawSeed)?;
                        m.dev_dependencies = map;
                        m.dev_dependency_order = order;
                        rv
                    }
                    "peerDependencies" => {
                        let ((map, order), rv) = access.next_value_seed(OrderedDepsWithRawSeed)?;
                        m.peer_dependencies = map;
                        m.peer_dependency_order = order;
                        rv
                    }
                    "peerDependenciesMeta" => {
                        let rv: OrderedJsonValue = access.next_value()?;
                        m.peer_dependencies_meta = decode_peer_meta_from_ordered(&rv)?;
                        rv
                    }
                    "optionalDependencies" => {
                        let ((map, order), rv) = access.next_value_seed(OrderedDepsWithRawSeed)?;
                        m.optional_dependencies = map;
                        m.optional_dependency_order = order;
                        rv
                    }
                    "bundledDependencies" | "bundleDependencies" => {
                        let rv: OrderedJsonValue = access.next_value()?;
                        m.bundled_dependencies = decode_bundled_from_ordered(&rv)?;
                        rv
                    }
                    "workspaces" => {
                        let rv: OrderedJsonValue = access.next_value()?;
                        m.workspaces = decode_workspaces_from_ordered(&rv)?;
                        rv
                    }
                    "os" => {
                        let rv: OrderedJsonValue = access.next_value()?;
                        m.os = decode_platform_list_from_ordered(&rv)?;
                        rv
                    }
                    "cpu" => {
                        let rv: OrderedJsonValue = access.next_value()?;
                        m.cpu = decode_platform_list_from_ordered(&rv)?;
                        rv
                    }
                    "libc" => {
                        let rv: OrderedJsonValue = access.next_value()?;
                        m.libc = decode_platform_list_from_ordered(&rv)?;
                        rv
                    }
                    "engines" => {
                        let rv: OrderedJsonValue = access.next_value()?;
                        m.engines = decode_engines_from_ordered(&rv)?;
                        rv
                    }
                    _ => {
                        let rv: OrderedJsonValue = access.next_value()?;
                        let key_owned = key_wrap.0.into_owned();
                        m.extra.insert(key_owned.clone(), rv.to_serde_value());
                        rmap.insert(key_owned, rv);
                        continue;
                    }
                };
                rmap.insert(key_wrap.0.into_owned(), raw_val);
            } else {
                match key {
                    "name" => m.name = access.next_value()?,
                    "version" => m.version = access.next_value()?,
                    "description" => m.description = access.next_value()?,
                    "main" => m.main = access.next_value_seed(OptStringOrBoolSeed)?,
                    "bin" => m.bin = access.next_value()?,
                    "files" => m.files = access.next_value_seed(OptVecOrStringSeed)?,
                    "scripts" => m.scripts = access.next_value()?,
                    "dependencies" => {
                        let (map, order) = access.next_value_seed(OrderedDepsSeed)?;
                        m.dependencies = map;
                        m.dependency_order = order;
                    }
                    "devDependencies" => {
                        let (map, order) = access.next_value_seed(OrderedDepsSeed)?;
                        m.dev_dependencies = map;
                        m.dev_dependency_order = order;
                    }
                    "peerDependencies" => {
                        let (map, order) = access.next_value_seed(OrderedDepsSeed)?;
                        m.peer_dependencies = map;
                        m.peer_dependency_order = order;
                    }
                    "peerDependenciesMeta" => m.peer_dependencies_meta = access.next_value()?,
                    "optionalDependencies" => {
                        let (map, order) = access.next_value_seed(OrderedDepsSeed)?;
                        m.optional_dependencies = map;
                        m.optional_dependency_order = order;
                    }
                    "bundledDependencies" | "bundleDependencies" => {
                        m.bundled_dependencies = access.next_value()?;
                    }
                    "workspaces" => m.workspaces = access.next_value()?,
                    "os" => m.os = access.next_value()?,
                    "cpu" => m.cpu = access.next_value()?,
                    "libc" => m.libc = access.next_value()?,
                    "engines" => m.engines = access.next_value_seed(EnginesSeed)?,
                    _ => {
                        let val: serde_json::Value = access.next_value()?;
                        m.extra.insert(key_wrap.0.into_owned(), val);
                    }
                }
            }
        }

        if let Some(rmap) = raw_map {
            m.raw_json = Some(OrderedJsonValue::Object(rmap));
        }

        Ok(m)
    }
}

struct FastManifestScanner<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> FastManifestScanner<'a> {
    #[inline]
    fn skip_ws(&mut self) {
        let bytes = self.bytes;
        let len = bytes.len();
        let mut p = self.pos;
        if p < len && bytes[p] > b' ' {
            return;
        }
        while p < len {
            let b = bytes[p];
            if b > b' ' {
                break;
            }
            if matches!(b, b' ' | b'\n' | b'\r' | b'\t') {
                p += 1;
            } else {
                break;
            }
        }
        self.pos = p;
    }

    #[inline]
    fn expect_byte(&mut self, expected: u8) -> Option<()> {
        if self.pos < self.bytes.len() && self.bytes[self.pos] == expected {
            self.pos += 1;
            return Some(());
        }
        self.skip_ws();
        if *self.bytes.get(self.pos)? == expected {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }

    #[inline]
    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.bytes.get(self.pos).copied()
    }

    #[inline]
    fn read_plain_str(&mut self) -> Option<&'a str> {
        self.skip_ws();
        if *self.bytes.get(self.pos)? != b'"' {
            return None;
        }
        self.pos += 1;
        let start = self.pos;
        let rest = &self.bytes[start..];
        for (i, &b) in rest.iter().enumerate() {
            if b == b'"' {
                self.pos = start + i + 1;
                // SAFETY: `self.bytes` came from `&str` and `start..start+i` is bounded by ASCII `"` bytes.
                return Some(unsafe {
                    std::str::from_utf8_unchecked(&self.bytes[start..start + i])
                });
            }
            if b == b'\\' || b < 0x20 {
                return None;
            }
        }
        None
    }

    #[inline]
    fn read_bool(&mut self) -> Option<bool> {
        self.skip_ws();
        let rest = &self.bytes[self.pos..];
        if rest.starts_with(b"true") {
            self.pos += 4;
            Some(true)
        } else if rest.starts_with(b"false") {
            self.pos += 5;
            Some(false)
        } else {
            None
        }
    }

    #[inline]
    fn read_null(&mut self) -> Option<()> {
        self.skip_ws();
        if self.bytes[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Some(())
        } else {
            None
        }
    }

    #[inline]
    fn read_string_vec_with_raw<const CAPTURE_RAW: bool>(
        &mut self,
    ) -> Option<(Vec<String>, Option<crate::ordered_json::OrderedJsonValue>)> {
        use crate::ordered_json::OrderedJsonValue;
        self.expect_byte(b'[')?;
        let mut out = Vec::with_capacity(4);
        let mut raw = if CAPTURE_RAW {
            Some(Vec::with_capacity(4))
        } else {
            None
        };
        if self.peek()? == b']' {
            self.pos += 1;
            return Some((out, raw.map(OrderedJsonValue::Array)));
        }
        loop {
            let s = self.read_plain_str()?;
            let s_owned = s.to_owned();
            if let Some(ref mut rvec) = raw {
                rvec.push(OrderedJsonValue::String(s_owned.clone()));
            }
            out.push(s_owned);
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                }
                b']' => {
                    self.pos += 1;
                    return Some((out, raw.map(OrderedJsonValue::Array)));
                }
                _ => return None,
            }
        }
    }

    #[inline]
    fn read_string_btree_with_raw<const CAPTURE_RAW: bool>(
        &mut self,
    ) -> Option<(
        BTreeMap<String, String>,
        Option<crate::ordered_json::OrderedJsonValue>,
    )> {
        use crate::ordered_json::{OrderedJsonMap, OrderedJsonValue};
        self.expect_byte(b'{')?;
        let mut map = BTreeMap::new();
        let mut raw_map = if CAPTURE_RAW {
            Some(OrderedJsonMap::with_capacity(8))
        } else {
            None
        };
        if self.peek()? == b'}' {
            self.pos += 1;
            return Some((map, raw_map.map(OrderedJsonValue::Object)));
        }
        loop {
            let k = self.read_plain_str()?;
            self.expect_byte(b':')?;
            let v = self.read_plain_str()?;
            let k_owned = k.to_owned();
            let v_owned = v.to_owned();
            if let Some(ref mut rmap) = raw_map {
                rmap.insert(k_owned.clone(), OrderedJsonValue::String(v_owned.clone()));
            }
            map.insert(k_owned, v_owned);
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                }
                b'}' => {
                    self.pos += 1;
                    return Some((map, raw_map.map(OrderedJsonValue::Object)));
                }
                _ => return None,
            }
        }
    }

    #[inline]
    fn read_ordered_deps_with_raw<const CAPTURE_RAW: bool>(
        &mut self,
    ) -> Option<(OrderedDeps, Option<crate::ordered_json::OrderedJsonValue>)> {
        use crate::ordered_json::{OrderedJsonMap, OrderedJsonValue};
        self.skip_ws();
        match self.bytes.get(self.pos)? {
            b'n' => {
                self.read_null()?;
                Some((
                    (BTreeMap::new(), Vec::new()),
                    CAPTURE_RAW.then_some(OrderedJsonValue::Null),
                ))
            }
            b'{' => {
                self.pos += 1;
                let mut map = BTreeMap::new();
                let mut order = Vec::with_capacity(16);
                let mut raw_map = if CAPTURE_RAW {
                    Some(OrderedJsonMap::with_capacity(16))
                } else {
                    None
                };
                if self.peek()? == b'}' {
                    self.pos += 1;
                    return Some(((map, order), raw_map.map(OrderedJsonValue::Object)));
                }
                loop {
                    let k = self.read_plain_str()?;
                    self.expect_byte(b':')?;
                    let v = self.read_plain_str()?;
                    let k_owned = k.to_owned();
                    let v_owned = v.to_owned();
                    if let Some(ref mut rmap) = raw_map {
                        rmap.insert(k_owned.clone(), OrderedJsonValue::String(v_owned.clone()));
                    }
                    match map.entry(k_owned) {
                        std::collections::btree_map::Entry::Vacant(e) => {
                            order.push(e.key().clone());
                            e.insert(v_owned);
                        }
                        std::collections::btree_map::Entry::Occupied(mut e) => {
                            e.insert(v_owned);
                        }
                    }
                    match self.peek()? {
                        b',' => {
                            self.pos += 1;
                        }
                        b'}' => {
                            self.pos += 1;
                            return Some(((map, order), raw_map.map(OrderedJsonValue::Object)));
                        }
                        _ => return None,
                    }
                }
            }
            _ => None,
        }
    }

    fn read_any_value_with_raw<const CAPTURE_RAW: bool>(
        &mut self,
        depth: u8,
    ) -> Option<(
        serde_json::Value,
        Option<crate::ordered_json::OrderedJsonValue>,
    )> {
        use crate::ordered_json::{OrderedJsonMap, OrderedJsonValue};
        if depth > 24 {
            return None;
        }
        let b = self.peek()?;
        match b {
            b'"' => {
                let s = self.read_plain_str()?.to_owned();
                let raw = if CAPTURE_RAW {
                    Some(OrderedJsonValue::String(s.clone()))
                } else {
                    None
                };
                Some((serde_json::Value::String(s), raw))
            }
            b't' | b'f' => {
                let v = self.read_bool()?;
                let raw = CAPTURE_RAW.then_some(OrderedJsonValue::Bool(v));
                Some((serde_json::Value::Bool(v), raw))
            }
            b'n' => {
                self.read_null()?;
                Some((
                    serde_json::Value::Null,
                    CAPTURE_RAW.then_some(OrderedJsonValue::Null),
                ))
            }
            b'[' => {
                self.pos += 1;
                let mut arr = Vec::with_capacity(4);
                let mut rarr = if CAPTURE_RAW { Some(Vec::with_capacity(4)) } else { None };
                if self.peek()? == b']' {
                    self.pos += 1;
                    return Some((
                        serde_json::Value::Array(arr),
                        rarr.map(OrderedJsonValue::Array),
                    ));
                }
                loop {
                    let (sv, rv) = self.read_any_value_with_raw::<CAPTURE_RAW>(depth + 1)?;
                    arr.push(sv);
                    if let (Some(ref mut ra), Some(rv)) = (&mut rarr, rv) {
                        ra.push(rv);
                    }
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b']' => {
                            self.pos += 1;
                            return Some((
                                serde_json::Value::Array(arr),
                                rarr.map(OrderedJsonValue::Array),
                            ));
                        }
                        _ => return None,
                    }
                }
            }
            b'{' => {
                self.pos += 1;
                let mut map = serde_json::Map::with_capacity(4);
                let mut rmap = if CAPTURE_RAW {
                    Some(OrderedJsonMap::with_capacity(4))
                } else {
                    None
                };
                if self.peek()? == b'}' {
                    self.pos += 1;
                    return Some((
                        serde_json::Value::Object(map),
                        rmap.map(OrderedJsonValue::Object),
                    ));
                }
                loop {
                    let k = self.read_plain_str()?;
                    self.expect_byte(b':')?;
                    let (sv, rv) = self.read_any_value_with_raw::<CAPTURE_RAW>(depth + 1)?;
                    let k_owned = k.to_owned();
                    if let (Some(ref mut rm), Some(rv)) = (&mut rmap, rv) {
                        rm.insert(k_owned.clone(), rv);
                    }
                    map.insert(k_owned, sv);
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b'}' => {
                            self.pos += 1;
                            return Some((
                                serde_json::Value::Object(map),
                                rmap.map(OrderedJsonValue::Object),
                            ));
                        }
                        _ => return None,
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = self.pos;
                if b == b'-' {
                    self.pos += 1;
                }
                let first = *self.bytes.get(self.pos)?;
                if !first.is_ascii_digit() {
                    return None;
                }
                if first == b'0' {
                    if b == b'-' {
                        return None;
                    }
                    self.pos += 1;
                    if self.bytes.get(self.pos).is_some_and(|c| c.is_ascii_digit()) {
                        return None;
                    }
                } else {
                    while self.bytes.get(self.pos).is_some_and(|c| c.is_ascii_digit()) {
                        self.pos += 1;
                    }
                }
                // Defer floats/exponents to serde_json for exact parsing
                if self
                    .bytes
                    .get(self.pos)
                    .is_some_and(|&c| matches!(c, b'.' | b'e' | b'E'))
                {
                    return None;
                }
                let s = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
                let num = if b == b'-' {
                    let v: i64 = s.parse().ok()?;
                    serde_json::Number::from(v)
                } else {
                    let v: u64 = s.parse().ok()?;
                    serde_json::Number::from(v)
                };
                let raw = if CAPTURE_RAW {
                    Some(OrderedJsonValue::Number(num.clone()))
                } else {
                    None
                };
                Some((serde_json::Value::Number(num), raw))
            }
            _ => None,
        }
    }
}

fn try_parse_manifest_fast<const CAPTURE_RAW: bool>(clean_str: &str) -> Option<Manifest> {
    use crate::ordered_json::{OrderedJsonMap, OrderedJsonValue};

    let mut r = FastManifestScanner {
        bytes: clean_str.as_bytes(),
        pos: 0,
    };
    r.expect_byte(b'{')?;
    let mut m = Manifest::default();
    let mut raw_map = if CAPTURE_RAW {
        Some(OrderedJsonMap::with_capacity(24))
    } else {
        None
    };

    if r.peek()? == b'}' {
        r.pos += 1;
        r.skip_ws();
        return if r.pos == r.bytes.len() {
            if let Some(rmap) = raw_map {
                m.raw_json = Some(OrderedJsonValue::Object(rmap));
            }
            Some(m)
        } else {
            None
        };
    }

    loop {
        let key = r.read_plain_str()?;
        r.expect_byte(b':')?;
        let raw_val: Option<OrderedJsonValue> = match key {
            "name" => match r.peek()? {
                b'n' => {
                    r.read_null()?;
                    m.name = None;
                    CAPTURE_RAW.then_some(OrderedJsonValue::Null)
                }
                _ => {
                    let s = r.read_plain_str()?.to_owned();
                    let rv = CAPTURE_RAW.then(|| OrderedJsonValue::String(s.clone()));
                    m.name = Some(s);
                    rv
                }
            },
            "version" => match r.peek()? {
                b'n' => {
                    r.read_null()?;
                    m.version = None;
                    CAPTURE_RAW.then_some(OrderedJsonValue::Null)
                }
                _ => {
                    let s = r.read_plain_str()?.to_owned();
                    let rv = CAPTURE_RAW.then(|| OrderedJsonValue::String(s.clone()));
                    m.version = Some(s);
                    rv
                }
            },
            "description" => match r.peek()? {
                b'n' => {
                    r.read_null()?;
                    m.description = None;
                    CAPTURE_RAW.then_some(OrderedJsonValue::Null)
                }
                _ => {
                    let s = r.read_plain_str()?.to_owned();
                    let rv = CAPTURE_RAW.then(|| OrderedJsonValue::String(s.clone()));
                    m.description = Some(s);
                    rv
                }
            },
            "main" => match r.peek()? {
                b'"' => {
                    let s = r.read_plain_str()?.to_owned();
                    let rv = CAPTURE_RAW.then(|| OrderedJsonValue::String(s.clone()));
                    m.main = Some(s);
                    rv
                }
                b't' | b'f' => {
                    let b = r.read_bool()?;
                    m.main = None;
                    CAPTURE_RAW.then_some(OrderedJsonValue::Bool(b))
                }
                b'n' => {
                    r.read_null()?;
                    m.main = None;
                    CAPTURE_RAW.then_some(OrderedJsonValue::Null)
                }
                _ => return None,
            },
            "bin" => match r.peek()? {
                b'n' => {
                    r.read_null()?;
                    m.bin = None;
                    CAPTURE_RAW.then_some(OrderedJsonValue::Null)
                }
                b'"' => {
                    let s = r.read_plain_str()?.to_owned();
                    let rv = CAPTURE_RAW.then(|| OrderedJsonValue::String(s.clone()));
                    m.bin = Some(PackageBin::Single(s));
                    rv
                }
                b'{' => {
                    let (map, rv) = r.read_string_btree_with_raw::<CAPTURE_RAW>()?;
                    m.bin = Some(PackageBin::Map(map));
                    rv
                }
                _ => return None,
            },
            "files" => match r.peek()? {
                b'n' => {
                    r.read_null()?;
                    m.files = None;
                    CAPTURE_RAW.then_some(OrderedJsonValue::Null)
                }
                b'"' => {
                    let s = r.read_plain_str()?.to_owned();
                    let rv = CAPTURE_RAW.then(|| OrderedJsonValue::String(s.clone()));
                    m.files = Some(vec![s]);
                    rv
                }
                b'[' => {
                    let (vec, rv) = r.read_string_vec_with_raw::<CAPTURE_RAW>()?;
                    m.files = Some(vec);
                    rv
                }
                _ => return None,
            },
            "scripts" => {
                let (map, rv) = r.read_string_btree_with_raw::<CAPTURE_RAW>()?;
                m.scripts = map;
                rv
            }
            "dependencies" => {
                let ((map, order), rv) = r.read_ordered_deps_with_raw::<CAPTURE_RAW>()?;
                m.dependencies = map;
                m.dependency_order = order;
                rv
            }
            "devDependencies" => {
                let ((map, order), rv) = r.read_ordered_deps_with_raw::<CAPTURE_RAW>()?;
                m.dev_dependencies = map;
                m.dev_dependency_order = order;
                rv
            }
            "peerDependencies" => {
                let ((map, order), rv) = r.read_ordered_deps_with_raw::<CAPTURE_RAW>()?;
                m.peer_dependencies = map;
                m.peer_dependency_order = order;
                rv
            }
            "peerDependenciesMeta" => {
                r.expect_byte(b'{')?;
                let mut pmeta = BTreeMap::new();
                let mut pmeta_raw = if CAPTURE_RAW {
                    Some(OrderedJsonMap::new())
                } else {
                    None
                };
                if r.peek()? != b'}' {
                    loop {
                        let dep_k = r.read_plain_str()?;
                        r.expect_byte(b':')?;
                        r.expect_byte(b'{')?;
                        let mut optional = false;
                        let mut inner_raw = if CAPTURE_RAW {
                            Some(OrderedJsonMap::new())
                        } else {
                            None
                        };
                        if r.peek()? != b'}' {
                            loop {
                                let mk = r.read_plain_str()?;
                                r.expect_byte(b':')?;
                                if mk != "optional" {
                                    return None;
                                }
                                optional = r.read_bool()?;
                                if let Some(ref mut iraw) = inner_raw {
                                    iraw.insert(
                                        mk.to_owned(),
                                        OrderedJsonValue::Bool(optional),
                                    );
                                }
                                match r.peek()? {
                                    b',' => r.pos += 1,
                                    b'}' => break,
                                    _ => return None,
                                }
                            }
                        }
                        r.pos += 1;
                        let dep_k_owned = dep_k.to_owned();
                        if let (Some(ref mut pr), Some(ir)) = (&mut pmeta_raw, inner_raw) {
                            pr.insert(dep_k_owned.clone(), OrderedJsonValue::Object(ir));
                        }
                        pmeta.insert(dep_k_owned, PeerDependencyMeta { optional });
                        match r.peek()? {
                            b',' => r.pos += 1,
                            b'}' => break,
                            _ => return None,
                        }
                    }
                }
                r.pos += 1;
                m.peer_dependencies_meta = pmeta;
                pmeta_raw.map(OrderedJsonValue::Object)
            }
            "optionalDependencies" => {
                let ((map, order), rv) = r.read_ordered_deps_with_raw::<CAPTURE_RAW>()?;
                m.optional_dependencies = map;
                m.optional_dependency_order = order;
                rv
            }
            "bundledDependencies" | "bundleDependencies" => match r.peek()? {
                b'n' => {
                    r.read_null()?;
                    m.bundled_dependencies = None;
                    CAPTURE_RAW.then_some(OrderedJsonValue::Null)
                }
                b't' | b'f' => {
                    let b = r.read_bool()?;
                    m.bundled_dependencies = Some(BundledDependencies::Boolean(b));
                    CAPTURE_RAW.then_some(OrderedJsonValue::Bool(b))
                }
                b'[' => {
                    let (vec, rv) = r.read_string_vec_with_raw::<CAPTURE_RAW>()?;
                    m.bundled_dependencies = Some(BundledDependencies::List(vec));
                    rv
                }
                _ => return None,
            },
            "workspaces" => match r.peek()? {
                b'n' => {
                    r.read_null()?;
                    m.workspaces = None;
                    CAPTURE_RAW.then_some(OrderedJsonValue::Null)
                }
                b'[' => {
                    let (vec, rv) = r.read_string_vec_with_raw::<CAPTURE_RAW>()?;
                    m.workspaces = Some(PackageWorkspaces::List(vec));
                    rv
                }
                _ => return None,
            },
            "os" => match r.peek()? {
                b'n' => {
                    r.read_null()?;
                    m.os = None;
                    CAPTURE_RAW.then_some(OrderedJsonValue::Null)
                }
                b'"' => {
                    let s = r.read_plain_str()?.to_owned();
                    let rv = CAPTURE_RAW.then(|| OrderedJsonValue::String(s.clone()));
                    m.os = Some(PlatformList::from(s));
                    rv
                }
                b'[' => {
                    let (vec, rv) = r.read_string_vec_with_raw::<CAPTURE_RAW>()?;
                    m.os = Some(PlatformList::from(vec));
                    rv
                }
                _ => return None,
            },
            "cpu" => match r.peek()? {
                b'n' => {
                    r.read_null()?;
                    m.cpu = None;
                    CAPTURE_RAW.then_some(OrderedJsonValue::Null)
                }
                b'"' => {
                    let s = r.read_plain_str()?.to_owned();
                    let rv = CAPTURE_RAW.then(|| OrderedJsonValue::String(s.clone()));
                    m.cpu = Some(PlatformList::from(s));
                    rv
                }
                b'[' => {
                    let (vec, rv) = r.read_string_vec_with_raw::<CAPTURE_RAW>()?;
                    m.cpu = Some(PlatformList::from(vec));
                    rv
                }
                _ => return None,
            },
            "libc" => match r.peek()? {
                b'n' => {
                    r.read_null()?;
                    m.libc = None;
                    CAPTURE_RAW.then_some(OrderedJsonValue::Null)
                }
                b'"' => {
                    let s = r.read_plain_str()?.to_owned();
                    let rv = CAPTURE_RAW.then(|| OrderedJsonValue::String(s.clone()));
                    m.libc = Some(PlatformList::from(s));
                    rv
                }
                b'[' => {
                    let (vec, rv) = r.read_string_vec_with_raw::<CAPTURE_RAW>()?;
                    m.libc = Some(PlatformList::from(vec));
                    rv
                }
                _ => return None,
            },
            "engines" => match r.peek()? {
                b'n' => {
                    r.read_null()?;
                    m.engines = BTreeMap::new();
                    CAPTURE_RAW.then_some(OrderedJsonValue::Null)
                }
                b'{' => {
                    let (map, rv) = r.read_string_btree_with_raw::<CAPTURE_RAW>()?;
                    m.engines = map;
                    rv
                }
                _ => return None,
            },
            _ => {
                let (val, rv) = r.read_any_value_with_raw::<CAPTURE_RAW>(0)?;
                m.extra.insert(key.to_owned(), val);
                rv
            }
        };

        if let (Some(ref mut rmap), Some(rv)) = (&mut raw_map, raw_val) {
            rmap.insert(key.to_owned(), rv);
        }

        match r.peek()? {
            b',' => {
                r.pos += 1;
            }
            b'}' => {
                r.pos += 1;
                r.skip_ws();
                return if r.pos == r.bytes.len() {
                    if let Some(rmap) = raw_map {
                        m.raw_json = Some(OrderedJsonValue::Object(rmap));
                    }
                    Some(m)
                } else {
                    None
                };
            }
            _ => return None,
        }
    }
}

impl<'de> Deserialize<'de> for Manifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ManifestVisitor { capture_raw: false })
    }
}

impl Manifest {
    /// Parse manifest from raw bytes, with tolerance for UTF-8 BOM.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ManifestError> {
        // Strip UTF-8 BOM if present (0xEF, 0xBB, 0xBF)
        let clean_bytes = if bytes.starts_with(b"\xEF\xBB\xBF") {
            &bytes[3..]
        } else {
            bytes
        };
        let s = std::str::from_utf8(clean_bytes).map_err(|_| ManifestError::MalformedJson {
            message: "invalid utf-8".to_string(),
            line: 0,
            column: 0,
        })?;
        Self::from_str(s)
    }

    /// Parse manifest from string in a single JSON pass, with tolerance for UTF-8 BOM.
    pub fn from_str(s: &str) -> Result<Self, ManifestError> {
        let format = ManifestFormat::detect(s);
        let clean_str = s.strip_prefix('\u{feff}').unwrap_or(s);
        if let Some(mut manifest) = try_parse_manifest_fast::<true>(clean_str) {
            manifest.format = format;
            manifest.raw_text = Some(clean_str.to_string());
            return Ok(manifest);
        }
        let mut de = serde_json::Deserializer::from_str(clean_str);
        let mut manifest = de
            .deserialize_map(ManifestVisitor { capture_raw: true })
            .map_err(|err| ManifestError::MalformedJson {
                message: err.to_string(),
                line: err.line(),
                column: err.column(),
            })?;
        de.end().map_err(|err| ManifestError::MalformedJson {
            message: err.to_string(),
            line: err.line(),
            column: err.column(),
        })?;
        manifest.format = format;
        manifest.raw_text = Some(clean_str.to_string());
        Ok(manifest)
    }

    /// Read and parse a package.json file from disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ManifestError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|err| ManifestError::Io {
            path: path.to_path_buf(),
            source: err,
        })?;
        Self::from_slice(&bytes)
    }

    /// Parse manifest in read-only mode without building the heavy OrderedJsonValue DOM.
    /// Runs in a pure single pass and sets `raw_json: None` and `raw_text: None`.
    pub fn from_str_readonly(s: &str) -> Result<Self, ManifestError> {
        let format = ManifestFormat::detect(s);
        let clean_str = s.strip_prefix('\u{feff}').unwrap_or(s);
        if let Some(mut manifest) = try_parse_manifest_fast::<false>(clean_str) {
            manifest.format = format;
            return Ok(manifest);
        }
        let mut manifest: Self =
            serde_json::from_str(clean_str).map_err(|err| ManifestError::MalformedJson {
                message: err.to_string(),
                line: err.line(),
                column: err.column(),
            })?;
        manifest.format = format;
        manifest.raw_text = None;
        manifest.raw_json = None;
        Ok(manifest)
    }

    /// Parse manifest from raw bytes in read-only mode, with tolerance for UTF-8 BOM.
    pub fn from_slice_readonly(bytes: &[u8]) -> Result<Self, ManifestError> {
        let clean_bytes = if bytes.starts_with(b"\xEF\xBB\xBF") {
            &bytes[3..]
        } else {
            bytes
        };
        let s = std::str::from_utf8(clean_bytes).map_err(|_| ManifestError::MalformedJson {
            message: "invalid utf-8".to_string(),
            line: 0,
            column: 0,
        })?;
        Self::from_str_readonly(s)
    }

    /// Read and parse a package.json file from disk in read-only mode without building OrderedJsonValue.
    pub fn from_file_readonly(path: impl AsRef<Path>) -> Result<Self, ManifestError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|err| ManifestError::Io {
            path: path.to_path_buf(),
            source: err,
        })?;
        Self::from_slice_readonly(&bytes)
    }

    /// Lazily parse and return a mutable reference to raw_json if raw_text is present.
    pub fn ensure_raw_json(&mut self) -> Option<&mut crate::ordered_json::OrderedJsonValue> {
        if self.raw_json.is_none() {
            if let Some(ref text) = self.raw_text {
                if let Ok(val) = serde_json::from_str(text) {
                    self.raw_json = Some(val);
                }
            }
        }
        self.raw_json.as_mut()
    }

    pub fn capture_dependency_order(&mut self, value: &crate::ordered_json::OrderedJsonValue) {
        let Some(object) = value.as_object() else {
            return;
        };
        let collect = |key: &str| {
            object
                .get(key)
                .and_then(crate::ordered_json::OrderedJsonValue::as_object)
                .map(|map| map.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        };
        self.dependency_order = collect("dependencies");
        self.dev_dependency_order = collect("devDependencies");
        self.peer_dependency_order = collect("peerDependencies");
        self.optional_dependency_order = collect("optionalDependencies");
    }

    /// Returns list of (binary_name, script_path) defined in manifest, sanitized according to npm 11.20.0.
    pub fn bin_entries(&self) -> Vec<(String, String)> {
        match &self.bin {
            None => Vec::new(),
            Some(PackageBin::Single(script_path)) => {
                // If package name is missing or empty, npm removes the bin
                let Some(pkg_name) = self.name.as_deref().filter(|n| !n.trim().is_empty()) else {
                    return Vec::new();
                };
                let bin_name = clean_bin_key(pkg_name);
                let bin_target = clean_bin_target(script_path);
                if !bin_name.is_empty() && !bin_target.is_empty() {
                    vec![(bin_name, bin_target)]
                } else {
                    Vec::new()
                }
            }
            Some(PackageBin::Map(map)) => {
                let mut entries = Vec::new();
                for (k, v) in map {
                    let bin_name = clean_bin_key(k);
                    let bin_target = clean_bin_target(v);
                    if !bin_name.is_empty() && !bin_target.is_empty() {
                        entries.push((bin_name, bin_target));
                    }
                }
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                entries
            }
        }
    }

    /// Returns a list of package names that are marked as bundled.
    pub fn bundled_package_names(&self) -> Vec<String> {
        match &self.bundled_dependencies {
            None => Vec::new(),
            Some(BundledDependencies::Boolean(true)) => {
                // If true, all regular dependencies are bundled
                self.dependencies.keys().cloned().collect()
            }
            Some(BundledDependencies::Boolean(false)) => Vec::new(),
            Some(BundledDependencies::List(list)) => list.clone(),
        }
    }

    /// Returns workspace patterns if configured.
    pub fn workspace_patterns(&self) -> Vec<String> {
        match &self.workspaces {
            None => Vec::new(),
            Some(PackageWorkspaces::List(patterns)) => patterns.clone(),
            Some(PackageWorkspaces::Config { packages }) => packages.clone(),
        }
    }

    /// Format a JSON Value or serializable value preserving indentation, newline, BOM, and trailing newline preferences.
    pub fn format_json_value<T: Serialize>(
        value: &T,
        format: &ManifestFormat,
    ) -> Result<String, ManifestError> {
        let out = if format.indent.is_empty() {
            let mut s = serde_json::to_string(value).map_err(|err| ManifestError::MalformedJson {
                message: err.to_string(),
                line: err.line(),
                column: err.column(),
            })?;
            if format.has_bom {
                s.insert(0, '\u{feff}');
            }
            s.push_str(&format.newline);
            return Ok(s);
        } else if format.newline == "\r\n" {
            let mut buf = Vec::new();
            let formatter = serde_json::ser::PrettyFormatter::with_indent(format.indent.as_bytes());
            let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
            value.serialize(&mut ser).map_err(|err| ManifestError::MalformedJson {
                message: err.to_string(),
                line: err.line(),
                column: err.column(),
            })?;
            let formatted = String::from_utf8(buf).map_err(|e| ManifestError::MalformedJson {
                message: e.to_string(),
                line: 0,
                column: 0,
            })?;
            let nl_count = formatted.as_bytes().iter().filter(|&&b| b == b'\n').count();
            let mut s = String::with_capacity(
                formatted.len() + nl_count + 2 + if format.has_bom { 3 } else { 0 },
            );
            if format.has_bom {
                s.push('\u{feff}');
            }
            let bytes = formatted.as_bytes();
            let mut start = 0usize;
            for (i, &b) in bytes.iter().enumerate() {
                if b == b'\n' {
                    let end = if i > start && bytes[i - 1] == b'\r' {
                        i - 1
                    } else {
                        i
                    };
                    s.push_str(&formatted[start..end]);
                    s.push_str("\r\n");
                    start = i + 1;
                }
            }
            if start < bytes.len() {
                s.push_str(&formatted[start..]);
            }
            s.push_str("\r\n");
            return Ok(s);
        } else {
            let mut buf = Vec::with_capacity(if format.has_bom { 256 } else { 128 });
            if format.has_bom {
                buf.extend_from_slice("\u{feff}".as_bytes());
            }
            let formatter = serde_json::ser::PrettyFormatter::with_indent(format.indent.as_bytes());
            let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
            value.serialize(&mut ser).map_err(|err| ManifestError::MalformedJson {
                message: err.to_string(),
                line: err.line(),
                column: err.column(),
            })?;
            buf.extend_from_slice(format.newline.as_bytes());
            String::from_utf8(buf).map_err(|e| ManifestError::MalformedJson {
                message: e.to_string(),
                line: 0,
                column: 0,
            })?
        };
        Ok(out)
    }

    /// Serialize manifest to a deterministic formatted JSON string with high fidelity,
    /// preserving original key order, custom indentation (spaces or tabs), and line endings (CRLF or LF).
    /// Streams directly from `&self` and `&self.raw_json` without cloning the JSON DOM.
    pub fn to_json_string(&self) -> Result<String, ManifestError> {
        use crate::ordered_json::{
            ordered_json_eq_serde_value, push_indent, write_json_str, write_ordered_json_value,
            write_serde_json_value, OrderedJsonValue,
        };

        let parsed_fallback;
        let raw_opt = if let Some(ref raw) = self.raw_json {
            Some(raw)
        } else if let Some(ref raw_str) = self.raw_text {
            match serde_json::from_str::<OrderedJsonValue>(raw_str) {
                Ok(val) => {
                    parsed_fallback = Some(val);
                    parsed_fallback.as_ref()
                }
                Err(_) => None,
            }
        } else {
            None
        };

        let Some(OrderedJsonValue::Object(raw_map)) = raw_opt else {
            if let Some(raw_val) = raw_opt {
                let mut out = String::with_capacity(self.raw_text.as_ref().map_or(256, |s| s.len() + 32));
                if self.format.has_bom {
                    out.push('\u{feff}');
                }
                let nl = if self.format.newline.is_empty() {
                    "\n"
                } else {
                    self.format.newline.as_str()
                };
                write_ordered_json_value(raw_val, &self.format.indent, nl, 0, &mut out);
                out.push_str(&self.format.newline);
                return Ok(out);
            }
            return Self::format_json_value(self, &self.format);
        };

        let est_cap = self.raw_text.as_ref().map_or(512, |s| s.len() + 128);
        let mut out = String::with_capacity(est_cap);
        if self.format.has_bom {
            out.push('\u{feff}');
        }

        let indent = self.format.indent.as_str();
        let pretty = !indent.is_empty();
        let newline = if self.format.newline.is_empty() {
            "\n"
        } else {
            self.format.newline.as_str()
        };
        let colon = if pretty { ": " } else { ":" };
        let (nl_indent_1, nl_indent_2, nl_indent_3) = if pretty {
            let mut s1 = String::with_capacity(newline.len() + indent.len());
            s1.push_str(newline);
            s1.push_str(indent);
            let mut s2 = String::with_capacity(newline.len() + indent.len() * 2);
            s2.push_str(newline);
            s2.push_str(indent);
            s2.push_str(indent);
            let mut s3 = String::with_capacity(newline.len() + indent.len() * 3);
            s3.push_str(newline);
            s3.push_str(indent);
            s3.push_str(indent);
            s3.push_str(indent);
            (s1, s2, s3)
        } else {
            (String::new(), String::new(), String::new())
        };
        let mut deps_seen_scratch = crate::fast_hash::FxHashSet::default();
        fn write_ordered_deps_impl<'a>(
            out: &mut String,
            deps: &'a BTreeMap<String, String>,
            order: &'a [String],
            nl_indent_1: &str,
            nl_indent_2: &str,
            colon: &str,
            deps_seen_scratch: &mut crate::fast_hash::FxHashSet<&'a str>,
        ) {
            if deps.is_empty() {
                out.push_str("{}");
                return;
            }
            let pretty = !nl_indent_1.is_empty();
            out.push('{');
            if order.len() == deps.len() && deps.keys().eq(order.iter()) {
                for (idx, (k, v)) in deps.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    if pretty {
                        out.push_str(nl_indent_2);
                    }
                    write_json_str(k, out);
                    out.push_str(colon);
                    write_json_str(v, out);
                }
                if pretty {
                    out.push_str(nl_indent_1);
                }
                out.push('}');
                return;
            }
            let mut idx = 0usize;
            let mut emitted_unique = 0usize;
            let use_set = order.len() > 16;
            if use_set {
                deps_seen_scratch.clear();
                deps_seen_scratch.reserve(order.len());
            }
            for (i, k) in order.iter().enumerate() {
                if let Some(v) = deps.get(k) {
                    let is_dup = if use_set {
                        !deps_seen_scratch.insert(k.as_str())
                    } else {
                        order[..i].iter().any(|prev| prev == k)
                    };
                    if is_dup {
                        continue;
                    }
                    if idx > 0 {
                        out.push(',');
                    }
                    if pretty {
                        out.push_str(nl_indent_2);
                    }
                    write_json_str(k, out);
                    out.push_str(colon);
                    write_json_str(v, out);
                    idx += 1;
                    emitted_unique += 1;
                }
            }
            if emitted_unique < deps.len() {
                for (k, v) in deps {
                    let already = if use_set {
                        deps_seen_scratch.contains(k.as_str())
                    } else {
                        order.iter().any(|ok| ok == k)
                    };
                    if !already {
                        if idx > 0 {
                            out.push(',');
                        }
                        if pretty {
                            out.push_str(nl_indent_2);
                        }
                        write_json_str(k, out);
                        out.push_str(colon);
                        write_json_str(v, out);
                        idx += 1;
                    }
                }
            }
            if pretty {
                out.push_str(nl_indent_1);
            }
            out.push('}');
        }

        let write_entry_prefix = |out: &mut String, first: &mut bool, key: &str| {
            if *first {
                *first = false;
            } else {
                out.push(',');
            }
            if pretty {
                out.push_str(&nl_indent_1);
            }
            write_json_str(key, out);
            out.push_str(colon);
        };

        let write_str_map = |out: &mut String, map: &BTreeMap<String, String>| {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (idx, (k, v)) in map.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push_str(&nl_indent_2);
                }
                write_json_str(k, out);
                out.push_str(colon);
                write_json_str(v, out);
            }
            if pretty {
                out.push_str(&nl_indent_1);
            }
            out.push('}');
        };

        let write_bundled = |out: &mut String, bundled: &BundledDependencies| match bundled {
            BundledDependencies::Boolean(b) => out.push_str(if *b { "true" } else { "false" }),
            BundledDependencies::List(list) => {
                if list.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (idx, item) in list.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    if pretty {
                        out.push_str(&nl_indent_2);
                    }
                    write_json_str(item, out);
                }
                if pretty {
                    out.push_str(&nl_indent_1);
                }
                out.push(']');
            }
        };

        let write_peer_meta = |out: &mut String, meta: &BTreeMap<String, PeerDependencyMeta>| {
            if meta.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (idx, (k, pm)) in meta.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push_str(&nl_indent_2);
                }
                write_json_str(k, out);
                out.push_str(if pretty { ": {" } else { ":{" });
                if pretty {
                    out.push_str(&nl_indent_3);
                }
                out.push_str(if pretty { "\"optional\": " } else { "\"optional\":" });
                out.push_str(if pm.optional { "true" } else { "false" });
                if pretty {
                    out.push_str(&nl_indent_2);
                }
                out.push('}');
            }
            if pretty {
                out.push_str(&nl_indent_1);
            }
            out.push('}');
        };

        let write_workspaces = |out: &mut String, ws: &PackageWorkspaces| match ws {
            PackageWorkspaces::List(patterns) => {
                if patterns.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (idx, item) in patterns.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    if pretty {
                        out.push_str(newline);
                        push_indent(out, indent, 2);
                    }
                    write_json_str(item, out);
                }
                if pretty {
                    out.push_str(newline);
                    out.push_str(indent);
                }
                out.push(']');
            }
            PackageWorkspaces::Config { packages } => {
                out.push('{');
                if pretty {
                    out.push_str(newline);
                    push_indent(out, indent, 2);
                }
                out.push_str(if pretty { "\"packages\": " } else { "\"packages\":" });
                if packages.is_empty() {
                    out.push_str("[]");
                } else {
                    out.push('[');
                    for (idx, item) in packages.iter().enumerate() {
                        if idx > 0 {
                            out.push(',');
                        }
                        if pretty {
                            out.push_str(newline);
                            push_indent(out, indent, 3);
                        }
                        write_json_str(item, out);
                    }
                    if pretty {
                        out.push_str(newline);
                        push_indent(out, indent, 2);
                    }
                    out.push(']');
                }
                if pretty {
                    out.push_str(newline);
                    out.push_str(indent);
                }
                out.push('}');
            }
        };

        let write_str_array = |out: &mut String, list: &[String]| {
            if list.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (idx, item) in list.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push_str(&nl_indent_2);
                }
                write_json_str(item, out);
            }
            if pretty {
                out.push_str(&nl_indent_1);
            }
            out.push(']');
        };

        let write_bin = |out: &mut String, bin: &PackageBin| match bin {
            PackageBin::Single(s) => write_json_str(s, out),
            PackageBin::Map(map) => write_str_map(out, map),
        };

        let write_platform_list = |out: &mut String, pl: &PlatformList| {
            if pl.is_scalar() && pl.len() == 1 {
                write_json_str(&pl[0], out);
            } else {
                write_str_array(out, pl.as_slice());
            }
        };

        out.push('{');
        let mut first = true;
        // Track which synthesized fields existed in raw_map so missing active ones are appended in order
        let mut seen_name = false;
        let mut seen_version = false;
        let mut seen_description = false;
        let mut seen_main = false;
        let mut seen_bin = false;
        let mut seen_files = false;
        let mut seen_scripts = false;
        let mut seen_deps = false;
        let mut seen_dev_deps = false;
        let mut seen_peer_deps = false;
        let mut seen_opt_deps = false;
        let mut seen_bundle_deps = false;
        let mut seen_peer_meta = false;
        let mut seen_workspaces = false;
        let mut seen_os = false;
        let mut seen_cpu = false;
        let mut seen_libc = false;
        let mut seen_engines = false;

        for (k, raw_v) in raw_map {
            match k.as_str() {
                "name" => {
                    seen_name = true;
                    if let Some(ref name) = self.name {
                        write_entry_prefix(&mut out, &mut first, "name");
                        write_json_str(name, &mut out);
                    }
                }
                "version" => {
                    seen_version = true;
                    if let Some(ref version) = self.version {
                        write_entry_prefix(&mut out, &mut first, "version");
                        write_json_str(version, &mut out);
                    }
                }
                "description" => {
                    seen_description = true;
                    if let Some(ref desc) = self.description {
                        write_entry_prefix(&mut out, &mut first, "description");
                        write_json_str(desc, &mut out);
                    }
                }
                "main" => {
                    seen_main = true;
                    if let Some(ref main) = self.main {
                        write_entry_prefix(&mut out, &mut first, "main");
                        write_json_str(main, &mut out);
                    }
                }
                "bin" => {
                    seen_bin = true;
                    if let Some(ref bin) = self.bin {
                        write_entry_prefix(&mut out, &mut first, "bin");
                        write_bin(&mut out, bin);
                    }
                }
                "files" => {
                    seen_files = true;
                    if let Some(ref files) = self.files {
                        write_entry_prefix(&mut out, &mut first, "files");
                        write_str_array(&mut out, files);
                    }
                }
                "scripts" => {
                    seen_scripts = true;
                    if !self.scripts.is_empty() {
                        write_entry_prefix(&mut out, &mut first, "scripts");
                        write_str_map(&mut out, &self.scripts);
                    }
                }
                "dependencies" => {
                    seen_deps = true;
                    if !self.dependencies.is_empty() {
                        write_entry_prefix(&mut out, &mut first, "dependencies");
                        write_ordered_deps_impl(
                            &mut out,
                            &self.dependencies,
                            &self.dependency_order,
                            &nl_indent_1,
                            &nl_indent_2,
                            colon,
                            &mut deps_seen_scratch,
                        );
                    }
                }
                "devDependencies" => {
                    seen_dev_deps = true;
                    if !self.dev_dependencies.is_empty() {
                        write_entry_prefix(&mut out, &mut first, "devDependencies");
                        write_ordered_deps_impl(
                            &mut out,
                            &self.dev_dependencies,
                            &self.dev_dependency_order,
                            &nl_indent_1,
                            &nl_indent_2,
                            colon,
                            &mut deps_seen_scratch,
                        );
                    }
                }
                "peerDependencies" => {
                    seen_peer_deps = true;
                    if !self.peer_dependencies.is_empty() {
                        write_entry_prefix(&mut out, &mut first, "peerDependencies");
                        write_ordered_deps_impl(
                            &mut out,
                            &self.peer_dependencies,
                            &self.peer_dependency_order,
                            &nl_indent_1,
                            &nl_indent_2,
                            colon,
                            &mut deps_seen_scratch,
                        );
                    }
                }
                "optionalDependencies" => {
                    seen_opt_deps = true;
                    if !self.optional_dependencies.is_empty() {
                        write_entry_prefix(&mut out, &mut first, "optionalDependencies");
                        write_ordered_deps_impl(
                            &mut out,
                            &self.optional_dependencies,
                            &self.optional_dependency_order,
                            &nl_indent_1,
                            &nl_indent_2,
                            colon,
                            &mut deps_seen_scratch,
                        );
                    }
                }
                "bundledDependencies" => {}
                "bundleDependencies" => {
                    seen_bundle_deps = true;
                    if let Some(ref bundled) = self.bundled_dependencies {
                        write_entry_prefix(&mut out, &mut first, "bundleDependencies");
                        write_bundled(&mut out, bundled);
                    }
                }
                "peerDependenciesMeta" => {
                    seen_peer_meta = true;
                    if !self.peer_dependencies_meta.is_empty() {
                        write_entry_prefix(&mut out, &mut first, "peerDependenciesMeta");
                        write_peer_meta(&mut out, &self.peer_dependencies_meta);
                    }
                }
                "workspaces" => {
                    seen_workspaces = true;
                    if let Some(ref ws) = self.workspaces {
                        write_entry_prefix(&mut out, &mut first, "workspaces");
                        write_workspaces(&mut out, ws);
                    }
                }
                "os" => {
                    seen_os = true;
                    if let Some(ref os) = self.os {
                        write_entry_prefix(&mut out, &mut first, "os");
                        write_platform_list(&mut out, os);
                    }
                }
                "cpu" => {
                    seen_cpu = true;
                    if let Some(ref cpu) = self.cpu {
                        write_entry_prefix(&mut out, &mut first, "cpu");
                        write_platform_list(&mut out, cpu);
                    }
                }
                "libc" => {
                    seen_libc = true;
                    if let Some(ref libc) = self.libc {
                        write_entry_prefix(&mut out, &mut first, "libc");
                        write_platform_list(&mut out, libc);
                    }
                }
                "engines" => {
                    seen_engines = true;
                    if !self.engines.is_empty() {
                        write_entry_prefix(&mut out, &mut first, "engines");
                        write_str_map(&mut out, &self.engines);
                    }
                }
                other_key => {
                    if let Some(extra_val) = self.extra.get(other_key) {
                        write_entry_prefix(&mut out, &mut first, other_key);
                        if ordered_json_eq_serde_value(raw_v, extra_val) {
                            write_ordered_json_value(raw_v, indent, newline, 1, &mut out);
                        } else {
                            write_serde_json_value(extra_val, indent, newline, 1, &mut out);
                        }
                    }
                }
            }
        }

        if !seen_name {
            if let Some(ref name) = self.name {
                write_entry_prefix(&mut out, &mut first, "name");
                write_json_str(name, &mut out);
            }
        }
        if !seen_version {
            if let Some(ref version) = self.version {
                write_entry_prefix(&mut out, &mut first, "version");
                write_json_str(version, &mut out);
            }
        }
        if !seen_description {
            if let Some(ref desc) = self.description {
                write_entry_prefix(&mut out, &mut first, "description");
                write_json_str(desc, &mut out);
            }
        }
        if !seen_main {
            if let Some(ref main) = self.main {
                write_entry_prefix(&mut out, &mut first, "main");
                write_json_str(main, &mut out);
            }
        }
        if !seen_bin {
            if let Some(ref bin) = self.bin {
                write_entry_prefix(&mut out, &mut first, "bin");
                write_bin(&mut out, bin);
            }
        }
        if !seen_files {
            if let Some(ref files) = self.files {
                write_entry_prefix(&mut out, &mut first, "files");
                write_str_array(&mut out, files);
            }
        }
        if !seen_scripts && !self.scripts.is_empty() {
            write_entry_prefix(&mut out, &mut first, "scripts");
            write_str_map(&mut out, &self.scripts);
        }
        if !seen_deps && !self.dependencies.is_empty() {
            write_entry_prefix(&mut out, &mut first, "dependencies");
            write_ordered_deps_impl(
                &mut out,
                &self.dependencies,
                &self.dependency_order,
                &nl_indent_1,
                &nl_indent_2,
                colon,
                &mut deps_seen_scratch,
            );
        }
        if !seen_dev_deps && !self.dev_dependencies.is_empty() {
            write_entry_prefix(&mut out, &mut first, "devDependencies");
            write_ordered_deps_impl(
                &mut out,
                &self.dev_dependencies,
                &self.dev_dependency_order,
                &nl_indent_1,
                &nl_indent_2,
                colon,
                &mut deps_seen_scratch,
            );
        }
        if !seen_peer_deps && !self.peer_dependencies.is_empty() {
            write_entry_prefix(&mut out, &mut first, "peerDependencies");
            write_ordered_deps_impl(
                &mut out,
                &self.peer_dependencies,
                &self.peer_dependency_order,
                &nl_indent_1,
                &nl_indent_2,
                colon,
                &mut deps_seen_scratch,
            );
        }
        if !seen_opt_deps && !self.optional_dependencies.is_empty() {
            write_entry_prefix(&mut out, &mut first, "optionalDependencies");
            write_ordered_deps_impl(
                &mut out,
                &self.optional_dependencies,
                &self.optional_dependency_order,
                &nl_indent_1,
                &nl_indent_2,
                colon,
                &mut deps_seen_scratch,
            );
        }
        if !seen_bundle_deps {
            if let Some(ref bundled) = self.bundled_dependencies {
                write_entry_prefix(&mut out, &mut first, "bundleDependencies");
                write_bundled(&mut out, bundled);
            }
        }
        if !seen_peer_meta && !self.peer_dependencies_meta.is_empty() {
            write_entry_prefix(&mut out, &mut first, "peerDependenciesMeta");
            write_peer_meta(&mut out, &self.peer_dependencies_meta);
        }
        if !seen_workspaces {
            if let Some(ref ws) = self.workspaces {
                write_entry_prefix(&mut out, &mut first, "workspaces");
                write_workspaces(&mut out, ws);
            }
        }
        if !seen_os {
            if let Some(ref os) = self.os {
                write_entry_prefix(&mut out, &mut first, "os");
                write_platform_list(&mut out, os);
            }
        }
        if !seen_cpu {
            if let Some(ref cpu) = self.cpu {
                write_entry_prefix(&mut out, &mut first, "cpu");
                write_platform_list(&mut out, cpu);
            }
        }
        if !seen_libc {
            if let Some(ref libc) = self.libc {
                write_entry_prefix(&mut out, &mut first, "libc");
                write_platform_list(&mut out, libc);
            }
        }
        if !seen_engines && !self.engines.is_empty() {
            write_entry_prefix(&mut out, &mut first, "engines");
            write_str_map(&mut out, &self.engines);
        }
        for (extra_key, extra_val) in &self.extra {
            if !raw_map.contains_key(extra_key.as_str())
                && !matches!(
                    extra_key.as_str(),
                    "name"
                        | "version"
                        | "description"
                        | "main"
                        | "bin"
                        | "files"
                        | "scripts"
                        | "dependencies"
                        | "devDependencies"
                        | "peerDependencies"
                        | "optionalDependencies"
                        | "bundleDependencies"
                        | "bundledDependencies"
                        | "peerDependenciesMeta"
                        | "workspaces"
                        | "os"
                        | "cpu"
                        | "libc"
                        | "engines"
                )
            {
                write_entry_prefix(&mut out, &mut first, extra_key);
                write_serde_json_value(extra_val, indent, newline, 1, &mut out);
            }
        }

        if pretty && !first {
            out.push_str(newline);
        }
        out.push('}');
        out.push_str(&self.format.newline);

        Ok(out)
    }

    /// Save the manifest deterministically to disk.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), ManifestError> {
        let path = path.as_ref();
        let content = self.to_json_string()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| ManifestError::Io {
                path: parent.to_path_buf(),
                source: err,
            })?;
        }
        fs::write(path, content).map_err(|err| ManifestError::Io {
            path: path.to_path_buf(),
            source: err,
        })?;
        Ok(())
    }
}
