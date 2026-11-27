use crate::error::LockfileError;
use rnpm_core::manifest::BundledDependencies;
use rnpm_core::semver::Version;
use rnpm_core::spec::PackageTarget;
use rnpm_core::{to_posix_path, to_posix_path_cow};
use rnpm_core::PlatformList;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

/// Helper function to omit booleans during serialization if false or None.
fn is_false_or_none(v: &Option<bool>) -> bool {
    v.map(|b| !b).unwrap_or(true)
}

/// Helper function to omit empty maps or None during serialization.
fn is_none_or_empty_map<V>(v: &Option<BTreeMap<String, V>>) -> bool {
    v.as_ref().map(|m| m.is_empty()).unwrap_or(true)
}

/// Helper function to omit empty bundleDependencies or false during serialization.
fn is_empty_bundle_deps(v: &Option<BundledDependencies>) -> bool {
    match v {
        None => true,
        Some(BundledDependencies::Boolean(false)) => true,
        Some(BundledDependencies::List(list)) => list.is_empty(),
        _ => false,
    }
}

/// Helper function to omit empty engines or None during serialization.
fn is_none_or_empty_engines(v: &Option<PackageEngines>) -> bool {
    v.as_ref().map(|e| e.is_empty()).unwrap_or(true)
}

/// npm copies platform constraints in their original string or array form.
fn is_none_or_empty_platform(v: &Option<PlatformList>) -> bool {
    v.as_ref().map(|l| l.is_empty()).unwrap_or(true)
}

/// Package supported engine constraints.
///
/// In npm package-lock files, `engines` is usually a map of engine names to semver constraints,
/// but npm has also published and tolerated array, string, and arbitrary JSON representations.
/// Uninterpreted representations are preserved during deserialization and serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageEngines {
    Map(BTreeMap<String, String>),
    List(Vec<serde_json::Value>),
    String(String),
    Other(serde_json::Value),
}

impl Serialize for PackageEngines {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            PackageEngines::Map(m) => m.serialize(serializer),
            PackageEngines::List(l) => l.serialize(serializer),
            PackageEngines::String(s) => s.serialize(serializer),
            PackageEngines::Other(v) => v.serialize(serializer),
        }
    }
}

enum StringOrJsonValue {
    Str(String),
    Other(serde_json::Value),
}

impl<'de> Deserialize<'de> for StringOrJsonValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StringOrJsonVisitor;
        impl<'de> Visitor<'de> for StringOrJsonVisitor {
            type Value = StringOrJsonValue;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StringOrJsonValue::Str(v.to_owned()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(StringOrJsonValue::Str(v))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StringOrJsonValue::Other(serde_json::Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StringOrJsonValue::Other(serde_json::Value::from(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StringOrJsonValue::Other(serde_json::Value::from(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| StringOrJsonValue::Other(serde_json::Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite float"))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StringOrJsonValue::Other(serde_json::Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StringOrJsonValue::Other(serde_json::Value::Null))
            }
            fn visit_some<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                Self::Value::deserialize(deserializer)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(elem) = seq.next_element::<serde_json::Value>()? {
                    vec.push(elem);
                }
                Ok(StringOrJsonValue::Other(serde_json::Value::Array(vec)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut obj = serde_json::Map::with_capacity(map.size_hint().unwrap_or(0));
                while let Some((k, v)) = map.next_entry::<String, serde_json::Value>()? {
                    obj.insert(k, v);
                }
                Ok(StringOrJsonValue::Other(serde_json::Value::Object(obj)))
            }
        }
        deserializer.deserialize_any(StringOrJsonVisitor)
    }
}

impl<'de> Deserialize<'de> for PackageEngines {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PackageEnginesVisitor;
        impl<'de> Visitor<'de> for PackageEnginesVisitor {
            type Value = PackageEngines;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map, list, string, or arbitrary JSON value for engines")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(PackageEngines::String(v.to_owned()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(PackageEngines::String(v))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(elem) = seq.next_element::<serde_json::Value>()? {
                    vec.push(elem);
                }
                Ok(PackageEngines::List(vec))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut str_map: Option<BTreeMap<String, String>> = Some(BTreeMap::new());
                let mut obj_map: Option<serde_json::Map<String, serde_json::Value>> = None;
                while let Some(k) = map.next_key::<String>()? {
                    if let Some(ref mut sm) = str_map {
                        match map.next_value::<StringOrJsonValue>()? {
                            StringOrJsonValue::Str(s) => {
                                sm.insert(k, s);
                            }
                            StringOrJsonValue::Other(val) => {
                                let prev = str_map.take().unwrap();
                                let mut m = serde_json::Map::with_capacity(prev.len() + 4);
                                for (pk, pv) in prev {
                                    m.insert(pk, serde_json::Value::String(pv));
                                }
                                m.insert(k, val);
                                obj_map = Some(m);
                            }
                        }
                    } else if let Some(ref mut om) = obj_map {
                        let val = map.next_value::<serde_json::Value>()?;
                        om.insert(k, val);
                    }
                }
                if let Some(m) = obj_map {
                    Ok(PackageEngines::Other(serde_json::Value::Object(m)))
                } else {
                    Ok(PackageEngines::Map(str_map.unwrap_or_default()))
                }
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(PackageEngines::Other(serde_json::Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(PackageEngines::Other(serde_json::Value::from(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(PackageEngines::Other(serde_json::Value::from(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(serde_json::Value::Number)
                    .map(PackageEngines::Other)
                    .ok_or_else(|| E::custom("non-finite float in engines"))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(PackageEngines::Other(serde_json::Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(PackageEngines::Other(serde_json::Value::Null))
            }
            fn visit_some<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                Self::Value::deserialize(deserializer)
            }
        }
        deserializer.deserialize_any(PackageEnginesVisitor)
    }
}

impl PackageEngines {
    /// Returns the engines map if this is a map, or attempts to parse string/list entries if possible.
    pub fn as_map(&self) -> Option<BTreeMap<String, String>> {
        match self {
            PackageEngines::Map(map) => Some(map.clone()),
            PackageEngines::List(list) => {
                let mut map = BTreeMap::new();
                for item in list {
                    if let Some(s) = item.as_str() {
                        if let Some((name, range)) = parse_engine_entry(s) {
                            map.insert(name, range);
                        }
                    }
                }
                if map.is_empty() {
                    None
                } else {
                    Some(map)
                }
            }
            PackageEngines::String(s) => {
                if let Some((name, range)) = parse_engine_entry(s) {
                    let mut map = BTreeMap::new();
                    map.insert(name, range);
                    Some(map)
                } else {
                    None
                }
            }
            PackageEngines::Other(serde_json::Value::Object(obj)) => {
                let mut map = BTreeMap::new();
                for (k, v) in obj {
                    if let Some(s) = v.as_str() {
                        map.insert(k.clone(), s.to_string());
                    }
                }
                if map.is_empty() {
                    None
                } else {
                    Some(map)
                }
            }
            _ => None,
        }
    }

    /// Returns a reference to the map if this engines representation is a `Map`.
    pub fn map_ref(&self) -> Option<&BTreeMap<String, String>> {
        match self {
            PackageEngines::Map(map) => Some(map),
            _ => None,
        }
    }

    /// Looks up an engine constraint by engine name.
    /// Handles map, list, string, and arbitrary JSON object/array representations.
    pub fn get(&self, engine: &str) -> Option<String> {
        self.get_str(engine).map(str::to_string)
    }

    /// Looks up an engine constraint by engine name, returning a borrowed slice if possible.
    pub fn get_str<'a>(&'a self, engine: &str) -> Option<&'a str> {
        match self {
            PackageEngines::Map(map) => map.get(engine).map(|s| s.as_str()),
            PackageEngines::List(list) => {
                for item in list {
                    if let Some(s) = item.as_str() {
                        for (name, range) in parse_engine_entries_from_str(s) {
                            if name == engine {
                                return Some(range);
                            }
                        }
                    }
                }
                None
            }
            PackageEngines::String(s) => {
                for (name, range) in parse_engine_entries_from_str(s) {
                    if name == engine {
                        return Some(range);
                    }
                }
                None
            }
            PackageEngines::Other(serde_json::Value::Object(obj)) => {
                obj.get(engine).and_then(|v| v.as_str())
            }
            PackageEngines::Other(serde_json::Value::Array(arr)) => {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        for (name, range) in parse_engine_entries_from_str(s) {
                            if name == engine {
                                return Some(range);
                            }
                        }
                    }
                }
                None
            }
            PackageEngines::Other(serde_json::Value::String(s)) => {
                for (name, range) in parse_engine_entries_from_str(s) {
                    if name == engine {
                        return Some(range);
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Returns true if this engines representation contains no constraints.
    pub fn is_empty(&self) -> bool {
        match self {
            PackageEngines::Map(map) => map.is_empty(),
            PackageEngines::List(list) => list.is_empty(),
            PackageEngines::String(s) => s.trim().is_empty(),
            PackageEngines::Other(serde_json::Value::Null) => true,
            PackageEngines::Other(serde_json::Value::Object(obj)) => obj.is_empty(),
            PackageEngines::Other(serde_json::Value::Array(arr)) => arr.is_empty(),
            _ => false,
        }
    }
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

fn parse_engine_entry_str(entry: &str) -> Option<(&str, &str)> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((idx, ch)) = trimmed.char_indices().find(|(_, c)| c.is_whitespace() || *c == '@') {
        let name = trimmed[..idx].trim();
        let range = trimmed[idx + ch.len_utf8()..].trim();
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

fn parse_engine_entry(entry: &str) -> Option<(String, String)> {
    parse_engine_entry_str(entry).map(|(n, r)| (n.to_string(), r.to_string()))
}

impl Default for PackageEngines {
    fn default() -> Self {
        PackageEngines::Map(BTreeMap::new())
    }
}

impl From<BTreeMap<String, String>> for PackageEngines {
    fn from(map: BTreeMap<String, String>) -> Self {
        PackageEngines::Map(map)
    }
}

impl From<std::collections::HashMap<String, String>> for PackageEngines {
    fn from(map: std::collections::HashMap<String, String>) -> Self {
        PackageEngines::Map(map.into_iter().collect())
    }
}

impl FromIterator<(String, String)> for PackageEngines {
    fn from_iter<T: IntoIterator<Item = (String, String)>>(iter: T) -> Self {
        PackageEngines::Map(iter.into_iter().collect())
    }
}

impl From<Vec<String>> for PackageEngines {
    fn from(list: Vec<String>) -> Self {
        PackageEngines::List(list.into_iter().map(serde_json::Value::String).collect())
    }
}

impl From<String> for PackageEngines {
    fn from(s: String) -> Self {
        PackageEngines::String(s)
    }
}

impl From<&str> for PackageEngines {
    fn from(s: &str) -> Self {
        PackageEngines::String(s.to_string())
    }
}

/// Package executable configuration: single path or named binaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageBin {
    Single(String),
    Map(BTreeMap<String, String>),
}

impl Serialize for PackageBin {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            PackageBin::Single(s) => s.serialize(serializer),
            PackageBin::Map(m) => m.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for PackageBin {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PackageBinVisitor;
        impl<'de> Visitor<'de> for PackageBinVisitor {
            type Value = PackageBin;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a string or a map of binary names to paths")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(PackageBin::Single(v.to_owned()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(PackageBin::Single(v))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut out = BTreeMap::new();
                while let Some((k, v)) = map.next_entry::<String, String>()? {
                    out.insert(k, v);
                }
                Ok(PackageBin::Map(out))
            }
        }
        deserializer.deserialize_any(PackageBinVisitor)
    }
}

pub(crate) fn license_from_value(val: &serde_json::Value) -> Option<String> {
    match val {
        serde_json::Value::String(s) => {
            if s.is_empty() {
                None
            } else {
                Some(s.clone())
            }
        }
        serde_json::Value::Object(map) => map
            .get("type")
            .and_then(|v| v.as_str())
            .or_else(|| map.get("name").and_then(|v| v.as_str()))
            .map(str::to_string),
        serde_json::Value::Array(arr) => {
            let mut out = String::new();
            let mut any = false;
            for item in arr {
                if let Some(s) = item.as_str() {
                    if any {
                        out.push_str(" OR ");
                    }
                    any = true;
                    out.push_str(s);
                }
            }
            if any {
                Some(out)
            } else {
                None
            }
        }
        _ => None,
    }
}

struct OptString(Option<String>);

impl<'de> Deserialize<'de> for OptString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OptStringVisitor;
        impl<'de> Visitor<'de> for OptStringVisitor {
            type Value = OptString;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(OptString(Some(v.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(OptString(Some(v)))
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(OptString(None))
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(OptString(None))
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(OptString(None))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(OptString(None))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(OptString(None))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(OptString(None))
            }
            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
                Self::Value::deserialize(d)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(OptString(None))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                while map
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(OptString(None))
            }
        }
        deserializer.deserialize_any(OptStringVisitor)
    }
}

pub(crate) enum KeyStr<'de> {
    Borrowed(&'de str),
    Owned(String),
}

impl<'de> KeyStr<'de> {
    #[inline]
    pub(crate) fn as_str(&self) -> &str {
        match self {
            KeyStr::Borrowed(s) => s,
            KeyStr::Owned(s) => s.as_str(),
        }
    }

    #[inline]
    pub(crate) fn into_string(self) -> String {
        match self {
            KeyStr::Borrowed(s) => s.to_owned(),
            KeyStr::Owned(s) => s,
        }
    }
}

impl<'de> Deserialize<'de> for KeyStr<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeyStrVisitor;
        impl<'de> Visitor<'de> for KeyStrVisitor {
            type Value = KeyStr<'de>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a string key")
            }
            fn visit_borrowed_str<E: serde::de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
                Ok(KeyStr::Borrowed(v))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(KeyStr::Owned(v.to_owned()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(KeyStr::Owned(v))
            }
        }
        deserializer.deserialize_str(KeyStrVisitor)
    }
}

struct LicenseSeed;

impl<'de> DeserializeSeed<'de> for LicenseSeed {
    type Value = Option<String>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserialize_license(deserializer)
    }
}

/// Helper deserializer to tolerate object or array license forms and extract the license type/expression.
pub(crate) fn deserialize_license<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct LicenseVisitor;
    impl<'de> Visitor<'de> for LicenseVisitor {
        type Value = Option<String>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a license string, object, or array")
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            if v.is_empty() {
                Ok(None)
            } else {
                Ok(Some(v.to_owned()))
            }
        }
        fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
            if v.is_empty() {
                Ok(None)
            } else {
                Ok(Some(v))
            }
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            deserialize_license(d)
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut type_val: Option<String> = None;
            let mut name_val: Option<String> = None;
            while let Some(key) = map.next_key::<KeyStr<'de>>()? {
                match key.as_str() {
                    "type" => type_val = map.next_value::<OptString>()?.0,
                    "name" => name_val = map.next_value::<OptString>()?.0,
                    _ => {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
            }
            Ok(type_val.or(name_val))
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = String::new();
            let mut any = false;
            while let Some(OptString(opt)) = seq.next_element::<OptString>()? {
                if let Some(s) = opt {
                    if any {
                        out.push_str(" OR ");
                    }
                    any = true;
                    out.push_str(&s);
                }
            }
            if any {
                Ok(Some(out))
            } else {
                Ok(None)
            }
        }
    }
    deserializer.deserialize_any(LicenseVisitor)
}

/// Metadata for a package node in lockfile v3 `packages`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct LockfilePackage {
    /// Internal marker used for freshly generated npm 11 lockfiles. npm 11
    /// writes `dev` and `optional` separately for a package reachable only
    /// through a dev optional branch; older lockfiles may still use the
    /// combined `devOptional` field.
    #[serde(skip)]
    pub preserve_dev_optional_split: bool,

    /// Raw JSON value captured on disk to preserve untouched key ordering.
    #[serde(skip)]
    pub raw_value: Option<serde_json::Value>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,

    #[serde(skip_serializing_if = "is_false_or_none")]
    pub link: Option<bool>,

    #[serde(skip_serializing_if = "is_false_or_none")]
    pub dev: Option<bool>,

    #[serde(skip_serializing_if = "is_false_or_none")]
    pub optional: Option<bool>,

    #[serde(rename = "devOptional", skip_serializing_if = "is_false_or_none")]
    pub dev_optional: Option<bool>,

    #[serde(skip_serializing_if = "is_false_or_none")]
    pub peer: Option<bool>,

    #[serde(rename = "peerOptional", skip_serializing_if = "is_false_or_none")]
    pub peer_optional: Option<bool>,

    #[serde(rename = "inBundle", skip_serializing_if = "is_false_or_none")]
    pub in_bundle: Option<bool>,

    #[serde(rename = "hasInstallScript", skip_serializing_if = "is_false_or_none")]
    pub has_install_script: Option<bool>,

    #[serde(rename = "hasShrinkwrap", skip_serializing_if = "is_false_or_none")]
    pub has_shrinkwrap: Option<bool>,

    #[serde(skip_serializing_if = "is_false_or_none")]
    pub extraneous: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,

    #[serde(skip_serializing_if = "is_none_or_empty_platform")]
    pub os: Option<PlatformList>,

    #[serde(skip_serializing_if = "is_none_or_empty_platform")]
    pub cpu: Option<PlatformList>,

    #[serde(skip_serializing_if = "is_none_or_empty_platform")]
    pub libc: Option<PlatformList>,

    #[serde(skip_serializing_if = "is_none_or_empty_map")]
    pub dependencies: Option<BTreeMap<String, String>>,

    // npm-normalize-package-bin drops a bin map with no entries.
    #[serde(skip_serializing_if = "bin_is_empty")]
    pub bin: Option<PackageBin>,

    #[serde(rename = "devDependencies", skip_serializing_if = "is_none_or_empty_map")]
    pub dev_dependencies: Option<BTreeMap<String, String>>,

    #[serde(skip_serializing_if = "is_none_or_empty_engines")]
    pub engines: Option<PackageEngines>,

    #[serde(rename = "optionalDependencies", skip_serializing_if = "is_none_or_empty_map")]
    pub optional_dependencies: Option<BTreeMap<String, String>>,

    #[serde(rename = "peerDependencies", skip_serializing_if = "is_none_or_empty_map")]
    pub peer_dependencies: Option<BTreeMap<String, String>>,

    #[serde(rename = "peerDependenciesMeta", skip_serializing_if = "is_none_or_empty_map")]
    pub peer_dependencies_meta: Option<BTreeMap<String, serde_json::Value>>,

    #[serde(rename = "bundleDependencies", skip_serializing_if = "is_empty_bundle_deps")]
    pub bundle_dependencies: Option<BundledDependencies>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspaces: Option<Vec<String>>,

    /// Preserved hidden-tree metadata or arbitrary package properties.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

struct OptStringMapWithRawSeed;

impl<'de> DeserializeSeed<'de> for OptStringMapWithRawSeed {
    type Value = (Option<BTreeMap<String, String>>, serde_json::Value);
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct OptStringMapVisitor;
        impl<'de> Visitor<'de> for OptStringMapVisitor {
            type Value = (Option<BTreeMap<String, String>>, serde_json::Value);
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map of strings or null")
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok((None, serde_json::Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok((None, serde_json::Value::Null))
            }
            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
                d.deserialize_any(self)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut pkg_map = BTreeMap::new();
                let mut raw_map = serde_json::Map::with_capacity(map.size_hint().unwrap_or(4));
                while let Some((k, v)) = map.next_entry::<String, String>()? {
                    raw_map.insert(k.clone(), serde_json::Value::String(v.clone()));
                    pkg_map.insert(k, v);
                }
                Ok((Some(pkg_map), serde_json::Value::Object(raw_map)))
            }
        }
        deserializer.deserialize_any(OptStringMapVisitor)
    }
}

fn platform_list_from_json_value<E: serde::de::Error>(
    val: &serde_json::Value,
) -> Result<Option<PlatformList>, E> {
    match val {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) => Ok(Some(PlatformList::from(s.clone()))),
        serde_json::Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item
                    .as_str()
                    .ok_or_else(|| E::custom("expected a string in platform array"))?;
                out.push(s.to_owned());
            }
            Ok(Some(PlatformList::from(out)))
        }
        _ => Err(E::custom("expected a string or an array of strings")),
    }
}

fn bin_from_json_value<E: serde::de::Error>(
    val: &serde_json::Value,
) -> Result<Option<PackageBin>, E> {
    match val {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) => Ok(Some(PackageBin::Single(s.clone()))),
        serde_json::Value::Object(map) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                let s = v
                    .as_str()
                    .ok_or_else(|| E::custom("expected string value in bin map"))?;
                out.insert(k.clone(), s.to_owned());
            }
            Ok(Some(PackageBin::Map(out)))
        }
        _ => Err(E::custom("expected a string or a map of binary names to paths")),
    }
}

fn engines_from_json_value(val: &serde_json::Value) -> Option<PackageEngines> {
    match val {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(PackageEngines::String(s.clone())),
        serde_json::Value::Array(arr) => Some(PackageEngines::List(arr.clone())),
        serde_json::Value::Object(map) => {
            let mut str_map = BTreeMap::new();
            for (k, v) in map {
                if let Some(s) = v.as_str() {
                    str_map.insert(k.clone(), s.to_owned());
                } else {
                    return Some(PackageEngines::Other(val.clone()));
                }
            }
            Some(PackageEngines::Map(str_map))
        }
        other => Some(PackageEngines::Other(other.clone())),
    }
}

fn peer_meta_from_json_value<E: serde::de::Error>(
    val: &serde_json::Value,
) -> Result<Option<BTreeMap<String, serde_json::Value>>, E> {
    match val {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Object(map) => Ok(Some(
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        )),
        _ => Err(E::custom("expected a map or null for peerDependenciesMeta")),
    }
}

fn bundle_deps_from_json_value<E: serde::de::Error>(
    val: &serde_json::Value,
) -> Result<Option<BundledDependencies>, E> {
    match val {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Bool(b) => Ok(Some(BundledDependencies::Boolean(*b))),
        serde_json::Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item
                    .as_str()
                    .ok_or_else(|| E::custom("expected string in bundleDependencies"))?;
                out.push(s.to_owned());
            }
            Ok(Some(BundledDependencies::List(out)))
        }
        serde_json::Value::Object(map) => Ok(Some(BundledDependencies::List(
            map.keys().cloned().collect(),
        ))),
        _ => Err(E::custom("expected a boolean, array of strings, or object for bundleDependencies")),
    }
}

fn string_vec_from_json_value<E: serde::de::Error>(
    val: &serde_json::Value,
) -> Result<Option<Vec<String>>, E> {
    match val {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item
                    .as_str()
                    .ok_or_else(|| E::custom("expected string in workspaces"))?;
                out.push(s.to_owned());
            }
            Ok(Some(out))
        }
        _ => Err(E::custom("expected an array of strings or null for workspaces")),
    }
}

#[inline]
fn mark_seen<E: serde::de::Error>(seen: &mut u32, bit: u32, field: &'static str) -> Result<(), E> {
    if (*seen & bit) != 0 {
        return Err(E::duplicate_field(field));
    }
    *seen |= bit;
    Ok(())
}

pub(crate) struct LockfilePackageSeed {
    pub(crate) capture_raw: bool,
    pub(crate) normalize: bool,
}

impl<'de> DeserializeSeed<'de> for LockfilePackageSeed {
    type Value = LockfilePackage;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct LockfilePackageVisitor {
            capture_raw: bool,
            normalize: bool,
        }

        impl<'de> Visitor<'de> for LockfilePackageVisitor {
            type Value = LockfilePackage;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a lockfile package object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut pkg = LockfilePackage::default();
                let mut raw_map = if self.capture_raw {
                    Some(serde_json::Map::with_capacity(map.size_hint().unwrap_or(8)))
                } else {
                    None
                };
                let mut seen: u32 = 0;

                while let Some(key) = map.next_key::<KeyStr<'de>>()? {
                    let ks = key.as_str();
                    macro_rules! raw_str_opt {
                        ($field:ident, $bit:expr, $fname:expr) => {{
                            mark_seen(&mut seen, 1 << $bit, $fname)?;
                            let v = map.next_value::<Option<String>>()?;
                            if let Some(ref mut rm) = raw_map {
                                let rv = match &v {
                                    Some(s) => serde_json::Value::String(s.clone()),
                                    None => serde_json::Value::Null,
                                };
                                rm.insert(key.into_string(), rv);
                            }
                            pkg.$field = v;
                        }};
                    }
                    macro_rules! raw_bool_opt {
                        ($field:ident, $bit:expr, $fname:expr) => {{
                            mark_seen(&mut seen, 1 << $bit, $fname)?;
                            let v = map.next_value::<Option<bool>>()?;
                            if let Some(ref mut rm) = raw_map {
                                let rv = match v {
                                    Some(b) => serde_json::Value::Bool(b),
                                    None => serde_json::Value::Null,
                                };
                                rm.insert(key.into_string(), rv);
                            }
                            pkg.$field = v;
                        }};
                    }
                    macro_rules! raw_map_opt {
                        ($field:ident, $bit:expr, $fname:expr) => {{
                            mark_seen(&mut seen, 1 << $bit, $fname)?;
                            if let Some(ref mut rm) = raw_map {
                                let (parsed, rv) = map.next_value_seed(OptStringMapWithRawSeed)?;
                                rm.insert(key.into_string(), rv);
                                pkg.$field = parsed;
                            } else {
                                pkg.$field = map.next_value::<Option<BTreeMap<String, String>>>()?;
                            }
                        }};
                    }

                    match ks {
                        "name" => raw_str_opt!(name, 0, "name"),
                        "version" => raw_str_opt!(version, 1, "version"),
                        "resolved" => raw_str_opt!(resolved, 2, "resolved"),
                        "integrity" | "_integrity" => raw_str_opt!(integrity, 3, "integrity"),
                        "link" => raw_bool_opt!(link, 4, "link"),
                        "dev" => raw_bool_opt!(dev, 5, "dev"),
                        "optional" => raw_bool_opt!(optional, 6, "optional"),
                        "devOptional" => raw_bool_opt!(dev_optional, 7, "devOptional"),
                        "peer" => raw_bool_opt!(peer, 8, "peer"),
                        "peerOptional" => raw_bool_opt!(peer_optional, 9, "peerOptional"),
                        "inBundle" | "bundled" => raw_bool_opt!(in_bundle, 10, "inBundle"),
                        "hasInstallScript" => {
                            raw_bool_opt!(has_install_script, 11, "hasInstallScript")
                        }
                        "hasShrinkwrap" | "_hasShrinkwrap" => {
                            raw_bool_opt!(has_shrinkwrap, 12, "hasShrinkwrap")
                        }
                        "extraneous" => raw_bool_opt!(extraneous, 13, "extraneous"),
                        "license" => {
                            mark_seen(&mut seen, 1 << 14, "license")?;
                            if let Some(ref mut rm) = raw_map {
                                let rv = map.next_value::<serde_json::Value>()?;
                                pkg.license = license_from_value(&rv);
                                rm.insert(key.into_string(), rv);
                            } else {
                                pkg.license = map.next_value_seed(LicenseSeed)?;
                            }
                        }
                        "os" => {
                            mark_seen(&mut seen, 1 << 15, "os")?;
                            if let Some(ref mut rm) = raw_map {
                                let rv = map.next_value::<serde_json::Value>()?;
                                pkg.os = platform_list_from_json_value(&rv)?;
                                rm.insert(key.into_string(), rv);
                            } else {
                                pkg.os = map.next_value::<Option<PlatformList>>()?;
                            }
                        }
                        "cpu" => {
                            mark_seen(&mut seen, 1 << 16, "cpu")?;
                            if let Some(ref mut rm) = raw_map {
                                let rv = map.next_value::<serde_json::Value>()?;
                                pkg.cpu = platform_list_from_json_value(&rv)?;
                                rm.insert(key.into_string(), rv);
                            } else {
                                pkg.cpu = map.next_value::<Option<PlatformList>>()?;
                            }
                        }
                        "libc" => {
                            mark_seen(&mut seen, 1 << 17, "libc")?;
                            if let Some(ref mut rm) = raw_map {
                                let rv = map.next_value::<serde_json::Value>()?;
                                pkg.libc = platform_list_from_json_value(&rv)?;
                                rm.insert(key.into_string(), rv);
                            } else {
                                pkg.libc = map.next_value::<Option<PlatformList>>()?;
                            }
                        }
                        "dependencies" => raw_map_opt!(dependencies, 18, "dependencies"),
                        "bin" => {
                            mark_seen(&mut seen, 1 << 19, "bin")?;
                            if let Some(ref mut rm) = raw_map {
                                let rv = map.next_value::<serde_json::Value>()?;
                                pkg.bin = bin_from_json_value(&rv)?;
                                rm.insert(key.into_string(), rv);
                            } else {
                                pkg.bin = map.next_value::<Option<PackageBin>>()?;
                            }
                        }
                        "devDependencies" => {
                            raw_map_opt!(dev_dependencies, 20, "devDependencies")
                        }
                        "engines" => {
                            mark_seen(&mut seen, 1 << 21, "engines")?;
                            if let Some(ref mut rm) = raw_map {
                                let rv = map.next_value::<serde_json::Value>()?;
                                pkg.engines = engines_from_json_value(&rv);
                                rm.insert(key.into_string(), rv);
                            } else {
                                pkg.engines = map.next_value::<Option<PackageEngines>>()?;
                            }
                        }
                        "optionalDependencies" => {
                            raw_map_opt!(optional_dependencies, 22, "optionalDependencies")
                        }
                        "peerDependencies" => {
                            raw_map_opt!(peer_dependencies, 23, "peerDependencies")
                        }
                        "peerDependenciesMeta" => {
                            mark_seen(&mut seen, 1 << 24, "peerDependenciesMeta")?;
                            if let Some(ref mut rm) = raw_map {
                                let rv = map.next_value::<serde_json::Value>()?;
                                pkg.peer_dependencies_meta = peer_meta_from_json_value(&rv)?;
                                rm.insert(key.into_string(), rv);
                            } else {
                                pkg.peer_dependencies_meta = map
                                    .next_value::<Option<BTreeMap<String, serde_json::Value>>>()?;
                            }
                        }
                        "bundleDependencies" | "bundledDependencies" => {
                            mark_seen(&mut seen, 1 << 25, "bundleDependencies")?;
                            if let Some(ref mut rm) = raw_map {
                                let rv = map.next_value::<serde_json::Value>()?;
                                pkg.bundle_dependencies = bundle_deps_from_json_value(&rv)?;
                                rm.insert(key.into_string(), rv);
                            } else {
                                pkg.bundle_dependencies =
                                    map.next_value::<Option<BundledDependencies>>()?;
                            }
                        }
                        "workspaces" => {
                            mark_seen(&mut seen, 1 << 26, "workspaces")?;
                            if let Some(ref mut rm) = raw_map {
                                let rv = map.next_value::<serde_json::Value>()?;
                                pkg.workspaces = string_vec_from_json_value(&rv)?;
                                rm.insert(key.into_string(), rv);
                            } else {
                                pkg.workspaces = map.next_value::<Option<Vec<String>>>()?;
                            }
                        }
                        _ => {
                            let val = map.next_value::<serde_json::Value>()?;
                            let is_dir = ks == "directories";
                            let is_falsy_deprecated = ks == "deprecated"
                                && (val == serde_json::Value::Bool(false)
                                    || val.is_null()
                                    || val == "");
                            if self.normalize && (is_dir || is_falsy_deprecated) {
                                if is_falsy_deprecated {
                                    pkg.extra.remove("deprecated");
                                }
                                if let Some(ref mut rm) = raw_map {
                                    rm.insert(key.into_string(), val);
                                }
                            } else {
                                let key_owned = key.into_string();
                                if let Some(ref mut rm) = raw_map {
                                    rm.insert(key_owned.clone(), val.clone());
                                }
                                pkg.extra.insert(key_owned, val);
                            }
                        }
                    }
                }

                if self.normalize {
                    pkg.normalize_flags_keeping_raw();
                }
                if let Some(rm) = raw_map {
                    pkg.raw_value = Some(serde_json::Value::Object(rm));
                }

                Ok(pkg)
            }
        }

        deserializer.deserialize_map(LockfilePackageVisitor {
            capture_raw: self.capture_raw,
            normalize: self.normalize,
        })
    }
}

impl<'de> Deserialize<'de> for LockfilePackage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        LockfilePackageSeed {
            capture_raw: false,
            normalize: false,
        }
        .deserialize(deserializer)
    }
}

impl LockfilePackage {
    /// Returns true if this package is a development dependency (`dev: true`).
    pub fn is_dev(&self) -> bool {
        self.dev == Some(true)
    }

    /// Returns true if this package is an optional dependency (`optional: true`).
    pub fn is_optional(&self) -> bool {
        self.optional == Some(true)
    }

    /// Returns true if this package is both dev and optional (`devOptional: true`).
    pub fn is_dev_optional(&self) -> bool {
        self.dev_optional == Some(true)
    }

    /// Returns true if this package is needed for development (either `dev: true` or `devOptional: true`).
    pub fn is_effective_dev(&self) -> bool {
        self.is_dev() || self.is_dev_optional()
    }

    /// Returns true if this package is optional (either `optional: true` or `devOptional: true`).
    pub fn is_effective_optional(&self) -> bool {
        self.is_optional() || self.is_dev_optional()
    }

    /// Returns true if this package is a peer dependency (`peer: true`).
    pub fn is_peer(&self) -> bool {
        self.peer == Some(true)
    }

    /// Returns true if this package is an optional peer dependency (`peerOptional: true`).
    pub fn is_peer_optional(&self) -> bool {
        self.peer_optional == Some(true)
    }

    /// Returns true if this package is bundled in its parent package (`inBundle: true`).
    pub fn is_in_bundle(&self) -> bool {
        self.in_bundle == Some(true)
    }

    /// Returns true if this package has an install or postinstall lifecycle script (`hasInstallScript: true`).
    pub fn has_install_script(&self) -> bool {
        self.has_install_script == Some(true)
    }

    /// Returns true if this package contains a shrinkwrap file (`hasShrinkwrap: true`).
    pub fn has_shrinkwrap(&self) -> bool {
        self.has_shrinkwrap == Some(true)
    }

    /// Returns true if this package is marked extraneous (`extraneous: true`).
    pub fn is_extraneous(&self) -> bool {
        self.extraneous == Some(true)
            || self.extra.get("extraneous") == Some(&serde_json::Value::Bool(true))
    }

    /// Returns true if this package is a symlink or workspace link (`link: true`).
    pub fn is_link(&self) -> bool {
        self.link == Some(true)
    }

    /// Sets the `dev` flag (clearing `false` to `None`).
    pub fn set_dev(&mut self, val: bool) {
        self.dev = if val { Some(true) } else { None };
        self.raw_value = None;
    }

    /// `$name` override references of this package, in arborist's edge.js
    /// lookup order: dev, optional, dependencies, peer. The first non-empty
    /// spec wins (an empty string is falsy in arborist).
    pub fn all_dependency_specs(&self) -> BTreeMap<String, String> {
        let mut specs = BTreeMap::new();
        for section in [
            &self.peer_dependencies,
            &self.dependencies,
            &self.optional_dependencies,
            &self.dev_dependencies,
        ]
        .into_iter()
        .flatten()
        {
            for (name, spec) in section {
                if !spec.is_empty() {
                    specs.insert(name.clone(), spec.clone());
                }
            }
        }
        specs
    }

    pub fn with_dev(mut self, val: bool) -> Self {
        self.set_dev(val);
        self
    }

    /// Sets the `optional` flag (clearing `false` to `None`).
    pub fn set_optional(&mut self, val: bool) {
        self.optional = if val { Some(true) } else { None };
        self.raw_value = None;
    }

    pub fn with_optional(mut self, val: bool) -> Self {
        self.set_optional(val);
        self
    }

    /// Sets the `devOptional` flag (clearing `false` to `None`).
    pub fn set_dev_optional(&mut self, val: bool) {
        self.dev_optional = if val { Some(true) } else { None };
        self.raw_value = None;
    }

    pub fn with_dev_optional(mut self, val: bool) -> Self {
        self.set_dev_optional(val);
        self
    }

    /// Sets the `peer` flag (clearing `false` to `None`).
    pub fn set_peer(&mut self, val: bool) {
        self.peer = if val { Some(true) } else { None };
        self.raw_value = None;
    }

    pub fn with_peer(mut self, val: bool) -> Self {
        self.set_peer(val);
        self
    }

    /// Sets the `peerOptional` flag (clearing `false` to `None`).
    pub fn set_peer_optional(&mut self, val: bool) {
        self.peer_optional = if val { Some(true) } else { None };
        self.raw_value = None;
    }

    pub fn with_peer_optional(mut self, val: bool) -> Self {
        self.set_peer_optional(val);
        self
    }

    /// Sets the `inBundle` flag (clearing `false` to `None`).
    pub fn set_in_bundle(&mut self, val: bool) {
        self.in_bundle = if val { Some(true) } else { None };
        self.raw_value = None;
    }

    pub fn with_in_bundle(mut self, val: bool) -> Self {
        self.set_in_bundle(val);
        self
    }

    /// Sets the `hasInstallScript` flag (clearing `false` to `None`).
    pub fn set_has_install_script(&mut self, val: bool) {
        self.has_install_script = if val { Some(true) } else { None };
        self.raw_value = None;
    }

    pub fn with_has_install_script(mut self, val: bool) -> Self {
        self.set_has_install_script(val);
        self
    }

    /// Sets the `hasShrinkwrap` flag (clearing `false` to `None`).
    pub fn set_has_shrinkwrap(&mut self, val: bool) {
        self.has_shrinkwrap = if val { Some(true) } else { None };
        self.raw_value = None;
    }

    pub fn with_has_shrinkwrap(mut self, val: bool) -> Self {
        self.set_has_shrinkwrap(val);
        self
    }

    /// Sets the `link` flag (clearing `false` to `None`).
    pub fn set_link(&mut self, val: bool) {
        self.link = if val { Some(true) } else { None };
        self.raw_value = None;
    }

    pub fn with_link(mut self, val: bool) -> Self {
        self.set_link(val);
        self
    }

    /// Sets npm dependency relationship rules:
    /// - If both `is_dev` and `is_optional` are true, sets `dev: true` and `optional: true` (npm 11 / lockfile v3 parity).
    /// - If only `is_dev` is true, sets `dev: true`.
    /// - If only `is_optional` is true, sets `optional: true`.
    /// - If neither, clears all three flags.
    pub fn set_dependency_types(&mut self, is_dev: bool, is_optional: bool) {
        self.raw_value = None;
        if is_dev && is_optional {
            self.dev = Some(true);
            self.optional = Some(true);
            self.dev_optional = None;
        } else if is_dev {
            self.dev = Some(true);
            self.dev_optional = None;
            self.optional = None;
        } else if is_optional {
            self.optional = Some(true);
            self.dev = None;
            self.dev_optional = None;
        } else {
            self.dev = None;
            self.optional = None;
            self.dev_optional = None;
        }
    }

    /// Returns the engines map if available, converting from map/list/string formats.
    pub fn engines_map(&self) -> Option<BTreeMap<String, String>> {
        self.engines.as_ref().and_then(|e| e.as_map())
    }

    /// Normalizes boolean flags to ensure npm lockfile v3 fidelity:
    /// - If legacy `devOptional: true` is set, clears `dev` and `optional`.
    /// - For npm 11 / lockfile v3, packages reachable via dev and optional branches retain `dev: true, optional: true`.
    /// - Any `false` boolean flags are normalized to `None`.
    pub fn normalize_flags(&mut self) {
        self.raw_value = None;
        self.normalize_flags_keeping_raw();
    }

    pub(crate) fn normalize_flags_keeping_raw(&mut self) {
        if self.dev == Some(false) {
            self.dev = None;
        }
        if self.optional == Some(false) {
            self.optional = None;
        }
        if self.dev_optional == Some(false) {
            self.dev_optional = None;
        }
        if self.peer == Some(false) {
            self.peer = None;
        }
        if self.peer_optional == Some(false) {
            self.peer_optional = None;
        }
        if self.in_bundle == Some(false) {
            self.in_bundle = None;
        }
        if self.has_install_script == Some(false) {
            self.has_install_script = None;
        }
        if self.has_shrinkwrap == Some(false) {
            self.has_shrinkwrap = None;
        }
        if self.link == Some(false) {
            self.link = None;
        }

        if self.dev_optional == Some(true) {
            self.dev = None;
            self.optional = None;
        }

        if let Some(os) = &self.os {
            if os.is_empty() {
                self.os = None;
            }
        }
        if let Some(cpu) = &self.cpu {
            if cpu.is_empty() {
                self.cpu = None;
            }
        }
        if let Some(libc) = &self.libc {
            if libc.is_empty() {
                self.libc = None;
            }
        }
        if let Some(e) = &self.engines {
            if e.is_empty() {
                self.engines = None;
            }
        }

        self.extra.remove("directories");
        if let Some(v) = self.extra.get("deprecated") {
            if v == &serde_json::Value::Bool(false) || v.is_null() || v == "" {
                self.extra.remove("deprecated");
            }
        }
    }

    /// Returns list of package names that are marked as bundled in this package.
    pub fn bundled_package_names(&self) -> Vec<String> {
        match &self.bundle_dependencies {
            None => {
                if let Some(extra_val) = self
                    .extra
                    .get("bundleDependencies")
                    .or_else(|| self.extra.get("bundledDependencies"))
                {
                    if let Some(list) = extra_val.as_array() {
                        return list
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect();
                    } else if let Some(b) = extra_val.as_bool() {
                        if b {
                            return self
                                .dependencies
                                .as_ref()
                                .map(|d| d.keys().cloned().collect())
                                .unwrap_or_default();
                        }
                    }
                }
                Vec::new()
            }
            Some(BundledDependencies::Boolean(true)) => self
                .dependencies
                .as_ref()
                .map(|d| d.keys().cloned().collect())
                .unwrap_or_default(),
            Some(BundledDependencies::Boolean(false)) => Vec::new(),
            Some(BundledDependencies::List(list)) => list.clone(),
        }
    }

    /// Checks if a dependency is marked as an optional peer dependency in `peerDependenciesMeta`.
    pub fn is_peer_dep_optional(&self, dep_name: &str) -> bool {
        let Some(meta_map) = &self.peer_dependencies_meta else {
            return false;
        };
        let Some(val) = meta_map.get(dep_name) else {
            return false;
        };
        val.get("optional")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Sets or unsets `optional: true` for a peer dependency in `peerDependenciesMeta`.
    pub fn set_peer_dep_optional(&mut self, dep_name: impl Into<String>, optional: bool) {
        self.raw_value = None;
        let name = dep_name.into();
        if optional {
            let map = self
                .peer_dependencies_meta
                .get_or_insert_with(BTreeMap::new);
            map.insert(name, serde_json::json!({ "optional": true }));
        } else if let Some(map) = &mut self.peer_dependencies_meta {
            map.remove(&name);
            if map.is_empty() {
                self.peer_dependencies_meta = None;
            }
        }
    }
}

/// npm `package-lock.json` lockfile version 3 document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LockfileV3 {
    // npm omits root metadata from the hidden lock with --no-package-lock.
    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[serde(rename = "lockfileVersion")]
    pub lockfile_version: u32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires: Option<bool>,

    /// Node packages keyed by their POSIX forward-slash path (e.g. `""`, `"node_modules/foo"`).
    /// Sorted keys via `BTreeMap` guarantee deterministic byte output across runs.
    pub packages: BTreeMap<String, LockfilePackage>,
}

fn read_packages_map<'de, A: MapAccess<'de>>(
    mut map: A,
    capture_raw: bool,
    normalize: bool,
    normalize_keys: bool,
) -> Result<BTreeMap<String, LockfilePackage>, A::Error> {
    let mut packages = BTreeMap::new();
    while let Some(key) = map.next_key::<String>()? {
        let pkg = map.next_value_seed(LockfilePackageSeed {
            capture_raw,
            normalize,
        })?;
        let norm_key = if normalize_keys {
            match to_posix_path_cow(&key) {
                std::borrow::Cow::Borrowed(_) => key,
                std::borrow::Cow::Owned(s) => s,
            }
        } else {
            key
        };
        packages.insert(norm_key, pkg);
    }
    Ok(packages)
}

pub(crate) struct PackagesMapSeed {
    pub(crate) capture_raw: bool,
    pub(crate) normalize: bool,
    pub(crate) normalize_keys: bool,
}

impl<'de> DeserializeSeed<'de> for PackagesMapSeed {
    type Value = BTreeMap<String, LockfilePackage>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct PackagesMapVisitor {
            capture_raw: bool,
            normalize: bool,
            normalize_keys: bool,
        }

        impl<'de> Visitor<'de> for PackagesMapVisitor {
            type Value = BTreeMap<String, LockfilePackage>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map of package paths to package entries")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                read_packages_map(map, self.capture_raw, self.normalize, self.normalize_keys)
            }
        }

        deserializer.deserialize_map(PackagesMapVisitor {
            capture_raw: self.capture_raw,
            normalize: self.normalize,
            normalize_keys: self.normalize_keys,
        })
    }
}

pub(crate) enum OptPackagesField {
    Null,
    Map(BTreeMap<String, LockfilePackage>),
}

pub(crate) struct OptPackagesMapSeed {
    pub(crate) capture_raw: bool,
    pub(crate) normalize: bool,
    pub(crate) normalize_keys: bool,
}

impl<'de> DeserializeSeed<'de> for OptPackagesMapSeed {
    type Value = OptPackagesField;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct OptPackagesMapVisitor {
            capture_raw: bool,
            normalize: bool,
            normalize_keys: bool,
        }

        impl<'de> Visitor<'de> for OptPackagesMapVisitor {
            type Value = OptPackagesField;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map of package paths or null")
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(OptPackagesField::Null)
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(OptPackagesField::Null)
            }

            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
                d.deserialize_any(self)
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                read_packages_map(map, self.capture_raw, self.normalize, self.normalize_keys)
                    .map(OptPackagesField::Map)
            }
        }

        deserializer.deserialize_any(OptPackagesMapVisitor {
            capture_raw: self.capture_raw,
            normalize: self.normalize,
            normalize_keys: self.normalize_keys,
        })
    }
}

pub(crate) struct LockfileVersionSeed;

impl<'de> DeserializeSeed<'de> for LockfileVersionSeed {
    type Value = u32;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        crate::migration::deserialize_lockfile_version(deserializer)
    }
}

pub(crate) struct LockfileV3Seed {
    pub(crate) capture_raw: bool,
    pub(crate) normalize: bool,
    pub(crate) normalize_keys: bool,
}

impl<'de> DeserializeSeed<'de> for LockfileV3Seed {
    type Value = LockfileV3;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct LockfileV3Visitor {
            capture_raw: bool,
            normalize: bool,
            normalize_keys: bool,
        }

        impl<'de> Visitor<'de> for LockfileV3Visitor {
            type Value = LockfileV3;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a lockfile v3 object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut name: Option<String> = None;
                let mut version: Option<Option<String>> = None;
                let mut lockfile_version: Option<u32> = None;
                let mut requires: Option<Option<bool>> = None;
                let mut packages: Option<BTreeMap<String, LockfilePackage>> = None;

                while let Some(key) = map.next_key::<KeyStr<'de>>()? {
                    match key.as_str() {
                        "name" => {
                            if name.is_some() {
                                return Err(serde::de::Error::duplicate_field("name"));
                            }
                            name = Some(map.next_value()?);
                        }
                        "version" => {
                            if version.is_some() {
                                return Err(serde::de::Error::duplicate_field("version"));
                            }
                            version = Some(map.next_value()?);
                        }
                        "lockfileVersion" => {
                            if lockfile_version.is_some() {
                                return Err(serde::de::Error::duplicate_field("lockfileVersion"));
                            }
                            lockfile_version = Some(map.next_value_seed(LockfileVersionSeed)?);
                        }
                        "requires" => {
                            if requires.is_some() {
                                return Err(serde::de::Error::duplicate_field("requires"));
                            }
                            requires = Some(map.next_value()?);
                        }
                        "packages" => {
                            if packages.is_some() {
                                return Err(serde::de::Error::duplicate_field("packages"));
                            }
                            packages = Some(map.next_value_seed(PackagesMapSeed {
                                capture_raw: self.capture_raw,
                                normalize: self.normalize,
                                normalize_keys: self.normalize_keys,
                            })?);
                        }
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                Ok(LockfileV3 {
                    name: name.unwrap_or_default(),
                    version: version.unwrap_or(None),
                    lockfile_version: lockfile_version
                        .unwrap_or_else(crate::migration::default_lockfile_version),
                    requires: requires.unwrap_or(None),
                    packages: packages.unwrap_or_default(),
                })
            }
        }

        deserializer.deserialize_map(LockfileV3Visitor {
            capture_raw: self.capture_raw,
            normalize: self.normalize,
            normalize_keys: self.normalize_keys,
        })
    }
}

impl<'de> Deserialize<'de> for LockfileV3 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        LockfileV3Seed {
            capture_raw: false,
            normalize: false,
            normalize_keys: false,
        }
        .deserialize(deserializer)
    }
}

// Shrinkwrap.inferFormattingOptions takes formatting from package.json, even
// when an existing lockfile uses another newline or indentation style.
fn project_lockfile_format(
    project_dir: &Path,
    fallbacks: &[std::path::PathBuf],
) -> rnpm_core::ManifestFormat {
    let all_paths: Vec<_> = std::iter::once(project_dir.join("package.json"))
        .chain(fallbacks.iter().cloned())
        .collect();

    let mut detected_indent = None;
    let mut detected_newline = None;

    for path in all_paths {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            let fmt = rnpm_core::ManifestFormat::detect(&raw);
            if detected_indent.is_none() && !fmt.indent.is_empty() {
                detected_indent = Some(fmt.indent);
            }
            if detected_newline.is_none() && !fmt.newline.is_empty() {
                detected_newline = Some(fmt.newline);
            }
            if detected_indent.is_some() && detected_newline.is_some() {
                break;
            }
        }
    }

    rnpm_core::ManifestFormat {
        indent: detected_indent.unwrap_or_else(|| rnpm_core::ManifestFormat::default().indent),
        newline: detected_newline.unwrap_or_else(|| rnpm_core::ManifestFormat::default().newline),
        trailing_newline: true,
        has_bom: false,
    }
}

impl LockfileV3 {
    /// Create a new LockfileV3 with an empty root package `""`.
    pub fn new(name: impl Into<String>, version: Option<String>) -> Self {
        let name_str = name.into();
        let mut packages = BTreeMap::new();
        packages.insert(
            "".to_string(),
            LockfilePackage {
                name: Some(name_str.clone()),
                version: version.clone(),
                ..Default::default()
            },
        );

        Self {
            name: name_str,
            version,
            lockfile_version: 3,
            requires: Some(true),
            packages,
        }
    }

    /// Insert a package into the lockfile, normalizing the path to POSIX forward slashes.
    pub fn insert_package(&mut self, path: &str, mut package: LockfilePackage) {
        let posix_key = to_posix_path(path);
        package.normalize_flags();
        self.packages.insert(posix_key, package);
    }

    /// Retrieve a package by path, normalizing the lookup key to POSIX forward slashes.
    pub fn get_package(&self, path: &str) -> Option<&LockfilePackage> {
        let posix_key = to_posix_path(path);
        self.packages.get(&posix_key)
    }

    /// Remove a package by path, normalizing the lookup key to POSIX forward slashes.
    pub fn remove_package(&mut self, path: &str) -> Option<LockfilePackage> {
        let posix_key = to_posix_path(path);
        self.packages.remove(&posix_key)
    }

    /// Access the root package `""`.
    pub fn root_package(&self) -> Option<&LockfilePackage> {
        self.packages.get("")
    }

    /// Access mutable reference to the root package `""`.
    pub fn root_package_mut(&mut self) -> Option<&mut LockfilePackage> {
        let pkg = self.packages.get_mut("")?;
        pkg.raw_value = None;
        Some(pkg)
    }

    /// Create a new LockfileV3 populated from a `package.json` Manifest.
    pub fn from_manifest(manifest: &rnpm_core::manifest::Manifest) -> Self {
        let name_str = manifest.name.clone().unwrap_or_default();
        let version = manifest.version.clone();
        let mut packages = BTreeMap::new();

        let peer_meta = if manifest.peer_dependencies_meta.is_empty() {
            None
        } else {
            let mut map = BTreeMap::new();
            for (k, v) in &manifest.peer_dependencies_meta {
                if v.optional {
                    map.insert(k.clone(), serde_json::json!({ "optional": true }));
                }
            }
            if map.is_empty() {
                None
            } else {
                Some(map)
            }
        };

        let workspaces_vec = match &manifest.workspaces {
            Some(rnpm_core::manifest::PackageWorkspaces::List(list)) => Some(list.clone()),
            Some(rnpm_core::manifest::PackageWorkspaces::Config { packages }) => {
                Some(packages.clone())
            }
            None => None,
        };

        packages.insert(
            "".to_string(),
            LockfilePackage {
                name: manifest.name.clone(),
                version: manifest.version.clone(),
                dependencies: if manifest.dependencies.is_empty() {
                    None
                } else {
                    Some(manifest.dependencies.clone())
                },
                dev_dependencies: if manifest.dev_dependencies.is_empty() {
                    None
                } else {
                    Some(manifest.dev_dependencies.clone())
                },
                peer_dependencies: if manifest.peer_dependencies.is_empty() {
                    None
                } else {
                    Some(manifest.peer_dependencies.clone())
                },
                peer_dependencies_meta: peer_meta,
                optional_dependencies: if manifest.optional_dependencies.is_empty() {
                    None
                } else {
                    Some(manifest.optional_dependencies.clone())
                },
                bundle_dependencies: manifest.bundled_dependencies.clone(),
                workspaces: workspaces_vec,
                extra: {
                    let mut extra = manifest.extra.clone();
                    extra.remove("overrides");
                    extra.remove("directories");
                    extra.remove("private");
                    if let Some(v) = extra.get("deprecated") {
                        if v == &serde_json::Value::Bool(false) || v.is_null() || v == "" {
                            extra.remove("deprecated");
                        }
                    }
                    extra
                },
                ..Default::default()
            },
        );

        Self {
            name: name_str,
            version,
            lockfile_version: 3,
            requires: Some(true),
            packages,
        }
    }

    /// Synchronize the root package descriptor `""` from a manifest.
    pub fn sync_root_manifest(&mut self, manifest: &rnpm_core::manifest::Manifest) {
        if let Some(name) = &manifest.name {
            self.name = name.clone();
        }
        self.version = manifest.version.clone();

        let root = self.packages.entry("".to_string()).or_default();
        root.name = manifest.name.clone();
        root.version = manifest.version.clone();
        root.dependencies = if manifest.dependencies.is_empty() {
            None
        } else {
            Some(manifest.dependencies.clone())
        };
        root.dev_dependencies = if manifest.dev_dependencies.is_empty() {
            None
        } else {
            Some(manifest.dev_dependencies.clone())
        };
        root.optional_dependencies = if manifest.optional_dependencies.is_empty() {
            None
        } else {
            Some(manifest.optional_dependencies.clone())
        };
        root.peer_dependencies = if manifest.peer_dependencies.is_empty() {
            None
        } else {
            Some(manifest.peer_dependencies.clone())
        };
        root.peer_dependencies_meta = if manifest.peer_dependencies_meta.is_empty() {
            None
        } else {
            let mut map = BTreeMap::new();
            for (k, v) in &manifest.peer_dependencies_meta {
                if v.optional {
                    map.insert(k.clone(), serde_json::json!({ "optional": true }));
                }
            }
            if map.is_empty() {
                None
            } else {
                Some(map)
            }
        };
        root.bundle_dependencies = manifest.bundled_dependencies.clone();
        root.workspaces = match &manifest.workspaces {
            Some(rnpm_core::manifest::PackageWorkspaces::List(list)) => Some(list.clone()),
            Some(rnpm_core::manifest::PackageWorkspaces::Config { packages }) => {
                Some(packages.clone())
            }
            None => None,
        };
        for (k, v) in &manifest.extra {
            if k == "overrides" || k == "directories" {
                continue;
            }
            if k == "deprecated" && (v == &serde_json::Value::Bool(false) || v.is_null() || v == "")
            {
                continue;
            }
            root.extra.insert(k.clone(), v.clone());
        }
        root.extra.remove("overrides");
        root.extra.remove("directories");
        if let Some(v) = root.extra.get("deprecated") {
            if v == &serde_json::Value::Bool(false) || v.is_null() || v == "" {
                root.extra.remove("deprecated");
            }
        }
    }

    /// Normalizes all package keys to POSIX forward slashes and normalizes package flags.
    pub fn normalize(&mut self) {
        let old_packages = std::mem::take(&mut self.packages);
        for (k, mut v) in old_packages {
            v.normalize_flags();
            self.packages.insert(to_posix_path(&k), v);
        }
    }

    /// Populates or updates the flags for a specific package path.
    pub fn populate_package_flags(
        &mut self,
        path: &str,
        dev: Option<bool>,
        optional: Option<bool>,
        dev_optional: Option<bool>,
        peer: Option<bool>,
        peer_optional: Option<bool>,
        in_bundle: Option<bool>,
        has_install_script: Option<bool>,
    ) -> bool {
        let key = to_posix_path(path);
        if let Some(pkg) = self.packages.get_mut(&key) {
            if let Some(v) = dev {
                pkg.set_dev(v);
            }
            if let Some(v) = optional {
                pkg.set_optional(v);
            }
            if let Some(v) = dev_optional {
                pkg.set_dev_optional(v);
            }
            if let Some(v) = peer {
                pkg.set_peer(v);
            }
            if let Some(v) = peer_optional {
                pkg.set_peer_optional(v);
            }
            if let Some(v) = in_bundle {
                pkg.set_in_bundle(v);
            }
            if let Some(v) = has_install_script {
                pkg.set_has_install_script(v);
            }
            pkg.normalize_flags();
            true
        } else {
            false
        }
    }

    /// Iterator over packages that have `dev: true`.
    pub fn dev_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages.iter().filter(|(_, pkg)| pkg.is_dev())
    }

    /// Iterator over packages that have `optional: true`.
    pub fn optional_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages.iter().filter(|(_, pkg)| pkg.is_optional())
    }

    /// Iterator over packages that have `devOptional: true`.
    pub fn dev_optional_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages
            .iter()
            .filter(|(_, pkg)| pkg.is_dev_optional())
    }

    /// Iterator over packages that have `peer: true`.
    pub fn peer_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages.iter().filter(|(_, pkg)| pkg.is_peer())
    }

    /// Iterator over packages that have `peerOptional: true`.
    pub fn peer_optional_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages
            .iter()
            .filter(|(_, pkg)| pkg.is_peer_optional())
    }

    /// Iterator over packages that have `inBundle: true`.
    pub fn bundled_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages.iter().filter(|(_, pkg)| pkg.is_in_bundle())
    }

    /// Iterator over packages that have `hasInstallScript: true`.
    pub fn script_packages(&self) -> impl Iterator<Item = (&String, &LockfilePackage)> {
        self.packages
            .iter()
            .filter(|(_, pkg)| pkg.has_install_script())
    }

    /// Standard relative path to the hidden lockfile inside `node_modules`.
    pub const HIDDEN_LOCKFILE_PATH: &'static str = "node_modules/.package-lock.json";

    /// Checks if this lockfile v3 matches the given package.json manifest.
    /// Returns true if all direct dependencies in the manifest match the root package descriptor,
    /// overrides match, and every required package exists in the lockfile `packages` map satisfying its spec.
    pub fn matches_manifest(
        &self,
        manifest: &rnpm_core::manifest::Manifest,
        include_dev: bool,
    ) -> bool {
        self.matches_manifest_ext(manifest, include_dev, false)
    }

    pub fn matches_manifest_for_ci(
        &self,
        manifest: &rnpm_core::manifest::Manifest,
        include_dev: bool,
    ) -> bool {
        self.matches_manifest_ext_with_workspaces(manifest, include_dev, true, None)
    }

    pub fn matches_manifest_for_ci_with_workspaces(
        &self,
        manifest: &rnpm_core::manifest::Manifest,
        include_dev: bool,
        workspace_members: Option<&[rnpm_core::workspace::WorkspaceMember]>,
    ) -> bool {
        self.matches_manifest_ext_with_workspaces(manifest, include_dev, true, workspace_members)
    }

    pub fn matches_manifest_ext(
        &self,
        manifest: &rnpm_core::manifest::Manifest,
        include_dev: bool,
        allow_extra_lock_deps: bool,
    ) -> bool {
        self.matches_manifest_ext_with_workspaces(manifest, include_dev, allow_extra_lock_deps, None)
    }

    pub fn matches_manifest_ext_with_workspaces(
        &self,
        manifest: &rnpm_core::manifest::Manifest,
        include_dev: bool,
        allow_extra_lock_deps: bool,
        workspace_members: Option<&[rnpm_core::workspace::WorkspaceMember]>,
    ) -> bool {
        let Some(root_pkg) = self.root_package() else {
            return false;
        };

        // Check package name if defined in manifest
        if let Some(ref m_name) = manifest.name {
            if let Some(ref r_name) = root_pkg.name {
                if m_name != r_name {
                    return false;
                }
            }
        }

        // Check package version if defined in manifest
        if let Some(ref m_ver) = manifest.version {
            if let Some(ref r_ver) = root_pkg.version {
                if m_ver != r_ver {
                    return false;
                }
            }
        }

        // 1. Check dependencies
        if !Self::map_matches(
            &self.packages,
            &manifest.dependencies,
            &root_pkg.dependencies,
            allow_extra_lock_deps,
        ) {
            return false;
        }

        // 2. Check devDependencies
        if include_dev
            && !Self::map_matches(
                &self.packages,
                &manifest.dev_dependencies,
                &root_pkg.dev_dependencies,
                allow_extra_lock_deps,
            )
        {
            return false;
        }

        // 3. Check optionalDependencies
        if !Self::map_matches(
            &self.packages,
            &manifest.optional_dependencies,
            &root_pkg.optional_dependencies,
            allow_extra_lock_deps,
        ) {
            return false;
        }

        // 4. Check peerDependencies
        if !Self::map_matches(
            &self.packages,
            &manifest.peer_dependencies,
            &root_pkg.peer_dependencies,
            allow_extra_lock_deps,
        ) {
            return false;
        }

        // 5. Check peerDependenciesMeta
        if !Self::peer_meta_matches(
            &manifest.peer_dependencies_meta,
            &root_pkg.peer_dependencies_meta,
        ) {
            return false;
        }

        // 6. Check bundleDependencies
        if !Self::bundled_deps_matches(manifest, root_pkg) {
            return false;
        }

        // Check workspaces drift
        let manifest_ws: &[String] = match &manifest.workspaces {
            Some(rnpm_core::manifest::PackageWorkspaces::List(list)) => list.as_slice(),
            Some(rnpm_core::manifest::PackageWorkspaces::Config { packages }) => packages.as_slice(),
            None => &[],
        };
        let manifest_has_ws = !manifest_ws.is_empty();
        let root_ws: &[String] = root_pkg.workspaces.as_deref().unwrap_or(&[]);
        let root_has_ws = !root_ws.is_empty();

        if manifest_has_ws && root_has_ws {
            if manifest_ws != root_ws {
                let mut m = manifest_ws.to_vec();
                let mut r = root_ws.to_vec();
                m.sort();
                r.sort();
                if m != r {
                    return false;
                }
            }
        } else if !manifest_has_ws && root_has_ws {
            return false;
        }

        if manifest_has_ws {
            // Validate workspace members and links against manifest patterns and discovered members on disk.
            let patterns = manifest.workspace_patterns();

            // Collect discovered workspace member paths from packages map
            // Exclude any key that has a "node_modules" path segment (e.g. unhoisted packages in packages/member/node_modules/dep)
            let lockfile_member_paths: BTreeSet<String> = self
                .packages
                .keys()
                .filter(|k| !k.is_empty() && !k.split(['/', '\\']).any(|seg| seg == "node_modules"))
                .cloned()
                .collect();

            // Collect available links (target relative paths and link package names)
            let mut available_link_targets = BTreeSet::new();
            let mut available_link_names = BTreeSet::new();

            for (loc, pkg) in &self.packages {
                let mut target_opt = None;
                if pkg.link == Some(true) {
                    if let Some(res) = &pkg.resolved {
                        target_opt = Some(res.as_str());
                    }
                } else if let Some(ver) = &pkg.version {
                    if let Some(t) = ver.strip_prefix("file:") {
                        target_opt = Some(t);
                    }
                } else if let Some(res) = &pkg.resolved {
                    if let Some(t) = res.strip_prefix("file:") {
                        target_opt = Some(t);
                    }
                }

                if let Some(raw_target) = target_opt {
                    let clean = raw_target
                        .strip_prefix("./")
                        .unwrap_or(raw_target)
                        .strip_prefix(".\\")
                        .unwrap_or(raw_target);
                    let posix = clean.replace('\\', "/");
                    let posix = posix.trim_end_matches('/').to_string();
                    available_link_targets.insert(posix);
                    if let Some(name) = loc.strip_prefix("node_modules/") {
                        available_link_names.insert(name.to_string());
                    }
                    if let Some(ref name) = pkg.name {
                        available_link_names.insert(name.clone());
                    }
                }
            }

            if !root_has_ws {
                // All lockfile member paths outside node_modules must match workspace patterns
                for member_path in &lockfile_member_paths {
                    if !Self::path_matches_workspace_patterns(member_path, &patterns) {
                        return false;
                    }
                }
            }

            if let Some(members) = workspace_members {
                // Workspace discovery is available (caller supplied workspace_members).
                // 1. Every discovered member on disk must exist in the lockfile (real npm `ci`
                //    rejects new workspace members on disk that are missing from package-lock.json).
                for member in members {
                    let has_entry = lockfile_member_paths.contains(&member.relative_path)
                        || available_link_targets.contains(&member.relative_path)
                        || available_link_names.contains(&member.name);
                    if !has_entry {
                        return false;
                    }
                }

                // 2 & 3. Strict bidirectional checks (stale/deleted members or link targets).
                // Real npm `ci` (`allow_extra_lock_deps == true`) allows absent lockfile workspace
                // targets (e.g. `eslint` published tarball / `ci-missing-link-target`) and installs
                // dangling links or omits dev links instead of throwing ELOCKFILE_DRIFT.
                if !allow_extra_lock_deps {
                    for member_path in &lockfile_member_paths {
                        if Self::path_matches_workspace_patterns(member_path, &patterns)
                            && !members.iter().any(|m| m.relative_path == *member_path)
                        {
                            return false;
                        }
                    }

                    for link_target in &available_link_targets {
                        if Self::path_matches_workspace_patterns(link_target, &patterns)
                            && !members.iter().any(|m| m.relative_path == *link_target)
                        {
                            return false;
                        }
                    }
                }
            } else if !root_has_ws {
                // Workspace discovery is unavailable (None).
                // Lockfile must have at least one workspace member or link matching patterns.
                let has_matching_member = lockfile_member_paths
                    .iter()
                    .any(|p| Self::path_matches_workspace_patterns(p, &patterns));
                let has_matching_link = available_link_targets
                    .iter()
                    .any(|t| Self::path_matches_workspace_patterns(t, &patterns));

                if !has_matching_member && !has_matching_link {
                    return false;
                }
            }
        } else if !manifest_has_ws && !root_has_ws && !allow_extra_lock_deps {
            use std::ops::Bound::{Excluded, Included, Unbounded};
            let is_non_nm = |k: &String| !k.split(['/', '\\']).any(|seg| seg == "node_modules");
            let has_non_nm_key = self
                .packages
                .range::<str, _>((Excluded(""), Excluded("node_modules/")))
                .any(|(k, _)| is_non_nm(k))
                || self
                    .packages
                    .range::<str, _>((Included("node_modules0"), Unbounded))
                    .any(|(k, _)| is_non_nm(k));
            if has_non_nm_key {
                let link_targets: BTreeSet<String> = self
                    .packages
                    .iter()
                    .filter(|(pkg_key, p)| {
                        if p.link != Some(true) {
                            return false;
                        }
                        let norm_key = to_posix_path_cow(pkg_key);
                        // A direct `node_modules/<dep>` link is only a non-workspace `file:` target
                        // when `<dep>` is declared in the root manifest; otherwise it is an orphaned
                        // workspace link left over after removing `workspaces` from package.json.
                        if let Some(dep_name) = norm_key.strip_prefix("node_modules/") {
                            if !dep_name.contains("node_modules/") {
                                return manifest.dependencies.contains_key(dep_name)
                                    || manifest.dev_dependencies.contains_key(dep_name)
                                    || manifest.optional_dependencies.contains_key(dep_name)
                                    || manifest.peer_dependencies.contains_key(dep_name);
                            }
                        }
                        true
                    })
                    .filter_map(|(_, p)| p.resolved.as_deref().or(p.version.as_deref()))
                    .map(|r| {
                        let s = to_posix_path_cow(r);
                        let s = s.strip_prefix("file:").unwrap_or(s.as_ref());
                        let s = s.strip_prefix("./").unwrap_or(s).trim_end_matches('/');
                        if cfg!(windows) {
                            s.to_ascii_lowercase()
                        } else {
                            s.to_string()
                        }
                    })
                    .collect();
                let has_lockfile_members = self.packages.keys().any(|k| {
                    if k.is_empty() || k.split(['/', '\\']).any(|seg| seg == "node_modules") {
                        return false;
                    }
                    let norm = to_posix_path_cow(k);
                    let norm = norm.strip_prefix("file:").unwrap_or(norm.as_ref());
                    let norm = norm
                        .strip_prefix("./")
                        .unwrap_or(norm)
                        .trim_end_matches('/');
                    let key_to_check = if cfg!(windows) {
                        norm.to_ascii_lowercase()
                    } else {
                        norm.to_string()
                    };
                    !link_targets.contains(&key_to_check)
                });
                if has_lockfile_members {
                    return false;
                }
            }
        }

        // Check direct overrides (skip entirely if manifest has no "overrides" field)
        let overrides = if manifest.extra.contains_key("overrides") {
            rnpm_core::overrides::Overrides::from_manifest(manifest)
                .ok()
                .filter(|ov| !ov.rules.is_empty())
        } else {
            None
        };
        let mut key_buf = String::with_capacity(64);

        if let Some(ref ov) = overrides {
            for rule_key in ov.rules.keys() {
                let dep_name: std::borrow::Cow<'_, str> = rule_key
                    .split_once('@')
                    .map(|(name, _)| {
                        if name.is_empty() && rule_key.starts_with('@') {
                            if let Some((sub_name, _)) = rule_key[1..].split_once('@') {
                                std::borrow::Cow::Owned(format!("@{sub_name}"))
                            } else {
                                std::borrow::Cow::Borrowed(rule_key.as_str())
                            }
                        } else if name.is_empty() {
                            std::borrow::Cow::Borrowed(rule_key.as_str())
                        } else {
                            std::borrow::Cow::Borrowed(name)
                        }
                    })
                    .unwrap_or(std::borrow::Cow::Borrowed(rule_key.as_str()));

                key_buf.clear();
                key_buf.push_str("node_modules/");
                key_buf.push_str(&dep_name);
                if let Some(pkg) = self.packages.get(key_buf.as_str()) {
                    let req_spec = pkg.version.as_deref().unwrap_or("*");
                    if let Ok(Some(eff_spec)) = ov.resolve_override(&dep_name, req_spec, &[]) {
                        if !Self::package_satisfies_spec(&dep_name, pkg, &eff_spec) {
                            return false;
                        }
                    }
                }
            }
        }

        // 7. Verify direct dependencies exist in packages map and satisfy specs
        for (dep, spec) in &manifest.dependencies {
            if manifest.optional_dependencies.contains_key(dep) {
                continue;
            }
            if !self.check_direct_dep_entry(
                dep,
                spec,
                root_pkg.dependencies.as_ref(),
                overrides.as_ref(),
                false,
                &mut key_buf,
            ) {
                return false;
            }
        }

        // 8. Verify direct devDependencies exist in packages map and satisfy specs
        if include_dev {
            for (dep, spec) in &manifest.dev_dependencies {
                if !self.check_direct_dep_entry(
                    dep,
                    spec,
                    root_pkg.dev_dependencies.as_ref(),
                    overrides.as_ref(),
                    false,
                    &mut key_buf,
                ) {
                    return false;
                }
            }
        }

        // 9. Verify optional dependencies in packages map satisfy specs if present
        for (dep, spec) in &manifest.optional_dependencies {
            if !self.check_direct_dep_entry(
                dep,
                spec,
                root_pkg.optional_dependencies.as_ref(),
                overrides.as_ref(),
                true,
                &mut key_buf,
            ) {
                return false;
            }
        }

        // 10. Verify peer dependencies in packages map
        for (dep, spec) in &manifest.peer_dependencies {
            let is_optional = manifest
                .peer_dependencies_meta
                .get(dep)
                .map(|m| m.optional)
                .unwrap_or_else(|| root_pkg.is_peer_dep_optional(dep));
            if !self.check_direct_dep_entry(
                dep,
                spec,
                root_pkg.peer_dependencies.as_ref(),
                overrides.as_ref(),
                is_optional,
                &mut key_buf,
            ) {
                return false;
            }
        }

        true
    }

    fn check_direct_dep_entry(
        &self,
        dep: &str,
        spec: &str,
        lock_map: Option<&BTreeMap<String, String>>,
        overrides: Option<&rnpm_core::overrides::Overrides>,
        allow_missing_pkg: bool,
        key_buf: &mut String,
    ) -> bool {
        key_buf.clear();
        key_buf.push_str("node_modules/");
        key_buf.push_str(dep);
        let pkg = self.packages.get(key_buf.as_str());
        if pkg.is_none() && !allow_missing_pkg {
            return false;
        }
        let eff_spec: std::borrow::Cow<'_, str> = if let Some(ov) = overrides {
            ov.resolve_override(dep, spec, &[])
                .ok()
                .flatten()
                .map(std::borrow::Cow::Owned)
                .unwrap_or(std::borrow::Cow::Borrowed(spec))
        } else {
            std::borrow::Cow::Borrowed(spec)
        };
        if let Some(lock_spec) = lock_map.and_then(|m| m.get(dep)) {
            if lock_spec != eff_spec.as_ref() {
                let eff_non_reg = Self::is_non_registry_spec(&eff_spec);
                let lock_non_reg = Self::is_non_registry_spec(lock_spec);
                if eff_non_reg != lock_non_reg
                    || (eff_non_reg && !Self::non_registry_specs_match(&eff_spec, lock_spec))
                {
                    return false;
                }
            }
        }
        if let Some(pkg) = pkg {
            Self::package_satisfies_spec(dep, pkg, &eff_spec)
        } else {
            allow_missing_pkg
        }
    }

    pub fn path_matches_workspace_patterns(path: &str, patterns: &[String]) -> bool {
        rnpm_core::workspace::path_matches_workspace_patterns(path, patterns)
    }

    pub fn package_satisfies_spec(install_name: &str, pkg: &LockfilePackage, spec: &str) -> bool {
        if pkg.link != Some(true) {
            if let Some(ref ver_str) = pkg.version {
                let trimmed = spec.trim();
                let bytes = trimmed.as_bytes();
                let is_non_alias_semver = trimmed.is_empty()
                    || trimmed == "*"
                    || (!bytes.is_empty()
                        && (matches!(bytes[0], b'^' | b'>' | b'<')
                            || (bytes[0] == b'~' && !trimmed.starts_with("~/"))
                            || bytes[0] == b'='
                            || ((bytes[0].is_ascii_digit()
                                || ((bytes[0] == b'v' || bytes[0] == b'V')
                                    && bytes.len() > 1
                                    && bytes[1].is_ascii_digit()))
                                && !trimmed.contains(':')
                                && !trimmed.contains('/')
                                && !trimmed.contains('@'))));

                if is_non_alias_semver {
                    if let Some(ref real_name) = pkg.name {
                        if real_name != install_name {
                            return false;
                        }
                    }
                    if let Ok(v) = Version::parse(ver_str) {
                        if trimmed.is_empty() || trimmed == "*" {
                            return true;
                        }
                        if matches!(bytes[0], b'^' | b'>' | b'<') || bytes[0] == b'~' {
                            if let Ok(matched) =
                                rnpm_core::semver::Range::satisfies_str(trimmed, &v)
                            {
                                return matched;
                            }
                        } else {
                            if let Ok(expected) = Version::parse(trimmed) {
                                return v == expected;
                            }
                            if let Ok(matched) =
                                rnpm_core::semver::Range::satisfies_str(trimmed, &v)
                            {
                                return matched;
                            }
                        }
                    }
                } else if !bytes.is_empty()
                    && bytes[0].is_ascii_alphabetic()
                    && !matches!(bytes[0], b'v' | b'V' | b'x' | b'X')
                    && bytes
                        .iter()
                        .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
                {
                    if let Some(ref real_name) = pkg.name {
                        if real_name != install_name {
                            return false;
                        }
                    }
                    return true;
                }
            }
        }
        let Ok(target) = PackageTarget::parse(spec) else {
            // Handle SCP-like git specs (e.g. git@host:path#ref) or ssh:// that PackageTarget doesn't parse
            if spec.starts_with("git@") || spec.starts_with("ssh://") {
                if let Some(ref real_name) = pkg.name {
                    if real_name != install_name {
                        return false;
                    }
                }
                if let Some(ref res) = pkg.resolved {
                    let canon_target = Self::canonicalize_git_identity(spec);
                    let canon_res = Self::canonicalize_git_identity(res);
                    if canon_target != canon_res {
                        return false;
                    }
                    let target_frag = spec.split('#').nth(1).unwrap_or("");
                    if !target_frag.is_empty() {
                        if let Some(semver_spec) = Self::extract_git_semver_range(target_frag) {
                            let Some(ver_str) = pkg.version.as_deref() else {
                                return false;
                            };
                            let (Ok(range), Ok(ver)) = (
                                rnpm_core::semver::Range::parse(semver_spec.trim()),
                                Version::parse(ver_str),
                            ) else {
                                return false;
                            };
                            if !range.satisfies(&ver) {
                                return false;
                            }
                        }
                        let res_frag = res.split('#').nth(1).unwrap_or("");
                        if res_frag.is_empty() {
                            return false;
                        }
                        if Self::git_refs_equal(res_frag, target_frag) {
                            return true;
                        }
                        let res_is_sha = res_frag.len() >= 7
                            && res_frag.chars().all(|ch| ch.is_ascii_hexdigit());
                        let target_is_sha = target_frag.len() >= 7
                            && target_frag.chars().all(|ch| ch.is_ascii_hexdigit());
                        if target_is_sha {
                            return Self::git_refs_equal(res_frag, target_frag);
                        }
                        return res_is_sha;
                    }
                    return true;
                }
            }
            return false;
        };
        if pkg.link == Some(true) {
            match &target {
                PackageTarget::Alias { name, target } => {
                    if pkg.name.as_deref() != Some(name) {
                        return false;
                    }
                    if let PackageTarget::File(_) = &**target {
                        if let Some(ref res) = pkg.resolved {
                            return Self::target_matches_resolved(res, target);
                        }
                    }
                }
                PackageTarget::File(_) => {
                    if let Some(ref res) = pkg.resolved {
                        return Self::target_matches_resolved(res, &target);
                    }
                }
                _ => {}
            }
            return true;
        }
        let Some(ref ver_str) = pkg.version else {
            if let Some(ref res) = pkg.resolved {
                return Self::target_matches_resolved(res, &target);
            }
            return false;
        };
        match &target {
            PackageTarget::Alias { name, target } => {
                if pkg.name.as_deref() != Some(name) {
                    return false;
                }
                Self::version_matches_target(ver_str, target, pkg.resolved.as_deref())
            }
            other => {
                if let Some(ref real_name) = pkg.name {
                    if real_name != install_name {
                        return false;
                    }
                }
                Self::version_matches_target(ver_str, other, pkg.resolved.as_deref())
            }
        }
    }

    fn is_posix_path_absolute(p: &str) -> bool {
        p.starts_with('/')
            || (p.len() >= 2
                && p.as_bytes()[0].is_ascii_alphabetic()
                && p.as_bytes()[1] == b':')
    }

    fn canonicalize_git_identity(raw: &str) -> String {
        let s = raw.split('#').next().unwrap_or(raw).trim();
        let s = s.split('?').next().unwrap_or(s).trim();
        let s = s.strip_prefix("git+").unwrap_or(s);
        let s = if s.starts_with("git:") && !s.starts_with("git://") {
            s.strip_prefix("git:").unwrap_or(s)
        } else {
            s
        };

        let expanded = if let Some(rest) = s.strip_prefix("github:") {
            format!("github.com/{rest}")
        } else if let Some(rest) = s.strip_prefix("gitlab:") {
            format!("gitlab.com/{rest}")
        } else if let Some(rest) = s.strip_prefix("bitbucket:") {
            format!("bitbucket.org/{rest}")
        } else if let Some(rest) = s.strip_prefix("gist:") {
            format!("gist.github.com/{rest}")
        } else if !s.contains(':') && !s.contains('@') && s.split('/').count() == 2 {
            format!("github.com/{s}")
        } else {
            s.to_string()
        };

        let (had_scheme, without_proto) = if let Some(idx) = expanded.find("://") {
            (true, &expanded[idx + 3..])
        } else {
            (false, expanded.as_str())
        };

        let without_user = if let Some(at_idx) = without_proto.find('@') {
            let slash_idx = without_proto.find('/').unwrap_or(usize::MAX);
            let should_strip = if had_scheme {
                at_idx < slash_idx
            } else {
                let colon_idx = without_proto.find(':').unwrap_or(usize::MAX);
                at_idx < colon_idx && at_idx < slash_idx
            };
            if should_strip {
                &without_proto[at_idx + 1..]
            } else {
                without_proto
            }
        } else {
            without_proto
        };

        let normalized = if !had_scheme {
            if let Some((host, path)) = without_user.split_once(':') {
                let path = path.trim_start_matches('/');
                if !host.contains('/') && !path.is_empty() {
                    format!("{host}/{path}")
                } else {
                    without_user.to_string()
                }
            } else {
                without_user.to_string()
            }
        } else {
            without_user.to_string()
        };

        let trimmed = normalized.trim_matches('/');
        let clean = trimmed.strip_suffix(".git").unwrap_or(trimmed);
        clean.to_ascii_lowercase()
    }

    fn percent_decode(s: &str) -> String {
        let mut bytes = Vec::with_capacity(s.len());
        let mut chars = s.bytes();
        while let Some(b) = chars.next() {
            if b == b'%' {
                let h1 = chars.next();
                let h2 = chars.next();
                if let (Some(h1), Some(h2)) = (h1, h2) {
                    if let Ok(val) =
                        u8::from_str_radix(std::str::from_utf8(&[h1, h2]).unwrap_or(""), 16)
                    {
                        bytes.push(val);
                        continue;
                    }
                    bytes.push(b'%');
                    bytes.push(h1);
                    bytes.push(h2);
                } else {
                    bytes.push(b'%');
                    if let Some(h1) = h1 {
                        bytes.push(h1);
                    }
                }
            } else {
                bytes.push(b);
            }
        }
        String::from_utf8(bytes).unwrap_or_else(|_| s.to_string())
    }

    pub fn extract_git_semver_range(ref_str: &str) -> Option<String> {
        let s = ref_str.trim();
        let raw = s
            .strip_prefix("semver:")
            .or_else(|| s.strip_prefix("semver%3A"))
            .or_else(|| s.strip_prefix("semver%3a"))?;
        let decoded = Self::percent_decode(raw);
        Some(decoded.trim().to_string())
    }

    /// Compares two git ref fragments: hex commit SHAs match case-insensitively (full or prefix >= 7 chars),
    /// semver ranges match semver equivalence (including #semver:^1.0.0 and #semver%3A^1.0.0),
    /// while named branches/tags match case-sensitively (matching git & npm).
    pub fn git_refs_equal(a: &str, b: &str) -> bool {
        if a == b {
            return true;
        }

        // SemVer git range comparisons: e.g. semver:^1.0.0 vs semver%3A^1.0.0 or semver: ^1.0.0
        if let (Some(range_a), Some(range_b)) = (
            Self::extract_git_semver_range(a),
            Self::extract_git_semver_range(b),
        ) {
            if range_a == range_b {
                return true;
            }
            if let (Ok(ra), Ok(rb)) = (
                rnpm_core::semver::Range::parse(&range_a),
                rnpm_core::semver::Range::parse(&range_b),
            ) {
                return ra == rb;
            }
            return false;
        }

        let a_is_hex = a.chars().all(|c| c.is_ascii_hexdigit());
        let b_is_hex = b.chars().all(|c| c.is_ascii_hexdigit());
        if a_is_hex && b_is_hex {
            let a_is_full_sha = a.len() == 40 || a.len() == 64;
            let b_is_full_sha = b.len() == 40 || b.len() == 64;

            // Same-length hex commit refs (>= 7 chars) match case-insensitively
            if a.len() == b.len() && a.len() >= 7 {
                return a.eq_ignore_ascii_case(b);
            }

            // Prefix matching: ONLY allow when at least ONE operand is a full 40-char (SHA-1)
            // or 64-char (SHA-256) hex commit SHA and the other is a >= 7-char hex prefix
            if (a_is_full_sha && b.len() >= 7) || (b_is_full_sha && a.len() >= 7) {
                let min_len = a.len().min(b.len());
                return a[..min_len].eq_ignore_ascii_case(&b[..min_len]);
            }
        }

        false
    }

    pub fn is_non_registry_spec(spec: &str) -> bool {
        let s = spec.trim();
        if s.is_empty() {
            return false;
        }

        // npm: alias specifier wrapping an inner spec: e.g. npm:pkg@spec or npm:@scope/pkg@spec
        if let Some(rest) = s.strip_prefix("npm:") {
            let inner = if let Some(stripped_scope) = rest.strip_prefix('@') {
                if let Some(slash_idx) = stripped_scope.find('/') {
                    let after_slash = &stripped_scope[slash_idx + 1..];
                    if let Some(at_idx) = after_slash.find('@') {
                        &after_slash[at_idx + 1..]
                    } else {
                        ""
                    }
                } else {
                    ""
                }
            } else if let Some(at_idx) = rest.find('@') {
                &rest[at_idx + 1..]
            } else {
                ""
            };
            if !inner.is_empty() {
                return Self::is_non_registry_spec(inner);
            }
            return false;
        }

        // Direct protocol and path prefixes
        if s.starts_with("file:")
            || s.starts_with("link:")
            || s.starts_with("git:")
            || s.starts_with("git+")
            || s.starts_with("github:")
            || s.starts_with("gitlab:")
            || s.starts_with("bitbucket:")
            || s.starts_with("gist:")
            || s.starts_with("ssh://")
            || rnpm_core::is_scp_git_url(s)
            || s.starts_with("./")
            || s.starts_with(".\\")
            || s.starts_with("../")
            || s.starts_with("..\\")
            || s.starts_with('/')
            || s.starts_with("~/")
            || s.starts_with("http://")
            || s.starts_with("https://")
        {
            return true;
        }

        // Windows drive path like C:\ or C:/
        let b = s.as_bytes();
        if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
            return true;
        }

        // Tarball archive suffixes (.tgz, .tar.gz, .tar) before any query or fragment
        let without_hash = s.split('#').next().unwrap_or(s);
        let without_query = without_hash.split('?').next().unwrap_or(without_hash);
        if without_query.ends_with(".tgz")
            || without_query.ends_with(".tar.gz")
            || without_query.ends_with(".tar")
        {
            return true;
        }

        // GitHub shorthand: user/repo or user/repo#committish
        let (body, _) = s.split_once('#').unwrap_or((s, ""));
        if let Some((user, repo)) = body.split_once('/') {
            let user_ok = user
                .chars()
                .next()
                .is_some_and(|c| !matches!(c, '@' | '%' | '/' | '.' | '-') && !c.is_whitespace())
                && !user
                    .chars()
                    .any(|c| matches!(c, ':' | '@' | '%' | '/') || c.is_whitespace());
            let repo_ok = !repo.is_empty()
                && !repo
                    .chars()
                    .any(|c| matches!(c, '@' | '/' | '%') || c.is_whitespace());
            if user_ok && repo_ok {
                return true;
            }
        }

        // Checked against PackageTarget::parse
        if let Ok(target) = PackageTarget::parse(s) {
            match target {
                PackageTarget::Git { .. }
                | PackageTarget::File(_)
                | PackageTarget::Url(_) => return true,
                PackageTarget::Alias { target, .. } => {
                    match *target {
                        PackageTarget::Git { .. }
                        | PackageTarget::File(_)
                        | PackageTarget::Url(_) => return true,
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        false
    }

    pub fn non_registry_specs_match(spec_a: &str, spec_b: &str) -> bool {
        let a = spec_a.trim();
        let b = spec_b.trim();
        if a == b {
            return true;
        }

        // Handle npm: aliases
        let a_alias = a.strip_prefix("npm:");
        let b_alias = b.strip_prefix("npm:");
        if a_alias.is_some() != b_alias.is_some() {
            return false;
        }
        if let (Some(a_rest), Some(b_rest)) = (a_alias, b_alias) {
            let parse_alias_parts = |rest: &str| -> (String, String) {
                if let Some(stripped_scope) = rest.strip_prefix('@') {
                    if let Some(slash_idx) = stripped_scope.find('/') {
                        let after_slash = &stripped_scope[slash_idx + 1..];
                        if let Some(at_idx) = after_slash.find('@') {
                            let name = format!("@{}", &stripped_scope[..slash_idx + 1 + at_idx]);
                            let sub_spec = &after_slash[at_idx + 1..];
                            (name, sub_spec.to_string())
                        } else {
                            (format!("@{stripped_scope}"), String::new())
                        }
                    } else {
                        (format!("@{stripped_scope}"), String::new())
                    }
                } else if let Some(at_idx) = rest.find('@') {
                    (rest[..at_idx].to_string(), rest[at_idx + 1..].to_string())
                } else {
                    (rest.to_string(), String::new())
                }
            };
            let (name_a, sub_a) = parse_alias_parts(a_rest);
            let (name_b, sub_b) = parse_alias_parts(b_rest);
            if name_a != name_b {
                return false;
            }
            if sub_a.is_empty() && sub_b.is_empty() {
                return true;
            }
            return Self::non_registry_specs_match(&sub_a, &sub_b);
        }

        // Check if both parse as PackageTarget::Git
        let target_a = PackageTarget::parse(a);
        let target_b = PackageTarget::parse(b);
        if let (
            Ok(PackageTarget::Git {
                url: url_a,
                committish: c_a,
                subdir: s_a,
            }),
            Ok(PackageTarget::Git {
                url: url_b,
                committish: c_b,
                subdir: s_b,
            }),
        ) = (&target_a, &target_b)
        {
            let canon_a = Self::canonicalize_git_identity(url_a.as_str());
            let canon_b = Self::canonicalize_git_identity(url_b.as_str());
            if canon_a != canon_b {
                return false;
            }
            if s_a != s_b {
                return false;
            }
            let c_a_str = c_a.as_deref().unwrap_or("");
            let c_b_str = c_b.as_deref().unwrap_or("");
            return Self::git_refs_equal(c_a_str, c_b_str);
        }

        // Also handle git specs that might not parse via PackageTarget::parse (e.g. git@ or ssh://)
        // as well as GitHub shorthands paired against SCP/ssh specs.
        let is_git_like = |s: &str, parsed: &Result<PackageTarget, _>| {
            matches!(parsed, Ok(PackageTarget::Git { .. }))
                || rnpm_core::is_scp_git_url(s)
                || s.starts_with("ssh://")
                || s.starts_with("git:")
                || s.starts_with("git+")
                || s.starts_with("github:")
                || s.starts_with("gitlab:")
                || s.starts_with("bitbucket:")
                || s.starts_with("gist:")
        };
        if is_git_like(a, &target_a) || is_git_like(b, &target_b) {
            if is_git_like(a, &target_a) && is_git_like(b, &target_b) {
                let canon_a = Self::canonicalize_git_identity(a);
                let canon_b = Self::canonicalize_git_identity(b);
                if canon_a != canon_b {
                    return false;
                }
                let frag_a = a.split('#').nth(1).unwrap_or("");
                let frag_b = b.split('#').nth(1).unwrap_or("");
                return Self::git_refs_equal(frag_a, frag_b);
            }
            return false;
        }

        // Check if both are File specs
        if let (Ok(PackageTarget::File(p_a)), Ok(PackageTarget::File(p_b))) = (&target_a, &target_b) {
            let norm = |p: &std::path::Path| -> String {
                let s = p.to_string_lossy().replace('\\', "/");
                let s = s.strip_prefix("file:").unwrap_or(&s);
                let s = s.strip_prefix("./").unwrap_or(s).trim_end_matches('/').to_string();
                if s == "." {
                    String::new()
                } else {
                    s
                }
            };
            let na = norm(p_a);
            let nb = norm(p_b);
            if cfg!(windows) {
                return na.eq_ignore_ascii_case(&nb);
            } else {
                return na == nb;
            }
        }

        // Also check raw file/link prefixes if PackageTarget::File wasn't returned
        let is_file_prefix = |s: &str| {
            s.starts_with("file:")
                || s.starts_with("link:")
                || s.starts_with("./")
                || s.starts_with(".\\")
                || s.starts_with("../")
                || s.starts_with("..\\")
        };
        if is_file_prefix(a) && is_file_prefix(b) {
            let clean = |s: &str| -> String {
                let s = s.strip_prefix("file:").unwrap_or(s);
                let s = s.strip_prefix("link:").unwrap_or(s);
                let s = s.replace('\\', "/");
                let s = s.strip_prefix("./").unwrap_or(&s).trim_end_matches('/').to_string();
                if s == "." {
                    String::new()
                } else {
                    s
                }
            };
            let ca = clean(a);
            let cb = clean(b);
            if cfg!(windows) {
                return ca.eq_ignore_ascii_case(&cb);
            } else {
                return ca == cb;
            }
        }

        false
    }

    fn target_matches_resolved(resolved: &str, target: &PackageTarget) -> bool {
        match target {
            PackageTarget::Url(u) => resolved == u.as_str(),
            PackageTarget::File(p) => {
                let clean_res = resolved
                    .strip_prefix("file:")
                    .unwrap_or(resolved)
                    .replace('\\', "/");
                let clean_res = clean_res
                    .strip_prefix("./")
                    .unwrap_or(&clean_res)
                    .trim_end_matches('/');
                let clean_res = if clean_res == "." { "" } else { clean_res };
                let clean_p = p.to_str().unwrap_or("").replace('\\', "/");
                let clean_p = clean_p
                    .strip_prefix("./")
                    .unwrap_or(&clean_p)
                    .trim_end_matches('/');
                let clean_p = if clean_p == "." { "" } else { clean_p };

                let res_abs = Self::is_posix_path_absolute(clean_res);
                let p_abs = Self::is_posix_path_absolute(clean_p);

                if res_abs == p_abs {
                    if cfg!(windows) {
                        clean_res.eq_ignore_ascii_case(clean_p)
                    } else {
                        clean_res == clean_p
                    }
                } else if res_abs {
                    let suffix = clean_p.trim_start_matches("../").trim_matches('/');
                    if suffix.is_empty() {
                        false
                    } else if cfg!(windows) {
                        clean_res
                            .to_ascii_lowercase()
                            .ends_with(&format!("/{suffix}").to_ascii_lowercase())
                    } else {
                        clean_res.ends_with(&format!("/{suffix}"))
                    }
                } else {
                    let suffix = clean_res.trim_start_matches("../").trim_matches('/');
                    if suffix.is_empty() {
                        false
                    } else if cfg!(windows) {
                        clean_p
                            .to_ascii_lowercase()
                            .ends_with(&format!("/{suffix}").to_ascii_lowercase())
                    } else {
                        clean_p.ends_with(&format!("/{suffix}"))
                    }
                }
            }
            PackageTarget::Git { url, committish, .. } => {
                let canon_target = Self::canonicalize_git_identity(url.as_str());
                let canon_res = Self::canonicalize_git_identity(resolved);
                if canon_target != canon_res {
                    return false;
                }
                if let Some(ref c) = committish {
                    let res_frag = resolved.split('#').nth(1).unwrap_or("");
                    let c_is_hex = c.len() >= 7 && c.chars().all(|ch| ch.is_ascii_hexdigit());
                    if c_is_hex {
                        if !Self::git_refs_equal(res_frag, c) {
                            return false;
                        }
                    } else if !res_frag.is_empty() {
                        if Self::git_refs_equal(res_frag, c) {
                            return true;
                        }
                        let res_is_sha = res_frag.len() >= 7
                            && res_frag.chars().all(|ch| ch.is_ascii_hexdigit());
                        if !res_is_sha {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                true
            }
            _ => true,
        }
    }

    fn version_matches_target(
        ver_str: &str,
        target: &PackageTarget,
        resolved: Option<&str>,
    ) -> bool {
        match target {
            PackageTarget::Tag(_) => true,
            PackageTarget::Git { committish, .. } => {
                if let Some(res) = resolved {
                    if !Self::target_matches_resolved(res, target) {
                        return false;
                    }
                }
                if let Some(semver_spec) = committish
                    .as_deref()
                    .and_then(Self::extract_git_semver_range)
                {
                    let (Ok(range), Ok(v)) = (
                        rnpm_core::semver::Range::parse(semver_spec.trim()),
                        Version::parse(ver_str),
                    ) else {
                        return false;
                    };
                    return range.satisfies(&v);
                }
                true
            }
            PackageTarget::File(_) | PackageTarget::Url(_) => {
                if let Some(res) = resolved {
                    Self::target_matches_resolved(res, target)
                } else {
                    true
                }
            }
            PackageTarget::Version(expected) => {
                let Ok(v) = Version::parse(ver_str) else {
                    return false;
                };
                &v == expected
            }
            PackageTarget::Range(range) => {
                let Ok(v) = Version::parse(ver_str) else {
                    return false;
                };
                range.satisfies(&v)
            }
            PackageTarget::Workspace(ws_spec) => {
                let s = ws_spec.trim();
                if s == "*" || s == "^" || s == "~" || s.is_empty() {
                    true
                } else if let Ok(range) = rnpm_core::semver::Range::parse(s) {
                    if let Ok(v) = Version::parse(ver_str) {
                        range.satisfies(&v)
                    } else {
                        false
                    }
                } else if let Ok(expected) = Version::parse(s) {
                    if let Ok(v) = Version::parse(ver_str) {
                        v == expected
                    } else {
                        false
                    }
                } else {
                    true
                }
            }
            PackageTarget::Alias { target, .. } => {
                Self::version_matches_target(ver_str, target, resolved)
            }
        }
    }

    fn map_matches(
        packages: &std::collections::BTreeMap<String, LockfilePackage>,
        manifest_map: &std::collections::BTreeMap<String, String>,
        lock_map: &Option<std::collections::BTreeMap<String, String>>,
        allow_extra_lock_deps: bool,
    ) -> bool {
        let lock_len = lock_map.as_ref().map_or(0, |m| m.len());
        if !allow_extra_lock_deps && manifest_map.len() != lock_len {
            return false;
        }
        if manifest_map.is_empty() {
            return true;
        }
        let Some(lock) = lock_map else {
            return false;
        };

        let mut key_buf: Option<String> = None;

        for (k, manifest_spec) in manifest_map {
            let Some(lock_spec) = lock.get(k) else {
                return false;
            };

            if lock_spec == manifest_spec {
                continue;
            }
            // If lock spec is a Version and manifest spec is a Range, check satisfies
            if let Ok(v) = Version::parse(lock_spec) {
                if rnpm_core::semver::Range::satisfies_str(manifest_spec, &v) == Ok(true) {
                    continue;
                }
            }
            // If lock spec is a Range and manifest spec is a Version, check satisfies
            if let Ok(v) = Version::parse(manifest_spec) {
                if rnpm_core::semver::Range::satisfies_str(lock_spec, &v) == Ok(true) {
                    continue;
                }
            }

            // For non-registry specs, check whether they canonically match (e.g. user/repo#v1 vs github:user/repo#v1);
            // any drift in ref/path/identity must reject with false.
            let m_non_reg = Self::is_non_registry_spec(manifest_spec);
            let l_non_reg = Self::is_non_registry_spec(lock_spec);
            if m_non_reg || l_non_reg {
                if m_non_reg
                    && l_non_reg
                    && Self::non_registry_specs_match(manifest_spec, lock_spec)
                {
                    continue;
                }
                return false;
            }

            let m_alias = manifest_spec.starts_with("npm:");
            let l_alias = lock_spec.starts_with("npm:");
            if m_alias != l_alias {
                return false;
            }
            if m_alias && l_alias {
                let Ok(PackageTarget::Alias {
                    name: m_name,
                    target: _m_target,
                }) = PackageTarget::parse(manifest_spec)
                else {
                    return false;
                };
                let Ok(PackageTarget::Alias {
                    name: l_name,
                    target: _l_target,
                }) = PackageTarget::parse(lock_spec)
                else {
                    return false;
                };
                if m_name != l_name {
                    return false;
                }
            }
            let buf = key_buf.get_or_insert_with(|| String::with_capacity(64));
            buf.clear();
            buf.push_str("node_modules/");
            buf.push_str(k);
            let Some(pkg) = packages.get(buf.as_str()) else {
                return false;
            };
            if !Self::package_satisfies_spec(k, pkg, manifest_spec) {
                return false;
            }
        }
        true
    }

    fn peer_meta_matches(
        manifest_meta: &BTreeMap<String, rnpm_core::manifest::PeerDependencyMeta>,
        lock_meta: &Option<BTreeMap<String, serde_json::Value>>,
    ) -> bool {
        let Some(lock_map) = lock_meta else {
            return manifest_meta.values().all(|m| !m.optional);
        };
        if manifest_meta.is_empty() && lock_map.is_empty() {
            return true;
        }
        let mut m_opt_count = 0usize;
        for meta in manifest_meta.values() {
            if meta.optional {
                m_opt_count += 1;
            }
        }
        let mut l_opt_count = 0usize;
        for (k, v) in lock_map {
            if v.get("optional").and_then(|o| o.as_bool()).unwrap_or(false) {
                if !manifest_meta.get(k).is_some_and(|m| m.optional) {
                    return false;
                }
                l_opt_count += 1;
            }
        }
        l_opt_count == m_opt_count
    }

    fn bundled_deps_matches(
        manifest: &rnpm_core::manifest::Manifest,
        root_pkg: &LockfilePackage,
    ) -> bool {
        if manifest.bundled_dependencies.is_none()
            && root_pkg.bundle_dependencies.is_none()
            && !root_pkg.extra.contains_key("bundleDependencies")
            && !root_pkg.extra.contains_key("bundledDependencies")
        {
            return true;
        }
        let mut m_names = manifest.bundled_package_names();
        let mut r_names = root_pkg.bundled_package_names();
        if m_names.is_empty() && r_names.is_empty() {
            return true;
        }
        m_names.sort();
        r_names.sort();
        m_names == r_names
    }

    /// Deterministic serialization to formatted JSON string (2-space indent, trailing newline).
    /// Guarantees strict LF line endings and normalized POSIX forward-slash package keys.
    /// Fast-path avoids cloning the entire package tree when all keys are already normalized POSIX paths.
    pub fn to_json_string(&self) -> Result<String, LockfileError> {
        self.to_json_string_formatted(&rnpm_core::ManifestFormat::default())
    }

    pub fn to_json_string_formatted(
        &self,
        format: &rnpm_core::ManifestFormat,
    ) -> Result<String, LockfileError> {
        self.to_npm_json_string_formatted(format, true)
    }

    /// Serialize using npm's requested lockfile format.  The resolver keeps a
    /// single v3 graph internally, then projects it to the legacy v1/v2
    /// representations only at the filesystem boundary.
    pub fn to_json_string_version(&self, version: u32) -> Result<String, LockfileError> {
        self.to_json_string_version_formatted(version, &rnpm_core::ManifestFormat::default())
    }

    pub fn to_json_string_version_formatted(
        &self,
        version: u32,
        format: &rnpm_core::ManifestFormat,
    ) -> Result<String, LockfileError> {
        if version != 1 && version != 2 && version != 3 {
            return Err(LockfileError::UnsupportedVersion(version));
        }
        let mut out = String::with_capacity(self.packages.len() * 512 + 256);
        let writer = LockfileWriter::new(&format.indent, &format.newline, false, true);
        writer.write_lockfile(self, version, &mut out)?;
        Ok(out)
    }

    /// Serialize to compact single-line JSON without indentation or trailing newline.
    pub fn to_json_string_compact(&self) -> Result<String, LockfileError> {
        self.to_json_string_version_compact(self.lockfile_version)
    }

    /// Serialize using npm's requested lockfile format (1, 2, or 3) in compact single-line JSON.
    pub fn to_json_string_version_compact(&self, version: u32) -> Result<String, LockfileError> {
        if version != 1 && version != 2 && version != 3 {
            return Err(LockfileError::UnsupportedVersion(version));
        }
        let mut out = String::with_capacity(self.packages.len() * 384 + 128);
        let writer = LockfileWriter::new("", "", true, true);
        writer.write_lockfile(self, version, &mut out)?;
        Ok(out)
    }

    pub fn to_json_string_version_formatted_options(
        &self,
        version: u32,
        format: &rnpm_core::ManifestFormat,
        format_package_lock: bool,
    ) -> Result<String, LockfileError> {
        if format_package_lock {
            self.to_json_string_version_formatted(version, format)
        } else {
            self.to_json_string_version_compact(version)
        }
    }

    /// Save using npm lockfile-version semantics (1, 2, or 3).
    /// Copy without `resolved` on registry tarballs when
    /// `omit-lockfile-registry-resolved` is set.
    fn for_writing(&self) -> std::borrow::Cow<'_, Self> {
        let registries = OMIT_REGISTRY_RESOLVED.read().ok().and_then(|g| g.clone());
        let Some(registries) = registries else {
            return std::borrow::Cow::Borrowed(self);
        };
        let is_registry = |r: &str| registries.iter().any(|base| r.starts_with(base.as_str()));
        let mut copy = self.clone();
        for pkg in copy.packages.values_mut() {
            if pkg.resolved.as_deref().is_some_and(is_registry) {
                pkg.resolved = None;
                if let Some(obj) = pkg.raw_value.as_mut().and_then(|v| v.as_object_mut()) {
                    obj.remove("resolved");
                }
            }
        }
        std::borrow::Cow::Owned(copy)
    }

    pub fn save_to_file_version_formatted_option(
        &self,
        path: &Path,
        version: u32,
        format_package_lock: bool,
    ) -> Result<(), LockfileError> {
        let this = self.for_writing();
        let content_source: &Self = this.as_ref();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let root_dir = if parent.ends_with("node_modules") {
            parent.parent().unwrap_or(parent)
        } else {
            parent
        };
        let format = project_lockfile_format(root_dir, &[path.to_path_buf()]);

        let content = if format_package_lock {
            content_source.to_json_string_version_formatted(version, &format)?
        } else {
            content_source.to_json_string_version_compact(version)?
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content)?;
        Ok(())
    }

    pub fn save_to_file_version(&self, path: &Path, version: u32) -> Result<(), LockfileError> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let root_dir = if parent.ends_with("node_modules") {
            parent.parent().unwrap_or(parent)
        } else {
            parent
        };
        let format_package_lock = is_format_package_lock_enabled(root_dir);
        self.save_to_file_version_formatted_option(path, version, format_package_lock)
    }

    fn to_legacy_dependencies(&self) -> serde_json::Value {
        fn package_value(
            dep_name: &str,
            package: &LockfilePackage,
            all_packages: &std::collections::BTreeMap<String, LockfilePackage>,
        ) -> serde_json::Value {
            let mut value = serde_json::Map::new();
            let is_link = package.link == Some(true);
            if let Some(v) = &package.version {
                let ver_str = if let Some(real_name) = &package.name {
                    if real_name != dep_name {
                        format!("npm:{real_name}@{v}")
                    } else {
                        v.clone()
                    }
                } else {
                    v.clone()
                };
                value.insert("version".into(), serde_json::Value::String(ver_str));
            } else if is_link {
                let resolved = package.resolved.as_deref().unwrap_or("");
                let ver_str = if resolved.starts_with("file:") {
                    resolved.to_string()
                } else {
                    format!("file:{resolved}")
                };
                value.insert("version".into(), serde_json::Value::String(ver_str));
            }
            if !is_link {
                if let Some(v) = &package.resolved {
                    value.insert("resolved".into(), serde_json::Value::String(v.clone()));
                }
                if let Some(v) = &package.integrity {
                    value.insert("integrity".into(), serde_json::Value::String(v.clone()));
                }
                if package.dev == Some(true) {
                    value.insert("dev".into(), serde_json::Value::Bool(true));
                }
                if package.optional == Some(true) {
                    value.insert("optional".into(), serde_json::Value::Bool(true));
                }
                if package.dev_optional == Some(true)
                    && package.dev != Some(true)
                    && package.optional != Some(true)
                {
                    value.insert("devOptional".into(), serde_json::Value::Bool(true));
                }
                if package.peer == Some(true) {
                    value.insert("peer".into(), serde_json::Value::Bool(true));
                }
                if package.peer_optional == Some(true) {
                    value.insert("peerOptional".into(), serde_json::Value::Bool(true));
                }
            }
            if package.in_bundle == Some(true) {
                value.insert("bundled".into(), serde_json::Value::Bool(true));
            }
            if package.has_install_script == Some(true) {
                value.insert("hasInstallScript".into(), serde_json::Value::Bool(true));
            }
            if package.has_shrinkwrap == Some(true) {
                value.insert("hasShrinkwrap".into(), serde_json::Value::Bool(true));
            }

            // Build requires from dependencies + optional_dependencies
            // If is_link and package has no dependencies, look up target package in all_packages
            let target_pkg = if is_link {
                let res = package.resolved.as_deref().unwrap_or("");
                let clean_res = res.strip_prefix("file:").unwrap_or(res).replace('\\', "/");
                let clean_res = clean_res
                    .strip_prefix("./")
                    .unwrap_or(&clean_res)
                    .trim_matches('/')
                    .to_string();
                all_packages
                    .get(&clean_res)
                    .or_else(|| {
                        let alt = format!("./{clean_res}");
                        all_packages.get(&alt)
                    })
                    .unwrap_or(package)
            } else {
                package
            };

            let mut requires = BTreeMap::new();
            if let Some(deps) = &target_pkg.dependencies {
                for (k, v) in deps {
                    requires.insert(k.clone(), v.clone());
                }
            }
            if let Some(opt_deps) = &target_pkg.optional_dependencies {
                for (k, v) in opt_deps {
                    requires.insert(k.clone(), v.clone());
                }
            }
            if !requires.is_empty() {
                value.insert(
                    "requires".into(),
                    serde_json::to_value(requires).unwrap_or_default(),
                );
            }
            serde_json::Value::Object(value)
        }

        fn insert_node(
            root: &mut serde_json::Map<String, serde_json::Value>,
            segments: &[&str],
            package: &LockfilePackage,
            all_packages: &std::collections::BTreeMap<String, LockfilePackage>,
        ) {
            if segments.is_empty() {
                return;
            }
            let name = segments[0];
            if segments.len() == 1 {
                root.insert(name.to_string(), package_value(name, package, all_packages));
                return;
            }
            let entry = root
                .entry(name.to_string())
                .or_insert_with(|| serde_json::json!({}));
            let Some(object) = entry.as_object_mut() else {
                return;
            };
            let nested = object
                .entry("dependencies")
                .or_insert_with(|| serde_json::json!({}));
            let Some(nested_obj) = nested.as_object_mut() else {
                return;
            };
            insert_node(nested_obj, &segments[1..], package, all_packages);
        }

        let mut root = serde_json::Map::new();
        let mut keys: Vec<_> = self
            .packages
            .keys()
            .filter(|k| k.starts_with("node_modules/"))
            .collect();
        keys.sort_by_key(|k| k.matches("/node_modules/").count());
        for key in keys {
            let path = key.strip_prefix("node_modules/").unwrap_or(key);
            let segments: Vec<_> = path.split("/node_modules/").collect();
            if let Some(package) = self.packages.get(key) {
                insert_node(&mut root, &segments, package, &self.packages);
            }
        }
        serde_json::Value::Object(root)
    }

    /// Save the lockfile deterministically to disk.
    pub fn save_to_file(&self, path: &Path) -> Result<(), LockfileError> {
        self.save_to_file_version(path, 3)
    }

    /// Load and parse a v3 lockfile from a string, normalizing all package keys to POSIX paths.
    /// Preserves untouched `raw_value` JSON values on packages for 100% round-trip fidelity.
    pub fn from_json_str(s: &str) -> Result<Self, LockfileError> {
        let s = s.strip_prefix('\u{feff}').unwrap_or(s);
        if let Some(lockfile) = crate::fast_parse::try_parse_lockfile_v3_fast(s, true) {
            return Ok(lockfile);
        }
        let mut de = serde_json::Deserializer::from_str(s);
        let lockfile = LockfileV3Seed {
            capture_raw: true,
            normalize: true,
            normalize_keys: true,
        }
        .deserialize(&mut de)?;
        de.end()?;
        Ok(lockfile)
    }

    /// Parse a v3 lockfile in a single serde pass without building `serde_json::Value`
    /// or populating `raw_value`. Zero extra DOM allocations (ideal for `ci` / `fast_path` / `ls`).
    pub fn from_json_str_readonly(content: &str) -> Result<Self, LockfileError> {
        let content = content.strip_prefix('\u{feff}').unwrap_or(content);
        if let Some(lockfile) = crate::fast_parse::try_parse_lockfile_v3_fast(content, false) {
            return Ok(lockfile);
        }
        let mut de = serde_json::Deserializer::from_str(content);
        let lockfile = LockfileV3Seed {
            capture_raw: false,
            normalize: true,
            normalize_keys: true,
        }
        .deserialize(&mut de)?;
        de.end()?;
        Ok(lockfile)
    }

    /// Read and parse a v3 lockfile from disk in a single pass without populating `raw_value`.
    pub fn from_file_readonly(path: &Path) -> Result<Self, LockfileError> {
        let content = fs::read_to_string(path)?;
        Self::from_json_str_readonly(&content)
    }

    /// Alias for `from_file_readonly`.
    pub fn load_from_file_readonly(path: &Path) -> Result<Self, LockfileError> {
        Self::from_file_readonly(path)
    }

    /// Load and parse a v3 lockfile from disk.
    pub fn load_from_file(path: &Path) -> Result<Self, LockfileError> {
        let content = fs::read_to_string(path)?;
        Self::from_json_str(&content)
    }

    /// Alias for `load_from_file`.
    pub fn from_file(path: &Path) -> Result<Self, LockfileError> {
        Self::load_from_file(path)
    }

    /// Load the hidden lockfile from `<project_dir>/node_modules/.package-lock.json`.
    pub fn load_hidden(project_dir: &Path) -> Result<Self, LockfileError> {
        let hidden_path = project_dir.join(Self::HIDDEN_LOCKFILE_PATH);
        Self::load_from_file(&hidden_path)
    }

    /// Save this lockfile as the hidden lockfile at `<project_dir>/node_modules/.package-lock.json`.
    ///
    /// Per npm Arborist parity (`Shrinkwrap` with `hiddenLockfile: true`):
    /// - Lockfile version is always forced to 3 (packages-only, no legacy dependencies).
    /// - Root `""` entry is omitted from `packages`.
    /// - Package entries retain installed metadata (`version`, `resolved`, `integrity`, `engines`, etc.)
    ///   while omitting extraneous fields like `directories`.
    /// - Platform-skipped optional packages (e.g. `fsevents` on Windows) are omitted because
    ///   npm's hidden lockfile lists only what is physically on disk.
    /// - Fields are ordered in npm's `json-stringify-nice` order so diffs against npm are minimal.
    pub fn save_hidden(&self, project_dir: &Path) -> Result<(), LockfileError> {
        self.save_hidden_with_root_metadata(project_dir, true)
    }

    /// A new --no-save install has no persisted root metadata in its hidden lock.
    pub fn save_hidden_with_root_metadata(
        &self,
        project_dir: &Path,
        root_metadata: bool,
    ) -> Result<(), LockfileError> {
        let hidden_path = project_dir.join(Self::HIDDEN_LOCKFILE_PATH);
        let mut hidden = self.for_writing().into_owned();
        hidden.lockfile_version = 3;
        hidden.packages.remove("");
        for pkg in hidden.packages.values_mut() {
            pkg.normalize_flags();
        }

        // Per npm Arborist parity: hidden lockfile lists only what is physically on disk!
        // Do NOT include platform-skipped optional packages (like `fsevents` on Windows).
        hidden.packages.retain(|pkg_key, pkg| {
            if pkg_key.is_empty() {
                return false;
            }
            let disk_path = project_dir.join(pkg_key);
            let exists_on_disk =
                disk_path.exists() || std::fs::symlink_metadata(&disk_path).is_ok();
            if exists_on_disk {
                return true;
            }
            let is_optional = pkg.optional.unwrap_or(false)
                || pkg.dev_optional.unwrap_or(false)
                || pkg.is_effective_optional();
            if is_optional && is_platform_incompatible(pkg) {
                return false;
            }
            if is_optional && project_dir.join("node_modules").is_dir() {
                return false;
            }
            true
        });

        let format = project_lockfile_format(
            project_dir,
            &[
                hidden_path.clone(),
                project_dir.join("npm-shrinkwrap.json"),
                project_dir.join("package-lock.json"),
            ],
        );
        let content = hidden.to_npm_json_string_formatted(&format, root_metadata)?;

        if let Some(parent) = hidden_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&hidden_path, content)?;
        Ok(())
    }

    /// Serializes with npm's `json-stringify-nice` key ordering so diffs against npm are minimal.
    pub fn to_npm_json_string(&self) -> Result<String, LockfileError> {
        self.to_npm_json_string_formatted(&rnpm_core::ManifestFormat::default(), true)
    }

    pub fn to_npm_json_string_formatted(
        &self,
        format: &rnpm_core::ManifestFormat,
        root_metadata: bool,
    ) -> Result<String, LockfileError> {
        let mut out = String::with_capacity(self.packages.len() * 512 + 256);
        let writer = LockfileWriter::new(&format.indent, &format.newline, false, root_metadata);
        writer.write_lockfile(self, self.lockfile_version, &mut out)?;
        Ok(out)
    }
}

pub const SW_KEY_ORDER: &[&str] = &[
    "name",
    "version",
    "lockfileVersion",
    "resolved",
    "integrity",
    "requires",
    "packages",
    "dependencies",
];

#[inline]
fn sw_key_rank(k: &str) -> u8 {
    match k.len() {
        4 if k == "name" => 0,
        7 if k == "version" => 1,
        15 if k == "lockfileVersion" => 2,
        8 => match k {
            "resolved" => 3,
            "requires" => 5,
            "packages" => 6,
            _ => 8,
        },
        9 if k == "integrity" => 4,
        12 if k == "dependencies" => 7,
        _ => 8,
    }
}

/// Finds the index of the first byte requiring JSON escaping (`< 0x20`, `"`, or `\`).
#[inline]
pub(crate) fn find_first_json_escape(bytes: &[u8]) -> Option<usize> {
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    const QUOTE_MASK: u64 = (b'"' as u64) * LO;
    const BACKSLASH_MASK: u64 = (b'\\' as u64) * LO;

    let len = bytes.len();
    let mut i = 0usize;
    if len >= 8 {
        let ptr = bytes.as_ptr();
        while i + 8 <= len {
            // SAFETY: `i + 8 <= len` guarantees 8 readable bytes within `bytes`.
            let w = unsafe { ptr.add(i).cast::<u64>().read_unaligned() };
            let has_ctrl = !(w | ((w & 0x7f7f_7f7f_7f7f_7f7f) + 0x6060_6060_6060_6060)) & HI;
            let xq = w ^ QUOTE_MASK;
            let has_quote = xq.wrapping_sub(LO) & !xq & HI;
            let xb = w ^ BACKSLASH_MASK;
            let has_bs = xb.wrapping_sub(LO) & !xb & HI;
            let hit = has_ctrl | has_quote | has_bs;
            if hit != 0 {
                #[cfg(target_endian = "little")]
                {
                    return Some(i + (hit.trailing_zeros() >> 3) as usize);
                }
                #[cfg(not(target_endian = "little"))]
                {
                    for j in 0..8 {
                        let b = bytes[i + j];
                        if b < 0x20 || b == b'"' || b == b'\\' {
                            return Some(i + j);
                        }
                    }
                }
            }
            i += 8;
        }
    }
    while i < len {
        let b = bytes[i];
        if b < 0x20 || b == b'"' || b == b'\\' {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[inline]
pub(crate) fn write_json_str(s: &str, out: &mut String) {
    out.reserve(s.len() + 2);
    out.push('"');
    let bytes = s.as_bytes();
    let Some(first_esc) = find_first_json_escape(bytes) else {
        out.push_str(s);
        out.push('"');
        return;
    };
    let mut start = 0usize;
    let mut i = first_esc;
    while i < bytes.len() {
        let b = bytes[i];
        if b >= 0x20 && b != b'"' && b != b'\\' {
            i += 1;
            continue;
        }
        if start < i {
            out.push_str(&s[start..i]);
        }
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\x08' => out.push_str("\\b"),
            b'\x0c' => out.push_str("\\f"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            _ => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let esc = [
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[(b >> 4) as usize],
                    HEX[(b & 0xf) as usize],
                ];
                // All bytes in `esc` are valid ASCII.
                out.push_str(unsafe { std::str::from_utf8_unchecked(&esc) });
            }
        }
        start = i + 1;
        i += 1;
    }
    if start < bytes.len() {
        out.push_str(&s[start..]);
    }
    out.push('"');
}

#[derive(Clone, Copy)]
enum PkgFieldVal<'p> {
    Str(&'p str),
    BoolTrue,
    StrSlice(&'p [String]),
    StrMap(&'p BTreeMap<String, String>),
    PeerMeta(&'p BTreeMap<String, serde_json::Value>),
    JsonArr(&'p [serde_json::Value]),
    JsonVal(&'p serde_json::Value),
}

#[inline]
fn is_stripped_extra_entry(k: &str, v: &serde_json::Value) -> bool {
    k == "directories"
        || (k == "deprecated"
            && (v == &serde_json::Value::Bool(false) || v.is_null() || v == ""))
}

fn collect_pkg_fields<'p>(
    pkg: &'p LockfilePackage,
    out: &mut Vec<(&'p str, bool, PkgFieldVal<'p>)>,
) {
    // 1. Non-object fields in exact (sw_key_rank, npm_key_compare) order.
    if let Some(ref s) = pkg.name {
        out.push(("name", false, PkgFieldVal::Str(s)));
    }
    if let Some(ref s) = pkg.version {
        out.push(("version", false, PkgFieldVal::Str(s)));
    }
    if let Some(ref s) = pkg.resolved {
        out.push(("resolved", false, PkgFieldVal::Str(s)));
    }
    if let Some(ref s) = pkg.integrity {
        out.push(("integrity", false, PkgFieldVal::Str(s)));
    }
    if let Some(PackageBin::Single(ref s)) = pkg.bin {
        out.push(("bin", false, PkgFieldVal::Str(s)));
    }
    match pkg.bundle_dependencies {
        Some(BundledDependencies::Boolean(true)) => {
            out.push(("bundleDependencies", false, PkgFieldVal::BoolTrue));
        }
        Some(BundledDependencies::List(ref list)) if !list.is_empty() => {
            out.push(("bundleDependencies", false, PkgFieldVal::StrSlice(list)));
        }
        _ => {}
    }
    if let Some(ref pl) = pkg.cpu {
        if !pl.is_empty() {
            let val = if pl.is_scalar() {
                PkgFieldVal::Str(&pl[0])
            } else {
                PkgFieldVal::StrSlice(pl.as_slice())
            };
            out.push(("cpu", false, val));
        }
    }
    let dev_optional_true = pkg.dev_optional == Some(true);
    if pkg.dev == Some(true) && !dev_optional_true {
        out.push(("dev", false, PkgFieldVal::BoolTrue));
    }
    if dev_optional_true {
        out.push(("devOptional", false, PkgFieldVal::BoolTrue));
    }
    if let Some(ref eng) = pkg.engines {
        if !eng.is_empty() {
            match eng {
                PackageEngines::List(arr) => {
                    out.push(("engines", false, PkgFieldVal::JsonArr(arr)));
                }
                PackageEngines::String(s) => {
                    out.push(("engines", false, PkgFieldVal::Str(s)));
                }
                PackageEngines::Other(v) if !v.is_object() => {
                    out.push(("engines", false, PkgFieldVal::JsonVal(v)));
                }
                _ => {}
            }
        }
    }
    if pkg.extraneous == Some(true) {
        out.push(("extraneous", false, PkgFieldVal::BoolTrue));
    }
    if pkg.has_install_script == Some(true) {
        out.push(("hasInstallScript", false, PkgFieldVal::BoolTrue));
    }
    if pkg.has_shrinkwrap == Some(true) {
        out.push(("hasShrinkwrap", false, PkgFieldVal::BoolTrue));
    }
    if pkg.in_bundle == Some(true) {
        out.push(("inBundle", false, PkgFieldVal::BoolTrue));
    }
    if let Some(ref pl) = pkg.libc {
        if !pl.is_empty() {
            let val = if pl.is_scalar() {
                PkgFieldVal::Str(&pl[0])
            } else {
                PkgFieldVal::StrSlice(pl.as_slice())
            };
            out.push(("libc", false, val));
        }
    }
    if let Some(ref s) = pkg.license {
        out.push(("license", false, PkgFieldVal::Str(s)));
    }
    if pkg.link == Some(true) {
        out.push(("link", false, PkgFieldVal::BoolTrue));
    }
    if pkg.optional == Some(true) && !dev_optional_true {
        out.push(("optional", false, PkgFieldVal::BoolTrue));
    }
    if let Some(ref pl) = pkg.os {
        if !pl.is_empty() {
            let val = if pl.is_scalar() {
                PkgFieldVal::Str(&pl[0])
            } else {
                PkgFieldVal::StrSlice(pl.as_slice())
            };
            out.push(("os", false, val));
        }
    }
    if pkg.peer == Some(true) {
        out.push(("peer", false, PkgFieldVal::BoolTrue));
    }
    if pkg.peer_optional == Some(true) {
        out.push(("peerOptional", false, PkgFieldVal::BoolTrue));
    }
    if let Some(ref ws) = pkg.workspaces {
        out.push(("workspaces", false, PkgFieldVal::StrSlice(ws)));
    }

    // 2. Object fields in exact (sw_key_rank, npm_key_compare) order.
    if let Some(ref m) = pkg.dependencies {
        if !m.is_empty() {
            out.push(("dependencies", true, PkgFieldVal::StrMap(m)));
        }
    }
    if let Some(PackageBin::Map(ref m)) = pkg.bin {
        if !m.is_empty() {
            out.push(("bin", true, PkgFieldVal::StrMap(m)));
        }
    }
    if let Some(ref m) = pkg.dev_dependencies {
        if !m.is_empty() {
            out.push(("devDependencies", true, PkgFieldVal::StrMap(m)));
        }
    }
    if let Some(ref eng) = pkg.engines {
        if !eng.is_empty() {
            match eng {
                PackageEngines::Map(m) => {
                    out.push(("engines", true, PkgFieldVal::StrMap(m)));
                }
                PackageEngines::Other(v) if v.is_object() => {
                    out.push(("engines", true, PkgFieldVal::JsonVal(v)));
                }
                _ => {}
            }
        }
    }
    if let Some(ref m) = pkg.optional_dependencies {
        if !m.is_empty() {
            out.push(("optionalDependencies", true, PkgFieldVal::StrMap(m)));
        }
    }
    if let Some(ref m) = pkg.peer_dependencies {
        if !m.is_empty() {
            out.push(("peerDependencies", true, PkgFieldVal::StrMap(m)));
        }
    }
    if let Some(ref m) = pkg.peer_dependencies_meta {
        if !m.is_empty() {
            out.push(("peerDependenciesMeta", true, PkgFieldVal::PeerMeta(m)));
        }
    }
}

/// Streaming serializer for npm lockfiles preserving 100% npm 11 key order,
/// collation, formatting, and raw value fidelity without intermediate DOM allocations.
#[derive(Debug, Clone)]
pub struct LockfileWriter<'a> {
    indent: &'a str,
    indent_buf: String,
    nl_indent: [String; 8],
    newline: &'a str,
    compact: bool,
    root_metadata: bool,
}

impl<'a> LockfileWriter<'a> {
    pub fn new(
        indent: &'a str,
        newline: &'a str,
        compact: bool,
        root_metadata: bool,
    ) -> Self {
        let indent_buf = if !compact && !indent.is_empty() {
            indent.repeat(8)
        } else {
            String::new()
        };
        let nl_indent = std::array::from_fn(|level| {
            if compact {
                String::new()
            } else {
                let mut s = String::with_capacity(newline.len() + level * indent.len());
                s.push_str(newline);
                for _ in 0..level {
                    s.push_str(indent);
                }
                s
            }
        });
        Self {
            indent,
            indent_buf,
            nl_indent,
            newline,
            compact,
            root_metadata,
        }
    }

    #[inline]
    fn write_nl_indent(&self, out: &mut String, level: usize) {
        if !self.compact {
            if level < 8 {
                out.push_str(&self.nl_indent[level]);
            } else {
                out.push_str(self.newline);
                self.write_indent(out, level);
            }
        }
    }

    #[inline]
    fn write_indent(&self, out: &mut String, level: usize) {
        if !self.compact && level > 0 && !self.indent.is_empty() {
            if level <= 8 {
                out.push_str(&self.indent_buf[..level * self.indent.len()]);
            } else {
                out.push_str(&self.indent_buf);
                for _ in 8..level {
                    out.push_str(self.indent);
                }
            }
        }
    }

    #[inline]
    fn write_newline(&self, out: &mut String) {
        if !self.compact {
            out.push_str(self.newline);
        }
    }

    #[inline]
    fn colon_sep(&self) -> &'static str {
        if self.compact {
            ":"
        } else {
            ": "
        }
    }

    pub fn write_value(&self, val: &serde_json::Value, level: usize, out: &mut String) {
        let mut scratch = Vec::with_capacity(16);
        self.write_value_inner(val, level, out, &mut scratch);
    }

    fn write_value_inner<'v>(
        &self,
        val: &'v serde_json::Value,
        level: usize,
        out: &mut String,
        scratch: &mut Vec<(&'v str, &'v serde_json::Value)>,
    ) {
        match val {
            serde_json::Value::Null => out.push_str("null"),
            serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            serde_json::Value::Number(n) => {
                use std::fmt::Write;
                let _ = write!(out, "{n}");
            }
            serde_json::Value::String(s) => write_json_str(s, out),
            serde_json::Value::Array(arr) => self.write_json_array(arr, level, out, scratch),
            serde_json::Value::Object(map) => {
                if map.is_empty() {
                    out.push_str("{}");
                } else {
                    let base = scratch.len();
                    scratch.extend(map.iter().map(|(k, v)| (k.as_str(), v)));
                    let slice_len = scratch.len();
                    if slice_len - base > 1 {
                        let cmp_entry = |(ak, av): &(&str, &serde_json::Value),
                                         (bk, bv): &(&str, &serde_json::Value)| {
                            av.is_object()
                                .cmp(&bv.is_object())
                                .then_with(|| sw_key_rank(ak).cmp(&sw_key_rank(bk)))
                                .then_with(|| npm_key_compare(ak, bk))
                        };
                        let sub = &mut scratch[base..slice_len];
                        if sub.windows(2).any(|w| cmp_entry(&w[0], &w[1]).is_gt()) {
                            sub.sort_unstable_by(cmp_entry);
                        }
                    }

                    if self.compact {
                        out.push('{');
                        for i in base..slice_len {
                            let (k, v) = scratch[i];
                            write_json_str(k, out);
                            out.push(':');
                            self.write_value_inner(v, 0, out, scratch);
                            if i + 1 < slice_len {
                                out.push(',');
                            }
                        }
                        out.push('}');
                    } else {
                        out.push('{');
                        for i in base..slice_len {
                            let (k, v) = scratch[i];
                            if i > base {
                                out.push(',');
                            }
                            self.write_nl_indent(out, level + 1);
                            write_json_str(k, out);
                            out.push_str(": ");
                            self.write_value_inner(v, level + 1, out, scratch);
                        }
                        self.write_nl_indent(out, level);
                        out.push('}');
                    }
                    scratch.truncate(base);
                }
            }
        }
    }

    fn write_json_array<'v>(
        &self,
        arr: &'v [serde_json::Value],
        level: usize,
        out: &mut String,
        scratch: &mut Vec<(&'v str, &'v serde_json::Value)>,
    ) {
        if arr.is_empty() {
            out.push_str("[]");
        } else if self.compact {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                self.write_value_inner(item, 0, out, scratch);
                if i + 1 < arr.len() {
                    out.push(',');
                }
            }
            out.push(']');
        } else {
            out.push('[');
            out.push_str(self.newline);
            for (i, item) in arr.iter().enumerate() {
                self.write_indent(out, level + 1);
                self.write_value_inner(item, level + 1, out, scratch);
                if i + 1 < arr.len() {
                    out.push(',');
                }
                out.push_str(self.newline);
            }
            self.write_indent(out, level);
            out.push(']');
        }
    }

    fn write_str_slice(&self, arr: &[String], level: usize, out: &mut String) {
        if arr.is_empty() {
            out.push_str("[]");
        } else if self.compact {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                write_json_str(item, out);
                if i + 1 < arr.len() {
                    out.push(',');
                }
            }
            out.push(']');
        } else {
            out.push('[');
            out.push_str(self.newline);
            for (i, item) in arr.iter().enumerate() {
                self.write_indent(out, level + 1);
                write_json_str(item, out);
                if i + 1 < arr.len() {
                    out.push(',');
                }
                out.push_str(self.newline);
            }
            self.write_indent(out, level);
            out.push(']');
        }
    }

    fn write_str_map<'m>(
        &self,
        map: &'m BTreeMap<String, String>,
        level: usize,
        out: &mut String,
        str_scratch: &mut Vec<(&'m str, &'m str)>,
    ) {
        if map.is_empty() {
            out.push_str("{}");
            return;
        }
        if map.len() == 1 {
            if let Some((k, v)) = map.iter().next() {
                out.push('{');
                if !self.compact {
                    self.write_nl_indent(out, level + 1);
                }
                write_json_str(k, out);
                out.push_str(self.colon_sep());
                write_json_str(v, out);
                if !self.compact {
                    self.write_nl_indent(out, level);
                }
                out.push('}');
                return;
            }
        }
        // Fast path: BTreeMap keys are usually already in `(sw_key_rank, npm_key_compare)` order.
        // Stream directly without copying into `str_scratch`, rolling back only if out of order.
        let snap = out.len();
        out.push('{');
        let colon = self.colon_sep();
        let mut prev_k: Option<&str> = None;
        let mut in_order = true;
        for (i, (k, v)) in map.iter().enumerate() {
            if let Some(pk) = prev_k {
                let ord = sw_key_rank(pk)
                    .cmp(&sw_key_rank(k))
                    .then_with(|| npm_key_compare(pk, k));
                if ord.is_gt() {
                    in_order = false;
                    break;
                }
            }
            prev_k = Some(k.as_str());
            if i > 0 {
                out.push(',');
            }
            if !self.compact {
                self.write_nl_indent(out, level + 1);
            }
            write_json_str(k, out);
            out.push_str(colon);
            write_json_str(v, out);
        }
        if in_order {
            if !self.compact {
                self.write_nl_indent(out, level);
            }
            out.push('}');
            return;
        }
        out.truncate(snap);

        str_scratch.clear();
        str_scratch.extend(map.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        if str_scratch.len() > 1 {
            str_scratch.sort_unstable_by(|(ak, _), (bk, _)| {
                sw_key_rank(ak)
                    .cmp(&sw_key_rank(bk))
                    .then_with(|| npm_key_compare(ak, bk))
            });
        }
        let len = str_scratch.len();
        if self.compact {
            out.push('{');
            for (i, &(k, v)) in str_scratch.iter().enumerate() {
                write_json_str(k, out);
                out.push(':');
                write_json_str(v, out);
                if i + 1 < len {
                    out.push(',');
                }
            }
            out.push('}');
        } else {
            out.push('{');
            for (i, &(k, v)) in str_scratch.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                self.write_nl_indent(out, level + 1);
                write_json_str(k, out);
                out.push_str(": ");
                write_json_str(v, out);
            }
            self.write_nl_indent(out, level);
            out.push('}');
        }
    }

    fn write_peer_meta<'m>(
        &self,
        map: &'m BTreeMap<String, serde_json::Value>,
        level: usize,
        out: &mut String,
        val_scratch: &mut Vec<(&'m str, &'m serde_json::Value)>,
    ) {
        if map.is_empty() {
            out.push_str("{}");
            return;
        }
        let base = val_scratch.len();
        val_scratch.extend(map.iter().map(|(k, v)| (k.as_str(), v)));
        let slice_len = val_scratch.len();
        if slice_len - base > 1 {
            val_scratch[base..slice_len].sort_unstable_by(|(ak, av), (bk, bv)| {
                av.is_object()
                    .cmp(&bv.is_object())
                    .then_with(|| sw_key_rank(ak).cmp(&sw_key_rank(bk)))
                    .then_with(|| npm_key_compare(ak, bk))
            });
        }
        if self.compact {
            out.push('{');
            for i in base..slice_len {
                let (k, v) = val_scratch[i];
                write_json_str(k, out);
                out.push(':');
                self.write_value_inner(v, 0, out, val_scratch);
                if i + 1 < slice_len {
                    out.push(',');
                }
            }
            out.push('}');
        } else {
            out.push('{');
            out.push_str(self.newline);
            for i in base..slice_len {
                let (k, v) = val_scratch[i];
                self.write_indent(out, level + 1);
                write_json_str(k, out);
                out.push_str(": ");
                self.write_value_inner(v, level + 1, out, val_scratch);
                if i + 1 < slice_len {
                    out.push(',');
                }
                out.push_str(self.newline);
            }
            self.write_indent(out, level);
            out.push('}');
        }
        val_scratch.truncate(base);
    }

    fn write_pkg_field_val<'p>(
        &self,
        val: PkgFieldVal<'p>,
        level: usize,
        out: &mut String,
        val_scratch: &mut Vec<(&'p str, &'p serde_json::Value)>,
        str_scratch: &mut Vec<(&'p str, &'p str)>,
    ) {
        match val {
            PkgFieldVal::Str(s) => write_json_str(s, out),
            PkgFieldVal::BoolTrue => out.push_str("true"),
            PkgFieldVal::StrSlice(arr) => self.write_str_slice(arr, level, out),
            PkgFieldVal::StrMap(m) => self.write_str_map(m, level, out, str_scratch),
            PkgFieldVal::PeerMeta(m) => self.write_peer_meta(m, level, out, val_scratch),
            PkgFieldVal::JsonArr(arr) => self.write_json_array(arr, level, out, val_scratch),
            PkgFieldVal::JsonVal(v) => self.write_value_inner(v, level, out, val_scratch),
        }
    }

    fn write_package<'p>(
        &self,
        pkg: &'p LockfilePackage,
        level: usize,
        out: &mut String,
        pkg_scratch: &mut Vec<(&'p str, bool, PkgFieldVal<'p>)>,
        val_scratch: &mut Vec<(&'p str, &'p serde_json::Value)>,
        str_scratch: &mut Vec<(&'p str, &'p str)>,
    ) {
        pkg_scratch.clear();
        collect_pkg_fields(pkg, pkg_scratch);

        if !pkg.extra.is_empty() {
            let mut has_emittable_extra = false;
            for (ek, ev) in &pkg.extra {
                if is_stripped_extra_entry(ek, ev) {
                    continue;
                }
                has_emittable_extra = true;
                let entry = (ek.as_str(), ev.is_object(), PkgFieldVal::JsonVal(ev));
                if let Some(pos) = pkg_scratch.iter().position(|(k, _, _)| *k == ek.as_str()) {
                    pkg_scratch[pos] = entry;
                } else {
                    pkg_scratch.push(entry);
                }
            }
            if has_emittable_extra && pkg_scratch.len() > 1 {
                pkg_scratch.sort_unstable_by(|(ak, a_obj, _), (bk, b_obj, _)| {
                    a_obj
                        .cmp(b_obj)
                        .then_with(|| sw_key_rank(ak).cmp(&sw_key_rank(bk)))
                        .then_with(|| npm_key_compare(ak, bk))
                });
            }
        }

        let len = pkg_scratch.len();
        if len == 0 {
            out.push_str("{}");
            return;
        }

        if self.compact {
            out.push('{');
            for (i, &(k, _, v)) in pkg_scratch.iter().enumerate() {
                write_json_str(k, out);
                out.push(':');
                self.write_pkg_field_val(v, 0, out, val_scratch, str_scratch);
                if i + 1 < len {
                    out.push(',');
                }
            }
            out.push('}');
        } else {
            out.push('{');
            for (i, &(k, _, v)) in pkg_scratch.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                self.write_nl_indent(out, level + 1);
                write_json_str(k, out);
                out.push_str(": ");
                self.write_pkg_field_val(v, level + 1, out, val_scratch, str_scratch);
            }
            self.write_nl_indent(out, level);
            out.push('}');
        }
    }

    pub fn write_lockfile(
        &self,
        lockfile: &LockfileV3,
        target_version: u32,
        out: &mut String,
    ) -> Result<(), LockfileError> {
        let per_pkg = if self.compact { 384 } else { 512 };
        out.reserve(lockfile.packages.len().saturating_mul(per_pkg) + 128);

        out.push('{');
        self.write_newline(out);

        let mut first_field = true;
        let mut val_scratch: Vec<(&str, &serde_json::Value)> = Vec::with_capacity(32);

        // 1. name (if root_metadata)
        if self.root_metadata {
            first_field = false;
            self.write_indent(out, 1);
            write_json_str("name", out);
            out.push_str(self.colon_sep());
            write_json_str(&lockfile.name, out);
        }

        // 2. version (if root_metadata and Some)
        if self.root_metadata {
            if let Some(ref v) = lockfile.version {
                if !first_field {
                    out.push(',');
                    self.write_newline(out);
                }
                first_field = false;
                self.write_indent(out, 1);
                write_json_str("version", out);
                out.push_str(self.colon_sep());
                write_json_str(v, out);
            }
        }

        // 3. lockfileVersion
        if !first_field {
            out.push(',');
            self.write_newline(out);
        }
        self.write_indent(out, 1);
        write_json_str("lockfileVersion", out);
        out.push_str(self.colon_sep());
        {
            use std::fmt::Write;
            let _ = write!(out, "{target_version}");
        }

        // 4. requires
        match target_version {
            1 | 2 => {
                out.push(',');
                self.write_newline(out);
                self.write_indent(out, 1);
                write_json_str("requires", out);
                out.push_str(self.colon_sep());
                out.push_str("true");
            }
            3 => {
                if let Some(r) = lockfile.requires {
                    out.push(',');
                    self.write_newline(out);
                    self.write_indent(out, 1);
                    write_json_str("requires", out);
                    out.push_str(self.colon_sep());
                    out.push_str(if r { "true" } else { "false" });
                }
            }
            _ => {}
        }

        // 5. packages (v2 or v3)
        if target_version == 2 || target_version == 3 {
            out.push(',');
            self.write_newline(out);
            self.write_indent(out, 1);
            write_json_str("packages", out);
            out.push_str(self.colon_sep());

            if lockfile.packages.is_empty() {
                out.push_str("{}");
            } else {
                out.push('{');
                self.write_newline(out);

                let mut pkg_entries: Vec<(std::borrow::Cow<'_, str>, &LockfilePackage)> =
                    Vec::with_capacity(lockfile.packages.len());
                for (k, v) in &lockfile.packages {
                    pkg_entries.push((to_posix_path_cow(k), v));
                }
                if pkg_entries.len() > 1
                    && pkg_entries
                        .windows(2)
                        .any(|w| npm_key_compare(&w[0].0, &w[1].0).is_gt())
                {
                    pkg_entries.sort_unstable_by(|(k1, _), (k2, _)| npm_key_compare(k1, k2));
                }

                let mut pkg_scratch: Vec<(&str, bool, PkgFieldVal<'_>)> = Vec::with_capacity(24);
                let mut str_scratch: Vec<(&str, &str)> = Vec::with_capacity(16);

                for (i, (k, pkg)) in pkg_entries.iter().enumerate() {
                    self.write_indent(out, 2);
                    write_json_str(k, out);
                    out.push_str(self.colon_sep());

                    if let Some(ref raw) = pkg.raw_value {
                        self.write_value_inner(raw, 2, out, &mut val_scratch);
                    } else {
                        self.write_package(
                            pkg,
                            2,
                            out,
                            &mut pkg_scratch,
                            &mut val_scratch,
                            &mut str_scratch,
                        );
                    }

                    if i + 1 < pkg_entries.len() {
                        out.push(',');
                    }
                    self.write_newline(out);
                }

                self.write_indent(out, 1);
                out.push('}');
            }
        }

        // 6. dependencies (v1 or v2)
        if target_version == 1 || target_version == 2 {
            out.push(',');
            self.write_newline(out);
            self.write_indent(out, 1);
            write_json_str("dependencies", out);
            out.push_str(self.colon_sep());
            let legacy = lockfile.to_legacy_dependencies();
            self.write_value_inner(&legacy, 1, out, &mut val_scratch);
        }

        // Close root
        self.write_newline(out);
        out.push('}');

        if !self.compact {
            out.push_str(self.newline);
        }

        Ok(())
    }
}

const NPM_CHAR_RANK: [u8; 256] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 6, 12, 25, 35, 26, 24, 10,
    13, 14, 20, 29, 3, 2, 8, 21, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 5, 4, 30, 31, 32, 7, 19,
    47, 49, 51, 53, 55, 57, 59, 61, 63, 65, 67, 69, 71, 73, 75, 77, 79, 81, 83, 85, 87, 89, 91, 93,
    95, 97, 15, 23, 16, 28, 1, 27, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76,
    78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 17, 33, 18, 34, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255,
];

const NPM_CHAR_RANK_FOLDED: [u8; 256] = {
    let mut table = NPM_CHAR_RANK;
    let mut i = b'A' as usize;
    while i <= b'Z' as usize {
        table[i] = NPM_CHAR_RANK[i + 32];
        i += 1;
    }
    table
};

static OMIT_REGISTRY_RESOLVED: std::sync::RwLock<Option<Vec<String>>> =
    std::sync::RwLock::new(None);

/// npm's `omit-lockfile-registry-resolved`: write registry packages without
/// `resolved`, so installs fetch them from whichever registry is configured.
/// `registries` lists the configured registry URLs whose tarballs count as
/// registry dependencies; `None` keeps `resolved`.
pub fn set_omit_registry_resolved(registries: Option<Vec<String>>) {
    if let Ok(mut guard) = OMIT_REGISTRY_RESOLVED.write() {
        *guard = registries;
    }
}

static FORMAT_PACKAGE_LOCK: std::sync::RwLock<Option<bool>> = std::sync::RwLock::new(None);

/// Set whether package-lock serialization produces human-readable pretty-printed JSON (true)
/// or compact single-line JSON (false).
pub fn set_format_package_lock(format: bool) {
    if let Ok(mut guard) = FORMAT_PACKAGE_LOCK.write() {
        *guard = Some(format);
    }
}

pub fn reset_format_package_lock() {
    if let Ok(mut guard) = FORMAT_PACKAGE_LOCK.write() {
        *guard = None;
    }
}

pub fn get_format_package_lock() -> Option<bool> {
    FORMAT_PACKAGE_LOCK.read().ok().and_then(|g| *g)
}

fn check_npmrc_file(path: &Path) -> Option<bool> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim().to_ascii_lowercase();
            if key == "format-package-lock" || key == "format_package_lock" {
                match v.trim().to_ascii_lowercase().as_str() {
                    "false" | "0" | "no" | "off" => return Some(false),
                    "true" | "1" | "yes" | "on" => return Some(true),
                    _ => {}
                }
            }
        }
    }
    None
}

fn is_format_package_lock_enabled(project_dir: &Path) -> bool {
    if let Some(explicit) = get_format_package_lock() {
        return explicit;
    }
    for var in &["npm_config_format_package_lock", "NPM_CONFIG_FORMAT_PACKAGE_LOCK"] {
        if let Ok(val) = std::env::var(var) {
            match val.trim().to_ascii_lowercase().as_str() {
                "false" | "0" | "no" | "off" => return false,
                "true" | "1" | "yes" | "on" => return true,
                _ => {}
            }
        }
    }
    if let Some(val) = check_npmrc_file(&project_dir.join(".npmrc")) {
        return val;
    }
    if let Some(user_home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
        let user_npmrc = Path::new(&user_home).join(".npmrc");
        if let Some(val) = check_npmrc_file(&user_npmrc) {
            return val;
        }
    }
    true
}

#[inline]
pub fn npm_key_compare(a: &str, b: &str) -> std::cmp::Ordering {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let n = a_bytes.len().min(b_bytes.len());
    let mut i = 0;
    if n >= 8 && a_bytes[0] == b_bytes[0] {
        while i + 8 <= n {
            let va = u64::from_ne_bytes(a_bytes[i..i + 8].try_into().unwrap());
            let vb = u64::from_ne_bytes(b_bytes[i..i + 8].try_into().unwrap());
            if va != vb {
                break;
            }
            i += 8;
        }
    }
    while i < n && a_bytes[i] == b_bytes[i] {
        i += 1;
    }
    if i == n && a_bytes.len() == b_bytes.len() {
        return std::cmp::Ordering::Equal;
    }
    let first_diff = i;
    while i < n {
        let ra = NPM_CHAR_RANK_FOLDED[a_bytes[i] as usize];
        let rb = NPM_CHAR_RANK_FOLDED[b_bytes[i] as usize];
        if ra != rb {
            return ra.cmp(&rb);
        }
        i += 1;
    }
    a_bytes
        .len()
        .cmp(&b_bytes.len())
        .then_with(|| {
            for idx in first_diff..n {
                let ra = NPM_CHAR_RANK[a_bytes[idx] as usize];
                let rb = NPM_CHAR_RANK[b_bytes[idx] as usize];
                if ra != rb {
                    return ra.cmp(&rb);
                }
            }
            std::cmp::Ordering::Equal
        })
        .then_with(|| a.cmp(b))
}

#[allow(dead_code)]
pub(crate) fn stringify_npm_nice(val: &serde_json::Value, indent_level: usize, out: &mut String) {
    stringify_npm_nice_indent(val, "  ", indent_level, out);
}

#[allow(dead_code)]
pub(crate) fn stringify_npm_nice_indent(
    val: &serde_json::Value,
    indent: &str,
    indent_level: usize,
    out: &mut String,
) {
    let writer = LockfileWriter::new(indent, "\n", false, true);
    writer.write_value(val, indent_level, out);
}

#[allow(dead_code)]
pub(crate) fn stringify_npm_compact(val: &serde_json::Value, out: &mut String) {
    let writer = LockfileWriter::new("", "", true, true);
    writer.write_value(val, 0, out);
}

pub(crate) fn is_platform_incompatible(pkg: &LockfilePackage) -> bool {
    let is_optional = pkg.optional.unwrap_or(false)
        || pkg.dev_optional.unwrap_or(false)
        || pkg.is_effective_optional();
    if !is_optional {
        return false;
    }

    let current_os = if cfg!(target_os = "windows") {
        "win32"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else if cfg!(target_os = "openbsd") {
        "openbsd"
    } else if cfg!(target_os = "android") {
        "android"
    } else {
        std::env::consts::OS
    };

    let current_cpu = if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86") {
        "ia32"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else if cfg!(target_arch = "wasm32") {
        "wasm32"
    } else {
        std::env::consts::ARCH
    };

    let current_libc = if cfg!(target_os = "linux") {
        if cfg!(target_env = "musl") {
            Some("musl")
        } else {
            Some("glibc")
        }
    } else {
        None
    };

    fn matches_list(current: &str, list_opt: Option<&[String]>) -> bool {
        let list = match list_opt {
            Some(l) if !l.is_empty() => l,
            _ => return true,
        };
        let mut has_positive = false;
        let mut positive_match = false;
        for item in list {
            if let Some(negated) = item.strip_prefix('!') {
                if negated == current {
                    return false;
                }
            } else {
                has_positive = true;
                if item == current {
                    positive_match = true;
                }
            }
        }
        if has_positive {
            positive_match
        } else {
            true
        }
    }

    let os_ok = matches_list(current_os, pkg.os.as_deref());
    let cpu_ok = matches_list(current_cpu, pkg.cpu.as_deref());
    let libc_ok = match (&pkg.libc, current_libc) {
        (Some(libc_list), Some(curr)) if !libc_list.is_empty() => {
            matches_list(curr, Some(libc_list))
        }
        (Some(libc_list), None) if !libc_list.is_empty() => {
            !libc_list.iter().any(|s| !s.starts_with('!'))
        }
        _ => true,
    };

    !(os_ok && cpu_ok && libc_ok)
}

fn bin_is_empty(bin: &Option<PackageBin>) -> bool {
    match bin {
        None => true,
        Some(PackageBin::Map(map)) => map.is_empty(),
        Some(_) => false,
    }
}

#[cfg(test)]
mod platform_field_tests {
    use super::LockfilePackage;

    #[test]
    fn npm_collation_compares_complete_names_before_case_tiebreaks() {
        assert!(
            super::npm_key_compare("node_modules/JSONStream", "node_modules/jsonwebtoken").is_lt()
        );
        assert!(super::npm_key_compare("aB", "Ab").is_lt());
        assert!(super::npm_key_compare("ab", "aB").is_lt());
    }

    #[test]
    fn libc_accepts_npm_string_form() {
        let pkg: LockfilePackage = serde_json::from_str(
            r#"{"version":"1.0.0","os":"linux","cpu":["arm"],"libc":"glibc"}"#,
        )
        .unwrap();
        assert_eq!(pkg.libc.as_deref(), Some(&["glibc".to_string()][..]));
        assert_eq!(pkg.os.as_deref(), Some(&["linux".to_string()][..]));
        assert_eq!(pkg.cpu.as_deref(), Some(&["arm".to_string()][..]));
        let json = serde_json::to_value(&pkg).unwrap();
        assert_eq!(json["libc"], "glibc");
        assert_eq!(json["os"], "linux");
        assert_eq!(json["cpu"], serde_json::json!(["arm"]));
    }

    #[test]
    fn test_git_refs_equal_semantics() {
        // Case-sensitive named branches and tags:
        assert!(!super::LockfileV3::git_refs_equal("Main", "main"));
        assert!(!super::LockfileV3::git_refs_equal("v1.0.0", "V1.0.0"));
        assert!(super::LockfileV3::git_refs_equal("main", "main"));
        assert!(super::LockfileV3::git_refs_equal("feature/foo", "feature/foo"));
        assert!(!super::LockfileV3::git_refs_equal("feature/foo", "feature/Foo"));

        // Case-insensitive full and prefix hex SHAs (len >= 7):
        let full_lower = "abcdef0123456789abcdef0123456789abcdef01";
        let full_upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF01";
        let prefix_lower = "abcdef0";
        let prefix_upper = "ABCDEF0";
        assert!(super::LockfileV3::git_refs_equal(full_lower, full_upper));
        assert!(super::LockfileV3::git_refs_equal(prefix_lower, full_upper));
        assert!(super::LockfileV3::git_refs_equal(full_lower, prefix_upper));
        assert!(super::LockfileV3::git_refs_equal(prefix_lower, prefix_upper));

        // Different hex SHAs:
        assert!(!super::LockfileV3::git_refs_equal("1234567", "7654321"));

        // #semver: git range matching and URL-encoded variants:
        assert!(super::LockfileV3::git_refs_equal("semver:^1.0.0", "semver%3A^1.0.0"));
        assert!(super::LockfileV3::git_refs_equal("semver:^1.0.0", "semver%3a^1.0.0"));
        assert!(super::LockfileV3::git_refs_equal("semver:^1.0.0", "semver: ^1.0.0"));
        assert!(!super::LockfileV3::git_refs_equal("semver:^1.0.0", "semver:^2.0.0"));
    }

    #[test]
    fn test_canonicalize_git_identity_and_numeric_orgs() {
        let scp_numeric = "git@github.com:12345/repo.git";
        let ssh_numeric = "git+ssh://git@github.com/12345/repo.git";
        let https_numeric = "git+https://github.com/12345/repo.git";
        let shortcut_numeric = "github:12345/repo";
        let bare_numeric = "12345/repo";

        assert_eq!(
            super::LockfileV3::canonicalize_git_identity(scp_numeric),
            "github.com/12345/repo"
        );
        assert_eq!(
            super::LockfileV3::canonicalize_git_identity(ssh_numeric),
            "github.com/12345/repo"
        );
        assert_eq!(
            super::LockfileV3::canonicalize_git_identity(https_numeric),
            "github.com/12345/repo"
        );
        assert_eq!(
            super::LockfileV3::canonicalize_git_identity(shortcut_numeric),
            "github.com/12345/repo"
        );
        assert_eq!(
            super::LockfileV3::canonicalize_git_identity(bare_numeric),
            "github.com/12345/repo"
        );

        // Explicit URL ports preservation:
        let port_8443 = "https://git.example.com:8443/org/repo.git";
        let port_9443 = "https://git.example.com:9443/org/repo.git";
        let port_default = "https://git.example.com/org/repo.git";
        assert_eq!(
            super::LockfileV3::canonicalize_git_identity(port_8443),
            "git.example.com:8443/org/repo"
        );
        assert_eq!(
            super::LockfileV3::canonicalize_git_identity(port_9443),
            "git.example.com:9443/org/repo"
        );
        assert_ne!(
            super::LockfileV3::canonicalize_git_identity(port_8443),
            super::LockfileV3::canonicalize_git_identity(port_9443)
        );
        assert_ne!(
            super::LockfileV3::canonicalize_git_identity(port_8443),
            super::LockfileV3::canonicalize_git_identity(port_default)
        );
    }

    #[test]
    fn test_non_registry_specs_match_and_platform_cases() {
        // user/repo vs github:user/repo vs git@github.com:user/repo.git
        assert!(super::LockfileV3::non_registry_specs_match(
            "user/repo",
            "github:user/repo"
        ));
        assert!(super::LockfileV3::non_registry_specs_match(
            "user/repo",
            "git@github.com:user/repo.git"
        ));
        assert!(super::LockfileV3::non_registry_specs_match(
            "github:user/repo",
            "git+ssh://git@github.com/user/repo.git"
        ));
        assert!(super::LockfileV3::non_registry_specs_match(
            "12345/repo",
            "git@github.com:12345/repo.git"
        ));

        // Ports preservation in non_registry_specs_match:
        assert!(!super::LockfileV3::non_registry_specs_match(
            "https://git.example.com:8443/org/repo.git",
            "https://git.example.com:9443/org/repo.git"
        ));
        assert!(super::LockfileV3::non_registry_specs_match(
            "https://git.example.com:8443/org/repo.git",
            "https://git.example.com:8443/org/repo.git"
        ));

        // File specs: relative ./ and ../
        assert!(super::LockfileV3::non_registry_specs_match(
            "file:../sibling",
            "../sibling"
        ));
        assert!(super::LockfileV3::non_registry_specs_match(
            "file:./local",
            "./local"
        ));
        assert!(super::LockfileV3::non_registry_specs_match(
            "file:./local",
            "file:local"
        ));
        assert!(!super::LockfileV3::non_registry_specs_match(
            "file:../sibling",
            "file:./sibling"
        ));

        if cfg!(windows) {
            assert!(super::LockfileV3::non_registry_specs_match(
                "file:./local",
                "file:./Local"
            ));
            assert!(super::LockfileV3::non_registry_specs_match(
                "file:../sibling",
                "file:../Sibling"
            ));
        }
    }

    #[test]
    fn test_git_semver_range_validation_in_package_satisfies_spec() {
        let pkg_locked_150 = super::LockfilePackage {
            version: Some("1.5.0".to_string()),
            resolved: Some("git+ssh://git@github.com/org/repo.git#abcdef0123456789abcdef0123456789abcdef01".to_string()),
            ..Default::default()
        };
        let pkg_locked_200 = super::LockfilePackage {
            version: Some("2.0.0".to_string()),
            resolved: Some("git+ssh://git@github.com/org/repo.git#abcdef0123456789abcdef0123456789abcdef01".to_string()),
            ..Default::default()
        };

        // Raw #semver:^1.0.0: accepts 1.5.0, rejects 2.0.0
        assert!(super::LockfileV3::package_satisfies_spec(
            "repo",
            &pkg_locked_150,
            "github:org/repo#semver:^1.0.0"
        ));
        assert!(!super::LockfileV3::package_satisfies_spec(
            "repo",
            &pkg_locked_200,
            "github:org/repo#semver:^1.0.0"
        ));

        // URL-encoded #semver%3A^1.0.0: accepts 1.5.0, rejects 2.0.0
        assert!(super::LockfileV3::package_satisfies_spec(
            "repo",
            &pkg_locked_150,
            "github:org/repo#semver%3A^1.0.0"
        ));
        assert!(!super::LockfileV3::package_satisfies_spec(
            "repo",
            &pkg_locked_200,
            "github:org/repo#semver%3A^1.0.0"
        ));
    }

    #[test]
    fn test_non_workspace_file_directory_link_and_deleted_workspaces_drift() {
        use rnpm_core::manifest::Manifest;

        // 1. Non-workspace file:./libs/local-a directory link passing strict matches_manifest
        let mut manifest_non_ws = Manifest::default();
        manifest_non_ws.name = Some("root-app".to_string());
        manifest_non_ws.version = Some("1.0.0".to_string());
        manifest_non_ws.dependencies.insert("local-a".to_string(), "file:./libs/local-a".to_string());

        let mut lockfile = super::LockfileV3::new("root-app", Some("1.0.0".to_string()));

        let mut root_pkg = super::LockfilePackage::default();
        let mut root_deps = std::collections::BTreeMap::new();
        root_deps.insert("local-a".to_string(), "file:./libs/local-a".to_string());
        root_pkg.dependencies = Some(root_deps);
        lockfile.packages.insert("".to_string(), root_pkg);

        let mut local_a_target = super::LockfilePackage::default();
        local_a_target.name = Some("local-a".to_string());
        local_a_target.version = Some("1.0.0".to_string());
        lockfile.packages.insert("libs/local-a".to_string(), local_a_target);

        let mut local_a_link = super::LockfilePackage::default();
        local_a_link.link = Some(true);
        local_a_link.resolved = Some("libs/local-a".to_string());
        lockfile.packages.insert("node_modules/local-a".to_string(), local_a_link);

        // Strict matches_manifest (allow_extra_lock_deps = false): must PASS!
        assert!(lockfile.matches_manifest(&manifest_non_ws, true));

        // Even with resolved prefixed with file:
        lockfile.packages.get_mut("node_modules/local-a").unwrap().resolved = Some("file:libs/local-a".to_string());
        assert!(lockfile.matches_manifest(&manifest_non_ws, true));

        // 2. Deleted workspaces: lockfile has packages/pkg-b leftover, not in manifest dependencies
        let mut orphaned_pkg = super::LockfilePackage::default();
        orphaned_pkg.name = Some("pkg-b".to_string());
        orphaned_pkg.version = Some("1.0.0".to_string());
        lockfile.packages.insert("packages/pkg-b".to_string(), orphaned_pkg);

        let mut orphaned_link = super::LockfilePackage::default();
        orphaned_link.link = Some(true);
        orphaned_link.resolved = Some("packages/pkg-b".to_string());
        lockfile.packages.insert("node_modules/pkg-b".to_string(), orphaned_link);

        // Strict matches_manifest must detect drift because pkg-b is an orphaned workspace member!
        assert!(!lockfile.matches_manifest(&manifest_non_ws, true));
    }

    #[test]
    fn test_cross_review_findings_regression_suite() {
        use std::path::PathBuf;

        // Finding 3: canonicalize_git_identity strips user:password@ in URLs
        let with_creds = "https://user:password@github.com/org/repo.git";
        let clean = "https://github.com/org/repo.git";
        assert_eq!(
            super::LockfileV3::canonicalize_git_identity(with_creds),
            super::LockfileV3::canonicalize_git_identity(clean)
        );
        assert_eq!(
            super::LockfileV3::canonicalize_git_identity(with_creds),
            "github.com/org/repo"
        );

        // Finding 4: git_refs_equal rejects unsound symmetrical prefix matching
        assert!(!super::LockfileV3::git_refs_equal("20240101", "202401010"));
        // Same length >= 7 hex strings match case-insensitively:
        assert!(super::LockfileV3::git_refs_equal("20240101", "20240101"));
        assert!(super::LockfileV3::git_refs_equal("abcdef0", "ABCDEF0"));
        // Prefix matching allowed only when one is full 40/64 hex commit SHA:
        assert!(super::LockfileV3::git_refs_equal(
            "abcdef0123456789abcdef0123456789abcdef01",
            "abcdef0"
        ));
        assert!(super::LockfileV3::git_refs_equal(
            "ABCDEF0",
            "abcdef0123456789abcdef0123456789abcdef01"
        ));

        // Git tags and branch names are independent of package.json version:
        // a tag #v1.0.0 whose commit has package.json version 0.9.0 must pass,
        // while changing package.json from #v1.0.0 to #v2.0.0 triggers drift via lock_spec.
        let pkg_v09 = super::LockfilePackage {
            version: Some("0.9.0".to_string()),
            resolved: Some("git+https://github.com/org/repo.git#1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b".to_string()),
            ..Default::default()
        };
        assert!(super::LockfileV3::package_satisfies_spec(
            "repo",
            &pkg_v09,
            "git+https://github.com/org/repo.git#v1.0.0"
        ));
        let mut git_lock = super::LockfileV3::new("git-tag-app", Some("1.0.0".to_string()));
        if let Some(root) = git_lock.packages.get_mut("") {
            root.dependencies = Some(std::collections::BTreeMap::from([(
                "repo".to_string(),
                "git+https://github.com/org/repo.git#v1.0.0".to_string(),
            )]));
        }
        git_lock.insert_package("node_modules/repo", pkg_v09);
        let mut git_manifest = rnpm_core::Manifest {
            name: Some("git-tag-app".to_string()),
            version: Some("1.0.0".to_string()),
            ..Default::default()
        };
        git_manifest.dependencies.insert(
            "repo".to_string(),
            "git+https://github.com/org/repo.git#v1.0.0".to_string(),
        );
        assert!(
            git_lock.matches_manifest(&git_manifest, true),
            "git tag #v1.0.0 with package.json version 0.9.0 must match valid lockfile"
        );
        git_manifest.dependencies.insert(
            "repo".to_string(),
            "git+https://github.com/org/repo.git#v2.0.0".to_string(),
        );
        assert!(
            !git_lock.matches_manifest(&git_manifest, true),
            "changing package.json git tag from #v1.0.0 to #v2.0.0 must trigger lockfile drift"
        );

        // Finding 6: target_matches_resolved for file:../ rejects arbitrary absolute paths
        let file_parent = rnpm_core::spec::PackageTarget::File(PathBuf::from("../"));
        assert!(!super::LockfileV3::target_matches_resolved(
            "/usr/local/random/path",
            &file_parent
        ));
        assert!(!super::LockfileV3::target_matches_resolved(
            "C:/some/random/dir",
            &file_parent
        ));

        let file_sibling = rnpm_core::spec::PackageTarget::File(PathBuf::from("../sibling"));
        assert!(super::LockfileV3::target_matches_resolved(
            "/workspace/sibling",
            &file_sibling
        ));

        // Switching a dependency between a file: link and a registry range must be detected as drift:
        let mut lock_pkg_root = super::LockfilePackage::default();
        lock_pkg_root.dependencies = Some(std::collections::BTreeMap::from([(
            "sibling".to_string(),
            "file:../sibling".to_string(),
        )]));
        let mut lock_pkg_link = super::LockfilePackage::default();
        lock_pkg_link.resolved = Some("../sibling".to_string());
        lock_pkg_link.link = Some(true);
        let lockfile = super::LockfileV3 {
            name: "root".to_string(),
            version: Some("1.0.0".to_string()),
            lockfile_version: 3,
            requires: Some(true),
            packages: std::collections::BTreeMap::from([
                (String::new(), lock_pkg_root),
                ("node_modules/sibling".to_string(), lock_pkg_link),
            ]),
        };
        let manifest_registry = rnpm_core::manifest::Manifest {
            name: Some("root".to_string()),
            version: Some("1.0.0".to_string()),
            dependencies: std::collections::BTreeMap::from([(
                "sibling".to_string(),
                "^1.0.0".to_string(),
            )]),
            ..Default::default()
        };
        assert!(!lockfile.matches_manifest(&manifest_registry, true));
    }
}
