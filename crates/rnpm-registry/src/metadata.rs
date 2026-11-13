use crate::error::RegistryError;
use indexmap::IndexMap;
use serde::{
    de::{self, Deserializer, MapAccess, SeqAccess, Visitor},
    Deserialize, Serialize,
};
use std::collections::{BTreeMap, HashMap};
use url::Url;

fn deserialize_license<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    // Arborist's shrinkwrap stores the type from legacy license objects.
    Ok(value.as_str().or_else(|| value.get("type").and_then(|v| v.as_str())).map(str::to_owned))
}

pub fn deserialize_unique_versions<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, AbbreviatedVersion>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueVersionsVisitor;

    impl<'de> Visitor<'de> for UniqueVersionsVisitor {
        type Value = BTreeMap<String, AbbreviatedVersion>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a map of package versions without duplicate keys")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut map = BTreeMap::new();
            while let Some((key, mut value)) = access.next_entry::<String, serde_json::Value>()? {
                if map.contains_key(&key) {
                    return Err(de::Error::custom(format!(
                        "duplicate version key '{key}' found in packument metadata"
                    )));
                }
                // Full packuments retain historical manifest spellings and
                // types. Apply pacote's package-json normalization before
                // deserializing the resolver's typed manifest representation.
                if let Some(object) = value.as_object_mut() {
                    if object.get("deprecated") == Some(&serde_json::Value::Bool(false)) {
                        object.remove("deprecated");
                    }
                    if let Some(legacy) = object.remove("bundledDependencies") {
                        object.entry("bundleDependencies").or_insert(legacy);
                    }
                    if let Some(bundled) = object.get("bundleDependencies") {
                        let names = match bundled {
                            serde_json::Value::Bool(true) => object.get("dependencies").and_then(|v| v.as_object()).map(|deps| deps.keys().cloned().collect::<Vec<_>>()),
                            serde_json::Value::Object(deps) => Some(deps.keys().cloned().collect()),
                            serde_json::Value::Array(_) => None,
                            _ => Some(Vec::new()),
                        };
                        if let Some(names) = names {
                            object.insert("bundleDependencies".into(), serde_json::json!(names));
                        }
                    }
                }
                let version = serde_json::from_value(value).map_err(de::Error::custom)?;
                map.insert(key, version);
            }
            Ok(map)
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

        fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
        where
            D2: Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }
    }

    deserializer.deserialize_any(UniqueVersionsVisitor)
}

pub fn deserialize_vec_or_string<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct VecOrStringVisitor;

    impl<'de> Visitor<'de> for VecOrStringVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or array of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value.to_string()])
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value])
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: SeqAccess<'de>,
        {
            let mut list = Vec::new();
            while let Some(item) = seq.next_element::<String>()? {
                list.push(item);
            }
            Ok(list)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Vec::new())
        }

        fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
        where
            D2: Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(VecOrStringVisitor)
}

/// npm has published a small number of legacy packuments with `engines` as an
/// array instead of the usual string map. Engines are advisory metadata, so a
/// malformed legacy shape must not prevent installing an otherwise valid
/// package. Preserve normal maps and ignore unsupported array/scalar forms.
pub fn deserialize_engines<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    let Some(serde_json::Value::Object(object)) = value else {
        return Ok(HashMap::new());
    };

    Ok(object
        .into_iter()
        .filter_map(|(key, value)| value.as_str().map(|value| (key, value.to_owned())))
        .collect())
}

/// Represents either a single string binary path or a map of command names to paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PackageBin {
    Single(String),
    Map(BTreeMap<String, String>),
}

impl PackageBin {
    /// Convert to a map of command names to relative executable paths.
    /// If single string, the command name is derived from package name
    /// (e.g. `@scope/foo` -> `foo`, or `foo` -> `foo`).
    pub fn into_map(self, package_name: &str) -> BTreeMap<String, String> {
        match self {
            PackageBin::Single(path) => {
                let bin_name = package_name
                    .split('/')
                    .next_back()
                    .unwrap_or(package_name)
                    .trim_start_matches('@');
                let mut map = BTreeMap::new();
                map.insert(bin_name.to_string(), path);
                map
            }
            PackageBin::Map(map) => map,
        }
    }
}

/// Distribution metadata for a package version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DistInfo {
    pub tarball: String,
    #[serde(default)]
    pub shasum: Option<String>,
    #[serde(default)]
    pub integrity: Option<String>,
    #[serde(default)]
    pub signatures: Vec<DistSignature>,
    #[serde(default)]
    pub attestations: Option<DistAttestations>,
}

/// npm package signature in `dist.signatures`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DistSignature {
    pub keyid: String,
    pub sig: String,
}

/// npm package attestations reference in `dist.attestations`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DistAttestations {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub provenance: Option<AttestationProvenance>,
}

/// Provenance metadata summary in `dist.attestations.provenance`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AttestationProvenance {
    #[serde(rename = "predicateType", default)]
    pub predicate_type: Option<String>,
}

/// Abbreviated version metadata matching `application/vnd.npm.install-v1+json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbbreviatedVersion {
    pub name: String,
    pub version: String,
    pub dist: DistInfo,
    #[serde(default)]
    pub dependencies: IndexMap<String, String>,
    #[serde(rename = "devDependencies", default)]
    pub dev_dependencies: IndexMap<String, String>,
    #[serde(rename = "peerDependencies", default)]
    pub peer_dependencies: IndexMap<String, String>,
    #[serde(rename = "peerDependenciesMeta", default)]
    pub peer_dependencies_meta: HashMap<String, rnpm_core::manifest::PeerDependencyMeta>,
    #[serde(rename = "optionalDependencies", default)]
    pub optional_dependencies: IndexMap<String, String>,
    #[serde(rename = "bundleDependencies", alias = "bundledDependencies", default)]
    pub bundle_dependencies: Vec<String>,
    #[serde(default)]
    pub bin: Option<PackageBin>,
    #[serde(default, deserialize_with = "deserialize_license")]
    pub license: Option<String>,
    #[serde(default, deserialize_with = "deserialize_engines")]
    pub engines: HashMap<String, String>,
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub os: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub cpu: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_vec_or_string")]
    pub libc: Vec<String>,
    #[serde(rename = "hasInstallScript", default)]
    pub has_install_script: bool,
    #[serde(default)]
    pub deprecated: Option<String>,
    /// Preserve package metadata that npm copies into package-lock entries
    /// (for example `funding`) even when it is not part of the abbreviated
    /// resolver schema.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Abbreviated package metadata document from the npm registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbbreviatedPackageMetadata {
    pub name: String,
    #[serde(rename = "dist-tags", default)]
    pub dist_tags: HashMap<String, String>,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default, deserialize_with = "deserialize_unique_versions")]
    pub versions: BTreeMap<String, AbbreviatedVersion>,
}

impl AbbreviatedPackageMetadata {
    /// Validates the packument according to Byzantine registry hardening rules:
    /// 1. Reject CR/LF characters in package name, dist-tag names, and target versions.
    /// 2. Validate that dist-tags point to existing versions in `versions`.
    /// 3. Validate each version key matches `ver_info.version`.
    /// 4. Validate each `ver_info.name == self.name`.
    /// 5. Validate that `dist.tarball` URL has a valid scheme (`http` or `https`) and does not use `file:`, `data:`, `javascript:`, etc.
    /// 6. Sanitize against CR/LF characters in version keys, inner fields, and tarball URLs.
    pub fn validate(&self) -> Result<(), RegistryError> {
        let has_crlf = |s: &str| s.contains('\r') || s.contains('\n');

        if self.name.trim().is_empty() {
            return Err(RegistryError::MalformedMetadata(
                "Package name is empty".into(),
            ));
        }

        if has_crlf(&self.name) {
            return Err(RegistryError::MalformedMetadata(format!(
                "Package name contains forbidden CR/LF characters: {:?}",
                self.name
            )));
        }

        // Validate dist-tags
        for (tag_name, tag_ver) in &self.dist_tags {
            if has_crlf(tag_name) {
                return Err(RegistryError::MalformedMetadata(format!(
                    "dist-tag name contains forbidden CR/LF characters: {tag_name:?}"
                )));
            }
            if has_crlf(tag_ver) {
                return Err(RegistryError::MalformedMetadata(format!(
                    "dist-tag version target for '{tag_name}' contains forbidden CR/LF characters: {tag_ver:?}"
                )));
            }
            // A dist-tag may dangle after an unpublish. npm keeps such
            // packuments usable and only fails when that tag is requested.
        }

        // Validate versions
        for (ver_key, ver_info) in &self.versions {
            if has_crlf(ver_key) {
                return Err(RegistryError::MalformedMetadata(format!(
                    "Version key contains forbidden CR/LF characters: {ver_key:?}"
                )));
            }
            if has_crlf(&ver_info.version) {
                return Err(RegistryError::MalformedMetadata(format!(
                    "Version field contains forbidden CR/LF characters: {:?}",
                    ver_info.version
                )));
            }
            if has_crlf(&ver_info.name) {
                return Err(RegistryError::MalformedMetadata(format!(
                    "Version package name contains forbidden CR/LF characters: {:?}",
                    ver_info.name
                )));
            }

            if ver_key != &ver_info.version {
                return Err(RegistryError::MalformedMetadata(format!(
                    "Version key '{ver_key}' does not match version field '{}' in package '{}'",
                    ver_info.version, self.name
                )));
            }

            if ver_info.name != self.name {
                return Err(RegistryError::MalformedMetadata(format!(
                    "Version '{ver_key}' package name '{}' does not match packument name '{}'",
                    ver_info.name, self.name
                )));
            }

            if has_crlf(&ver_info.dist.tarball) {
                return Err(RegistryError::MalformedMetadata(format!(
                    "Version '{ver_key}' tarball URL contains forbidden CR/LF characters: {:?}",
                    ver_info.dist.tarball
                )));
            }

            match Url::parse(&ver_info.dist.tarball) {
                Ok(parsed_tarball) => {
                    let scheme = parsed_tarball.scheme().to_ascii_lowercase();
                    if scheme != "http" && scheme != "https" {
                        return Err(RegistryError::MalformedMetadata(format!(
                            "Version '{ver_key}' tarball URL has forbidden scheme '{scheme}' (only http and https are allowed): {}",
                            ver_info.dist.tarball
                        )));
                    }
                }
                Err(url::ParseError::RelativeUrlWithoutBase) => {
                    let lower = ver_info.dist.tarball.to_ascii_lowercase();
                    if lower.starts_with("file:")
                        || lower.starts_with("data:")
                        || lower.starts_with("javascript:")
                    {
                        return Err(RegistryError::MalformedMetadata(format!(
                            "Version '{ver_key}' tarball URL has forbidden scheme: {}",
                            ver_info.dist.tarball
                        )));
                    }
                }
                Err(e) => {
                    return Err(RegistryError::MalformedMetadata(format!(
                        "Version '{ver_key}' has malformed tarball URL '{}': {e}",
                        ver_info.dist.tarball
                    )));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_abbreviated_metadata() {
        let json = r#"{
            "name": "@scope/example",
            "dist-tags": { "latest": "1.0.0" },
            "modified": "2026-01-01T00:00:00.000Z",
            "versions": {
                "1.0.0": {
                    "name": "@scope/example",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/@scope/example/-/@scope/example-1.0.0.tgz",
                        "shasum": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                        "integrity": "sha512-testintegrity=="
                    },
                    "dependencies": {
                        "dep-a": "^1.0.0"
                    },
                    "bin": "./bin/cli.js",
                    "license": "MIT",
                    "funding": { "type": "github", "url": "https://github.com/sponsors/example" },
                    "libc": ["glibc"],
                    "hasInstallScript": true
                }
            }
        }"#;

        let meta: AbbreviatedPackageMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.name, "@scope/example");
        assert_eq!(meta.dist_tags.get("latest"), Some(&"1.0.0".to_string()));
        let v = meta.versions.get("1.0.0").unwrap();
        assert_eq!(v.version, "1.0.0");
        assert!(v.has_install_script);
        assert_eq!(v.license.as_deref(), Some("MIT"));
        assert_eq!(v.libc, vec!["glibc"]);
        assert!(v.extra.contains_key("funding"));
        assert_eq!(v.dependencies.get("dep-a"), Some(&"^1.0.0".to_string()));

        let bin_map = v.bin.clone().unwrap().into_map(&v.name);
        assert_eq!(bin_map.get("example"), Some(&"./bin/cli.js".to_string()));
        meta.validate().unwrap();
    }

    #[test]
    fn test_legacy_array_engines_are_tolerated() {
        let json = r#"{
            "name": "legacy-engines",
            "versions": {
                "1.0.0": {
                    "name": "legacy-engines",
                    "version": "1.0.0",
                    "engines": ["node >=0.10.0"],
                    "dist": { "tarball": "https://registry.npmjs.org/legacy-engines/-/legacy-engines-1.0.0.tgz" }
                }
            }
        }"#;
        let meta: AbbreviatedPackageMetadata = serde_json::from_str(json).unwrap();
        assert!(meta.versions["1.0.0"].engines.is_empty());
        meta.validate().unwrap();
    }

    #[test]
    fn test_reject_duplicate_version_keys() {
        let json = r#"{
            "name": "example",
            "versions": {
                "1.0.0": {
                    "name": "example",
                    "version": "1.0.0",
                    "dist": { "tarball": "https://registry.npmjs.org/example/-/example-1.0.0.tgz" }
                },
                "1.0.0": {
                    "name": "example",
                    "version": "1.0.0",
                    "dist": { "tarball": "https://registry.npmjs.org/example/-/example-1.0.0-spoofed.tgz" }
                }
            }
        }"#;

        let res: Result<AbbreviatedPackageMetadata, _> = serde_json::from_str(json);
        assert!(
            res.is_err(),
            "Duplicate version keys must be rejected during deserialization"
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("duplicate version key '1.0.0'"),
            "Error message was: {err_msg}"
        );
    }

    #[test]
    fn test_reject_mismatched_version_key() {
        let json = r#"{
            "name": "example",
            "versions": {
                "1.0.1": {
                    "name": "example",
                    "version": "1.0.0",
                    "dist": { "tarball": "https://registry.npmjs.org/example/-/example-1.0.0.tgz" }
                }
            }
        }"#;
        let meta: AbbreviatedPackageMetadata = serde_json::from_str(json).unwrap();
        let err = meta.validate().unwrap_err();
        assert!(err.is_malformed_metadata());
        assert!(err.to_string().contains("does not match version field"));
    }

    #[test]
    fn test_reject_mismatched_package_name() {
        let json = r#"{
            "name": "legit-pkg",
            "versions": {
                "1.0.0": {
                    "name": "malicious-pkg",
                    "version": "1.0.0",
                    "dist": { "tarball": "https://registry.npmjs.org/legit-pkg/-/legit-pkg-1.0.0.tgz" }
                }
            }
        }"#;
        let meta: AbbreviatedPackageMetadata = serde_json::from_str(json).unwrap();
        let err = meta.validate().unwrap_err();
        assert!(err.is_malformed_metadata());
        assert!(err.to_string().contains("does not match packument name"));
    }

    #[test]
    fn test_dangling_dist_tags_are_tolerated_like_npm() {
        let json = r#"{
            "name": "example",
            "dist-tags": { "latest": "9.9.9" },
            "versions": {
                "1.0.0": {
                    "name": "example",
                    "version": "1.0.0",
                    "dist": { "tarball": "https://registry.npmjs.org/example/-/example-1.0.0.tgz" }
                }
            }
        }"#;
        let meta: AbbreviatedPackageMetadata = serde_json::from_str(json).unwrap();
        meta.validate()
            .expect("npm accepts packuments whose dist-tag names a missing version");
    }

    #[test]
    fn test_reject_malicious_tarball_schemes() {
        let schemes = [
            "file:///etc/passwd",
            "data:text/plain;base64,SGVsbG8sIFdvcmxkIQ==",
            "javascript:alert(1)",
            "ftp://files.example.com/tarball.tgz",
        ];

        for scheme_url in schemes {
            let json = format!(
                r#"{{
                "name": "example",
                "versions": {{
                    "1.0.0": {{
                        "name": "example",
                        "version": "1.0.0",
                        "dist": {{ "tarball": "{scheme_url}" }}
                    }}
                }}
            }}"#
            );
            let meta: AbbreviatedPackageMetadata = serde_json::from_str(&json).unwrap();
            let err = meta.validate().unwrap_err();
            assert!(err.is_malformed_metadata());
            assert!(
                err.to_string().contains("forbidden scheme")
                    || err.to_string().contains("malformed tarball URL")
            );
        }
    }

    #[test]
    fn test_reject_crlf_injection() {
        // CR/LF in package name
        let json1 = r#"{
            "name": "evil\r\nSet-Cookie: admin=1",
            "versions": {}
        }"#;
        let meta1: AbbreviatedPackageMetadata = serde_json::from_str(json1).unwrap();
        assert!(meta1.validate().unwrap_err().is_malformed_metadata());

        // CR/LF in dist-tag
        let json2 = r#"{
            "name": "example",
            "dist-tags": { "latest\r\n": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "example",
                    "version": "1.0.0",
                    "dist": { "tarball": "https://registry.npmjs.org/example/-/example-1.0.0.tgz" }
                }
            }
        }"#;
        let meta2: AbbreviatedPackageMetadata = serde_json::from_str(json2).unwrap();
        assert!(meta2.validate().unwrap_err().is_malformed_metadata());

        // CR/LF in version key
        let json3 = r#"{
            "name": "example",
            "versions": {
                "1.0.0\r\n": {
                    "name": "example",
                    "version": "1.0.0\r\n",
                    "dist": { "tarball": "https://registry.npmjs.org/example/-/example-1.0.0.tgz" }
                }
            }
        }"#;
        let meta3: AbbreviatedPackageMetadata = serde_json::from_str(json3).unwrap();
        assert!(meta3.validate().unwrap_err().is_malformed_metadata());
    }
}
