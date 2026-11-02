use serde::{de::{self, Deserializer, SeqAccess, Visitor}, Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

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
}

/// Abbreviated version metadata matching `application/vnd.npm.install-v1+json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbbreviatedVersion {
    pub name: String,
    pub version: String,
    pub dist: DistInfo,
    #[serde(default)]
    pub dependencies: HashMap<String, String>,
    #[serde(rename = "devDependencies", default)]
    pub dev_dependencies: HashMap<String, String>,
    #[serde(rename = "peerDependencies", default)]
    pub peer_dependencies: HashMap<String, String>,
    #[serde(rename = "optionalDependencies", default)]
    pub optional_dependencies: HashMap<String, String>,
    #[serde(rename = "bundleDependencies", alias = "bundledDependencies", default)]
    pub bundle_dependencies: Vec<String>,
    #[serde(default)]
    pub bin: Option<PackageBin>,
    #[serde(default)]
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
}

/// Abbreviated package metadata document from the npm registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbbreviatedPackageMetadata {
    pub name: String,
    #[serde(rename = "dist-tags", default)]
    pub dist_tags: HashMap<String, String>,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default)]
    pub versions: BTreeMap<String, AbbreviatedVersion>,
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
        assert_eq!(v.dependencies.get("dep-a"), Some(&"^1.0.0".to_string()));

        let bin_map = v.bin.clone().unwrap().into_map(&v.name);
        assert_eq!(bin_map.get("example"), Some(&"./bin/cli.js".to_string()));
    }
}
