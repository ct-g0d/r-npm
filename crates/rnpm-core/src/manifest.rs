use crate::error::ManifestError;
use serde::{
    de::{self, Deserializer, SeqAccess, Visitor},
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
    struct OptVecOrStringVisitor;

    impl<'de> Visitor<'de> for OptVecOrStringVisitor {
        type Value = Option<Vec<String>>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string, array of strings, or null")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(vec![value.to_string()]))
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(vec![value]))
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: SeqAccess<'de>,
        {
            let mut list = Vec::new();
            while let Some(item) = seq.next_element::<String>()? {
                list.push(item);
            }
            Ok(Some(list))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
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

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(OptVecOrStringVisitor)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PackageBin {
    Single(String),
    Map(BTreeMap<String, String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BundledDependencies {
    Boolean(bool),
    List(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PackageWorkspaces {
    List(Vec<String>),
    Config { packages: Vec<String> },
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
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

    #[serde(default, skip_serializing_if = "Option::is_none")]
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

    #[serde(
        default,
        deserialize_with = "deserialize_opt_vec_or_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub os: Option<Vec<String>>,

    #[serde(
        default,
        deserialize_with = "deserialize_opt_vec_or_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub cpu: Option<Vec<String>>,

    #[serde(
        default,
        deserialize_with = "deserialize_opt_vec_or_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub libc: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub engines: BTreeMap<String, String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
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

        let mut manifest: Self =
            serde_json::from_slice(clean_bytes).map_err(|err| ManifestError::MalformedJson {
                message: err.to_string(),
                line: err.line(),
                column: err.column(),
            })?;
        let value: serde_json::Value =
            serde_json::from_slice(clean_bytes).map_err(|err| ManifestError::MalformedJson {
                message: err.to_string(),
                line: err.line(),
                column: err.column(),
            })?;
        manifest.capture_dependency_order(&value);
        Ok(manifest)
    }

    /// Parse manifest from string, with tolerance for UTF-8 BOM.
    pub fn from_str(s: &str) -> Result<Self, ManifestError> {
        let clean_str = s.strip_prefix('\u{feff}').unwrap_or(s);
        let mut manifest: Self =
            serde_json::from_str(clean_str).map_err(|err| ManifestError::MalformedJson {
                message: err.to_string(),
                line: err.line(),
                column: err.column(),
            })?;
        let value: serde_json::Value =
            serde_json::from_str(clean_str).map_err(|err| ManifestError::MalformedJson {
                message: err.to_string(),
                line: err.line(),
                column: err.column(),
            })?;
        manifest.capture_dependency_order(&value);
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

    fn capture_dependency_order(&mut self, value: &serde_json::Value) {
        let Some(object) = value.as_object() else {
            return;
        };
        let collect = |key: &str| {
            object
                .get(key)
                .and_then(serde_json::Value::as_object)
                .map(|map| map.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        };
        self.dependency_order = collect("dependencies");
        self.dev_dependency_order = collect("devDependencies");
        self.peer_dependency_order = collect("peerDependencies");
        self.optional_dependency_order = collect("optionalDependencies");
    }

    /// Returns list of (binary_name, script_path) defined in manifest.
    pub fn bin_entries(&self) -> Vec<(String, String)> {
        match &self.bin {
            None => Vec::new(),
            Some(PackageBin::Single(script_path)) => {
                // If package name is "@scope/foo", binary name is "foo"
                let bin_name = self
                    .name
                    .as_deref()
                    .map(|n| {
                        if let Some(slash_idx) = n.find('/') {
                            &n[slash_idx + 1..]
                        } else {
                            n
                        }
                    })
                    .unwrap_or("app")
                    .to_string();
                vec![(bin_name, script_path.clone())]
            }
            Some(PackageBin::Map(map)) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
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

    /// Serialize manifest to a deterministic formatted JSON string with a trailing newline.
    pub fn to_json_string(&self) -> Result<String, ManifestError> {
        let mut json =
            serde_json::to_string_pretty(self).map_err(|err| ManifestError::MalformedJson {
                message: err.to_string(),
                line: err.line(),
                column: err.column(),
            })?;
        json.push('\n');
        Ok(json)
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
