use crate::error::RegistryError;
use indexmap::IndexMap;
use rnpm_core::PlatformList;
use serde::{
    de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor},
    Deserialize, Serialize,
};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use url::Url;

/// Alias for [`AbbreviatedPackageMetadata`] representing packument metadata.
pub type PackageMetadata = AbbreviatedPackageMetadata;

/// Alias for [`AbbreviatedVersion`] representing version metadata within a packument.
pub type VersionMetadata = AbbreviatedVersion;

/// Parsing mode for packument deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackumentParseMode {
    /// Lean install packument: drops heavy fields (`readme`, `maintainers`, `contributors`,
    /// `users`, `bugs`, `homepage`, `keywords`, `repository`, etc.) while keeping all
    /// resolution, platform, lockfile, funding, scripts, license, engines, and shrinkwrap data.
    Install,
    /// Full packument: drops bloated `readme`, `maintainers`, `contributors`, `users`,
    /// but retains `repository`, `homepage`, `bugs`, etc. for CLI inspection (`npm repo`, `npm docs`).
    Full,
}

/// Identifies heavy unused fields that should be dropped during install packument parsing.
#[inline]
pub fn is_heavy_unused_install_field(key: &str) -> bool {
    matches!(
        key,
        "readme"
            | "readmeFilename"
            | "maintainers"
            | "contributors"
            | "users"
            | "bugs"
            | "homepage"
            | "keywords"
            | "repository"
            | "author"
            | "description"
            | "gitHead"
            | "directories"
            | "_id"
            | "_nodeVersion"
            | "_npmVersion"
            | "_npmUser"
            | "_npmOperationalInternal"
            | "_from"
            | "_resolved"
            | "_shasum"
            | "dist-tags"
            | "exports"
            | "imports"
            | "typesVersions"
            | "main"
            | "module"
            | "types"
            | "typings"
            | "files"
            | "sideEffects"
            | "browser"
            | "unpkg"
            | "jsdelivr"
            | "eslintConfig"
            | "prettier"
            | "jest"
            | "babel"
            | "nyc"
            | "publishConfig"
            | "man"
            | "preferGlobal"
            | "private"
            | "config"
            | "commitlint"
            | "husky"
            | "lint-staged"
            | "devEngines"
            | "release"
            | "standard"
            | "ava"
            | "xo"
            | "tap"
            | "mocha"
            | "c8"
            | "tsconfig"
    )
}

/// Identifies heavy bloated fields that should be dropped during full packument parsing.
#[inline]
pub fn is_heavy_unused_full_field(key: &str) -> bool {
    matches!(
        key,
        "readme"
            | "readmeFilename"
            | "maintainers"
            | "contributors"
            | "users"
            | "gitHead"
            | "directories"
            | "_id"
            | "_nodeVersion"
            | "_npmVersion"
            | "_npmUser"
            | "_npmOperationalInternal"
            | "_from"
            | "_resolved"
            | "_shasum"
            | "dist-tags"
            | "exports"
            | "imports"
            | "typesVersions"
            | "files"
            | "publishConfig"
            | "types"
            | "typings"
            | "sideEffects"
            | "unpkg"
            | "jsdelivr"
            | "man"
            | "preferGlobal"
            | "main"
            | "module"
            | "browser"
            | "eslintConfig"
            | "prettier"
            | "jest"
            | "babel"
            | "nyc"
            | "commitlint"
            | "husky"
            | "lint-staged"
            | "devEngines"
            | "release"
            | "standard"
            | "ava"
            | "xo"
            | "tap"
            | "mocha"
            | "c8"
            | "tsconfig"
    )
}

/// Deserializes a license string or legacy object `{ "type": "MIT" }`.
pub fn deserialize_license<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    deserializer.deserialize_any(LicenseVisitor)
}

/// Deserializes versions using full packument mode by default.
pub fn deserialize_unique_versions<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, AbbreviatedVersion>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_versions_with_mode(deserializer, PackumentParseMode::Full)
}

/// Deserializes versions using lean install packument mode.
pub fn deserialize_unique_versions_install<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, AbbreviatedVersion>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_versions_with_mode(deserializer, PackumentParseMode::Install)
}

/// Deserializes versions with a specified [`PackumentParseMode`].
pub fn deserialize_unique_versions_with_mode<'de, D>(
    deserializer: D,
    mode: PackumentParseMode,
) -> Result<BTreeMap<String, AbbreviatedVersion>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(VersionsVisitor {
        mode,
        root_name: None,
    })
}

pub fn deserialize_vec_or_string<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_platform_list(deserializer).map(PlatformList::into_vec)
}

pub fn deserialize_platform_list<'de, D>(deserializer: D) -> Result<PlatformList, D::Error>
where
    D: Deserializer<'de>,
{
    struct VecOrStringVisitor;

    impl<'de> Visitor<'de> for VecOrStringVisitor {
        type Value = PlatformList;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or array of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value.to_string().into())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value.into())
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: SeqAccess<'de>,
        {
            let mut list = Vec::new();
            while let Some(OptStringOrSkip(opt)) = seq.next_element()? {
                if let Some(s) = opt {
                    if list.is_empty() {
                        list.reserve(seq.size_hint().unwrap_or(4));
                    }
                    list.push(s);
                }
            }
            Ok(list.into())
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(PlatformList::default())
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
            Ok(PlatformList::default())
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
    deserializer.deserialize_any(EnginesVisitor).map(|(m, _)| m)
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
    #[serde(default)]
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
    #[serde(default)]
    pub bundle: Option<serde_json::Value>,
}

/// Provenance metadata summary in `dist.attestations.provenance`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AttestationProvenance {
    #[serde(rename = "predicateType", default)]
    pub predicate_type: Option<String>,
}

/// Abbreviated version metadata matching `application/vnd.npm.install-v1+json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AbbreviatedVersion {
    pub name: String,
    pub version: String,
    #[serde(default)]
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
    /// Retain legacy engine shapes across the typed packument disk cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engines_raw: Option<serde_json::Value>,
    #[serde(default, deserialize_with = "deserialize_platform_list")]
    pub os: PlatformList,
    #[serde(default, deserialize_with = "deserialize_platform_list")]
    pub cpu: PlatformList,
    #[serde(default, deserialize_with = "deserialize_platform_list")]
    pub libc: PlatformList,
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

impl<'de> Deserialize<'de> for AbbreviatedVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(VersionVisitor {
            mode: PackumentParseMode::Full,
            root_name: None,
            version_key: None,
        })
    }
}

/// Deserializes dist-tags tolerating `null`, arrays, or quirky shapes.
pub fn deserialize_dist_tags<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    DistTagsSeed.deserialize(deserializer)
}

/// Abbreviated package metadata document from the npm registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AbbreviatedPackageMetadata {
    pub name: String,
    #[serde(rename = "dist-tags", default, deserialize_with = "deserialize_dist_tags")]
    pub dist_tags: HashMap<String, String>,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default, deserialize_with = "deserialize_unique_versions")]
    pub versions: BTreeMap<String, AbbreviatedVersion>,
    /// Publish times by version, present only in the full packument.
    #[serde(
        default,
        deserialize_with = "deserialize_publish_times",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub time: BTreeMap<String, String>,
}

impl<'de> Deserialize<'de> for AbbreviatedPackageMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        PackageMetadataSeed {
            mode: PackumentParseMode::Full,
        }
        .deserialize(deserializer)
    }
}

/// Keeps string entries only: unpublished packuments carry an object or array there.
pub fn deserialize_publish_times<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    TimeSeed.deserialize(deserializer)
}

#[inline]
fn contains_crlf(s: &str) -> bool {
    s.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n')
}

#[inline]
fn is_fast_tarball_path(path: &str) -> bool {
    path.as_bytes().iter().all(|&b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'/'
                    | b'@'
                    | b'+'
                    | b'='
                    | b','
                    | b';'
                    | b':'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
            )
    })
}

/// Fast-path validation returning the validated scheme+authority prefix length (`"https://host/"`)
/// when `s` is a canonical lowercase ASCII `http://` or `https://` URL.
#[inline]
fn fast_http_tarball_origin_end(s: &str) -> Option<usize> {
    let scheme_len = if s.starts_with("https://") {
        8
    } else if s.starts_with("http://") {
        7
    } else {
        return None;
    };
    let rest = &s[scheme_len..];

    let (authority, path, origin_end) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..], scheme_len + idx + 1),
        None => (rest, "", s.len()),
    };

    if authority.is_empty() {
        return None;
    }

    let host = match authority.split_once(':') {
        Some((h, port_str)) => {
            if port_str.is_empty()
                || port_str.len() > 5
                || port_str.contains(':')
                || !port_str.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            let port: u32 = port_str.parse().ok()?;
            if port == 0 || port > 65535 {
                return None;
            }
            h
        }
        None => authority,
    };

    if host.is_empty()
        || host.len() > 253
        || host
            .as_bytes()
            .windows(4)
            .any(|w| w.eq_ignore_ascii_case(b"xn--"))
    {
        return None;
    }

    let mut has_last_label_alpha = false;
    let mut label_count = 0usize;
    let mut all_valid_ipv4_octets = true;
    for label in host.split('.') {
        label_count += 1;
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        let mut label_alpha = false;
        let mut label_digits_only = label.len() <= 3;
        for &b in label.as_bytes() {
            if b.is_ascii_alphabetic() {
                label_alpha = true;
                label_digits_only = false;
            } else if b == b'-' {
                label_digits_only = false;
            } else if !b.is_ascii_digit() {
                return None;
            }
        }
        if label_digits_only {
            if (label.len() > 1 && label.starts_with('0')) || label.parse::<u8>().is_err() {
                all_valid_ipv4_octets = false;
            }
        } else {
            all_valid_ipv4_octets = false;
        }
        has_last_label_alpha = label_alpha;
    }
    if !has_last_label_alpha && !(all_valid_ipv4_octets && label_count == 4) {
        return None;
    }

    if is_fast_tarball_path(path) {
        Some(origin_end)
    } else {
        None
    }
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
        if self.name.is_empty() || self.name.trim().is_empty() {
            return Err(RegistryError::MalformedMetadata(
                "Package name is empty".into(),
            ));
        }

        if contains_crlf(&self.name) {
            return Err(RegistryError::MalformedMetadata(format!(
                "Package name contains forbidden CR/LF characters: {:?}",
                self.name
            )));
        }

        // Validate dist-tags
        for (tag_name, tag_ver) in &self.dist_tags {
            if contains_crlf(tag_name) {
                return Err(RegistryError::MalformedMetadata(format!(
                    "dist-tag name contains forbidden CR/LF characters: {tag_name:?}"
                )));
            }
            if contains_crlf(tag_ver) {
                return Err(RegistryError::MalformedMetadata(format!(
                    "dist-tag version target for '{tag_name}' contains forbidden CR/LF characters: {tag_ver:?}"
                )));
            }
        }

        // Validate versions, memoizing the previously validated scheme://host/ origin prefix
        // across versions so typical N-version packuments skip redundant authority parsing.
        let mut verified_origin_prefix: Option<&str> = None;
        for (ver_key, ver_info) in &self.versions {
            if contains_crlf(ver_key) {
                return Err(RegistryError::MalformedMetadata(format!(
                    "Version key contains forbidden CR/LF characters: {ver_key:?}"
                )));
            }
            if ver_key != &ver_info.version {
                if contains_crlf(&ver_info.version) {
                    return Err(RegistryError::MalformedMetadata(format!(
                        "Version field contains forbidden CR/LF characters: {:?}",
                        ver_info.version
                    )));
                }
                return Err(RegistryError::MalformedMetadata(format!(
                    "Version key '{ver_key}' does not match version field '{}' in package '{}'",
                    ver_info.version, self.name
                )));
            }

            if ver_info.name != self.name {
                if contains_crlf(&ver_info.name) {
                    return Err(RegistryError::MalformedMetadata(format!(
                        "Version package name contains forbidden CR/LF characters: {:?}",
                        ver_info.name
                    )));
                }
                return Err(RegistryError::MalformedMetadata(format!(
                    "Version '{ver_key}' package name '{}' does not match packument name '{}'",
                    ver_info.name, self.name
                )));
            }

            if !ver_info.dist.tarball.is_empty() {
                let fast_ok = if let Some(prefix) = verified_origin_prefix {
                    if prefix.ends_with('/')
                        && ver_info.dist.tarball.starts_with(prefix)
                        && is_fast_tarball_path(&ver_info.dist.tarball[prefix.len()..])
                    {
                        true
                    } else if let Some(origin_end) =
                        fast_http_tarball_origin_end(&ver_info.dist.tarball)
                    {
                        verified_origin_prefix = Some(&ver_info.dist.tarball[..origin_end]);
                        true
                    } else {
                        false
                    }
                } else if let Some(origin_end) =
                    fast_http_tarball_origin_end(&ver_info.dist.tarball)
                {
                    verified_origin_prefix = Some(&ver_info.dist.tarball[..origin_end]);
                    true
                } else {
                    false
                };

                if !fast_ok {
                if contains_crlf(&ver_info.dist.tarball) {
                    return Err(RegistryError::MalformedMetadata(format!(
                        "Version '{ver_key}' tarball URL contains forbidden CR/LF characters: {:?}",
                        ver_info.dist.tarball
                    )));
                }
                match Url::parse(&ver_info.dist.tarball) {
                    Ok(parsed_tarball) => {
                        let scheme = parsed_tarball.scheme();
                        if !scheme.eq_ignore_ascii_case("http")
                            && !scheme.eq_ignore_ascii_case("https")
                        {
                            return Err(RegistryError::MalformedMetadata(format!(
                                "Version '{ver_key}' tarball URL has forbidden scheme '{}' (only http and https are allowed): {}",
                                scheme.to_ascii_lowercase(),
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
            }
        }

        Ok(())
    }
}

/// Lean single-pass install packument parser.
///
/// Parses registry packument bytes in one pass directly into typed metadata,
/// dropping heavy unused fields (`readme`, `maintainers`, `contributors`, `users`,
/// `bugs`, `homepage`, `keywords`, `repository`, etc.) while keeping all fields
/// required for resolution, platform filtering, lockfile generation, scripts,
/// funding, license, deprecated, engines, os, cpu, libc, bin, dist, dependencies,
/// devDependencies, optionalDependencies, peerDependencies, peerDependenciesMeta,
/// bundleDependencies, bundledDependencies, hasInstallScript, `_hasShrinkwrap`,
/// `time`, and `dist-tags`.
pub fn parse_install_packument(bytes: &[u8]) -> Result<AbbreviatedPackageMetadata, RegistryError> {
    parse_packument_with_mode(bytes, PackumentParseMode::Install)
}

/// Parse full packument bytes while avoiding double-parsing and untyped DOM allocation.
///
/// Drops bloated `readme`, `maintainers`, `contributors`, `users` payloads while
/// retaining metadata needed for full inspection (e.g. repository, homepage, bugs).
pub fn parse_full_packument(bytes: &[u8]) -> Result<AbbreviatedPackageMetadata, RegistryError> {
    parse_packument_with_mode(bytes, PackumentParseMode::Full)
}

/// Parse packument bytes with a specific parse mode and validate Byzantine registry rules.
pub fn parse_packument_with_mode(
    bytes: &[u8],
    mode: PackumentParseMode,
) -> Result<AbbreviatedPackageMetadata, RegistryError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let metadata = PackageMetadataSeed { mode }.deserialize(&mut deserializer)?;
    deserializer.end()?;
    metadata.validate()?;
    Ok(metadata)
}

// ---------------------------------------------------------------------------
// Single-Pass Seeds and Visitors
// ---------------------------------------------------------------------------

/// Zero-copy string wrapper that borrows directly from slice deserializers when unescaped.
struct CowStr<'de>(Cow<'de, str>);

impl<'de> CowStr<'de> {
    #[inline]
    fn into_owned(self) -> String {
        self.0.into_owned()
    }
}

impl<'de> Deserialize<'de> for CowStr<'de> {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CowStrVisitor;
        impl<'de> Visitor<'de> for CowStrVisitor {
            type Value = CowStr<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string")
            }
            #[inline]
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E> {
                Ok(CowStr(Cow::Borrowed(v)))
            }
            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(CowStr(Cow::Owned(v.to_owned())))
            }
            #[inline]
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(CowStr(Cow::Owned(v)))
            }
        }
        deserializer.deserialize_str(CowStrVisitor)
    }
}

struct OptStringOrSkip(Option<String>);

impl<'de> Deserialize<'de> for OptStringOrSkip {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptStringOrSkipVisitor;

        impl<'de> Visitor<'de> for OptStringOrSkipVisitor {
            type Value = OptStringOrSkip;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string or ignorable value")
            }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(OptStringOrSkip(Some(v.to_owned())))
            }

            #[inline]
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(OptStringOrSkip(Some(v)))
            }

            #[inline]
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(OptStringOrSkip(None))
            }

            #[inline]
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(OptStringOrSkip(None))
            }

            #[inline]
            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(OptStringOrSkip(None))
            }

            #[inline]
            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(OptStringOrSkip(None))
            }

            #[inline]
            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(OptStringOrSkip(None))
            }

            #[inline]
            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(OptStringOrSkip(None))
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                while let Some((serde::de::IgnoredAny, serde::de::IgnoredAny)) = access.next_entry()? {}
                Ok(OptStringOrSkip(None))
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                while let Some(serde::de::IgnoredAny) = seq.next_element()? {}
                Ok(OptStringOrSkip(None))
            }
        }

        deserializer.deserialize_any(OptStringOrSkipVisitor)
    }
}

struct OptStringFromStrOrNum(Option<String>);

impl<'de> Deserialize<'de> for OptStringFromStrOrNum {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptStringFromStrOrNumVisitor;

        impl<'de> Visitor<'de> for OptStringFromStrOrNumVisitor {
            type Value = OptStringFromStrOrNum;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string, number, or other JSON value")
            }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(OptStringFromStrOrNum(Some(v.to_owned())))
            }

            #[inline]
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(OptStringFromStrOrNum(Some(v)))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
                Ok(OptStringFromStrOrNum(Some(v.to_string())))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
                Ok(OptStringFromStrOrNum(Some(v.to_string())))
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                serde_json::Number::from_f64(v)
                    .map(|n| OptStringFromStrOrNum(Some(n.to_string())))
                    .ok_or_else(|| de::Error::custom("invalid float number"))
            }

            #[inline]
            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(OptStringFromStrOrNum(None))
            }

            #[inline]
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(OptStringFromStrOrNum(None))
            }

            #[inline]
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(OptStringFromStrOrNum(None))
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                while let Some(serde::de::IgnoredAny) = seq.next_element()? {}
                Ok(OptStringFromStrOrNum(None))
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                while let Some((serde::de::IgnoredAny, serde::de::IgnoredAny)) = access.next_entry()? {}
                Ok(OptStringFromStrOrNum(None))
            }
        }

        deserializer.deserialize_any(OptStringFromStrOrNumVisitor)
    }
}

/// Pre-sized `serde_json::Value` seed that avoids repeated capacity 0 -> 1 -> 2 -> 4 growth on small objects/arrays.
struct FastJsonValueSeed;

impl<'de> DeserializeSeed<'de> for FastJsonValueSeed {
    type Value = serde_json::Value;

    #[inline]
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(FastJsonValueVisitor)
    }
}

struct FastJsonValueVisitor;

impl<'de> Visitor<'de> for FastJsonValueVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    #[inline]
    fn visit_bool<E>(self, b: bool) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Bool(b))
    }

    #[inline]
    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(v.into()))
    }

    #[inline]
    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(v.into()))
    }

    #[inline]
    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(v)
            .map(serde_json::Value::Number)
            .ok_or_else(|| de::Error::custom("invalid JSON number"))
    }

    #[inline]
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(v.to_owned()))
    }

    #[inline]
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(v))
    }

    #[inline]
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    #[inline]
    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer)
    }

    #[inline]
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        let Some(first) = seq.next_element_seed(FastJsonValueSeed)? else {
            return Ok(serde_json::Value::Array(Vec::new()));
        };
        let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(4));
        vec.push(first);
        while let Some(elem) = seq.next_element_seed(FastJsonValueSeed)? {
            vec.push(elem);
        }
        Ok(serde_json::Value::Array(vec))
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let Some(first_key) = access.next_key::<String>()? else {
            return Ok(serde_json::Value::Object(serde_json::Map::new()));
        };
        let mut map = serde_json::Map::with_capacity(access.size_hint().unwrap_or(4));
        let first_val = access.next_value_seed(FastJsonValueSeed)?;
        map.insert(first_key, first_val);
        while let Some(key) = access.next_key::<String>()? {
            let val = access.next_value_seed(FastJsonValueSeed)?;
            map.insert(key, val);
        }
        Ok(serde_json::Value::Object(map))
    }
}

struct DependencyMapSeed;

impl<'de> DeserializeSeed<'de> for DependencyMapSeed {
    type Value = IndexMap<String, String>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DependencyMapVisitor)
    }
}

struct DependencyMapVisitor;

impl<'de> Visitor<'de> for DependencyMapVisitor {
    type Value = IndexMap<String, String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a dependency map")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = IndexMap::new();
        while let Some(key) = access.next_key::<CowStr<'_>>()? {
            if let Some(s) = access.next_value::<OptStringFromStrOrNum>()?.0 {
                if map.is_empty() {
                    map.reserve(access.size_hint().unwrap_or(4));
                }
                map.insert(key.into_owned(), s);
            }
        }
        Ok(map)
    }

    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        while let Some(serde::de::IgnoredAny) = seq.next_element()? {}
        Ok(IndexMap::new())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(IndexMap::new())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(IndexMap::new())
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(IndexMap::new())
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(IndexMap::new())
    }
}

struct PeerDepsMetaSeed;

impl<'de> DeserializeSeed<'de> for PeerDepsMetaSeed {
    type Value = HashMap<String, rnpm_core::manifest::PeerDependencyMeta>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PeerDepsMetaVisitor)
    }
}

struct PeerDepsMetaVisitor;

impl<'de> Visitor<'de> for PeerDepsMetaVisitor {
    type Value = HashMap<String, rnpm_core::manifest::PeerDependencyMeta>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a peerDependenciesMeta map")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = HashMap::new();
        while let Some((k, v)) =
            access.next_entry::<String, rnpm_core::manifest::PeerDependencyMeta>()?
        {
            if map.is_empty() {
                map.reserve(access.size_hint().unwrap_or(4));
            }
            map.insert(k, v);
        }
        Ok(map)
    }

    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        while let Some(serde::de::IgnoredAny) = seq.next_element()? {}
        Ok(HashMap::new())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(HashMap::new())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(HashMap::new())
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(HashMap::new())
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(HashMap::new())
    }
}

enum RawBundleDeps {
    All,
    List(Vec<String>),
}

struct BundleDepsSeed;

impl<'de> DeserializeSeed<'de> for BundleDepsSeed {
    type Value = RawBundleDeps;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(BundleDepsVisitor)
    }
}

struct BundleDepsVisitor;

impl<'de> Visitor<'de> for BundleDepsVisitor {
    type Value = RawBundleDeps;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a boolean, array of package names, or map of package names")
    }

    fn visit_bool<E>(self, b: bool) -> Result<Self::Value, E> {
        if b {
            Ok(RawBundleDeps::All)
        } else {
            Ok(RawBundleDeps::List(Vec::new()))
        }
    }

    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        let mut list = Vec::new();
        while let Some(OptStringOrSkip(opt)) = seq.next_element()? {
            if let Some(s) = opt {
                if list.is_empty() {
                    list.reserve(seq.size_hint().unwrap_or(4));
                }
                list.push(s);
            }
        }
        Ok(RawBundleDeps::List(list))
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut list = Vec::new();
        while let Some(k) = access.next_key::<String>()? {
            let _ = access.next_value::<serde::de::IgnoredAny>()?;
            if list.is_empty() {
                list.reserve(access.size_hint().unwrap_or(4));
            }
            list.push(k);
        }
        Ok(RawBundleDeps::List(list))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(RawBundleDeps::List(Vec::new()))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(RawBundleDeps::List(Vec::new()))
    }
}

struct BinSeed;

impl<'de> DeserializeSeed<'de> for BinSeed {
    type Value = Option<PackageBin>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(BinVisitor)
    }
}

struct BinVisitor;

impl<'de> Visitor<'de> for BinVisitor {
    type Value = Option<PackageBin>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a bin string, map, or array of executable paths")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E> {
        Ok(Some(PackageBin::Single(s.to_string())))
    }

    fn visit_string<E>(self, s: String) -> Result<Self::Value, E> {
        Ok(Some(PackageBin::Single(s)))
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = BTreeMap::new();
        while let Some(k) = access.next_key::<CowStr<'_>>()? {
            if let Some(v) = access.next_value::<OptStringOrSkip>()?.0 {
                map.insert(k.into_owned(), v);
            }
        }
        if map.is_empty() {
            Ok(None)
        } else {
            Ok(Some(PackageBin::Map(map)))
        }
    }

    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        let mut map = BTreeMap::new();
        while let Some(OptStringOrSkip(opt)) = seq.next_element()? {
            if let Some(path_str) = opt {
                let name = path_str
                    .rsplit(&['/', '\\'])
                    .next()
                    .unwrap_or(&path_str)
                    .trim();
                if !name.is_empty() {
                    map.insert(name.to_string(), path_str);
                }
            }
        }
        if map.is_empty() {
            Ok(None)
        } else {
            Ok(Some(PackageBin::Map(map)))
        }
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(None)
    }
}

struct LicenseSeed;

impl<'de> DeserializeSeed<'de> for LicenseSeed {
    type Value = Option<String>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(LicenseVisitor)
    }
}

struct LicenseVisitor;

impl<'de> Visitor<'de> for LicenseVisitor {
    type Value = Option<String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a license string or object with type field")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E> {
        Ok(Some(s.to_string()))
    }

    fn visit_string<E>(self, s: String) -> Result<Self::Value, E> {
        Ok(Some(s))
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut license = None;
        while let Some(k) = access.next_key::<CowStr<'_>>()? {
            if k.0.as_ref() == "type" {
                if let Some(s) = access.next_value::<OptStringOrSkip>()?.0 {
                    license = Some(s);
                }
            } else {
                let _ = access.next_value::<serde::de::IgnoredAny>()?;
            }
        }
        Ok(license)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        while let Some(serde::de::IgnoredAny) = seq.next_element()? {}
        Ok(None)
    }
}

struct DeprecatedSeed;

impl<'de> DeserializeSeed<'de> for DeprecatedSeed {
    type Value = Option<String>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DeprecatedVisitor)
    }
}

struct DeprecatedVisitor;

impl<'de> Visitor<'de> for DeprecatedVisitor {
    type Value = Option<String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a deprecation message string or boolean")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E> {
        Ok(Some(s.to_string()))
    }

    fn visit_string<E>(self, s: String) -> Result<Self::Value, E> {
        Ok(Some(s))
    }

    fn visit_bool<E>(self, b: bool) -> Result<Self::Value, E> {
        if b {
            Ok(Some("deprecated".to_string()))
        } else {
            Ok(None)
        }
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
}

struct EnginesSeed;

impl<'de> DeserializeSeed<'de> for EnginesSeed {
    type Value = (HashMap<String, String>, Option<serde_json::Value>);

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(EnginesVisitor)
    }
}

struct EnginesVisitor;

impl<'de> Visitor<'de> for EnginesVisitor {
    type Value = (HashMap<String, String>, Option<serde_json::Value>);

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("an engines map, array, or string")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = HashMap::new();
        while let Some(k) = access.next_key::<CowStr<'_>>()? {
            if let Some(s) = access.next_value::<OptStringFromStrOrNum>()?.0 {
                if map.is_empty() {
                    map.reserve(access.size_hint().unwrap_or(2));
                }
                map.insert(k.into_owned(), s);
            }
        }
        Ok((map, None))
    }

    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        let mut list = Vec::new();
        while let Some(item) = seq.next_element::<serde_json::Value>()? {
            list.push(item);
        }
        Ok((HashMap::new(), Some(serde_json::Value::Array(list))))
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok((HashMap::new(), Some(serde_json::Value::String(s.to_string()))))
    }

    fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok((HashMap::new(), Some(serde_json::Value::String(s))))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok((HashMap::new(), None))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok((HashMap::new(), None))
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok((HashMap::new(), None))
    }
}

struct PlatformListSeed;

impl<'de> DeserializeSeed<'de> for PlatformListSeed {
    type Value = PlatformList;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_platform_list(deserializer)
    }
}

pub struct VersionSeed<'a> {
    pub mode: PackumentParseMode,
    pub root_name: Option<&'a str>,
    pub version_key: Option<&'a str>,
}

impl<'de, 'a> DeserializeSeed<'de> for VersionSeed<'a> {
    type Value = AbbreviatedVersion;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(VersionVisitor {
            mode: self.mode,
            root_name: self.root_name,
            version_key: self.version_key,
        })
    }
}

struct VersionVisitor<'a> {
    mode: PackumentParseMode,
    root_name: Option<&'a str>,
    version_key: Option<&'a str>,
}

impl<'de, 'a> Visitor<'de> for VersionVisitor<'a> {
    type Value = AbbreviatedVersion;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a package version object")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut name: Option<String> = None;
        let mut version: Option<String> = None;
        let mut dist: Option<DistInfo> = None;
        let mut dependencies: IndexMap<String, String> = IndexMap::new();
        let mut dev_dependencies: IndexMap<String, String> = IndexMap::new();
        let mut peer_dependencies: IndexMap<String, String> = IndexMap::new();
        let mut peer_dependencies_meta: HashMap<String, rnpm_core::manifest::PeerDependencyMeta> =
            HashMap::new();
        let mut optional_dependencies: IndexMap<String, String> = IndexMap::new();
        let mut bundle_deps_raw: Option<RawBundleDeps> = None;
        let mut bundled_deps_raw: Option<RawBundleDeps> = None;
        let mut bin: Option<PackageBin> = None;
        let mut license: Option<String> = None;
        let mut engines: HashMap<String, String> = HashMap::new();
        let mut engines_raw: Option<serde_json::Value> = None;
        let mut os: PlatformList = PlatformList::default();
        let mut cpu: PlatformList = PlatformList::default();
        let mut libc: PlatformList = PlatformList::default();
        let mut has_install_script: bool = false;
        let mut deprecated: Option<String> = None;
        let mut extra: BTreeMap<String, serde_json::Value> = BTreeMap::new();

        while let Some(key) = access.next_key::<CowStr<'_>>()? {
            match key.0.as_ref() {
                "name" => {
                    name = access.next_value::<Option<String>>()?;
                }
                "version" => {
                    version = access.next_value::<Option<String>>()?;
                }
                "dist" => {
                    dist = access.next_value::<Option<DistInfo>>()?;
                }
                "dependencies" => {
                    dependencies = access.next_value_seed(DependencyMapSeed)?;
                }
                "devDependencies" => {
                    dev_dependencies = access.next_value_seed(DependencyMapSeed)?;
                }
                "peerDependencies" => {
                    peer_dependencies = access.next_value_seed(DependencyMapSeed)?;
                }
                "peerDependenciesMeta" => {
                    peer_dependencies_meta = access.next_value_seed(PeerDepsMetaSeed)?;
                }
                "optionalDependencies" => {
                    optional_dependencies = access.next_value_seed(DependencyMapSeed)?;
                }
                "bundleDependencies" => {
                    bundle_deps_raw = Some(access.next_value_seed(BundleDepsSeed)?);
                }
                "bundledDependencies" => {
                    bundled_deps_raw = Some(access.next_value_seed(BundleDepsSeed)?);
                }
                "bin" => {
                    bin = access.next_value_seed(BinSeed)?;
                }
                "license" => {
                    license = access.next_value_seed(LicenseSeed)?;
                }
                "engines" => {
                    let (eng_map, eng_raw) = access.next_value_seed(EnginesSeed)?;
                    engines = eng_map;
                    if eng_raw.is_some() {
                        engines_raw = eng_raw;
                    }
                }
                "os" => {
                    os = access.next_value_seed(PlatformListSeed)?;
                }
                "cpu" => {
                    cpu = access.next_value_seed(PlatformListSeed)?;
                }
                "libc" => {
                    libc = access.next_value_seed(PlatformListSeed)?;
                }
                "hasInstallScript" => {
                    has_install_script = access.next_value::<Option<bool>>()?.unwrap_or(false);
                }
                "deprecated" => {
                    deprecated = access.next_value_seed(DeprecatedSeed)?;
                }
                other => {
                    let drop = match self.mode {
                        PackumentParseMode::Install => is_heavy_unused_install_field(other),
                        PackumentParseMode::Full => is_heavy_unused_full_field(other),
                    };
                    if drop {
                        let _ = access.next_value::<serde::de::IgnoredAny>()?;
                    } else {
                        let val = access.next_value_seed(FastJsonValueSeed)?;
                        extra.insert(key.into_owned(), val);
                    }
                }
            }
        }

        // Finalize bundle_dependencies: if boolean true, bundles all dependencies keys.
        let final_bundle_deps = match bundle_deps_raw.or(bundled_deps_raw) {
            Some(RawBundleDeps::All) => dependencies.keys().cloned().collect(),
            Some(RawBundleDeps::List(list)) => list,
            None => Vec::new(),
        };

        // Fallbacks for name and version
        let final_name = name
            .or_else(|| self.root_name.map(str::to_string))
            .unwrap_or_default();
        let final_version = version
            .or_else(|| self.version_key.map(str::to_string))
            .unwrap_or_default();

        Ok(AbbreviatedVersion {
            name: final_name,
            version: final_version,
            dist: dist.unwrap_or_default(),
            dependencies,
            dev_dependencies,
            peer_dependencies,
            peer_dependencies_meta,
            optional_dependencies,
            bundle_dependencies: final_bundle_deps,
            bin,
            license,
            engines,
            engines_raw,
            os,
            cpu,
            libc,
            has_install_script,
            deprecated,
            extra,
        })
    }
}

pub struct VersionsSeed<'a> {
    pub mode: PackumentParseMode,
    pub root_name: Option<&'a str>,
}

impl<'de, 'a> DeserializeSeed<'de> for VersionsSeed<'a> {
    type Value = BTreeMap<String, AbbreviatedVersion>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(VersionsVisitor {
            mode: self.mode,
            root_name: self.root_name,
        })
    }
}

struct VersionsVisitor<'a> {
    mode: PackumentParseMode,
    root_name: Option<&'a str>,
}

impl<'de, 'a> Visitor<'de> for VersionsVisitor<'a> {
    type Value = BTreeMap<String, AbbreviatedVersion>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a map of package versions without duplicate keys")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = BTreeMap::new();
        while let Some(key) = access.next_key::<String>()? {
            match map.entry(key) {
                std::collections::btree_map::Entry::Occupied(occ) => {
                    return Err(de::Error::custom(format!(
                        "duplicate version key '{}' found in packument metadata",
                        occ.key()
                    )));
                }
                std::collections::btree_map::Entry::Vacant(vacant) => {
                    let version = access.next_value_seed(VersionSeed {
                        mode: self.mode,
                        root_name: self.root_name,
                        version_key: Some(vacant.key().as_str()),
                    })?;
                    vacant.insert(version);
                }
            }
        }
        Ok(map)
    }

    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        while let Some(serde::de::IgnoredAny) = seq.next_element()? {}
        Ok(BTreeMap::new())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(BTreeMap::new())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(BTreeMap::new())
    }
}

pub struct DistTagsSeed;

impl<'de> DeserializeSeed<'de> for DistTagsSeed {
    type Value = HashMap<String, String>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DistTagsVisitor)
    }
}

struct DistTagsVisitor;

impl<'de> Visitor<'de> for DistTagsVisitor {
    type Value = HashMap<String, String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a map of dist-tags")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = HashMap::new();
        while let Some(k) = access.next_key::<CowStr<'_>>()? {
            if let Some(s) = access.next_value::<OptStringFromStrOrNum>()?.0 {
                if map.is_empty() {
                    map.reserve(access.size_hint().unwrap_or(4));
                }
                map.insert(k.into_owned(), s);
            }
        }
        Ok(map)
    }

    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        while let Some(serde::de::IgnoredAny) = seq.next_element()? {}
        Ok(HashMap::new())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(HashMap::new())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(HashMap::new())
    }
}

pub struct TimeSeed;

impl<'de> DeserializeSeed<'de> for TimeSeed {
    type Value = BTreeMap<String, String>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(TimeVisitor)
    }
}

struct TimeVisitor;

impl<'de> Visitor<'de> for TimeVisitor {
    type Value = BTreeMap<String, String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a map of publish times")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = BTreeMap::new();
        while let Some(k) = access.next_key::<CowStr<'_>>()? {
            if let Some(s) = access.next_value::<OptStringOrSkip>()?.0 {
                map.insert(k.into_owned(), s);
            }
        }
        Ok(map)
    }

    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        while let Some(serde::de::IgnoredAny) = seq.next_element()? {}
        Ok(BTreeMap::new())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(BTreeMap::new())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(BTreeMap::new())
    }
}

pub struct PackageMetadataSeed {
    pub mode: PackumentParseMode,
}

impl<'de> DeserializeSeed<'de> for PackageMetadataSeed {
    type Value = AbbreviatedPackageMetadata;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(PackageMetadataVisitor { mode: self.mode })
    }
}

struct PackageMetadataVisitor {
    mode: PackumentParseMode,
}

impl<'de> Visitor<'de> for PackageMetadataVisitor {
    type Value = AbbreviatedPackageMetadata;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a package metadata packument object")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut name: Option<String> = None;
        let mut dist_tags: HashMap<String, String> = HashMap::new();
        let mut modified: Option<String> = None;
        let mut versions: BTreeMap<String, AbbreviatedVersion> = BTreeMap::new();
        let mut time: BTreeMap<String, String> = BTreeMap::new();
        let mut root_name_missing_during_versions = false;

        while let Some(key) = access.next_key::<CowStr<'_>>()? {
            match key.0.as_ref() {
                "name" => {
                    name = access.next_value::<Option<String>>()?;
                }
                "dist-tags" => {
                    dist_tags = access.next_value_seed(DistTagsSeed)?;
                }
                "modified" => {
                    modified = access.next_value::<Option<String>>()?;
                }
                "versions" => {
                    if name.is_none() {
                        root_name_missing_during_versions = true;
                    }
                    versions = access.next_value_seed(VersionsSeed {
                        mode: self.mode,
                        root_name: name.as_deref(),
                    })?;
                }
                "time" => {
                    time = access.next_value_seed(TimeSeed)?;
                }
                _ => {
                    let _ = access.next_value::<serde::de::IgnoredAny>()?;
                }
            }
        }

        let pkg_name = name.unwrap_or_default();

        if root_name_missing_during_versions && !pkg_name.is_empty() {
            for ver in versions.values_mut() {
                if ver.name.is_empty() {
                    ver.name = pkg_name.clone();
                }
            }
        }

        Ok(AbbreviatedPackageMetadata {
            name: pkg_name,
            dist_tags,
            modified,
            versions,
            time,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_lists_tolerate_null_entries() {
        let json = r#"{
            "name": "binding", "version": "1.0.0",
            "dist": { "tarball": "https://r/b.tgz" },
            "os": ["win32"], "cpu": ["arm64"], "libc": [null]
        }"#;
        let version: AbbreviatedVersion = serde_json::from_str(json).unwrap();
        assert_eq!(version.os.as_slice(), ["win32"]);
        assert!(version.libc.is_empty());
    }

    #[test]
    fn platform_forms_survive_metadata_cache_roundtrip() {
        let version: AbbreviatedVersion = serde_json::from_value(serde_json::json!({
            "name": "binding", "version": "1.0.0",
            "dist": { "tarball": "https://r/b.tgz" },
            "os": "linux", "cpu": ["x64"], "libc": "glibc"
        }))
        .unwrap();
        let cached = serde_json::to_vec(&version).unwrap();
        let restored: AbbreviatedVersion = serde_json::from_slice(&cached).unwrap();
        let json = serde_json::to_value(restored).unwrap();
        assert_eq!(json["os"], "linux");
        assert_eq!(json["cpu"], serde_json::json!(["x64"]));
        assert_eq!(json["libc"], "glibc");
    }

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
        assert_eq!(v.libc.as_slice(), ["glibc"]);
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
            "name": "example\r\nmalicious",
            "versions": {}
        }"#;
        let meta1: AbbreviatedPackageMetadata = serde_json::from_str(json1).unwrap();
        assert!(meta1.validate().unwrap_err().is_malformed_metadata());

        // CR/LF in dist-tag
        let json2 = r#"{
            "name": "example",
            "dist-tags": { "latest\r\n": "1.0.0" },
            "versions": {}
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

    #[test]
    fn test_quirky_couchdb_packuments_deserialization() {
        let quirky_json = r#"{
            "name": "quirky-pkg",
            "dist-tags": null,
            "versions": [],
            "time": []
        }"#;
        let meta: AbbreviatedPackageMetadata = serde_json::from_str(quirky_json).unwrap();
        assert_eq!(meta.name, "quirky-pkg");
        assert!(meta.dist_tags.is_empty());
        assert!(meta.versions.is_empty());
        assert!(meta.time.is_empty());

        let quirky_json2 = r#"{
            "name": "quirky-pkg2",
            "dist-tags": [],
            "versions": [],
            "time": null
        }"#;
        let meta2: AbbreviatedPackageMetadata = serde_json::from_str(quirky_json2).unwrap();
        assert!(meta2.dist_tags.is_empty());
        assert!(meta2.versions.is_empty());
        assert!(meta2.time.is_empty());

        let version_json = r#"{
            "name": "quirky-pkg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "quirky-pkg",
                    "version": "1.0.0",
                    "dependencies": [],
                    "devDependencies": null,
                    "optionalDependencies": false,
                    "bin": [],
                    "peerDependenciesMeta": [],
                    "dist": { "tarball": "https://registry.npmjs.org/quirky-pkg/-/quirky-pkg-1.0.0.tgz" }
                },
                "1.0.1": {
                    "name": "quirky-pkg",
                    "version": "1.0.1",
                    "dependencies": { "valid-dep": "^1.0.0", "numeric-dep": 2 },
                    "bin": "cli.js",
                    "dist": { "tarball": "https://registry.npmjs.org/quirky-pkg/-/quirky-pkg-1.0.1.tgz" }
                },
                "1.0.2": {
                    "name": "quirky-pkg",
                    "version": "1.0.2",
                    "bin": ["./bin/tool.js", "bin/runner"],
                    "dist": { "tarball": "https://registry.npmjs.org/quirky-pkg/-/quirky-pkg-1.0.2.tgz" }
                }
            }
        }"#;
        let meta3: AbbreviatedPackageMetadata = serde_json::from_str(version_json).unwrap();
        assert_eq!(meta3.versions.len(), 3);
        let v0 = meta3.versions.get("1.0.0").unwrap();
        assert!(v0.dependencies.is_empty());
        assert!(v0.dev_dependencies.is_empty());
        assert!(v0.optional_dependencies.is_empty());
        assert!(v0.bin.is_none());
        assert!(v0.peer_dependencies_meta.is_empty());

        let v1 = meta3.versions.get("1.0.1").unwrap();
        assert_eq!(v1.dependencies.get("valid-dep").unwrap(), "^1.0.0");
        assert_eq!(v1.dependencies.get("numeric-dep").unwrap(), "2");
        assert_eq!(
            v1.bin.as_ref().unwrap().clone().into_map("quirky-pkg"),
            [("quirky-pkg".to_string(), "cli.js".to_string())].into_iter().collect()
        );

        let v2 = meta3.versions.get("1.0.2").unwrap();
        assert_eq!(
            v2.bin.as_ref().unwrap().clone().into_map("quirky-pkg"),
            [
                ("tool.js".to_string(), "./bin/tool.js".to_string()),
                ("runner".to_string(), "bin/runner".to_string())
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn test_lean_install_packument_preserves_resolution_and_drops_bloat() {
        let full_doc = r##"{
            "name": "super-pkg",
            "description": "Root description should be ignored without allocating DOM",
            "readme": "Root Readme\nThis is a massive 50KB readme string that should never be allocated in heap",
            "maintainers": [
                { "name": "alice", "email": "alice@example.com" },
                { "name": "bob", "email": "bob@example.com" }
            ],
            "dist-tags": { "latest": "1.0.0" },
            "time": {
                "modified": "2026-02-01T00:00:00.000Z",
                "created": "2026-01-01T00:00:00.000Z",
                "1.0.0": "2026-01-01T12:00:00.000Z"
            },
            "versions": {
                "1.0.0": {
                    "name": "super-pkg",
                    "version": "1.0.0",
                    "description": "Version description to drop",
                    "readme": "Massive version readme string",
                    "maintainers": [{ "name": "alice" }],
                    "contributors": [{ "name": "carol" }],
                    "users": { "fan1": true, "fan2": true },
                    "bugs": { "url": "https://github.com/super/pkg/issues" },
                    "homepage": "https://superpkg.org",
                    "keywords": ["super", "fast", "lean"],
                    "repository": { "type": "git", "url": "https://github.com/super/pkg.git" },
                    "author": "Alice",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/super-pkg/-/super-pkg-1.0.0.tgz",
                        "shasum": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                        "integrity": "sha512-testintegrity==",
                        "signatures": [
                            { "keyid": "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA", "sig": "MEQCIB..." }
                        ]
                    },
                    "bin": ["./bin/cli.js", "bin/daemon"],
                    "engines": { "node": ">=18.0.0" },
                    "os": ["linux", "darwin"],
                    "cpu": ["x64", "arm64"],
                    "libc": ["glibc"],
                    "dependencies": {
                        "dep-a": "^1.0.0",
                        "dep-numeric": 12
                    },
                    "devDependencies": { "dev-dep": "^2.0.0" },
                    "optionalDependencies": { "opt-dep": "^3.0.0" },
                    "peerDependencies": { "peer-dep": "^4.0.0" },
                    "peerDependenciesMeta": {
                        "peer-dep": { "optional": true }
                    },
                    "bundleDependencies": ["dep-a"],
                    "deprecated": "This version is deprecated",
                    "license": "Apache-2.0",
                    "funding": { "type": "github", "url": "https://github.com/sponsors/super" },
                    "hasInstallScript": true,
                    "_hasShrinkwrap": true,
                    "scripts": { "test": "cargo test" }
                }
            }
        }"##;

        let meta = parse_install_packument(full_doc.as_bytes()).unwrap();
        assert_eq!(meta.name, "super-pkg");
        assert_eq!(meta.dist_tags.get("latest"), Some(&"1.0.0".to_string()));
        assert_eq!(
            meta.time.get("1.0.0"),
            Some(&"2026-01-01T12:00:00.000Z".to_string())
        );

        let v = meta.versions.get("1.0.0").unwrap();
        // Preserved resolution and lockfile fields
        assert_eq!(v.name, "super-pkg");
        assert_eq!(v.version, "1.0.0");
        assert_eq!(
            v.dist.tarball,
            "https://registry.npmjs.org/super-pkg/-/super-pkg-1.0.0.tgz"
        );
        assert_eq!(
            v.dist.integrity.as_deref(),
            Some("sha512-testintegrity==")
        );
        assert_eq!(v.dist.signatures.len(), 1);
        assert_eq!(
            v.dist.signatures[0].keyid,
            "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"
        );

        let bin_map = v.bin.as_ref().unwrap().clone().into_map(&v.name);
        assert_eq!(bin_map.get("cli.js"), Some(&"./bin/cli.js".to_string()));
        assert_eq!(bin_map.get("daemon"), Some(&"bin/daemon".to_string()));

        assert_eq!(v.engines.get("node"), Some(&">=18.0.0".to_string()));
        assert_eq!(v.os.as_slice(), ["linux", "darwin"]);
        assert_eq!(v.cpu.as_slice(), ["x64", "arm64"]);
        assert_eq!(v.libc.as_slice(), ["glibc"]);

        assert_eq!(v.dependencies.get("dep-a"), Some(&"^1.0.0".to_string()));
        assert_eq!(v.dependencies.get("dep-numeric"), Some(&"12".to_string()));
        assert_eq!(v.dev_dependencies.get("dev-dep"), Some(&"^2.0.0".to_string()));
        assert_eq!(v.optional_dependencies.get("opt-dep"), Some(&"^3.0.0".to_string()));
        assert_eq!(v.peer_dependencies.get("peer-dep"), Some(&"^4.0.0".to_string()));
        assert!(v.peer_dependencies_meta.get("peer-dep").unwrap().optional);
        assert_eq!(v.bundle_dependencies, vec!["dep-a"]);

        assert_eq!(v.deprecated.as_deref(), Some("This version is deprecated"));
        assert_eq!(v.license.as_deref(), Some("Apache-2.0"));
        assert!(v.has_install_script);

        // Required extra fields preserved
        assert!(v.extra.contains_key("funding"));
        assert!(v.extra.contains_key("_hasShrinkwrap"));
        assert!(v.extra.contains_key("scripts"));

        // Heavy bloated fields MUST be dropped in install mode
        assert!(!v.extra.contains_key("readme"));
        assert!(!v.extra.contains_key("maintainers"));
        assert!(!v.extra.contains_key("contributors"));
        assert!(!v.extra.contains_key("users"));
        assert!(!v.extra.contains_key("bugs"));
        assert!(!v.extra.contains_key("homepage"));
        assert!(!v.extra.contains_key("keywords"));
        assert!(!v.extra.contains_key("repository"));
        assert!(!v.extra.contains_key("author"));
        assert!(!v.extra.contains_key("description"));
    }

    #[test]
    fn test_install_v1_and_full_json_produce_identical_resolution_fields() {
        let full_doc = r#"{
            "name": "parity-pkg",
            "dist-tags": { "latest": "1.0.0" },
            "readme": "Huge README",
            "versions": {
                "1.0.0": {
                    "name": "parity-pkg",
                    "version": "1.0.0",
                    "readme": "version readme",
                    "maintainers": [{ "name": "foo" }],
                    "dist": {
                        "tarball": "https://registry.npmjs.org/parity-pkg/-/parity-pkg-1.0.0.tgz",
                        "integrity": "sha512-identical=="
                    },
                    "bin": { "cli": "bin/cli.js" },
                    "engines": { "node": ">=16" },
                    "os": ["win32"],
                    "cpu": ["x64"],
                    "libc": ["msvc"],
                    "dependencies": { "dep": "^1.0.0" },
                    "optionalDependencies": { "opt": "1.0.0" },
                    "peerDependencies": { "peer": "*" },
                    "bundleDependencies": ["dep"],
                    "license": "MIT",
                    "funding": "https://sponsor.me",
                    "hasInstallScript": true
                }
            }
        }"#;

        let corgi_doc = r#"{
            "name": "parity-pkg",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "parity-pkg",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/parity-pkg/-/parity-pkg-1.0.0.tgz",
                        "integrity": "sha512-identical=="
                    },
                    "bin": { "cli": "bin/cli.js" },
                    "engines": { "node": ">=16" },
                    "os": ["win32"],
                    "cpu": ["x64"],
                    "libc": ["msvc"],
                    "dependencies": { "dep": "^1.0.0" },
                    "optionalDependencies": { "opt": "1.0.0" },
                    "peerDependencies": { "peer": "*" },
                    "bundleDependencies": ["dep"],
                    "license": "MIT",
                    "funding": "https://sponsor.me",
                    "hasInstallScript": true
                }
            }
        }"#;

        let full_meta = parse_install_packument(full_doc.as_bytes()).unwrap();
        let corgi_meta = parse_install_packument(corgi_doc.as_bytes()).unwrap();

        assert_eq!(full_meta.name, corgi_meta.name);
        assert_eq!(full_meta.dist_tags, corgi_meta.dist_tags);

        let vf = &full_meta.versions["1.0.0"];
        let vc = &corgi_meta.versions["1.0.0"];

        assert_eq!(vf.name, vc.name);
        assert_eq!(vf.version, vc.version);
        assert_eq!(vf.dist, vc.dist);
        assert_eq!(vf.bin, vc.bin);
        assert_eq!(vf.engines, vc.engines);
        assert_eq!(vf.os, vc.os);
        assert_eq!(vf.cpu, vc.cpu);
        assert_eq!(vf.libc, vc.libc);
        assert_eq!(vf.dependencies, vc.dependencies);
        assert_eq!(vf.optional_dependencies, vc.optional_dependencies);
        assert_eq!(vf.peer_dependencies, vc.peer_dependencies);
        assert_eq!(vf.bundle_dependencies, vc.bundle_dependencies);
        assert_eq!(vf.license, vc.license);
        assert_eq!(vf.has_install_script, vc.has_install_script);
        assert_eq!(vf.extra, vc.extra);
    }

    #[test]
    fn test_full_packument_mode_retains_repository_while_dropping_readme() {
        let full_doc = r#"{
            "name": "full-pkg",
            "readme": "Huge root readme",
            "versions": {
                "1.0.0": {
                    "name": "full-pkg",
                    "version": "1.0.0",
                    "readme": "Huge version readme",
                    "maintainers": [{ "name": "admin" }],
                    "repository": { "type": "git", "url": "https://github.com/full/pkg.git" },
                    "homepage": "https://fullpkg.org",
                    "bugs": { "url": "https://github.com/full/pkg/issues" },
                    "dist": { "tarball": "https://registry.npmjs.org/full-pkg/-/full-pkg-1.0.0.tgz" }
                }
            }
        }"#;

        let meta = parse_full_packument(full_doc.as_bytes()).unwrap();
        let v = &meta.versions["1.0.0"];

        // Retains repository, homepage, bugs for CLI view/repo commands
        assert!(v.extra.contains_key("repository"));
        assert!(v.extra.contains_key("homepage"));
        assert!(v.extra.contains_key("bugs"));

        // Drops bloated readme and maintainers
        assert!(!v.extra.contains_key("readme"));
        assert!(!v.extra.contains_key("maintainers"));
    }

    #[test]
    fn test_bundle_dependencies_boolean_true_bundles_all_dependencies() {
        let json = r#"{
            "name": "bundle-all",
            "versions": {
                "1.0.0": {
                    "name": "bundle-all",
                    "version": "1.0.0",
                    "dependencies": { "dep1": "^1.0", "dep2": "^2.0" },
                    "bundleDependencies": true,
                    "dist": { "tarball": "https://registry.npmjs.org/bundle-all/-/bundle-all-1.0.0.tgz" }
                }
            }
        }"#;

        let meta = parse_install_packument(json.as_bytes()).unwrap();
        let mut bundled = meta.versions["1.0.0"].bundle_dependencies.clone();
        bundled.sort();
        assert_eq!(bundled, vec!["dep1".to_string(), "dep2".to_string()]);
    }

    #[test]
    fn test_negative_zero_parity_with_serde_json() {
        let json = r#"{
            "name": "neg-zero",
            "dist-tags": { "latest": "1.0.0", "neg": -0 },
            "versions": {
                "1.0.0": {
                    "name": "neg-zero",
                    "version": "1.0.0",
                    "dependencies": { "numdep": -0 },
                    "custom": -0,
                    "dist": { "tarball": "https://registry.npmjs.org/neg-zero/-/neg-zero-1.0.0.tgz" }
                }
            }
        }"#;
        let fast = parse_full_packument(json.as_bytes()).unwrap();
        let serde_meta: AbbreviatedPackageMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(fast.dist_tags.get("neg"), serde_meta.dist_tags.get("neg"));
        assert_eq!(
            fast.versions["1.0.0"].dependencies.get("numdep"),
            serde_meta.versions["1.0.0"].dependencies.get("numdep")
        );
        assert_eq!(
            fast.versions["1.0.0"].extra.get("custom").map(ToString::to_string),
            serde_meta.versions["1.0.0"].extra.get("custom").map(ToString::to_string)
        );
    }

}
