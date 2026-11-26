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

/// Fast-path validation for standard canonical lowercase `http://`/`https://` ASCII URLs
/// (no IDNA/punycode, no percent escapes, no query/fragment, alphabetic TLD label, valid port).
/// Returns `false` for anything unusual so callers fall back to full `Url::parse` parity.
#[cfg(test)]
#[inline]
#[allow(dead_code)]
fn is_fast_valid_http_tarball_url(s: &str) -> bool {
    fast_http_tarball_origin_end(s).is_some()
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
    let metadata = FastPackumentParser::new(bytes).parse_root(mode)?;
    metadata.validate()?;
    Ok(metadata)
}

// ---------------------------------------------------------------------------
// Direct RFC-8259 Byte-Slice Packument Parser
// ---------------------------------------------------------------------------

const MAX_JSON_DEPTH: usize = 128;

#[inline(never)]
#[cold]
fn json_syntax_err(msg: &str) -> RegistryError {
    RegistryError::Json(serde::de::Error::custom(msg))
}

#[inline]
fn hex_val(b: u8) -> Option<u16> {
    match b {
        b'0'..=b'9' => Some((b - b'0') as u16),
        b'a'..=b'f' => Some((b - b'a' + 10) as u16),
        b'A'..=b'F' => Some((b - b'A' + 10) as u16),
        _ => None,
    }
}

enum FastStr<'a> {
    Borrowed(&'a str),
    Scratch,
}

impl<'a> FastStr<'a> {
    #[inline]
    fn as_str<'s>(&'s self, scratch: &'s [u8]) -> &'s str {
        match self {
            FastStr::Borrowed(s) => s,
            FastStr::Scratch => {
                // SAFETY: `scratch` is exclusively written from validated UTF-8 sequences.
                unsafe { std::str::from_utf8_unchecked(scratch) }
            }
        }
    }

    #[inline]
    fn into_string(self, scratch: &[u8]) -> String {
        self.as_str(scratch).to_owned()
    }
}

struct FastPackumentParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    scratch: Vec<u8>,
}

impl<'a> FastPackumentParser<'a> {
    #[inline]
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            scratch: Vec::new(),
        }
    }

    #[inline]
    fn skip_ws(&mut self) {
        let len = self.bytes.len();
        let mut p = self.pos;
        if p < len && !matches!(self.bytes[p], b' ' | b'\n' | b'\r' | b'\t') {
            return;
        }
        while p < len && matches!(self.bytes[p], b' ' | b'\n' | b'\r' | b'\t') {
            p += 1;
        }
        self.pos = p;
    }

    #[inline]
    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.bytes.get(self.pos).copied()
    }

    #[inline]
    fn expect_byte(&mut self, expected: u8) -> Result<(), RegistryError> {
        if self.bytes.get(self.pos).copied() == Some(expected) {
            self.pos += 1;
            return Ok(());
        }
        self.skip_ws();
        if self.bytes.get(self.pos).copied() == Some(expected) {
            self.pos += 1;
            Ok(())
        } else {
            Err(json_syntax_err("unexpected token in JSON"))
        }
    }

    #[inline]
    fn consume_literal(&mut self, lit: &[u8]) -> Result<(), RegistryError> {
        if self.bytes.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(json_syntax_err("invalid JSON literal"))
        }
    }

    /// Scans a JSON string using 8-byte SWAR chunks for plain ASCII runs.
    /// Returns `FastStr::Borrowed` without allocating when there are no escapes.
    #[inline]
    fn parse_str<'s>(&'s mut self) -> Result<FastStr<'a>, RegistryError> {
        if self.bytes.get(self.pos).copied() != Some(b'"') {
            return Err(json_syntax_err("expected JSON string"));
        }
        self.pos += 1;
        let start = self.pos;
        let len = self.bytes.len();
        let mut p = start;
        let mut all_ascii = true;

        const HI: u64 = 0x8080_8080_8080_8080;
        const LO: u64 = 0x0101_0101_0101_0101;
        const QUOTE_MASK: u64 = LO * (b'"' as u64);
        const SLASH_MASK: u64 = LO * (b'\\' as u64);
        const CTRL_MASK: u64 = LO * 0x20;

        while p + 8 <= len {
            let w = u64::from_le_bytes(self.bytes[p..p + 8].try_into().unwrap());
            let q = w ^ QUOTE_MASK;
            let bs = w ^ SLASH_MASK;
            let has_special = (w & HI)
                | (w.wrapping_sub(CTRL_MASK) & !w & HI)
                | (q.wrapping_sub(LO) & !q & HI)
                | (bs.wrapping_sub(LO) & !bs & HI);
            if has_special == 0 {
                p += 8;
            } else {
                break;
            }
        }

        while p < len {
            let b = self.bytes[p];
            if b == b'"' {
                self.pos = p + 1;
                let s = if all_ascii {
                    // SAFETY: all bytes in start..p are < 0x80 and thus valid UTF-8.
                    unsafe { std::str::from_utf8_unchecked(&self.bytes[start..p]) }
                } else {
                    std::str::from_utf8(&self.bytes[start..p])
                        .map_err(|_| json_syntax_err("invalid UTF-8 in JSON string"))?
                };
                return Ok(FastStr::Borrowed(s));
            }
            if b == b'\\' {
                self.finish_escaped_str(start, p, all_ascii)?;
                return Ok(FastStr::Scratch);
            }
            if b < 0x20 {
                return Err(json_syntax_err("unescaped control character in JSON string"));
            }
            if b >= 0x80 {
                all_ascii = false;
            }
            p += 1;
        }

        Err(json_syntax_err("unterminated JSON string"))
    }

    #[inline(never)]
    fn finish_escaped_str(
        &mut self,
        start: usize,
        mut p: usize,
        prefix_ascii: bool,
    ) -> Result<(), RegistryError> {
        let len = self.bytes.len();
        self.scratch.clear();
        if !prefix_ascii {
            std::str::from_utf8(&self.bytes[start..p])
                .map_err(|_| json_syntax_err("invalid UTF-8 in JSON string"))?;
        }
        self.scratch.extend_from_slice(&self.bytes[start..p]);

        while p < len {
            let b = self.bytes[p];
            if b == b'"' {
                self.pos = p + 1;
                return Ok(());
            }
            if b == b'\\' {
                p += 1;
                if p >= len {
                    return Err(json_syntax_err("unexpected EOF in JSON string escape"));
                }
                match self.bytes[p] {
                    b'"' => {
                        self.scratch.push(b'"');
                        p += 1;
                    }
                    b'\\' => {
                        self.scratch.push(b'\\');
                        p += 1;
                    }
                    b'/' => {
                        self.scratch.push(b'/');
                        p += 1;
                    }
                    b'b' => {
                        self.scratch.push(0x08);
                        p += 1;
                    }
                    b'f' => {
                        self.scratch.push(0x0c);
                        p += 1;
                    }
                    b'n' => {
                        self.scratch.push(b'\n');
                        p += 1;
                    }
                    b'r' => {
                        self.scratch.push(b'\r');
                        p += 1;
                    }
                    b't' => {
                        self.scratch.push(b'\t');
                        p += 1;
                    }
                    b'u' => {
                        p += 1;
                        let u1 = self.read_hex4(&mut p)?;
                        let ch = if (0xD800..=0xDBFF).contains(&u1) {
                            if p + 6 > len || self.bytes[p] != b'\\' || self.bytes[p + 1] != b'u' {
                                return Err(json_syntax_err("unpaired UTF-16 high surrogate"));
                            }
                            p += 2;
                            let u2 = self.read_hex4(&mut p)?;
                            if !(0xDC00..=0xDFFF).contains(&u2) {
                                return Err(json_syntax_err("invalid UTF-16 low surrogate"));
                            }
                            let code = 0x10000 + (((u1 as u32 - 0xD800) << 10) | (u2 as u32 - 0xDC00));
                            char::from_u32(code)
                                .ok_or_else(|| json_syntax_err("invalid surrogate codepoint"))?
                        } else if (0xDC00..=0xDFFF).contains(&u1) {
                            return Err(json_syntax_err("unpaired UTF-16 low surrogate"));
                        } else {
                            char::from_u32(u1 as u32)
                                .ok_or_else(|| json_syntax_err("invalid unicode scalar"))?
                        };
                        let mut utf8_buf = [0u8; 4];
                        self.scratch
                            .extend_from_slice(ch.encode_utf8(&mut utf8_buf).as_bytes());
                    }
                    _ => return Err(json_syntax_err("invalid JSON string escape")),
                }
            } else if b < 0x20 {
                return Err(json_syntax_err("unescaped control character in JSON string"));
            } else if b < 0x80 {
                self.scratch.push(b);
                p += 1;
            } else {
                let chunk_start = p;
                p += 1;
                while p < len && self.bytes[p] >= 0x80 {
                    p += 1;
                }
                let slice = &self.bytes[chunk_start..p];
                std::str::from_utf8(slice)
                    .map_err(|_| json_syntax_err("invalid UTF-8 in JSON string"))?;
                self.scratch.extend_from_slice(slice);
            }
        }

        Err(json_syntax_err("unterminated JSON string"))
    }

    #[inline]
    fn read_hex4(&self, p: &mut usize) -> Result<u16, RegistryError> {
        let idx = *p;
        if idx + 4 > self.bytes.len() {
            return Err(json_syntax_err("truncated \\uXXXX escape"));
        }
        let h0 = hex_val(self.bytes[idx]).ok_or_else(|| json_syntax_err("invalid hex in \\uXXXX"))?;
        let h1 = hex_val(self.bytes[idx + 1]).ok_or_else(|| json_syntax_err("invalid hex in \\uXXXX"))?;
        let h2 = hex_val(self.bytes[idx + 2]).ok_or_else(|| json_syntax_err("invalid hex in \\uXXXX"))?;
        let h3 = hex_val(self.bytes[idx + 3]).ok_or_else(|| json_syntax_err("invalid hex in \\uXXXX"))?;
        *p = idx + 4;
        Ok((h0 << 12) | (h1 << 8) | (h2 << 4) | h3)
    }

    #[inline]
    fn skip_string(&mut self) -> Result<(), RegistryError> {
        if self.bytes.get(self.pos).copied() != Some(b'"') {
            return Err(json_syntax_err("expected JSON string"));
        }
        self.pos += 1;
        let len = self.bytes.len();
        let mut p = self.pos;

        const HI: u64 = 0x8080_8080_8080_8080;
        const LO: u64 = 0x0101_0101_0101_0101;
        const QUOTE_MASK: u64 = LO * (b'"' as u64);
        const SLASH_MASK: u64 = LO * (b'\\' as u64);
        const CTRL_MASK: u64 = LO * 0x20;

        while p < len {
            while p + 8 <= len {
                let w = u64::from_le_bytes(self.bytes[p..p + 8].try_into().unwrap());
                let q = w ^ QUOTE_MASK;
                let bs = w ^ SLASH_MASK;
                let has_special = (w & HI)
                    | (w.wrapping_sub(CTRL_MASK) & !w & HI)
                    | (q.wrapping_sub(LO) & !q & HI)
                    | (bs.wrapping_sub(LO) & !bs & HI);
                if has_special == 0 {
                    p += 8;
                } else {
                    break;
                }
            }
            if p >= len {
                break;
            }
            let b = self.bytes[p];
            if b == b'"' {
                self.pos = p + 1;
                return Ok(());
            }
            if b == b'\\' {
                p += 1;
                if p >= len {
                    return Err(json_syntax_err("unterminated escape in JSON string"));
                }
                match self.bytes[p] {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => p += 1,
                    b'u' => {
                        p += 1;
                        let u1 = self.read_hex4(&mut p)?;
                        if (0xD800..=0xDBFF).contains(&u1) {
                            if p + 6 > len || self.bytes[p] != b'\\' || self.bytes[p + 1] != b'u' {
                                return Err(json_syntax_err("unpaired UTF-16 high surrogate"));
                            }
                            p += 2;
                            let u2 = self.read_hex4(&mut p)?;
                            if !(0xDC00..=0xDFFF).contains(&u2) {
                                return Err(json_syntax_err("invalid UTF-16 low surrogate"));
                            }
                        } else if (0xDC00..=0xDFFF).contains(&u1) {
                            return Err(json_syntax_err("unpaired UTF-16 low surrogate"));
                        }
                    }
                    _ => return Err(json_syntax_err("invalid JSON string escape")),
                }
            } else if b < 0x20 {
                return Err(json_syntax_err("unescaped control character in JSON string"));
            } else if b >= 0x80 {
                let chunk_start = p;
                p += 1;
                while p < len && self.bytes[p] >= 0x80 {
                    p += 1;
                }
                std::str::from_utf8(&self.bytes[chunk_start..p])
                    .map_err(|_| json_syntax_err("invalid UTF-8 in JSON string"))?;
            } else {
                p += 1;
            }
        }
        Err(json_syntax_err("unterminated JSON string"))
    }

    #[inline]
    fn skip_number(&mut self) -> Result<&'a [u8], RegistryError> {
        let start = self.pos;
        let len = self.bytes.len();
        let mut p = start;
        if p < len && self.bytes[p] == b'-' {
            p += 1;
        }
        if p >= len {
            return Err(json_syntax_err("invalid JSON number"));
        }
        if self.bytes[p] == b'0' {
            p += 1;
            if p < len && self.bytes[p].is_ascii_digit() {
                return Err(json_syntax_err("leading zero in JSON number"));
            }
        } else if matches!(self.bytes[p], b'1'..=b'9') {
            p += 1;
            while p < len && self.bytes[p].is_ascii_digit() {
                p += 1;
            }
        } else {
            return Err(json_syntax_err("invalid JSON number"));
        }

        if p < len && self.bytes[p] == b'.' {
            p += 1;
            if p >= len || !self.bytes[p].is_ascii_digit() {
                return Err(json_syntax_err("invalid fraction in JSON number"));
            }
            p += 1;
            while p < len && self.bytes[p].is_ascii_digit() {
                p += 1;
            }
        }

        if p < len && (self.bytes[p] == b'e' || self.bytes[p] == b'E') {
            p += 1;
            if p < len && (self.bytes[p] == b'+' || self.bytes[p] == b'-') {
                p += 1;
            }
            if p >= len || !self.bytes[p].is_ascii_digit() {
                return Err(json_syntax_err("invalid exponent in JSON number"));
            }
            p += 1;
            while p < len && self.bytes[p].is_ascii_digit() {
                p += 1;
            }
        }
        self.pos = p;
        Ok(&self.bytes[start..p])
    }

    fn skip_value(&mut self, depth: usize) -> Result<(), RegistryError> {
        if depth > MAX_JSON_DEPTH {
            return Err(json_syntax_err("JSON recursion limit exceeded"));
        }
        match self.peek() {
            Some(b'"') => self.skip_string(),
            Some(b'{') => {
                self.pos += 1;
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    self.skip_ws();
                    self.skip_string()?;
                    self.expect_byte(b':')?;
                    self.skip_value(depth + 1)?;
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(());
                        }
                        _ => return Err(json_syntax_err("expected ',' or '}' in JSON object")),
                    }
                }
            }
            Some(b'[') => {
                self.pos += 1;
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    self.skip_value(depth + 1)?;
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(());
                        }
                        _ => return Err(json_syntax_err("expected ',' or ']' in JSON array")),
                    }
                }
            }
            Some(b't') => self.consume_literal(b"true"),
            Some(b'f') => self.consume_literal(b"false"),
            Some(b'n') => self.consume_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => {
                self.skip_number()?;
                Ok(())
            }
            _ => Err(json_syntax_err("unexpected token while skipping JSON value")),
        }
    }

    fn parse_serde_value(&mut self, depth: usize) -> Result<serde_json::Value, RegistryError> {
        if depth > MAX_JSON_DEPTH {
            return Err(json_syntax_err("JSON recursion limit exceeded"));
        }
        match self.peek() {
            Some(b'"') => Ok(serde_json::Value::String(
                self.parse_str()?.into_string(&self.scratch),
            )),
            Some(b't') => {
                self.consume_literal(b"true")?;
                Ok(serde_json::Value::Bool(true))
            }
            Some(b'f') => {
                self.consume_literal(b"false")?;
                Ok(serde_json::Value::Bool(false))
            }
            Some(b'n') => {
                self.consume_literal(b"null")?;
                Ok(serde_json::Value::Null)
            }
            Some(b'-' | b'0'..=b'9') => {
                let slice = self.skip_number()?;
                if !slice.contains(&b'.') && !slice.contains(&b'e') && !slice.contains(&b'E') {
                    // SAFETY: `skip_number` verified ASCII digits with optional leading '-'.
                    let s = unsafe { std::str::from_utf8_unchecked(slice) };
                    if slice[0] == b'-' {
                        if let Ok(v) = s.parse::<i64>() {
                            return Ok(serde_json::Value::Number(v.into()));
                        }
                    } else if let Ok(v) = s.parse::<u64>() {
                        return Ok(serde_json::Value::Number(v.into()));
                    }
                }
                let f: f64 = serde_json::from_slice(slice).map_err(RegistryError::Json)?;
                let n = serde_json::Number::from_f64(f)
                    .ok_or_else(|| json_syntax_err("invalid JSON float"))?;
                Ok(serde_json::Value::Number(n))
            }
            Some(b'{') => {
                self.pos += 1;
                let mut map = serde_json::Map::new();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(serde_json::Value::Object(map));
                }
                loop {
                    self.skip_ws();
                    let k = self.parse_str()?.into_string(&self.scratch);
                    self.expect_byte(b':')?;
                    let v = self.parse_serde_value(depth + 1)?;
                    map.insert(k, v);
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(serde_json::Value::Object(map));
                        }
                        _ => return Err(json_syntax_err("expected ',' or '}' in JSON object")),
                    }
                }
            }
            Some(b'[') => {
                self.pos += 1;
                let mut vec = Vec::new();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(serde_json::Value::Array(vec));
                }
                loop {
                    let elem = self.parse_serde_value(depth + 1)?;
                    vec.push(elem);
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(serde_json::Value::Array(vec));
                        }
                        _ => return Err(json_syntax_err("expected ',' or ']' in JSON array")),
                    }
                }
            }
            _ => Err(json_syntax_err("unexpected token in JSON value")),
        }
    }

    #[inline]
    fn parse_opt_string(&mut self) -> Result<Option<String>, RegistryError> {
        match self.peek() {
            Some(b'n') => {
                self.consume_literal(b"null")?;
                Ok(None)
            }
            Some(b'"') => {
                let fs = self.parse_str()?;
                Ok(Some(fs.into_string(&self.scratch)))
            }
            _ => Err(json_syntax_err("expected string or null")),
        }
    }

    #[inline]
    fn parse_req_string(&mut self) -> Result<String, RegistryError> {
        self.skip_ws();
        let fs = self.parse_str()?;
        Ok(fs.into_string(&self.scratch))
    }

    #[inline]
    fn parse_opt_string_or_skip(&mut self, depth: usize) -> Result<Option<String>, RegistryError> {
        match self.peek() {
            Some(b'"') => {
                let fs = self.parse_str()?;
                Ok(Some(fs.into_string(&self.scratch)))
            }
            _ => {
                self.skip_value(depth)?;
                Ok(None)
            }
        }
    }

    #[inline]
    fn parse_opt_str_or_num(&mut self, depth: usize) -> Result<Option<String>, RegistryError> {
        match self.peek() {
            Some(b'"') => {
                let fs = self.parse_str()?;
                Ok(Some(fs.into_string(&self.scratch)))
            }
            Some(b'-' | b'0'..=b'9') => {
                let slice = self.skip_number()?;
                if !slice.contains(&b'.') && !slice.contains(&b'e') && !slice.contains(&b'E') {
                    // Integer bytes match serde visit_i64/visit_u64 string representation unless outside u64/i64
                    if let Ok(s) = std::str::from_utf8(slice) {
                        if s.starts_with('-') {
                            if s.parse::<i64>().is_ok() {
                                return Ok(Some(s.to_owned()));
                            }
                        } else if s.parse::<u64>().is_ok() {
                            return Ok(Some(s.to_owned()));
                        }
                    }
                }
                let f: f64 = serde_json::from_slice(slice).map_err(RegistryError::Json)?;
                let n = serde_json::Number::from_f64(f)
                    .ok_or_else(|| json_syntax_err("invalid float number"))?;
                Ok(Some(n.to_string()))
            }
            _ => {
                self.skip_value(depth)?;
                Ok(None)
            }
        }
    }

    fn parse_dist_tags(&mut self, depth: usize) -> Result<HashMap<String, String>, RegistryError> {
        match self.peek() {
            Some(b'{') => {
                self.pos += 1;
                let mut map = HashMap::new();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(map);
                }
                map.reserve(4);
                loop {
                    self.skip_ws();
                    let k = self.parse_str()?.into_string(&self.scratch);
                    self.expect_byte(b':')?;
                    if let Some(v) = self.parse_opt_str_or_num(depth + 1)? {
                        map.insert(k, v);
                    }
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(map);
                        }
                        _ => return Err(json_syntax_err("expected ',' or '}' in dist-tags")),
                    }
                }
            }
            Some(b'[' | b'n') => {
                self.skip_value(depth)?;
                Ok(HashMap::new())
            }
            _ => Err(json_syntax_err("expected object, array, or null for dist-tags")),
        }
    }

    fn parse_time(&mut self, depth: usize) -> Result<BTreeMap<String, String>, RegistryError> {
        match self.peek() {
            Some(b'{') => {
                self.pos += 1;
                let mut map = BTreeMap::new();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(map);
                }
                loop {
                    self.skip_ws();
                    let k = self.parse_str()?.into_string(&self.scratch);
                    self.expect_byte(b':')?;
                    if let Some(v) = self.parse_opt_string_or_skip(depth + 1)? {
                        map.insert(k, v);
                    }
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(map);
                        }
                        _ => return Err(json_syntax_err("expected ',' or '}' in time map")),
                    }
                }
            }
            Some(b'[' | b'n') => {
                self.skip_value(depth)?;
                Ok(BTreeMap::new())
            }
            _ => Err(json_syntax_err("expected object, array, or null for time")),
        }
    }

    fn parse_dep_map(&mut self, depth: usize) -> Result<IndexMap<String, String>, RegistryError> {
        match self.peek() {
            Some(b'{') => {
                self.pos += 1;
                let mut map = IndexMap::new();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(map);
                }
                loop {
                    self.skip_ws();
                    let k = self.parse_str()?.into_string(&self.scratch);
                    self.expect_byte(b':')?;
                    if let Some(v) = self.parse_opt_str_or_num(depth + 1)? {
                        if map.is_empty() {
                            map.reserve(4);
                        }
                        map.insert(k, v);
                    }
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(map);
                        }
                        _ => return Err(json_syntax_err("expected ',' or '}' in dependencies map")),
                    }
                }
            }
            Some(b'[' | b'n' | b't' | b'f' | b'"') => {
                self.skip_value(depth)?;
                Ok(IndexMap::new())
            }
            _ => Err(json_syntax_err("expected dependency map or ignorable value")),
        }
    }

    fn parse_peer_deps_meta(
        &mut self,
        depth: usize,
    ) -> Result<HashMap<String, rnpm_core::manifest::PeerDependencyMeta>, RegistryError> {
        match self.peek() {
            Some(b'{') => {
                let start = self.pos;
                self.skip_value(depth)?;
                serde_json::from_slice(&self.bytes[start..self.pos]).map_err(RegistryError::Json)
            }
            Some(b'[' | b'n' | b't' | b'f' | b'"') => {
                self.skip_value(depth)?;
                Ok(HashMap::new())
            }
            _ => Err(json_syntax_err("expected peerDependenciesMeta map")),
        }
    }

    fn parse_bundle_deps(&mut self, depth: usize) -> Result<RawBundleDeps, RegistryError> {
        match self.peek() {
            Some(b't') => {
                self.consume_literal(b"true")?;
                Ok(RawBundleDeps::All)
            }
            Some(b'f') => {
                self.consume_literal(b"false")?;
                Ok(RawBundleDeps::List(Vec::new()))
            }
            Some(b'n') => {
                self.consume_literal(b"null")?;
                Ok(RawBundleDeps::List(Vec::new()))
            }
            Some(b'[') => {
                self.pos += 1;
                let mut list = Vec::new();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(RawBundleDeps::List(list));
                }
                loop {
                    if let Some(s) = self.parse_opt_string_or_skip(depth + 1)? {
                        list.push(s);
                    }
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(RawBundleDeps::List(list));
                        }
                        _ => return Err(json_syntax_err("expected ',' or ']' in bundleDependencies")),
                    }
                }
            }
            Some(b'{') => {
                self.pos += 1;
                let mut list = Vec::new();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(RawBundleDeps::List(list));
                }
                loop {
                    self.skip_ws();
                    let k = self.parse_str()?.into_string(&self.scratch);
                    self.expect_byte(b':')?;
                    self.skip_value(depth + 1)?;
                    list.push(k);
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(RawBundleDeps::List(list));
                        }
                        _ => return Err(json_syntax_err("expected ',' or '}' in bundleDependencies")),
                    }
                }
            }
            _ => Err(json_syntax_err("invalid bundleDependencies value")),
        }
    }

    fn parse_bin(&mut self, depth: usize) -> Result<Option<PackageBin>, RegistryError> {
        match self.peek() {
            Some(b'"') => {
                let s = self.parse_str()?.into_string(&self.scratch);
                Ok(Some(PackageBin::Single(s)))
            }
            Some(b'{') => {
                self.pos += 1;
                let mut map = BTreeMap::new();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(None);
                }
                loop {
                    self.skip_ws();
                    let k = self.parse_str()?.into_string(&self.scratch);
                    self.expect_byte(b':')?;
                    if let Some(v) = self.parse_opt_string_or_skip(depth + 1)? {
                        map.insert(k, v);
                    }
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(if map.is_empty() {
                                None
                            } else {
                                Some(PackageBin::Map(map))
                            });
                        }
                        _ => return Err(json_syntax_err("expected ',' or '}' in bin map")),
                    }
                }
            }
            Some(b'[') => {
                self.pos += 1;
                let mut map = BTreeMap::new();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(None);
                }
                loop {
                    if let Some(path_str) = self.parse_opt_string_or_skip(depth + 1)? {
                        let name = path_str
                            .rsplit(&['/', '\\'])
                            .next()
                            .unwrap_or(&path_str)
                            .trim();
                        if !name.is_empty() {
                            map.insert(name.to_string(), path_str);
                        }
                    }
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(if map.is_empty() {
                                None
                            } else {
                                Some(PackageBin::Map(map))
                            });
                        }
                        _ => return Err(json_syntax_err("expected ',' or ']' in bin array")),
                    }
                }
            }
            Some(b'n' | b't' | b'f') => {
                self.skip_value(depth)?;
                Ok(None)
            }
            _ => Err(json_syntax_err("invalid bin field")),
        }
    }

    fn parse_license(&mut self, depth: usize) -> Result<Option<String>, RegistryError> {
        match self.peek() {
            Some(b'"') => Ok(Some(self.parse_str()?.into_string(&self.scratch))),
            Some(b'{') => {
                self.pos += 1;
                let mut license = None;
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(None);
                }
                loop {
                    self.skip_ws();
                    let k = self.parse_str()?;
                    let is_type = k.as_str(&self.scratch) == "type";
                    self.expect_byte(b':')?;
                    if is_type {
                        if let Some(s) = self.parse_opt_string_or_skip(depth + 1)? {
                            license = Some(s);
                        }
                    } else {
                        self.skip_value(depth + 1)?;
                    }
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(license);
                        }
                        _ => return Err(json_syntax_err("expected ',' or '}' in license object")),
                    }
                }
            }
            Some(b'[' | b'n' | b't' | b'f') => {
                self.skip_value(depth)?;
                Ok(None)
            }
            _ => Err(json_syntax_err("invalid license field")),
        }
    }

    fn parse_engines(
        &mut self,
        depth: usize,
    ) -> Result<(HashMap<String, String>, Option<serde_json::Value>), RegistryError> {
        match self.peek() {
            Some(b'{') => {
                self.pos += 1;
                let mut map = HashMap::new();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok((map, None));
                }
                loop {
                    self.skip_ws();
                    let k = self.parse_str()?.into_string(&self.scratch);
                    self.expect_byte(b':')?;
                    if let Some(v) = self.parse_opt_str_or_num(depth + 1)? {
                        if map.is_empty() {
                            map.reserve(2);
                        }
                        map.insert(k, v);
                    }
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok((map, None));
                        }
                        _ => return Err(json_syntax_err("expected ',' or '}' in engines map")),
                    }
                }
            }
            Some(b'[' | b'"') => {
                let raw = self.parse_serde_value(depth)?;
                Ok((HashMap::new(), Some(raw)))
            }
            Some(b'n' | b't' | b'f') => {
                self.skip_value(depth)?;
                Ok((HashMap::new(), None))
            }
            _ => Err(json_syntax_err("invalid engines field")),
        }
    }

    fn parse_platform_list(&mut self, depth: usize) -> Result<PlatformList, RegistryError> {
        match self.peek() {
            Some(b'"') => Ok(self.parse_str()?.into_string(&self.scratch).into()),
            Some(b'[') => {
                self.pos += 1;
                let mut list = Vec::new();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(list.into());
                }
                loop {
                    if let Some(s) = self.parse_opt_string_or_skip(depth + 1)? {
                        list.push(s);
                    }
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(list.into());
                        }
                        _ => return Err(json_syntax_err("expected ',' or ']' in platform list")),
                    }
                }
            }
            Some(b'n') => {
                self.consume_literal(b"null")?;
                Ok(PlatformList::default())
            }
            _ => Err(json_syntax_err("expected string, array, or null for platform list")),
        }
    }

    fn parse_deprecated(&mut self) -> Result<Option<String>, RegistryError> {
        match self.peek() {
            Some(b'"') => Ok(Some(self.parse_str()?.into_string(&self.scratch))),
            Some(b't') => {
                self.consume_literal(b"true")?;
                Ok(Some("deprecated".to_string()))
            }
            Some(b'f') => {
                self.consume_literal(b"false")?;
                Ok(None)
            }
            Some(b'n') => {
                self.consume_literal(b"null")?;
                Ok(None)
            }
            _ => Err(json_syntax_err("expected deprecation string, boolean, or null")),
        }
    }

    fn parse_dist_signature(&mut self, depth: usize) -> Result<DistSignature, RegistryError> {
        self.expect_byte(b'{')?;
        let mut keyid: Option<String> = None;
        let mut sig: Option<String> = None;
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Err(json_syntax_err("missing keyid/sig in dist signature"));
        }
        loop {
            self.skip_ws();
            let k = self.parse_str()?;
            match k.as_str(&self.scratch) {
                "keyid" => {
                    self.expect_byte(b':')?;
                    keyid = Some(self.parse_req_string()?);
                }
                "sig" => {
                    self.expect_byte(b':')?;
                    sig = Some(self.parse_req_string()?);
                }
                _ => {
                    self.expect_byte(b':')?;
                    self.skip_value(depth + 1)?;
                }
            }
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    let keyid = keyid.ok_or_else(|| json_syntax_err("missing field 'keyid'"))?;
                    let sig = sig.ok_or_else(|| json_syntax_err("missing field 'sig'"))?;
                    return Ok(DistSignature { keyid, sig });
                }
                _ => return Err(json_syntax_err("expected ',' or '}' in signature")),
            }
        }
    }

    fn parse_dist(&mut self, depth: usize) -> Result<Option<DistInfo>, RegistryError> {
        match self.peek() {
            Some(b'n') => {
                self.consume_literal(b"null")?;
                Ok(None)
            }
            Some(b'{') => {
                self.pos += 1;
                let mut dist = DistInfo::default();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(Some(dist));
                }
                loop {
                    self.skip_ws();
                    let k = self.parse_str()?;
                    match k.as_str(&self.scratch) {
                        "tarball" => {
                            self.expect_byte(b':')?;
                            dist.tarball = self.parse_req_string()?;
                        }
                        "shasum" => {
                            self.expect_byte(b':')?;
                            dist.shasum = self.parse_opt_string()?;
                        }
                        "integrity" => {
                            self.expect_byte(b':')?;
                            dist.integrity = self.parse_opt_string()?;
                        }
                        "signatures" => {
                            self.expect_byte(b':')?;
                            if self.peek() == Some(b'[') {
                                self.pos += 1;
                                if self.peek() != Some(b']') {
                                    loop {
                                        dist.signatures.push(self.parse_dist_signature(depth + 1)?);
                                        match self.peek() {
                                            Some(b',') => self.pos += 1,
                                            Some(b']') => {
                                                self.pos += 1;
                                                break;
                                            }
                                            _ => {
                                                return Err(json_syntax_err(
                                                    "expected ',' or ']' in dist.signatures",
                                                ))
                                            }
                                        }
                                    }
                                } else {
                                    self.pos += 1;
                                }
                            } else {
                                return Err(json_syntax_err("expected array for dist.signatures"));
                            }
                        }
                        "attestations" => {
                            self.expect_byte(b':')?;
                            if self.peek() == Some(b'n') {
                                self.consume_literal(b"null")?;
                                dist.attestations = None;
                            } else {
                                let start = self.pos;
                                self.skip_value(depth + 1)?;
                                dist.attestations = serde_json::from_slice(&self.bytes[start..self.pos])
                                    .map_err(RegistryError::Json)?;
                            }
                        }
                        _ => {
                            self.expect_byte(b':')?;
                            self.skip_value(depth + 1)?;
                        }
                    }
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(Some(dist));
                        }
                        _ => return Err(json_syntax_err("expected ',' or '}' in dist object")),
                    }
                }
            }
            _ => Err(json_syntax_err("expected dist object or null")),
        }
    }

    fn parse_version(
        &mut self,
        mode: PackumentParseMode,
        root_name: Option<&str>,
        version_key: &str,
        depth: usize,
    ) -> Result<AbbreviatedVersion, RegistryError> {
        self.expect_byte(b'{')?;
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

        if self.peek() != Some(b'}') {
            loop {
                self.skip_ws();
                let key = self.parse_str()?;
                let key_bytes_match = match key.as_str(&self.scratch) {
                    "name" => 1,
                    "version" => 2,
                    "dist" => 3,
                    "dependencies" => 4,
                    "devDependencies" => 5,
                    "peerDependencies" => 6,
                    "peerDependenciesMeta" => 7,
                    "optionalDependencies" => 8,
                    "bundleDependencies" => 9,
                    "bundledDependencies" => 10,
                    "bin" => 11,
                    "license" => 12,
                    "engines" => 13,
                    "os" => 14,
                    "cpu" => 15,
                    "libc" => 16,
                    "hasInstallScript" => 17,
                    "deprecated" => 18,
                    other => {
                        let drop = match mode {
                            PackumentParseMode::Install => is_heavy_unused_install_field(other),
                            PackumentParseMode::Full => is_heavy_unused_full_field(other),
                        };
                        if drop {
                            0
                        } else {
                            19
                        }
                    }
                };

                if key_bytes_match == 19 {
                    let extra_key = key.into_string(&self.scratch);
                    self.expect_byte(b':')?;
                    let val = self.parse_serde_value(depth + 1)?;
                    extra.insert(extra_key, val);
                } else {
                    self.expect_byte(b':')?;
                    match key_bytes_match {
                        0 => self.skip_value(depth + 1)?,
                        1 => name = self.parse_opt_string()?,
                        2 => version = self.parse_opt_string()?,
                        3 => dist = self.parse_dist(depth + 1)?,
                        4 => dependencies = self.parse_dep_map(depth + 1)?,
                        5 => dev_dependencies = self.parse_dep_map(depth + 1)?,
                        6 => peer_dependencies = self.parse_dep_map(depth + 1)?,
                        7 => peer_dependencies_meta = self.parse_peer_deps_meta(depth + 1)?,
                        8 => optional_dependencies = self.parse_dep_map(depth + 1)?,
                        9 => bundle_deps_raw = Some(self.parse_bundle_deps(depth + 1)?),
                        10 => bundled_deps_raw = Some(self.parse_bundle_deps(depth + 1)?),
                        11 => bin = self.parse_bin(depth + 1)?,
                        12 => license = self.parse_license(depth + 1)?,
                        13 => {
                            let (eng_map, eng_raw) = self.parse_engines(depth + 1)?;
                            engines = eng_map;
                            if eng_raw.is_some() {
                                engines_raw = eng_raw;
                            }
                        }
                        14 => os = self.parse_platform_list(depth + 1)?,
                        15 => cpu = self.parse_platform_list(depth + 1)?,
                        16 => libc = self.parse_platform_list(depth + 1)?,
                        17 => {
                            has_install_script = match self.peek() {
                                Some(b't') => {
                                    self.consume_literal(b"true")?;
                                    true
                                }
                                Some(b'f') => {
                                    self.consume_literal(b"false")?;
                                    false
                                }
                                Some(b'n') => {
                                    self.consume_literal(b"null")?;
                                    false
                                }
                                _ => {
                                    return Err(json_syntax_err(
                                        "expected boolean or null for hasInstallScript",
                                    ))
                                }
                            };
                        }
                        18 => deprecated = self.parse_deprecated()?,
                        _ => unreachable!(),
                    }
                }

                match self.peek() {
                    Some(b',') => self.pos += 1,
                    Some(b'}') => {
                        self.pos += 1;
                        break;
                    }
                    _ => return Err(json_syntax_err("expected ',' or '}' in version object")),
                }
            }
        } else {
            self.pos += 1;
        }

        let final_bundle_deps = match bundle_deps_raw.or(bundled_deps_raw) {
            Some(RawBundleDeps::All) => dependencies.keys().cloned().collect(),
            Some(RawBundleDeps::List(list)) => list,
            None => Vec::new(),
        };

        Ok(AbbreviatedVersion {
            name: name
                .or_else(|| root_name.map(str::to_string))
                .unwrap_or_default(),
            version: version.unwrap_or_else(|| version_key.to_string()),
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

    fn parse_versions(
        &mut self,
        mode: PackumentParseMode,
        root_name: Option<&str>,
        depth: usize,
    ) -> Result<BTreeMap<String, AbbreviatedVersion>, RegistryError> {
        match self.peek() {
            Some(b'{') => {
                self.pos += 1;
                let mut map = BTreeMap::new();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(map);
                }
                loop {
                    self.skip_ws();
                    let ver_key = self.parse_str()?.into_string(&self.scratch);
                    self.expect_byte(b':')?;
                    let ver_obj = self.parse_version(mode, root_name, &ver_key, depth + 1)?;
                    match map.entry(ver_key) {
                        std::collections::btree_map::Entry::Occupied(occ) => {
                            return Err(json_syntax_err(&format!(
                                "duplicate version key '{}' found in packument metadata",
                                occ.key()
                            )));
                        }
                        std::collections::btree_map::Entry::Vacant(vac) => {
                            vac.insert(ver_obj);
                        }
                    }
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(map);
                        }
                        _ => return Err(json_syntax_err("expected ',' or '}' in versions map")),
                    }
                }
            }
            Some(b'[' | b'n') => {
                self.skip_value(depth)?;
                Ok(BTreeMap::new())
            }
            _ => Err(json_syntax_err("expected versions object, array, or null")),
        }
    }

    fn parse_root(
        mut self,
        mode: PackumentParseMode,
    ) -> Result<AbbreviatedPackageMetadata, RegistryError> {
        self.expect_byte(b'{')?;
        let mut name: Option<String> = None;
        let mut dist_tags: HashMap<String, String> = HashMap::new();
        let mut modified: Option<String> = None;
        let mut versions: BTreeMap<String, AbbreviatedVersion> = BTreeMap::new();
        let mut time: BTreeMap<String, String> = BTreeMap::new();
        let mut root_name_missing_during_versions = false;

        if self.peek() != Some(b'}') {
            loop {
                self.skip_ws();
                let key = self.parse_str()?;
                let field_id = match key.as_str(&self.scratch) {
                    "name" => 1,
                    "dist-tags" => 2,
                    "modified" => 3,
                    "versions" => 4,
                    "time" => 5,
                    _ => 0,
                };
                self.expect_byte(b':')?;
                match field_id {
                    1 => name = self.parse_opt_string()?,
                    2 => dist_tags = self.parse_dist_tags(1)?,
                    3 => modified = self.parse_opt_string()?,
                    4 => {
                        if name.is_none() {
                            root_name_missing_during_versions = true;
                        }
                        versions = self.parse_versions(mode, name.as_deref(), 1)?;
                    }
                    5 => time = self.parse_time(1)?,
                    _ => self.skip_value(1)?,
                }
                match self.peek() {
                    Some(b',') => self.pos += 1,
                    Some(b'}') => {
                        self.pos += 1;
                        break;
                    }
                    _ => return Err(json_syntax_err("expected ',' or '}' in root packument")),
                }
            }
        } else {
            self.pos += 1;
        }

        if self.peek().is_some() {
            return Err(json_syntax_err("trailing characters after JSON packument"));
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
}
