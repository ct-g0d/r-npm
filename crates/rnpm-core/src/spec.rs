use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use crate::error::SpecError;
use crate::semver::range::Range;
use crate::semver::version::Version;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageTarget {
    Version(Version),
    Range(Range),
    Tag(String),
    Alias {
        name: String,
        target: Box<PackageTarget>,
    },
    File(PathBuf),
    Workspace(String),
}

impl PackageTarget {
    pub fn parse(spec: &str) -> Result<Self, SpecError> {
        let s = spec.trim();
        if s.is_empty() || s == "*" {
            return Ok(PackageTarget::Range(
                Range::parse("*").map_err(|e| SpecError::Semver(e.to_string()))?,
            ));
        }

        // workspace: protocol specifier (e.g. workspace:*, workspace:^, workspace:~, workspace:^1.0.0)
        if let Some(ws_spec) = s.strip_prefix("workspace:") {
            return Ok(PackageTarget::Workspace(ws_spec.trim().to_string()));
        }

        // file: specifier
        if let Some(path_str) = s.strip_prefix("file:") {
            return Ok(PackageTarget::File(PathBuf::from(path_str)));
        }

        // npm: alias specifier (e.g. npm:foo@^1.0.0 or npm:@scope/foo@~2.0.0)
        if let Some(alias_str) = s.strip_prefix("npm:") {
            return Self::parse_alias(alias_str);
        }

        // Try exact version
        if let Ok(ver) = Version::parse(s) {
            return Ok(PackageTarget::Version(ver));
        }

        // If it looks like a range (starts with range chars or contains digits/dots)
        let is_range_syntax = s.starts_with('^')
            || s.starts_with('~')
            || s.starts_with('>')
            || s.starts_with('<')
            || s.starts_with('=')
            || s.contains("||")
            || s.contains(" - ")
            || (s.chars().any(|c| c.is_ascii_digit()) && s.contains('.'));

        if is_range_syntax {
            if let Ok(range) = Range::parse(s) {
                return Ok(PackageTarget::Range(range));
            }
        }

        // Dist-tag like "latest", "next", "beta"
        if is_valid_tag(s) {
            Ok(PackageTarget::Tag(s.to_string()))
        } else if let Ok(range) = Range::parse(s) {
            Ok(PackageTarget::Range(range))
        } else {
            Err(SpecError::InvalidFormat(s.to_string()))
        }
    }

    fn parse_alias(alias_str: &str) -> Result<Self, SpecError> {
        let trimmed = alias_str.trim();
        if trimmed.is_empty() {
            return Err(SpecError::InvalidAlias(alias_str.to_string()));
        }

        // Could be @scope/pkg@spec or pkg@spec or pkg
        let (name, sub_spec) = split_name_and_spec(trimmed)?;
        let inner_target = if let Some(spec) = sub_spec {
            PackageTarget::parse(spec)?
        } else {
            PackageTarget::Tag("latest".to_string())
        };

        Ok(PackageTarget::Alias {
            name,
            target: Box::new(inner_target),
        })
    }
}

impl fmt::Display for PackageTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackageTarget::Version(v) => write!(f, "{v}"),
            PackageTarget::Range(r) => write!(f, "{r}"),
            PackageTarget::Tag(t) => write!(f, "{t}"),
            PackageTarget::Alias { name, target } => write!(f, "npm:{name}@{target}"),
            PackageTarget::File(p) => write!(f, "file:{}", p.display()),
            PackageTarget::Workspace(w) => write!(f, "workspace:{w}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageSpec {
    pub name: String,
    pub target: PackageTarget,
}

impl PackageSpec {
    pub fn new(name: impl Into<String>, target: PackageTarget) -> Self {
        Self {
            name: name.into(),
            target,
        }
    }

    /// Parse a package specifier as provided in CLI arguments or manifests:
    /// e.g. "express", "express@^4.18.0", "@types/node@18.0.0", "foo@npm:bar@^1.0.0", "foo@file:../bar", "foo@workspace:*"
    pub fn parse(input: &str) -> Result<Self, SpecError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(SpecError::Empty);
        }

        // Direct "workspace:" specifier without name (e.g. "workspace:*")
        if let Some(ws_str) = trimmed.strip_prefix("workspace:") {
            return Ok(Self {
                name: "workspace".to_string(),
                target: PackageTarget::Workspace(ws_str.trim().to_string()),
            });
        }

        // Direct "file:" specifier without name (e.g. "file:../foo")
        if let Some(path_str) = trimmed.strip_prefix("file:") {
            let path = PathBuf::from(path_str);
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unnamed")
                .to_string();
            return Ok(Self {
                name,
                target: PackageTarget::File(path),
            });
        }

        // Direct "npm:" alias without alias name (e.g. "npm:bar@^1.0.0")
        if let Some(alias_str) = trimmed.strip_prefix("npm:") {
            let target = PackageTarget::parse_alias(alias_str)?;
            if let PackageTarget::Alias { ref name, .. } = target {
                return Ok(Self {
                    name: name.clone(),
                    target,
                });
            }
        }

        let (name, spec_opt) = split_name_and_spec(trimmed)?;
        let target = if let Some(spec) = spec_opt {
            PackageTarget::parse(spec)?
        } else {
            PackageTarget::Tag("latest".to_string())
        };

        Ok(Self { name, target })
    }

    /// Parse a dependency entry from package.json:
    /// name: "express", spec: "^4.18.2" or "npm:bar@^1.0.0" or "file:../bar"
    pub fn parse_dependency(name: &str, spec: &str) -> Result<Self, SpecError> {
        let trimmed_name = name.trim();
        if trimmed_name.is_empty() {
            return Err(SpecError::InvalidName(name.to_string()));
        }

        let target = PackageTarget::parse(spec)?;
        Ok(Self {
            name: trimmed_name.to_string(),
            target,
        })
    }
}

impl fmt::Display for PackageSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.target)
    }
}

impl FromStr for PackageSpec {
    type Err = SpecError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Splits a package string into (name, Option<spec>)
/// Handles scoped packages like "@scope/pkg@1.0.0"
fn split_name_and_spec(input: &str) -> Result<(String, Option<&str>), SpecError> {
    if input.starts_with('@') {
        // Scoped package
        let slash_idx = input
            .find('/')
            .ok_or_else(|| SpecError::InvalidName(input.to_string()))?;
        let after_slash = &input[slash_idx + 1..];
        if let Some(at_idx) = after_slash.find('@') {
            let full_at_idx = slash_idx + 1 + at_idx;
            let name = &input[..full_at_idx];
            let spec = &input[full_at_idx + 1..];
            if name.is_empty() || spec.is_empty() {
                return Err(SpecError::InvalidFormat(input.to_string()));
            }
            Ok((name.to_string(), Some(spec)))
        } else {
            Ok((input.to_string(), None))
        }
    } else {
        // Unscoped package
        if let Some(at_idx) = input.find('@') {
            let name = &input[..at_idx];
            let spec = &input[at_idx + 1..];
            if name.is_empty() || spec.is_empty() {
                return Err(SpecError::InvalidFormat(input.to_string()));
            }
            Ok((name.to_string(), Some(spec)))
        } else {
            Ok((input.to_string(), None))
        }
    }
}

fn is_valid_tag(s: &str) -> bool {
    // Dist-tags typically start with letters, e.g. "latest", "next", "beta", "canary"
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
        && s.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false)
}
