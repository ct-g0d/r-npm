use rnpm_core::spec::PackageTarget;
use crate::error::SolverError;

/// Resolved dependency specification distinguishing install name (folder name / manifest key)
/// from the real package name and target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencySpec {
    /// The name used as directory name in node_modules and key in parent manifest
    pub install_name: String,
    /// The actual package name to query in registry
    pub package_name: String,
    /// The target specification (Range, Version, Tag, File, etc.)
    pub target: PackageTarget,
    /// The raw specifier string
    pub raw_spec: String,
    /// Whether this dependency is an `npm:` alias
    pub is_alias: bool,
}

impl DependencySpec {
    pub fn parse(install_name: &str, raw_spec: &str) -> Result<Self, SolverError> {
        let trimmed_install = install_name.trim();
        let trimmed_spec = raw_spec.trim();

        if let Some(alias_str) = trimmed_spec.strip_prefix("npm:") {
            // Can be "pkg@spec", "@scope/pkg@spec", "pkg", or "@scope/pkg"
            let (real_name, sub_spec) = split_alias_name_and_spec(alias_str)?;
            let inner_target = if let Some(spec) = sub_spec {
                PackageTarget::parse(spec)?
            } else {
                PackageTarget::parse("*")?
            };

            Ok(Self {
                install_name: trimmed_install.to_string(),
                package_name: real_name,
                target: inner_target,
                raw_spec: trimmed_spec.to_string(),
                is_alias: true,
            })
        } else {
            let target = PackageTarget::parse(trimmed_spec)?;
            Ok(Self {
                install_name: trimmed_install.to_string(),
                package_name: trimmed_install.to_string(),
                target,
                raw_spec: trimmed_spec.to_string(),
                is_alias: false,
            })
        }
    }
}

/// Splits alias contents (e.g. `foo@^1.0.0` or `@scope/foo@~2.0.0` or `foo`)
/// into real package name and optional inner spec.
fn split_alias_name_and_spec(input: &str) -> Result<(String, Option<&str>), SolverError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(SolverError::UnresolvedDependency {
            name: String::new(),
            spec: input.to_string(),
            message: "Empty npm alias target".to_string(),
        });
    }

    if s.starts_with('@') {
        let slash = s.find('/').ok_or_else(|| SolverError::UnresolvedDependency {
            name: s.to_string(),
            spec: input.to_string(),
            message: "Invalid scoped alias format".to_string(),
        })?;
        let after_slash = &s[slash + 1..];
        if let Some(at) = after_slash.find('@') {
            let full_at = slash + 1 + at;
            Ok((s[..full_at].to_string(), Some(&s[full_at + 1..])))
        } else {
            Ok((s.to_string(), None))
        }
    } else if let Some(at) = s.find('@') {
        Ok((s[..at].to_string(), Some(&s[at + 1..])))
    } else {
        Ok((s.to_string(), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_regular_dependency() {
        let dep = DependencySpec::parse("express", "^4.18.2").unwrap();
        assert_eq!(dep.install_name, "express");
        assert_eq!(dep.package_name, "express");
        assert!(!dep.is_alias);
    }

    #[test]
    fn test_parse_npm_alias() {
        let dep = DependencySpec::parse("my-chalk", "npm:chalk@^5.3.0").unwrap();
        assert_eq!(dep.install_name, "my-chalk");
        assert_eq!(dep.package_name, "chalk");
        assert!(dep.is_alias);
        assert_eq!(dep.raw_spec, "npm:chalk@^5.3.0");
    }

    #[test]
    fn test_parse_scoped_npm_alias() {
        let dep = DependencySpec::parse("my-types", "npm:@types/node@^18.0.0").unwrap();
        assert_eq!(dep.install_name, "my-types");
        assert_eq!(dep.package_name, "@types/node");
        assert!(dep.is_alias);
    }

    #[test]
    fn test_parse_bare_alias() {
        let dep = DependencySpec::parse("foo-alias", "npm:foo").unwrap();
        assert_eq!(dep.install_name, "foo-alias");
        assert_eq!(dep.package_name, "foo");
        assert!(dep.is_alias);
    }
}
