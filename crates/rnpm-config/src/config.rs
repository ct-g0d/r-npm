use std::env;
use std::path::{Path, PathBuf};
use crate::error::ConfigError;
use crate::npmrc::Npmrc;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub npmrc: Npmrc,
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration by merging user .npmrc and project .npmrc.
    /// Project .npmrc overrides user .npmrc.
    pub fn load(project_dir: Option<&Path>) -> Result<Self, ConfigError> {
        let mut base_npmrc = Npmrc::default();

        // 1. User ~/.npmrc
        if let Some(user_npmrc_path) = find_user_npmrc() {
            if user_npmrc_path.exists() {
                let user_config = Npmrc::from_file(&user_npmrc_path)?;
                base_npmrc.merge(user_config);
            }
        }

        // 2. Project .npmrc
        if let Some(dir) = project_dir {
            let project_npmrc_path = dir.join(".npmrc");
            if project_npmrc_path.exists() {
                let project_config = Npmrc::from_file(&project_npmrc_path)?;
                base_npmrc.merge(project_config);
            }
        }

        Ok(Self { npmrc: base_npmrc })
    }
}

pub fn find_user_npmrc() -> Option<PathBuf> {
    if let Ok(userprofile) = env::var("USERPROFILE") {
        let p = PathBuf::from(userprofile).join(".npmrc");
        return Some(p);
    }
    if let Ok(home) = env::var("HOME") {
        let p = PathBuf::from(home).join(".npmrc");
        return Some(p);
    }
    None
}
