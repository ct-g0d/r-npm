use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct IsolatedNpmEnv {
    pub root: PathBuf,
    pub cache_dir: PathBuf,
    pub prefix_dir: PathBuf,
    pub userconfig: PathBuf,
    pub globalconfig: PathBuf,
    pub appdata: PathBuf,
    pub localappdata: PathBuf,
    pub logs_dir: PathBuf,
}

impl IsolatedNpmEnv {
    pub fn new(root: &Path) -> Self {
        let cache_dir = root.join("cache");
        let prefix_dir = root.join("prefix");
        let appdata = root.join("appdata");
        let localappdata = root.join("localappdata");
        let logs_dir = root.join("logs");
        let userconfig = root.join(".npmrc");
        let globalconfig = root.join("global.npmrc");

        fs::create_dir_all(&cache_dir)
            .unwrap_or_else(|e| panic!("Failed to create isolated cache_dir at {:?}: {}", cache_dir, e));
        fs::create_dir_all(&prefix_dir)
            .unwrap_or_else(|e| panic!("Failed to create isolated prefix_dir at {:?}: {}", prefix_dir, e));
        fs::create_dir_all(&appdata)
            .unwrap_or_else(|e| panic!("Failed to create isolated appdata at {:?}: {}", appdata, e));
        fs::create_dir_all(&localappdata)
            .unwrap_or_else(|e| panic!("Failed to create isolated localappdata at {:?}: {}", localappdata, e));
        fs::create_dir_all(&logs_dir)
            .unwrap_or_else(|e| panic!("Failed to create isolated logs_dir at {:?}: {}", logs_dir, e));

        if !userconfig.exists() {
            fs::write(&userconfig, "")
                .unwrap_or_else(|e| panic!("Failed to initialize isolated userconfig at {:?}: {}", userconfig, e));
        }
        if !globalconfig.exists() {
            fs::write(&globalconfig, "")
                .unwrap_or_else(|e| panic!("Failed to initialize isolated globalconfig at {:?}: {}", globalconfig, e));
        }

        Self {
            root: root.to_path_buf(),
            cache_dir,
            prefix_dir,
            userconfig,
            globalconfig,
            appdata,
            localappdata,
            logs_dir,
        }
    }

    #[allow(dead_code)]
    pub fn with_userconfig(mut self, path: PathBuf) -> Self {
        self.userconfig = path;
        self
    }

    #[allow(dead_code)]
    pub fn with_prefix(mut self, path: PathBuf) -> Self {
        self.prefix_dir = path;
        self
    }

    /// Case-insensitively removes any inherited `npm_config_*` or shorthand config variables from `cmd`.
    #[allow(dead_code)]
    pub fn scrub_env_keys<I, S>(cmd: &mut Command, keys: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for key in keys {
            let s = key.as_ref();
            let lower = s.to_ascii_lowercase();
            if lower.starts_with("npm_config_")
                || lower == "cache"
                || lower == "prefix"
                || lower == "userconfig"
                || lower == "globalconfig"
            {
                cmd.env_remove(s);
            }
        }
    }

    pub fn command(&self) -> Command {
        #[cfg(windows)]
        let mut cmd = {
            let mut c = Command::new("cmd.exe");
            c.args(["/d", "/s", "/c", "npm.cmd"]);
            c
        };
        #[cfg(not(windows))]
        let mut cmd = Command::new("npm");

        // Scrub all inherited NPM_CONFIG_* / npm_config_* environment variables case-insensitively
        Self::scrub_env_keys(&mut cmd, std::env::vars().map(|(k, _)| k));

        cmd.env("HOME", &self.root)
            .env("USERPROFILE", &self.root)
            .env("NPM_CONFIG_CACHE", &self.cache_dir)
            .env("npm_config_cache", &self.cache_dir)
            .env("CACHE", &self.cache_dir)
            .env("NPM_CONFIG_PREFIX", &self.prefix_dir)
            .env("PREFIX", &self.prefix_dir)
            .env("NPM_CONFIG_USERCONFIG", &self.userconfig)
            .env("USERCONFIG", &self.userconfig)
            .env("npm_config_userconfig", &self.userconfig)
            .env("NPM_CONFIG_GLOBALCONFIG", &self.globalconfig)
            .env("GLOBALCONFIG", &self.globalconfig)
            .env("npm_config_globalconfig", &self.globalconfig)
            .env("APPDATA", &self.appdata)
            .env("LOCALAPPDATA", &self.localappdata)
            .env("NPM_CONFIG_LOGS_DIR", &self.logs_dir)
            .env("npm_config_logs_dir", &self.logs_dir);

        cmd
    }
}

/// Convenience factory that takes an explicit isolation root path,
/// provisions the isolated directory tree, and returns a `Command` with
/// all required isolation environment variables configured.
#[allow(dead_code)]
pub fn isolated_npm(root: &Path) -> Command {
    IsolatedNpmEnv::new(root).command()
}
