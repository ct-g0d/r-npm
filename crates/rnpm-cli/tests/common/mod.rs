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

        let _ = fs::create_dir_all(&cache_dir);
        let _ = fs::create_dir_all(&prefix_dir);
        let _ = fs::create_dir_all(&appdata);
        let _ = fs::create_dir_all(&localappdata);
        let _ = fs::create_dir_all(&logs_dir);
        if !globalconfig.exists() {
            let _ = fs::write(&globalconfig, "");
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

    pub fn command(&self) -> Command {
        #[cfg(windows)]
        let mut cmd = {
            let mut c = Command::new("cmd.exe");
            c.args(["/d", "/s", "/c", "npm.cmd"]);
            c
        };
        #[cfg(not(windows))]
        let mut cmd = Command::new("npm");

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
