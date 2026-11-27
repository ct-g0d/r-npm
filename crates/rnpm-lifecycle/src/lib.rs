#![allow(clippy::upper_case_acronyms, clippy::field_reassign_with_default)]

use anyhow::{Context, Result};
use rnpm_core::manifest::Manifest;
use std::collections::BinaryHeap;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use tracing::{debug, info, warn};

pub mod error;
pub mod node_gyp;
pub mod policy;
pub mod sandbox;

pub use error::LifecycleError;
pub use node_gyp::{
    bootstrap_node_gyp, count_node_modules_depth, create_private_node_gyp_shim, ensure_node_gyp,
    find_cache_dir, find_node_gyp, find_registry, install_production_dependencies,
    is_ancestor_satisfied, is_offline_mode, node_gyp_bin_dir, package_dir_in_node_modules,
    pick_matching_version, unpack_tarball, validate_package_name, verify_tarball_integrity,
    MAX_NESTING_DEPTH, StagingGuard,
};
pub use policy::{SandboxLevel, ScriptSandboxPolicy};
pub use sandbox::{check_dangerous_command_patterns, CommandPatternAnalyzer};

#[cfg(test)]
mod tests;

#[cfg(windows)]
pub mod process_guard {
    use std::os::windows::io::RawHandle;

    type HANDLE = *mut std::ffi::c_void;
    type BOOL = i32;
    type DWORD = u32;

    #[repr(C)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: DWORD,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: DWORD,
        affinity: usize,
        priority_class: DWORD,
        scheduling_class: DWORD,
    }

    #[repr(C)]
    struct IO_COUNTERS {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        io_info: IO_COUNTERS,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_limit: usize,
        peak_job_memory_limit: usize,
    }

    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x00002000;
    const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: DWORD = 0x00000008;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;

    extern "system" {
        fn CreateJobObjectW(lpJobAttributes: *const std::ffi::c_void, lpName: *const u16)
            -> HANDLE;
        fn SetInformationJobObject(
            hJob: HANDLE,
            JobObjectInformationClass: i32,
            lpJobObjectInformation: *const std::ffi::c_void,
            cbJobObjectInformationLength: DWORD,
        ) -> BOOL;
        fn AssignProcessToJobObject(hJob: HANDLE, hProcess: HANDLE) -> BOOL;
        fn TerminateJobObject(hJob: HANDLE, uExitCode: u32) -> BOOL;
        fn CloseHandle(hObject: HANDLE) -> BOOL;
    }

    pub struct ProcessTreeGuard {
        job_handle: HANDLE,
        terminated: std::sync::atomic::AtomicBool,
    }

    unsafe impl Send for ProcessTreeGuard {}
    unsafe impl Sync for ProcessTreeGuard {}

    impl ProcessTreeGuard {
        pub fn new() -> Option<Self> {
            Self::new_with_limits(None)
        }

        pub fn new_with_limits(active_process_limit: Option<u32>) -> Option<Self> {
            unsafe {
                let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if job.is_null() {
                    return None;
                }
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if let Some(limit) = active_process_limit {
                    info.basic_limit_information.limit_flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                    info.basic_limit_information.active_process_limit = limit;
                }
                let res = SetInformationJobObject(
                    job,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    &info as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
                );
                if res == 0 {
                    CloseHandle(job);
                    return None;
                }
                Some(Self {
                    job_handle: job,
                    terminated: std::sync::atomic::AtomicBool::new(false),
                })
            }
        }

        pub fn assign_process(&self, process_handle: RawHandle) -> bool {
            unsafe {
                if self.job_handle.is_null() {
                    return false;
                }
                AssignProcessToJobObject(self.job_handle, process_handle as HANDLE) != 0
            }
        }

        pub fn terminate(&self, exit_code: u32) -> bool {
            self.terminated
                .store(true, std::sync::atomic::Ordering::SeqCst);
            unsafe {
                if self.job_handle.is_null() {
                    return false;
                }
                TerminateJobObject(self.job_handle, exit_code) != 0
            }
        }
    }

    impl Drop for ProcessTreeGuard {
        fn drop(&mut self) {
            unsafe {
                if !self.job_handle.is_null() {
                    // Forcefully terminate any lingering child or grandchild processes
                    // running inside the job object before closing handle if not already terminated.
                    if !self.terminated.load(std::sync::atomic::Ordering::SeqCst) {
                        let _ = TerminateJobObject(self.job_handle, 1);
                    }
                    CloseHandle(self.job_handle);
                    self.job_handle = std::ptr::null_mut();
                }
            }
        }
    }

    pub fn is_process_running(pid: u32) -> bool {
        unsafe {
            extern "system" {
                fn OpenProcess(
                    dwDesiredAccess: u32,
                    bInheritHandle: i32,
                    dwProcessId: u32,
                ) -> *mut std::ffi::c_void;
                fn GetExitCodeProcess(hProcess: *mut std::ffi::c_void, lpExitCode: *mut u32)
                    -> i32;
                fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
            }
            const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
            const STILL_ACTIVE: u32 = 259;
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return false;
            }
            let mut exit_code = 0;
            let res = GetExitCodeProcess(handle, &mut exit_code);
            CloseHandle(handle);
            res != 0 && exit_code == STILL_ACTIVE
        }
    }
}

#[cfg(not(windows))]
pub mod process_guard {
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

    pub struct ProcessTreeGuard {
        pgid: AtomicI32,
        terminated: AtomicBool,
    }

    impl ProcessTreeGuard {
        pub fn new() -> Option<Self> {
            Self::new_with_limits(None)
        }

        pub fn new_with_limits(_active_process_limit: Option<u32>) -> Option<Self> {
            Some(Self {
                pgid: AtomicI32::new(0),
                terminated: AtomicBool::new(false),
            })
        }

        pub fn assign_process(&self, pid: u32) -> bool {
            self.pgid.store(pid as i32, Ordering::SeqCst);
            true
        }

        pub fn terminate(&self, exit_code: u32) -> bool {
            self.terminated.store(true, Ordering::SeqCst);
            let pid = self.pgid.load(Ordering::SeqCst);
            if pid > 0 {
                // Send signal according to exit_code then SIGKILL to entire process group
                unsafe {
                    #[cfg(unix)]
                    {
                        let sig = match exit_code {
                            130 => libc::SIGINT,
                            143 => libc::SIGTERM,
                            _ => libc::SIGTERM,
                        };
                        libc::kill(-pid, sig);
                        libc::kill(-pid, libc::SIGKILL) == 0
                    }
                    #[cfg(not(unix))]
                    {
                        false
                    }
                }
            } else {
                true
            }
        }
    }

    impl Drop for ProcessTreeGuard {
        fn drop(&mut self) {
            if !self.terminated.load(Ordering::SeqCst) {
                let _ = self.terminate(1);
            }
        }
    }

    pub fn is_process_running(pid: u32) -> bool {
        #[cfg(unix)]
        unsafe {
            libc::kill(pid as i32, 0) == 0
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            false
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageSource {
    Registry,
    Local,
    Git,
    LocalTarball,
}

impl PackageSource {
    pub fn is_registry(&self) -> bool {
        matches!(self, PackageSource::Registry)
    }

    pub fn runs_prepare(&self) -> bool {
        matches!(
            self,
            PackageSource::Local | PackageSource::Git | PackageSource::LocalTarball
        )
    }

    pub fn lifecycle_hooks(&self) -> &'static [&'static str] {
        match self {
            PackageSource::Registry => &["preinstall", "install", "postinstall"],
            PackageSource::Local | PackageSource::Git | PackageSource::LocalTarball => {
                &["preinstall", "install", "postinstall", "prepare"]
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct LifecyclePackageNode {
    pub package_path: String,
    pub disk_path: PathBuf,
    pub manifest: Manifest,
    pub source: PackageSource,
    pub dependencies: Vec<String>,
    pub optional: bool,
}

#[derive(Debug, Clone)]
pub struct LifecycleOptions {
    pub root_dir: PathBuf,
    pub init_cwd: PathBuf,
    pub ignore_scripts: bool,
    pub capture_output: bool,
    pub foreground_scripts: bool,
    pub timeout: Option<std::time::Duration>,
    pub sandbox_policy: ScriptSandboxPolicy,
    pub node_gyp: Option<PathBuf>,
    pub offline: bool,
}

impl Default for LifecycleOptions {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::new(),
            init_cwd: PathBuf::new(),
            ignore_scripts: false,
            capture_output: true,
            foreground_scripts: false,
            timeout: None,
            sandbox_policy: ScriptSandboxPolicy::default(),
            node_gyp: None,
            offline: false,
        }
    }
}

tokio::task_local! {
    static SCOPED_TRUSTED_CONFIG: Option<rnpm_config::Config>;
}

static GLOBAL_TRUSTED_CONFIG: std::sync::RwLock<Option<rnpm_config::Config>> = std::sync::RwLock::new(None);

pub fn set_trusted_config(config: Option<rnpm_config::Config>) {
    if let Ok(mut lock) = GLOBAL_TRUSTED_CONFIG.write() {
        *lock = config;
    }
}

pub fn get_trusted_config() -> Option<rnpm_config::Config> {
    SCOPED_TRUSTED_CONFIG
        .try_with(|c| c.clone())
        .ok()
        .flatten()
        .or_else(|| GLOBAL_TRUSTED_CONFIG.read().ok().and_then(|lock| lock.clone()))
}

pub async fn with_trusted_config<F, R>(config: Option<rnpm_config::Config>, f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    SCOPED_TRUSTED_CONFIG.scope(config, f).await
}

impl LifecycleOptions {
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        let root = root_dir.into();
        let node_gyp = std::env::var("npm_config_node_gyp")
            .or_else(|_| std::env::var("NPM_CONFIG_NODE_GYP"))
            .ok()
            .map(PathBuf::from)
            .or_else(|| {
                if let Some(cfg) = get_trusted_config() {
                    cfg.get("node-gyp").map(PathBuf::from)
                } else {
                    rnpm_config::Config::load(Some(&root))
                        .ok()
                        .and_then(|c| c.get("node-gyp").map(PathBuf::from))
                }
            });
        Self {
            init_cwd: root.clone(),
            root_dir: root,
            ignore_scripts: false,
            capture_output: true,
            foreground_scripts: false,
            timeout: None,
            sandbox_policy: ScriptSandboxPolicy::default(),
            node_gyp,
            offline: false,
        }
    }

    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_sandbox_policy(mut self, policy: ScriptSandboxPolicy) -> Self {
        self.sandbox_policy = policy;
        self
    }

    pub fn with_foreground_scripts(mut self, foreground: bool) -> Self {
        self.foreground_scripts = foreground;
        if foreground {
            self.capture_output = false;
        }
        self
    }

    pub fn with_ignore_scripts(mut self, ignore: bool) -> Self {
        self.ignore_scripts = ignore;
        self
    }

    pub fn with_node_gyp(mut self, node_gyp: impl Into<PathBuf>) -> Self {
        self.node_gyp = Some(node_gyp.into());
        self
    }

    pub fn with_offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }
}

/// Captured output of a script execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl ScriptOutput {
    pub fn success() -> Self {
        Self {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }
}

/// Context for running a lifecycle script per docs/lifecycle-contract.md.
#[derive(Debug, Clone)]
pub struct LifecycleContext {
    pub project_root: PathBuf,
    pub package_dir: PathBuf,
    pub package_name: String,
    pub package_version: Option<String>,
    pub event: String,
    pub script_cmd: String,
    pub node_execpath: Option<PathBuf>,
    pub npm_execpath: Option<PathBuf>,
    pub extra_env: HashMap<String, String>,
    pub timeout: Option<std::time::Duration>,
    pub capture_output: bool,
    pub foreground_scripts: bool,
    pub captured_output: std::sync::Arc<std::sync::Mutex<Option<ScriptOutput>>>,
    pub sandbox_policy: ScriptSandboxPolicy,
    pub script_shell: Option<String>,
    pub node_gyp: Option<PathBuf>,
    pub offline: bool,
    pub config: Option<rnpm_config::Config>,
    pub precomputed_env: Option<HashMap<String, String>>,
}

impl LifecycleContext {
    pub fn new(
        project_root: impl Into<PathBuf>,
        package_dir: impl Into<PathBuf>,
        package_name: impl Into<String>,
        event: impl Into<String>,
        script_cmd: impl Into<String>,
    ) -> Self {
        let project_root = project_root.into();
        let package_dir = package_dir.into();
        let package_name = package_name.into();
        let event = event.into();
        let script_cmd = script_cmd.into();

        if let Some(trusted) = get_trusted_config() {
            return Self::new_with_config(
                project_root,
                package_dir,
                package_name,
                event,
                script_cmd,
                trusted,
            );
        }

        let pkg_cfg = if package_dir != project_root && package_dir.join(".npmrc").exists() {
            rnpm_config::Config::load(Some(&package_dir)).ok()
        } else {
            None
        };
        let root_cfg = if pkg_cfg.is_none()
            || pkg_cfg
                .as_ref()
                .is_some_and(|c| c.get("script-shell").is_none() || c.get("node-gyp").is_none())
        {
            rnpm_config::Config::load(Some(&project_root)).ok()
        } else {
            None
        };
        let effective_cfg = pkg_cfg.as_ref().or(root_cfg.as_ref());

        let script_shell = pkg_cfg
            .as_ref()
            .and_then(|c| c.get("script-shell").map(str::to_string))
            .or_else(|| {
                root_cfg
                    .as_ref()
                    .and_then(|c| c.get("script-shell").map(str::to_string))
            })
            .filter(|s| {
                let trimmed = s.trim().trim_matches('"');
                !trimmed.is_empty() && trimmed != "null" && s != "null"
            });

        let node_gyp = std::env::var("npm_config_node_gyp")
            .or_else(|_| std::env::var("NPM_CONFIG_NODE_GYP"))
            .ok()
            .map(PathBuf::from)
            .or_else(|| {
                pkg_cfg
                    .as_ref()
                    .and_then(|c| c.get("node-gyp").map(PathBuf::from))
                    .or_else(|| {
                        root_cfg
                            .as_ref()
                            .and_then(|c| c.get("node-gyp").map(PathBuf::from))
                    })
            });

        Self {
            project_root,
            package_dir,
            package_name,
            package_version: None,
            event,
            script_cmd,
            node_execpath: None,
            npm_execpath: None,
            extra_env: HashMap::new(),
            timeout: None,
            capture_output: false,
            foreground_scripts: false,
            captured_output: std::sync::Arc::new(std::sync::Mutex::new(None)),
            sandbox_policy: ScriptSandboxPolicy::default(),
            script_shell,
            node_gyp,
            offline: false,
            config: effective_cfg.cloned(),
            precomputed_env: None,
        }
    }

    pub fn new_with_config(
        project_root: impl Into<PathBuf>,
        package_dir: impl Into<PathBuf>,
        package_name: impl Into<String>,
        event: impl Into<String>,
        script_cmd: impl Into<String>,
        config: rnpm_config::Config,
    ) -> Self {
        let project_root = project_root.into();
        let package_dir = package_dir.into();
        let package_name = package_name.into();
        let event = event.into();
        let script_cmd = script_cmd.into();

        let script_shell = config
            .get("script-shell")
            .map(str::to_string)
            .filter(|s| {
                let trimmed = s.trim().trim_matches('"');
                !trimmed.is_empty() && trimmed != "null" && s != "null"
            });

        let node_gyp = std::env::var("npm_config_node_gyp")
            .or_else(|_| std::env::var("NPM_CONFIG_NODE_GYP"))
            .ok()
            .map(PathBuf::from)
            .or_else(|| config.get("node-gyp").map(PathBuf::from));

        Self {
            project_root,
            package_dir,
            package_name,
            package_version: None,
            event,
            script_cmd,
            node_execpath: None,
            npm_execpath: None,
            extra_env: HashMap::new(),
            timeout: None,
            capture_output: false,
            foreground_scripts: false,
            captured_output: std::sync::Arc::new(std::sync::Mutex::new(None)),
            sandbox_policy: ScriptSandboxPolicy::default(),
            script_shell,
            node_gyp,
            offline: false,
            config: Some(config),
            precomputed_env: None,
        }
    }

    pub fn with_precomputed_env(mut self, env: HashMap<String, String>) -> Self {
        self.precomputed_env = Some(env);
        self
    }

    pub fn from_config(
        project_root: impl Into<PathBuf>,
        package_dir: impl Into<PathBuf>,
        package_name: impl Into<String>,
        event: impl Into<String>,
        script_cmd: impl Into<String>,
        config: rnpm_config::Config,
    ) -> Self {
        Self::new_with_config(project_root, package_dir, package_name, event, script_cmd, config)
    }

    pub fn with_config(mut self, config: rnpm_config::Config) -> Self {
        if self.script_shell.is_none() {
            self.script_shell = config
                .get("script-shell")
                .map(str::to_string)
                .filter(|s| {
                    let trimmed = s.trim().trim_matches('"');
                    !trimmed.is_empty() && trimmed != "null" && s != "null"
                });
        }
        if self.node_gyp.is_none() {
            self.node_gyp = config.get("node-gyp").map(PathBuf::from);
        }
        self.config = Some(config);
        self
    }

    pub fn with_script_shell(mut self, script_shell: impl Into<String>) -> Self {
        self.script_shell = Some(script_shell.into());
        self
    }

    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_capture_output(mut self, capture: bool) -> Self {
        self.capture_output = capture;
        self
    }

    pub fn with_foreground_scripts(mut self, foreground: bool) -> Self {
        self.foreground_scripts = foreground;
        if foreground {
            self.capture_output = false;
        }
        self
    }

    pub fn with_sandbox_policy(mut self, policy: ScriptSandboxPolicy) -> Self {
        self.sandbox_policy = policy;
        self
    }

    pub fn with_node_gyp(mut self, node_gyp: impl Into<PathBuf>) -> Self {
        self.node_gyp = Some(node_gyp.into());
        self
    }

    pub fn with_offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    pub fn get_captured_output(&self) -> Option<ScriptOutput> {
        self.captured_output.lock().unwrap().clone()
    }
}

#[inline]
fn bytes_contain_lc(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Scrub sensitive authentication tokens and credentials from environment map.
pub fn is_sensitive_credential_key(key: &str) -> bool {
    let b = key.as_bytes();
    if b.len() < 3 {
        return b == b"//";
    }
    if b.starts_with(b"//") {
        return true;
    }

    let mut stack = [0u8; 128];
    let mut heap = Vec::new();
    let lower: &mut [u8] = if b.len() <= stack.len() {
        &mut stack[..b.len()]
    } else {
        heap.resize(b.len(), 0);
        &mut heap
    };
    let mut mask = 0u32;
    let mut has_colon = false;
    let mut has_underscore = false;
    for (dst, &ch) in lower.iter_mut().zip(b.iter()) {
        let lb = ch.to_ascii_lowercase();
        *dst = lb;
        if lb.is_ascii_lowercase() {
            mask |= 1u32 << (lb - b'a');
        } else if lb == b':' {
            has_colon = true;
        } else if lb == b'_' {
            has_underscore = true;
        }
    }

    const fn lmask(s: &[u8]) -> u32 {
        let mut m = 0u32;
        let mut i = 0;
        while i < s.len() {
            let c = s[i];
            if c >= b'a' && c <= b'z' {
                m |= 1u32 << (c - b'a');
            }
            i += 1;
        }
        m
    }

    const M_TOKEN: u32 = lmask(b"token");
    const M_SECRET: u32 = lmask(b"secret");
    const M_PASSWORD: u32 = lmask(b"password");
    const M_PASSWD: u32 = lmask(b"passwd");
    const M_JWT: u32 = lmask(b"jwt");
    const M_KEY: u32 = lmask(b"key");
    const M_AUTH: u32 = lmask(b"auth");
    const M_GHP: u32 = lmask(b"ghp_");
    const M_GITHUB_PAT: u32 = lmask(b"github_pat_");
    const M_CREDENTIAL: u32 = lmask(b"credential");
    const M_BEARER: u32 = lmask(b"bearer");

    if (mask & M_TOKEN) == M_TOKEN && bytes_contain_lc(lower, b"token") {
        return true;
    }
    if (mask & M_SECRET) == M_SECRET && bytes_contain_lc(lower, b"secret") {
        return true;
    }
    if ((mask & M_PASSWORD) == M_PASSWORD && bytes_contain_lc(lower, b"password"))
        || ((mask & M_PASSWD) == M_PASSWD && bytes_contain_lc(lower, b"passwd"))
    {
        return true;
    }
    if (mask & M_JWT) == M_JWT && bytes_contain_lc(lower, b"jwt") {
        return true;
    }
    if (mask & M_CREDENTIAL) == M_CREDENTIAL && bytes_contain_lc(lower, b"credential") {
        return true;
    }
    if (mask & M_BEARER) == M_BEARER && bytes_contain_lc(lower, b"bearer") {
        return true;
    }
    if has_underscore
        && (((mask & M_GHP) == M_GHP && bytes_contain_lc(lower, b"ghp_"))
            || ((mask & M_GITHUB_PAT) == M_GITHUB_PAT && bytes_contain_lc(lower, b"github_pat_")))
    {
        return true;
    }
    if (mask & M_KEY) == M_KEY
        && (bytes_contain_lc(lower, b"apikey")
            || bytes_contain_lc(lower, b"api_key")
            || bytes_contain_lc(lower, b"deploy_key")
            || bytes_contain_lc(lower, b"deploykey")
            || bytes_contain_lc(lower, b"signing_key")
            || bytes_contain_lc(lower, b"signingkey")
            || bytes_contain_lc(lower, b"encryption_key")
            || bytes_contain_lc(lower, b"encryptionkey")
            || bytes_contain_lc(lower, b"secret_key")
            || bytes_contain_lc(lower, b"secretkey")
            || bytes_contain_lc(lower, b"private_key")
            || bytes_contain_lc(lower, b"privatekey")
            || (has_underscore && bytes_contain_lc(lower, b"aws_access_key_id")))
    {
        return true;
    }
    if has_underscore && (mask & M_AUTH) == M_AUTH && bytes_contain_lc(lower, b"ssh_auth_sock") {
        return true;
    }
    if has_colon
        && (bytes_contain_lc(lower, b"/:_") || bytes_contain_lc(lower, b":_auth"))
    {
        return true;
    }
    if lower.len() >= 13 && &lower[..13] == b"npm_config_//" {
        return true;
    }
    if (mask & M_AUTH) == M_AUTH
        && (((has_underscore
            && (bytes_contain_lc(lower, b"_auth") || bytes_contain_lc(lower, b"auth_")))
            || (lower.len() >= 4
                && (&lower[..4] == b"auth" || &lower[lower.len() - 4..] == b"auth")))
            && !bytes_contain_lc(lower, b"author"))
    {
        return true;
    }
    false
}

/// Redact sensitive tokens and passwords from stdout, stderr, or error traces.
/// Section 4.2: Logging & Error Scrubbing.
pub fn scrub_text(text: &str) -> String {
    let mut result = text.to_string();

    // 1. Redact Bearer tokens
    result = replace_bearer(&result);

    // 2. Redact npm tokens: npm_[A-Za-z0-9_-]{32,}
    result = replace_npm_tokens(&result);

    // 3. Redact GitHub personal access tokens: ghp_ and github_pat_
    result = replace_token_prefix(&result, "ghp_", 10);
    result = replace_token_prefix(&result, "github_pat_", 10);

    // 4. Redact :_authToken=<val> and other key-value credentials
    for key in &[
        "aws_secret_access_key",
        "aws_access_key_id",
        "ssh_auth_sock",
        "encryption_key",
        "signing_key",
        "deploy_key",
        "secret_key",
        "_authtoken",
        "_authToken",
        "authtoken",
        "password",
        "passwd",
        "secret",
        "token",
        "_auth",
        "jwt",
    ] {
        result = replace_kv_pairs(&result, key);
    }

    result
}

fn replace_bearer(text: &str) -> String {
    let mut out = String::new();
    let lower = text.to_ascii_lowercase();
    let mut last_idx = 0;

    for (idx, _) in lower.match_indices("bearer ") {
        if idx < last_idx {
            continue;
        }
        out.push_str(&text[last_idx..idx + 7]);
        let remainder = &text[idx + 7..];
        let end_token = remainder
            .find(|c: char| {
                c.is_whitespace() || c == '"' || c == '\'' || c == '\n' || c == '\r' || c == ';'
            })
            .unwrap_or(remainder.len());
        out.push_str("[REDACTED]");
        last_idx = idx + 7 + end_token;
    }
    out.push_str(&text[last_idx..]);
    out
}

fn replace_npm_tokens(text: &str) -> String {
    let mut out = String::new();
    let mut last_idx = 0;

    for (idx, _) in text.match_indices("npm_") {
        if idx < last_idx {
            continue;
        }
        let remainder = &text[idx + 4..];
        let end_token = remainder
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .unwrap_or(remainder.len());
        if end_token >= 32 {
            out.push_str(&text[last_idx..idx]);
            out.push_str("npm_[REDACTED]");
            last_idx = idx + 4 + end_token;
        }
    }
    out.push_str(&text[last_idx..]);
    out
}

fn replace_token_prefix(text: &str, prefix: &str, min_len: usize) -> String {
    let mut out = String::new();
    let lower = text.to_ascii_lowercase();
    let prefix_lower = prefix.to_ascii_lowercase();
    let mut last_idx = 0;

    for (idx, _) in lower.match_indices(&prefix_lower) {
        if idx < last_idx {
            continue;
        }
        let remainder = &text[idx + prefix.len()..];
        let end_token = remainder
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .unwrap_or(remainder.len());
        if end_token >= min_len {
            out.push_str(&text[last_idx..idx]);
            out.push_str(&format!("{prefix}[REDACTED]"));
            last_idx = idx + prefix.len() + end_token;
        }
    }
    out.push_str(&text[last_idx..]);
    out
}

fn replace_kv_pairs(text: &str, key_name: &str) -> String {
    let mut out = String::new();
    let lower = text.to_ascii_lowercase();
    let pattern = format!("{key_name}=");
    let mut last_idx = 0;

    for (idx, _) in lower.match_indices(&pattern) {
        if idx < last_idx {
            continue;
        }
        if idx > 0 && !key_name.starts_with('_') && !key_name.starts_with(':') {
            let prev = text[..idx].chars().next_back().unwrap();
            if prev.is_ascii_alphanumeric() || prev == '_' {
                continue;
            }
        }
        let key_len = pattern.len();
        out.push_str(&text[last_idx..idx + key_len]);
        let remainder = &text[idx + key_len..];
        let end_token = remainder
            .find(|c: char| {
                c.is_whitespace()
                    || c == ';'
                    || c == '&'
                    || c == '"'
                    || c == '\''
                    || c == '\n'
                    || c == '\r'
                    || c == ','
            })
            .unwrap_or(remainder.len());
        out.push_str("[REDACTED]");
        last_idx = idx + key_len + end_token;
    }
    out.push_str(&text[last_idx..]);
    out
}

/// Concurrently drains a readable stream in chunks, applying credential scrubbing
/// on streaming chunks to ensure child processes cannot stall from filled pipe buffers.
pub fn drain_and_scrub_reader<R: std::io::Read>(reader: &mut R) -> String {
    let mut out = String::new();
    let mut buf = [0u8; 8192];
    let mut carry = String::new();

    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                if !carry.is_empty() {
                    let scrubbed = scrub_text(&carry);
                    out.push_str(&scrubbed);
                }
                break;
            }
            Ok(n) => {
                let chunk_str = String::from_utf8_lossy(&buf[..n]);
                let combined = format!("{carry}{chunk_str}");

                if combined.len() > 512 {
                    let split_candidate = combined.len() - 256;
                    let split_pos = match combined[..split_candidate].rfind(['\n', '\r', ' ', ';'])
                    {
                        Some(pos) => pos + 1,
                        None => split_candidate,
                    };

                    let to_process = &combined[..split_pos];
                    let scrubbed = scrub_text(to_process);
                    out.push_str(&scrubbed);
                    carry = combined[split_pos..].to_string();
                } else {
                    carry = combined;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                if !carry.is_empty() {
                    let scrubbed = scrub_text(&carry);
                    out.push_str(&scrubbed);
                }
                break;
            }
        }
    }

    out
}

fn flatten_package_json_to_env(
    prefix: &str,
    key: &str,
    val: &serde_json::Value,
    env: &mut HashMap<String, String>,
) {
    let sanitized_key = key.replace('-', "_");
    let full_key = format!("{prefix}_{sanitized_key}");

    match val {
        serde_json::Value::Null => {}
        serde_json::Value::Bool(b) => {
            env.insert(full_key, b.to_string());
        }
        serde_json::Value::Number(n) => {
            env.insert(full_key, n.to_string());
        }
        serde_json::Value::String(s) => {
            env.insert(full_key, s.clone());
        }
        serde_json::Value::Array(arr) => {
            for (idx, item) in arr.iter().enumerate() {
                flatten_package_json_to_env(&full_key, &idx.to_string(), item, env);
            }
        }
        serde_json::Value::Object(obj) => {
            for (child_k, child_v) in obj {
                flatten_package_json_to_env(&full_key, child_k, child_v, env);
            }
        }
    }
}

/// npm release whose CLI contract rnpm follows.
pub const NPM_VERSION: &str = "11.20.0";

/// Absolute path of the `node` executable on PATH.
pub fn node_executable() -> Option<PathBuf> {
    static NODE: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    NODE.get_or_init(|| {
        let exts: Vec<String> = if cfg!(windows) {
            std::env::var("PATHEXT")
                .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".into())
                .split(';')
                .filter(|e| !e.is_empty())
                .map(str::to_string)
                .collect()
        } else {
            vec![String::new()]
        };
        std::env::split_paths(&std::env::var_os("PATH")?)
            .flat_map(|dir| exts.iter().map(move |e| dir.join(format!("node{e}"))))
            .find(|p| p.is_file())
            .map(|p| {
                // Report the on-disk spelling (node.exe, not node.EXE).
                std::fs::canonicalize(&p)
                    .ok()
                    .map(|c| {
                        let s = c.to_string_lossy().to_string();
                        PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s).to_string())
                    })
                    .unwrap_or(p)
            })
    })
    .clone()
}

/// Reads `RT_VERSION` (`VS_VERSION_INFO`) directly from an official Windows `node.exe`
/// using bounded header/resource seeks instead of spawning `node.exe --version`.
#[cfg(windows)]
pub fn read_official_node_pe_version(path: &Path) -> Option<String> {
    pe_version::read_official_node_pe_version(path)
}

#[cfg(not(windows))]
pub fn read_official_node_pe_version(_path: &Path) -> Option<String> {
    None
}

#[cfg(windows)]
mod pe_version {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    use std::path::Path;

    pub(super) fn read_official_node_pe_version(path: &Path) -> Option<String> {
        let mut file = File::open(path).ok()?;
        let mut header = [0u8; 4096];
        let n = file.read(&mut header).ok()?;
        let hdr = &header[..n];
        if hdr.len() < 64 || &hdr[0..2] != b"MZ" {
            return None;
        }

        let e_lfanew = read_u32(hdr, 60)? as usize;
        let pe_end = e_lfanew.checked_add(24)?;
        let full_hdr: Vec<u8>;
        let h = if pe_end <= hdr.len() {
            hdr
        } else if e_lfanew < 65536 {
            file.seek(SeekFrom::Start(0)).ok()?;
            full_hdr = read_exact_up_to(&mut file, pe_end.max(4096))?;
            &full_hdr
        } else {
            return None;
        };

        if h.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
            return None;
        }
        let num_sections = read_u16(h, e_lfanew + 6)? as usize;
        let size_of_opt = read_u16(h, e_lfanew + 20)? as usize;
        let opt_off = e_lfanew + 24;
        let sec_off = opt_off.checked_add(size_of_opt)?;
        let sec_table_end = sec_off.checked_add(num_sections.checked_mul(40)?)?;
        if num_sections == 0 || num_sections > 96 || sec_table_end > 65536 {
            return None;
        }

        let extended_hdr: Vec<u8>;
        let h = if sec_table_end <= h.len() {
            h
        } else {
            file.seek(SeekFrom::Start(0)).ok()?;
            extended_hdr = read_exact_up_to(&mut file, sec_table_end)?;
            &extended_hdr
        };

        let opt = h.get(opt_off..sec_off)?;
        let magic = read_u16(opt, 0)?;
        let (rva_count_off, dd_off) = match magic {
            0x010b => (92usize, 96usize),   // PE32
            0x020b => (108usize, 112usize), // PE32+
            _ => return None,
        };
        let num_rva = read_u32(opt, rva_count_off)? as usize;
        if num_rva <= 2 {
            return None;
        }
        let rsrc_dir_rva = read_u32(opt, dd_off + 2 * 8)?;
        let rsrc_dir_size = read_u32(opt, dd_off + 2 * 8 + 4)?;
        if rsrc_dir_rva == 0 || rsrc_dir_size == 0 {
            return None;
        }

        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let base = sec_off + i * 40;
            sections.push(PeSection {
                virtual_size: read_u32(h, base + 8)?,
                virtual_address: read_u32(h, base + 12)?,
                size_of_raw_data: read_u32(h, base + 16)?,
                pointer_to_raw_data: read_u32(h, base + 20)?,
            });
        }

        let rsrc_base = rva_to_file_offset(&sections, rsrc_dir_rva)?;
        let version_bytes = read_rt_version_resource(&mut file, &sections, rsrc_base)?;
        parse_node_version_info(&version_bytes)
    }

    #[derive(Clone, Copy)]
    struct PeSection {
        virtual_size: u32,
        virtual_address: u32,
        size_of_raw_data: u32,
        pointer_to_raw_data: u32,
    }

    fn rva_to_file_offset(sections: &[PeSection], rva: u32) -> Option<u64> {
        for sec in sections {
            let span = sec.virtual_size.max(sec.size_of_raw_data);
            let end = sec.virtual_address.checked_add(span)?;
            if rva >= sec.virtual_address && rva < end {
                let delta = rva - sec.virtual_address;
                if delta < sec.size_of_raw_data {
                    return Some(u64::from(sec.pointer_to_raw_data) + u64::from(delta));
                }
            }
        }
        None
    }

    fn read_exact_up_to(file: &mut File, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut read_total = 0;
        while read_total < len {
            match file.read(&mut buf[read_total..]) {
                Ok(0) => break,
                Ok(k) => read_total += k,
                Err(_) => return None,
            }
        }
        buf.truncate(read_total);
        Some(buf)
    }

    fn read_at(file: &mut File, offset: u64, len: usize) -> Option<Vec<u8>> {
        file.seek(SeekFrom::Start(offset)).ok()?;
        let buf = read_exact_up_to(file, len)?;
        if buf.len() < len {
            None
        } else {
            Some(buf)
        }
    }

    fn read_resource_dir_entries(file: &mut File, dir_offset: u64) -> Option<Vec<(u32, u32)>> {
        let hdr = read_at(file, dir_offset, 16)?;
        let num_named = read_u16(&hdr, 12)? as usize;
        let num_id = read_u16(&hdr, 14)? as usize;
        let total = num_named.checked_add(num_id)?;
        if total == 0 || total > 512 {
            return None;
        }
        let raw = read_at(file, dir_offset.checked_add(16)?, total * 8)?;
        let mut entries = Vec::with_capacity(total);
        for i in 0..total {
            let base = i * 8;
            entries.push((read_u32(&raw, base)?, read_u32(&raw, base + 4)?));
        }
        Some(entries)
    }

    fn read_rt_version_resource(
        file: &mut File,
        sections: &[PeSection],
        rsrc_base: u64,
    ) -> Option<Vec<u8>> {
        const RT_VERSION: u32 = 16;
        const SUBDIR_FLAG: u32 = 0x8000_0000;

        let type_entries = read_resource_dir_entries(file, rsrc_base)?;
        let (_, type_off) = type_entries
            .into_iter()
            .find(|(id, off)| *id == RT_VERSION && (*off & SUBDIR_FLAG) != 0)?;

        let name_entries = read_resource_dir_entries(
            file,
            rsrc_base.checked_add(u64::from(type_off & !SUBDIR_FLAG))?,
        )?;
        let (_, name_off) = name_entries
            .into_iter()
            .find(|(_, off)| (*off & SUBDIR_FLAG) != 0)?;

        let lang_entries = read_resource_dir_entries(
            file,
            rsrc_base.checked_add(u64::from(name_off & !SUBDIR_FLAG))?,
        )?;
        let (_, leaf_off) = lang_entries
            .into_iter()
            .find(|(_, off)| (*off & SUBDIR_FLAG) == 0)?;

        let data_entry = read_at(file, rsrc_base.checked_add(u64::from(leaf_off))?, 16)?;
        let data_rva = read_u32(&data_entry, 0)?;
        let data_size = read_u32(&data_entry, 4)? as usize;
        if !(64..=65536).contains(&data_size) {
            return None;
        }
        let data_offset = rva_to_file_offset(sections, data_rva)?;
        read_at(file, data_offset, data_size)
    }

    fn parse_node_version_info(buf: &[u8]) -> Option<String> {
        let (key, w_type, val_start, val_len, children_start, node_end) =
            parse_ver_node(buf, 0, buf.len())?;
        if key != "VS_VERSION_INFO" || w_type != 0 || val_len < 52 {
            return None;
        }
        let fixed_end = val_start.checked_add(52)?;
        let fixed = buf.get(val_start..fixed_end)?;
        if read_u32(fixed, 0)? != 0xFEEF_04BD {
            return None;
        }
        let prod_ms = read_u32(fixed, 16)?;
        let prod_ls = read_u32(fixed, 20)?;
        if (prod_ls & 0xFFFF) != 0 {
            return None;
        }
        let expected_ver = format!("{}.{}.{}", prod_ms >> 16, prod_ms & 0xFFFF, prod_ls >> 16);

        let mut original_filename: Option<String> = None;
        let mut file_description: Option<String> = None;
        let mut product_name: Option<String> = None;
        let mut product_version: Option<String> = None;

        let mut sfi_off = children_start;
        while sfi_off + 6 <= node_end {
            let Some((sfi_key, _, _, _, sfi_children, sfi_end)) =
                parse_ver_node(buf, sfi_off, node_end)
            else {
                break;
            };
            if sfi_key == "StringFileInfo" {
                let mut tbl_off = sfi_children;
                while tbl_off + 6 <= sfi_end {
                    let Some((_, _, _, _, tbl_children, tbl_end)) =
                        parse_ver_node(buf, tbl_off, sfi_end)
                    else {
                        break;
                    };
                    let mut str_off = tbl_children;
                    while str_off + 6 <= tbl_end {
                        let Some((str_key, str_type, sv_start, sv_len, _, str_end)) =
                            parse_ver_node(buf, str_off, tbl_end)
                        else {
                            break;
                        };
                        if str_type == 1 {
                            let byte_len = sv_len.saturating_mul(2);
                            let sv_end = sv_start.saturating_add(byte_len).min(str_end);
                            if let Some(val) = decode_utf16le_trimmed(buf.get(sv_start..sv_end)?) {
                                match str_key.as_str() {
                                    "OriginalFilename" => original_filename = Some(val),
                                    "FileDescription" => file_description = Some(val),
                                    "ProductName" => product_name = Some(val),
                                    "ProductVersion" => product_version = Some(val),
                                    _ => {}
                                }
                            }
                        }
                        let next = align4(str_end);
                        if next <= str_off {
                            break;
                        }
                        str_off = next;
                    }
                    let next = align4(tbl_end);
                    if next <= tbl_off {
                        break;
                    }
                    tbl_off = next;
                }
            }
            let next = align4(sfi_end);
            if next <= sfi_off {
                break;
            }
            sfi_off = next;
        }

        if !original_filename.as_deref()?.eq_ignore_ascii_case("node.exe") {
            return None;
        }
        if file_description.as_deref()? != "Node.js JavaScript Runtime" {
            return None;
        }
        if product_name.as_deref()? != "Node.js" {
            return None;
        }
        let pv = product_version?;
        if pv != expected_ver {
            return None;
        }
        Some(format!("v{pv}"))
    }

    fn parse_ver_node(
        buf: &[u8],
        offset: usize,
        limit: usize,
    ) -> Option<(String, u16, usize, usize, usize, usize)> {
        let w_len = read_u16(buf, offset)? as usize;
        let w_val_len = read_u16(buf, offset + 2)? as usize;
        let w_type = read_u16(buf, offset + 4)?;
        if w_len < 6 {
            return None;
        }
        let node_end = offset.checked_add(w_len)?.min(limit);
        let (key, key_end) = read_utf16le_cstr(buf, offset + 6, node_end)?;
        let val_start = align4(key_end).min(node_end);
        let val_bytes = if w_type == 1 {
            w_val_len.saturating_mul(2)
        } else {
            w_val_len
        };
        let children_start = align4(val_start.saturating_add(val_bytes).min(node_end)).min(node_end);
        Some((key, w_type, val_start, w_val_len, children_start, node_end))
    }

    fn read_utf16le_cstr(buf: &[u8], start: usize, limit: usize) -> Option<(String, usize)> {
        let mut pos = start;
        let mut units = Vec::new();
        while pos + 2 <= limit {
            let unit = u16::from_le_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
            if unit == 0 {
                return Some((String::from_utf16(&units).ok()?, pos));
            }
            units.push(unit);
        }
        None
    }

    fn decode_utf16le_trimmed(bytes: &[u8]) -> Option<String> {
        let (chunks, _) = bytes.as_chunks::<2>();
        let mut units: Vec<u16> = chunks
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        String::from_utf16(&units).ok()
    }

    fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
        let slice = buf.get(off..off.checked_add(2)?)?;
        Some(u16::from_le_bytes([slice[0], slice[1]]))
    }

    fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
        let slice = buf.get(off..off.checked_add(4)?)?;
        Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    const fn align4(n: usize) -> usize {
        (n + 3) & !3
    }
}

/// Returns the trimmed `node --version` output for `path`, avoiding a subprocess
/// spawn on Windows when reading an official `node.exe`, or empty string on failure.
pub fn node_version_for(path: &Path) -> String {
    if let Some(version) = read_official_node_pe_version(path) {
        return version;
    }
    std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Version string of the `node` on PATH (`v26.13.0`), or `unknown`.
pub fn node_version() -> String {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION
        .get_or_init(|| {
            node_executable()
                .map(|n| node_version_for(&n))
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "unknown".into())
        })
        .clone()
}

/// Extract the lowercase ASCII hostname from an HTTP(S) URL string.
fn url_hostname(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let after_scheme = trimmed.split_once("://")?.1;
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next()?
    } else {
        host_port.split(':').next()?
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Map GitHub Actions server URL + runner environment to npm's sub-CI token
/// (`dotcom-hosted`, `dotcom-selfhosted`, `dotcom`, `ghecom`, `ghes`).
fn github_actions_sub_ci(server_url: &str, runner_env: &str) -> Option<&'static str> {
    let runner_env = runner_env.trim();
    match url_hostname(server_url).as_deref() {
        Some("github.com") => match runner_env {
            "github-hosted" => Some("dotcom-hosted"),
            "self-hosted" => Some("dotcom-selfhosted"),
            _ => Some("dotcom"),
        },
        Some(host) if host == "ghe.com" || host.ends_with(".ghe.com") => Some("ghecom"),
        Some(_) => Some("ghes"),
        None => None,
    }
}

/// npm's default `user-agent`:
/// `npm/{npm-version} node/{node-version} {platform} {arch} workspaces/{bool} {ci}`.
pub fn npm_user_agent() -> String {
    let platform = match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        other => other,
    };
    let is_github_actions = std::env::var_os("GITHUB_ACTIONS").is_some_and(|v| !v.is_empty());
    let ci_name = if is_github_actions {
        Some("github-actions")
    } else {
        [
            ("GITLAB_CI", "gitlab-ci"),
            ("CIRCLECI", "circleci"),
            ("TRAVIS", "travis-ci"),
            ("BUILDKITE", "buildkite"),
            ("TF_BUILD", "azure-pipelines"),
        ]
        .iter()
        .find(|(var, _)| std::env::var_os(var).is_some_and(|v| !v.is_empty()))
        .map(|(_, name)| *name)
    };
    let sub_ci_name = if is_github_actions {
        let server_url = std::env::var("GITHUB_SERVER_URL").unwrap_or_default();
        let runner_env = std::env::var("RUNNER_ENVIRONMENT").unwrap_or_default();
        github_actions_sub_ci(&server_url, &runner_env)
    } else {
        None
    };
    let ci = match (ci_name, sub_ci_name) {
        (Some(name), Some(sub)) => format!(" ci/{name}/{sub}"),
        (Some(name), None) => format!(" ci/{name}"),
        (None, _) => String::new(),
    };
    format!(
        "npm/{NPM_VERSION} node/{} {platform} {arch} workspaces/false{ci}",
        node_version()
    )
}

/// A Node entry point for `npm_execpath`: tools run `node $npm_execpath ...`,
/// so rnpm provides a small script that forwards to the native binary.
pub fn node_entrypoint() -> Option<PathBuf> {
    static ENTRY: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    ENTRY
        .get_or_init(|| {
            let exe = std::env::current_exe().ok()?;
            let exe_json = serde_json::to_string(&exe.to_string_lossy()).ok()?;
            let script = format!(
                "#!/usr/bin/env node\n// Forwards to the rnpm binary so `node $npm_execpath` works.\nconst {{ spawnSync }} = require('child_process')\nconst r = spawnSync({exe_json}, process.argv.slice(2), {{ stdio: 'inherit' }})\nprocess.exit(r.status === null ? 1 : r.status)\n"
            );
            let candidates = [
                exe.parent().map(|d| d.join("rnpm-cli.js")),
                Some(std::env::temp_dir().join("rnpm").join("rnpm-cli.js")),
            ];
            candidates.into_iter().flatten().find(|path| {
                if std::fs::read_to_string(path).is_ok_and(|s| s == script) {
                    return true;
                }
                path.parent().is_some_and(|d| std::fs::create_dir_all(d).is_ok())
                    && std::fs::write(path, &script).is_ok()
            })
        })
        .clone()
}

/// Config npm exports to scripts (@npmcli/config set-envs): non-default
/// non-env settings, plus global/local prefix, node-gyp and npm version,
/// built directly from a preloaded Config without disk re-reads.
pub fn npm_config_env_from_config(
    project_root: &Path,
    config: &rnpm_config::Config,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if !config.layers.is_empty() {
        let mut winning: std::collections::BTreeMap<String, (&str, &String)> =
            std::collections::BTreeMap::new();
        for layer in &config.layers {
            let source = if layer.name == "env" { "env" } else { "other" };
            for (key, value) in &layer.settings {
                winning.insert(key.clone(), (source, value));
            }
        }
        for (key, (source, value)) in winning {
            if source == "env"
                || key.starts_with(['/', '@', '_'])
                || key.contains(":_")
                || key.contains("//")
            {
                continue;
            }
            out.push((
                format!("npm_config_{}", key.replace('-', "_").to_ascii_lowercase()),
                value.clone(),
            ));
        }
    } else {
        for (key, value) in &config.npmrc.settings {
            if key.starts_with(['/', '@', '_']) || key.contains(":_") || key.contains("//") {
                continue;
            }
            out.push((
                format!("npm_config_{}", key.replace('-', "_").to_ascii_lowercase()),
                value.clone(),
            ));
        }
    }
    let global_prefix = config
        .get("prefix")
        .map(PathBuf::from)
        .unwrap_or_else(rnpm_config::find_global_prefix);
    let prefix = global_prefix.to_string_lossy().to_string();
    out.push(("npm_config_global_prefix".into(), prefix));
    out.push((
        "npm_config_local_prefix".into(),
        project_root.to_string_lossy().to_string(),
    ));
    if let Some(gyp) = find_node_gyp(project_root, project_root, config, None) {
        out.push((
            "npm_config_node_gyp".into(),
            gyp.to_string_lossy().to_string(),
        ));
    }
    out.push(("npm_config_npm_version".into(), NPM_VERSION.into()));
    out
}

pub fn npm_config_env(
    project_root: &Path,
    trusted_config: Option<&rnpm_config::Config>,
) -> Vec<(String, String)> {
    if let Some(cfg) = trusted_config {
        npm_config_env_from_config(project_root, cfg)
    } else {
        let loaded_config = rnpm_config::Config::load(Some(project_root)).unwrap_or_default();
        npm_config_env_from_config(project_root, &loaded_config)
    }
}

/// Builds the scrubbed and populated environment map for the lifecycle script using a preloaded Config.
pub fn build_lifecycle_env_with_config(
    ctx: &LifecycleContext,
    config: &rnpm_config::Config,
) -> HashMap<String, String> {
    let mut env: HashMap<String, String> = HashMap::new();

    // 1. Inherit existing environment while scrubbing sensitive credentials
    for (k, v) in std::env::vars() {
        if !is_sensitive_credential_key(&k) {
            env.insert(k, v);
        } else {
            debug!("Scrubbed sensitive credential key: {}", k);
        }
    }

    // 2. Extra env passed in (also scrubbed)
    for (k, v) in &ctx.extra_env {
        if !k.eq_ignore_ascii_case("path") && !is_sensitive_credential_key(k) {
            env.insert(k.clone(), v.clone());
        }
    }

    // Sanitize npm_config_user_agent if present
    if let Some(ua) = env.get_mut("npm_config_user_agent") {
        *ua = scrub_text(ua);
    } else {
        env.insert("npm_config_user_agent".to_string(), npm_user_agent());
    }
    for (key, value) in npm_config_env_from_config(&ctx.project_root, config) {
        env.entry(key).or_insert(value);
    }

    // 3. Hierarchical PATH construction:
    // 3.1: Local package node_modules/.bin
    // 3.2: Ancestor directories node_modules/.bin up to project root
    let mut path_entries: Vec<PathBuf> = Vec::new();

    let local_bin = ctx.package_dir.join("node_modules").join(".bin");
    if local_bin.exists() {
        path_entries.push(local_bin);
    }

    let mut current = ctx.package_dir.as_path();
    while let Some(parent) = current.parent() {
        let parent_bin = parent.join("node_modules").join(".bin");
        if parent_bin.exists() && !path_entries.contains(&parent_bin) {
            path_entries.push(parent_bin);
        }
        if parent == ctx.project_root {
            break;
        }
        current = parent;
    }

    let root_bin = ctx.project_root.join("node_modules").join(".bin");
    if root_bin.exists() && !path_entries.contains(&root_bin) {
        path_entries.push(root_bin);
    }

    // Node executable directory (absolute, like npm's process.execPath)
    let node_bin = ctx.node_execpath.clone().unwrap_or_else(|| {
        if let Ok(cur_node) = std::env::var("NODE") {
            PathBuf::from(cur_node)
        } else {
            node_executable().unwrap_or_else(|| PathBuf::from("node"))
        }
    });

    if let Some(parent) = node_bin.parent() {
        if parent.as_os_str() != "" {
            path_entries.push(parent.to_path_buf());
        }
    }

    if let Some(gyp_bin) = node_gyp_bin_dir() {
        if !path_entries.contains(&gyp_bin) {
            path_entries.push(gyp_bin);
        }
    }

    // Append existing system PATH
    let existing_path = std::env::var("PATH")
        .or_else(|_| std::env::var("Path"))
        .unwrap_or_default();
    let joined_custom_path = std::env::join_paths(&path_entries)
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    let final_path = if joined_custom_path.is_empty() {
        existing_path
    } else if existing_path.is_empty() {
        joined_custom_path
    } else {
        format!(
            "{joined_custom_path}{}{existing_path}",
            if cfg!(windows) { ";" } else { ":" }
        )
    };

    // Update all variations of PATH to avoid Windows case-sensitivity mismatches
    env.remove("Path");
    env.remove("path");
    env.insert("PATH".to_string(), final_path.clone());
    #[cfg(windows)]
    env.insert("Path".to_string(), final_path);

    // 4. Standard npm environment contract
    // Real npm set-envs.js always sets INIT_CWD to invocation cwd (unless explicitly passed in extra_env),
    // never letting a stale outer process INIT_CWD leak through from inherited process.env.
    if let Some(val) = ctx.extra_env.get("INIT_CWD") {
        env.insert("INIT_CWD".to_string(), val.clone());
    } else {
        env.insert(
            "INIT_CWD".to_string(),
            ctx.project_root.to_string_lossy().to_string(),
        );
    }
    if !env.contains_key("npm_command") {
        let cmd = match ctx.event.as_str() {
            "preinstall" | "install" | "postinstall" => "install",
            "prepack" | "postpack" => "pack",
            "prepublish" | "publish" | "postpublish" | "prepublishOnly" => "publish",
            "test" | "pretest" | "posttest" => "test",
            "start" | "prestart" | "poststart" => "start",
            "restart" | "prerestart" | "postrestart" => "restart",
            "stop" | "prestop" | "poststop" => "stop",
            _ => "run",
        };
        env.insert("npm_command".to_string(), cmd.to_string());
    }
    env.insert("npm_lifecycle_event".to_string(), ctx.event.clone());
    env.insert("npm_lifecycle_script".to_string(), ctx.script_cmd.clone());
    env.insert("npm_package_name".to_string(), ctx.package_name.clone());

    if let Some(ref ver) = ctx.package_version {
        env.insert("npm_package_version".to_string(), ver.clone());
    }

    if let Some(ref gyp) = ctx.node_gyp {
        env.insert(
            "npm_config_node_gyp".to_string(),
            gyp.to_string_lossy().to_string(),
        );
    }

    let pkg_json = ctx.package_dir.join("package.json");
    env.insert(
        "npm_package_json".to_string(),
        pkg_json.to_string_lossy().to_string(),
    );

    // Populate full npm_package_* environment hierarchy from package.json if present
    if pkg_json.exists() {
        if let Ok(content) = std::fs::read_to_string(&pkg_json) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(obj) = val.as_object() {
                    for (k, v) in obj {
                        flatten_package_json_to_env("npm_package", k, v, &mut env);
                    }
                }
            }
        }
    }

    let node_str = node_bin.to_string_lossy().to_string();
    env.insert("NODE".to_string(), node_str.clone());
    env.insert("npm_node_execpath".to_string(), node_str);

    let rnpm_exec = ctx
        .npm_execpath
        .clone()
        .or_else(node_entrypoint)
        .unwrap_or_else(|| std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rnpm")));
    env.insert(
        "npm_execpath".to_string(),
        rnpm_exec.to_string_lossy().to_string(),
    );

    // Honor config node-options: inject or append into NODE_OPTIONS
    let active_config = ctx.config.as_ref().unwrap_or(config);
    let node_opts = active_config
        .get("node-options")
        .map(str::to_string)
        .or_else(|| env.get("npm_config_node_options").cloned())
        .filter(|s| {
            let trimmed = s.trim().trim_matches('"');
            !trimmed.is_empty() && trimmed != "null" && s != "null"
        });

    if let Some(opts) = node_opts {
        if let Some(existing) = env.get_mut("NODE_OPTIONS") {
            let trimmed = existing.trim();
            if trimmed.is_empty() {
                *existing = opts;
            } else if trimmed == opts {
                // already identical
            } else {
                *existing = format!("{trimmed} {opts}");
            }
        } else {
            env.insert("NODE_OPTIONS".to_string(), opts);
        }
    }

    // Set NODE_ENV=production on --omit=dev or --production when not already set
    if !env.contains_key("NODE_ENV") {
        let is_omit_dev = |val: &str| {
            val.split(',').any(|p| {
                matches!(
                    p.trim().to_ascii_lowercase().as_str(),
                    "dev" | "development" | "prod" | "production"
                )
            })
        };
        let is_truthy = |val: &str| {
            matches!(
                val.trim().to_ascii_lowercase().as_str(),
                "true" | "1" | "yes" | "on"
            )
        };

        let mut omit_dev_active = false;

        if let Some(val) = env.get("npm_config_omit").or_else(|| env.get("omit")) {
            if is_omit_dev(val) {
                omit_dev_active = true;
            }
        }
        if let Some(val) = env
            .get("npm_config_production")
            .or_else(|| env.get("production"))
        {
            if is_truthy(val) {
                omit_dev_active = true;
            }
        }

        if !omit_dev_active {
            if let Some(val) = active_config.get("omit") {
                if is_omit_dev(val) {
                    omit_dev_active = true;
                }
            }
            if let Some(val) = active_config.get("production") {
                if is_truthy(val) {
                    omit_dev_active = true;
                }
            }
        }

        if !omit_dev_active {
            if let Some(overrides) = rnpm_config::get_process_cli_overrides() {
                if let Some(val) = overrides.get("omit") {
                    if is_omit_dev(val) {
                        omit_dev_active = true;
                    }
                }
                if let Some(val) = overrides.get("production") {
                    if is_truthy(val) {
                        omit_dev_active = true;
                    }
                }
            }
        }

        let has_include_dev = |val: &str| {
            val.split(',').any(|p| {
                matches!(
                    p.trim().to_ascii_lowercase().as_str(),
                    "dev" | "development" | "prod" | "production"
                )
            })
        };

        let mut include_dev = false;
        if let Some(val) = env
            .get("npm_config_include")
            .or_else(|| env.get("include"))
        {
            if has_include_dev(val) {
                include_dev = true;
            }
        }
        if !include_dev {
            if let Some(val) = active_config.get("include") {
                if has_include_dev(val) {
                    include_dev = true;
                }
            }
        }
        if !include_dev {
            if let Some(overrides) = rnpm_config::get_process_cli_overrides() {
                if let Some(val) = overrides.get("include") {
                    if has_include_dev(val) {
                        include_dev = true;
                    }
                }
            }
        }

        if omit_dev_active && !include_dev {
            env.insert("NODE_ENV".to_string(), "production".to_string());
        }
    }

    env
}

/// Builds the scrubbed and populated environment map for the lifecycle script.
pub fn build_lifecycle_env(ctx: &LifecycleContext) -> HashMap<String, String> {
    let loaded_config;
    let config = if let Some(ref cfg) = ctx.config {
        cfg
    } else {
        loaded_config = rnpm_config::Config::load(Some(&ctx.project_root)).unwrap_or_default();
        &loaded_config
    };
    build_lifecycle_env_with_config(ctx, config)
}

fn flatten_pkg_script_env(prefix: &str, value: &serde_json::Value, env: &mut HashMap<String, String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                flatten_pkg_script_env(&format!("{prefix}_{key}"), value, env);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                flatten_pkg_script_env(&format!("{prefix}_{index}"), value, env);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(false) => {
            env.insert(prefix.into(), String::new());
        }
        serde_json::Value::String(value) => {
            env.insert(prefix.into(), value.clone());
        }
        value => {
            env.insert(prefix.into(), value.to_string());
        }
    }
}

#[inline]
fn bytes_contain_subslice(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
}

fn flatten_pkg_script_fields_from_bytes(bytes: &[u8], env: &mut HashMap<String, String>) {
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let maybe_has_fields = bytes_contain_subslice(bytes, b"\"config\"")
        || bytes_contain_subslice(bytes, b"\"engines\"")
        || bytes_contain_subslice(bytes, b"\"bin\"")
        || bytes_contain_subslice(bytes, b"\"name\"")
        || bytes_contain_subslice(bytes, b"\"version\"")
        || bytes_contain_subslice(bytes, b"\\u");
    if !maybe_has_fields {
        return;
    }
    if let Ok(package) = serde_json::from_slice::<serde_json::Value>(bytes) {
        for key in ["name", "version"] {
            if let Some(value) = package.get(key).filter(|value| value.is_string()) {
                flatten_pkg_script_env(&format!("npm_package_{key}"), value, env);
            }
        }
        for key in ["config", "engines", "bin"] {
            if let Some(value) = package.get(key) {
                flatten_pkg_script_env(&format!("npm_package_{key}"), value, env);
            }
        }
    }
}

/// Shared immutable environment snapshot computed once per dependency/workspace batch
/// (inherited env scrubbed once, config layers resolved once, node/node-gyp/PATH resolved once).
struct ScriptBaseEnv {
    env: HashMap<String, String>,
    gyp_bin: Option<PathBuf>,
    inherited_tail_no_gyp: std::ffi::OsString,
    inherited_tail_with_gyp: Option<std::ffi::OsString>,
    init_cwd_fallback: PathBuf,
}

impl ScriptBaseEnv {
    fn build(
        project_root: &Path,
        config: &rnpm_config::Config,
        node_execpath: Option<&Path>,
        npm_execpath: Option<&Path>,
        extra_env: Option<&HashMap<String, String>>,
    ) -> Self {
        let mut env: HashMap<String, String> = HashMap::with_capacity(96);

        for (k, v) in std::env::vars() {
            if !k.eq_ignore_ascii_case("path") && !is_sensitive_credential_key(&k) {
                env.insert(k, v);
            }
        }

        if let Some(extra) = extra_env {
            for (k, v) in extra {
                if !k.eq_ignore_ascii_case("path") && !is_sensitive_credential_key(k) {
                    env.insert(k.clone(), v.clone());
                }
            }
        }

        if let Some(ua) = env.get_mut("npm_config_user_agent") {
            *ua = scrub_text(ua);
        } else {
            env.insert("npm_config_user_agent".to_string(), npm_user_agent());
        }

        // Single pass over config layers instead of walking config twice.
        if !config.layers.is_empty() {
            let mut winning = std::collections::BTreeMap::new();
            for layer in &config.layers {
                let source = if layer.name == "env" { "env" } else { "other" };
                for (key, value) in &layer.settings {
                    winning.insert(key.as_str(), (source, value));
                }
            }
            for (key, (source, value)) in winning {
                if source == "env" {
                    continue;
                }
                if !(key.starts_with(['/', '@', '_'])
                    || key.contains(":_")
                    || key.contains("//"))
                {
                    let lower_k = format!("npm_config_{}", key.replace('-', "_").to_ascii_lowercase());
                    env.entry(lower_k).or_insert_with(|| value.clone());
                }
                if !is_sensitive_credential_key(key) {
                    env.insert(format!("npm_config_{}", key.replace('-', "_")), value.clone());
                }
            }
        } else {
            for (key, value) in &config.npmrc.settings {
                if !(key.starts_with(['/', '@', '_'])
                    || key.contains(":_")
                    || key.contains("//"))
                {
                    let lower_k = format!("npm_config_{}", key.replace('-', "_").to_ascii_lowercase());
                    env.entry(lower_k).or_insert_with(|| value.clone());
                }
                if !is_sensitive_credential_key(key) {
                    env.insert(format!("npm_config_{}", key.replace('-', "_")), value.clone());
                }
            }
        }

        let global_prefix = config
            .get("prefix")
            .map(PathBuf::from)
            .unwrap_or_else(rnpm_config::find_global_prefix);
        env.entry("npm_config_global_prefix".into())
            .or_insert_with(|| global_prefix.to_string_lossy().into_owned());
        env.entry("npm_config_local_prefix".into())
            .or_insert_with(|| project_root.to_string_lossy().into_owned());
        if let Some(gyp) = find_node_gyp(project_root, project_root, config, None) {
            env.entry("npm_config_node_gyp".into())
                .or_insert_with(|| gyp.to_string_lossy().into_owned());
        }
        env.entry("npm_config_npm_version".into())
            .or_insert_with(|| NPM_VERSION.into());

        let node_bin = node_execpath.map(Path::to_path_buf).unwrap_or_else(|| {
            if let Ok(cur_node) = std::env::var("NODE") {
                PathBuf::from(cur_node)
            } else {
                node_executable().unwrap_or_else(|| PathBuf::from("node"))
            }
        });
        let node_str = node_bin.to_string_lossy().into_owned();
        env.insert("npm_node_execpath".to_string(), node_str.clone());
        env.insert("NODE".to_string(), node_str);

        let rnpm_exec = npm_execpath
            .map(Path::to_path_buf)
            .or_else(node_entrypoint)
            .unwrap_or_else(|| std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rnpm")));
        env.insert(
            "npm_execpath".to_string(),
            rnpm_exec.to_string_lossy().into_owned(),
        );

        let node_opts = config
            .get("node-options")
            .map(str::to_string)
            .or_else(|| env.get("npm_config_node_options").cloned())
            .filter(|s| {
                let trimmed = s.trim().trim_matches('"');
                !trimmed.is_empty() && trimmed != "null" && s != "null"
            });

        if let Some(opts) = node_opts {
            if let Some(existing) = env.get_mut("NODE_OPTIONS") {
                let trimmed = existing.trim();
                if trimmed.is_empty() {
                    *existing = opts;
                } else if trimmed != opts {
                    *existing = format!("{trimmed} {opts}");
                }
            } else {
                env.insert("NODE_OPTIONS".to_string(), opts);
            }
        }

        if !env.contains_key("NODE_ENV") {
            let is_omit_dev = |val: &str| {
                val.split(',').any(|p| {
                    matches!(
                        p.trim().to_ascii_lowercase().as_str(),
                        "dev" | "development" | "prod" | "production"
                    )
                })
            };
            let is_truthy = |val: &str| {
                matches!(
                    val.trim().to_ascii_lowercase().as_str(),
                    "true" | "1" | "yes" | "on"
                )
            };

            let mut omit_dev_active = env
                .get("npm_config_omit")
                .or_else(|| env.get("omit"))
                .is_some_and(|v| is_omit_dev(v))
                || env
                    .get("npm_config_production")
                    .or_else(|| env.get("production"))
                    .is_some_and(|v| is_truthy(v));

            if !omit_dev_active {
                if config.get("omit").is_some_and(is_omit_dev)
                    || config.get("production").is_some_and(is_truthy)
                {
                    omit_dev_active = true;
                } else if let Some(overrides) = rnpm_config::get_process_cli_overrides() {
                    if overrides.get("omit").is_some_and(|v| is_omit_dev(v))
                        || overrides.get("production").is_some_and(|v| is_truthy(v))
                    {
                        omit_dev_active = true;
                    }
                }
            }

            let has_include_dev = |val: &str| {
                val.split(',').any(|p| {
                    matches!(
                        p.trim().to_ascii_lowercase().as_str(),
                        "dev" | "development" | "prod" | "production"
                    )
                })
            };

            let mut include_dev = env
                .get("npm_config_include")
                .or_else(|| env.get("include"))
                .is_some_and(|v| has_include_dev(v));
            if !include_dev {
                if config.get("include").is_some_and(has_include_dev) {
                    include_dev = true;
                } else if let Some(overrides) = rnpm_config::get_process_cli_overrides() {
                    if overrides.get("include").is_some_and(|v| has_include_dev(v)) {
                        include_dev = true;
                    }
                }
            }

            if omit_dev_active && !include_dev {
                env.insert("NODE_ENV".to_string(), "production".to_string());
            }
        }

        let gyp_bin = node_gyp_bin_dir();
        let inherited = std::env::var_os("PATH")
            .or_else(|| std::env::var_os("Path"))
            .unwrap_or_default();
        let inherited_paths: Vec<PathBuf> = std::env::split_paths(&inherited).collect();
        let inherited_tail_no_gyp =
            std::env::join_paths(inherited_paths.iter()).unwrap_or_default();
        let inherited_tail_with_gyp = gyp_bin.as_ref().and_then(|g| {
            std::env::join_paths(std::iter::once(g).chain(inherited_paths.iter())).ok()
        });

        Self {
            env,
            gyp_bin,
            inherited_tail_no_gyp,
            inherited_tail_with_gyp,
            init_cwd_fallback: extra_env
                .and_then(|extra| extra.get("INIT_CWD"))
                .map_or_else(|| project_root.to_path_buf(), PathBuf::from),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_package_env_with_manifest(
        &self,
        package_dir: &Path,
        package_name: &str,
        package_version: Option<&str>,
        event: &str,
        script_cmd: &str,
        extra_env: Option<&HashMap<String, String>>,
        node_gyp: Option<&Path>,
        manifest: Option<&rnpm_core::Manifest>,
    ) -> HashMap<String, String> {
        let mut env = self.env.clone();

        if let Some(extra) = extra_env {
            for (k, v) in extra {
                if !k.eq_ignore_ascii_case("path") && !is_sensitive_credential_key(k) {
                    env.insert(k.clone(), v.clone());
                }
            }
        }

        if let Some(val) = extra_env.and_then(|e| e.get("INIT_CWD")) {
            env.insert("INIT_CWD".to_string(), val.clone());
        } else {
            env.insert(
                "INIT_CWD".to_string(),
                self.init_cwd_fallback.to_string_lossy().into_owned(),
            );
        }

        let cmd = match event {
            "preinstall" | "install" | "postinstall" => "install",
            "prepack" | "postpack" => "pack",
            "prepublish" | "publish" | "postpublish" | "prepublishOnly" => "publish",
            "test" | "pretest" | "posttest" => "test",
            "start" | "prestart" | "poststart" => "start",
            "restart" | "prerestart" | "postrestart" => "restart",
            "stop" | "prestop" | "poststop" => "stop",
            _ => "run",
        };
        env.entry("npm_command".to_string())
            .or_insert_with(|| cmd.to_string());
        env.insert("npm_lifecycle_event".to_string(), event.to_string());
        env.insert("npm_lifecycle_script".to_string(), script_cmd.to_string());
        env.retain(|key, _| !key.starts_with("npm_package_") || key == "npm_package_version");
        env.insert("npm_package_name".to_string(), package_name.to_string());
        if let Some(ver) = package_version {
            env.insert("npm_package_version".to_string(), ver.to_string());
        }
        let pkg_json = package_dir.join("package.json");
        env.insert(
            "npm_package_json".to_string(),
            pkg_json.to_string_lossy().into_owned(),
        );

        // Reuse raw-field JSON flattening whenever raw package.json text or the
        // file on disk is available so arrays/booleans/nulls in `engines`, `bin`,
        // and `config` flatten identically to single-package script execution.
        if let Some(raw_bytes) = manifest.and_then(|m| m.raw_text.as_deref().map(str::as_bytes)) {
            flatten_pkg_script_fields_from_bytes(raw_bytes, &mut env);
        } else if let Ok(bytes) = std::fs::read(&pkg_json) {
            flatten_pkg_script_fields_from_bytes(&bytes, &mut env);
        } else if let Some(m) = manifest {
            if let Some(config_val) = m.extra.get("config") {
                flatten_pkg_script_env("npm_package_config", config_val, &mut env);
            }
            for (k, v) in &m.engines {
                env.insert(format!("npm_package_engines_{k}"), v.clone());
            }
            match &m.bin {
                Some(rnpm_core::manifest::PackageBin::Single(s)) => {
                    env.insert("npm_package_bin".to_string(), s.clone());
                }
                Some(rnpm_core::manifest::PackageBin::Map(map)) => {
                    for (k, v) in map {
                        env.insert(format!("npm_package_bin_{k}"), v.clone());
                    }
                }
                None => {}
            }
        }

        // npm inserts every ancestor's .bin directory, even before it exists.
        let mut bins: Vec<PathBuf> = Vec::with_capacity(8);
        for dir in package_dir.ancestors() {
            bins.push(dir.join("node_modules").join(".bin"));
        }
        let gyp_in_bins = self.gyp_bin.as_ref().is_some_and(|g| bins.contains(g));
        let tail = if gyp_in_bins {
            &self.inherited_tail_no_gyp
        } else {
            self.inherited_tail_with_gyp
                .as_ref()
                .unwrap_or(&self.inherited_tail_no_gyp)
        };
        if let Ok(bins_joined) = std::env::join_paths(&bins) {
            let mut full = bins_joined.to_string_lossy().into_owned();
            if !tail.is_empty() {
                let sep = if cfg!(windows) { ';' } else { ':' };
                if !full.is_empty() {
                    full.push(sep);
                }
                full.push_str(&tail.to_string_lossy());
            }
            env.insert("PATH".into(), full);
        }

        if let Some(gyp) = node_gyp {
            env.insert(
                "npm_config_node_gyp".to_string(),
                gyp.to_string_lossy().into_owned(),
            );
        }
        if let Some(script) = extra_env.and_then(|e| e.get("npm_lifecycle_script")) {
            env.insert("npm_lifecycle_script".into(), script.clone());
        }
        env
    }

    #[allow(clippy::too_many_arguments)]
    fn build_package_env(
        &self,
        package_dir: &Path,
        package_name: &str,
        package_version: Option<&str>,
        event: &str,
        script_cmd: &str,
        extra_env: Option<&HashMap<String, String>>,
        node_gyp: Option<&Path>,
    ) -> HashMap<String, String> {
        self.build_package_env_with_manifest(
            package_dir,
            package_name,
            package_version,
            event,
            script_cmd,
            extra_env,
            node_gyp,
            None,
        )
    }
}

/// The process environment follows npm's current package-field contract.
pub fn build_script_env_with_config(
    ctx: &LifecycleContext,
    config: &rnpm_config::Config,
) -> HashMap<String, String> {
    if let Some(ref precomputed) = ctx.precomputed_env {
        let mut env = precomputed.clone();
        apply_context_overrides_to_precomputed_env(&mut env, ctx);
        return env;
    }

    let base = ScriptBaseEnv::build(
        &ctx.project_root,
        config,
        ctx.node_execpath.as_deref(),
        ctx.npm_execpath.as_deref(),
        Some(&ctx.extra_env),
    );
    let mut env = base.build_package_env(
        &ctx.package_dir,
        &ctx.package_name,
        ctx.package_version.as_deref(),
        &ctx.event,
        &ctx.script_cmd,
        None,
        ctx.node_gyp.as_deref(),
    );
    if let Some(script) = ctx.extra_env.get("npm_lifecycle_script") {
        env.insert("npm_lifecycle_script".into(), script.clone());
    }
    env
}

fn apply_context_overrides_to_precomputed_env(
    env: &mut HashMap<String, String>,
    ctx: &LifecycleContext,
) {
    let cmd = match ctx.event.as_str() {
        "preinstall" | "install" | "postinstall" => "install",
        "prepack" | "postpack" => "pack",
        "prepublish" | "publish" | "postpublish" | "prepublishOnly" => "publish",
        "test" | "pretest" | "posttest" => "test",
        "start" | "prestart" | "poststart" => "start",
        "restart" | "prerestart" | "postrestart" => "restart",
        "stop" | "prestop" | "poststop" => "stop",
        _ => "run",
    };
    env.insert("npm_command".to_string(), cmd.to_string());
    env.insert("npm_lifecycle_event".to_string(), ctx.event.clone());
    let has_precomputed_script = env
        .get("npm_lifecycle_script")
        .is_some_and(|s| !s.is_empty());
    if !has_precomputed_script {
        env.insert("npm_lifecycle_script".to_string(), ctx.script_cmd.clone());
    }
    for (k, v) in &ctx.extra_env {
        if !k.eq_ignore_ascii_case("path") && !is_sensitive_credential_key(k) {
            env.insert(k.clone(), v.clone());
        }
    }
    if let Some(ref gyp) = ctx.node_gyp {
        env.insert(
            "npm_config_node_gyp".to_string(),
            gyp.to_string_lossy().to_string(),
        );
    }
    if let Some(script) = ctx.extra_env.get("npm_lifecycle_script") {
        env.insert("npm_lifecycle_script".into(), script.clone());
    }
}

/// Precompute the shared environment for a package's lifecycle scripts (PATH,
/// npm_package_*, and npm_config_*), avoiding re-walking ancestor directories and
/// re-reading package.json across pre*, main, and post* hooks.
pub fn precompute_lifecycle_env(
    package_dir: &Path,
    project_root: &Path,
    package_name: &str,
    package_version: Option<&str>,
    config: &rnpm_config::Config,
    base_extra_env: Option<&HashMap<String, String>>,
) -> HashMap<String, String> {
    precompute_lifecycle_env_with_manifest(
        package_dir,
        project_root,
        package_name,
        package_version,
        config,
        base_extra_env,
        None,
    )
}

/// Same as [`precompute_lifecycle_env`], reusing an already-parsed `Manifest`
/// when available to avoid re-reading `package.json` from disk.
#[allow(clippy::too_many_arguments)]
pub fn precompute_lifecycle_env_with_manifest(
    package_dir: &Path,
    project_root: &Path,
    package_name: &str,
    package_version: Option<&str>,
    config: &rnpm_config::Config,
    base_extra_env: Option<&HashMap<String, String>>,
    manifest: Option<&rnpm_core::Manifest>,
) -> HashMap<String, String> {
    let base = ScriptBaseEnv::build(project_root, config, None, None, None);
    base.build_package_env_with_manifest(
        package_dir,
        package_name,
        package_version,
        "run",
        "",
        base_extra_env,
        None,
        manifest,
    )
}

/// Spawns and executes a lifecycle script synchronously within the specified context,
/// enforcing process-tree containment so child and grandchild processes terminate on exit.
/// The process environment follows npm's current package-field contract. Keep
/// build_lifecycle_env's full manifest expansion available to existing callers.
fn build_process_env(ctx: &LifecycleContext) -> HashMap<String, String> {
    if let Some(ref cfg) = ctx.config {
        build_script_env_with_config(ctx, cfg)
    } else {
        let loaded = rnpm_config::Config::load(Some(&ctx.package_dir))
            .or_else(|_| rnpm_config::Config::load(Some(&ctx.project_root)))
            .unwrap_or_default();
        build_script_env_with_config(ctx, &loaded)
    }
}

pub fn is_cmd_shell(shell: &str) -> bool {
    let trimmed = shell.trim().trim_matches('"');
    let name = trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed);
    name.eq_ignore_ascii_case("cmd") || name.eq_ignore_ascii_case("cmd.exe")
}

fn configured_script_shell(ctx: &LifecycleContext) -> Option<&str> {
    ctx.script_shell.as_deref().or_else(|| {
        ctx.extra_env
            .get("npm_config_script_shell")
            .filter(|s| {
                let trimmed = s.trim().trim_matches('"');
                !trimmed.is_empty() && trimmed != "null" && *s != "null"
            })
            .map(|s| s.as_str())
    })
}

#[cfg(any(windows, test))]
fn is_shell_builtin(prog: &str) -> bool {
    #[cfg(windows)]
    let eq = |kw: &str| prog.eq_ignore_ascii_case(kw);
    #[cfg(not(windows))]
    let eq = |kw: &str| prog == kw;

    [
        "echo", "set", "exit", "if", "for", "call", "cd", "chdir", "copy", "del", "erase", "dir",
        "md", "mkdir", "rd", "rmdir", "ren", "rename", "type", "rem", "ver", "vol", "pushd",
        "popd", "start", "assoc", "ftype", "mklink", "cls", "color", "date", "time", "title",
        "prompt", "path", "pause", "break", "verify", "goto", "shift", "setlocal", "endlocal",
        "true", "false", ":", ".", "[", "[[", "export", "unset", "eval", "exec", "source",
        "alias", "unalias", "trap", "umask", "wait", "read", "test", "command", "builtin",
        "declare", "local", "readonly", "return", "times", "ulimit", "which",
    ]
    .into_iter()
    .any(eq)
}

/// Conservatively splits a simple command line into argv tokens when guaranteed
/// free of shell metacharacters, redirections, pipelines, globs, or variable
/// expansions on both cmd.exe and /bin/sh.
#[cfg(any(windows, test))]
fn try_split_simple_args(cmd: &str) -> Option<Vec<String>> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_arg = false;
    let mut in_quotes = false;
    let mut just_closed_quote = false;

    for ch in trimmed.chars() {
        if in_quotes {
            match ch {
                '"' => {
                    in_quotes = false;
                    just_closed_quote = true;
                }
                '%' | '!' | '$' | '`' | '\\' | '\n' | '\r' | '\0' => return None,
                c => current.push(c),
            }
            continue;
        }
        match ch {
            ' ' | '\t' => {
                just_closed_quote = false;
                if in_arg {
                    args.push(std::mem::take(&mut current));
                    in_arg = false;
                }
            }
            '"' => {
                // Reject adjacent `""` (MSVCRT treats `""` inside quotes as a literal quote)
                // and `\"` on Windows (MSVCRT treats `\"` as an escaped literal quote).
                if just_closed_quote || (cfg!(windows) && current.ends_with('\\')) {
                    return None;
                }
                in_quotes = true;
                in_arg = true;
            }
            '&' | '|' | ';' | '<' | '>' | '(' | ')' | '^' | '%' | '!' | '$' | '`' | '*' | '?'
            | '[' | ']' | '~' | '{' | '}' | '#' | '\'' | '\n' | '\r' | '\0' => return None,
            '\\' => {
                if cfg!(not(windows)) {
                    return None;
                }
                just_closed_quote = false;
                in_arg = true;
                current.push(ch);
            }
            c => {
                just_closed_quote = false;
                in_arg = true;
                current.push(c);
            }
        }
    }
    if in_quotes {
        return None;
    }
    if in_arg {
        args.push(current);
    }
    if args.is_empty() || args[0].is_empty() {
        return None;
    }
    if cfg!(not(windows)) && args[0].contains('=') {
        return None;
    }
    if is_shell_builtin(&args[0]) {
        return None;
    }
    Some(args)
}

#[cfg(windows)]
fn find_env_case_insensitive<'a>(env: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    env.get(key).map(String::as_str).or_else(|| {
        env.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    })
}

#[cfg(windows)]
fn resolve_executable_in_env(
    prog: &str,
    package_dir: &Path,
    env: &HashMap<String, String>,
) -> Option<PathBuf> {
    let pathext_str = find_env_case_insensitive(env, "PATHEXT").unwrap_or(".COM;.EXE;.BAT;.CMD");
    let exts: Vec<&str> = pathext_str
        .split(';')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .collect();
    let has_known_ext = Path::new(prog)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| {
            exts.iter()
                .any(|pe| pe.trim_start_matches('.').eq_ignore_ascii_case(e))
        });

    let probe_dir = |dir: &Path, stem: &str| -> Option<PathBuf> {
        if has_known_ext {
            let p = dir.join(stem);
            if p.is_file() {
                return Some(p);
            }
        }
        for ext in &exts {
            let candidate = dir.join(format!("{stem}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    };

    let base_dir: std::borrow::Cow<'_, Path> = if package_dir.is_absolute() {
        std::borrow::Cow::Borrowed(package_dir)
    } else {
        std::borrow::Cow::Owned(std::env::current_dir().ok()?.join(package_dir))
    };

    if prog.contains('/') || prog.contains('\\') {
        let norm = prog.replace('/', "\\");
        let p = Path::new(&norm);
        let full = if p.is_absolute() {
            p.to_path_buf()
        } else {
            base_dir.join(p)
        };
        if has_known_ext {
            return full.is_file().then_some(full);
        }
        for ext in &exts {
            let candidate = PathBuf::from(format!("{}{ext}", full.to_string_lossy()));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        return None;
    }

    let is_node_lookup = prog.eq_ignore_ascii_case("node") || prog.eq_ignore_ascii_case("node.exe");
    let cached_node = is_node_lookup.then(node_executable).flatten();

    if let Some(ref node_path) = cached_node {
        if node_path.parent().is_some_and(|p| p == base_dir.as_ref()) {
            return Some(node_path.clone());
        }
    }
    if let Some(found) = probe_dir(&base_dir, prog) {
        return Some(found);
    }
    let path_str = find_env_case_insensitive(env, "PATH")?;
    for dir in std::env::split_paths(path_str) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let search_dir = if dir.is_absolute() {
            dir
        } else {
            base_dir.join(dir)
        };
        if let Some(ref node_path) = cached_node {
            if let Some(node_parent) = node_path.parent() {
                if search_dir
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&node_parent.to_string_lossy())
                    && !search_dir.join("node.cmd").is_file()
                    && !search_dir.join("node.bat").is_file()
                    && !search_dir.join("node.com").is_file()
                {
                    return Some(node_path.clone());
                }
            }
            // Avoid probing unrelated PATH directories when searching specifically for node.exe
            // before reaching the directory where node.exe lives unless .exe/.cmd/.bat could exist.
            if prog.eq_ignore_ascii_case("node.exe") {
                if search_dir.join("node.exe").is_file() {
                    return Some(search_dir.join("node.exe"));
                }
                continue;
            }
        }
        if let Some(found) = probe_dir(&search_dir, prog) {
            return Some(found);
        }
    }
    None
}

#[cfg(windows)]
fn try_unwrap_node_cmd_shim(
    cmd_path: &Path,
    rest: &[String],
    package_dir: &Path,
    env: &HashMap<String, String>,
) -> Option<Command> {
    let meta = std::fs::metadata(cmd_path).ok()?;
    if meta.len() > 4096 {
        return None;
    }
    let content = std::fs::read_to_string(cmd_path).ok()?;
    let mut lines = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty());

    // Strictly match the entire canonical npm/rnpm cmd-shim template so custom
    // `.cmd` wrappers (e.g. `SET FOO=bar` or extra commands) always use cmd.exe.
    if !lines.next()?.eq_ignore_ascii_case("@ECHO off")
        || !lines.next()?.eq_ignore_ascii_case("GOTO start")
        || !lines.next()?.eq_ignore_ascii_case(":find_dp0")
        || !lines
            .next()
            .is_some_and(|l| l.eq_ignore_ascii_case("SET dp0=%~dp0") || l.eq_ignore_ascii_case("SET \"dp0=%~dp0\""))
        || !lines.next()?.eq_ignore_ascii_case("EXIT /b")
        || !lines.next()?.eq_ignore_ascii_case(":start")
        || !lines.next()?.eq_ignore_ascii_case("SETLOCAL")
        || !lines.next()?.eq_ignore_ascii_case("CALL :find_dp0")
        || !lines.next()?.eq_ignore_ascii_case("IF EXIST \"%dp0%\\node.exe\" (")
        || !lines.next()?.eq_ignore_ascii_case("SET \"_prog=%dp0%\\node.exe\"")
        || !lines.next()?.eq_ignore_ascii_case(") ELSE (")
        || !lines.next()?.eq_ignore_ascii_case("SET \"_prog=node\"")
    {
        return None;
    }

    let maybe_pathext = lines.next()?;
    let invoke_line = if maybe_pathext.eq_ignore_ascii_case("SET PATHEXT=%PATHEXT:;.JS;=;%") {
        if lines.next() != Some(")") {
            return None;
        }
        lines.next()?
    } else if maybe_pathext == ")" {
        lines.next()?
    } else {
        return None;
    };
    if lines.next().is_some() {
        return None;
    }

    let bin_dir = cmd_path.parent()?;
    let tail = invoke_line
        .strip_prefix("endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\"")?;
    if !tail.starts_with([' ', '\t']) {
        return None;
    }
    let tail_before_args = tail.trim().strip_suffix("%*").map(str::trim)?;

    // Only unwrap canonical shims that invoke `"%dp0%\<rel_path>"` directly with no
    // extra interpreter arguments (preserving exact cmd.exe quoting for shebang flags).
    let raw_target = tail_before_args.strip_prefix('"')?.strip_suffix('"')?;
    if raw_target.contains('"') {
        return None;
    }
    let rel_after_dp0 = raw_target
        .strip_prefix("%dp0%\\")
        .or_else(|| raw_target.strip_prefix("%dp0%/"))?;
    if rel_after_dp0.contains('%') && !rel_after_dp0.contains("%%") {
        // Reject unescaped %VAR% expansions in target path, unescape %% -> %.
        return None;
    }
    let rel_clean = if rel_after_dp0.contains("%%") {
        // Ensure every single % was doubled %%
        let mut s = String::with_capacity(rel_after_dp0.len());
        let mut iter = rel_after_dp0.chars();
        while let Some(ch) = iter.next() {
            if ch == '%' {
                if iter.next() != Some('%') {
                    return None;
                }
                s.push('%');
            } else {
                s.push(ch);
            }
        }
        s
    } else {
        rel_after_dp0.to_string()
    };

    let target_script = bin_dir.join(&rel_clean);
    if !target_script.is_file() {
        return None;
    }

    let local_node = bin_dir.join("node.exe");
    let node_exe = if local_node.is_file() {
        local_node
    } else {
        let resolved = resolve_executable_in_env("node", package_dir, env)?;
        if !resolved
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
        {
            return None;
        }
        resolved
    };

    let mut cmd = Command::new(node_exe);
    cmd.arg(target_script);
    cmd.args(rest);
    Some(cmd)
}

#[cfg(windows)]
fn try_create_direct_command(ctx: &LifecycleContext, env: &HashMap<String, String>) -> Option<Command> {
    if configured_script_shell(ctx).is_some() {
        return None;
    }
    let argv = try_split_simple_args(&ctx.script_cmd)?;
    let (prog, rest) = argv.split_first()?;

    let resolved = resolve_executable_in_env(prog, &ctx.package_dir, env)?;
    let ext = resolved
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())?;
    if ext == "exe" {
        let mut cmd = Command::new(resolved);
        cmd.args(rest);
        Some(cmd)
    } else if ext == "cmd" {
        try_unwrap_node_cmd_shim(&resolved, rest, &ctx.package_dir, env)
    } else {
        None
    }
}

pub(crate) fn create_shell_command_with_env(
    ctx: &LifecycleContext,
    env: &HashMap<String, String>,
) -> Command {
    #[cfg(windows)]
    if !env.is_empty() {
        if let Some(direct) = try_create_direct_command(ctx, env) {
            return direct;
        }
    }
    #[cfg(not(windows))]
    let _ = env;
    create_shell_command(ctx)
}

pub(crate) fn create_shell_command(ctx: &LifecycleContext) -> Command {
    let configured_shell = configured_script_shell(ctx);

    let (shell, is_cmd) = match configured_shell {
        Some(s) => {
            let is_cmd = is_cmd_shell(s);
            (s, is_cmd)
        }
        None => {
            if cfg!(windows) {
                ("cmd.exe", true)
            } else {
                ("/bin/sh", false)
            }
        }
    };

    let mut cmd = Command::new(shell);
    if is_cmd {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.raw_arg(format!("/d /s /c {}", ctx.script_cmd));
        }
        #[cfg(not(windows))]
        {
            cmd.arg("/d").arg("/s").arg("/c").arg(&ctx.script_cmd);
        }
    } else {
        cmd.arg("-c").arg(&ctx.script_cmd);
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    cmd
}

fn load_config_for_context(ctx: &LifecycleContext) -> rnpm_config::Config {
    let mut config = if let Some(ref cfg) = ctx.config {
        cfg.clone()
    } else {
        rnpm_config::Config::load(Some(&ctx.package_dir))
            .or_else(|_| rnpm_config::Config::load(Some(&ctx.project_root)))
            .unwrap_or_default()
    };
    for (k, v) in &ctx.extra_env {
        if let Some(stripped) = k.strip_prefix("npm_config_") {
            config.npmrc.settings.insert(stripped.replace('_', "-"), v.clone());
        } else if let Some(stripped) = k.strip_prefix("NPM_CONFIG_") {
            config.npmrc.settings.insert(stripped.to_ascii_lowercase().replace('_', "-"), v.clone());
        }
    }
    config
}

pub fn execute_lifecycle_script(ctx: &LifecycleContext) -> Result<ExitStatus> {
    info!(
        "Running lifecycle script '{}' for package {} in {}",
        ctx.event,
        ctx.package_name,
        ctx.package_dir.display()
    );

    // Validate against sandbox policy
    ctx.sandbox_policy
        .check_execution_allowed(&ctx.package_name, &ctx.script_cmd)
        .map_err(|e| anyhow::anyhow!(e))?;

    let mut env = build_process_env(ctx);

    if ctx.script_cmd.contains("node-gyp") {
        let config = load_config_for_context(ctx);
        let gyp_path = ensure_node_gyp(
            &ctx.project_root,
            &ctx.package_dir,
            &config,
            ctx.node_gyp.as_deref(),
            ctx.offline,
            &ctx.package_name,
        )
        .map_err(|e| anyhow::anyhow!(e))?;
        env.insert(
            "npm_config_node_gyp".to_string(),
            gyp_path.to_string_lossy().to_string(),
        );
    }

    let mut cmd = create_shell_command_with_env(ctx, &env);

    cmd.current_dir(&ctx.package_dir);
    cmd.env_clear();
    cmd.envs(env);
    cmd.stdin(std::process::Stdio::inherit());

    if ctx.capture_output && !ctx.foreground_scripts {
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
    } else {
        cmd.stdout(std::process::Stdio::inherit());
        cmd.stderr(std::process::Stdio::inherit());
    }

    let guard =
        process_guard::ProcessTreeGuard::new_with_limits(ctx.sandbox_policy.max_active_processes);

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn lifecycle script for {}", ctx.package_name))?;

    #[cfg(windows)]
    if let Some(ref g) = guard {
        use std::os::windows::io::AsRawHandle;
        if !g.assign_process(child.as_raw_handle()) {
            warn!(
                "Failed to assign process to Windows Job Object for {}",
                ctx.package_name
            );
        }
    }
    #[cfg(not(windows))]
    if let Some(ref g) = guard {
        g.assign_process(child.id());
    }

    // Drain piped stdout and stderr concurrently using dedicated worker threads
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    let stdout_handle =
        child_stdout.map(|mut r| std::thread::spawn(move || drain_and_scrub_reader(&mut r)));

    let stderr_handle =
        child_stderr.map(|mut r| std::thread::spawn(move || drain_and_scrub_reader(&mut r)));

    let effective_timeout = ctx.timeout.or(ctx.sandbox_policy.max_execution_time);
    let status = if let Some(timeout) = effective_timeout {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            extern "system" {
                fn WaitForSingleObject(hHandle: *mut std::ffi::c_void, dwMilliseconds: u32) -> u32;
            }
            const WAIT_TIMEOUT: u32 = 0x0000_0102;
            let timeout_ms = timeout.as_millis().min((u32::MAX - 1) as u128) as u32;
            let wait_res = unsafe { WaitForSingleObject(child.as_raw_handle(), timeout_ms) };
            if wait_res == WAIT_TIMEOUT {
                warn!(
                    "Lifecycle script '{}' timed out after {:?}; terminating process tree for {}",
                    ctx.event, timeout, ctx.package_name
                );
                if let Some(ref g) = guard {
                    g.terminate(124);
                }
                let _ = child.kill();
                let _ = child.wait();
                if let Some(handle) = stdout_handle {
                    let _ = handle.join();
                }
                if let Some(handle) = stderr_handle {
                    let _ = handle.join();
                }
                return Err(anyhow::Error::from(ScriptExitError {
                    exit_code: 124,
                    message: format!(
                        "Lifecycle script '{}' timed out after {:?}",
                        ctx.event, timeout
                    ),
                }));
            }
            child.wait().with_context(|| {
                format!(
                    "Failed to wait for lifecycle script for {}",
                    ctx.package_name
                )
            })?
        }
        #[cfg(not(windows))]
        {
            let start = std::time::Instant::now();
            let mut poll_interval = std::time::Duration::from_millis(1);
            loop {
                match child.try_wait().with_context(|| {
                    format!("Failed to poll lifecycle script for {}", ctx.package_name)
                })? {
                    Some(status) => break status,
                    None => {
                        if start.elapsed() >= timeout {
                            warn!(
                                "Lifecycle script '{}' timed out after {:?}; terminating process tree for {}",
                                ctx.event, timeout, ctx.package_name
                            );
                            if let Some(ref g) = guard {
                                g.terminate(124);
                            }
                            let _ = child.kill();
                            let _ = child.wait();
                            if let Some(handle) = stdout_handle {
                                let _ = handle.join();
                            }
                            if let Some(handle) = stderr_handle {
                                let _ = handle.join();
                            }
                            return Err(anyhow::Error::from(ScriptExitError {
                                exit_code: 124,
                                message: format!(
                                    "Lifecycle script '{}' timed out after {:?}",
                                    ctx.event, timeout
                                ),
                            }));
                        }
                        let remaining = timeout.saturating_sub(start.elapsed());
                        std::thread::sleep(poll_interval.min(remaining));
                        poll_interval = (poll_interval * 2).min(std::time::Duration::from_millis(10));
                    }
                }
            }
        }
    } else {
        child.wait().with_context(|| {
            format!(
                "Failed to wait for lifecycle script for {}",
                ctx.package_name
            )
        })?
    };

    // Descendants may inherit the pipe handles after the shell exits. Reap the
    // process tree before waiting for EOF, just as the async executor does.
    if let Some(ref g) = guard {
        g.terminate(0);
    }

    let stdout_str = stdout_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let stderr_str = stderr_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();

    if ctx.capture_output {
        *ctx.captured_output.lock().unwrap() = Some(ScriptOutput {
            exit_code: status.code().unwrap_or(-1),
            stdout: stdout_str,
            stderr: stderr_str,
        });
    }

    if !status.success() {
        warn!(
            "Lifecycle script '{}' failed for {} with exit code: {:?}",
            ctx.event,
            ctx.package_name,
            status.code()
        );
    }

    // Explicitly guarantee cleanup of any remaining grandchild processes on exit
    if let Some(ref g) = guard {
        g.terminate(0);
    }

    Ok(status)
}

// Termination requests are asynchronous on Windows. Do not detach process waits
// or pipe readers after an arbitrary 500ms; let the actual completion wake us.
async fn await_terminated_task<T>(task: &mut tokio::task::JoinHandle<T>) {
    match tokio::time::timeout(std::time::Duration::from_secs(60), task).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => warn!("Terminated process cleanup task failed: {error}"),
        Err(_) => warn!("Terminated process cleanup did not complete within 60 seconds"),
    }
}

/// Spawns and executes a lifecycle script asynchronously, enforcing process-tree signal cleanup.
/// If an abort future resolves, or if cancelled by SIGINT/SIGTERM, or if the future is dropped,
/// runaway child and grandchild processes are cleanly terminated immediately.
pub async fn execute_lifecycle_script_with_abort<F>(
    ctx: &LifecycleContext,
    abort_fut: F,
) -> Result<ExitStatus>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    info!(
        "Running async lifecycle script '{}' for package {} in {}",
        ctx.event,
        ctx.package_name,
        ctx.package_dir.display()
    );

    // Validate against sandbox policy
    ctx.sandbox_policy
        .check_execution_allowed(&ctx.package_name, &ctx.script_cmd)
        .map_err(|e| anyhow::anyhow!(e))?;

    let mut env = build_process_env(ctx);

    if ctx.script_cmd.contains("node-gyp") {
        let config = load_config_for_context(ctx);
        let gyp_path = ensure_node_gyp(
            &ctx.project_root,
            &ctx.package_dir,
            &config,
            ctx.node_gyp.as_deref(),
            ctx.offline,
            &ctx.package_name,
        )
        .map_err(|e| anyhow::anyhow!(e))?;
        env.insert(
            "npm_config_node_gyp".to_string(),
            gyp_path.to_string_lossy().to_string(),
        );
    }

    let mut cmd = create_shell_command_with_env(ctx, &env);

    cmd.current_dir(&ctx.package_dir);
    cmd.env_clear();
    cmd.envs(env);
    cmd.stdin(std::process::Stdio::inherit());

    if ctx.capture_output && !ctx.foreground_scripts {
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
    } else {
        cmd.stdout(std::process::Stdio::inherit());
        cmd.stderr(std::process::Stdio::inherit());
    }

    let guard = std::sync::Arc::new(process_guard::ProcessTreeGuard::new_with_limits(
        ctx.sandbox_policy.max_active_processes,
    ));

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn lifecycle script for {}", ctx.package_name))?;

    #[cfg(windows)]
    if let Some(ref g) = *guard {
        use std::os::windows::io::AsRawHandle;
        if !g.assign_process(child.as_raw_handle()) {
            warn!(
                "Failed to assign process to Windows Job Object for {}",
                ctx.package_name
            );
        }
    }
    #[cfg(not(windows))]
    if let Some(ref g) = *guard {
        g.assign_process(child.id());
    }

    // Drain piped stdout and stderr concurrently using tokio worker tasks
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    let mut stdout_task = child_stdout.map(|mut r| {
        tokio::task::spawn_blocking(move || drain_and_scrub_reader(&mut r))
    });

    let mut stderr_task = child_stderr.map(|mut r| {
        tokio::task::spawn_blocking(move || drain_and_scrub_reader(&mut r))
    });

    let pkg_name = ctx.package_name.clone();
    let guard_clone = guard.clone();

    // Cancellation guard to ensure immediate termination if future is dropped/aborted
    struct CancellationGuard {
        guard: std::sync::Arc<Option<process_guard::ProcessTreeGuard>>,
        completed: bool,
    }
    impl Drop for CancellationGuard {
        fn drop(&mut self) {
            if !self.completed {
                if let Some(ref g) = *self.guard {
                    g.terminate(1);
                }
            }
        }
    }

    let mut cancel_guard = CancellationGuard {
        guard: guard.clone(),
        completed: false,
    };

    let mut wait_handle = tokio::task::spawn_blocking(move || {
        let res = child.wait();
        (child, res)
    });

    let timeout_fut = async {
        let effective_timeout = ctx.timeout.or(ctx.sandbox_policy.max_execution_time);
        if let Some(timeout) = effective_timeout {
            tokio::time::sleep(timeout).await;
            true
        } else {
            std::future::pending::<bool>().await
        }
    };

    let signal_fut = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).ok();
            tokio::select! {
                _ = tokio::signal::ctrl_c() => "SIGINT",
                _ = async {
                    if let Some(ref mut s) = sigterm {
                        s.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => "SIGTERM",
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            "SIGINT"
        }
    };

    let status_res = tokio::select! {
        res = &mut wait_handle => {
            cancel_guard.completed = true;
            let (_child, wait_res) = res
                .map_err(|e| anyhow::anyhow!("Lifecycle execution task for {pkg_name} interrupted: {e}"))?;
            wait_res
        }
        _ = timeout_fut => {
            warn!("Lifecycle script '{}' timed out after {:?}; terminating process tree for {pkg_name}", ctx.event, ctx.timeout.unwrap_or_default());
            if let Some(ref g) = *guard_clone {
                g.terminate(124);
            }
            cancel_guard.completed = true;
            await_terminated_task(&mut wait_handle).await;
            if let Some(ref mut t) = stdout_task {
                await_terminated_task(t).await;
            }
            if let Some(ref mut t) = stderr_task {
                await_terminated_task(t).await;
            }
            return Err(anyhow::Error::from(ScriptExitError {
                exit_code: 124,
                message: format!("Lifecycle script '{}' timed out after {:?}", ctx.event, ctx.timeout.unwrap_or_default()),
            }));
        }
        sig = signal_fut => {
            warn!("Received {sig}; terminating lifecycle process tree for {pkg_name}");
            let exit_code = if sig == "SIGINT" { 130 } else { 143 };
            if let Some(ref g) = *guard_clone {
                g.terminate(exit_code);
            }
            cancel_guard.completed = true;
            await_terminated_task(&mut wait_handle).await;
            if let Some(ref mut t) = stdout_task {
                await_terminated_task(t).await;
            }
            if let Some(ref mut t) = stderr_task {
                await_terminated_task(t).await;
            }
            return Err(anyhow::Error::from(ScriptExitError {
                exit_code: exit_code as i32,
                message: format!("Lifecycle execution for {pkg_name} terminated by {sig}"),
            }));
        }
        _ = abort_fut => {
            warn!("Abort signal triggered; terminating lifecycle process tree for {pkg_name}");
            if let Some(ref g) = *guard_clone {
                g.terminate(143);
            }
            cancel_guard.completed = true;
            await_terminated_task(&mut wait_handle).await;
            if let Some(ref mut t) = stdout_task {
                await_terminated_task(t).await;
            }
            if let Some(ref mut t) = stderr_task {
                await_terminated_task(t).await;
            }
            return Err(anyhow::Error::from(ScriptExitError {
                exit_code: 143,
                message: format!("Lifecycle execution for {pkg_name} aborted by signal"),
            }));
        }
    };

    // Guarantee cleanup of any remaining grandchild processes on exit
    if let Some(ref g) = *guard {
        g.terminate(0);
    }

    let status = status_res.with_context(|| {
        format!(
            "Failed to wait for lifecycle script for {}",
            ctx.package_name
        )
    })?;

    let stdout_str = match stdout_task {
        Some(t) => t.await.unwrap_or_default(),
        None => String::new(),
    };
    let stderr_str = match stderr_task {
        Some(t) => t.await.unwrap_or_default(),
        None => String::new(),
    };

    if ctx.capture_output {
        *ctx.captured_output.lock().unwrap() = Some(ScriptOutput {
            exit_code: status.code().unwrap_or(-1),
            stdout: stdout_str,
            stderr: stderr_str,
        });
    }

    if !status.success() {
        warn!(
            "Lifecycle script '{}' failed for {} with exit code: {:?}",
            ctx.event,
            ctx.package_name,
            status.code()
        );
    }

    Ok(status)
}

/// Spawns and executes a lifecycle script asynchronously, enforcing process-tree signal cleanup.
/// If cancelled or aborted by SIGINT/SIGTERM, runaway child processes are cleanly terminated immediately.
pub async fn execute_lifecycle_script_async(ctx: &LifecycleContext) -> Result<ExitStatus> {
    execute_lifecycle_script_with_abort(ctx, std::future::pending()).await
}

/// Spawns and executes a lifecycle script synchronously, capturing stdout and stderr cleanly.
pub fn execute_lifecycle_script_captured(ctx: &LifecycleContext) -> Result<ScriptOutput> {
    let mut ctx_clone = ctx.clone();
    ctx_clone.capture_output = true;
    let status = execute_lifecycle_script(&ctx_clone)?;
    let out = ctx_clone
        .get_captured_output()
        .unwrap_or_else(|| ScriptOutput {
            exit_code: status.code().unwrap_or(-1),
            stdout: String::new(),
            stderr: String::new(),
        });
    Ok(out)
}

/// Spawns and executes a lifecycle script asynchronously, capturing stdout and stderr cleanly.
pub async fn execute_lifecycle_script_async_captured(
    ctx: &LifecycleContext,
) -> Result<ScriptOutput> {
    let mut ctx_clone = ctx.clone();
    ctx_clone.capture_output = true;
    let status = execute_lifecycle_script_async(&ctx_clone).await?;
    let out = ctx_clone
        .get_captured_output()
        .unwrap_or_else(|| ScriptOutput {
            exit_code: status.code().unwrap_or(-1),
            stdout: String::new(),
            stderr: String::new(),
        });
    Ok(out)
}

/// Spawns and executes a lifecycle script asynchronously with abort, capturing stdout and stderr cleanly.
pub async fn execute_lifecycle_script_with_abort_captured<F>(
    ctx: &LifecycleContext,
    abort_fut: F,
) -> Result<ScriptOutput>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let mut ctx_clone = ctx.clone();
    ctx_clone.capture_output = true;
    let status = execute_lifecycle_script_with_abort(&ctx_clone, abort_fut).await?;
    let out = ctx_clone
        .get_captured_output()
        .unwrap_or_else(|| ScriptOutput {
            exit_code: status.code().unwrap_or(-1),
            stdout: String::new(),
            stderr: String::new(),
        });
    Ok(out)
}

/// Detailed error holding the exact non-zero exit code of a process or script execution.
#[derive(Debug, Clone)]
pub struct ScriptExitError {
    pub exit_code: i32,
    pub message: String,
}

impl ScriptExitError {
    pub fn lifecycle_failure(ctx: &LifecycleContext, status: &ExitStatus) -> Self {
        let code = extract_exit_status_code(status);
        let shell = if cfg!(windows) {
            format!(
                "{} /d /s /c",
                std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".into())
            )
        } else {
            "sh -c".into()
        };
        Self {
            exit_code: code,
            message: format!("npm error code {code}\nnpm error path {}\nnpm error command failed\nnpm error command {shell} {}", ctx.package_dir.display(), ctx.script_cmd),
        }
    }
}

impl std::fmt::Display for ScriptExitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ScriptExitError {}

/// Extracts the exact exit code from ExitStatus across Windows and Unix platforms,
/// handling signal terminations on Unix (128 + signal) and non-zero exit codes.
pub fn extract_exit_status_code(status: &ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(code) = status.code() {
            code
        } else if let Some(sig) = status.signal() {
            128 + sig
        } else {
            1
        }
    }
    #[cfg(not(unix))]
    {
        status.code().unwrap_or(1)
    }
}

/// Extracts the exit code from an anyhow::Error if it originated from a ScriptExitError,
/// defaulting to 1 otherwise.
pub fn extract_error_exit_code(err: &anyhow::Error) -> i32 {
    if let Some(script_err) = err.downcast_ref::<ScriptExitError>() {
        script_err.exit_code
    } else {
        1
    }
}

/// Simple, zero-dependency wildcard matching supporting `*` and `?`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p_bytes = pattern.as_bytes();
    let t_bytes = text.as_bytes();
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    while t_idx < t_bytes.len() {
        if p_idx < p_bytes.len() && (p_bytes[p_idx] == b'?' || p_bytes[p_idx] == t_bytes[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
            star_idx = Some(p_idx);
            p_idx += 1;
            match_idx = t_idx;
        } else if let Some(star) = star_idx {
            p_idx = star + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    while p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
        p_idx += 1;
    }

    p_idx == p_bytes.len()
}

/// Matches a workspace member name or path against a filter pattern.
/// Supports exact names ("foo"), scopes ("@scope" or "@scope/*"), wildcards ("ui-*", "*-app"),
/// and relative filesystem paths ("packages/foo" or "./packages/foo").
pub fn matches_filter(
    filter: &str,
    member_name: &str,
    member_path: &Path,
    root_dir: &Path,
) -> bool {
    let filter = filter.trim();
    if filter.is_empty() {
        return false;
    }

    // 1. Exact package name match
    if filter == member_name {
        return true;
    }

    // 2. Scope prefix match: e.g. "@scope" or "@scope/*"
    if filter.starts_with('@') {
        if let Some(scope_name) = filter.strip_suffix("/*") {
            if member_name.starts_with(scope_name)
                && member_name[scope_name.len()..].starts_with('/')
            {
                return true;
            }
        } else if !filter.contains('/')
            && member_name.starts_with(filter)
            && member_name[filter.len()..].starts_with('/')
        {
            return true;
        }
    }

    // 3. Glob wildcard matching
    if (filter.contains('*') || filter.contains('?')) && glob_match(filter, member_name) {
        return true;
    }

    // 4. Path matching relative to root_dir
    let norm_filter = filter
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string();
    if let Ok(rel) = member_path.strip_prefix(root_dir) {
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if rel_str == norm_filter
            || glob_match(&norm_filter, &rel_str)
            || rel_str.starts_with(&format!("{}/", norm_filter.trim_end_matches('/')))
        {
            return true;
        }
    }

    false
}

/// Traverses ancestor directories starting from `start_dir` searching for `bin_name` in `node_modules/.bin/`.
pub fn find_local_binary(start_dir: &Path, bin_name: &str) -> Option<PathBuf> {
    let mut current = Some(start_dir);

    let clean_name = bin_name
        .trim_end_matches(".cmd")
        .trim_end_matches(".exe")
        .trim_end_matches(".ps1")
        .trim_end_matches(".bat");

    let unscoped_name = if clean_name.contains('/') {
        clean_name.rsplit('/').next().unwrap_or(clean_name)
    } else {
        clean_name
    };

    while let Some(dir) = current {
        let bin_dir = dir.join("node_modules").join(".bin");
        if bin_dir.is_dir() {
            #[cfg(windows)]
            {
                let names = if unscoped_name != clean_name {
                    vec![clean_name, unscoped_name]
                } else {
                    vec![clean_name]
                };

                for n in names {
                    let candidates = [
                        bin_dir.join(format!("{n}.cmd")),
                        bin_dir.join(format!("{n}.exe")),
                        bin_dir.join(format!("{n}.bat")),
                        bin_dir.join(format!("{n}.ps1")),
                        bin_dir.join(n),
                    ];
                    for candidate in candidates {
                        if candidate.exists() {
                            return Some(candidate);
                        }
                    }
                }
            }

            #[cfg(not(windows))]
            {
                let candidate1 = bin_dir.join(clean_name);
                if candidate1.exists() {
                    return Some(candidate1);
                }
                if unscoped_name != clean_name {
                    let candidate2 = bin_dir.join(unscoped_name);
                    if candidate2.exists() {
                        return Some(candidate2);
                    }
                }
            }
        }
        current = dir.parent();
    }

    None
}

/// Collects all `node_modules/.bin` directories from `start_dir` and all its ancestors.
pub fn collect_ancestor_bin_dirs(start_dir: &Path) -> Vec<PathBuf> {
    let mut entries = Vec::new();
    let mut current = Some(start_dir);
    while let Some(dir) = current {
        let bin_dir = dir.join("node_modules").join(".bin");
        if bin_dir.is_dir() && !entries.contains(&bin_dir) {
            entries.push(bin_dir);
        }
        current = dir.parent();
    }
    entries
}

#[cfg(windows)]
fn build_binary_command_windows(
    binary_path: &Path,
    args: &[String],
    current_dir: &Path,
    env: &HashMap<String, String>,
) -> Command {
    use std::io::Read;
    let ext = binary_path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if ext.eq_ignore_ascii_case("cmd") || ext.eq_ignore_ascii_case("bat") {
        if ext.eq_ignore_ascii_case("cmd") {
            if let Some(cmd) = try_unwrap_node_cmd_shim(binary_path, args, current_dir, env) {
                return cmd;
            }
        }
        let mut c = Command::new("cmd.exe");
        c.arg("/c").arg(binary_path);
        c.args(args);
        return c;
    }
    if ext.eq_ignore_ascii_case("ps1") {
        let mut c = Command::new("powershell.exe");
        c.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]);
        c.arg(binary_path);
        c.args(args);
        return c;
    }
    let is_js = ext.eq_ignore_ascii_case("js")
        || ext.eq_ignore_ascii_case("cjs")
        || ext.eq_ignore_ascii_case("mjs");
    let has_shebang = if !is_js
        && !ext.eq_ignore_ascii_case("exe")
        && !ext.eq_ignore_ascii_case("com")
    {
        if let Ok(mut f) = std::fs::File::open(binary_path) {
            let mut prefix = [0u8; 5];
            let n = f.read(&mut prefix).unwrap_or(0);
            let head = &prefix[..n];
            head.starts_with(b"#!") || head.starts_with(b"\xEF\xBB\xBF#!")
        } else {
            false
        }
    } else {
        false
    };

    if is_js || has_shebang {
        let mut c = Command::new("node");
        c.arg(binary_path);
        c.args(args);
        c
    } else {
        let mut c = Command::new(binary_path);
        c.args(args);
        c
    }
}

/// Spawns and executes a standalone binary or command with full TTY stdin/stdout forwarding,
/// process tree guard containment (Windows Job Object or Unix process group),
/// signal propagation, and non-zero exit code fidelity.
pub fn execute_binary(
    binary_path: &Path,
    args: &[String],
    current_dir: &Path,
    path_entries: &[PathBuf],
    extra_env: &HashMap<String, String>,
) -> Result<ExitStatus> {
    info!(
        "Executing binary {} in {}",
        binary_path.display(),
        current_dir.display()
    );

    let mut env: HashMap<String, String> = HashMap::new();
    for (k, v) in std::env::vars() {
        if !is_sensitive_credential_key(&k) {
            env.insert(k, v);
        }
    }
    for (k, v) in extra_env {
        if !is_sensitive_credential_key(k) {
            env.insert(k.clone(), v.clone());
        }
    }

    let existing_path = std::env::var("PATH")
        .or_else(|_| std::env::var("Path"))
        .unwrap_or_default();
    let joined_custom = std::env::join_paths(path_entries)
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let final_path = if joined_custom.is_empty() {
        existing_path
    } else if existing_path.is_empty() {
        joined_custom
    } else {
        format!(
            "{joined_custom}{}{existing_path}",
            if cfg!(windows) { ";" } else { ":" }
        )
    };
    env.remove("Path");
    env.remove("path");
    env.insert("PATH".to_string(), final_path.clone());
    #[cfg(windows)]
    env.insert("Path".to_string(), final_path);

    env.insert(
        "INIT_CWD".to_string(),
        extra_env
            .get("INIT_CWD")
            .cloned()
            .unwrap_or_else(|| current_dir.to_string_lossy().to_string()),
    );

    #[cfg(windows)]
    let mut cmd = build_binary_command_windows(binary_path, args, current_dir, &env);

    #[cfg(not(windows))]
    let mut cmd = {
        use std::os::unix::process::CommandExt;
        let mut c = Command::new(binary_path);
        c.args(args);
        c.process_group(0);
        c
    };

    cmd.current_dir(current_dir);
    cmd.env_clear();
    cmd.envs(env);

    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let guard = process_guard::ProcessTreeGuard::new();

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn binary '{}'", binary_path.display()))?;

    #[cfg(windows)]
    if let Some(ref g) = guard {
        use std::os::windows::io::AsRawHandle;
        if !g.assign_process(child.as_raw_handle()) {
            warn!(
                "Failed to assign process to Windows Job Object for {}",
                binary_path.display()
            );
        }
    }
    #[cfg(not(windows))]
    if let Some(ref g) = guard {
        g.assign_process(child.id());
    }

    let status = child
        .wait()
        .with_context(|| format!("Failed to wait for binary '{}'", binary_path.display()))?;

    if let Some(ref g) = guard {
        let code = status.code().unwrap_or(0) as u32;
        g.terminate(code);
    }

    Ok(status)
}

/// Executes a binary asynchronously with process tree signal cleanup and optional abort future.
pub async fn execute_binary_with_abort<F>(
    binary_path: &Path,
    args: &[String],
    current_dir: &Path,
    path_entries: &[PathBuf],
    extra_env: &HashMap<String, String>,
    abort_fut: F,
) -> Result<ExitStatus>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    info!(
        "Executing async binary {} in {}",
        binary_path.display(),
        current_dir.display()
    );

    let mut env: HashMap<String, String> = HashMap::new();
    for (k, v) in std::env::vars() {
        if !is_sensitive_credential_key(&k) {
            env.insert(k, v);
        }
    }
    for (k, v) in extra_env {
        if !is_sensitive_credential_key(k) {
            env.insert(k.clone(), v.clone());
        }
    }

    let existing_path = std::env::var("PATH")
        .or_else(|_| std::env::var("Path"))
        .unwrap_or_default();
    let joined_custom = std::env::join_paths(path_entries)
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let final_path = if joined_custom.is_empty() {
        existing_path
    } else if existing_path.is_empty() {
        joined_custom
    } else {
        format!(
            "{joined_custom}{}{existing_path}",
            if cfg!(windows) { ";" } else { ":" }
        )
    };
    env.remove("Path");
    env.remove("path");
    env.insert("PATH".to_string(), final_path.clone());
    #[cfg(windows)]
    env.insert("Path".to_string(), final_path);

    env.insert(
        "INIT_CWD".to_string(),
        extra_env
            .get("INIT_CWD")
            .cloned()
            .unwrap_or_else(|| current_dir.to_string_lossy().to_string()),
    );

    #[cfg(windows)]
    let mut cmd = build_binary_command_windows(binary_path, args, current_dir, &env);

    #[cfg(not(windows))]
    let mut cmd = {
        use std::os::unix::process::CommandExt;
        let mut c = Command::new(binary_path);
        c.args(args);
        c.process_group(0);
        c
    };

    cmd.current_dir(current_dir);
    cmd.env_clear();
    cmd.envs(env);

    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let guard = std::sync::Arc::new(process_guard::ProcessTreeGuard::new());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn binary '{}'", binary_path.display()))?;

    #[cfg(windows)]
    if let Some(ref g) = *guard {
        use std::os::windows::io::AsRawHandle;
        if !g.assign_process(child.as_raw_handle()) {
            warn!(
                "Failed to assign process to Windows Job Object for {}",
                binary_path.display()
            );
        }
    }
    #[cfg(not(windows))]
    if let Some(ref g) = *guard {
        g.assign_process(child.id());
    }

    let bin_display = binary_path.display().to_string();
    let guard_clone = guard.clone();

    struct CancellationGuard {
        guard: std::sync::Arc<Option<process_guard::ProcessTreeGuard>>,
        completed: bool,
    }
    impl Drop for CancellationGuard {
        fn drop(&mut self) {
            if !self.completed {
                if let Some(ref g) = *self.guard {
                    g.terminate(1);
                }
            }
        }
    }

    let mut cancel_guard = CancellationGuard {
        guard: guard.clone(),
        completed: false,
    };

    let mut wait_handle = tokio::task::spawn_blocking(move || {
        let res = child.wait();
        (child, res)
    });

    let signal_fut = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).ok();
            tokio::select! {
                _ = tokio::signal::ctrl_c() => "SIGINT",
                _ = async {
                    if let Some(ref mut s) = sigterm {
                        s.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => "SIGTERM",
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            "SIGINT"
        }
    };

    let status_res = tokio::select! {
        res = &mut wait_handle => {
            cancel_guard.completed = true;
            let (_child, wait_res) = res
                .map_err(|e| anyhow::anyhow!("Process execution task for {bin_display} interrupted: {e}"))?;
            wait_res
        }
        sig = signal_fut => {
            warn!("Received {sig}; terminating process tree for {bin_display}");
            let exit_code = if sig == "SIGINT" { 130 } else { 143 };
            if let Some(ref g) = *guard_clone {
                g.terminate(exit_code);
            }
            cancel_guard.completed = true;
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), &mut wait_handle).await;
            return Err(anyhow::Error::from(ScriptExitError {
                exit_code: exit_code as i32,
                message: format!("Process execution for {bin_display} terminated by {sig}"),
            }));
        }
        _ = abort_fut => {
            warn!("Abort signal triggered; terminating process tree for {bin_display}");
            if let Some(ref g) = *guard_clone {
                g.terminate(143);
            }
            cancel_guard.completed = true;
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), &mut wait_handle).await;
            return Err(anyhow::Error::from(ScriptExitError {
                exit_code: 143,
                message: format!("Process execution for {bin_display} aborted by signal"),
            }));
        }
    };

    if let Some(ref g) = *guard {
        g.terminate(0);
    }

    let status =
        status_res.with_context(|| format!("Failed to wait for binary '{bin_display}'"))?;

    Ok(status)
}

/// Executes a binary asynchronously with process tree signal cleanup.
pub async fn execute_binary_async(
    binary_path: &Path,
    args: &[String],
    current_dir: &Path,
    path_entries: &[PathBuf],
    extra_env: &HashMap<String, String>,
) -> Result<ExitStatus> {
    execute_binary_with_abort(
        binary_path,
        args,
        current_dir,
        path_entries,
        extra_env,
        std::future::pending(),
    )
    .await
}

/// Executes dependency lifecycle scripts bottom-up (topologically), followed by root hooks,
/// with optional abort signal monitoring.
pub async fn execute_topological_with_abort(
    nodes: &[LifecyclePackageNode],
    root_manifest: &Manifest,
    opts: &LifecycleOptions,
    abort_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<()> {
    execute_dependency_hooks_with_abort(nodes, opts, abort_rx.clone()).await?;
    execute_root_hooks_with_abort(root_manifest, opts, abort_rx).await
}

/// Build dependencies before persisting the reified tree's metadata.
pub async fn execute_dependency_hooks(
    nodes: &[LifecyclePackageNode],
    opts: &LifecycleOptions,
) -> Result<()> {
    execute_dependency_hooks_with_abort(nodes, opts, None).await
}

async fn execute_dependency_hooks_with_abort(
    nodes: &[LifecyclePackageNode],
    opts: &LifecycleOptions,
    abort_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<()> {
    if opts.ignore_scripts || opts.sandbox_policy.level == SandboxLevel::Disabled {
        return Ok(());
    }

    // Check if already aborted
    if let Some(ref rx) = abort_rx {
        if *rx.borrow() {
            return Err(anyhow::anyhow!(
                "Topological lifecycle execution aborted by signal"
            ));
        }
    }

    if nodes.is_empty() {
        return Ok(());
    }

    // Build dependency index matching node name / package_path lookup.
    let mut name_to_idx: HashMap<String, usize> = HashMap::with_capacity(nodes.len() * 2);
    for (idx, node) in nodes.iter().enumerate() {
        let name = node
            .manifest
            .name
            .clone()
            .unwrap_or_else(|| node.package_path.clone());
        name_to_idx.insert(name, idx);
        if let Some(stripped) = node.package_path.strip_prefix("node_modules/") {
            name_to_idx.insert(stripped.to_string(), idx);
        }
    }

    // Construct an acyclic dependency DAG using DFS cycle back-edge breaking.
    let n = nodes.len();
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut indegree: Vec<usize> = vec![0; n];
    let mut visited = vec![false; n];
    let mut in_stack = vec![false; n];

    fn dfs_dag(
        u: usize,
        nodes: &[LifecyclePackageNode],
        name_to_idx: &HashMap<String, usize>,
        visited: &mut [bool],
        in_stack: &mut [bool],
        dependents: &mut [Vec<usize>],
        indegree: &mut [usize],
    ) {
        if visited[u] || in_stack[u] {
            return;
        }
        in_stack[u] = true;
        let mut added_deps: Vec<usize> = Vec::with_capacity(nodes[u].dependencies.len());
        for dep in &nodes[u].dependencies {
            if let Some(&v) = name_to_idx.get(dep) {
                if v != u && !in_stack[v] {
                    if !added_deps.contains(&v) {
                        added_deps.push(v);
                        dependents[v].push(u);
                        indegree[u] += 1;
                    }
                    dfs_dag(v, nodes, name_to_idx, visited, in_stack, dependents, indegree);
                }
            }
        }
        in_stack[u] = false;
        visited[u] = true;
    }

    for i in 0..n {
        if !visited[i] {
            dfs_dag(
                i,
                nodes,
                &name_to_idx,
                &mut visited,
                &mut in_stack,
                &mut dependents,
                &mut indegree,
            );
        }
    }

    let has_matching_hooks: Vec<bool> = nodes
        .iter()
        .map(|node| {
            let hooks = node.source.lifecycle_hooks();
            hooks
                .iter()
                .any(|h| node.manifest.scripts.get(*h).is_some_and(|cmd| !cmd.is_empty()))
        })
        .collect();

    if !has_matching_hooks.iter().any(|&has| has) {
        return Ok(());
    }

    let root_config = Arc::new(get_trusted_config().unwrap_or_else(|| {
        rnpm_config::Config::load(Some(&opts.root_dir)).unwrap_or_default()
    }));
    let base_env = Arc::new(ScriptBaseEnv::build(
        &opts.root_dir,
        &root_config,
        None,
        None,
        None,
    ));

    let mut ready_hooks = std::collections::VecDeque::new();
    let mut zero_queue = std::collections::VecDeque::new();
    for (i, &deg) in indegree.iter().enumerate() {
        if deg == 0 {
            zero_queue.push_back(i);
        }
    }
    let drain_ready = |zero_q: &mut std::collections::VecDeque<usize>,
                       ready_h: &mut std::collections::VecDeque<usize>,
                       indeg: &mut [usize]| {
        while let Some(u) = zero_q.pop_front() {
            if has_matching_hooks[u] {
                ready_h.push_back(u);
            } else {
                for &child in &dependents[u] {
                    indeg[child] -= 1;
                    if indeg[child] == 0 {
                        zero_q.push_back(child);
                    }
                }
            }
        }
    };
    drain_ready(&mut zero_queue, &mut ready_hooks, &mut indegree);

    let max_workers = if opts.foreground_scripts {
        1
    } else {
        std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4)
            .clamp(4, 16)
    };

    let (fail_abort_tx, fail_abort_rx) = tokio::sync::watch::channel(false);
    let mut join_set: tokio::task::JoinSet<Result<usize>> = tokio::task::JoinSet::new();
    let opts_arc = Arc::new(opts.clone());

    let spawn_node = |idx: usize,
                      join_set: &mut tokio::task::JoinSet<Result<usize>>,
                      base_env: &Arc<ScriptBaseEnv>,
                      root_config: &Arc<rnpm_config::Config>,
                      opts_arc: &Arc<LifecycleOptions>,
                      abort_rx: &Option<tokio::sync::watch::Receiver<bool>>,
                      fail_abort_rx: &tokio::sync::watch::Receiver<bool>| {
        let node = nodes[idx].clone();
        let base_env = Arc::clone(base_env);
        let root_config = Arc::clone(root_config);
        let opts = Arc::clone(opts_arc);
        let caller_rx = abort_rx.clone();
        let local_fail_rx = fail_abort_rx.clone();

        join_set.spawn(async move {
            let hooks = node.source.lifecycle_hooks();
            let matching_hooks: Vec<(&str, &str)> = hooks
                .iter()
                .filter_map(|&h| {
                    node.manifest
                        .scripts
                        .get(h)
                        .filter(|cmd| !cmd.is_empty())
                        .map(|cmd| (h, cmd.as_str()))
                })
                .collect();

            let mut base_extra = HashMap::new();
            if !opts.init_cwd.as_os_str().is_empty() {
                base_extra.insert(
                    "INIT_CWD".to_string(),
                    opts.init_cwd.to_string_lossy().to_string(),
                );
            }
            let pkg_name = node.manifest.name.as_deref().unwrap_or("unknown");
            let mut precomputed = base_env.build_package_env_with_manifest(
                &node.disk_path,
                pkg_name,
                node.manifest.version.as_deref(),
                "run",
                "",
                Some(&base_extra),
                None,
                Some(&node.manifest),
            );

            let last_i = matching_hooks.len().saturating_sub(1);
            for (i, (hook, script_cmd)) in matching_hooks.into_iter().enumerate() {
                if *local_fail_rx.borrow()
                    || caller_rx.as_ref().is_some_and(|rx| *rx.borrow())
                {
                    return Err(anyhow::anyhow!(
                        "Topological lifecycle execution aborted by signal"
                    ));
                }

                let mut ctx = LifecycleContext::new_with_config(
                    &opts.root_dir,
                    &node.disk_path,
                    pkg_name,
                    hook,
                    script_cmd,
                    (*root_config).clone(),
                );
                let mut hook_env = if i == last_i {
                    std::mem::take(&mut precomputed)
                } else {
                    precomputed.clone()
                };
                if !opts.init_cwd.as_os_str().is_empty() {
                    ctx.extra_env.insert(
                        "INIT_CWD".to_string(),
                        opts.init_cwd.to_string_lossy().to_string(),
                    );
                }
                ctx.package_version = node.manifest.version.clone();
                ctx.timeout = opts.timeout;
                ctx.sandbox_policy = opts.sandbox_policy.clone();
                ctx.foreground_scripts = opts.foreground_scripts;
                // Dependency build output is captured and only shown on failure.
                ctx.capture_output = opts.capture_output && !opts.foreground_scripts;
                ctx.node_gyp = opts.node_gyp.clone();
                ctx.offline = opts.offline;
                apply_context_overrides_to_precomputed_env(&mut hook_env, &ctx);
                ctx.precomputed_env = Some(hook_env);

                let mut rx_caller_wait = caller_rx.clone();
                let mut rx_fail_wait = local_fail_rx.clone();
                let abort_fut = async move {
                    tokio::select! {
                        _ = async {
                            if let Some(ref mut rx) = rx_caller_wait {
                                let _ = rx.wait_for(|&val| val).await;
                            } else {
                                std::future::pending::<()>().await;
                            }
                        } => {}
                        _ = async {
                            let _ = rx_fail_wait.wait_for(|&val| val).await;
                        } => {}
                    }
                };

                match execute_lifecycle_script_with_abort(&ctx, abort_fut).await {
                    Ok(status) if status.success() => {}
                    Ok(status) => {
                        if node.optional {
                            let pkg_ver = node.manifest.version.as_deref().unwrap_or("unknown");
                            warn!(
                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: {}@{} ({}):",
                                pkg_name,
                                pkg_ver,
                                node.disk_path.display()
                            );
                            warn!(
                                "npm warn optional {} failed at the {} script with exit code: {:?}.",
                                pkg_name,
                                hook,
                                status.code()
                            );
                            if node.disk_path.exists() {
                                let _ = std::fs::remove_dir_all(&node.disk_path);
                            }
                            break;
                        } else {
                            let mut failure = ScriptExitError::lifecycle_failure(&ctx, &status);
                            if let Some(out) =
                                ctx.captured_output.lock().ok().and_then(|o| o.clone())
                            {
                                for line in out.stdout.lines().chain(out.stderr.lines()) {
                                    failure.message.push_str("\nnpm error ");
                                    failure.message.push_str(line);
                                }
                            }
                            return Err(anyhow::Error::from(failure));
                        }
                    }
                    Err(e) => {
                        if node.optional {
                            let pkg_ver = node.manifest.version.as_deref().unwrap_or("unknown");
                            warn!(
                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: {}@{} ({}):",
                                pkg_name,
                                pkg_ver,
                                node.disk_path.display()
                            );
                            warn!(
                                "npm warn optional {} failed at the {} script: {}",
                                pkg_name, hook, e
                            );
                            if node.disk_path.exists() {
                                let _ = std::fs::remove_dir_all(&node.disk_path);
                            }
                            break;
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
            Ok(idx)
        });
    };

    while join_set.len() < max_workers {
        if let Some(idx) = ready_hooks.pop_front() {
            spawn_node(
                idx,
                &mut join_set,
                &base_env,
                &root_config,
                &opts_arc,
                &abort_rx,
                &fail_abort_rx,
            );
        } else {
            break;
        }
    }

    let mut first_err: Option<anyhow::Error> = None;
    while let Some(res) = join_set.join_next().await {
        match res {
            Ok(Ok(done_idx)) => {
                if first_err.is_none() {
                    for &child in &dependents[done_idx] {
                        indegree[child] -= 1;
                        if indegree[child] == 0 {
                            zero_queue.push_back(child);
                        }
                    }
                    drain_ready(&mut zero_queue, &mut ready_hooks, &mut indegree);
                    while join_set.len() < max_workers {
                        if let Some(idx) = ready_hooks.pop_front() {
                            spawn_node(
                                idx,
                                &mut join_set,
                                &base_env,
                                &root_config,
                                &opts_arc,
                                &abort_rx,
                                &fail_abort_rx,
                            );
                        } else {
                            break;
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                if first_err.is_none() {
                    first_err = Some(e);
                    let _ = fail_abort_tx.send(true);
                }
            }
            Err(join_err) => {
                if first_err.is_none() {
                    first_err = Some(anyhow::anyhow!("Lifecycle worker panicked: {join_err}"));
                    let _ = fail_abort_tx.send(true);
                }
            }
        }
    }

    if let Some(err) = first_err {
        return Err(err);
    }

    Ok(())
}

const ROOT_INSTALL_HOOKS: [&str; 7] = [
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
];

fn prepare_root_hook_contexts(
    root_manifest: &Manifest,
    opts: &LifecycleOptions,
    trusted_config: Option<&rnpm_config::Config>,
) -> (Vec<LifecycleContext>, bool) {
    if opts.ignore_scripts || opts.sandbox_policy.level == SandboxLevel::Disabled {
        return (Vec::new(), true);
    }

    let active_hooks: Vec<(&str, &str)> = ROOT_INSTALL_HOOKS
        .iter()
        .filter_map(|&hook| {
            root_manifest
                .scripts
                .get(hook)
                .filter(|cmd| !cmd.is_empty())
                .map(|cmd| (hook, cmd.as_str()))
        })
        .collect();
    if active_hooks.is_empty() {
        return (Vec::new(), true);
    }

    let root_config = trusted_config
        .cloned()
        .or_else(get_trusted_config)
        .unwrap_or_else(|| rnpm_config::Config::load(Some(&opts.root_dir)).unwrap_or_default());
    let mut base_extra = HashMap::new();
    if !opts.init_cwd.as_os_str().is_empty() {
        base_extra.insert(
            "INIT_CWD".to_string(),
            opts.init_cwd.to_string_lossy().to_string(),
        );
    }
    let mut root_precomputed = Some(precompute_lifecycle_env_with_manifest(
        &opts.root_dir,
        &opts.root_dir,
        root_manifest.name.as_deref().unwrap_or("root"),
        root_manifest.version.as_deref(),
        &root_config,
        Some(&base_extra),
        Some(root_manifest),
    ));
    let is_silent = root_config.get("loglevel") == Some("silent");
    let last_idx = active_hooks.len() - 1;
    let mut contexts = Vec::with_capacity(active_hooks.len());

    for (idx, (hook, script_cmd)) in active_hooks.into_iter().enumerate() {
        let mut ctx = LifecycleContext::new_with_config(
            &opts.root_dir,
            &opts.root_dir,
            root_manifest.name.as_deref().unwrap_or("root"),
            hook,
            script_cmd,
            root_config.clone(),
        );
        ctx.precomputed_env = if idx == last_idx {
            root_precomputed.take()
        } else {
            root_precomputed.clone()
        };
        if !opts.init_cwd.as_os_str().is_empty() {
            ctx.extra_env.insert(
                "INIT_CWD".to_string(),
                opts.init_cwd.to_string_lossy().to_string(),
            );
        }
        ctx.package_version = root_manifest.version.clone();
        ctx.timeout = opts.timeout;
        ctx.sandbox_policy = opts.sandbox_policy.clone();
        ctx.foreground_scripts = opts.foreground_scripts;
        if opts.foreground_scripts {
            ctx.capture_output = false;
        }
        ctx.node_gyp = opts.node_gyp.clone();
        ctx.offline = opts.offline;
        contexts.push(ctx);
    }

    (contexts, is_silent)
}

fn print_root_hook_banner(root_manifest: &Manifest, hook: &str, script_cmd: &str) {
    let name = root_manifest.name.as_deref().unwrap_or("");
    let id = root_manifest
        .version
        .as_ref()
        .map(|v| format!("{name}@{v} "))
        .unwrap_or_else(|| {
            if name.is_empty() {
                String::new()
            } else {
                format!("{name} ")
            }
        });
    // npm routes lifecycle banners to stderr in JSON mode so stdout stays parseable.
    let json_mode = rnpm_config::get_process_cli_overrides()
        .and_then(|o| o.get("json").cloned())
        .is_some_and(|v| v != "false" && v != "0");
    if json_mode {
        eprintln!("\n> {id}{hook}\n> {script_cmd}\n");
    } else {
        println!("\n> {id}{hook}\n> {script_cmd}\n");
    }
}

/// Synchronously run root install hooks after reification without a Tokio runtime.
pub fn execute_root_hooks_sync(root_manifest: &Manifest, opts: &LifecycleOptions) -> Result<()> {
    execute_root_hooks_sync_with_config(root_manifest, opts, None)
}

/// Synchronously run root install hooks using an already-loaded config without a Tokio runtime.
pub fn execute_root_hooks_sync_with_config(
    root_manifest: &Manifest,
    opts: &LifecycleOptions,
    trusted_config: Option<&rnpm_config::Config>,
) -> Result<()> {
    let (contexts, is_silent) = prepare_root_hook_contexts(root_manifest, opts, trusted_config);
    for ctx in &contexts {
        if !is_silent {
            print_root_hook_banner(root_manifest, &ctx.event, &ctx.script_cmd);
        }
        let status = execute_lifecycle_script(ctx)?;
        if !status.success() {
            return Err(anyhow::Error::from(ScriptExitError::lifecycle_failure(
                ctx, &status,
            )));
        }
    }
    Ok(())
}

/// Run root install hooks after reification has persisted the public lockfile.
pub async fn execute_root_hooks(root_manifest: &Manifest, opts: &LifecycleOptions) -> Result<()> {
    execute_root_hooks_with_abort(root_manifest, opts, None).await
}

async fn execute_root_hooks_with_abort(
    root_manifest: &Manifest,
    opts: &LifecycleOptions,
    abort_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<()> {
    let (contexts, is_silent) = prepare_root_hook_contexts(root_manifest, opts, None);
    for ctx in &contexts {
        if let Some(ref rx) = abort_rx {
            if *rx.borrow() {
                return Err(anyhow::anyhow!(
                    "Topological lifecycle execution aborted by signal"
                ));
            }
        }
        if !is_silent {
            print_root_hook_banner(root_manifest, &ctx.event, &ctx.script_cmd);
        }
        let abort_fut = {
            let mut rx_opt = abort_rx.clone();
            async move {
                if let Some(ref mut rx) = rx_opt {
                    let _ = rx.wait_for(|&val| val).await;
                } else {
                    std::future::pending::<()>().await;
                }
            }
        };
        let status = execute_lifecycle_script_with_abort(ctx, abort_fut).await?;
        if !status.success() {
            return Err(anyhow::Error::from(ScriptExitError::lifecycle_failure(
                ctx, &status,
            )));
        }
    }

    Ok(())
}

/// Executes dependency lifecycle scripts bottom-up (topologically), followed by root hooks.
pub async fn execute_topological(
    nodes: &[LifecyclePackageNode],
    root_manifest: &Manifest,
    opts: &LifecycleOptions,
) -> Result<()> {
    execute_topological_with_abort(nodes, root_manifest, opts, None).await
}

/// Represents a workspace package member participating in script execution.
#[derive(Debug, Clone)]
pub struct WorkspaceScriptMember {
    pub name: String,
    pub path: PathBuf,
    pub manifest: Manifest,
}

#[derive(Debug, Clone, Default)]
pub struct WorkspaceRunOptions {
    pub script: String,
    pub args: Vec<String>,
    pub ignore_scripts: bool,
    pub foreground_scripts: bool,
    pub strict_sandbox: bool,
    pub if_present: bool,
    pub filter_members: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct WorkspaceRunSummary {
    pub executed_packages: Vec<String>,
    pub skipped_packages: Vec<String>,
}

/// Topologically sorts workspace members such that dependencies precede dependents (bottom-up).
/// If `topological_order` provides a preferred sequence, it is respected as a priority guide
/// while strictly maintaining the topological dependency invariant.
pub fn sort_workspace_members_topologically<'a>(
    members: &'a [WorkspaceScriptMember],
    topological_order: &[String],
) -> Vec<&'a WorkspaceScriptMember> {
    if members.is_empty() {
        return Vec::new();
    }

    let n = members.len();

    let mut name_to_indices: HashMap<&str, Vec<usize>> = HashMap::new();
    for (idx, m) in members.iter().enumerate() {
        name_to_indices
            .entry(m.name.as_str())
            .or_default()
            .push(idx);
        if let Some(ref m_name) = m.manifest.name {
            if m_name.as_str() != m.name.as_str() {
                name_to_indices
                    .entry(m_name.as_str())
                    .or_default()
                    .push(idx);
            }
        }
    }

    let mut order_rank: HashMap<&str, usize> = HashMap::new();
    for (pos, name) in topological_order.iter().enumerate() {
        order_rank.entry(name.as_str()).or_insert(pos);
    }

    let base_rank = topological_order.len();
    let mut member_ranks: Vec<usize> = Vec::with_capacity(n);
    for (idx, m) in members.iter().enumerate() {
        let rank = order_rank
            .get(m.name.as_str())
            .copied()
            .or_else(|| {
                m.manifest
                    .name
                    .as_deref()
                    .and_then(|nm| order_rank.get(nm).copied())
            })
            .unwrap_or(base_rank + idx);
        member_ranks.push(rank);
    }

    let mut in_degrees: Vec<usize> = vec![0; n];
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (b_idx, member) in members.iter().enumerate() {
        let mut dep_names = HashSet::new();
        for dep_name in member
            .manifest
            .dependencies
            .keys()
            .chain(member.manifest.dev_dependencies.keys())
            .chain(member.manifest.optional_dependencies.keys())
            .chain(member.manifest.peer_dependencies.keys())
        {
            if dep_name.as_str() != member.name.as_str() {
                dep_names.insert(dep_name.as_str());
            }
        }

        let mut prereq_indices = HashSet::new();
        for dep_name in dep_names {
            if let Some(a_indices) = name_to_indices.get(dep_name) {
                for &a_idx in a_indices {
                    if a_idx != b_idx {
                        prereq_indices.insert(a_idx);
                    }
                }
            }
        }

        in_degrees[b_idx] = prereq_indices.len();
        for &a_idx in &prereq_indices {
            adj[a_idx].push(b_idx);
        }
    }

    let mut visited = vec![false; n];
    let mut ordered: Vec<&'a WorkspaceScriptMember> = Vec::with_capacity(n);

    let mut ready: BinaryHeap<std::cmp::Reverse<(usize, usize)>> = BinaryHeap::new();
    for idx in 0..n {
        if in_degrees[idx] == 0 {
            ready.push(std::cmp::Reverse((member_ranks[idx], idx)));
        }
    }

    while ordered.len() < n {
        if let Some(std::cmp::Reverse((_, curr_idx))) = ready.pop() {
            if visited[curr_idx] {
                continue;
            }
            visited[curr_idx] = true;
            ordered.push(&members[curr_idx]);

            for &next_idx in &adj[curr_idx] {
                if in_degrees[next_idx] > 0 {
                    in_degrees[next_idx] -= 1;
                    if in_degrees[next_idx] == 0 && !visited[next_idx] {
                        ready.push(std::cmp::Reverse((member_ranks[next_idx], next_idx)));
                    }
                }
            }
        } else {
            let mut best_idx = None;
            let mut best_rank = usize::MAX;
            for idx in 0..n {
                if !visited[idx] && member_ranks[idx] < best_rank {
                    best_rank = member_ranks[idx];
                    best_idx = Some(idx);
                }
            }

            if let Some(curr_idx) = best_idx {
                visited[curr_idx] = true;
                ordered.push(&members[curr_idx]);

                for &next_idx in &adj[curr_idx] {
                    if in_degrees[next_idx] > 0 {
                        in_degrees[next_idx] -= 1;
                        if in_degrees[next_idx] == 0 && !visited[next_idx] {
                            ready.push(std::cmp::Reverse((member_ranks[next_idx], next_idx)));
                        }
                    }
                }
            } else {
                break;
            }
        }
    }

    ordered
}

/// Executes an arbitrary script across workspace members in topological dependency order (leaf packages first),
/// with optional abort signal support.
pub async fn execute_workspace_scripts_topological_with_abort(
    root_dir: &Path,
    members: &[WorkspaceScriptMember],
    topological_order: &[String],
    opts: &WorkspaceRunOptions,
    abort_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<WorkspaceRunSummary> {
    if opts.ignore_scripts {
        return Ok(WorkspaceRunSummary::default());
    }

    if let Some(ref rx) = abort_rx {
        if *rx.borrow() {
            return Err(anyhow::anyhow!("Workspace execution aborted by signal"));
        }
    }

    if let Some(ref filters) = opts.filter_members {
        let any_match = members.iter().any(|m| {
            filters
                .iter()
                .any(|f| matches_filter(f, &m.name, &m.path, root_dir))
        });
        if !any_match {
            return Err(anyhow::anyhow!(
                "No workspace packages matched the filter/scope criteria: {}",
                filters.join(", ")
            ));
        }
    }

    let ordered_members = sort_workspace_members_topologically(members, topological_order);
    let mut summary = WorkspaceRunSummary::default();

    let trusted_config = get_trusted_config();
    let has_trusted_config = trusted_config.is_some();
    let root_config = trusted_config.unwrap_or_else(|| {
        rnpm_config::Config::load(Some(root_dir)).unwrap_or_default()
    });
    let root_base_env = ScriptBaseEnv::build(root_dir, &root_config, None, None, None);

    let pre_hook_name = format!("pre{}", opts.script);
    let post_hook_name = format!("post{}", opts.script);

    for member in ordered_members {
        if let Some(ref rx) = abort_rx {
            if *rx.borrow() {
                return Err(anyhow::anyhow!("Workspace execution aborted by signal"));
            }
        }

        if let Some(ref filter) = opts.filter_members {
            if !filter
                .iter()
                .any(|f| matches_filter(f, &member.name, &member.path, root_dir))
            {
                continue;
            }
        }

        let pre_cmd = member.manifest.scripts.get(&pre_hook_name);
        let main_cmd = member.manifest.scripts.get(&opts.script);
        let post_cmd = member.manifest.scripts.get(&post_hook_name);

        if pre_cmd.is_none() && main_cmd.is_none() && post_cmd.is_none() {
            if opts.if_present || opts.filter_members.is_none() {
                debug!(
                    "Skipping package '{}': script '{}' not found",
                    member.name, opts.script
                );
                summary.skipped_packages.push(member.name.clone());
                continue;
            } else {
                return Err(anyhow::anyhow!(
                    "rnpm ERR! missing script: {} in workspace package {}",
                    opts.script,
                    member.name
                ));
            }
        }

        let mut hooks_to_run = Vec::new();
        if let Some(cmd) = pre_cmd.filter(|cmd| !cmd.is_empty()) {
            hooks_to_run.push((pre_hook_name.as_str(), cmd, false));
        }
        if let Some(cmd) = main_cmd.filter(|cmd| !cmd.is_empty()) {
            hooks_to_run.push((opts.script.as_str(), cmd, true));
        }
        if let Some(cmd) = post_cmd.filter(|cmd| !cmd.is_empty()) {
            hooks_to_run.push((post_hook_name.as_str(), cmd, false));
        }

        let member_config;
        let member_base_storage;
        let use_member_config = !has_trusted_config && member.path.join(".npmrc").is_file();
        let base_ref = if use_member_config {
            member_config = rnpm_config::Config::load(Some(&member.path))
                .unwrap_or_else(|_| root_config.clone());
            member_base_storage = ScriptBaseEnv::build(root_dir, &member_config, None, None, None);
            &member_base_storage
        } else {
            &root_base_env
        };
        let mut precomputed = if hooks_to_run.len() > 1 {
            Some(base_ref.build_package_env_with_manifest(
                &member.path,
                &member.name,
                member.manifest.version.as_deref(),
                "run",
                "",
                None,
                None,
                Some(&member.manifest),
            ))
        } else {
            None
        };

        let last_hook_idx = hooks_to_run.len().saturating_sub(1);
        for (hook_i, (hook_name, cmd, pass_args)) in hooks_to_run.into_iter().enumerate() {
            if let Some(ref rx) = abort_rx {
                if *rx.borrow() {
                    return Err(anyhow::anyhow!("Workspace execution aborted by signal"));
                }
            }

            let full_cmd = if pass_args && !opts.args.is_empty() {
                format!("{cmd} {}", opts.args.join(" "))
            } else {
                cmd.clone()
            };

            println!(
                "\n> {}@{} {} {}",
                member.name,
                member.manifest.version.as_deref().unwrap_or("0.0.0"),
                hook_name,
                member.path.display()
            );
            println!("> {full_cmd}\n");

            let mut ctx = if use_member_config {
                LifecycleContext::new(root_dir, &member.path, &member.name, hook_name, &full_cmd)
            } else {
                LifecycleContext::new_with_config(
                    root_dir,
                    &member.path,
                    &member.name,
                    hook_name,
                    &full_cmd,
                    root_config.clone(),
                )
            };
            ctx.package_version = member.manifest.version.clone();
            if let Ok(command) = std::env::var("npm_command") {
                ctx.extra_env.insert("npm_command".to_string(), command);
            }
            ctx.precomputed_env = match precomputed.as_mut() {
                Some(p) if hook_i == last_hook_idx => Some(std::mem::take(p)),
                Some(p) => Some(p.clone()),
                None => Some(base_ref.build_package_env_with_manifest(
                    &member.path,
                    &member.name,
                    member.manifest.version.as_deref(),
                    hook_name,
                    &full_cmd,
                    None,
                    None,
                    Some(&member.manifest),
                )),
            };
            ctx.foreground_scripts = opts.foreground_scripts;
            if opts.foreground_scripts {
                ctx.capture_output = false;
            }
            if opts.strict_sandbox {
                ctx.sandbox_policy = ScriptSandboxPolicy::restricted();
            }

            let abort_fut = {
                let mut rx_opt = abort_rx.clone();
                async move {
                    if let Some(ref mut rx) = rx_opt {
                        let _ = rx.wait_for(|&val| val).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }
            };

            let status = execute_lifecycle_script_with_abort(&ctx, abort_fut).await?;
            if !status.success() {
                let code = extract_exit_status_code(&status);
                return Err(anyhow::Error::from(ScriptExitError {
                    exit_code: code,
                    message: format!(
                        "Workspace member '{}' script '{}' exited with status code: {}",
                        member.name, hook_name, code
                    ),
                }));
            }
        }

        summary.executed_packages.push(member.name.clone());
    }

    Ok(summary)
}

/// Executes an arbitrary script across workspace members in topological dependency order (leaf packages first).
pub async fn execute_workspace_scripts_topological(
    root_dir: &Path,
    members: &[WorkspaceScriptMember],
    topological_order: &[String],
    opts: &WorkspaceRunOptions,
) -> Result<WorkspaceRunSummary> {
    execute_workspace_scripts_topological_with_abort(
        root_dir,
        members,
        topological_order,
        opts,
        None,
    )
    .await
}
