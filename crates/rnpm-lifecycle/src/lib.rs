#![allow(clippy::upper_case_acronyms, clippy::field_reassign_with_default)]

use anyhow::{Context, Result};
use rnpm_core::manifest::Manifest;
use std::collections::BinaryHeap;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use tracing::{debug, info, warn};

pub mod error;
pub mod policy;
pub mod sandbox;

pub use error::LifecycleError;
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
        }
    }
}

impl LifecycleOptions {
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        let root = root_dir.into();
        Self {
            init_cwd: root.clone(),
            root_dir: root,
            ignore_scripts: false,
            capture_output: true,
            foreground_scripts: false,
            timeout: None,
            sandbox_policy: ScriptSandboxPolicy::default(),
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
}

impl LifecycleContext {
    pub fn new(
        project_root: impl Into<PathBuf>,
        package_dir: impl Into<PathBuf>,
        package_name: impl Into<String>,
        event: impl Into<String>,
        script_cmd: impl Into<String>,
    ) -> Self {
        Self {
            project_root: project_root.into(),
            package_dir: package_dir.into(),
            package_name: package_name.into(),
            package_version: None,
            event: event.into(),
            script_cmd: script_cmd.into(),
            node_execpath: None,
            npm_execpath: None,
            extra_env: HashMap::new(),
            timeout: None,
            capture_output: false,
            foreground_scripts: false,
            captured_output: std::sync::Arc::new(std::sync::Mutex::new(None)),
            sandbox_policy: ScriptSandboxPolicy::default(),
        }
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

    pub fn get_captured_output(&self) -> Option<ScriptOutput> {
        self.captured_output.lock().unwrap().clone()
    }
}

/// Scrub sensitive authentication tokens and credentials from environment map.
pub fn is_sensitive_credential_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();

    // Specific credential keys requested for hardening
    if lower.contains("aws_access_key_id")
        || lower.contains("aws_secret_access_key")
        || lower.contains("aws_session_token")
        || lower.contains("ssh_auth_sock")
        || lower.contains("jwt")
        || lower.contains("deploy_key")
        || lower.contains("deploykey")
        || lower.contains("signing_key")
        || lower.contains("signingkey")
        || lower.contains("encryption_key")
        || lower.contains("encryptionkey")
        || lower.contains("secret_key")
        || lower.contains("secretkey")
    {
        return true;
    }

    // Token prefixes
    if lower.starts_with("ghp_")
        || lower.contains("ghp_")
        || lower.starts_with("github_pat_")
        || lower.contains("github_pat_")
    {
        return true;
    }

    if lower.contains("authtoken")
        || lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("secret")
        || lower.contains("credential")
        || lower.contains("private_key")
        || lower.contains("privatekey")
        || lower.contains("apikey")
        || lower.contains("api_key")
        || lower.contains("bearer")
    {
        return true;
    }

    if lower.starts_with("//")
        || lower.contains("/:_")
        || lower.contains(":_authtoken")
        || lower.contains(":_auth")
        || lower.contains(":_password")
        || lower.starts_with("npm_config_//")
    {
        return true;
    }

    if (lower.contains("_auth")
        || lower.contains("auth_")
        || lower.starts_with("auth")
        || lower.ends_with("auth")
        || lower == "auth")
        && !lower.contains("author")
    {
        return true;
    }

    if lower.contains("token") {
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
    let mut buf = vec![0u8; 64 * 1024];
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

/// Builds the scrubbed and populated environment map for the lifecycle script.
pub fn build_lifecycle_env(ctx: &LifecycleContext) -> HashMap<String, String> {
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
        if !is_sensitive_credential_key(k) {
            env.insert(k.clone(), v.clone());
        }
    }

    // Sanitize npm_config_user_agent if present
    if let Some(ua) = env.get_mut("npm_config_user_agent") {
        *ua = scrub_text(ua);
    } else {
        env.insert(
            "npm_config_user_agent".to_string(),
            format!(
                "rnpm/{} node/{} {} {}",
                env!("CARGO_PKG_VERSION"),
                "v20.0.0",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        );
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

    // Node executable directory
    let node_bin = ctx.node_execpath.clone().unwrap_or_else(|| {
        if let Ok(cur_node) = std::env::var("NODE") {
            PathBuf::from(cur_node)
        } else {
            PathBuf::from("node")
        }
    });

    if let Some(parent) = node_bin.parent() {
        if parent.as_os_str() != "" {
            path_entries.push(parent.to_path_buf());
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
    env.insert(
        "INIT_CWD".to_string(),
        ctx.project_root.to_string_lossy().to_string(),
    );
    env.insert("npm_lifecycle_event".to_string(), ctx.event.clone());
    env.insert("npm_lifecycle_script".to_string(), ctx.script_cmd.clone());
    env.insert("npm_package_name".to_string(), ctx.package_name.clone());

    if let Some(ref ver) = ctx.package_version {
        env.insert("npm_package_version".to_string(), ver.clone());
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
        .unwrap_or_else(|| std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rnpm")));
    env.insert(
        "npm_execpath".to_string(),
        rnpm_exec.to_string_lossy().to_string(),
    );

    env
}

/// Spawns and executes a lifecycle script synchronously within the specified context,
/// enforcing process-tree containment so child and grandchild processes terminate on exit.
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

    let env = build_lifecycle_env(ctx);

    #[cfg(windows)]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        let mut c = Command::new("cmd.exe");
        c.raw_arg(format!("/d /s /c {}", ctx.script_cmd));
        c
    };

    #[cfg(not(windows))]
    let mut cmd = {
        use std::os::unix::process::CommandExt;
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(&ctx.script_cmd);
        c.process_group(0);
        c
    };

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
        let start = std::time::Instant::now();
        let poll_interval = std::time::Duration::from_millis(10);
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
                        return Err(anyhow::Error::from(ScriptExitError {
                            exit_code: 124,
                            message: format!(
                                "Lifecycle script '{}' timed out after {:?}",
                                ctx.event, timeout
                            ),
                        }));
                    }
                    std::thread::sleep(poll_interval);
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

    let env = build_lifecycle_env(ctx);

    #[cfg(windows)]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        let mut c = Command::new("cmd.exe");
        c.raw_arg(format!("/d /s /c {}", ctx.script_cmd));
        c
    };

    #[cfg(not(windows))]
    let mut cmd = {
        use std::os::unix::process::CommandExt;
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(&ctx.script_cmd);
        c.process_group(0);
        c
    };

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

    let stdout_task = tokio::task::spawn_blocking(move || {
        if let Some(mut r) = child_stdout {
            drain_and_scrub_reader(&mut r)
        } else {
            String::new()
        }
    });

    let stderr_task = tokio::task::spawn_blocking(move || {
        if let Some(mut r) = child_stderr {
            drain_and_scrub_reader(&mut r)
        } else {
            String::new()
        }
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
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), &mut wait_handle).await;
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
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), &mut wait_handle).await;
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
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), &mut wait_handle).await;
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

    let stdout_str = stdout_task.await.unwrap_or_default();
    let stderr_str = stderr_task.await.unwrap_or_default();

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
        if rel_str == norm_filter || glob_match(&norm_filter, &rel_str) {
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
        current_dir.to_string_lossy().to_string(),
    );

    #[cfg(windows)]
    let mut cmd = {
        let ext = binary_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if ext.eq_ignore_ascii_case("cmd") || ext.eq_ignore_ascii_case("bat") {
            let mut c = Command::new("cmd.exe");
            c.arg("/c").arg(binary_path);
            c.args(args);
            c
        } else if ext.eq_ignore_ascii_case("ps1") {
            let mut c = Command::new("powershell.exe");
            c.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]);
            c.arg(binary_path);
            c.args(args);
            c
        } else {
            let is_js = ext.eq_ignore_ascii_case("js")
                || ext.eq_ignore_ascii_case("cjs")
                || ext.eq_ignore_ascii_case("mjs");
            let has_shebang = if binary_path.exists() {
                if let Ok(bytes) = std::fs::read(binary_path) {
                    bytes.starts_with(b"#!") || bytes.starts_with(b"\xEF\xBB\xBF#!")
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
    };

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
        current_dir.to_string_lossy().to_string(),
    );

    #[cfg(windows)]
    let mut cmd = {
        let ext = binary_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if ext.eq_ignore_ascii_case("cmd") || ext.eq_ignore_ascii_case("bat") {
            let mut c = Command::new("cmd.exe");
            c.arg("/c").arg(binary_path);
            c.args(args);
            c
        } else if ext.eq_ignore_ascii_case("ps1") {
            let mut c = Command::new("powershell.exe");
            c.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]);
            c.arg(binary_path);
            c.args(args);
            c
        } else {
            let is_js = ext.eq_ignore_ascii_case("js")
                || ext.eq_ignore_ascii_case("cjs")
                || ext.eq_ignore_ascii_case("mjs");
            let has_shebang = if binary_path.exists() {
                if let Ok(bytes) = std::fs::read(binary_path) {
                    bytes.starts_with(b"#!") || bytes.starts_with(b"\xEF\xBB\xBF#!")
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
    };

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

    // Topological sorting: leaf nodes first (bottom-up)
    let mut name_to_node: HashMap<String, &LifecyclePackageNode> = HashMap::new();
    for node in nodes {
        let name = node
            .manifest
            .name
            .clone()
            .unwrap_or_else(|| node.package_path.clone());
        name_to_node.insert(name, node);
        if let Some(stripped) = node.package_path.strip_prefix("node_modules/") {
            name_to_node.insert(stripped.to_string(), node);
        }
    }

    let mut ordered: Vec<&LifecyclePackageNode> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut in_stack: HashSet<String> = HashSet::new();

    fn visit<'a>(
        node: &'a LifecyclePackageNode,
        name_to_node: &HashMap<String, &'a LifecyclePackageNode>,
        visited: &mut HashSet<String>,
        in_stack: &mut HashSet<String>,
        ordered: &mut Vec<&'a LifecyclePackageNode>,
    ) {
        let name = node.manifest.name.as_deref().unwrap_or(&node.package_path);
        if in_stack.contains(name) {
            // Cycle detected: safely skip back-edge to prevent infinite recursion
            return;
        }
        if visited.contains(name) {
            return;
        }

        in_stack.insert(name.to_string());
        for dep in &node.dependencies {
            if let Some(dep_node) = name_to_node.get(dep) {
                visit(dep_node, name_to_node, visited, in_stack, ordered);
            }
        }
        in_stack.remove(name);
        visited.insert(name.to_string());
        ordered.push(node);
    }

    for node in nodes {
        visit(
            node,
            &name_to_node,
            &mut visited,
            &mut in_stack,
            &mut ordered,
        );
    }

    // Execute dependency hooks in bottom-up order:
    // Hooks: preinstall -> install -> postinstall -> prepare (for local / git / tarball dependencies)
    // Note: Registry dependencies NEVER run `prepare` per docs/lifecycle-contract.md!
    for node in ordered {
        let hooks = node.source.lifecycle_hooks();

        for &hook in hooks {
            if let Some(script_cmd) = node.manifest.scripts.get(hook) {
                if let Some(ref rx) = abort_rx {
                    if *rx.borrow() {
                        return Err(anyhow::anyhow!(
                            "Topological lifecycle execution aborted by signal"
                        ));
                    }
                }

                let mut ctx = LifecycleContext::new(
                    &opts.root_dir,
                    &node.disk_path,
                    node.manifest.name.as_deref().unwrap_or("unknown"),
                    hook,
                    script_cmd,
                );
                ctx.package_version = node.manifest.version.clone();
                ctx.timeout = opts.timeout;
                ctx.sandbox_policy = opts.sandbox_policy.clone();
                ctx.foreground_scripts = opts.foreground_scripts;
                if opts.foreground_scripts {
                    ctx.capture_output = false;
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

                match execute_lifecycle_script_with_abort(&ctx, abort_fut).await {
                    Ok(status) if status.success() => {}
                    Ok(status) => {
                        if node.optional {
                            let pkg_name = node.manifest.name.as_deref().unwrap_or("unknown");
                            let pkg_ver = node.manifest.version.as_deref().unwrap_or("unknown");
                            warn!(
                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: {}@{} ({}):",
                                pkg_name,
                                pkg_ver,
                                node.disk_path.display()
                            );
                            warn!(
                                "npm warn optional {} failed at the {} script with exit code: {:?}.",
                                pkg_name, hook, status.code()
                            );
                            if node.disk_path.exists() {
                                let _ = std::fs::remove_dir_all(&node.disk_path);
                            }
                            // Break hook loop for this optional dependency; isolate failure
                            break;
                        } else {
                            return Err(anyhow::anyhow!(
                                "Lifecycle script '{}' failed for package {} with exit code: {:?}",
                                hook,
                                node.manifest.name.as_deref().unwrap_or("unknown"),
                                status.code()
                            ));
                        }
                    }
                    Err(e) => {
                        if node.optional {
                            let pkg_name = node.manifest.name.as_deref().unwrap_or("unknown");
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
                            // Break hook loop for this optional dependency; isolate failure
                            break;
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
        }
    }

    // Root package lifecycle execution: preinstall -> install -> postinstall -> prepare
    let root_hooks = ["preinstall", "install", "postinstall", "prepare"];
    for hook in root_hooks {
        if let Some(script_cmd) = root_manifest.scripts.get(hook) {
            if let Some(ref rx) = abort_rx {
                if *rx.borrow() {
                    return Err(anyhow::anyhow!(
                        "Topological lifecycle execution aborted by signal"
                    ));
                }
            }

            let mut ctx = LifecycleContext::new(
                &opts.root_dir,
                &opts.root_dir,
                root_manifest.name.as_deref().unwrap_or("root"),
                hook,
                script_cmd,
            );
            ctx.package_version = root_manifest.version.clone();
            ctx.timeout = opts.timeout;
            ctx.sandbox_policy = opts.sandbox_policy.clone();
            ctx.foreground_scripts = opts.foreground_scripts;
            if opts.foreground_scripts {
                ctx.capture_output = false;
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
                return Err(anyhow::anyhow!(
                    "Root lifecycle script '{}' failed with exit code: {:?}",
                    hook,
                    status.code()
                ));
            }
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
        if let Some(cmd) = pre_cmd {
            hooks_to_run.push((pre_hook_name.as_str(), cmd, false));
        }
        if let Some(cmd) = main_cmd {
            hooks_to_run.push((opts.script.as_str(), cmd, true));
        }
        if let Some(cmd) = post_cmd {
            hooks_to_run.push((post_hook_name.as_str(), cmd, false));
        }

        for (hook_name, cmd, pass_args) in hooks_to_run {
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

            let mut ctx =
                LifecycleContext::new(root_dir, &member.path, &member.name, hook_name, &full_cmd);
            ctx.package_version = member.manifest.version.clone();
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
