use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use anyhow::{Context, Result};
use tracing::{debug, info, warn};
use rnpm_core::manifest::Manifest;

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
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;

    extern "system" {
        fn CreateJobObjectW(lpJobAttributes: *const std::ffi::c_void, lpName: *const u16) -> HANDLE;
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
    }

    unsafe impl Send for ProcessTreeGuard {}
    unsafe impl Sync for ProcessTreeGuard {}

    impl ProcessTreeGuard {
        pub fn new() -> Option<Self> {
            unsafe {
                let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if job.is_null() {
                    return None;
                }
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
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
                Some(Self { job_handle: job })
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
                    // running inside the job object before closing handle to guarantee cleanup.
                    let _ = TerminateJobObject(self.job_handle, 1);
                    CloseHandle(self.job_handle);
                    self.job_handle = std::ptr::null_mut();
                }
            }
        }
    }

    pub fn is_process_running(pid: u32) -> bool {
        unsafe {
            extern "system" {
                fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut std::ffi::c_void;
                fn GetExitCodeProcess(hProcess: *mut std::ffi::c_void, lpExitCode: *mut u32) -> i32;
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
    use std::sync::atomic::{AtomicI32, Ordering};

    pub struct ProcessTreeGuard {
        pgid: AtomicI32,
    }

    impl ProcessTreeGuard {
        pub fn new() -> Option<Self> {
            Some(Self {
                pgid: AtomicI32::new(0),
            })
        }

        pub fn assign_process(&self, pid: u32) -> bool {
            self.pgid.store(pid as i32, Ordering::SeqCst);
            true
        }

        pub fn terminate(&self, _exit_code: u32) -> bool {
            let pid = self.pgid.load(Ordering::SeqCst);
            if pid > 0 {
                // Send SIGTERM then SIGKILL to entire process group
                unsafe {
                    #[cfg(unix)]
                    {
                        libc::kill(-pid, libc::SIGTERM);
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
            let _ = self.terminate(1);
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
        }
    }
}

/// Scrub sensitive authentication tokens and credentials from environment map.
pub fn is_sensitive_credential_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();

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

    // 3. Redact :_authToken=<val> and other key-value credentials
    for key in &["_authtoken", "_authToken", "authtoken", "password", "secret", "token", "_auth"] {
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
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '\n' || c == '\r' || c == ';')
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

fn replace_kv_pairs(text: &str, key_name: &str) -> String {
    let mut out = String::new();
    let lower = text.to_ascii_lowercase();
    let pattern = format!("{key_name}=");
    let mut last_idx = 0;

    for (idx, _) in lower.match_indices(&pattern) {
        if idx < last_idx {
            continue;
        }
        let key_len = pattern.len();
        out.push_str(&text[last_idx..idx + key_len]);
        let remainder = &text[idx + key_len..];
        let end_token = remainder
            .find(|c: char| c.is_whitespace() || c == ';' || c == '&' || c == '"' || c == '\'' || c == '\n' || c == '\r')
            .unwrap_or(remainder.len());
        out.push_str("[REDACTED]");
        last_idx = idx + key_len + end_token;
    }
    out.push_str(&text[last_idx..]);
    out
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
        format!("{joined_custom_path}{}{existing_path}", if cfg!(windows) { ";" } else { ":" })
    };

    // Update all variations of PATH to avoid Windows case-sensitivity mismatches
    env.remove("Path");
    env.remove("path");
    env.insert("PATH".to_string(), final_path.clone());
    #[cfg(windows)]
    env.insert("Path".to_string(), final_path);

    // 4. Standard npm environment contract
    env.insert("INIT_CWD".to_string(), ctx.project_root.to_string_lossy().to_string());
    env.insert("npm_lifecycle_event".to_string(), ctx.event.clone());
    env.insert("npm_lifecycle_script".to_string(), ctx.script_cmd.clone());
    env.insert("npm_package_name".to_string(), ctx.package_name.clone());

    if let Some(ref ver) = ctx.package_version {
        env.insert("npm_package_version".to_string(), ver.clone());
    }

    let pkg_json = ctx.package_dir.join("package.json");
    env.insert("npm_package_json".to_string(), pkg_json.to_string_lossy().to_string());

    let node_str = node_bin.to_string_lossy().to_string();
    env.insert("NODE".to_string(), node_str.clone());
    env.insert("npm_node_execpath".to_string(), node_str);

    let rnpm_exec = ctx.npm_execpath.clone().unwrap_or_else(|| {
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rnpm"))
    });
    env.insert("npm_execpath".to_string(), rnpm_exec.to_string_lossy().to_string());

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

    let guard = process_guard::ProcessTreeGuard::new();

    let mut child = cmd.spawn()
        .with_context(|| format!("Failed to spawn lifecycle script for {}", ctx.package_name))?;

    #[cfg(windows)]
    if let Some(ref g) = guard {
        use std::os::windows::io::AsRawHandle;
        if !g.assign_process(child.as_raw_handle()) {
            warn!("Failed to assign process to Windows Job Object for {}", ctx.package_name);
        }
    }
    #[cfg(not(windows))]
    if let Some(ref g) = guard {
        g.assign_process(child.id());
    }

    let status = child.wait()
        .with_context(|| format!("Failed to wait for lifecycle script for {}", ctx.package_name))?;

    if !status.success() {
        warn!(
            "Lifecycle script '{}' failed for {} with exit code: {:?}",
            ctx.event, ctx.package_name, status.code()
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

    let guard = std::sync::Arc::new(process_guard::ProcessTreeGuard::new());

    let mut child = cmd.spawn()
        .with_context(|| format!("Failed to spawn lifecycle script for {}", ctx.package_name))?;

    #[cfg(windows)]
    if let Some(ref g) = *guard {
        use std::os::windows::io::AsRawHandle;
        if !g.assign_process(child.as_raw_handle()) {
            warn!("Failed to assign process to Windows Job Object for {}", ctx.package_name);
        }
    }
    #[cfg(not(windows))]
    if let Some(ref g) = *guard {
        g.assign_process(child.id());
    }

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
        sig = signal_fut => {
            warn!("Received {sig}; terminating lifecycle process tree for {pkg_name}");
            let exit_code = if sig == "SIGINT" { 130 } else { 143 };
            if let Some(ref g) = *guard_clone {
                g.terminate(exit_code);
            }
            cancel_guard.completed = true;
            return Err(anyhow::anyhow!("Lifecycle execution for {pkg_name} terminated by {sig}"));
        }
        _ = abort_fut => {
            warn!("Abort signal triggered; terminating lifecycle process tree for {pkg_name}");
            if let Some(ref g) = *guard_clone {
                g.terminate(143);
            }
            cancel_guard.completed = true;
            return Err(anyhow::anyhow!("Lifecycle execution for {pkg_name} aborted by signal"));
        }
    };

    // Guarantee cleanup of any remaining grandchild processes on exit
    if let Some(ref g) = *guard {
        g.terminate(0);
    }

    let status = status_res
        .with_context(|| format!("Failed to wait for lifecycle script for {}", ctx.package_name))?;

    if !status.success() {
        warn!(
            "Lifecycle script '{}' failed for {} with exit code: {:?}",
            ctx.event, ctx.package_name, status.code()
        );
    }

    Ok(status)
}

/// Spawns and executes a lifecycle script asynchronously, enforcing process-tree signal cleanup.
/// If cancelled or aborted by SIGINT/SIGTERM, runaway child processes are cleanly terminated immediately.
pub async fn execute_lifecycle_script_async(ctx: &LifecycleContext) -> Result<ExitStatus> {
    execute_lifecycle_script_with_abort(ctx, std::future::pending()).await
}

/// Executes dependency lifecycle scripts bottom-up (topologically), followed by root hooks,
/// with optional abort signal monitoring.
pub async fn execute_topological_with_abort(
    nodes: &[LifecyclePackageNode],
    root_manifest: &Manifest,
    opts: &LifecycleOptions,
    abort_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<()> {
    if opts.ignore_scripts {
        return Ok(());
    }

    // Check if already aborted
    if let Some(ref rx) = abort_rx {
        if *rx.borrow() {
            return Err(anyhow::anyhow!("Topological lifecycle execution aborted by signal"));
        }
    }

    // Topological sorting: leaf nodes first (bottom-up)
    let mut name_to_node: HashMap<String, &LifecyclePackageNode> = HashMap::new();
    for node in nodes {
        let name = node.manifest.name.clone().unwrap_or_else(|| node.package_path.clone());
        name_to_node.insert(name, node);
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
        visit(node, &name_to_node, &mut visited, &mut in_stack, &mut ordered);
    }

    // Execute dependency hooks in bottom-up order:
    // Hooks: preinstall -> install -> postinstall
    // Note: Registry dependencies NEVER run `prepare` per docs/lifecycle-contract.md!
    for node in ordered {
        let hooks = match node.source {
            PackageSource::Registry => &["preinstall", "install", "postinstall"][..],
            PackageSource::Local => &["preinstall", "install", "postinstall", "prepare"][..],
        };

        for &hook in hooks {
            if let Some(script_cmd) = node.manifest.scripts.get(hook) {
                if let Some(ref rx) = abort_rx {
                    if *rx.borrow() {
                        return Err(anyhow::anyhow!("Topological lifecycle execution aborted by signal"));
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
                    Ok(status) if status.success() => {},
                    Ok(status) => {
                        if node.optional {
                            let pkg_name = node.manifest.name.as_deref().unwrap_or("unknown");
                            let pkg_ver = node.manifest.version.as_deref().unwrap_or("unknown");
                            warn!(
                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: {}@{} ({}):",
                                pkg_name, pkg_ver, node.disk_path.display()
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
                                hook, node.manifest.name.as_deref().unwrap_or("unknown"), status.code()
                            ));
                        }
                    },
                    Err(e) => {
                        if node.optional {
                            let pkg_name = node.manifest.name.as_deref().unwrap_or("unknown");
                            let pkg_ver = node.manifest.version.as_deref().unwrap_or("unknown");
                            warn!(
                                "npm warn optional SKIPPING OPTIONAL DEPENDENCY: {}@{} ({}):",
                                pkg_name, pkg_ver, node.disk_path.display()
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
                    return Err(anyhow::anyhow!("Topological lifecycle execution aborted by signal"));
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
                    hook, status.code()
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

#[derive(Debug, Clone)]
pub struct WorkspaceRunOptions {
    pub script: String,
    pub args: Vec<String>,
    pub ignore_scripts: bool,
    pub if_present: bool,
    pub filter_members: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct WorkspaceRunSummary {
    pub executed_packages: Vec<String>,
    pub skipped_packages: Vec<String>,
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

    let mut name_to_member: HashMap<&str, &WorkspaceScriptMember> = HashMap::new();
    for m in members {
        name_to_member.insert(m.name.as_str(), m);
    }

    let mut summary = WorkspaceRunSummary::default();
    let mut executed_or_skipped: HashSet<String> = HashSet::new();

    // 1. Run members in explicit topological order
    for pkg_name in topological_order {
        if let Some(ref rx) = abort_rx {
            if *rx.borrow() {
                return Err(anyhow::anyhow!("Workspace execution aborted by signal"));
            }
        }

        if let Some(ref filter) = opts.filter_members {
            if !filter.iter().any(|f| f == pkg_name) {
                continue;
            }
        }

        if let Some(member) = name_to_member.get(pkg_name.as_str()) {
            executed_or_skipped.insert(pkg_name.clone());
            if let Some(cmd) = member.manifest.scripts.get(&opts.script) {
                let full_cmd = if opts.args.is_empty() {
                    cmd.clone()
                } else {
                    format!("{cmd} {}", opts.args.join(" "))
                };

                println!(
                    "\n> {}@{} {} {}",
                    member.name,
                    member.manifest.version.as_deref().unwrap_or("0.0.0"),
                    opts.script,
                    member.path.display()
                );
                println!("> {full_cmd}\n");

                let mut ctx = LifecycleContext::new(
                    root_dir,
                    &member.path,
                    &member.name,
                    &opts.script,
                    &full_cmd,
                );
                ctx.package_version = member.manifest.version.clone();

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
                    let code = status.code().unwrap_or(1);
                    return Err(anyhow::anyhow!(
                        "Workspace member '{}' script '{}' exited with status code: {}",
                        member.name,
                        opts.script,
                        code
                    ));
                }
                summary.executed_packages.push(member.name.clone());
            } else {
                if opts.if_present || opts.filter_members.is_none() {
                    debug!(
                        "Skipping package '{}': script '{}' not found",
                        member.name, opts.script
                    );
                    summary.skipped_packages.push(member.name.clone());
                } else {
                    return Err(anyhow::anyhow!(
                        "rnpm ERR! missing script: {} in workspace package {}",
                        opts.script,
                        member.name
                    ));
                }
            }
        }
    }

    // 2. Run any members not covered in topological_order
    for member in members {
        if let Some(ref rx) = abort_rx {
            if *rx.borrow() {
                return Err(anyhow::anyhow!("Workspace execution aborted by signal"));
            }
        }

        if executed_or_skipped.contains(&member.name) {
            continue;
        }
        if let Some(ref filter) = opts.filter_members {
            if !filter.iter().any(|f| f == &member.name) {
                continue;
            }
        }

        if let Some(cmd) = member.manifest.scripts.get(&opts.script) {
            let full_cmd = if opts.args.is_empty() {
                cmd.clone()
            } else {
                format!("{cmd} {}", opts.args.join(" "))
            };

            println!(
                "\n> {}@{} {} {}",
                member.name,
                member.manifest.version.as_deref().unwrap_or("0.0.0"),
                opts.script,
                member.path.display()
            );
            println!("> {full_cmd}\n");

            let mut ctx = LifecycleContext::new(
                root_dir,
                &member.path,
                &member.name,
                &opts.script,
                &full_cmd,
            );
            ctx.package_version = member.manifest.version.clone();

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
                let code = status.code().unwrap_or(1);
                return Err(anyhow::anyhow!(
                    "Workspace member '{}' script '{}' exited with status code: {}",
                    member.name,
                    opts.script,
                    code
                ));
            }
            summary.executed_packages.push(member.name.clone());
        } else if opts.if_present || opts.filter_members.is_none() {
            debug!(
                "Skipping package '{}': script '{}' not found",
                member.name, opts.script
            );
            summary.skipped_packages.push(member.name.clone());
        } else {
            return Err(anyhow::anyhow!(
                "rnpm ERR! missing script: {} in workspace package {}",
                opts.script,
                member.name
            ));
        }
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
    execute_workspace_scripts_topological_with_abort(root_dir, members, topological_order, opts, None).await
}
