use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;
use crate::env::scrub_text;
use crate::error::LifecycleError;

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

#[cfg(windows)]
mod windows_job {
    use std::io;

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
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
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

    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;

    unsafe extern "system" {
        fn CreateJobObjectW(lp_job_attributes: *mut std::ffi::c_void, lp_name: *const u16) -> *mut std::ffi::c_void;
        fn SetInformationJobObject(
            h_job: *mut std::ffi::c_void,
            job_object_info_class: i32,
            lp_job_object_info: *const std::ffi::c_void,
            cb_job_object_info_length: u32,
        ) -> i32;
        fn AssignProcessToJobObject(h_job: *mut std::ffi::c_void, h_process: *mut std::ffi::c_void) -> i32;
        fn CloseHandle(h_object: *mut std::ffi::c_void) -> i32;
    }

    pub struct JobObject {
        handle: *mut std::ffi::c_void,
    }

    // Safety: JobObject handle can be sent across threads
    unsafe impl Send for JobObject {}
    unsafe impl Sync for JobObject {}

    impl JobObject {
        pub fn new() -> io::Result<Self> {
            unsafe {
                let h = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
                if h.is_null() {
                    return Err(io::Error::last_os_error());
                }

                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

                let ret = SetInformationJobObject(
                    h,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    &info as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );

                if ret == 0 {
                    let err = io::Error::last_os_error();
                    CloseHandle(h);
                    return Err(err);
                }

                Ok(Self { handle: h })
            }
        }

        pub fn assign_process(&self, raw_h: std::os::windows::io::RawHandle) -> io::Result<()> {
            unsafe {
                let ret = AssignProcessToJobObject(self.handle, raw_h as *mut std::ffi::c_void);
                if ret == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            }
        }
    }

    impl Drop for JobObject {
        fn drop(&mut self) {
            unsafe {
                if !self.handle.is_null() {
                    CloseHandle(self.handle);
                }
            }
        }
    }
}

/// Spawns and executes a script command using the platform shell:
/// - Windows: `cmd.exe /d /s /c "<script>"`
/// - Unix: `/bin/sh -c "<script>"`
pub async fn execute_shell_command(
    command_str: &str,
    script_name: &str,
    package_dir: &Path,
    env: &BTreeMap<String, String>,
    capture_output: bool,
) -> Result<ScriptOutput, LifecycleError> {
    #[cfg(windows)]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        let mut c = tokio::process::Command::new("cmd.exe");
        c.as_std_mut().raw_arg(format!("/d /s /c \"{}\"", command_str));
        c
    };

    #[cfg(not(windows))]
    let mut cmd = {
        use std::os::unix::process::CommandExt;
        let mut c = tokio::process::Command::new("/bin/sh");
        c.args(["-c", command_str]);
        // Section 6.2: distinct process group
        c.process_group(0);
        c
    };

    cmd.current_dir(package_dir);
    cmd.envs(env);

    if capture_output {
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
    } else {
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
    }

    #[cfg(windows)]
    let job_guard = windows_job::JobObject::new().ok();

    let mut child = cmd.spawn().map_err(|err| LifecycleError::Io {
        path: package_dir.to_path_buf(),
        source: err,
    })?;

    #[cfg(windows)]
    {
        if let (Some(ref job), Some(raw_h)) = (job_guard.as_ref(), child.raw_handle()) {
            let _ = job.assign_process(raw_h);
        }
    }

    if capture_output {
        let output = child.wait_with_output().await.map_err(|err| LifecycleError::Io {
            path: package_dir.to_path_buf(),
            source: err,
        })?;

        let raw_stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let raw_stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Filter credentials from logs / output
        let stdout = scrub_text(&raw_stdout);
        let stderr = scrub_text(&raw_stderr);
        let exit_code = output.status.code().unwrap_or(-1);

        if output.status.success() {
            Ok(ScriptOutput {
                exit_code,
                stdout,
                stderr,
            })
        } else {
            Err(LifecycleError::ExecutionFailed {
                script_name: script_name.to_string(),
                exit_code: Some(exit_code),
                stdout,
                stderr,
            })
        }
    } else {
        let status = child.wait().await.map_err(|err| LifecycleError::Io {
            path: package_dir.to_path_buf(),
            source: err,
        })?;

        let exit_code = status.code().unwrap_or(-1);
        if status.success() {
            Ok(ScriptOutput {
                exit_code,
                stdout: String::new(),
                stderr: String::new(),
            })
        } else {
            Err(LifecycleError::ExecutionFailed {
                script_name: script_name.to_string(),
                exit_code: Some(exit_code),
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }
}
