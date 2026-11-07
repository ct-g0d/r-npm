//! `rnpm doctor` and `rnpm doctor perf` command implementation and diagnostics.
//!
//! Provides comprehensive diagnostics for:
//! 1. Dev Drive status (distinguishing true Dev Drive ReFS volumes from plain ReFS volumes).
//! 2. Cross-volume block cloning compatibility (`FSCTL_DUPLICATE_EXTENTS_TO_FILE`).
//! 3. Disk seek penalty detection (HDD vs SSD/NVMe) via `rnpm_fs`.
//! 4. Windows Defender real-time protection, Dev Drive Performance Mode (0 = Enabled, 1 = Disabled), and exclusion parsing.
//! 5. Standard npm/rnpm environment and project health checks.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub volume_path: String,
    pub volume_name: String,
    pub file_system: String,
    pub serial_number: u32,
    pub is_dev_drive: bool,
    pub supports_block_cloning: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefenderInfo {
    pub real_time_protection: Option<bool>,
    pub dev_drive_performance_mode: Option<bool>,
    pub has_exclusions: Option<bool>,
    pub status_source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticLevel {
    Ok,
    Warn,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticItem {
    pub level: DiagnosticLevel,
    pub category: String,
    pub title: String,
    pub message: String,
    pub advice: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfDiagnosticReport {
    pub project_path: PathBuf,
    pub store_path: PathBuf,
    pub project_volume: Option<VolumeInfo>,
    pub store_volume: Option<VolumeInfo>,
    pub same_volume: bool,
    pub block_cloning_supported: bool,
    pub project_seek_penalty: Option<bool>,
    pub store_seek_penalty: Option<bool>,
    pub defender: DefenderInfo,
    pub items: Vec<DiagnosticItem>,
    pub recommendations: Vec<String>,
}

/// Query Windows volume information for a given path.
#[cfg(windows)]
pub fn query_volume_info(path: &Path) -> Option<VolumeInfo> {
    use std::os::windows::ffi::OsStrExt;

    let abs_path = if path.is_relative() {
        std::env::current_dir().ok()?.join(path)
    } else {
        path.to_path_buf()
    };

    let path_wide: Vec<u16> = abs_path.as_os_str().encode_wide().chain(Some(0)).collect();

    let mut vol_path_buf = [0u16; 512];
    let ok = unsafe {
        GetVolumePathNameW(
            path_wide.as_ptr(),
            vol_path_buf.as_mut_ptr(),
            vol_path_buf.len() as u32,
        )
    };
    if ok == 0 {
        return None;
    }

    let vol_path_len = vol_path_buf
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(vol_path_buf.len());
    let volume_path = String::from_utf16_lossy(&vol_path_buf[..vol_path_len]);

    let mut vol_name_buf = [0u16; 512];
    let mut fs_name_buf = [0u16; 512];
    let mut serial_number = 0u32;
    let mut max_component_len = 0u32;
    let mut fs_flags = 0u32;

    let info_ok = unsafe {
        GetVolumeInformationW(
            vol_path_buf.as_ptr(),
            vol_name_buf.as_mut_ptr(),
            vol_name_buf.len() as u32,
            &mut serial_number,
            &mut max_component_len,
            &mut fs_flags,
            fs_name_buf.as_mut_ptr(),
            fs_name_buf.len() as u32,
        )
    };
    if info_ok == 0 {
        return None;
    }

    let vol_name_len = vol_name_buf
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(vol_name_buf.len());
    let volume_name = String::from_utf16_lossy(&vol_name_buf[..vol_name_len]);

    let fs_name_len = fs_name_buf
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(fs_name_buf.len());
    let file_system = String::from_utf16_lossy(&fs_name_buf[..fs_name_len]);

    // ReFS volumes support block cloning (FSCTL_DUPLICATE_EXTENTS_TO_FILE).
    // FILE_SUPPORTS_BLOCK_REFCOUNTING flag is 0x08000000.
    const FILE_SUPPORTS_BLOCK_REFCOUNTING: u32 = 0x08000000;
    let is_refs = file_system.eq_ignore_ascii_case("ReFS");
    let is_dev_drive = is_refs && query_is_dev_drive(&volume_path);
    let supports_block_cloning = is_refs || (fs_flags & FILE_SUPPORTS_BLOCK_REFCOUNTING) != 0;

    Some(VolumeInfo {
        volume_path,
        volume_name,
        file_system,
        serial_number,
        is_dev_drive,
        supports_block_cloning,
    })
}

/// Query whether a volume is a true Dev Drive.
///
/// On Windows, a Dev Drive is formatted as ReFS and has the persistent volume state flag
/// `PERSISTENT_VOLUME_STATE_DEV_VOLUME` (0x2000) queried via `FSCTL_QUERY_PERSISTENT_VOLUME_STATE`.
/// Fallback checks `fsutil devdrv query <drive>` or PowerShell `(Get-Volume -DriveLetter <x>).DevDrive`.
#[cfg(windows)]
pub fn query_is_dev_drive(volume_path: &str) -> bool {
    use std::os::windows::ffi::OsStrExt;

    let trimmed = volume_path.trim_end_matches('\\').trim_end_matches('/');
    let dev_path = if let Some(stripped) = trimmed.strip_prefix(r"\\?\") {
        format!(r"\\.\{}", stripped)
    } else if trimmed.len() == 2 && trimmed.ends_with(':') {
        format!(r"\\.\{}", trimmed)
    } else if let Some(drive) = trimmed.chars().next() {
        if trimmed.chars().nth(1) == Some(':') {
            format!(r"\\.\{drive}:")
        } else {
            trimmed.to_string()
        }
    } else {
        trimmed.to_string()
    };

    let dev_path_wide: Vec<u16> = std::ffi::OsStr::new(&dev_path)
        .encode_wide()
        .chain(Some(0))
        .collect();

    extern "system" {
        fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *mut std::ffi::c_void,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: *mut std::ffi::c_void,
        ) -> *mut std::ffi::c_void;

        fn DeviceIoControl(
            hDevice: *mut std::ffi::c_void,
            dwIoControlCode: u32,
            lpInBuffer: *const std::ffi::c_void,
            nInBufferSize: u32,
            lpOutBuffer: *mut std::ffi::c_void,
            nOutBufferSize: u32,
            lpBytesReturned: *mut u32,
            lpOverlapped: *mut std::ffi::c_void,
        ) -> i32;

        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    }

    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const FILE_SHARE_DELETE: u32 = 4;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
    const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;

    const FSCTL_QUERY_PERSISTENT_VOLUME_STATE: u32 = 0x0009023C;
    const PERSISTENT_VOLUME_STATE_DEV_VOLUME: u32 = 0x00002000;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct FILE_FS_PERSISTENT_VOLUME_INFORMATION {
        VolumeFlags: u32,
        FlagMask: u32,
        Version: u32,
        Reserved: u32,
    }

    let handle = unsafe {
        CreateFileW(
            dev_path_wide.as_ptr(),
            0x80, // FILE_READ_ATTRIBUTES
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };

    let handle = if handle == INVALID_HANDLE_VALUE {
        unsafe {
            CreateFileW(
                dev_path_wide.as_ptr(),
                0, // dwDesiredAccess = 0
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        }
    } else {
        handle
    };

    if handle != INVALID_HANDLE_VALUE {
        let in_info = FILE_FS_PERSISTENT_VOLUME_INFORMATION {
            VolumeFlags: 0,
            FlagMask: PERSISTENT_VOLUME_STATE_DEV_VOLUME,
            Version: 1,
            Reserved: 0,
        };
        let mut out_info = FILE_FS_PERSISTENT_VOLUME_INFORMATION {
            VolumeFlags: 0,
            FlagMask: 0,
            Version: 0,
            Reserved: 0,
        };
        let mut bytes_returned = 0u32;

        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_QUERY_PERSISTENT_VOLUME_STATE,
                &in_info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<FILE_FS_PERSISTENT_VOLUME_INFORMATION>() as u32,
                &mut out_info as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<FILE_FS_PERSISTENT_VOLUME_INFORMATION>() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };
        unsafe {
            CloseHandle(handle);
        }

        if ok != 0 {
            return (out_info.VolumeFlags & PERSISTENT_VOLUME_STATE_DEV_VOLUME) != 0;
        }
    }

    // Fallback: check via fsutil devdrv query <drive> or PowerShell (Get-Volume -DriveLetter <x>).DevDrive
    if let Some(drive_letter) = trimmed.chars().next() {
        if trimmed.chars().nth(1) == Some(':') {
            if let Ok(output) = std::process::Command::new("fsutil")
                .args(["devdrv", "query", &format!("{drive_letter}:")])
                .output()
            {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
                    if text.contains("developer volume: yes")
                        || text.contains("is a dev drive: yes")
                        || text.contains("is a developer volume: yes")
                        || (text.contains("developer volume")
                            && !text.contains("not a developer volume"))
                    {
                        return true;
                    }
                }
            }

            let ps_cmd = format!(
                "& {{ try {{ $v = Get-Volume -DriveLetter {drive_letter} -ErrorAction Stop; [bool]$v.DevDrive }} catch {{ $false }} }}"
            );
            if let Ok(output) = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
                .output()
            {
                let text = String::from_utf8_lossy(&output.stdout);
                if text.trim().eq_ignore_ascii_case("true") {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(not(windows))]
pub fn query_is_dev_drive(_volume_path: &str) -> bool {
    false
}

#[cfg(not(windows))]
pub fn query_volume_info(path: &Path) -> Option<VolumeInfo> {
    let _ = path;
    Some(VolumeInfo {
        volume_path: "/".to_string(),
        volume_name: String::new(),
        file_system: "POSIX".to_string(),
        serial_number: 0,
        is_dev_drive: false,
        supports_block_cloning: false,
    })
}

#[cfg(windows)]
extern "system" {
    fn GetVolumePathNameW(
        lpszFileName: *const u16,
        lpszVolumePathName: *mut u16,
        cchBufferLength: u32,
    ) -> i32;

    fn GetVolumeInformationW(
        lpRootPathName: *const u16,
        lpVolumeNameBuffer: *mut u16,
        nVolumeNameSize: u32,
        lpVolumeSerialNumber: *mut u32,
        lpMaximumComponentLength: *mut u32,
        lpFileSystemFlags: *mut u32,
        lpFileSystemNameBuffer: *mut u16,
        nFileSystemNameSize: u32,
    ) -> i32;
}

/// Validate whether an exclusion path string is non-empty and not a placeholder/permission message.
pub fn is_valid_exclusion_path(path: &str) -> bool {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("n/a")
        || lower.contains("administrator")
        || lower.contains("placeholder")
        || lower.contains("access denied")
        || lower.contains("not available")
    {
        return false;
    }
    true
}

/// Parse Defender exclusions from JSON value, ignoring nulls and placeholder objects.
pub fn parse_defender_exclusions(val: &serde_json::Value) -> Option<bool> {
    match val {
        serde_json::Value::Array(items) => {
            let valid_count = items
                .iter()
                .filter_map(|item| item.as_str())
                .filter(|s| is_valid_exclusion_path(s))
                .count();
            Some(valid_count > 0)
        }
        serde_json::Value::String(s) => Some(is_valid_exclusion_path(s)),
        serde_json::Value::Bool(b) => Some(*b),
        serde_json::Value::Null => Some(false),
        _ => None,
    }
}

/// Query Windows Defender real-time protection, Dev Drive performance mode, and exclusion state.
pub fn query_defender_info() -> DefenderInfo {
    #[cfg(windows)]
    {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let cmd = "& { try { $s = Get-MpComputerStatus; $p = Get-MpPreference; $excl = if ($p.ExclusionPath) { @($p.ExclusionPath) } else { @() }; @{ RealTime = [bool]$s.RealTimeProtectionEnabled; PerfMode = [int]$p.PerformanceModeStatus; Excl = $excl } | ConvertTo-Json -Compress } catch { @{ Error = 'unavailable' } | ConvertTo-Json -Compress } }";
            let res = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", cmd])
                .output();
            let _ = tx.send(res);
        });

        if let Ok(Ok(output)) = rx.recv_timeout(std::time::Duration::from_millis(3000)) {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(stdout.trim()) {
                    let real_time = val.get("RealTime").and_then(|v| v.as_bool());
                    // In Microsoft Defender documentation:
                    // 0 = Enabled (Performance Mode active on Dev Drives)
                    // 1 = Disabled
                    // 2 = Not Supported
                    let perf_mode =
                        val.get("PerfMode")
                            .and_then(|v| v.as_i64())
                            .and_then(|m| match m {
                                0 => Some(true),
                                1 => Some(false),
                                _ => None,
                            });
                    let excl = parse_defender_exclusions(
                        val.get("Excl").unwrap_or(&serde_json::Value::Null),
                    );
                    if real_time.is_some() || perf_mode.is_some() || excl.is_some() {
                        return DefenderInfo {
                            real_time_protection: real_time,
                            dev_drive_performance_mode: perf_mode,
                            has_exclusions: excl,
                            status_source: "PowerShell Defender cmdlets".to_string(),
                        };
                    }
                }
            }
        }

        DefenderInfo {
            real_time_protection: None,
            dev_drive_performance_mode: None,
            has_exclusions: None,
            status_source: "Unavailable or query timed out".to_string(),
        }
    }

    #[cfg(not(windows))]
    {
        DefenderInfo {
            real_time_protection: None,
            dev_drive_performance_mode: None,
            has_exclusions: None,
            status_source: "Non-Windows platform".to_string(),
        }
    }
}

/// Evaluates machine performance diagnostics given project and package store configuration.
pub fn evaluate_perf_diagnostics(
    project_path: &Path,
    store_path: &Path,
    project_volume: Option<VolumeInfo>,
    store_volume: Option<VolumeInfo>,
    project_seek_penalty: Option<bool>,
    store_seek_penalty: Option<bool>,
    defender: DefenderInfo,
) -> PerfDiagnosticReport {
    let mut items = Vec::new();
    let mut recommendations = Vec::new();

    // 1. Dev Drive - Project directory
    let proj_dev = project_volume
        .as_ref()
        .map(|v| v.is_dev_drive)
        .unwrap_or(false);
    let proj_fs = project_volume
        .as_ref()
        .map(|v| v.file_system.as_str())
        .unwrap_or("Unknown");
    let proj_vol_path = project_volume
        .as_ref()
        .map(|v| v.volume_path.as_str())
        .unwrap_or("");

    if proj_dev {
        items.push(DiagnosticItem {
            level: DiagnosticLevel::Ok,
            category: "Dev Drive".to_string(),
            title: "Project Dev Drive Status".to_string(),
            message: format!(
                "[OK] Dev Drive (ReFS) (volume: {}). Asynchronous Defender scanning and block cloning are enabled.",
                proj_vol_path
            ),
            advice: None,
        });
    } else if proj_fs.eq_ignore_ascii_case("ReFS") {
        let advice = "To convert or create a true Dev Drive (requires Windows 11 & >= 50 GB free space on SSD):\n  Open Settings > System > Storage > Disks & volumes > Create dev drive";
        items.push(DiagnosticItem {
            level: DiagnosticLevel::Warn,
            category: "Dev Drive".to_string(),
            title: "Project Dev Drive Status".to_string(),
            message: format!(
                "Project directory is on a plain ReFS volume ({}), not a Dev Drive. While block cloning is supported, Windows Defender Performance Mode only applies to trusted Dev Drive volumes.",
                project_path.display()
            ),
            advice: Some(advice.to_string()),
        });
        recommendations.push("Move active project to a true Dev Drive (ReFS) on SSD to enable Defender Performance Mode.".to_string());
    } else {
        let advice = "To create a Dev Drive (requires Windows 11 & >= 50 GB free space on SSD):\n  Open Settings > System > Storage > Disks & volumes > Create dev drive";
        items.push(DiagnosticItem {
            level: DiagnosticLevel::Warn,
            category: "Dev Drive".to_string(),
            title: "Project Dev Drive Status".to_string(),
            message: format!(
                "Project directory is on {} ({}), not a Dev Drive (ReFS). Dev Drive provides up to 5x faster file operations via block cloning and Defender Performance Mode.",
                proj_fs,
                project_path.display()
            ),
            advice: Some(advice.to_string()),
        });
        recommendations.push(
            "Move active project to a Dev Drive (ReFS) on SSD for up to 5x faster installs."
                .to_string(),
        );
    }

    // 2. Dev Drive - Package store
    let store_dev = store_volume
        .as_ref()
        .map(|v| v.is_dev_drive)
        .unwrap_or(false);
    let store_fs = store_volume
        .as_ref()
        .map(|v| v.file_system.as_str())
        .unwrap_or("Unknown");
    let store_vol_path = store_volume
        .as_ref()
        .map(|v| v.volume_path.as_str())
        .unwrap_or("");

    if store_dev {
        items.push(DiagnosticItem {
            level: DiagnosticLevel::Ok,
            category: "Dev Drive".to_string(),
            title: "Package Store Dev Drive Status".to_string(),
            message: format!("[OK] Dev Drive (ReFS) (volume: {}).", store_vol_path),
            advice: None,
        });
    } else if store_fs.eq_ignore_ascii_case("ReFS") {
        let advice = "Dev Drive enables Windows Defender Performance Mode for package stores.\nTo create a Dev Drive:\n  Open Settings > System > Storage > Disks & volumes > Create dev drive";
        items.push(DiagnosticItem {
            level: DiagnosticLevel::Warn,
            category: "Dev Drive".to_string(),
            title: "Package Store Dev Drive Status".to_string(),
            message: format!(
                "Package store is on a plain ReFS volume ({}), not a Dev Drive.",
                store_path.display()
            ),
            advice: Some(advice.to_string()),
        });
        recommendations.push(
            "Move package store to a true Dev Drive (ReFS) for full Defender optimization."
                .to_string(),
        );
    } else {
        let advice = "Set the RNPM_STORE_DIR environment variable to a directory on your Dev Drive to place packages on ReFS.";
        items.push(DiagnosticItem {
            level: DiagnosticLevel::Warn,
            category: "Dev Drive".to_string(),
            title: "Package Store Dev Drive Status".to_string(),
            message: format!(
                "Package store is on {} ({}), not a Dev Drive (ReFS).",
                store_fs,
                store_path.display()
            ),
            advice: Some(advice.to_string()),
        });
        recommendations.push("Configure RNPM_STORE_DIR on your Dev Drive to enable block cloning from store to project.".to_string());
    }

    // 3. Same volume and block cloning
    let same_volume = match (&project_volume, &store_volume) {
        (Some(p), Some(s)) => {
            if p.serial_number != 0 && s.serial_number != 0 {
                p.serial_number == s.serial_number
            } else {
                p.volume_path.eq_ignore_ascii_case(&s.volume_path)
            }
        }
        _ => false,
    };

    let block_cloning_supported = same_volume
        && project_volume
            .as_ref()
            .map(|v| v.supports_block_cloning)
            .unwrap_or(false)
        && store_volume
            .as_ref()
            .map(|v| v.supports_block_cloning)
            .unwrap_or(false);

    if block_cloning_supported {
        let vol_desc = if proj_dev {
            "Dev Drive (ReFS volume)"
        } else {
            "ReFS volume"
        };
        items.push(DiagnosticItem {
            level: DiagnosticLevel::Ok,
            category: "Volume / Block Cloning".to_string(),
            title: "Zero-Cost Block Cloning".to_string(),
            message: format!("Both project and package store reside on the same {vol_desc}. Zero-cost block cloning (FSCTL_DUPLICATE_EXTENTS_TO_FILE) is fully supported!"),
            advice: None,
        });
    } else if !same_volume {
        let advice = format!(
            "Move either the project or the package store so both reside on the same ReFS volume.\n  Store location can be overridden via: $env:RNPM_STORE_DIR = \"{}\\rnpm-store\"",
            if proj_vol_path.is_empty() { "C:" } else { proj_vol_path.trim_end_matches('\\') }
        );
        items.push(DiagnosticItem {
            level: DiagnosticLevel::Warn,
            category: "Volume / Block Cloning".to_string(),
            title: "Cross-Volume Store and Project".to_string(),
            message: format!(
                "Project volume ('{}') and store volume ('{}') are different. Cross-volume block cloning is not supported by Windows; file copying or junction linking is used instead.",
                proj_vol_path, store_vol_path
            ),
            advice: Some(advice),
        });
        recommendations.push("Co-locate package store and projects on the same Dev Drive volume for zero-copy block cloning.".to_string());
    } else {
        items.push(DiagnosticItem {
            level: DiagnosticLevel::Warn,
            category: "Volume / Block Cloning".to_string(),
            title: "Block Cloning Unavailable".to_string(),
            message: format!(
                "Project and package store are on the same volume ({}), but filesystem is {} (requires ReFS for block cloning).",
                proj_vol_path, proj_fs
            ),
            advice: Some("Dev Drive (ReFS) is required for FSCTL_DUPLICATE_EXTENTS_TO_FILE block cloning.".to_string()),
        });
    }

    // 4. Seek Penalty / Disk Speed
    match project_seek_penalty {
        Some(true) => {
            let advice = "Move active projects to an NVMe SSD (e.g. C:) or a Dev Drive.\n  rnpm automatically selects an HDD-tuned writer profile (sequential 4-thread writing) on this volume to minimize head thrashing.";
            items.push(DiagnosticItem {
                level: DiagnosticLevel::Warn,
                category: "Disk Speed".to_string(),
                title: "Project Disk Speed (Seek Penalty Detected)".to_string(),
                message: format!(
                    "Project directory is located on a rotational seek-penalty disk (HDD, e.g. 5400rpm drive on {}). Rotational seek latency severely impairs node_modules materialization.",
                    proj_vol_path
                ),
                advice: Some(advice.to_string()),
            });
            recommendations.push("Move active project from HDD to NVMe SSD (or Dev Drive) to eliminate rotational seek overhead.".to_string());
        }
        Some(false) => {
            items.push(DiagnosticItem {
                level: DiagnosticLevel::Ok,
                category: "Disk Speed".to_string(),
                title: "Project Disk Speed".to_string(),
                message: "Project is on a solid-state disk (SSD/NVMe, no seek penalty). Dedicated parallel writer pool (24-32 threads) is active.".to_string(),
                advice: None,
            });
        }
        None => {
            items.push(DiagnosticItem {
                level: DiagnosticLevel::Info,
                category: "Disk Speed".to_string(),
                title: "Project Disk Speed".to_string(),
                message: "Disk seek penalty query not supported on this platform or drive type."
                    .to_string(),
                advice: None,
            });
        }
    }

    if let Some(store_seek) = store_seek_penalty {
        if store_seek {
            items.push(DiagnosticItem {
                level: DiagnosticLevel::Warn,
                category: "Disk Speed".to_string(),
                title: "Package Store Disk Speed".to_string(),
                message: format!("Package store ({}) is on an HDD with seek penalty.", store_path.display()),
                advice: Some("Point RNPM_STORE_DIR to an SSD/NVMe volume for faster tarball unpacking and caching.".to_string()),
            });
            recommendations.push(
                "Move package store to an SSD/NVMe volume to accelerate cache unpacks.".to_string(),
            );
        } else {
            items.push(DiagnosticItem {
                level: DiagnosticLevel::Ok,
                category: "Disk Speed".to_string(),
                title: "Package Store Disk Speed".to_string(),
                message: "Package store is on an SSD/NVMe volume (no seek penalty).".to_string(),
                advice: None,
            });
        }
    }

    // 5. Windows Defender Status
    match defender.real_time_protection {
        Some(true) => {
            if proj_dev {
                if defender.dev_drive_performance_mode == Some(true) {
                    items.push(DiagnosticItem {
                        level: DiagnosticLevel::Ok,
                        category: "Windows Defender".to_string(),
                        title: "Defender Dev Drive Performance Mode".to_string(),
                        message: "Defender Dev Drive Performance Mode is ENABLED. Scanning on Dev Drive volumes runs asynchronously in the background without blocking file writes.".to_string(),
                        advice: None,
                    });
                } else {
                    let advice = "Enable Defender Performance Mode for Dev Drive by running in an elevated PowerShell:\n  Set-MpPreference -PerformanceModeStatus 0\nOr trust the Dev Drive:\n  fsutil devdrv trust <drive>";
                    items.push(DiagnosticItem {
                        level: DiagnosticLevel::Warn,
                        category: "Windows Defender".to_string(),
                        title: "Defender Dev Drive Performance Mode Disabled".to_string(),
                        message: "Project is on a Dev Drive, but Defender Dev Drive Performance Mode is not enabled.".to_string(),
                        advice: Some(advice.to_string()),
                    });
                    recommendations.push("Enable Defender Dev Drive Performance Mode via 'Set-MpPreference -PerformanceModeStatus 0' (or 'fsutil devdrv trust <drive>').".to_string());
                }
            } else {
                let fs_label = if proj_fs.eq_ignore_ascii_case("ReFS") {
                    "plain ReFS (non-Dev Drive)"
                } else {
                    "NTFS"
                };
                let advice = format!(
                    "Defender intercepts file writes on {} synchronously (MsMpEng.exe). Options to reduce overhead:\n1. (Recommended) Create and use a Dev Drive (ReFS) where Defender Performance Mode scans asynchronously without blocking writes.\n2. (Security tradeoff) Add folder exclusions in an elevated PowerShell:\n  Add-MpPreference -ExclusionPath \"{}\\node_modules\"\n  Add-MpPreference -ExclusionPath \"{}\"",
                    fs_label,
                    project_path.display(),
                    store_path.display()
                );
                items.push(DiagnosticItem {
                    level: DiagnosticLevel::Warn,
                    category: "Windows Defender".to_string(),
                    title: "Windows Defender Real-Time Protection Active".to_string(),
                    message: format!(
                        "Defender real-time protection is ACTIVE and synchronously intercepts file writes on {}. Dev Drive Performance Mode only applies to trusted Dev Drive volumes. This can account for >50% of fresh install latency.",
                        fs_label
                    ),
                    advice: Some(advice),
                });
                recommendations.push("Use a Dev Drive or configure Defender exclusions to avoid synchronous scanning overhead.".to_string());
            }

            if defender.has_exclusions == Some(true) {
                items.push(DiagnosticItem {
                    level: DiagnosticLevel::Info,
                    category: "Windows Defender".to_string(),
                    title: "Defender Exclusions".to_string(),
                    message: "Windows Defender has active exclusions configured.".to_string(),
                    advice: None,
                });
            }
        }
        Some(false) => {
            items.push(DiagnosticItem {
                level: DiagnosticLevel::Info,
                category: "Windows Defender".to_string(),
                title: "Windows Defender Real-Time Protection".to_string(),
                message: "Windows Defender real-time protection is DISABLED.".to_string(),
                advice: None,
            });
        }
        None => {
            items.push(DiagnosticItem {
                level: DiagnosticLevel::Info,
                category: "Windows Defender".to_string(),
                title: "Windows Defender Status".to_string(),
                message: format!("Defender query source: {}.", defender.status_source),
                advice: None,
            });
        }
    }

    PerfDiagnosticReport {
        project_path: project_path.to_path_buf(),
        store_path: store_path.to_path_buf(),
        project_volume,
        store_volume,
        same_volume,
        block_cloning_supported,
        project_seek_penalty,
        store_seek_penalty,
        defender,
        items,
        recommendations,
    }
}

/// Format the performance diagnostic report into human-readable console output.
pub fn format_perf_report_text(report: &PerfDiagnosticReport) -> String {
    let mut out = String::new();
    out.push_str("rnpm doctor perf - Machine Configuration & Performance Diagnostics\n");
    out.push_str("=================================================================\n\n");

    out.push_str(&format!(
        "  Project Directory : {}\n",
        report.project_path.display()
    ));
    out.push_str(&format!(
        "  Package Store     : {}\n\n",
        report.store_path.display()
    ));

    let mut current_cat = "";
    for item in &report.items {
        if item.category != current_cat {
            current_cat = &item.category;
            out.push_str(&format!("[{}]\n", current_cat));
        }

        let prefix = match item.level {
            DiagnosticLevel::Ok => "  [OK]  ",
            DiagnosticLevel::Warn => "  [WARN]",
            DiagnosticLevel::Info => "  [INFO]",
        };

        out.push_str(&format!("{} {}: {}\n", prefix, item.title, item.message));
        if let Some(ref advice) = item.advice {
            for line in advice.lines() {
                out.push_str(&format!("          {}\n", line));
            }
        }
        out.push('\n');
    }

    out.push_str("Actionable Recommendations:\n");
    out.push_str("--------------------------\n");
    if report.recommendations.is_empty() {
        out.push_str(
            "  (None! Your machine configuration is fully optimized for rnpm 5x performance.)\n",
        );
    } else {
        for (i, rec) in report.recommendations.iter().enumerate() {
            out.push_str(&format!("  {}. {}\n", i + 1, rec));
        }
    }
    out.push('\n');

    out.push_str("Summary Table:\n");
    out.push_str("--------------\n");
    out.push_str(&format!(
        "  Dev Drive (Project)    : {}\n",
        if report
            .project_volume
            .as_ref()
            .map(|v| v.is_dev_drive)
            .unwrap_or(false)
        {
            "[OK] Dev Drive (ReFS)"
        } else if report
            .project_volume
            .as_ref()
            .map(|v| v.file_system.eq_ignore_ascii_case("ReFS"))
            .unwrap_or(false)
        {
            "No (Plain ReFS volume, not a Dev Drive)"
        } else {
            "No (NTFS / non-ReFS)"
        }
    ));
    out.push_str(&format!(
        "  Dev Drive (Store)      : {}\n",
        if report
            .store_volume
            .as_ref()
            .map(|v| v.is_dev_drive)
            .unwrap_or(false)
        {
            "[OK] Dev Drive (ReFS)"
        } else if report
            .store_volume
            .as_ref()
            .map(|v| v.file_system.eq_ignore_ascii_case("ReFS"))
            .unwrap_or(false)
        {
            "No (Plain ReFS volume, not a Dev Drive)"
        } else {
            "No (NTFS / non-ReFS)"
        }
    ));
    out.push_str(&format!(
        "  Same Volume Cloning    : {}\n",
        if report.block_cloning_supported {
            "ENABLED (FSCTL_DUPLICATE_EXTENTS_TO_FILE)"
        } else {
            "Disabled"
        }
    ));
    out.push_str(&format!(
        "  Project Disk Speed     : {}\n",
        match report.project_seek_penalty {
            Some(true) => "Rotational HDD (Seek penalty present, 4-thread writer)",
            Some(false) => "SSD / NVMe (Fast, 24-32 thread writer)",
            None => "Unknown",
        }
    ));
    out.push_str(&format!(
        "  Defender Status        : {}\n",
        match report.defender.real_time_protection {
            Some(true) => {
                if report.defender.dev_drive_performance_mode == Some(true) {
                    "Real-Time Protection Active (Dev Drive Performance Mode Enabled)"
                } else {
                    "Real-Time Protection Active (Synchronous NTFS Scanning)"
                }
            }
            Some(false) => "Disabled",
            None => "Unknown / Third-party AV",
        }
    ));

    out
}

/// Run `rnpm doctor perf` command.
pub async fn run_doctor_perf(project_path: &Path, json: bool) -> anyhow::Result<()> {
    let store_path = rnpm_cache::PackStore::default_location(None);

    let project_volume = query_volume_info(project_path);
    let store_volume = query_volume_info(&store_path);

    let project_seek_penalty = rnpm_fs::detect_seek_penalty(project_path);
    let store_seek_penalty = rnpm_fs::detect_seek_penalty(&store_path);

    let defender = query_defender_info();

    let report = evaluate_perf_diagnostics(
        project_path,
        &store_path,
        project_volume,
        store_volume,
        project_seek_penalty,
        store_seek_penalty,
        defender,
    );

    if json {
        let json_str = serde_json::to_string_pretty(&report)?;
        println!("{}", json_str);
    } else {
        print!("{}", format_perf_report_text(&report));
    }

    Ok(())
}

/// Standard doctor health check report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardDoctorReport {
    pub rnpm_version: String,
    pub os: String,
    pub arch: String,
    pub registry: String,
    pub package_json: bool,
    pub package_lock: bool,
    pub node_modules: bool,
    pub cache_dir: String,
    pub cache_writable: bool,
    pub dev_drive: bool,
    pub seek_penalty: Option<bool>,
}

/// Run `rnpm doctor` standard diagnostic check.
pub async fn run_doctor_standard(project_path: &Path, json: bool) -> anyhow::Result<()> {
    let config = rnpm_config::Config::load(Some(project_path)).unwrap_or_default();
    let registry = config.npmrc.registry.clone();

    let package_json = project_path.join("package.json").exists();
    let package_lock = project_path.join("package-lock.json").exists();
    let node_modules = project_path.join("node_modules").exists();

    let cache_dir = rnpm_cache::PackStore::default_location(None);
    let cache_writable = std::fs::create_dir_all(&cache_dir).is_ok();

    let vol = query_volume_info(project_path);
    let dev_drive = vol.as_ref().map(|v| v.is_dev_drive).unwrap_or(false);
    let is_refs = vol
        .as_ref()
        .map(|v| v.file_system.eq_ignore_ascii_case("ReFS"))
        .unwrap_or(false);
    let seek_penalty = rnpm_fs::detect_seek_penalty(project_path);

    let report = StandardDoctorReport {
        rnpm_version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        registry: registry.to_string(),
        package_json,
        package_lock,
        node_modules,
        cache_dir: cache_dir.to_string_lossy().to_string(),
        cache_writable,
        dev_drive,
        seek_penalty,
    };

    if json {
        let json_str = serde_json::to_string_pretty(&report)?;
        println!("{}", json_str);
    } else {
        println!("rnpm doctor - Environment & Project Health Check");
        println!("================================================");
        println!("  rnpm version : v{}", report.rnpm_version);
        println!("  Platform     : {} ({})", report.os, report.arch);
        println!("  Registry     : {}", report.registry);
        println!(
            "  package.json : {}",
            if package_json {
                "[OK] Found"
            } else {
                "[!] Not found"
            }
        );
        println!(
            "  package-lock : {}",
            if package_lock {
                "[OK] Found"
            } else {
                "[!] Not found"
            }
        );
        println!(
            "  node_modules : {}",
            if node_modules {
                "[OK] Present"
            } else {
                "Not present"
            }
        );
        println!(
            "  Cache dir    : {} {}",
            report.cache_dir,
            if cache_writable {
                "[OK] Writable"
            } else {
                "[!] Not writable"
            }
        );
        println!(
            "  Dev Drive    : {}",
            if dev_drive {
                "[OK] Dev Drive (ReFS)"
            } else if is_refs {
                "No (Plain ReFS volume, not a Dev Drive)"
            } else {
                "No (NTFS / other)"
            }
        );
        println!(
            "  Seek Penalty : {}",
            match seek_penalty {
                Some(true) => "Yes (Rotational HDD)",
                Some(false) => "No (SSD / NVMe)",
                None => "Unknown",
            }
        );
        println!("\nTip: Run 'rnpm doctor perf' for in-depth Dev Drive, disk speed, and Windows Defender diagnostics.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_volume_info_detection_current_dir() {
        let cwd = std::env::current_dir().unwrap();
        let vol = query_volume_info(&cwd);
        assert!(
            vol.is_some(),
            "Volume info should be resolvable for current dir"
        );
        let vol = vol.unwrap();
        assert!(!vol.volume_path.is_empty());
        assert!(!vol.file_system.is_empty());
    }

    #[test]
    fn test_evaluate_perf_diagnostics_dev_drive_same_volume() {
        let proj = PathBuf::from("E:\\my-project");
        let store = PathBuf::from("E:\\rnpm-store");

        let proj_vol = VolumeInfo {
            volume_path: "E:\\".to_string(),
            volume_name: "DevVolume".to_string(),
            file_system: "ReFS".to_string(),
            serial_number: 12345,
            is_dev_drive: true,
            supports_block_cloning: true,
        };

        let store_vol = proj_vol.clone();

        let defender = DefenderInfo {
            real_time_protection: Some(true),
            dev_drive_performance_mode: Some(true),
            has_exclusions: Some(false),
            status_source: "mock".to_string(),
        };

        let report = evaluate_perf_diagnostics(
            &proj,
            &store,
            Some(proj_vol),
            Some(store_vol),
            Some(false),
            Some(false),
            defender,
        );

        assert!(report.same_volume);
        assert!(report.block_cloning_supported);
        assert_eq!(report.project_seek_penalty, Some(false));
        assert!(
            report.recommendations.is_empty(),
            "Fully optimized setup has no warnings"
        );

        let text = format_perf_report_text(&report);
        assert!(text.contains("Zero-Cost Block Cloning"));
        assert!(text.contains("Dev Drive Performance Mode is ENABLED"));
        assert!(text.contains("[OK] Dev Drive (ReFS)"));
    }

    #[test]
    fn test_evaluate_perf_diagnostics_hdd_ntfs_cross_volume() {
        let proj = PathBuf::from("D:\\projects\\web");
        let store = PathBuf::from("C:\\Users\\dev\\AppData\\Local\\rnpm\\store-v1");

        let proj_vol = VolumeInfo {
            volume_path: "D:\\".to_string(),
            volume_name: "Data".to_string(),
            file_system: "NTFS".to_string(),
            serial_number: 11111,
            is_dev_drive: false,
            supports_block_cloning: false,
        };

        let store_vol = VolumeInfo {
            volume_path: "C:\\".to_string(),
            volume_name: "Windows".to_string(),
            file_system: "NTFS".to_string(),
            serial_number: 22222,
            is_dev_drive: false,
            supports_block_cloning: false,
        };

        let defender = DefenderInfo {
            real_time_protection: Some(true),
            dev_drive_performance_mode: Some(false),
            has_exclusions: Some(false),
            status_source: "mock".to_string(),
        };

        let report = evaluate_perf_diagnostics(
            &proj,
            &store,
            Some(proj_vol),
            Some(store_vol),
            Some(true),  // HDD seek penalty
            Some(false), // SSD store
            defender,
        );

        assert!(!report.same_volume);
        assert!(!report.block_cloning_supported);
        assert_eq!(report.project_seek_penalty, Some(true));

        let text = format_perf_report_text(&report);
        assert!(text.contains("rotational seek-penalty disk"));
        assert!(text.contains("Cross-Volume"));
        assert!(text.contains("Add-MpPreference"));
        assert!(text.contains("Create dev drive"));
        assert!(report.recommendations.len() >= 3);
    }

    #[test]
    fn test_evaluate_perf_diagnostics_json_serialization() {
        let proj = PathBuf::from("C:\\test");
        let store = PathBuf::from("C:\\test\\store");

        let defender = DefenderInfo {
            real_time_protection: Some(false),
            dev_drive_performance_mode: None,
            has_exclusions: None,
            status_source: "mock".to_string(),
        };

        let report = evaluate_perf_diagnostics(&proj, &store, None, None, None, None, defender);

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"project_path\""));
        assert!(json.contains("\"recommendations\""));
    }

    #[test]
    fn test_evaluate_perf_diagnostics_plain_refs_volume() {
        let proj = PathBuf::from("R:\\plain-project");
        let store = PathBuf::from("R:\\plain-store");

        // Plain ReFS volume: formatted as ReFS, supports block cloning, but NOT Dev Drive
        let proj_vol = VolumeInfo {
            volume_path: "R:\\".to_string(),
            volume_name: "PlainReFS".to_string(),
            file_system: "ReFS".to_string(),
            serial_number: 99999,
            is_dev_drive: false,
            supports_block_cloning: true,
        };
        let store_vol = proj_vol.clone();

        let defender = DefenderInfo {
            real_time_protection: Some(true),
            dev_drive_performance_mode: Some(false),
            has_exclusions: Some(false),
            status_source: "mock".to_string(),
        };

        let report = evaluate_perf_diagnostics(
            &proj,
            &store,
            Some(proj_vol),
            Some(store_vol),
            Some(false),
            Some(false),
            defender,
        );

        assert!(report.same_volume);
        assert!(report.block_cloning_supported);

        let text = format_perf_report_text(&report);
        // Dev Drive item warns that this is a plain ReFS volume, not a Dev Drive
        assert!(text.contains("plain ReFS volume"));
        assert!(text.contains("not a Dev Drive"));
        assert!(text.contains("No (Plain ReFS volume, not a Dev Drive)"));
        // Block cloning is still supported on ReFS
        assert!(text.contains("Zero-Cost Block Cloning"));
    }

    #[test]
    fn test_defender_performance_mode_and_advice() {
        let proj = PathBuf::from("E:\\dev-project");
        let store = PathBuf::from("E:\\dev-store");

        let proj_vol = VolumeInfo {
            volume_path: "E:\\".to_string(),
            volume_name: "DevDrive".to_string(),
            file_system: "ReFS".to_string(),
            serial_number: 54321,
            is_dev_drive: true,
            supports_block_cloning: true,
        };

        // When PerformanceModeStatus is 1 (Disabled), dev_drive_performance_mode is false
        let defender_disabled = DefenderInfo {
            real_time_protection: Some(true),
            dev_drive_performance_mode: Some(false),
            has_exclusions: Some(false),
            status_source: "mock".to_string(),
        };

        let report = evaluate_perf_diagnostics(
            &proj,
            &store,
            Some(proj_vol.clone()),
            Some(proj_vol.clone()),
            Some(false),
            Some(false),
            defender_disabled,
        );

        let text = format_perf_report_text(&report);
        assert!(text.contains("Defender Dev Drive Performance Mode Disabled"));
        assert!(text.contains("Set-MpPreference -PerformanceModeStatus 0"));
        assert!(text.contains("fsutil devdrv trust"));
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.contains("-PerformanceModeStatus 0")));

        // When PerformanceModeStatus is 0 (Enabled), dev_drive_performance_mode is true
        let defender_enabled = DefenderInfo {
            real_time_protection: Some(true),
            dev_drive_performance_mode: Some(true),
            has_exclusions: Some(false),
            status_source: "mock".to_string(),
        };

        let report_ok = evaluate_perf_diagnostics(
            &proj,
            &store,
            Some(proj_vol.clone()),
            Some(proj_vol),
            Some(false),
            Some(false),
            defender_enabled,
        );

        let text_ok = format_perf_report_text(&report_ok);
        assert!(text_ok.contains("Defender Dev Drive Performance Mode is ENABLED"));
        assert!(report_ok.recommendations.is_empty());
    }

    #[test]
    fn test_defender_exclusion_parsing_and_placeholders() {
        // Placeholders in non-elevated PowerShell must be rejected
        assert!(!is_valid_exclusion_path(""));
        assert!(!is_valid_exclusion_path("   "));
        assert!(!is_valid_exclusion_path(
            "N/A: Must be an administrator to view exclusions"
        ));
        assert!(!is_valid_exclusion_path(
            "n/a: must be an administrator to view exclusions"
        ));
        assert!(!is_valid_exclusion_path(
            "{N/A: Must be an administrator to view exclusions}"
        ));
        assert!(!is_valid_exclusion_path("placeholder"));

        // Valid paths must be accepted
        assert!(is_valid_exclusion_path("C:\\projects\\node_modules"));
        assert!(is_valid_exclusion_path("D:\\npm-rust"));

        // JSON parsing
        let placeholder_val = serde_json::json!("N/A: Must be an administrator to view exclusions");
        assert_eq!(parse_defender_exclusions(&placeholder_val), Some(false));

        let placeholder_arr =
            serde_json::json!(["N/A: Must be an administrator to view exclusions"]);
        assert_eq!(parse_defender_exclusions(&placeholder_arr), Some(false));

        let empty_arr = serde_json::json!([]);
        assert_eq!(parse_defender_exclusions(&empty_arr), Some(false));

        let null_val = serde_json::Value::Null;
        assert_eq!(parse_defender_exclusions(&null_val), Some(false));

        let valid_arr = serde_json::json!(["C:\\dev\\node_modules"]);
        assert_eq!(parse_defender_exclusions(&valid_arr), Some(true));

        let mixed_arr = serde_json::json!([
            "N/A: Must be an administrator to view exclusions",
            "C:\\dev\\node_modules"
        ]);
        assert_eq!(parse_defender_exclusions(&mixed_arr), Some(true));
    }
}
