//! ReFS Dev Drive & Block Cloning primitives for rnpm (Milestone M7).
//!
//! Per fifty-mark.md Section 4.7:
//! When the store and project are on the same ReFS volume (Dev Drive), the materializer
//! can clone ranges out of the pack with `FSCTL_DUPLICATE_EXTENTS_TO_FILE` (cluster-aligned,
//! matching our 4 KiB pack alignment) instead of copying bytes.

#![allow(clippy::upper_case_acronyms, clippy::not_unsafe_ptr_arg_deref)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(windows)]
pub type RawFileHandle = *mut std::ffi::c_void;

#[cfg(not(windows))]
pub type RawFileHandle = std::os::raw::c_int;

/// Windows IOCTL control code for block cloning:
/// `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 209, METHOD_BUFFERED, FILE_WRITE_DATA)` = `0x00098344`.
pub const FSCTL_DUPLICATE_EXTENTS_TO_FILE: u32 = 0x00098344;

/// Standard cluster alignment requirement for block cloning (4 KiB = 4096 bytes).
pub const CLUSTER_SIZE: u64 = 4096;

/// Structure passed to `FSCTL_DUPLICATE_EXTENTS_TO_FILE` control code.
#[repr(C)]
#[allow(non_snake_case)]
pub struct DUPLICATE_EXTENTS_DATA {
    pub FileHandle: RawFileHandle,
    pub SourceFileOffset: i64,
    pub TargetFileOffset: i64,
    pub ByteCount: i64,
}

static BLOCK_CLONES_PERFORMED: AtomicU64 = AtomicU64::new(0);

/// Record that a block clone operation succeeded.
pub fn record_block_clone() {
    BLOCK_CLONES_PERFORMED.fetch_add(1, Ordering::Relaxed);
}

/// Returns the total number of block clone operations successfully performed.
pub fn block_clones_performed() -> u64 {
    BLOCK_CLONES_PERFORMED.load(Ordering::Relaxed)
}

/// Resets the block clones counter.
pub fn reset_block_clones() {
    BLOCK_CLONES_PERFORMED.store(0, Ordering::Relaxed);
}

#[cfg(windows)]
fn normalize_for_volume_query(path: &Path) -> Option<PathBuf> {
    let clean = crate::path::strip_verbatim_prefix(path);
    let s = clean.to_string_lossy();
    if s.len() == 2 && s.as_bytes()[1] == b':' {
        let drive = (s.as_bytes()[0] as char).to_ascii_uppercase();
        return Some(PathBuf::from(format!(r"{drive}:\")));
    }
    if s.len() >= 3
        && s.as_bytes()[1] == b':'
        && (s.as_bytes()[2] == b'\\' || s.as_bytes()[2] == b'/')
    {
        let drive = (s.as_bytes()[0] as char).to_ascii_uppercase();
        if s.len() == 3 {
            return Some(PathBuf::from(format!(r"{drive}:\")));
        }
    }
    if path.is_relative() {
        let cur = std::env::current_dir().ok()?;
        Some(cur.join(path))
    } else {
        Some(path.to_path_buf())
    }
}

/// Windows volume capability flag indicating that the volume filesystem supports block refcounting
/// (e.g. block cloning via `FSCTL_DUPLICATE_EXTENTS_TO_FILE`).
pub const FILE_SUPPORTS_BLOCK_REFCOUNTING: u32 = 0x08000000;

#[cfg(windows)]
fn get_volume_root_path_wide(path: &Path) -> Option<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    extern "system" {
        fn GetVolumePathNameW(
            lpszFileName: *const u16,
            lpszVolumePathName: *mut u16,
            cchBufferLength: u32,
        ) -> i32;
    }

    let norm_path = normalize_for_volume_query(path)?;
    let verbatim = crate::path::to_verbatim_path(&norm_path);
    let wide_path: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();

    let mut volume_path = vec![0u16; 512];
    let ok = unsafe {
        GetVolumePathNameW(
            wide_path.as_ptr(),
            volume_path.as_mut_ptr(),
            volume_path.len() as u32,
        )
    };

    if ok != 0 {
        let len = volume_path
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(volume_path.len());
        Some(volume_path[..len].to_vec())
    } else {
        let clean = crate::path::strip_verbatim_prefix(&norm_path);
        let s = clean.to_string_lossy();
        if s.len() >= 2 && s.as_bytes()[1] == b':' {
            let drive = (s.as_bytes()[0] as char).to_ascii_uppercase();
            let root_str = format!(r"{drive}:\");
            Some(std::ffi::OsStr::new(&root_str).encode_wide().collect())
        } else {
            None
        }
    }
}

/// Retrieves the filesystem name, volume serial number, and filesystem flags for `path` on Windows.
#[cfg(windows)]
pub fn get_volume_details(path: &Path) -> Option<(String, u32, u32)> {
    use std::os::windows::ffi::OsStrExt;

    extern "system" {
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

    let root_wide = get_volume_root_path_wide(path)?;
    let mut root_null_term = root_wide;
    root_null_term.push(0);

    let mut fs_name_buf = vec![0u16; 260];
    let mut serial_number = 0u32;
    let mut flags = 0u32;
    let mut max_comp_len = 0u32;

    let mut success = unsafe {
        GetVolumeInformationW(
            root_null_term.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial_number,
            &mut max_comp_len,
            &mut flags,
            fs_name_buf.as_mut_ptr(),
            fs_name_buf.len() as u32,
        )
    };

    if success == 0 {
        // Fallback: try raw drive letter root if verbatim format was rejected
        if let Some(norm_path) = normalize_for_volume_query(path) {
            let clean = crate::path::strip_verbatim_prefix(&norm_path);
            let s = clean.to_string_lossy();
            if s.len() >= 2 && s.as_bytes()[1] == b':' {
                let drive = (s.as_bytes()[0] as char).to_ascii_uppercase();
                let root_str = format!(r"{drive}:\");
                let fallback_root: Vec<u16> = std::ffi::OsStr::new(&root_str)
                    .encode_wide()
                    .chain(Some(0))
                    .collect();
                success = unsafe {
                    GetVolumeInformationW(
                        fallback_root.as_ptr(),
                        std::ptr::null_mut(),
                        0,
                        &mut serial_number,
                        &mut max_comp_len,
                        &mut flags,
                        fs_name_buf.as_mut_ptr(),
                        fs_name_buf.len() as u32,
                    )
                };
            }
        }
    }

    if success == 0 {
        return None;
    }

    let end = fs_name_buf
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(fs_name_buf.len());
    let fs_name = String::from_utf16_lossy(&fs_name_buf[..end]);
    Some((fs_name, serial_number, flags))
}

/// Retrieves the filesystem name (e.g. "NTFS", "ReFS") and volume serial number for `path` on Windows.
#[cfg(windows)]
pub fn get_volume_info(path: &Path) -> Option<(String, u32)> {
    get_volume_details(path).map(|(fs_name, serial, _flags)| (fs_name, serial))
}

/// Non-Windows stub for `get_volume_details`.
#[cfg(not(windows))]
pub fn get_volume_details(_path: &Path) -> Option<(String, u32, u32)> {
    None
}

/// Non-Windows stub for `get_volume_info`.
#[cfg(not(windows))]
pub fn get_volume_info(_path: &Path) -> Option<(String, u32)> {
    None
}

/// Queries the actual filesystem cluster size in bytes for `path` using `GetDiskFreeSpaceW`.
#[cfg(windows)]
pub fn get_volume_cluster_size(path: &Path) -> Option<u32> {
    use std::os::windows::ffi::OsStrExt;

    extern "system" {
        fn GetDiskFreeSpaceW(
            lpRootPathName: *const u16,
            lpSectorsPerCluster: *mut u32,
            lpBytesPerSector: *mut u32,
            lpNumberOfFreeClusters: *mut u32,
            lpTotalNumberOfClusters: *mut u32,
        ) -> i32;
    }

    let root_wide = get_volume_root_path_wide(path)?;
    let mut root_null = root_wide;
    if !root_null.ends_with(&[b'\\' as u16]) {
        root_null.push(b'\\' as u16);
    }
    root_null.push(0);

    let mut sectors_per_cluster = 0u32;
    let mut bytes_per_sector = 0u32;
    let mut free_clusters = 0u32;
    let mut total_clusters = 0u32;

    let mut ok = unsafe {
        GetDiskFreeSpaceW(
            root_null.as_ptr(),
            &mut sectors_per_cluster,
            &mut bytes_per_sector,
            &mut free_clusters,
            &mut total_clusters,
        )
    };

    if ok == 0 {
        if let Some(norm_path) = normalize_for_volume_query(path) {
            let clean = crate::path::strip_verbatim_prefix(&norm_path);
            let s = clean.to_string_lossy();
            if s.len() >= 2 && s.as_bytes()[1] == b':' {
                let drive = (s.as_bytes()[0] as char).to_ascii_uppercase();
                let root_str = format!(r"{drive}:\");
                let fallback_root: Vec<u16> = std::ffi::OsStr::new(&root_str)
                    .encode_wide()
                    .chain(Some(0))
                    .collect();
                ok = unsafe {
                    GetDiskFreeSpaceW(
                        fallback_root.as_ptr(),
                        &mut sectors_per_cluster,
                        &mut bytes_per_sector,
                        &mut free_clusters,
                        &mut total_clusters,
                    )
                };
            }
        }
    }

    if ok != 0 && sectors_per_cluster > 0 && bytes_per_sector > 0 {
        sectors_per_cluster.checked_mul(bytes_per_sector)
    } else {
        None
    }
}

#[cfg(not(windows))]
pub fn get_volume_cluster_size(_path: &Path) -> Option<u32> {
    None
}

/// Queries the volume GUID name (e.g. `\\?\Volume{GUID}\`) for `path` using `GetVolumeNameForVolumeMountPointW`.
#[cfg(windows)]
pub fn get_volume_guid(path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;

    extern "system" {
        fn GetVolumeNameForVolumeMountPointW(
            lpszVolumeMountPoint: *const u16,
            lpszVolumeName: *mut u16,
            cchBufferLength: u32,
        ) -> i32;
    }

    let root_wide = get_volume_root_path_wide(path)?;
    let mut root_null = root_wide;
    if !root_null.ends_with(&[b'\\' as u16]) {
        root_null.push(b'\\' as u16);
    }
    root_null.push(0);

    let mut guid_buf = vec![0u16; 128];
    let mut ok = unsafe {
        GetVolumeNameForVolumeMountPointW(
            root_null.as_ptr(),
            guid_buf.as_mut_ptr(),
            guid_buf.len() as u32,
        )
    };

    if ok == 0 {
        if let Some(norm_path) = normalize_for_volume_query(path) {
            let clean = crate::path::strip_verbatim_prefix(&norm_path);
            let s = clean.to_string_lossy();
            if s.len() >= 2 && s.as_bytes()[1] == b':' {
                let drive = (s.as_bytes()[0] as char).to_ascii_uppercase();
                let root_str = format!(r"{drive}:\");
                let fallback_root: Vec<u16> = std::ffi::OsStr::new(&root_str)
                    .encode_wide()
                    .chain(Some(0))
                    .collect();
                ok = unsafe {
                    GetVolumeNameForVolumeMountPointW(
                        fallback_root.as_ptr(),
                        guid_buf.as_mut_ptr(),
                        guid_buf.len() as u32,
                    )
                };
            }
        }
    }

    if ok != 0 {
        let len = guid_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(guid_buf.len());
        Some(String::from_utf16_lossy(&guid_buf[..len]))
    } else {
        None
    }
}

#[cfg(not(windows))]
pub fn get_volume_guid(_path: &Path) -> Option<String> {
    None
}

/// Fallback helper to query volume serial number using `GetFileInformationByHandle`
/// on an existing file or directory path.
#[cfg(windows)]
fn get_file_info_serial(path: &Path) -> Option<u32> {
    use std::os::windows::ffi::OsStrExt;

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

        fn GetFileInformationByHandle(
            hFile: *mut std::ffi::c_void,
            lpFileInformation: *mut BY_HANDLE_FILE_INFORMATION,
        ) -> i32;

        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct FILETIME {
        dwLowDateTime: u32,
        dwHighDateTime: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct BY_HANDLE_FILE_INFORMATION {
        dwFileAttributes: u32,
        ftCreationTime: FILETIME,
        ftLastAccessTime: FILETIME,
        ftLastWriteTime: FILETIME,
        dwVolumeSerialNumber: u32,
        nFileSizeHigh: u32,
        nFileSizeLow: u32,
        nNumberOfLinks: u32,
        nFileIndexHigh: u32,
        nFileIndexLow: u32,
    }

    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const FILE_SHARE_DELETE: u32 = 4;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
    const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;

    let mut curr = if path.is_relative() {
        std::env::current_dir().ok()?.join(path)
    } else {
        path.to_path_buf()
    };

    while !curr.exists() {
        if !curr.pop() {
            return None;
        }
    }

    let verbatim = crate::path::to_verbatim_path(&curr);
    let wide: Vec<u16> = verbatim.as_os_str().encode_wide().chain(Some(0)).collect();

    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    unsafe {
        CloseHandle(handle);
    }

    if ok != 0 {
        Some(info.dwVolumeSerialNumber)
    } else {
        None
    }
}

/// Returns the volume serial number for `path` on Windows, querying `GetVolumeInformationW`
/// first and falling back to `GetFileInformationByHandle` if needed.
#[cfg(windows)]
pub fn get_volume_serial_number(path: &Path) -> Option<u32> {
    if let Some((_, serial)) = get_volume_info(path) {
        if serial != 0 {
            return Some(serial);
        }
    }
    get_file_info_serial(path)
}

#[cfg(not(windows))]
pub fn get_volume_serial_number(_path: &Path) -> Option<u32> {
    None
}

/// Returns the volume filesystem type name (e.g. "NTFS", "ReFS", "FAT32") on Windows.
pub fn get_volume_filesystem_name(path: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        get_volume_info(path).map(|(fs_name, _)| fs_name)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

/// Checks whether `path` resides on an ReFS filesystem volume supporting block refcounting (e.g. Windows Dev Drive).
pub fn is_refs_volume(path: &Path) -> bool {
    #[cfg(windows)]
    {
        if let Some((fs_name, _serial, flags)) = get_volume_details(path) {
            fs_name.eq_ignore_ascii_case("ReFS") && (flags & FILE_SUPPORTS_BLOCK_REFCOUNTING != 0)
        } else {
            false
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}

/// Checks whether block cloning (`FSCTL_DUPLICATE_EXTENTS_TO_FILE`) is supported for `path`.
/// Verifies ReFS filesystem, `FILE_SUPPORTS_BLOCK_REFCOUNTING` capability flag, and 4 KiB cluster size.
pub fn is_block_cloning_supported(path: &Path) -> bool {
    #[cfg(windows)]
    {
        if !is_refs_volume(path) {
            return false;
        }
        match get_volume_cluster_size(path) {
            Some(cs) => cs as u64 == CLUSTER_SIZE,
            None => false,
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}

/// Checks whether two filesystem paths reside on the same storage volume.
///
/// On Windows, compares volume GUID names via `GetVolumeNameForVolumeMountPointW`
/// and volume serial numbers via `GetVolumeInformationW` or `GetFileInformationByHandle`.
/// On Unix, compares filesystem device IDs (`st_dev`).
pub fn is_same_volume(path_a: &Path, path_b: &Path) -> bool {
    #[cfg(windows)]
    {
        let guid_a = get_volume_guid(path_a);
        let guid_b = get_volume_guid(path_b);
        if let (Some(ref ga), Some(ref gb)) = (&guid_a, &guid_b) {
            if !ga.is_empty() && !gb.is_empty() && !ga.eq_ignore_ascii_case(gb) {
                return false;
            }
        }

        let serial_a = get_volume_serial_number(path_a);
        let serial_b = get_volume_serial_number(path_b);

        match (serial_a, serial_b) {
            (Some(s_a), Some(s_b)) => s_a == s_b,
            _ => {
                if let (Some(ref ga), Some(ref gb)) = (&guid_a, &guid_b) {
                    !ga.is_empty() && ga.eq_ignore_ascii_case(gb)
                } else {
                    false
                }
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let get_dev = |p: &Path| -> Option<u64> {
            let mut curr = if p.is_relative() {
                std::env::current_dir().ok()?.join(p)
            } else {
                p.to_path_buf()
            };
            loop {
                if let Ok(meta) = std::fs::metadata(&curr) {
                    return Some(meta.dev());
                }
                if !curr.pop() {
                    return None;
                }
            }
        };
        match (get_dev(path_a), get_dev(path_b)) {
            (Some(dev_a), Some(dev_b)) => dev_a == dev_b,
            _ => false,
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (path_a, path_b);
        false
    }
}

/// Duplicates byte extents directly from `src_handle` into `dst_handle` using
/// Windows `FSCTL_DUPLICATE_EXTENTS_TO_FILE` (`0x00098344`).
///
/// Ensures `src_offset`, `dst_offset`, and `length` are cluster-aligned (multiples of 4096 bytes).
/// If `length` is 0, returns `Ok(())` immediately without issuing an IOCTL.
pub fn duplicate_extents(
    src_handle: RawFileHandle,
    dst_handle: RawFileHandle,
    src_offset: u64,
    dst_offset: u64,
    length: u64,
) -> std::io::Result<()> {
    if length == 0 {
        return Ok(());
    }

    if !src_offset.is_multiple_of(CLUSTER_SIZE) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Source offset {} is not cluster-aligned (must be multiple of {} bytes)",
                src_offset, CLUSTER_SIZE
            ),
        ));
    }
    if !dst_offset.is_multiple_of(CLUSTER_SIZE) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Target offset {} is not cluster-aligned (must be multiple of {} bytes)",
                dst_offset, CLUSTER_SIZE
            ),
        ));
    }
    if !length.is_multiple_of(CLUSTER_SIZE) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "ByteCount length {} is not cluster-aligned (must be multiple of {} bytes)",
                length, CLUSTER_SIZE
            ),
        ));
    }

    #[cfg(windows)]
    {
        extern "system" {
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
            fn GetLastError() -> u32;
        }

        let ded = DUPLICATE_EXTENTS_DATA {
            FileHandle: src_handle,
            SourceFileOffset: src_offset as i64,
            TargetFileOffset: dst_offset as i64,
            ByteCount: length as i64,
        };

        let mut bytes_returned = 0u32;
        let ret = unsafe {
            DeviceIoControl(
                dst_handle,
                FSCTL_DUPLICATE_EXTENTS_TO_FILE,
                &ded as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<DUPLICATE_EXTENTS_DATA>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };

        if ret == 0 {
            let err = unsafe { GetLastError() };
            return Err(std::io::Error::from_raw_os_error(err as i32));
        }

        record_block_clone();
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = (src_handle, dst_handle);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "FSCTL_DUPLICATE_EXTENTS_TO_FILE is only supported on Windows ReFS",
        ))
    }
}

/// Clones a single file extent directly from `src_handle` (an open pack file) into `dst_path`.
///
/// Prepares the destination file by pre-extending it to the cluster-aligned clone size,
/// issuing `duplicate_extents`, and then truncating EOF to the exact uncompressed `size`.
#[cfg(windows)]
pub fn clone_file_from_pack(
    src_handle: RawFileHandle,
    dst_path: &Path,
    src_offset: u64,
    size: u64,
    _mode: u32,
) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

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

        fn SetFilePointerEx(
            hFile: *mut std::ffi::c_void,
            liDistanceToMove: i64,
            lpNewFilePointer: *mut i64,
            dwMoveMethod: u32,
        ) -> i32;

        fn SetEndOfFile(hFile: *mut std::ffi::c_void) -> i32;
        fn SetFileAttributesW(lpFileName: *const u16, dwFileAttributes: u32) -> i32;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
        fn GetLastError() -> u32;
    }

    const GENERIC_READ: u32 = 0x80000000;
    const GENERIC_WRITE: u32 = 0x40000000;
    const FILE_SHARE_READ: u32 = 1;
    const CREATE_ALWAYS: u32 = 2;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;
    const FILE_BEGIN: u32 = 0;
    const ERROR_ACCESS_DENIED: u32 = 5;

    crate::tarball::unlink_target_path(dst_path);
    let verbatim_path = crate::path::to_verbatim_path(dst_path);
    let path_wide: Vec<u16> = verbatim_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();

    let mut dst_handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            std::ptr::null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };

    if dst_handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        if err == ERROR_ACCESS_DENIED {
            unsafe {
                SetFileAttributesW(path_wide.as_ptr(), FILE_ATTRIBUTE_NORMAL);
            }
            dst_handle = unsafe {
                CreateFileW(
                    path_wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ,
                    std::ptr::null_mut(),
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            };
        }
        if dst_handle == INVALID_HANDLE_VALUE {
            let final_err = unsafe { GetLastError() };
            return Err(std::io::Error::from_raw_os_error(final_err as i32));
        }
    }

    struct HandleGuard(*mut std::ffi::c_void);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }
    let _guard = HandleGuard(dst_handle);

    if size == 0 {
        crate::tarball::record_file_created(0);
        return Ok(());
    }

    let cloned_bytes = (size + CLUSTER_SIZE - 1) & !(CLUSTER_SIZE - 1);

    // 1. Extend destination file size to cloned_bytes so it can receive duplicated extents
    let set_ptr = unsafe {
        SetFilePointerEx(
            dst_handle,
            cloned_bytes as i64,
            std::ptr::null_mut(),
            FILE_BEGIN,
        )
    };
    if set_ptr == 0 {
        let err = unsafe { GetLastError() };
        return Err(std::io::Error::from_raw_os_error(err as i32));
    }
    let set_eof = unsafe { SetEndOfFile(dst_handle) };
    if set_eof == 0 {
        let err = unsafe { GetLastError() };
        return Err(std::io::Error::from_raw_os_error(err as i32));
    }

    // 2. Clone extent directly from pack file
    duplicate_extents(src_handle, dst_handle, src_offset, 0, cloned_bytes)?;

    // 3. If size is not an exact multiple of CLUSTER_SIZE, truncate to true logical EOF
    if cloned_bytes != size {
        let set_ptr2 =
            unsafe { SetFilePointerEx(dst_handle, size as i64, std::ptr::null_mut(), FILE_BEGIN) };
        if set_ptr2 == 0 {
            let err = unsafe { GetLastError() };
            return Err(std::io::Error::from_raw_os_error(err as i32));
        }
        let set_eof2 = unsafe { SetEndOfFile(dst_handle) };
        if set_eof2 == 0 {
            let err = unsafe { GetLastError() };
            return Err(std::io::Error::from_raw_os_error(err as i32));
        }
    }

    // Block cloning creates the file without writing data bytes to disk!
    crate::tarball::record_file_created(0);
    Ok(())
}

#[cfg(not(windows))]
pub fn clone_file_from_pack(
    _src_handle: RawFileHandle,
    _dst_path: &Path,
    _src_offset: u64,
    _size: u64,
    _mode: u32,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Block cloning is only supported on Windows ReFS",
    ))
}

/// Materializes a single pack entry into `dest_path`.
///
/// If `src_handle` is provided (e.g. when pack file and destination are on the same ReFS volume),
/// attempts block cloning via `FSCTL_DUPLICATE_EXTENTS_TO_FILE`.
/// If block clone succeeds, returns `Ok(true)` (indicating block cloned, 0 data bytes written).
/// If block cloning is not available or fails (e.g. non-ReFS volume, unsupported IOCTL),
/// falls back gracefully to `write_file_fast` and returns `Ok(false)`.
pub fn clone_or_write_pack_file(
    src_handle: Option<RawFileHandle>,
    dest_path: &Path,
    data: &[u8],
    offset: u64,
    size: u64,
    mode: u32,
    prealloc_threshold: usize,
) -> std::io::Result<bool> {
    #[cfg(windows)]
    if let Some(src_h) = src_handle {
        if offset.is_multiple_of(CLUSTER_SIZE) {
            match clone_file_from_pack(src_h, dest_path, offset, size, mode) {
                Ok(()) => return Ok(true),
                Err(err) => {
                    tracing::debug!(
                        "Block clone unsupported or failed for {} at offset {}: {err}. Falling back to write_file_fast",
                        dest_path.display(),
                        offset
                    );
                }
            }
        }
    }

    #[cfg(not(windows))]
    let _ = (src_handle, offset, size);

    crate::writer::write_file_fast(dest_path, data, mode, prealloc_threshold)?;
    Ok(false)
}

/// A borrowed reference to a pack entry for materialization.
#[derive(Debug, Clone)]
pub struct PackEntryRef<'a> {
    pub path: &'a str,
    pub offset: u64,
    pub size: u64,
    pub mode: u32,
    pub data: &'a [u8],
}

/// Materializes a collection of pack entries into `dest_dir`.
///
/// Automatically detects if `pack_path` and `dest_dir` reside on the same ReFS volume (Dev Drive).
/// If so, uses `FSCTL_DUPLICATE_EXTENTS_TO_FILE` block cloning for each entry.
/// If not on ReFS or if block cloning returns an error, falls back gracefully to `write_file_fast`.
pub fn materialize_pack_entries(
    pack_path: &Path,
    dest_dir: &Path,
    entries: &[PackEntryRef<'_>],
    writer_config: Option<&crate::writer::ParallelWriterConfig>,
) -> Result<crate::tarball::ExtractionSummary, crate::error::FsError> {
    let start_time = std::time::Instant::now();
    let clean_target_dir = path_clean::clean(dest_dir);

    // Security check: validate entry paths and ensure strict containment
    for entry in entries {
        let p = Path::new(entry.path);
        crate::tarball::validate_entry_path(p)?;
        let full_path = path_clean::clean(dest_dir.join(entry.path));
        if !full_path.starts_with(&clean_target_dir) {
            return Err(crate::error::FsError::PathTraversal {
                path: PathBuf::from(entry.path),
            });
        }
    }

    // 1. Precreate directories breadth-first
    let mut dirs = std::collections::BTreeSet::new();
    dirs.insert(dest_dir.to_path_buf());
    for entry in entries {
        let full_path = dest_dir.join(entry.path);
        if let Some(parent) = full_path.parent() {
            dirs.insert(parent.to_path_buf());
        }
    }
    let dir_refs: Vec<&Path> = dirs.iter().map(|p| p.as_path()).collect();
    crate::writer::precreate_directories(dir_refs).map_err(crate::error::FsError::Io)?;

    let default_cfg = crate::writer::ParallelWriterConfig::default();
    let cfg = writer_config.unwrap_or(&default_cfg);
    let prealloc_thresh = cfg.preallocate_threshold;

    let can_block_clone =
        is_same_volume(pack_path, dest_dir) && is_block_cloning_supported(dest_dir);

    #[cfg(windows)]
    let pack_file = if can_block_clone {
        std::fs::File::open(pack_path).ok()
    } else {
        None
    };

    #[cfg(windows)]
    let raw_handle = pack_file.as_ref().map(|f| {
        use std::os::windows::io::AsRawHandle;
        f.as_raw_handle() as usize
    });

    #[cfg(not(windows))]
    let raw_handle: Option<usize> = None;
    let _ = can_block_clone;
    let _ = raw_handle;

    let mut total_uncompressed_bytes = 0u64;
    for entry in entries {
        total_uncompressed_bytes += entry.size;
    }

    let num_threads = cfg.worker_threads.clamp(1, 32).min(entries.len());
    if num_threads > 1 && entries.len() > 1 {
        let queue = std::sync::Mutex::new(entries.to_vec());
        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(num_threads);
            for _ in 0..num_threads {
                let q = &queue;
                handles.push(scope.spawn(move || -> Result<(), crate::error::FsError> {
                    loop {
                        let entry = {
                            let mut guard = q.lock().unwrap();
                            guard.pop()
                        };
                        let entry = match entry {
                            Some(e) => e,
                            None => break,
                        };
                        let full_path = dest_dir.join(entry.path);

                        #[cfg(windows)]
                        let src_h = raw_handle.map(|h| h as RawFileHandle);
                        #[cfg(not(windows))]
                        let src_h = None;

                        clone_or_write_pack_file(
                            src_h,
                            &full_path,
                            entry.data,
                            entry.offset,
                            entry.size,
                            entry.mode,
                            prealloc_thresh,
                        )
                        .map_err(crate::error::FsError::Io)?;
                    }
                    Ok(())
                }));
            }
            for handle in handles {
                handle.join().map_err(|_| {
                    crate::error::FsError::Io(std::io::Error::other(
                        "Pack materialization thread panicked",
                    ))
                })??;
            }
            Ok::<(), crate::error::FsError>(())
        })?;
    } else {
        for entry in entries {
            let full_path = dest_dir.join(entry.path);

            #[cfg(windows)]
            let src_h = raw_handle.map(|h| h as RawFileHandle);
            #[cfg(not(windows))]
            let src_h = None;

            clone_or_write_pack_file(
                src_h,
                &full_path,
                entry.data,
                entry.offset,
                entry.size,
                entry.mode,
                prealloc_thresh,
            )
            .map_err(crate::error::FsError::Io)?;
        }
    }

    let elapsed = start_time.elapsed();
    Ok(crate::tarball::ExtractionSummary {
        entries_extracted: entries.len(),
        total_uncompressed_bytes,
        inflate_duration: std::time::Duration::ZERO,
        materialize_duration: elapsed,
    })
}
