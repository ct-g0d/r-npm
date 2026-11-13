use crate::error::FsError;
use flate2::read::GzDecoder;
use path_clean::clean;
use rnpm_core::integrity::{Algorithm, Integrity};
use rnpm_core::manifest::Manifest;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use tar::{Archive, Builder, Header};

/// Normalized POSIX timestamp for tarball reproducibility:
/// 1985-10-26 08:15:00 UTC (499162500 seconds) - standard npm pack epoch.
pub const NPM_PACK_EPOCH_MTIME: u64 = 499162500;

/// Default file permission mode: rw-r--r-- (0o644)
pub const NPM_DEFAULT_FILE_MODE: u32 = 0o644;
/// Executable file permission mode: rwxr-xr-x (0o755)
pub const NPM_EXECUTABLE_FILE_MODE: u32 = 0o755;

#[derive(Debug, Clone, Copy)]
pub struct TarLimits {
    pub max_entries: usize,
    pub max_uncompressed_size: u64,
    pub max_compression_ratio: f64,
    pub max_single_entry_size: u64,
    pub max_symlinks: usize,
    pub max_path_depth: usize,
    pub max_directories: usize,
}

impl Default for TarLimits {
    fn default() -> Self {
        Self {
            max_entries: 50_000,
            max_uncompressed_size: 512 * 1024 * 1024, // 512 MB
            max_compression_ratio: 100.0,
            max_single_entry_size: 256 * 1024 * 1024, // 256 MB
            max_symlinks: 5_000,
            max_path_depth: 32,
            max_directories: 10_000,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExtractionSummary {
    pub entries_extracted: usize,
    pub total_uncompressed_bytes: u64,
    pub inflate_duration: std::time::Duration,
    pub materialize_duration: std::time::Duration,
}

static FILES_CREATED: AtomicU64 = AtomicU64::new(0);
static BYTES_WRITTEN: AtomicU64 = AtomicU64::new(0);

/// Record a batch of files created and bytes written.
pub fn record_files_created_batch(count: u64, bytes: u64) {
    FILES_CREATED.fetch_add(count, Ordering::Relaxed);
    BYTES_WRITTEN.fetch_add(bytes, Ordering::Relaxed);
}

/// Record a single file created and bytes written.
pub fn record_file_created(bytes: u64) {
    FILES_CREATED.fetch_add(1, Ordering::Relaxed);
    BYTES_WRITTEN.fetch_add(bytes, Ordering::Relaxed);
}

/// Returns the total count of files created.
pub fn files_created() -> u64 {
    FILES_CREATED.load(Ordering::Relaxed)
}

/// Returns the total bytes written to disk.
pub fn bytes_written() -> u64 {
    BYTES_WRITTEN.load(Ordering::Relaxed)
}

/// Reset all filesystem counters (files created, bytes written, junctions created, block clones).
pub fn reset_fs_counters() {
    FILES_CREATED.store(0, Ordering::Relaxed);
    BYTES_WRITTEN.store(0, Ordering::Relaxed);
    crate::junction::reset_junctions_created();
    crate::block_clone::reset_block_clones();
}

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct CountingReader<R> {
    inner: R,
    bytes_read: Arc<AtomicU64>,
}

impl<R: Read> CountingReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            bytes_read: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn with_counter(inner: R, bytes_read: Arc<AtomicU64>) -> Self {
        Self { inner, bytes_read }
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    pub fn counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.bytes_read)
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// Extract a .tar.gz stream into destination, stripping the archive's first root component
/// and enforcing all security and tar-bomb defenses.
pub fn extract_tar_gz<R: Read>(
    reader: R,
    destination: &Path,
    limits: Option<TarLimits>,
) -> Result<ExtractionSummary, FsError> {
    let start_extract = std::time::Instant::now();
    let mut inflate_nanos = 0u64;
    let limits = limits.unwrap_or_default();
    let verbatim_dest = crate::path::to_verbatim_path(destination);
    fs::create_dir_all(&verbatim_dest)?;
    let clean_dest = clean(&verbatim_dest);
    let mut verified_safe_ancestors: HashSet<PathBuf> = HashSet::new();

    let compressed_counter = Arc::new(AtomicU64::new(0));
    let counting_reader = CountingReader::with_counter(reader, Arc::clone(&compressed_counter));
    let gz = GzDecoder::new(counting_reader);
    let mut archive = Archive::new(gz);

    let mut entry_count = 0;
    let mut directory_count = 0usize;
    let mut symlink_count = 0;
    let mut total_uncompressed = 0u64;
    let mut symlink_paths: HashSet<PathBuf> = HashSet::new();
    let mut extracted_regular_files: HashSet<PathBuf> = HashSet::new();
    let mut seen_paths: HashMap<String, String> = HashMap::new();
    let mut seen_dirs_lower: HashSet<String> = HashSet::new();
    let mut seen_files_lower: HashSet<String> = HashSet::new();
    let mut hardlink_targets: std::collections::HashMap<PathBuf, PathBuf> =
        std::collections::HashMap::new();
    let mut copy_buf = vec![0u8; 128 * 1024];

    let entries = archive.entries().map_err(FsError::Io)?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(FsError::Io)?;

        let entry_type = entry.header().entry_type();

        // Skip EntryType::XGlobalHeader without failing validation
        if entry_type == tar::EntryType::XGlobalHeader || entry_type.as_byte() == b'g' {
            continue;
        }

        entry_count += 1;
        if entry_count > limits.max_entries {
            return Err(FsError::TarBombLimitExceeded {
                limit_type: "entry count".to_string(),
                detail: format!(
                    "Tarball exceeded maximum allowed entries: {}",
                    limits.max_entries
                ),
            });
        }

        // Security check: SUID / SGID mode bits
        let mode = entry.header().mode().unwrap_or(0);
        if mode & 0o4000 != 0 || mode & 0o2000 != 0 {
            return Err(FsError::ForbiddenModeBits {
                mode,
                path: entry.path().unwrap_or_default().to_path_buf(),
            });
        }

        // Check non-UTF-8 path bytes before entry.path()
        let path_bytes = entry.path_bytes();
        if std::str::from_utf8(&path_bytes).is_err() {
            return Err(FsError::InvalidUtf8Path {
                path: PathBuf::from(String::from_utf8_lossy(&path_bytes).into_owned()),
            });
        }

        // Get raw entry path
        let raw_path = match entry.path() {
            Ok(p) => p.to_path_buf(),
            Err(_) if std::str::from_utf8(&path_bytes).is_err() => {
                return Err(FsError::InvalidUtf8Path {
                    path: PathBuf::from(String::from_utf8_lossy(&path_bytes).into_owned()),
                });
            }
            Err(e) => return Err(FsError::Io(e)),
        };

        // Reject sparse entries: entry_type.as_byte() == b'S' or PAX sparse attributes
        let is_sparse = entry_type.as_byte() == b'S' || entry_type.is_gnu_sparse();
        let has_pax_sparse = if let Ok(Some(extensions)) = entry.pax_extensions() {
            extensions.filter_map(|e| e.ok()).any(|ext| {
                ext.key()
                    .map(|k| k.starts_with("GNU.sparse."))
                    .unwrap_or(false)
                    || ext.key_bytes().starts_with(b"GNU.sparse.")
            })
        } else {
            false
        };
        if is_sparse || has_pax_sparse {
            return Err(FsError::ForbiddenSparseFile { path: raw_path });
        }

        // Security check raw path before stripping prefix
        validate_entry_path(&raw_path)?;

        // Strip the archive root component (usually "package/").
        let relative_path = match strip_package_prefix(&raw_path) {
            Some(p) => {
                let cleaned: PathBuf = p
                    .components()
                    .filter(|c| !matches!(c, Component::CurDir))
                    .collect();
                if cleaned.as_os_str().is_empty() {
                    continue;
                }
                cleaned
            }
            None => {
                // If this is the directory entry for "package" itself, skip it
                continue;
            }
        };

        // Security check relative path: path traversal, absolute paths, device names, trailing dots/spaces
        validate_entry_path(&relative_path)?;

        // Check path depth: count components; if deeper than limits.max_path_depth
        let path_depth = relative_path
            .components()
            .filter(|c| matches!(c, Component::Normal(_)))
            .count();
        if path_depth > limits.max_path_depth {
            return Err(FsError::TarBombLimitExceeded {
                limit_type: "path depth".to_string(),
                detail: format!(
                    "Path depth {} exceeded maximum allowed path depth of {}: '{}'",
                    path_depth,
                    limits.max_path_depth,
                    relative_path.display()
                ),
            });
        }

        // Track directory count: if directories exceed limits.max_directories
        if entry_type.is_dir() {
            directory_count += 1;
            if directory_count > limits.max_directories {
                return Err(FsError::TarBombLimitExceeded {
                    limit_type: "directory count".to_string(),
                    detail: format!(
                        "Tarball exceeded maximum allowed directories: {}",
                        limits.max_directories
                    ),
                });
            }
        }

        // Check special entry types: FIFOs, block/character devices
        if entry_type.is_block_special()
            || entry_type.is_character_special()
            || entry_type.is_fifo()
        {
            return Err(FsError::ForbiddenSpecialEntry { path: raw_path });
        }

        let target_path = verbatim_dest.join(&relative_path);

        // Verify strict canonical path containment
        let clean_target = clean(&target_path);
        if !clean_target.starts_with(&clean_dest) {
            return Err(FsError::PathTraversal {
                path: relative_path.clone(),
            });
        }
        if clean_target == clean_dest && !entry_type.is_dir() {
            return Err(FsError::PathTraversal {
                path: relative_path.clone(),
            });
        }
        let target_path = clean_target;

        // Security check against Symlink Slip:
        // Ensure neither target_path nor any intermediate ancestor directory is a symlink or junction
        // pointing outside destination or created by an earlier tarball entry.
        ensure_no_symlink_ancestors_with_cache(
            &target_path,
            &verbatim_dest,
            &symlink_paths,
            &relative_path,
            Some(&mut verified_safe_ancestors),
        )?;

        // Track case-preserved normalized paths: maintain seen_paths: HashMap<String, String>
        // mapping lowercase normalized path -> exact case-preserved normalized path.
        // Node-tar and npm rule: same path (case preserved) = later entry wins.
        // Only raise FsError::CaseCollision when two extracted paths differ only by case (e.g. foo.js vs FOO.JS).
        let norm_exact = relative_path
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => Some(s.to_string_lossy().to_string()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("/");
        if norm_exact.is_empty() {
            continue;
        }
        let norm_lower = norm_exact.to_ascii_lowercase();

        if let Some(existing_exact) = seen_paths.get(&norm_lower) {
            if existing_exact != &norm_exact {
                return Err(FsError::CaseCollision {
                    path: relative_path.clone(),
                });
            }
        }

        // Case collision check between files and directory ancestors
        let path_segments: Vec<&str> = norm_lower.split('/').collect();
        if entry_type.is_dir() {
            if seen_files_lower.contains(&norm_lower) {
                return Err(FsError::CaseCollision {
                    path: relative_path.clone(),
                });
            }
            seen_dirs_lower.insert(norm_lower.clone());
            let mut prefix = String::new();
            for seg in &path_segments {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(seg);
                if seen_files_lower.contains(&prefix) {
                    return Err(FsError::CaseCollision {
                        path: relative_path.clone(),
                    });
                }
                seen_dirs_lower.insert(prefix.clone());
            }
        } else {
            if seen_dirs_lower.contains(&norm_lower) {
                return Err(FsError::CaseCollision {
                    path: relative_path.clone(),
                });
            }
            seen_files_lower.insert(norm_lower.clone());
            let mut prefix = String::new();
            for seg in &path_segments[..path_segments.len().saturating_sub(1)] {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(seg);
                if seen_files_lower.contains(&prefix) {
                    return Err(FsError::CaseCollision {
                        path: relative_path.clone(),
                    });
                }
                seen_dirs_lower.insert(prefix.clone());
            }
        }

        seen_paths.insert(norm_lower, norm_exact);

        // Security check: escaping symlinks/hardlinks
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            symlink_count += 1;
            if symlink_count > limits.max_symlinks {
                return Err(FsError::TarBombLimitExceeded {
                    limit_type: "symlink count".to_string(),
                    detail: format!(
                        "Tarball exceeded maximum allowed symlinks/hardlinks: {}",
                        limits.max_symlinks
                    ),
                });
            }

            if let Some(link_bytes) = entry.link_name_bytes() {
                if std::str::from_utf8(&link_bytes).is_err() {
                    return Err(FsError::InvalidUtf8Path {
                        path: PathBuf::from(String::from_utf8_lossy(&link_bytes).into_owned()),
                    });
                }
            }

            if let Some(link_target) = entry.link_name().map_err(FsError::Io)? {
                // For hardlinks, the target is often archived as package/...
                let normalized_target =
                    strip_package_prefix(&link_target).unwrap_or_else(|| link_target.to_path_buf());

                if entry_type.is_symlink() {
                    let cleaned_rel =
                        validate_link_target(&relative_path, &normalized_target, destination)?;

                    if let Some(parent) = target_path.parent() {
                        fs::create_dir_all(parent)?;
                    }

                    // If target_path exists, safely unlink it (handling Windows junctions) before creating link
                    unlink_target_path(&target_path);

                    extracted_regular_files.remove(&relative_path);
                    extracted_regular_files.remove(&normalize_rel_path(&relative_path));
                    symlink_paths.insert(relative_path.clone());
                    symlink_paths.insert(normalize_rel_path(&relative_path));
                    #[cfg(unix)]
                    {
                        let _ = &cleaned_rel;
                        let _ = std::os::unix::fs::symlink(&link_target, &target_path);
                    }
                    #[cfg(windows)]
                    {
                        let target_full = verbatim_dest.join(&cleaned_rel);
                        if target_full.is_dir() {
                            let _ = crate::junction::create_junction(&target_path, &target_full);
                        } else if target_full.is_file() {
                            let _ = fs::copy(&target_full, &target_path);
                        }
                    }
                } else if entry_type.is_hard_link() {
                    // Hardlinks in tar are relative to archive root (destination), NOT relative to link_dir!
                    if normalized_target.is_absolute() || normalized_target.has_root() {
                        return Err(FsError::AbsolutePath {
                            path: normalized_target,
                        });
                    }

                    let target_str = normalized_target.to_string_lossy();
                    if target_str.starts_with('/')
                        || target_str.starts_with('\\')
                        || target_str.starts_with(r"\\?\")
                        || target_str.starts_with(r"\??\")
                        || target_str.starts_with("//?/")
                        || target_str.starts_with(r"\\.\")
                        || target_str.starts_with("//./")
                    {
                        return Err(FsError::AbsolutePath {
                            path: normalized_target,
                        });
                    }

                    let bytes = target_str.as_bytes();
                    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
                        return Err(FsError::AbsolutePath {
                            path: normalized_target,
                        });
                    }

                    for comp in normalized_target.components() {
                        if matches!(comp, Component::Prefix(_) | Component::RootDir) {
                            return Err(FsError::AbsolutePath {
                                path: normalized_target,
                            });
                        }
                    }

                    let cleaned_target = clean(&normalized_target);

                    // If cleaned target starts with '..' or is root/absolute, it escapes destination
                    if cleaned_target.starts_with("..")
                        || cleaned_target.is_absolute()
                        || cleaned_target.has_root()
                    {
                        return Err(FsError::EscapingSymlink {
                            link: relative_path.clone(),
                            target: normalized_target,
                        });
                    }

                    validate_entry_path(&cleaned_target)?;

                    let source_full = verbatim_dest.join(&cleaned_target);
                    let clean_source = clean(&source_full);
                    let clean_dest = clean(&verbatim_dest);
                    if !clean_source.starts_with(&clean_dest) {
                        return Err(FsError::EscapingSymlink {
                            link: relative_path.clone(),
                            target: normalized_target,
                        });
                    }

                    #[cfg(windows)]
                    let is_symlink_or_junction = source_full.is_symlink()
                        || crate::junction::is_junction(&source_full).unwrap_or(false);
                    #[cfg(not(windows))]
                    let is_symlink_or_junction = source_full.is_symlink();

                    let norm_cleaned = normalize_rel_path(&cleaned_target);
                    let mut has_symlink_ancestor = symlink_paths.contains(&cleaned_target)
                        || symlink_paths.contains(&norm_cleaned)
                        || is_symlink_or_junction;

                    if !has_symlink_ancestor {
                        for ancestor in norm_cleaned.ancestors() {
                            if !ancestor.as_os_str().is_empty() && symlink_paths.contains(ancestor)
                            {
                                has_symlink_ancestor = true;
                                break;
                            }
                        }
                    }

                    if !has_symlink_ancestor {
                        let mut curr_p = source_full.parent();
                        while let Some(p) = curr_p {
                            if p == verbatim_dest || p.as_os_str().is_empty() {
                                break;
                            }
                            if !p.starts_with(&verbatim_dest) {
                                break;
                            }
                            if let Ok(meta) = fs::symlink_metadata(p) {
                                if meta.file_type().is_symlink() {
                                    has_symlink_ancestor = true;
                                    break;
                                }
                                #[cfg(windows)]
                                if crate::junction::is_junction(p).unwrap_or(false) {
                                    has_symlink_ancestor = true;
                                    break;
                                }
                            }
                            curr_p = p.parent();
                        }
                    }

                    if has_symlink_ancestor {
                        return Err(FsError::EscapingSymlink {
                            link: relative_path.clone(),
                            target: normalized_target,
                        });
                    }

                    // Check for circular hardlink
                    if cleaned_target == relative_path {
                        return Err(FsError::CircularHardlink {
                            link: relative_path.clone(),
                            target: normalized_target,
                        });
                    }
                    let mut curr = cleaned_target.clone();
                    let mut visited = HashSet::new();
                    visited.insert(relative_path.clone());
                    while let Some(next) = hardlink_targets.get(&curr) {
                        if !visited.insert(curr.clone()) || curr == relative_path {
                            return Err(FsError::CircularHardlink {
                                link: relative_path.clone(),
                                target: normalized_target,
                            });
                        }
                        curr = next.clone();
                    }

                    // Reject dangling hardlinks: hardlinks can only point to previously extracted regular files
                    if (!extracted_regular_files.contains(&cleaned_target)
                        && !extracted_regular_files.contains(&norm_cleaned))
                        || !source_full.exists()
                        || !source_full.is_file()
                    {
                        return Err(FsError::DanglingHardlink {
                            link: relative_path.clone(),
                            target: normalized_target,
                        });
                    }

                    if let Some(parent) = target_path.parent() {
                        fs::create_dir_all(parent)?;
                    }

                    unlink_target_path(&target_path);

                    if fs::hard_link(&source_full, &target_path).is_err() && source_full.is_file() {
                        let _ = fs::copy(&source_full, &target_path);
                    }

                    hardlink_targets.insert(relative_path.clone(), cleaned_target);
                    extracted_regular_files.insert(relative_path.clone());
                    extracted_regular_files.insert(normalize_rel_path(&relative_path));
                }
            }
            continue;
        }

        // Unpack entry with size and ratio checks
        if entry_type.is_dir() {
            if !target_path.is_dir() {
                unlink_target_path(&target_path);
                fs::create_dir_all(&target_path)?;
            }
        } else if entry_type.is_file() {
            // Check single entry size limit from header if available
            if let Ok(entry_size) = entry.header().size() {
                if entry_size > limits.max_single_entry_size {
                    return Err(FsError::TarBombLimitExceeded {
                        limit_type: "entry size".to_string(),
                        detail: format!(
                            "Entry size {} exceeded single file limit of {} bytes",
                            entry_size, limits.max_single_entry_size
                        ),
                    });
                }
                if total_uncompressed.saturating_add(entry_size) > limits.max_uncompressed_size {
                    return Err(FsError::TarBombLimitExceeded {
                        limit_type: "uncompressed size".to_string(),
                        detail: format!(
                            "Projected uncompressed size exceeds limit of {} bytes",
                            limits.max_uncompressed_size
                        ),
                    });
                }
            }

            // Replace the directory entry before opening it: truncating an existing
            // symlink or hardlink would modify the linked file, possibly outside dest.
            unlink_target_path(&target_path);

            if let Ok(0) = entry.header().size() {
                crate::writer::write_file_fast(&target_path, &[], mode, 64 * 1024)
                    .map_err(FsError::Io)?;
                symlink_paths.remove(&relative_path);
                symlink_paths.remove(&normalize_rel_path(&relative_path));
                extracted_regular_files.insert(relative_path.clone());
                extracted_regular_files.insert(normalize_rel_path(&relative_path));
                continue;
            }

            let mut raw_file = match File::create(&target_path) {
                Ok(f) => f,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    if let Some(parent) = target_path.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    File::create(&target_path)?
                }
                Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                    unlink_target_path(&target_path);
                    #[cfg(windows)]
                    if let Ok(meta) = fs::metadata(&target_path) {
                        let mut perms = meta.permissions();
                        if perms.readonly() {
                            perms.set_readonly(false);
                            let _ = fs::set_permissions(&target_path, perms);
                        }
                    }
                    #[cfg(unix)]
                    if let Ok(meta) = fs::metadata(&target_path) {
                        use std::os::unix::fs::PermissionsExt;
                        let mut perms = meta.permissions();
                        perms.set_mode(perms.mode() | 0o600);
                        let _ = fs::set_permissions(&target_path, perms);
                    }
                    File::create(&target_path)?
                }
                Err(err) => return Err(err.into()),
            };
            loop {
                let t_read = std::time::Instant::now();
                let n = entry.read(&mut copy_buf).map_err(FsError::Io)?;
                inflate_nanos += t_read.elapsed().as_nanos() as u64;
                if n == 0 {
                    break;
                }
                io::Write::write_all(&mut raw_file, &copy_buf[..n])?;
                total_uncompressed += n as u64;

                // Check max uncompressed size
                if total_uncompressed > limits.max_uncompressed_size {
                    return Err(FsError::TarBombLimitExceeded {
                        limit_type: "uncompressed size".to_string(),
                        detail: format!(
                            "Uncompressed size {} exceeded limit of {} bytes",
                            total_uncompressed, limits.max_uncompressed_size
                        ),
                    });
                }

                // Real-time check for high-ratio tar bombs in-flight (threshold 50KB)
                if total_uncompressed > 50_000 {
                    let compressed_so_far = compressed_counter.load(Ordering::Relaxed);
                    let ratio = if compressed_so_far == 0 {
                        f64::INFINITY
                    } else {
                        total_uncompressed as f64 / compressed_so_far as f64
                    };
                    if ratio > limits.max_compression_ratio {
                        return Err(FsError::TarBombLimitExceeded {
                            limit_type: "compression ratio".to_string(),
                            detail: format!(
                                "Compression ratio {:.1}:1 exceeded limit of {:.1}:1",
                                ratio, limits.max_compression_ratio
                            ),
                        });
                    }
                }
            }
            drop(raw_file);
            symlink_paths.remove(&relative_path);
            symlink_paths.remove(&normalize_rel_path(&relative_path));
            extracted_regular_files.insert(relative_path.clone());
            extracted_regular_files.insert(normalize_rel_path(&relative_path));
        }
    }

    // Final check for compression ratio after extraction
    let compressed_bytes = compressed_counter.load(Ordering::Relaxed);
    if total_uncompressed > 50_000 {
        let ratio = if compressed_bytes == 0 {
            f64::INFINITY
        } else {
            total_uncompressed as f64 / compressed_bytes as f64
        };
        if ratio > limits.max_compression_ratio {
            return Err(FsError::TarBombLimitExceeded {
                limit_type: "compression ratio".to_string(),
                detail: format!(
                    "Compression ratio {:.1}:1 exceeded limit of {:.1}:1",
                    ratio, limits.max_compression_ratio
                ),
            });
        }
    }

    record_files_created_batch(entry_count as u64, total_uncompressed);
    let total_elapsed = start_extract.elapsed();
    let inflate_duration = std::time::Duration::from_nanos(inflate_nanos);
    let materialize_duration = total_elapsed.saturating_sub(inflate_duration);

    Ok(ExtractionSummary {
        entries_extracted: entry_count,
        total_uncompressed_bytes: total_uncompressed,
        inflate_duration,
        materialize_duration,
    })
}

/// Safely unlinks a pre-existing target path before creating a new entry.
/// On Windows, directory junctions are safely unlinked using `remove_junction` or `fs::remove_dir`
/// to prevent `fs::remove_file` failures and avoid deleting target contents.
pub(crate) fn unlink_target_path(path: &Path) {
    #[cfg(windows)]
    if crate::junction::is_junction(path).unwrap_or(false) {
        let _ = crate::junction::remove_junction(path);
        return;
    }
    if path.is_symlink() || path.is_file() {
        #[cfg(windows)]
        if let Ok(meta) = fs::metadata(path) {
            let mut perms = meta.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                let _ = fs::set_permissions(path, perms);
            }
        }
        let _ = fs::remove_file(path);
    }
}

pub(crate) fn normalize_rel_path(path: &Path) -> PathBuf {
    PathBuf::from(path.to_string_lossy().replace('\\', "/"))
}

#[allow(dead_code)]
fn is_link_pointing_outside(link: &Path, destination: &Path) -> bool {
    let verbatim_dest = crate::path::to_verbatim_path(destination);

    if let Ok(target) = fs::read_link(link) {
        let resolved = if target.is_absolute() {
            target
        } else {
            link.parent().unwrap_or(destination).join(target)
        };
        let cleaned = crate::path::to_verbatim_path(&resolved);
        if !cleaned.starts_with(&verbatim_dest) {
            return true;
        }
    }

    if let Ok(canonical) = fs::canonicalize(link) {
        let canonical_target = crate::path::to_verbatim_path(&canonical);
        let canonical_dest = fs::canonicalize(destination)
            .map(|d| crate::path::to_verbatim_path(&d))
            .unwrap_or_else(|_| verbatim_dest);
        if !canonical_target.starts_with(&canonical_dest) {
            return true;
        }
    }

    false
}

/// Security helper ensuring neither target nor any intermediate ancestor directory
/// between destination and target is a symlink or junction pointing outside destination
/// or created by an earlier tarball entry.
pub fn ensure_no_symlink_ancestors(
    target: &Path,
    destination: &Path,
    symlink_paths: &HashSet<PathBuf>,
    relative_path: &Path,
) -> Result<(), FsError> {
    ensure_no_symlink_ancestors_with_cache(target, destination, symlink_paths, relative_path, None)
}

pub fn ensure_no_symlink_ancestors_with_cache(
    target: &Path,
    destination: &Path,
    symlink_paths: &HashSet<PathBuf>,
    relative_path: &Path,
    mut safe_cache: Option<&mut HashSet<PathBuf>>,
) -> Result<(), FsError> {
    // 1. Check if any intermediate ancestor directory was created as a symlink/junction by an earlier entry
    let norm_rel = normalize_rel_path(relative_path);
    for ancestor in norm_rel.ancestors() {
        if !ancestor.as_os_str().is_empty()
            && ancestor != norm_rel
            && symlink_paths.contains(ancestor)
        {
            return Err(FsError::EscapingSymlink {
                link: destination.join(ancestor),
                target: target.to_path_buf(),
            });
        }
    }

    // 2. Check if target_path itself was created as a symlink/junction by an earlier entry
    if symlink_paths.contains(&norm_rel) {
        return Err(FsError::EscapingSymlink {
            link: target.to_path_buf(),
            target: target.to_path_buf(),
        });
    }

    // 3. Check all intermediate ancestors between destination and target on disk
    let mut current = target.parent();
    let mut newly_verified = Vec::new();
    while let Some(parent) = current {
        if parent == destination || parent.as_os_str().is_empty() {
            break;
        }
        if !parent.starts_with(destination) {
            break;
        }
        if let Some(ref cache) = safe_cache {
            if cache.contains(parent) {
                break;
            }
        }
        if let Ok(meta) = fs::symlink_metadata(parent) {
            if meta.file_type().is_symlink() {
                return Err(FsError::EscapingSymlink {
                    link: parent.to_path_buf(),
                    target: target.to_path_buf(),
                });
            }
            #[cfg(windows)]
            {
                if crate::junction::is_junction(parent).unwrap_or(false) {
                    return Err(FsError::EscapingSymlink {
                        link: parent.to_path_buf(),
                        target: target.to_path_buf(),
                    });
                }
            }
        }
        newly_verified.push(parent.to_path_buf());
        current = parent.parent();
    }
    if let Some(ref mut cache) = safe_cache {
        for p in newly_verified {
            cache.insert(p);
        }
    }
    Ok(())
}

/// Strips the first archive-root component from a tar entry path.
///
/// npm packages are normally packed below `package/`, but published tarballs
/// also use generated roots such as `mscdex-busboy-<sha>/`. npm strips one
/// component regardless of its name, so extraction must do the same. Leading
/// `./` components are ignored; a path consisting only of the root component
/// returns `None` because it has no extracted payload.
pub fn strip_package_prefix(path: &Path) -> Option<PathBuf> {
    let mut components = path.components().peekable();
    while let Some(Component::CurDir) = components.peek() {
        components.next();
    }

    let first = components.next()?;
    if matches!(first, Component::Normal(_)) {
        while let Some(Component::CurDir) = components.peek() {
            components.next();
        }
        let remainder: PathBuf = components.collect();
        if remainder.as_os_str().is_empty() {
            return None;
        }
        return Some(remainder);
    }

    // Preserve paths beginning with a parent/prefix component. They are
    // validated by the caller and must not be normalized before validation.
    Some(path.to_path_buf())
}

/// Validates that path contains no traversal, absolute prefixes, Windows device names, trailing dots/spaces, or non-UTF-8 components.
pub fn validate_entry_path(path: &Path) -> Result<(), FsError> {
    let path_str = match path.to_str() {
        Some(s) => s,
        None => {
            return Err(FsError::InvalidUtf8Path {
                path: path.to_path_buf(),
            });
        }
    };

    if path_str.is_empty() {
        return Ok(());
    }

    // Reject absolute paths, UNC paths, verbatim paths across all platforms
    if path.is_absolute()
        || path_str.starts_with('/')
        || path_str.starts_with('\\')
        || path_str.starts_with(r"\\?\")
        || path_str.starts_with(r"\??\")
        || path_str.starts_with("//?/")
        || path_str.starts_with(r"\\.\")
        || path_str.starts_with("//./")
    {
        return Err(FsError::AbsolutePath {
            path: path.to_path_buf(),
        });
    }

    // Reject Windows drive letters: "C:foo", "c:/...", "D:\...", etc.
    let bytes = path_str.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(FsError::AbsolutePath {
            path: path.to_path_buf(),
        });
    }

    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                return Err(FsError::AbsolutePath {
                    path: path.to_path_buf(),
                });
            }
            Component::ParentDir => {
                return Err(FsError::PathTraversal {
                    path: path.to_path_buf(),
                });
            }
            Component::CurDir => continue,
            Component::Normal(os_str) => {
                let name = match os_str.to_str() {
                    Some(s) => s,
                    None => {
                        return Err(FsError::InvalidUtf8Path {
                            path: path.to_path_buf(),
                        });
                    }
                };

                // Reject null bytes, colons, or backslashes (Windows Alternate Data Streams, drive colons, or traversal)
                if name.contains('\0') || name.contains(':') || name.contains('\\') {
                    return Err(FsError::PathTraversal {
                        path: path.to_path_buf(),
                    });
                }

                // Reject ASCII control characters (0x00 to 0x1F)
                if name.chars().any(|c| (c as u32) < 0x20) {
                    return Err(FsError::PathTraversal {
                        path: path.to_path_buf(),
                    });
                }

                // Reject Windows invalid characters: *, ?, ", <, >, |
                if name
                    .chars()
                    .any(|c| matches!(c, '*' | '?' | '"' | '<' | '>' | '|'))
                {
                    return Err(FsError::PathTraversal {
                        path: path.to_path_buf(),
                    });
                }

                // Reject Windows reserved device names: CON, PRN, AUX, NUL, COM0-9, LPT0-9, CLOCK$, CONIN$, CONOUT$, etc.
                // including with extensions (aux.js, com1.json) or embedded/trailing spaces/dots (aux .js, nul.)
                if is_windows_reserved_name(name) {
                    return Err(FsError::WindowsReservedDeviceName {
                        name: name.to_string(),
                        path: path.to_path_buf(),
                    });
                }

                // Reject trailing dot or trailing space in component
                if name.ends_with('.') || name.ends_with(' ') {
                    return Err(FsError::TrailingDotOrSpace {
                        name: name.to_string(),
                        path: path.to_path_buf(),
                    });
                }
            }
        }
    }

    Ok(())
}

/// Returns true if name is a Windows reserved device name (CON, PRN, AUX, NUL, COM0-9, LPT0-9, CLOCK$, CONIN$, CONOUT$),
/// superscripts (COM¹..³, LPT¹..³), reserved names with any extension (nul.txt, com1.json, aux.js),
/// trailing dots/spaces or embedded whitespace (aux .js, nul.), or NTFS Alternate Data Streams (file:stream, foo:$DATA).
pub fn is_windows_reserved_name(name: &str) -> bool {
    // 1. NTFS Alternate Data Streams (e.g. file:stream, foo:$DATA, nul:stream)
    if name.contains(':') {
        return true;
    }

    // 2. Extract base stem before any extension: split on '.'
    // Trim trailing spaces and dots from the base stem (e.g. "aux .js", "nul.", "com1  .json")
    let base = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim_matches(|c: char| c == ' ' || c == '.');

    if base.is_empty() {
        return false;
    }

    let upper = base.to_ascii_uppercase();

    match upper.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$" => true,
        "COM0" | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9" => {
            true
        }
        "LPT0" | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9" => {
            true
        }
        "COM\u{00B9}" | "COM\u{00B2}" | "COM\u{00B3}" => true,
        "LPT\u{00B9}" | "LPT\u{00B2}" | "LPT\u{00B3}" => true,
        _ => false,
    }
}

pub fn validate_link_target(
    link_path: &Path,
    target: &Path,
    destination: &Path,
) -> Result<PathBuf, FsError> {
    let target_str = match target.to_str() {
        Some(s) => s,
        None => {
            return Err(FsError::InvalidUtf8Path {
                path: target.to_path_buf(),
            });
        }
    };

    if target.is_absolute()
        || target.has_root()
        || target_str.starts_with('/')
        || target_str.starts_with('\\')
        || target_str.starts_with(r"\\?\")
        || target_str.starts_with(r"\??\")
        || target_str.starts_with("//?/")
        || target_str.starts_with(r"\\.\")
        || target_str.starts_with("//./")
    {
        return Err(FsError::AbsolutePath {
            path: target.to_path_buf(),
        });
    }

    let bytes = target_str.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(FsError::AbsolutePath {
            path: target.to_path_buf(),
        });
    }

    for comp in target.components() {
        if matches!(comp, Component::Prefix(_) | Component::RootDir) {
            return Err(FsError::AbsolutePath {
                path: target.to_path_buf(),
            });
        }
    }

    // Resolve target relative to link parent
    let normalized_target_str = target_str.replace('\\', "/");
    let norm_target = Path::new(&normalized_target_str);
    let link_dir = link_path.parent().unwrap_or_else(|| Path::new(""));
    let combined = link_dir.join(norm_target);
    let cleaned = clean(&combined);

    // If cleaned path starts with '..' or is root/absolute, it escapes destination
    if cleaned.starts_with("..") || cleaned.is_absolute() || cleaned.has_root() {
        return Err(FsError::EscapingSymlink {
            link: link_path.to_path_buf(),
            target: target.to_path_buf(),
        });
    }

    // Verify containment against destination
    let verbatim_dest = crate::path::to_verbatim_path(destination);
    let full_target = verbatim_dest.join(&cleaned);
    let clean_full = clean(&full_target);
    let clean_dest = clean(&verbatim_dest);

    if !clean_full.starts_with(&clean_dest) {
        return Err(FsError::EscapingSymlink {
            link: link_path.to_path_buf(),
            target: target.to_path_buf(),
        });
    }

    // Also validate the cleaned destination-relative path against traversal and reserved names
    validate_entry_path(&cleaned)?;

    Ok(cleaned)
}

// ============================================================================
// Packaging (rnpm pack) support
// ============================================================================

/// Metadata and content for an entry to be packed into the tarball.
#[derive(Debug, Clone)]
pub struct PackedFileEntry {
    /// Relative path inside the package, e.g. "package.json" or "lib/index.js"
    pub path: String,
    /// Uncompressed size in bytes
    pub size: u64,
    /// Normalized POSIX file permissions mode, e.g. 0o644 or 0o755
    pub mode: u32,
}

/// Summary report returned upon successful tarball creation.
#[derive(Debug, Clone)]
pub struct PackSummary {
    pub name: String,
    pub version: String,
    pub filename: String,
    /// Compressed .tgz size in bytes
    pub package_size: u64,
    /// Total uncompressed size of all contained files
    pub unpacked_size: u64,
    /// Hex-encoded SHA-1 hash of the compressed .tgz archive
    pub shasum: String,
    /// Full SSRI integrity string: `sha512-...`
    pub integrity: String,
    /// List of bundled files
    pub files: Vec<PackedFileEntry>,
    pub entry_count: usize,
    pub bundled: Vec<String>,
}

/// Compute canonical tarball filename for a package:
/// `@scope/pkg` @ `1.0.0` -> `scope-pkg-1.0.0.tgz`
/// `pkg` @ `1.0.0` -> `pkg-1.0.0.tgz`
pub fn compute_tarball_filename(name: &str, version: &str) -> String {
    let clean_name = name.replace('@', "").replace('/', "-");
    format!("{clean_name}-{version}.tgz")
}

/// Collect files to pack according to npm pack rules:
/// 1. If `files` array is defined in package.json, only include matching files + strictly required files.
/// 2. If `.npmignore` exists, use its patterns to exclude files; else if `.gitignore` exists, use it.
/// 3. Always include `package.json`, `README*`, `LICENSE*`, `LICENCE*`, `COPYING*`, `main`, and `bin`.
/// 4. Always exclude `.git*`, `node_modules/`, `.npmrc`, `package-lock.json`, and lockfiles.
pub fn collect_pack_files(
    package_dir: &Path,
    manifest: &Manifest,
) -> Result<Vec<(String, PathBuf)>, FsError> {
    let mut files_to_pack = Vec::new();

    // Check for ignore file
    let npmignore_path = package_dir.join(".npmignore");
    let gitignore_path = package_dir.join(".gitignore");

    let ignore_patterns = if manifest.files.is_some() {
        // npm-packlist's package.json rules disable both root ignore files.
        Vec::new()
    } else if npmignore_path.is_file() {
        parse_ignore_patterns(&npmignore_path)?
    } else if gitignore_path.is_file() {
        parse_ignore_patterns(&gitignore_path)?
    } else {
        Vec::new()
    };

    let files_filter: Option<Vec<String>> = manifest.files.clone();

    // Walk package_dir recursively
    walk_dir_collect(
        package_dir,
        package_dir,
        &files_filter,
        &[(String::new(), ignore_patterns)],
        manifest,
        &mut files_to_pack,
    )?;

    // Ensure strictly required files exist in files_to_pack if present on disk
    let required_rel_paths = collect_strictly_required_files(package_dir, manifest);
    let mut existing_set: HashSet<String> = files_to_pack.iter().map(|(r, _)| r.clone()).collect();

    for rel_path in required_rel_paths {
        if !existing_set.contains(&rel_path) {
            let full = package_dir.join(&rel_path);
            if full.is_file() {
                existing_set.insert(rel_path.clone());
                files_to_pack.push((rel_path, full));
            }
        }
    }

    // Include bundled dependency files from node_modules/<bundled_pkg>
    for bundled_name in manifest.bundled_package_names() {
        let bundled_dir = package_dir.join("node_modules").join(&bundled_name);
        if bundled_dir.is_dir() {
            walk_bundled_dependency_dir(
                &bundled_dir,
                package_dir,
                &mut files_to_pack,
                &mut existing_set,
            )?;
        }
    }

    // Sort files according to npm order:
    // uppercase initial files first sorted alphabetically, then others sorted alphabetically
    files_to_pack.sort_by(|a, b| sort_pack_file_paths(&a.0, &b.0));

    Ok(files_to_pack)
}

fn walk_bundled_dependency_dir(
    dir: &Path,
    root_dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
    existing: &mut HashSet<String>,
) -> Result<(), FsError> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let rel_path_buf = match path.strip_prefix(root_dir) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let rel_path = rel_path_buf
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");

        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if filename == ".git" || filename == ".gitignore" || filename == ".DS_Store" {
            continue;
        }

        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        if file_type.is_dir() {
            walk_bundled_dependency_dir(&path, root_dir, out, existing)?;
        } else if file_type.is_file() && !existing.contains(&rel_path) {
            existing.insert(rel_path.clone());
            out.push((rel_path, path));
        }
    }

    Ok(())
}

fn collect_strictly_required_files(package_dir: &Path, manifest: &Manifest) -> Vec<String> {
    let mut required = Vec::new();

    // package.json is always required
    required.push("package.json".to_string());

    // main script
    if let Some(main) = &manifest.main {
        let clean_main = main.trim_start_matches("./").trim_start_matches('/');
        required.push(clean_main.to_string());
    }

    // bins
    for (_, bin_path) in manifest.bin_entries() {
        let clean_bin = bin_path.trim_start_matches("./").trim_start_matches('/');
        required.push(clean_bin.to_string());
    }

    // npm-packlist promotes literal files entries to strict requirements. These
    // survive even an ignore file in their parent directory; directory/glob
    // entries remain subject to nested ignore rules.
    if let Some(files) = &manifest.files {
        for file in files {
            let clean = file
                .strip_prefix("./")
                .unwrap_or(file)
                .trim_start_matches('/');
            if package_dir.join(clean).is_file() && !is_strictly_excluded(clean, false) {
                required.push(clean.to_string());
            }
        }
    }

    // Look for README*, LICENSE*, LICENCE*, COPYING* in root
    if let Ok(entries) = fs::read_dir(package_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let upper = name.to_ascii_uppercase();
            if (upper.starts_with("README")
                || upper.starts_with("LICENSE")
                || upper.starts_with("LICENCE")
                || upper.starts_with("COPYING"))
                && entry.path().is_file()
            {
                required.push(name);
            }
        }
    }

    required
}

fn walk_dir_collect(
    current_dir: &Path,
    root_dir: &Path,
    files_filter: &Option<Vec<String>>,
    inherited_ignores: &[(String, Vec<String>)],
    manifest: &Manifest,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), FsError> {
    let mut ignore_scopes = inherited_ignores.to_vec();
    if current_dir != root_dir {
        let local = if current_dir.join(".npmignore").is_file() {
            current_dir.join(".npmignore")
        } else {
            current_dir.join(".gitignore")
        };
        let prefix = current_dir
            .strip_prefix(root_dir)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        ignore_scopes.push((format!("{prefix}/"), parse_ignore_patterns(&local)?));
    }
    let entries = match fs::read_dir(current_dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let rel_path_buf = match path.strip_prefix(root_dir) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let rel_path = rel_path_buf
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");

        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        // Check strictly excluded names
        if is_strictly_excluded(&rel_path, file_type.is_dir()) {
            continue;
        }

        if file_type.is_dir() {
            // Check if directory itself is ignored
            if is_path_ignored(&rel_path, &ignore_scopes) {
                continue;
            }
            walk_dir_collect(&path, root_dir, files_filter, &ignore_scopes, manifest, out)?;
        } else if file_type.is_file() {
            // Check if file is included
            if should_include_file(&rel_path, files_filter, &ignore_scopes, manifest) {
                out.push((rel_path, path));
            }
        }
    }

    Ok(())
}

fn is_strictly_excluded(rel_path: &str, is_dir: bool) -> bool {
    let filename = rel_path.split('/').next_back().unwrap_or(rel_path);

    // Hard exclusions matching npm
    if rel_path == ".git"
        || rel_path.starts_with(".git/")
        || filename == ".git"
        || filename == ".gitignore"
        || filename == ".npmignore"
        || filename == ".npmrc"
        || rel_path == "node_modules"
        || rel_path.starts_with("node_modules/")
        || filename == "package-lock.json"
        || filename == "yarn.lock"
        || filename == "pnpm-lock.yaml"
        || filename == "bun.lockb"
        || filename == "npm-debug.log"
        || filename == ".DS_Store"
    {
        return true;
    }

    if is_dir && (filename == ".svn" || filename == ".hg" || filename == "CVS") {
        return true;
    }

    false
}

fn should_include_file(
    rel_path: &str,
    files_filter: &Option<Vec<String>>,
    ignore_patterns: &[(String, Vec<String>)],
    manifest: &Manifest,
) -> bool {
    // 1. If it's an always-included root file
    if is_always_included_file(rel_path, manifest) {
        return true;
    }

    // 2. If `files` array is present in package.json
    if let Some(patterns) = files_filter {
        let matched = patterns.iter().any(|pattern| {
            let clean = pattern.trim_start_matches("./").trim_start_matches('/');
            let clean_no_slash = clean.trim_end_matches('/');

            // Exact match
            if rel_path == clean_no_slash {
                return true;
            }
            // Directory match
            if rel_path.starts_with(&format!("{clean_no_slash}/")) {
                return true;
            }
            // Glob match against the file or a directory containing it
            match_glob_or_parent(clean_no_slash, rel_path)
        });

        if !matched {
            return false;
        }

        // Only directory-local ignore rules remain when files is present.
        if is_path_ignored(rel_path, ignore_patterns) {
            return false;
        }

        return true;
    }

    // 3. Without `files` array, check ignore patterns
    !is_path_ignored(rel_path, ignore_patterns)
}

fn is_always_included_file(rel_path: &str, manifest: &Manifest) -> bool {
    if rel_path == "package.json" {
        return true;
    }

    if let Some(main) = &manifest.main {
        let clean = main.trim_start_matches("./").trim_start_matches('/');
        if rel_path == clean {
            return true;
        }
    }

    for (_, bin_path) in manifest.bin_entries() {
        let clean = bin_path.trim_start_matches("./").trim_start_matches('/');
        if rel_path == clean {
            return true;
        }
    }

    // Root README, LICENSE, LICENCE, COPYING
    if !rel_path.contains('/') {
        let upper = rel_path.to_ascii_uppercase();
        if upper.starts_with("README")
            || upper.starts_with("LICENSE")
            || upper.starts_with("LICENCE")
            || upper.starts_with("COPYING")
        {
            return true;
        }
    }

    false
}

fn parse_ignore_patterns(path: &Path) -> Result<Vec<String>, FsError> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };

    let mut patterns = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        patterns.push(trimmed.to_string());
    }

    Ok(patterns)
}

fn is_path_ignored(rel_path: &str, scopes: &[(String, Vec<String>)]) -> bool {
    let mut ignored = false;
    for (prefix, patterns) in scopes {
        let Some(local_path) = rel_path.strip_prefix(prefix) else {
            continue;
        };
        for pattern in patterns {
            let (rule, is_negated) = if let Some(rule) = pattern.strip_prefix('!') {
                (rule.trim(), true)
            } else {
                (pattern.as_str(), false)
            };
            if match_ignore_rule(rule, local_path) {
                ignored = !is_negated;
            }
        }
    }

    ignored
}

fn match_ignore_rule(pattern: &str, path: &str) -> bool {
    let clean_pat = pattern.trim_start_matches('/');
    let target_path = path.trim_start_matches('/');

    // If pattern ends with '/', it only matches directories or contents
    if clean_pat.ends_with('/') {
        let dir_prefix = clean_pat;
        if target_path.starts_with(dir_prefix) || format!("{target_path}/").starts_with(dir_prefix)
        {
            return true;
        }
    }

    if clean_pat.trim_end_matches('/').contains('/') {
        if match_glob_or_parent(clean_pat.trim_end_matches('/'), target_path) {
            return true;
        }
    } else {
        // Pattern matches basename or any segment
        let basename = target_path.split('/').next_back().unwrap_or(target_path);
        if match_glob(clean_pat, basename) {
            return true;
        }
        for segment in target_path.split('/') {
            if match_glob(clean_pat, segment) {
                return true;
            }
        }
    }

    false
}

/// minimatch-style path glob: `*` and `?` stay within a segment, `**`
/// spans any number of segments (including none), `[...]` is a class and
/// `{a,b}` alternatives are expanded.
fn match_glob(pattern: &str, text: &str) -> bool {
    expand_braces(pattern).iter().any(|p| {
        let pat: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
        let txt: Vec<&str> = text.split('/').filter(|s| !s.is_empty()).collect();
        match_segments(&pat, &txt)
    })
}

/// True when the glob matches `text` or any directory containing it, which is
/// how ignore-walk treats a matched directory.
fn match_glob_or_parent(pattern: &str, text: &str) -> bool {
    let segments: Vec<&str> = text.split('/').filter(|s| !s.is_empty()).collect();
    (1..=segments.len()).any(|n| match_glob(pattern, &segments[..n].join("/")))
}

fn expand_braces(pattern: &str) -> Vec<String> {
    let Some(open) = pattern.find('{') else {
        return vec![pattern.to_string()];
    };
    let mut depth = 0;
    let mut close = None;
    for (i, c) in pattern[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close) = close else {
        return vec![pattern.to_string()];
    };
    let inner = &pattern[open + 1..close];
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0, 0);
    for (i, c) in inner.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&inner[start..]);
    if parts.len() < 2 {
        return vec![pattern.to_string()];
    }
    let (head, tail) = (&pattern[..open], &pattern[close + 1..]);
    parts
        .into_iter()
        .flat_map(|part| expand_braces(&format!("{head}{part}{tail}")))
        .collect()
}

fn match_segments(pat: &[&str], txt: &[&str]) -> bool {
    match pat.first() {
        None => txt.is_empty(),
        Some(&"**") => {
            // `**` never matches dot-entries, mirroring minimatch's default.
            match_segments(&pat[1..], txt)
                || (!txt.is_empty()
                    && !txt[0].starts_with('.')
                    && match_segments(pat, &txt[1..]))
        }
        Some(seg) => {
            !txt.is_empty() && match_segment(seg, txt[0]) && match_segments(&pat[1..], &txt[1..])
        }
    }
}

fn match_segment(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // A leading wildcard does not match a leading dot (minimatch `dot: false`).
    if t.first() == Some(&'.') && matches!(p.first(), Some('*') | Some('?') | Some('[')) {
        return false;
    }
    fn go(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') => (0..=t.len()).any(|i| go(&p[1..], &t[i..])),
            Some('?') => !t.is_empty() && go(&p[1..], &t[1..]),
            Some('[') => {
                let Some(end) = p.iter().skip(1).position(|c| *c == ']').map(|i| i + 1) else {
                    return !t.is_empty() && t[0] == '[' && go(&p[1..], &t[1..]);
                };
                let Some(&c) = t.first() else { return false };
                let mut class = &p[1..end];
                let negate = matches!(class.first(), Some('!') | Some('^'));
                if negate {
                    class = &class[1..];
                }
                let mut hit = false;
                let mut i = 0;
                while i < class.len() {
                    if i + 2 < class.len() && class[i + 1] == '-' {
                        hit |= class[i] <= c && c <= class[i + 2];
                        i += 3;
                    } else {
                        hit |= class[i] == c;
                        i += 1;
                    }
                }
                hit != negate && go(&p[end + 1..], &t[1..])
            }
            Some('\\') if p.len() > 1 => !t.is_empty() && t[0] == p[1] && go(&p[2..], &t[1..]),
            Some(&c) => !t.is_empty() && t[0] == c && go(&p[1..], &t[1..]),
        }
    }
    go(&p, &t)
}

/// Sort helper for npm pack files:
/// Files starting with uppercase letter come first (alphabetical),
/// followed by others (alphabetical).
#[cfg(test)]
mod glob_tests {
    use super::{match_glob, match_glob_or_parent};

    #[test]
    fn globstar_matches_any_depth_including_none() {
        assert!(match_glob("secrets/**/*.pem", "secrets/prod/key.pem"));
        assert!(match_glob("secrets/**/*.pem", "secrets/key.pem"));
        assert!(match_glob("dist/**/*.js", "dist/sub/deep/index.js"));
        assert!(!match_glob("dist/**/*.js", "dist/sub/index.ts"));
        assert!(!match_glob("dist/*.js", "dist/sub/index.js"));
    }

    #[test]
    fn classes_braces_and_question_marks() {
        assert!(match_glob("lib/*.{js,cjs}", "lib/a.cjs"));
        assert!(!match_glob("lib/*.{js,cjs}", "lib/a.ts"));
        assert!(match_glob("file?.txt", "file1.txt"));
        assert!(match_glob("v[0-9].js", "v7.js"));
        assert!(!match_glob("v[!0-9].js", "v7.js"));
    }

    #[test]
    fn wildcards_skip_dotfiles_like_minimatch() {
        assert!(!match_glob("*", ".env"));
        assert!(!match_glob("**/*.js", ".hidden/a.js"));
    }

    #[test]
    fn matched_directories_cover_their_contents() {
        assert!(match_glob_or_parent("secrets/prod", "secrets/prod/key.pem"));
        assert!(!match_glob_or_parent("secrets/prod", "secrets/production/key.pem"));
    }
}

fn sort_pack_file_paths(a: &str, b: &str) -> std::cmp::Ordering {
    let a_first_char = a.chars().next().unwrap_or('\0');
    let b_first_char = b.chars().next().unwrap_or('\0');

    let a_is_upper = a_first_char.is_ascii_uppercase();
    let b_is_upper = b_first_char.is_ascii_uppercase();

    match (a_is_upper, b_is_upper) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.cmp(b),
    }
}

/// Create a tar.gz package archive for the project directory.
/// All file paths inside the archive are prefixed with `package/`.
/// All entries are created with POSIX normalized mode (0o644 or 0o755) and mtime (499162500).
pub fn pack_directory(
    package_dir: &Path,
    dest_tarball_path: Option<&Path>,
) -> Result<(PackSummary, Vec<u8>), FsError> {
    let manifest_path = package_dir.join("package.json");
    if !manifest_path.is_file() {
        return Err(FsError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("package.json not found in {}", package_dir.display()),
        )));
    }

    let manifest = Manifest::from_file(&manifest_path)
        .map_err(|e| FsError::Io(io::Error::new(io::ErrorKind::InvalidData, e.to_string())))?;

    let name = manifest
        .name
        .clone()
        .unwrap_or_else(|| "package".to_string());
    let version = manifest
        .version
        .clone()
        .unwrap_or_else(|| "1.0.0".to_string());
    let filename = compute_tarball_filename(&name, &version);

    let files_to_pack = collect_pack_files(package_dir, &manifest)?;
    // npm-packlist sorts archive entries by extension, basename, then path for
    // compressibility. The public file list keeps its separate display order.
    let mut archive_files: Vec<_> = files_to_pack.iter().collect();
    archive_files.sort_by_key(|(path, _)| {
        let file = Path::new(path);
        (
            file.extension()
                .unwrap_or_default()
                .to_string_lossy()
                .to_lowercase(),
            file.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_lowercase(),
            path.to_lowercase(),
        )
    });

    // Build tar archive in memory
    let mut tar_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_bytes);

        for (rel_path, full_path) in archive_files {
            let file_data = fs::read(full_path)?;
            let mut header = Header::new_ustar();
            header.set_size(file_data.len() as u64);

            // Normalized mtime
            header.set_mtime(NPM_PACK_EPOCH_MTIME);
            header.set_uid(0);
            header.set_gid(0);

            // Normalized mode
            let is_executable = is_file_executable(full_path);
            let mode = if is_executable {
                NPM_EXECUTABLE_FILE_MODE
            } else {
                NPM_DEFAULT_FILE_MODE
            };
            header.set_mode(mode);
            let entry_path = format!("package/{rel_path}");
            header.set_path(entry_path).map_err(FsError::Io)?;
            header.set_entry_type(tar::EntryType::Regular);
            // node-tar's portable USTAR encoder leaves uid/gid unset, and uses
            // octal digits followed by space + NUL (including checksum).
            let bytes = header.as_mut_bytes();
            bytes[108..124].fill(0);
            for (start, end, value) in [
                (100, 108, mode as u64),
                (124, 136, file_data.len() as u64),
                (136, 148, NPM_PACK_EPOCH_MTIME),
                (329, 337, 0),
                (337, 345, 0),
            ] {
                let encoded = format!("{:0width$o} \0", value, width = end - start - 2);
                bytes[start..end].copy_from_slice(encoded.as_bytes());
            }
            bytes[148..156].fill(b' ');
            let sum: u64 = bytes.iter().map(|b| *b as u64).sum();
            bytes[148..156].copy_from_slice(format!("{sum:06o} \0").as_bytes());
            builder
                .append(&header, &file_data[..])
                .map_err(FsError::Io)?;
        }

        builder.finish().map_err(FsError::Io)?;
    }

    // Compress with gzip level 9
    let compressed_bytes = npm_gzip(&tar_bytes)?;

    // Compute SHA-1 and SHA-512 hashes
    let sha1_digest = Algorithm::Sha1.compute_digest(&compressed_bytes);
    let shasum = data_encoding::HEXLOWER.encode(&sha1_digest);

    let integrity_obj = Integrity::from_bytes(&compressed_bytes, Algorithm::Sha512);
    let integrity_str = integrity_obj.to_string();

    let mut unpacked_size = 0u64;
    let mut summary_files = Vec::new();

    for (rel_path, full_path) in &files_to_pack {
        let meta = fs::metadata(full_path)?;
        let size = meta.len();
        unpacked_size += size;
        let mode = if is_file_executable(full_path) {
            NPM_EXECUTABLE_FILE_MODE
        } else {
            NPM_DEFAULT_FILE_MODE
        };
        summary_files.push(PackedFileEntry {
            path: rel_path.clone(),
            size,
            mode,
        });
    }

    let entry_count = summary_files.len();

    let summary = PackSummary {
        name,
        version,
        filename: filename.clone(),
        package_size: compressed_bytes.len() as u64,
        unpacked_size,
        shasum,
        integrity: integrity_str,
        files: summary_files,
        entry_count,
        bundled: manifest.bundled_package_names(),
    };

    // If destination path is provided, write out the compressed tarball
    if let Some(dest_path) = dest_tarball_path {
        let mut out = File::create(dest_path)?;
        out.write_all(&compressed_bytes)?;
    }

    Ok((summary, compressed_bytes))
}

/// npm's digests depend on the Node runtime's zlib byte stream. Different
/// compliant DEFLATE implementations produce different digests. Use only the
/// built-in zlib module, without requiring an npm installation.
fn npm_gzip(input: &[u8]) -> Result<Vec<u8>, FsError> {
    use std::process::{Command, Stdio};
    const SCRIPT: &str = "const {pipeline,Transform}=require('node:stream');let first=true;pipeline(process.stdin,require('node:zlib').createGzip({level:9}),new Transform({transform(b,e,cb){if(first){b[9]=255;first=false;}cb(null,b);}}),process.stdout,e=>{if(e){console.error(e.message);process.exitCode=1;}});";
    let mut command = Command::new("node");
    command
        .args(["-e", SCRIPT])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().map_err(FsError::Io)?;
    let mut stdin = child.stdin.take().expect("piped child stdin");
    let (output, written) = std::thread::scope(|scope| {
        // Drain stdout while feeding stdin so large archives cannot deadlock
        // when both OS pipes fill. Always reap the child, including EPIPE.
        let writer = scope.spawn(move || stdin.write_all(input));
        let output = child.wait_with_output();
        (output, writer.join())
    });
    let output = output.map_err(FsError::Io)?;
    if !output.status.success() {
        return Err(FsError::Io(std::io::Error::other(format!(
            "Node gzip failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))));
    }
    written
        .map_err(|_| FsError::Io(std::io::Error::other("gzip input writer panicked")))?
        .map_err(FsError::Io)?;
    Ok(output.stdout)
}

fn is_file_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            return meta.permissions().mode() & 0o111 != 0;
        }
    }

    #[cfg(windows)]
    {
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            let ext_lower = ext.to_ascii_lowercase();
            if ext_lower == "cmd" || ext_lower == "bat" || ext_lower == "ps1" || ext_lower == "exe"
            {
                return true;
            }
        }
    }

    false
}
