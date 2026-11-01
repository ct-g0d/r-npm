use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use flate2::read::GzDecoder;
use path_clean::clean;
use tar::Archive;
use crate::error::FsError;

#[derive(Debug, Clone, Copy)]
pub struct TarLimits {
    pub max_entries: usize,
    pub max_uncompressed_size: u64,
    pub max_compression_ratio: f64,
}

impl Default for TarLimits {
    fn default() -> Self {
        Self {
            max_entries: 50_000,
            max_uncompressed_size: 512 * 1024 * 1024, // 512 MB
            max_compression_ratio: 100.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExtractionSummary {
    pub entries_extracted: usize,
    pub total_uncompressed_bytes: u64,
}

pub struct CountingReader<R> {
    inner: R,
    bytes_read: u64,
}

impl<R: Read> CountingReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            bytes_read: 0,
        }
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read += n as u64;
        Ok(n)
    }
}

/// Extract a .tar.gz stream into destination, stripping the standard "package/" prefix
/// and enforcing all security and tar-bomb defenses.
pub fn extract_tar_gz<R: Read>(
    reader: R,
    destination: &Path,
    limits: Option<TarLimits>,
) -> Result<ExtractionSummary, FsError> {
    let limits = limits.unwrap_or_default();
    fs::create_dir_all(destination)?;

    let counting_reader = CountingReader::new(reader);
    let gz = GzDecoder::new(counting_reader);
    let mut archive = Archive::new(gz);

    let mut entry_count = 0;
    let mut total_uncompressed = 0;

    let entries = archive.entries().map_err(FsError::Io)?;

    for entry_res in entries {
        let mut entry = entry_res.map_err(FsError::Io)?;

        entry_count += 1;
        if entry_count > limits.max_entries {
            return Err(FsError::TarBombLimitExceeded {
                limit_type: "entry count".to_string(),
                detail: format!("Tarball exceeded maximum allowed entries: {}", limits.max_entries),
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

        // Get raw entry path
        let raw_path = entry.path().map_err(FsError::Io)?.to_path_buf();

        // Strip standard "package/" prefix
        let relative_path = match strip_package_prefix(&raw_path) {
            Some(p) => p,
            None => {
                // If this is the directory entry for "package" itself, skip it
                continue;
            }
        };

        // Security check: path traversal, absolute paths, device names, trailing dots/spaces
        validate_entry_path(&relative_path)?;

        let target_path = destination.join(&relative_path);

        // Security check: escaping symlinks/hardlinks
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            if let Some(link_target) = entry.link_name().map_err(FsError::Io)? {
                validate_link_target(&relative_path, &link_target, destination)?;
            }
        }

        // Unpack entry with size and ratio checks
        if entry_type.is_dir() {
            fs::create_dir_all(&target_path)?;
        } else if entry_type.is_file() {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut out_file = File::create(&target_path)?;
            let mut buf = [0u8; 8192];
            loop {
                let n = entry.read(&mut buf).map_err(FsError::Io)?;
                if n == 0 {
                    break;
                }
                io::Write::write_all(&mut out_file, &buf[..n])?;
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
            }
        }
    }

    // Check compression ratio after extraction
    let compressed_bytes = archive.into_inner().into_inner().bytes_read();
    if compressed_bytes > 0 && total_uncompressed > 1_000_000 {
        let ratio = total_uncompressed as f64 / compressed_bytes as f64;
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

    Ok(ExtractionSummary {
        entries_extracted: entry_count,
        total_uncompressed_bytes: total_uncompressed,
    })
}

/// Strips the standard "package/" prefix from tar entry path.
/// If path is exactly "package" or "package/", returns None.
pub fn strip_package_prefix(path: &Path) -> Option<PathBuf> {
    let mut components = path.components();
    let first = components.next()?;

    if let Component::Normal(os_str) = first {
        if os_str == "package" {
            let remainder: PathBuf = components.collect();
            if remainder.as_os_str().is_empty() {
                return None;
            }
            return Some(remainder);
        }
    }

    // Tarballs without package/ prefix are returned as is
    Some(path.to_path_buf())
}

/// Validates that path contains no traversal, absolute prefixes, Windows device names, or trailing dots/spaces.
pub fn validate_entry_path(path: &Path) -> Result<(), FsError> {
    if path.is_absolute() {
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
                let name = os_str.to_string_lossy();

                // Reject trailing dot or trailing space in component
                if name.ends_with('.') || name.ends_with(' ') {
                    return Err(FsError::TrailingDotOrSpace {
                        name: name.to_string(),
                        path: path.to_path_buf(),
                    });
                }

                // Reject Windows reserved device names: CON, PRN, AUX, NUL, COM1-9, LPT1-9
                if is_windows_reserved_name(&name) {
                    return Err(FsError::WindowsReservedDeviceName {
                        name: name.to_string(),
                        path: path.to_path_buf(),
                    });
                }
            }
        }
    }

    Ok(())
}

fn is_windows_reserved_name(name: &str) -> bool {
    // Check base name without extensions, e.g. "CON.txt" or "nul.tar.gz"
    let base = name.split('.').next().unwrap_or(name);
    let upper = base.to_ascii_uppercase();

    match upper.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" => true,
        "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9" => true,
        "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9" => true,
        _ => false,
    }
}

fn validate_link_target(
    link_path: &Path,
    target: &Path,
    _destination: &Path,
) -> Result<(), FsError> {
    if target.is_absolute() {
        return Err(FsError::AbsolutePath {
            path: target.to_path_buf(),
        });
    }

    // Resolve target relative to link parent
    let link_dir = link_path.parent().unwrap_or_else(|| Path::new(""));
    let combined = link_dir.join(target);
    let cleaned = clean(&combined);

    // If cleaned path starts with '..' it escapes destination
    if cleaned.starts_with("..") {
        return Err(FsError::EscapingSymlink {
            link: link_path.to_path_buf(),
            target: target.to_path_buf(),
        });
    }

    Ok(())
}
