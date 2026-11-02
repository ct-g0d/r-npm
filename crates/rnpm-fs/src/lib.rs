pub mod atomic;
pub mod error;
pub mod junction;
pub mod parallel;
pub mod tarball;

pub use atomic::{extract_and_replace, replace_dir_with_retries};
pub use error::FsError;
pub use junction::{create_junction, is_junction, remove_junction};
pub use parallel::{extract_batch_parallel, BatchExtractionItem};
pub use tarball::{
    collect_pack_files, compute_tarball_filename, extract_tar_gz, pack_directory,
    strip_package_prefix, validate_entry_path, ExtractionSummary, PackSummary, PackedFileEntry,
    TarLimits, NPM_DEFAULT_FILE_MODE, NPM_EXECUTABLE_FILE_MODE, NPM_PACK_EPOCH_MTIME,
};

#[cfg(test)]
mod tests;
