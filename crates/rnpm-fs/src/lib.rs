pub mod atomic;
pub mod error;
pub mod junction;
pub mod tarball;

pub use atomic::{extract_and_replace, replace_dir_with_retries};
pub use error::FsError;
pub use junction::{create_junction, is_junction, remove_junction};
pub use tarball::{
    extract_tar_gz, strip_package_prefix, validate_entry_path, ExtractionSummary, TarLimits,
};

#[cfg(test)]
mod tests;
