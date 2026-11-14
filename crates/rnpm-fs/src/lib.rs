#![allow(
    clippy::permissions_set_readonly_false,
    clippy::manual_strip,
    clippy::match_like_matches_macro
)]

pub mod atomic;
pub mod block_clone;
pub mod error;
pub mod junction;
pub mod node_writer;
pub mod parallel;
pub mod path;
pub mod tarball;
pub mod writer;

pub use node_writer::{
    AsyncFileWriter, AsyncFileWriterSender, NodeWriter, NodeWriterMsg, NodeWriterSender,
    RustWriterPool, WriteTask,
};

pub use atomic::{extract_and_replace, recover_atomic_writes, replace_dir_with_retries};
pub use block_clone::{
    block_clones_performed, clone_file_from_pack, clone_or_write_pack_file, duplicate_extents,
    get_volume_cluster_size, get_volume_details, get_volume_filesystem_name, get_volume_guid,
    get_volume_info, get_volume_serial_number, is_block_cloning_supported, is_refs_volume,
    is_same_volume, materialize_pack_entries, record_block_clone, reset_block_clones, PackEntryRef,
    RawFileHandle, CLUSTER_SIZE, DUPLICATE_EXTENTS_DATA, FILE_SUPPORTS_BLOCK_REFCOUNTING,
    FSCTL_DUPLICATE_EXTENTS_TO_FILE,
};
pub use error::FsError;
pub use junction::{
    create_junction, create_link_or_copy, is_junction, junction_points_to, junctions_created,
    read_junction_target, record_junction_created, remove_dir_all_safe, remove_junction,
    reset_junctions_created,
};
pub use parallel::{extract_batch_parallel, BatchExtractionItem};
pub use path::{strip_verbatim_prefix, to_verbatim_path};
pub use tarball::{
    bytes_written, collect_pack_files, compute_tarball_filename, extract_tar_gz, files_created,
    pack_directory, record_file_created, record_files_created_batch, reset_fs_counters,
    strip_package_prefix, read_tarball_text, summarize_tarball, validate_entry_path, ExtractionSummary, PackSummary, PackedFileEntry,
    TarLimits, NPM_DEFAULT_FILE_MODE, NPM_EXECUTABLE_FILE_MODE, NPM_PACK_EPOCH_MTIME,
};
pub use writer::{
    copy_file_fast, decode_tar_entries, detect_seek_penalty, determine_writer_config,
    extract_packages_direct_parallel, extract_tarball_direct, materialize_files_parallel,
    materialize_files_parallel_refs, precreate_directories, write_file_fast, BatchDirectItem,
    DecodedTarball, DriveType, MaterializeFile, MaterializeFileRef, ParallelWriterConfig,
};

#[cfg(test)]
mod tests;
