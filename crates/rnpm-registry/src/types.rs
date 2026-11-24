//! Type definitions and re-exports for registry metadata.

pub use crate::metadata::{
    deserialize_dist_tags, deserialize_engines, deserialize_license, deserialize_platform_list,
    deserialize_publish_times, deserialize_unique_versions, deserialize_unique_versions_install,
    deserialize_unique_versions_with_mode, deserialize_vec_or_string, is_heavy_unused_full_field,
    is_heavy_unused_install_field, parse_full_packument, parse_install_packument,
    parse_packument_with_mode, AbbreviatedPackageMetadata, AbbreviatedVersion,
    AttestationProvenance, DistAttestations, DistInfo, DistSignature, PackageBin, PackageMetadata,
    PackumentParseMode, VersionMetadata,
};
