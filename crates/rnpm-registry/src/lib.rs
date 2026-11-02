//! Registry client and metadata fetching for rnpm.
//!
//! Provides an HTTP client for npm registries with connection reuse,
//! custom User-Agent, abbreviated install metadata support, scoped package
//! URL encoding, streaming tarball downloads, and redirect security policies
//! (preventing auth header leakage across redirects to untrusted hostnames).

pub mod client;
pub mod error;
pub mod metadata;

pub use client::{
    default_user_agent, encode_package_name, validate_package_name, RegistryClient,
    RegistryClientConfig, NPM_INSTALL_V1_JSON,
};
pub use error::RegistryError;
pub use metadata::{
    AbbreviatedPackageMetadata, AbbreviatedVersion, DistInfo, PackageBin,
};
