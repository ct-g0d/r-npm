pub mod config;
pub mod error;
pub mod npmrc;

pub use config::{
    find_global_npmrc, find_global_npmrc_with_env, find_user_npmrc, find_user_npmrc_with_env,
    find_workspace_root, Config, ConfigOptions,
};
pub use error::ConfigError;
pub use npmrc::{
    encode_package_name, interpolate_env, is_sensitive_credential_key, mask_credential,
    scrub_credentials, validate_package_name, Npmrc, DEFAULT_REGISTRY,
};

#[cfg(test)]
mod tests;
