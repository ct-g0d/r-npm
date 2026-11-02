pub mod config;
pub mod error;
pub mod npmrc;

pub use config::Config;
pub use error::ConfigError;
pub use npmrc::{
    encode_package_name, interpolate_env, is_sensitive_credential_key, mask_credential,
    scrub_credentials, validate_package_name, Npmrc, DEFAULT_REGISTRY,
};

#[cfg(test)]
mod tests;
