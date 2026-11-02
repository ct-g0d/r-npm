pub mod config;
pub mod error;
pub mod npmrc;

pub use config::Config;
pub use error::ConfigError;
pub use npmrc::{
    encode_package_name, interpolate_env, validate_package_name, Npmrc, DEFAULT_REGISTRY,
};

#[cfg(test)]
mod tests;
