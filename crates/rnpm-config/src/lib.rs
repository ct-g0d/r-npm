pub mod config;
pub mod error;
pub mod npmrc;

pub use config::Config;
pub use error::ConfigError;
pub use npmrc::{interpolate_env, Npmrc, DEFAULT_REGISTRY};

#[cfg(test)]
mod tests;
