//! Registry client and metadata fetching for rnpm.
//!
//! Provides an HTTP client for npm registries with connection reuse,
//! custom User-Agent, abbreviated install metadata support, scoped package
//! URL encoding, streaming tarball downloads, and redirect security policies
//! (preventing auth header leakage across redirects to untrusted hostnames).

pub mod circuit_breaker;
pub mod client;
pub mod error;
pub mod metadata;
pub mod provenance;
pub mod publish;

pub use circuit_breaker::{CircuitBreaker, CircuitBreakerState};
pub use client::{
    default_user_agent, encode_package_name, format_http_date, parse_http_date_to_seconds_from_now,
    parse_http_date_to_unix_timestamp, parse_retry_after, parse_retry_after_str, BytesFetchResult,
    MetadataFetchResult, RegistryClient, RegistryClientConfig, TarballFetchResult, TarballStream,
    NPM_INSTALL_V1_JSON,
};
pub use error::RegistryError;
pub use metadata::{
    AbbreviatedPackageMetadata, AbbreviatedVersion, AttestationProvenance, DistAttestations,
    DistInfo, DistSignature, PackageBin,
};
pub use publish::{
    create_publish_payload, PublishAttachment, PublishPayloadOptions, PublishTarballData,
};
pub use provenance::{
    format_registry_signature_payload, normalize_repository_url, validate_dist_signatures,
    verify_provenance, AttestationItem, AttestationResponse, BuildProvenance, DsseEnvelope,
    DsseSignature, InTotoStatement, InTotoSubject, ProvenancePolicy, ProvenanceVerifier,
    SigstoreBundle, SlsaPredicate, TransparencyLogMetadata, VerificationMaterial,
    VerifiedProvenance, NPM_REGISTRY_KEYID,
};
