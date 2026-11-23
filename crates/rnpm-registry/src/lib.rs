//! Registry client and metadata fetching for rnpm.
//!
//! Provides an HTTP client for npm registries with connection reuse,
//! custom User-Agent, abbreviated install metadata support, scoped package
//! URL encoding, streaming tarball downloads, and redirect security policies
//! (preventing auth header leakage across redirects to untrusted hostnames).

pub mod asn1;
pub mod circuit_breaker;
pub mod client;
pub mod error;
pub mod metadata;
pub mod network_errors;
pub mod not_found;
pub mod provenance;
pub mod publish;

pub use circuit_breaker::{CircuitBreaker, CircuitBreakerState};
pub use client::{
    calculate_retry_backoff, default_user_agent, encode_package_name, format_http_date,
    http_request_count, parse_http_date_to_seconds_from_now, parse_http_date_to_unix_timestamp,
    parse_retry_after, parse_retry_after_str, reset_http_request_count, BytesFetchResult,
    MetadataFetchResult, RegistryClient, RegistryClientConfig, TarballFetchResult, TarballStream,
    DEFAULT_RETRY_FACTOR, HTTP_REQUEST_COUNT, NPM_INSTALL_V1_JSON,
};
pub use error::RegistryError;
pub use reqwest::StatusCode;
pub use metadata::{
    AbbreviatedPackageMetadata, AbbreviatedVersion, AttestationProvenance, DistAttestations,
    DistInfo, DistSignature, PackageBin,
};
pub use provenance::{
    assemble_sigstore_bundle, build_slsa_v1_statement, format_registry_signature_payload,
    generate_sigstore_provenance, normalize_repository_url, request_fulcio_signing_cert,
    sign_dsse_envelope, submit_rekor_dsse_entry, validate_dist_signatures, verify_provenance,
    AttestationItem, AttestationResponse, BuildProvenance, CiEnvironmentInfo, DsseEnvelope,
    DsseSignature, EphemeralSigner, InTotoStatement, InTotoSubject, ProvenancePolicy,
    ProvenanceVerifier, SigstoreBundle, SlsaBuilder, SlsaConfigSource, SlsaInvocation,
    SlsaPredicate, TransparencyLogMetadata, VerificationMaterial, VerifiedProvenance,
    NPM_REGISTRY_KEYID,
};
pub use publish::{
    create_publish_payload, PublishAttachment, PublishPayloadOptions, PublishTarballData,
};
