use std::collections::HashMap;
use data_encoding::{BASE64, BASE64_NOPAD, HEXLOWER};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::error::RegistryError;
use crate::metadata::{AbbreviatedVersion, DistSignature};

/// The well-known official npm registry public key identifier for package signatures.
pub const NPM_REGISTRY_KEYID: &str = "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA";

/// Decodes base64 strings with support for whitespace tolerance, unpadded, and URL-safe variants.
pub fn decode_base64(input: &str) -> Result<Vec<u8>, RegistryError> {
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(bytes) = BASE64.decode(clean.as_bytes()) {
        return Ok(bytes);
    }
    if let Ok(bytes) = BASE64_NOPAD.decode(clean.as_bytes()) {
        return Ok(bytes);
    }
    let un_url = clean.replace('-', "+").replace('_', "/");
    let padded = match un_url.len() % 4 {
        2 => format!("{un_url}=="),
        3 => format!("{un_url}="),
        _ => un_url,
    };
    BASE64
        .decode(padded.as_bytes())
        .map_err(|e| RegistryError::InvalidSigstoreBundle(format!("Base64 decoding failed: {e}")))
}

/// Normalizes source repository URLs (e.g. from GitHub, git+, ssh) into canonical form (`owner/repo`).
pub fn normalize_repository_url(url: &str) -> String {
    let mut s = url.trim();

    if let Some(rest) = s.strip_prefix("git+") {
        s = rest;
    }
    if let Some(rest) = s.strip_prefix("git@") {
        if let Some((_host, path)) = rest.split_once(':') {
            s = path;
        }
    }

    for proto in ["https://", "http://", "git://", "ssh://"] {
        if let Some(rest) = s.strip_prefix(proto) {
            s = rest;
            break;
        }
    }

    for domain in ["github.com/", "gitlab.com/"] {
        if let Some(rest) = s.strip_prefix(domain) {
            s = rest;
            break;
        }
    }

    if let Some((repo, _ref)) = s.split_once('@') {
        s = repo;
    }

    if let Some(rest) = s.strip_suffix(".git") {
        s = rest;
    }

    s.trim_matches('/').to_ascii_lowercase()
}

/// Formats the message payload signed by npm registry signatures: `{name}@{version}:{integrity}`.
pub fn format_registry_signature_payload(name: &str, version: &str, integrity: &str) -> String {
    format!("{name}@{version}:{integrity}")
}

/// Validates registry signatures in `dist.signatures`.
/// Checks signature structure, valid base64 decoding, and matching against trusted key IDs if specified.
pub fn validate_dist_signatures<'a>(
    signatures: &'a [DistSignature],
    trusted_keyids: Option<&[&str]>,
) -> Result<Vec<&'a DistSignature>, RegistryError> {
    if signatures.is_empty() {
        return Err(RegistryError::InvalidSignature(
            "No signatures present in dist.signatures".into(),
        ));
    }

    let mut valid_signatures = Vec::new();

    for sig in signatures {
        if sig.keyid.trim().is_empty() {
            return Err(RegistryError::InvalidSignature(
                "Signature keyid is empty".into(),
            ));
        }
        if sig.sig.trim().is_empty() {
            return Err(RegistryError::InvalidSignature(format!(
                "Signature string is empty for keyid '{}'",
                sig.keyid
            )));
        }

        if let Err(e) = decode_base64(&sig.sig) {
            return Err(RegistryError::InvalidSignature(format!(
                "Signature for keyid '{}' is not valid base64: {e}",
                sig.keyid
            )));
        }

        valid_signatures.push(sig);
    }

    if let Some(trusted) = trusted_keyids {
        let has_trusted = valid_signatures
            .iter()
            .any(|s| trusted.contains(&s.keyid.as_str()));
        if !has_trusted {
            return Err(RegistryError::InvalidSignature(format!(
                "None of the signatures matched trusted keyids: {trusted:?}"
            )));
        }
    }

    Ok(valid_signatures)
}

/// Dead Simple Signing Envelope (DSSE) envelope structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    #[serde(default)]
    pub signatures: Vec<DsseSignature>,
}

impl DsseEnvelope {
    pub fn decode_payload(&self) -> Result<Vec<u8>, RegistryError> {
        decode_base64(&self.payload)
    }

    pub fn parse_statement(&self) -> Result<InTotoStatement, RegistryError> {
        if self.payload_type != "application/vnd.in-toto+json" {
            return Err(RegistryError::InvalidSigstoreBundle(format!(
                "Unsupported DSSE payloadType: expected 'application/vnd.in-toto+json', got '{}'",
                self.payload_type
            )));
        }
        let bytes = self.decode_payload()?;
        serde_json::from_slice(&bytes).map_err(|e| {
            RegistryError::InvalidSigstoreBundle(format!(
                "Failed to parse in-toto statement JSON: {e}"
            ))
        })
    }
}

/// DSSE signature entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DsseSignature {
    #[serde(default)]
    pub keyid: Option<String>,
    pub sig: String,
}

/// in-toto Statement envelope (v0.1 / v1.0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    #[serde(default)]
    pub subject: Vec<InTotoSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: SlsaPredicate,
}

/// in-toto Statement subject item with name and digest map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InTotoSubject {
    pub name: String,
    #[serde(default)]
    pub digest: HashMap<String, String>,
}

/// SLSA Provenance predicate supporting both v0.2 and v1.0 specifications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SlsaPredicate {
    // SLSA v0.2 / generic fields
    #[serde(default)]
    pub builder: Option<SlsaBuilder>,
    #[serde(rename = "buildType", default)]
    pub build_type: Option<String>,
    #[serde(default)]
    pub invocation: Option<SlsaInvocation>,
    #[serde(default)]
    pub recipe: Option<serde_json::Value>,
    #[serde(default)]
    pub materials: Vec<SlsaMaterial>,

    // SLSA v1.0 fields
    #[serde(rename = "buildDefinition", default)]
    pub build_definition: Option<SlsaBuildDefinition>,
    #[serde(rename = "runDetails", default)]
    pub run_details: Option<SlsaRunDetails>,
}

impl SlsaPredicate {
    pub fn builder_id(&self) -> Option<&str> {
        self.run_details
            .as_ref()
            .and_then(|r| r.builder.as_ref())
            .map(|b| b.id.as_str())
            .or_else(|| self.builder.as_ref().map(|b| b.id.as_str()))
    }

    pub fn build_type(&self) -> Option<&str> {
        self.build_type
            .as_deref()
            .or_else(|| self.build_definition.as_ref().and_then(|d| d.build_type.as_deref()))
    }

    pub fn source_repository(&self) -> Option<String> {
        // v0.2: invocation.configSource.uri
        if let Some(uri) = self
            .invocation
            .as_ref()
            .and_then(|inv| inv.config_source.as_ref())
            .and_then(|cs| cs.uri.as_ref())
        {
            return Some(normalize_repository_url(uri));
        }

        // v1.0: buildDefinition.externalParameters
        if let Some(ext) = self
            .build_definition
            .as_ref()
            .and_then(|bd| bd.external_parameters.as_ref())
        {
            if let Some(repo) = ext
                .get("workflow")
                .and_then(|w| w.get("repository"))
                .and_then(|r| r.as_str())
            {
                return Some(normalize_repository_url(repo));
            }
            if let Some(repo) = ext
                .get("source")
                .and_then(|s| s.get("repository"))
                .and_then(|r| r.as_str())
            {
                return Some(normalize_repository_url(repo));
            }
            if let Some(repo) = ext.get("repository").and_then(|r| r.as_str()) {
                return Some(normalize_repository_url(repo));
            }
        }

        // Materials or resolvedDependencies
        if let Some(mat) = self.materials.iter().find_map(|m| m.uri.as_ref()) {
            return Some(normalize_repository_url(mat));
        }
        if let Some(dep) = self
            .build_definition
            .as_ref()
            .and_then(|bd| bd.resolved_dependencies.iter().find_map(|d| d.uri.as_ref()))
        {
            return Some(normalize_repository_url(dep));
        }

        // Invocation environment
        if let Some(env) = self
            .invocation
            .as_ref()
            .and_then(|inv| inv.environment.as_ref())
        {
            if let Some(repo) = env
                .get("github_repository")
                .or_else(|| env.get("GITHUB_REPOSITORY"))
                .and_then(|v| v.as_str())
            {
                return Some(normalize_repository_url(repo));
            }
        }

        None
    }

    pub fn commit_sha(&self) -> Option<String> {
        // v0.2: invocation.configSource.digest
        if let Some(digest) = self
            .invocation
            .as_ref()
            .and_then(|inv| inv.config_source.as_ref())
            .map(|cs| &cs.digest)
        {
            if let Some(sha) = digest
                .get("sha1")
                .or_else(|| digest.get("gitCommit"))
                .or_else(|| digest.get("sha256"))
            {
                return Some(sha.clone());
            }
        }

        // v1.0: buildDefinition.resolvedDependencies
        if let Some(bd) = self.build_definition.as_ref() {
            for dep in &bd.resolved_dependencies {
                if let Some(sha) = dep.digest.get("gitCommit").or_else(|| dep.digest.get("sha1")) {
                    return Some(sha.clone());
                }
            }
            if let Some(ext) = bd.external_parameters.as_ref() {
                if let Some(sha) = ext
                    .get("workflow")
                    .and_then(|w| w.get("ref").or_else(|| w.get("commit")))
                    .and_then(|r| r.as_str())
                {
                    if sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Some(sha.to_string());
                    }
                }
            }
        }

        // Materials
        for mat in &self.materials {
            if let Some(sha) = mat.digest.get("sha1").or_else(|| mat.digest.get("gitCommit")) {
                return Some(sha.clone());
            }
        }

        // Invocation environment
        if let Some(env) = self
            .invocation
            .as_ref()
            .and_then(|inv| inv.environment.as_ref())
        {
            if let Some(sha) = env
                .get("github_sha")
                .or_else(|| env.get("GITHUB_SHA"))
                .or_else(|| env.get("github_sha1"))
                .and_then(|v| v.as_str())
            {
                return Some(sha.to_string());
            }
        }

        None
    }

    pub fn workflow_path(&self) -> Option<String> {
        // v0.2: invocation.configSource.entryPoint
        if let Some(ep) = self
            .invocation
            .as_ref()
            .and_then(|inv| inv.config_source.as_ref())
            .and_then(|cs| cs.entry_point.as_ref())
        {
            return Some(ep.clone());
        }

        // v1.0: buildDefinition.externalParameters.workflow.path
        if let Some(ext) = self
            .build_definition
            .as_ref()
            .and_then(|bd| bd.external_parameters.as_ref())
        {
            if let Some(path) = ext
                .get("workflow")
                .and_then(|w| w.get("path"))
                .and_then(|p| p.as_str())
            {
                return Some(path.to_string());
            }
        }

        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SlsaBuilder {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SlsaInvocation {
    #[serde(rename = "configSource", default)]
    pub config_source: Option<SlsaConfigSource>,
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,
    #[serde(default)]
    pub environment: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SlsaConfigSource {
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub digest: HashMap<String, String>,
    #[serde(rename = "entryPoint", default)]
    pub entry_point: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SlsaMaterial {
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub digest: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SlsaBuildDefinition {
    #[serde(rename = "buildType", default)]
    pub build_type: Option<String>,
    #[serde(rename = "externalParameters", default)]
    pub external_parameters: Option<serde_json::Value>,
    #[serde(rename = "internalParameters", default)]
    pub internal_parameters: Option<serde_json::Value>,
    #[serde(rename = "resolvedDependencies", default)]
    pub resolved_dependencies: Vec<SlsaMaterial>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SlsaRunDetails {
    #[serde(default)]
    pub builder: Option<SlsaBuilder>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Sigstore bundle verification material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VerificationMaterial {
    #[serde(rename = "x509CertificateChain", default)]
    pub x509_certificate_chain: Option<X509CertificateChain>,
    #[serde(default)]
    pub certificate: Option<X509Certificate>,
    #[serde(rename = "tlogEntries", default)]
    pub tlog_entries: Vec<TlogEntry>,
    #[serde(rename = "timestampVerificationData", default)]
    pub timestamp_verification_data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct X509CertificateChain {
    #[serde(default)]
    pub certificates: Vec<X509Certificate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct X509Certificate {
    #[serde(rename = "rawBytes", default)]
    pub raw_bytes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TlogEntry {
    #[serde(rename = "logIndex")]
    pub log_index: u64,
    #[serde(rename = "logId")]
    pub log_id: LogId,
    #[serde(rename = "integratedTime")]
    pub integrated_time: i64,
    #[serde(rename = "inclusionPromise", default)]
    pub inclusion_promise: Option<InclusionPromise>,
    #[serde(rename = "inclusionProof", default)]
    pub inclusion_proof: Option<serde_json::Value>,
    #[serde(rename = "canonicalizedBody", default)]
    pub canonicalized_body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LogId {
    #[serde(rename = "keyId", default)]
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InclusionPromise {
    #[serde(rename = "signedEntryTimestamp", default)]
    pub signed_entry_timestamp: String,
}

/// Sigstore bundle structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SigstoreBundle {
    #[serde(rename = "mediaType", default)]
    pub media_type: Option<String>,
    #[serde(rename = "verificationMaterial", default)]
    pub verification_material: Option<VerificationMaterial>,
    #[serde(rename = "dsseEnvelope", default)]
    pub dsse_envelope: Option<DsseEnvelope>,
}

impl SigstoreBundle {
    /// Parses a SigstoreBundle from a JSON string, accepting either a direct SigstoreBundle
    /// or an npm AttestationResponse wrapper (`{"attestations": [{"bundle": ...}]}`).
    pub fn from_json(json_str: &str) -> Result<Self, RegistryError> {
        if let Ok(bundle) = serde_json::from_str::<SigstoreBundle>(json_str) {
            if bundle.dsse_envelope.is_some() {
                return Ok(bundle);
            }
        }

        if let Ok(response) = serde_json::from_str::<AttestationResponse>(json_str) {
            for item in response.attestations {
                if let Some(bundle) = item.bundle {
                    if bundle.dsse_envelope.is_some() {
                        return Ok(bundle);
                    }
                }
            }
        }

        Err(RegistryError::InvalidSigstoreBundle(
            "No valid Sigstore bundle with dsseEnvelope found in JSON payload".into(),
        ))
    }
}

/// npm attestation endpoint response document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AttestationResponse {
    #[serde(default)]
    pub attestations: Vec<AttestationItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AttestationItem {
    #[serde(rename = "predicateType", default)]
    pub predicate_type: Option<String>,
    #[serde(default)]
    pub bundle: Option<SigstoreBundle>,
}

/// Extracted build provenance details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildProvenance {
    pub builder_id: String,
    pub source_repository: Option<String>,
    pub commit_sha: Option<String>,
    pub workflow_path: Option<String>,
    pub build_type: Option<String>,
}

impl BuildProvenance {
    pub fn is_github_actions(&self) -> bool {
        self.builder_id.contains("github.com/actions")
            || self.builder_id.contains("GitHub")
            || self.source_repository.as_ref().is_some_and(|r| !r.is_empty())
    }
}

/// Extracted Rekor transparency log entry metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyLogMetadata {
    pub log_index: u64,
    pub log_id: String,
    pub integrated_time: i64,
}

/// Verified provenance result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedProvenance {
    pub package_name: String,
    pub statement_type: String,
    pub predicate_type: String,
    pub build: BuildProvenance,
    pub tlog_entry: TransparencyLogMetadata,
    pub certificate_count: usize,
}

/// Configurable policy for provenance verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenancePolicy {
    /// Allow packages with or without valid provenance.
    AllowAny,
    /// Require valid provenance; fails if provenance is absent or invalid.
    RequireProvenance,
    /// Require valid provenance from a specific source repository.
    RequireRepository { expected_repository: String },
}

/// Engine for verifying Sigstore provenance bundles and enforcing provenance policies.
#[derive(Debug, Clone)]
pub struct ProvenanceVerifier {
    policy: ProvenancePolicy,
}

impl ProvenanceVerifier {
    pub fn new(policy: ProvenancePolicy) -> Self {
        Self { policy }
    }

    pub fn policy(&self) -> &ProvenancePolicy {
        &self.policy
    }

    /// Verifies a package version against an optional Sigstore bundle based on the configured policy.
    pub fn verify_version(
        &self,
        version: &AbbreviatedVersion,
        bundle: Option<&SigstoreBundle>,
        tarball_bytes: Option<&[u8]>,
    ) -> Result<Option<VerifiedProvenance>, RegistryError> {
        match (&self.policy, bundle) {
            (ProvenancePolicy::AllowAny, None) => Ok(None),
            (ProvenancePolicy::RequireProvenance, None) => {
                Err(RegistryError::ProvenanceVerificationFailed(format!(
                    "Provenance required by policy for package '{}@{}', but no attestation was found",
                    version.name, version.version
                )))
            }
            (ProvenancePolicy::RequireRepository { expected_repository }, None) => {
                Err(RegistryError::UntrustedSourceRepository {
                    expected: expected_repository.clone(),
                    actual: format!(
                        "no provenance provided for package '{}@{}'",
                        version.name, version.version
                    ),
                })
            }
            (_, Some(bundle)) => {
                let integrity = version.dist.integrity.as_deref();
                let verified = self.verify(&version.name, bundle, integrity, tarball_bytes)?;
                Ok(Some(verified))
            }
        }
    }

    /// Verifies that a Sigstore bundle is authentic, matches package name and tarball digests,
    /// and conforms to the configured `ProvenancePolicy`.
    pub fn verify(
        &self,
        package_name: &str,
        bundle: &SigstoreBundle,
        tarball_integrity: Option<&str>,
        tarball_bytes: Option<&[u8]>,
    ) -> Result<VerifiedProvenance, RegistryError> {
        // 1. Validate DSSE envelope presence
        let envelope = bundle
            .dsse_envelope
            .as_ref()
            .ok_or_else(|| RegistryError::InvalidSigstoreBundle("Missing dsseEnvelope in bundle".into()))?;

        if envelope.signatures.is_empty() {
            return Err(RegistryError::InvalidSigstoreBundle(
                "DSSE envelope signatures array is empty".into(),
            ));
        }

        // 2. Validate verificationMaterial
        let vm = bundle
            .verification_material
            .as_ref()
            .ok_or_else(|| RegistryError::InvalidSigstoreBundle("Missing verificationMaterial in bundle".into()))?;

        // 3. Validate Rekor transparency log entries
        if vm.tlog_entries.is_empty() {
            return Err(RegistryError::InvalidSigstoreBundle(
                "Missing Rekor tlogEntries in verification material".into(),
            ));
        }

        let primary_tlog = &vm.tlog_entries[0];
        if primary_tlog.log_id.key_id.trim().is_empty() {
            return Err(RegistryError::InvalidSigstoreBundle(
                "Rekor entry logId.keyId is empty".into(),
            ));
        }
        if primary_tlog.integrated_time <= 0 {
            return Err(RegistryError::InvalidSigstoreBundle(format!(
                "Invalid Rekor entry integratedTime: {}",
                primary_tlog.integrated_time
            )));
        }

        let tlog_metadata = TransparencyLogMetadata {
            log_index: primary_tlog.log_index,
            log_id: primary_tlog.log_id.key_id.clone(),
            integrated_time: primary_tlog.integrated_time,
        };

        // 4. Validate X.509 certificate chain
        let cert_count = if let Some(chain) = &vm.x509_certificate_chain {
            if chain.certificates.is_empty() {
                return Err(RegistryError::InvalidSigstoreBundle(
                    "x509CertificateChain has no certificates".into(),
                ));
            }
            for (idx, cert) in chain.certificates.iter().enumerate() {
                if cert.raw_bytes.trim().is_empty() {
                    return Err(RegistryError::InvalidSigstoreBundle(format!(
                        "Certificate at index {idx} has empty rawBytes"
                    )));
                }
                decode_base64(&cert.raw_bytes).map_err(|e| {
                    RegistryError::InvalidSigstoreBundle(format!(
                        "Certificate at index {idx} has invalid base64 rawBytes: {e}"
                    ))
                })?;
            }
            chain.certificates.len()
        } else if let Some(cert) = &vm.certificate {
            if cert.raw_bytes.trim().is_empty() {
                return Err(RegistryError::InvalidSigstoreBundle(
                    "Certificate has empty rawBytes".into(),
                ));
            }
            decode_base64(&cert.raw_bytes).map_err(|e| {
                RegistryError::InvalidSigstoreBundle(format!(
                    "Certificate has invalid base64 rawBytes: {e}"
                ))
            })?;
            1
        } else {
            return Err(RegistryError::InvalidSigstoreBundle(
                "Missing certificate chain in verification material".into(),
            ));
        };

        // 5. Parse and validate in-toto statement
        let statement = envelope.parse_statement()?;
        if statement.subject.is_empty() {
            return Err(RegistryError::ProvenanceVerificationFailed(
                "in-toto Statement has no subjects".into(),
            ));
        }

        // 6. Match subject with expected package name
        let matched_subject = Self::find_matching_subject(&statement.subject, package_name)?;

        // 7. Verify tarball integrity digest against subject.digest
        Self::verify_subject_digest(matched_subject, tarball_integrity, tarball_bytes)?;

        // 8. Extract build provenance details
        let build = BuildProvenance {
            builder_id: statement.predicate.builder_id().unwrap_or_default().to_string(),
            source_repository: statement.predicate.source_repository(),
            commit_sha: statement.predicate.commit_sha(),
            workflow_path: statement.predicate.workflow_path(),
            build_type: statement.predicate.build_type().map(|s| s.to_string()),
        };

        // 9. Enforce repository policy if required
        if let ProvenancePolicy::RequireRepository { expected_repository } = &self.policy {
            let expected_norm = normalize_repository_url(expected_repository);
            match &build.source_repository {
                Some(actual_repo) => {
                    let actual_norm = normalize_repository_url(actual_repo);
                    if actual_norm != expected_norm {
                        return Err(RegistryError::UntrustedSourceRepository {
                            expected: expected_repository.clone(),
                            actual: actual_repo.clone(),
                        });
                    }
                }
                None => {
                    return Err(RegistryError::UntrustedSourceRepository {
                        expected: expected_repository.clone(),
                        actual: "<none>".into(),
                    });
                }
            }
        }

        Ok(VerifiedProvenance {
            package_name: package_name.to_string(),
            statement_type: statement.statement_type,
            predicate_type: statement.predicate_type,
            build,
            tlog_entry: tlog_metadata,
            certificate_count: cert_count,
        })
    }

    fn find_matching_subject<'a>(
        subjects: &'a [InTotoSubject],
        package_name: &str,
    ) -> Result<&'a InTotoSubject, RegistryError> {
        let unscoped_name = package_name
            .split('/')
            .next_back()
            .unwrap_or(package_name)
            .trim_start_matches('@');

        for subj in subjects {
            let s = subj.name.trim();
            if s == package_name || s == unscoped_name {
                return Ok(subj);
            }
            if let Some(prefix) = s.strip_suffix(".tgz") {
                if prefix == package_name || prefix == unscoped_name {
                    return Ok(subj);
                }
                if prefix.starts_with(&format!("{package_name}-"))
                    || prefix.starts_with(&format!("{unscoped_name}-"))
                {
                    return Ok(subj);
                }
            }
        }

        // If there's a single subject that doesn't match, or multiple that don't match:
        let found_names = subjects
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        Err(RegistryError::ProvenanceVerificationFailed(format!(
            "Attestation subject name mismatch: expected '{package_name}', found [{found_names}]"
        )))
    }

    fn verify_subject_digest(
        subject: &InTotoSubject,
        tarball_integrity: Option<&str>,
        tarball_bytes: Option<&[u8]>,
    ) -> Result<(), RegistryError> {
        let subject_sha512 = subject.digest.get("sha512").map(|s| s.trim());
        let subject_sha256 = subject.digest.get("sha256").map(|s| s.trim());

        if subject_sha512.is_none() && subject_sha256.is_none() {
            return Err(RegistryError::ProvenanceVerificationFailed(
                "Subject digest map does not contain sha512 or sha256 algorithm".into(),
            ));
        }

        if let Some(bytes) = tarball_bytes {
            if let Some(expected_512) = subject_sha512 {
                let actual_hex = HEXLOWER.encode(&Sha512::digest(bytes));
                if !Self::digest_matches(expected_512, &actual_hex) {
                    return Err(RegistryError::AttestationDigestMismatch {
                        algorithm: "sha512".into(),
                        expected: expected_512.to_string(),
                        actual: actual_hex,
                    });
                }
                return Ok(());
            }

            if let Some(expected_256) = subject_sha256 {
                let actual_hex = HEXLOWER.encode(&Sha256::digest(bytes));
                if !Self::digest_matches(expected_256, &actual_hex) {
                    return Err(RegistryError::AttestationDigestMismatch {
                        algorithm: "sha256".into(),
                        expected: expected_256.to_string(),
                        actual: actual_hex,
                    });
                }
                return Ok(());
            }
        }

        if let Some(integrity_str) = tarball_integrity {
            let trimmed = integrity_str.trim();

            // Parse SRI string like "sha512-<base64>" or "sha256-<base64>"
            for token in trimmed.split_whitespace() {
                if let Some((algo, b64)) = token.split_once('-') {
                    let algo_lower = algo.to_ascii_lowercase();
                    let decoded = decode_base64(b64).map_err(|e| {
                        RegistryError::ProvenanceVerificationFailed(format!(
                            "Invalid base64 in tarball integrity '{token}': {e}"
                        ))
                    })?;
                    let actual_hex = HEXLOWER.encode(&decoded);

                    if algo_lower == "sha512" {
                        if let Some(expected_512) = subject_sha512 {
                            if !Self::digest_matches(expected_512, &actual_hex) {
                                return Err(RegistryError::AttestationDigestMismatch {
                                    algorithm: "sha512".into(),
                                    expected: expected_512.to_string(),
                                    actual: actual_hex,
                                });
                            }
                            return Ok(());
                        }
                    } else if algo_lower == "sha256" {
                        if let Some(expected_256) = subject_sha256 {
                            if !Self::digest_matches(expected_256, &actual_hex) {
                                return Err(RegistryError::AttestationDigestMismatch {
                                    algorithm: "sha256".into(),
                                    expected: expected_256.to_string(),
                                    actual: actual_hex,
                                });
                            }
                            return Ok(());
                        }
                    }
                }
            }

            // Plain hex digest without algo prefix
            if trimmed.len() == 128 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Some(expected_512) = subject_sha512 {
                    if !Self::digest_matches(expected_512, trimmed) {
                        return Err(RegistryError::AttestationDigestMismatch {
                            algorithm: "sha512".into(),
                            expected: expected_512.to_string(),
                            actual: trimmed.to_string(),
                        });
                    }
                    return Ok(());
                }
            } else if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Some(expected_256) = subject_sha256 {
                    if !Self::digest_matches(expected_256, trimmed) {
                        return Err(RegistryError::AttestationDigestMismatch {
                            algorithm: "sha256".into(),
                            expected: expected_256.to_string(),
                            actual: trimmed.to_string(),
                        });
                    }
                    return Ok(());
                }
            }

            return Err(RegistryError::ProvenanceVerificationFailed(format!(
                "No matching algorithm found between tarball integrity '{integrity_str}' and subject digests"
            )));
        }

        Err(RegistryError::ProvenanceVerificationFailed(
            "Neither tarball_bytes nor tarball_integrity was provided for digest verification".into(),
        ))
    }

    fn digest_matches(expected: &str, actual_hex: &str) -> bool {
        let exp = expected.trim();
        if exp.eq_ignore_ascii_case(actual_hex) {
            return true;
        }
        if let Ok(bytes) = decode_base64(exp) {
            let exp_hex = HEXLOWER.encode(&bytes);
            if exp_hex.eq_ignore_ascii_case(actual_hex) {
                return true;
            }
        }
        false
    }
}

/// Convenience function for verifying provenance with a policy.
pub fn verify_provenance(
    package_name: &str,
    bundle: &SigstoreBundle,
    tarball_integrity: Option<&str>,
    tarball_bytes: Option<&[u8]>,
    policy: &ProvenancePolicy,
) -> Result<VerifiedProvenance, RegistryError> {
    ProvenanceVerifier::new(policy.clone()).verify(package_name, bundle, tarball_integrity, tarball_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_statement_v02(pkg: &str, sha512_hex: &str, repo: &str, commit: &str) -> InTotoStatement {
        let mut digest = HashMap::new();
        digest.insert("sha512".to_string(), sha512_hex.to_string());

        let mut cs_digest = HashMap::new();
        cs_digest.insert("sha1".to_string(), commit.to_string());

        InTotoStatement {
            statement_type: "https://in-toto.io/Statement/v0.1".into(),
            subject: vec![InTotoSubject {
                name: pkg.into(),
                digest,
            }],
            predicate_type: "https://slsa.dev/provenance/v0.2".into(),
            predicate: SlsaPredicate {
                builder: Some(SlsaBuilder {
                    id: "https://github.com/actions/runner/v2".into(),
                }),
                build_type: Some("https://actions.github.com/Workflow@v1".into()),
                invocation: Some(SlsaInvocation {
                    config_source: Some(SlsaConfigSource {
                        uri: Some(format!("git+{repo}@refs/heads/main")),
                        digest: cs_digest,
                        entry_point: Some(".github/workflows/release.yml".into()),
                    }),
                    parameters: None,
                    environment: None,
                }),
                recipe: None,
                materials: Vec::new(),
                build_definition: None,
                run_details: None,
            },
        }
    }

    fn sample_bundle(statement: &InTotoStatement) -> SigstoreBundle {
        let statement_json = serde_json::to_vec(statement).unwrap();
        let payload_b64 = BASE64.encode(&statement_json);

        SigstoreBundle {
            media_type: Some("application/vnd.dev.sigstore.bundle+json;version=0.1".into()),
            verification_material: Some(VerificationMaterial {
                x509_certificate_chain: Some(X509CertificateChain {
                    certificates: vec![X509Certificate {
                        raw_bytes: BASE64.encode(b"dummy-fulcio-cert"),
                    }],
                }),
                certificate: None,
                tlog_entries: vec![TlogEntry {
                    log_index: 123456,
                    log_id: LogId {
                        key_id: "rekor-tree-key-id".into(),
                    },
                    integrated_time: 1680000000,
                    inclusion_promise: Some(InclusionPromise {
                        signed_entry_timestamp: BASE64.encode(b"dummy-timestamp"),
                    }),
                    inclusion_proof: None,
                    canonicalized_body: None,
                }],
                timestamp_verification_data: None,
            }),
            dsse_envelope: Some(DsseEnvelope {
                payload_type: "application/vnd.in-toto+json".into(),
                payload: payload_b64,
                signatures: vec![DsseSignature {
                    keyid: Some("sig-key-1".into()),
                    sig: BASE64.encode(b"dummy-signature"),
                }],
            }),
        }
    }

    #[test]
    fn test_valid_provenance_passes_verification() {
        let tarball_bytes = b"fake package tarball content";
        let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));

        let statement = sample_statement_v02(
            "my-package",
            &sha512_hex,
            "https://github.com/my-org/my-package",
            "11223344556677889900aabbccddeeff11223344",
        );
        let bundle = sample_bundle(&statement);

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
        let res = verifier.verify("my-package", &bundle, None, Some(tarball_bytes));
        assert!(res.is_ok(), "Verification should succeed: {:?}", res.err());

        let verified = res.unwrap();
        assert_eq!(verified.package_name, "my-package");
        assert_eq!(verified.build.source_repository.as_deref(), Some("my-org/my-package"));
        assert_eq!(
            verified.build.commit_sha.as_deref(),
            Some("11223344556677889900aabbccddeeff11223344")
        );
        assert_eq!(
            verified.build.workflow_path.as_deref(),
            Some(".github/workflows/release.yml")
        );
        assert_eq!(verified.tlog_entry.log_index, 123456);
        assert_eq!(verified.certificate_count, 1);
    }

    #[test]
    fn test_tarball_hash_mismatch_fails() {
        let good_tarball = b"original tarball";
        let tampered_tarball = b"tampered tarball";
        let good_sha512 = HEXLOWER.encode(&Sha512::digest(good_tarball));

        let statement = sample_statement_v02(
            "my-package",
            &good_sha512,
            "https://github.com/my-org/my-package",
            "11223344556677889900aabbccddeeff11223344",
        );
        let bundle = sample_bundle(&statement);

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::RequireProvenance);
        let err = verifier
            .verify("my-package", &bundle, None, Some(tampered_tarball))
            .unwrap_err();

        match err {
            RegistryError::AttestationDigestMismatch { algorithm, expected, actual } => {
                assert_eq!(algorithm, "sha512");
                assert_eq!(expected, good_sha512);
                assert_eq!(actual, HEXLOWER.encode(&Sha512::digest(tampered_tarball)));
            }
            other => panic!("Expected AttestationDigestMismatch, got: {other:?}"),
        }
    }

    #[test]
    fn test_forged_subject_package_name_fails() {
        let tarball_bytes = b"package content";
        let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));

        // The attestation was signed for "other-package", but we are verifying "target-package"
        let statement = sample_statement_v02(
            "other-package",
            &sha512_hex,
            "https://github.com/my-org/my-package",
            "11223344556677889900aabbccddeeff11223344",
        );
        let bundle = sample_bundle(&statement);

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
        let err = verifier
            .verify("target-package", &bundle, None, Some(tarball_bytes))
            .unwrap_err();

        match err {
            RegistryError::ProvenanceVerificationFailed(msg) => {
                assert!(msg.contains("Attestation subject name mismatch"), "{msg}");
                assert!(msg.contains("target-package"), "{msg}");
            }
            other => panic!("Expected ProvenanceVerificationFailed, got: {other:?}"),
        }
    }

    #[test]
    fn test_untrusted_source_repository_fails() {
        let tarball_bytes = b"package content";
        let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));

        let statement = sample_statement_v02(
            "my-package",
            &sha512_hex,
            "https://github.com/attacker-org/my-package",
            "11223344556677889900aabbccddeeff11223344",
        );
        let bundle = sample_bundle(&statement);

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::RequireRepository {
            expected_repository: "my-org/my-package".into(),
        });

        let err = verifier
            .verify("my-package", &bundle, None, Some(tarball_bytes))
            .unwrap_err();

        match err {
            RegistryError::UntrustedSourceRepository { expected, actual } => {
                assert_eq!(expected, "my-org/my-package");
                assert_eq!(actual, "attacker-org/my-package");
            }
            other => panic!("Expected UntrustedSourceRepository, got: {other:?}"),
        }
    }

    #[test]
    fn test_slsa_v1_provenance_passes_verification() {
        let tarball_bytes = b"slsa v1 content";
        let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));

        let mut digest = HashMap::new();
        digest.insert("sha512".to_string(), sha512_hex.clone());

        let mut resolved_digest = HashMap::new();
        resolved_digest.insert("gitCommit".to_string(), "commit1234567890abcdef".to_string());

        let statement = InTotoStatement {
            statement_type: "https://in-toto.io/Statement/v1".into(),
            subject: vec![InTotoSubject {
                name: "v1-pkg".into(),
                digest,
            }],
            predicate_type: "https://slsa.dev/provenance/v1".into(),
            predicate: SlsaPredicate {
                builder: None,
                build_type: None,
                invocation: None,
                recipe: None,
                materials: Vec::new(),
                build_definition: Some(SlsaBuildDefinition {
                    build_type: Some("https://actions.github.com/Workflow@v1".into()),
                    external_parameters: Some(serde_json::json!({
                        "workflow": {
                            "repository": "https://github.com/trusted-org/v1-pkg",
                            "path": ".github/workflows/ci.yml"
                        }
                    })),
                    internal_parameters: None,
                    resolved_dependencies: vec![SlsaMaterial {
                        uri: Some("git+https://github.com/trusted-org/v1-pkg".into()),
                        digest: resolved_digest,
                    }],
                }),
                run_details: Some(SlsaRunDetails {
                    builder: Some(SlsaBuilder {
                        id: "https://github.com/actions/runner/v2".into(),
                    }),
                    metadata: None,
                }),
            },
        };

        let bundle = sample_bundle(&statement);
        let verifier = ProvenanceVerifier::new(ProvenancePolicy::RequireRepository {
            expected_repository: "trusted-org/v1-pkg".into(),
        });

        let verified = verifier
            .verify("v1-pkg", &bundle, None, Some(tarball_bytes))
            .unwrap();
        assert_eq!(verified.build.source_repository.as_deref(), Some("trusted-org/v1-pkg"));
        assert_eq!(verified.build.commit_sha.as_deref(), Some("commit1234567890abcdef"));
        assert_eq!(verified.build.workflow_path.as_deref(), Some(".github/workflows/ci.yml"));
    }

    #[test]
    fn test_registry_signature_parsing_and_validation() {
        let keyid = NPM_REGISTRY_KEYID;
        let valid_sig = BASE64.encode(b"dummy ecdsa signature bytes");

        let signatures = vec![DistSignature {
            keyid: keyid.to_string(),
            sig: valid_sig.clone(),
        }];

        // Validate without keyid filter
        let res = validate_dist_signatures(&signatures, None);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().len(), 1);

        // Validate with matching trusted keyid
        let res_trusted = validate_dist_signatures(&signatures, Some(&[NPM_REGISTRY_KEYID]));
        assert!(res_trusted.is_ok());

        // Validate with mismatched trusted keyid
        let err_untrusted = validate_dist_signatures(&signatures, Some(&["SHA256:some-other-key"]))
            .unwrap_err();
        match err_untrusted {
            RegistryError::InvalidSignature(msg) => {
                assert!(msg.contains("None of the signatures matched trusted keyids"), "{msg}");
            }
            other => panic!("Expected InvalidSignature, got: {other:?}"),
        }

        // Validate with malformed base64
        let malformed = vec![DistSignature {
            keyid: keyid.to_string(),
            sig: "not-valid-base64!@#$%^".to_string(),
        }];
        let err_b64 = validate_dist_signatures(&malformed, None).unwrap_err();
        match err_b64 {
            RegistryError::InvalidSignature(msg) => {
                assert!(msg.contains("is not valid base64"), "{msg}");
            }
            other => panic!("Expected InvalidSignature, got: {other:?}"),
        }
    }

    #[test]
    fn test_tarball_sri_integrity_verification() {
        let tarball_bytes = b"tarball for sri test";
        let sha512_digest = Sha512::digest(tarball_bytes);
        let sha512_hex = HEXLOWER.encode(&sha512_digest);
        let sha512_b64 = BASE64.encode(&sha512_digest);
        let sri_integrity = format!("sha512-{sha512_b64}");

        let statement = sample_statement_v02(
            "sri-pkg",
            &sha512_hex,
            "https://github.com/my-org/sri-pkg",
            "123456",
        );
        let bundle = sample_bundle(&statement);

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
        // Verifying with SRI string without raw tarball bytes
        let res = verifier.verify("sri-pkg", &bundle, Some(&sri_integrity), None);
        assert!(res.is_ok(), "SRI integrity verification failed: {:?}", res.err());
    }
}
