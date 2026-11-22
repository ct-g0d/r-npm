use data_encoding::{BASE64, BASE64_NOPAD, HEXLOWER};
use ring::signature::KeyPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;

use crate::asn1::{parse_spki, parse_x509_certificate, ParsedCertificate};
use crate::error::RegistryError;
use crate::metadata::{AbbreviatedVersion, DistSignature};

/// The well-known official npm registry public key identifier for package signatures.
pub const NPM_REGISTRY_KEYID: &str = "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA";

/// The well-known default Rekor public key SPKI base64 string from Sigstore TUF roots.
pub const REKOR_DEFAULT_PUBKEY_SPKI_B64: &str =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGIBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==";

/// The well-known default Rekor log identifier.
pub const REKOR_DEFAULT_LOG_ID: &str =
    "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d";

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

/// Formats the message payload for DSSE Pre-Authentication Encoding (PAE):
/// `DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>`
pub fn dsse_pre_auth_encoding(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = Vec::with_capacity(16 + payload_type.len() + payload.len());
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);
    pae
}

/// Cryptographically verifies a signature over a message against a public key (SPKI or raw).
/// Supports ECDSA P-256 (ASN.1 DER and FIXED 64-byte), ECDSA P-384, and Ed25519.
pub fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), RegistryError> {
    use ring::signature::{
        UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED,
        ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_FIXED, ED25519,
    };

    // 1. If public key is SPKI DER sequence (starts with 0x30)
    if public_key.first() == Some(&0x30) {
        if let Ok((algo_oid, curve_oid, pk_bytes)) = parse_spki(public_key) {
            if algo_oid == crate::asn1::OID_EC_PUBLIC_KEY {
                if curve_oid.as_deref() == Some(crate::asn1::OID_EC_P256) || pk_bytes.len() == 65 {
                    if UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &pk_bytes)
                        .verify(message, signature)
                        .is_ok()
                    {
                        return Ok(());
                    }
                    if UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &pk_bytes)
                        .verify(message, signature)
                        .is_ok()
                    {
                        return Ok(());
                    }
                } else if curve_oid.as_deref() == Some(crate::asn1::OID_EC_P384)
                    || pk_bytes.len() == 97
                {
                    if UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, &pk_bytes)
                        .verify(message, signature)
                        .is_ok()
                    {
                        return Ok(());
                    }
                    if UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &pk_bytes)
                        .verify(message, signature)
                        .is_ok()
                    {
                        return Ok(());
                    }
                }
            } else if (algo_oid == crate::asn1::OID_ED25519 || pk_bytes.len() == 32)
                && UnparsedPublicKey::new(&ED25519, &pk_bytes)
                    .verify(message, signature)
                    .is_ok()
            {
                return Ok(());
            }
        }
    }

    // 2. Direct formats or standard SPKI lengths
    if public_key.len() == 91 && public_key[0] == 0x30 {
        let pk_slice = &public_key[public_key.len() - 65..];
        if UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pk_slice)
            .verify(message, signature)
            .is_ok()
        {
            return Ok(());
        }
        if UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pk_slice)
            .verify(message, signature)
            .is_ok()
        {
            return Ok(());
        }
    }

    if public_key.len() == 65 && public_key[0] == 0x04 {
        if UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
            .verify(message, signature)
            .is_ok()
        {
            return Ok(());
        }
        if UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
            .verify(message, signature)
            .is_ok()
        {
            return Ok(());
        }
    }

    if public_key.len() == 97 && public_key[0] == 0x04 {
        if UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, public_key)
            .verify(message, signature)
            .is_ok()
        {
            return Ok(());
        }
        if UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, public_key)
            .verify(message, signature)
            .is_ok()
        {
            return Ok(());
        }
    }

    if public_key.len() == 32
        && UnparsedPublicKey::new(&ED25519, public_key)
            .verify(message, signature)
            .is_ok()
    {
        return Ok(());
    }

    Err(RegistryError::InvalidSignature(
        "Cryptographic signature verification failed".into(),
    ))
}

/// Verifies that a DSSE envelope is authentically signed by the given public key over DSSE PAE.
pub fn verify_dsse_envelope(
    envelope: &DsseEnvelope,
    public_key: &[u8],
) -> Result<(), RegistryError> {
    let payload = envelope.decode_payload()?;
    let pae = dsse_pre_auth_encoding(&envelope.payload_type, &payload);

    let mut any_verified = false;
    for s in &envelope.signatures {
        let sig_bytes = decode_base64(&s.sig)?;
        if verify_signature(public_key, &pae, &sig_bytes).is_ok() {
            any_verified = true;
            break;
        }
    }

    if !any_verified {
        return Err(RegistryError::InvalidSignature(
            "None of the DSSE signatures matched the expected public key".into(),
        ));
    }
    Ok(())
}

/// Verifies a Rekor Signed Entry Timestamp (SET) over canonicalized JSON.
pub fn verify_rekor_set(rekor_pubkeys: &[Vec<u8>], entry: &TlogEntry) -> Result<(), RegistryError> {
    let Some(promise) = &entry.inclusion_promise else {
        return Ok(());
    };
    if promise.signed_entry_timestamp.trim().is_empty() {
        return Ok(());
    }
    let sig_bytes = decode_base64(&promise.signed_entry_timestamp)?;

    let body = entry.canonicalized_body.as_deref().ok_or_else(|| {
        RegistryError::InvalidSigstoreBundle(
            "Missing canonicalizedBody for Rekor SET verification".into(),
        )
    })?;

    let log_id_str = &entry.log_id.key_id;
    let log_id_hex = if log_id_str.len() == 64 && log_id_str.chars().all(|c| c.is_ascii_hexdigit())
    {
        log_id_str.clone()
    } else if let Ok(bytes) = decode_base64(log_id_str) {
        HEXLOWER.encode(&bytes)
    } else {
        log_id_str.clone()
    };

    // Canonical JSON format: keys sorted lexicographically
    let canonical_json = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        body, entry.integrated_time, log_id_hex, entry.log_index
    );

    let mut ok = false;
    for pk in rekor_pubkeys {
        if verify_signature(pk, canonical_json.as_bytes(), &sig_bytes).is_ok() {
            ok = true;
            break;
        }
    }

    if !ok {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Rekor signedEntryTimestamp verification failed against trusted Rekor public keys"
                .into(),
        ));
    }
    Ok(())
}

/// Verifies an RFC 6962 Merkle tree inclusion proof against the root hash.
pub fn verify_merkle_inclusion_proof(entry: &TlogEntry) -> Result<(), RegistryError> {
    let Some(proof_val) = &entry.inclusion_proof else {
        return Ok(());
    };

    let log_index = proof_val
        .get("logIndex")
        .and_then(|v| v.as_u64())
        .unwrap_or(entry.log_index);
    let tree_size = proof_val
        .get("treeSize")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            RegistryError::InvalidSigstoreBundle("Missing treeSize in inclusionProof".into())
        })?;

    if log_index >= tree_size {
        return Err(RegistryError::InvalidSigstoreBundle(format!(
            "Invalid inclusion proof index {log_index} for tree size {tree_size}"
        )));
    }

    let hashes_array = proof_val
        .get("hashes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            RegistryError::InvalidSigstoreBundle("Missing hashes in inclusionProof".into())
        })?;

    let mut hashes = Vec::with_capacity(hashes_array.len());
    for h in hashes_array {
        let s = h.as_str().ok_or_else(|| {
            RegistryError::InvalidSigstoreBundle("Non-string hash in inclusionProof".into())
        })?;
        let bytes = if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            HEXLOWER.decode(s.as_bytes()).map_err(|e| {
                RegistryError::InvalidSigstoreBundle(format!("Invalid hex hash: {e}"))
            })?
        } else {
            decode_base64(s)?
        };
        hashes.push(bytes);
    }

    let expected_root = if let Some(rh_str) = proof_val.get("rootHash").and_then(|v| v.as_str()) {
        if rh_str.len() == 64 && rh_str.chars().all(|c| c.is_ascii_hexdigit()) {
            HEXLOWER.decode(rh_str.as_bytes()).map_err(|e| {
                RegistryError::InvalidSigstoreBundle(format!("Invalid rootHash hex: {e}"))
            })?
        } else {
            decode_base64(rh_str)?
        }
    } else if let Some(checkpoint) = proof_val.get("checkpoint").and_then(|v| v.as_str()) {
        let lines: Vec<&str> = checkpoint.lines().collect();
        if lines.len() >= 3 {
            decode_base64(lines[2].trim())?
        } else {
            return Err(RegistryError::InvalidSigstoreBundle(
                "Cannot extract root hash from checkpoint".into(),
            ));
        }
    } else {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Missing rootHash or checkpoint in inclusionProof".into(),
        ));
    };

    let body_bytes = if let Some(body_str) = &entry.canonicalized_body {
        decode_base64(body_str).unwrap_or_else(|_| body_str.as_bytes().to_vec())
    } else {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Missing canonicalizedBody in tlog entry for inclusion proof".into(),
        ));
    };

    let mut leaf_prefixed = Vec::with_capacity(1 + body_bytes.len());
    leaf_prefixed.push(0x00);
    leaf_prefixed.extend_from_slice(&body_bytes);
    let leaf_hash = Sha256::digest(&leaf_prefixed).to_vec();

    let inner = if log_index ^ (tree_size - 1) == 0 {
        0
    } else {
        64 - (log_index ^ (tree_size - 1)).leading_zeros() as usize
    };
    let border = (log_index >> inner).count_ones() as usize;

    if hashes.len() != inner + border {
        return Err(RegistryError::InvalidSigstoreBundle(format!(
            "Inclusion proof hash count mismatch: expected {}, got {}",
            inner + border,
            hashes.len()
        )));
    }

    fn hash_children(left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update([0x01]);
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().to_vec()
    }

    let mut current = leaf_hash;
    for (i, h) in hashes[..inner].iter().enumerate() {
        if ((log_index >> i) & 1) == 1 {
            current = hash_children(h, &current);
        } else {
            current = hash_children(&current, h);
        }
    }
    for h in &hashes[inner..] {
        current = hash_children(h, &current);
    }

    if current != expected_root {
        return Err(RegistryError::InvalidSigstoreBundle(format!(
            "Merkle inclusion proof root hash mismatch: expected {}, calculated {}",
            HEXLOWER.encode(&expected_root),
            HEXLOWER.encode(&current)
        )));
    }

    Ok(())
}

/// Validates registry signatures in `dist.signatures`.
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
        self.build_type.as_deref().or_else(|| {
            self.build_definition
                .as_ref()
                .and_then(|d| d.build_type.as_deref())
        })
    }

    pub fn source_repository(&self) -> Option<String> {
        if let Some(uri) = self
            .invocation
            .as_ref()
            .and_then(|inv| inv.config_source.as_ref())
            .and_then(|cs| cs.uri.as_ref())
        {
            return Some(normalize_repository_url(uri));
        }

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

        if let Some(bd) = self.build_definition.as_ref() {
            for dep in &bd.resolved_dependencies {
                if let Some(sha) = dep
                    .digest
                    .get("gitCommit")
                    .or_else(|| dep.digest.get("sha1"))
                {
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

        for mat in &self.materials {
            if let Some(sha) = mat
                .digest
                .get("sha1")
                .or_else(|| mat.digest.get("gitCommit"))
            {
                return Some(sha.clone());
            }
        }

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
        if let Some(ep) = self
            .invocation
            .as_ref()
            .and_then(|inv| inv.config_source.as_ref())
            .and_then(|cs| cs.entry_point.as_ref())
        {
            return Some(ep.clone());
        }

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

        if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
            if let Some(bundle_val) = val.get("bundle") {
                if let Ok(bundle) = serde_json::from_value::<SigstoreBundle>(bundle_val.clone()) {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BuildProvenance {
    pub builder_id: String,
    pub source_repository: Option<String>,
    pub commit_sha: Option<String>,
    pub workflow_path: Option<String>,
    pub build_type: Option<String>,
    pub issuer: Option<String>,
}

impl BuildProvenance {
    pub fn is_github_actions(&self) -> bool {
        self.builder_id.contains("github.com/actions")
            || self.builder_id.contains("GitHub")
            || self
                .source_repository
                .as_ref()
                .is_some_and(|r| !r.is_empty())
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
    rekor_public_keys: Vec<Vec<u8>>,
    registry_keys: HashMap<String, Vec<u8>>,
}

impl ProvenanceVerifier {
    pub fn new(policy: ProvenancePolicy) -> Self {
        let mut rekor_public_keys = Vec::new();
        if let Ok(k) = decode_base64(REKOR_DEFAULT_PUBKEY_SPKI_B64) {
            rekor_public_keys.push(k);
        }
        Self {
            policy,
            rekor_public_keys,
            registry_keys: HashMap::new(),
        }
    }

    pub fn with_rekor_public_key(mut self, key: Vec<u8>) -> Self {
        self.rekor_public_keys.push(key);
        self
    }

    pub fn with_registry_keys(mut self, keys: HashMap<String, Vec<u8>>) -> Self {
        self.registry_keys = keys;
        self
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
        let envelope = bundle.dsse_envelope.as_ref().ok_or_else(|| {
            RegistryError::InvalidSigstoreBundle("Missing dsseEnvelope in bundle".into())
        })?;

        if envelope.signatures.is_empty() {
            return Err(RegistryError::InvalidSigstoreBundle(
                "DSSE envelope signatures array is empty".into(),
            ));
        }

        // 2. Validate verificationMaterial
        let vm = bundle.verification_material.as_ref().ok_or_else(|| {
            RegistryError::InvalidSigstoreBundle("Missing verificationMaterial in bundle".into())
        })?;

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

        // 4. Extract verification public key (from leaf X.509 certificate or registry key)
        let mut parsed_leaf_cert: Option<ParsedCertificate> = None;
        let mut cert_count = 0;

        let leaf_cert_raw = if let Some(chain) = &vm.x509_certificate_chain {
            if chain.certificates.is_empty() {
                return Err(RegistryError::InvalidSigstoreBundle(
                    "x509CertificateChain has no certificates".into(),
                ));
            }
            cert_count = chain.certificates.len();
            Some(chain.certificates[0].raw_bytes.as_str())
        } else if let Some(cert) = &vm.certificate {
            cert_count = 1;
            Some(cert.raw_bytes.as_str())
        } else {
            None
        };

        let signing_key = if let Some(raw_b64) = leaf_cert_raw {
            if raw_b64.trim().is_empty() {
                return Err(RegistryError::InvalidSigstoreBundle(
                    "Certificate has empty rawBytes".into(),
                ));
            }
            let der = decode_base64(raw_b64)?;
            let parsed = parse_x509_certificate(&der)?;

            // Verify certificate validity window against Rekor integratedTime
            if primary_tlog.integrated_time > 0
                && (primary_tlog.integrated_time < parsed.not_before
                    || primary_tlog.integrated_time > parsed.not_after)
            {
                return Err(RegistryError::InvalidSigstoreBundle(format!(
                    "Certificate not valid at integratedTime {}: validity window [{}, {}]",
                    primary_tlog.integrated_time, parsed.not_before, parsed.not_after
                )));
            }

            let spki = parsed.spki_bytes.clone();
            parsed_leaf_cert = Some(parsed);
            spki
        } else {
            // Check if keyed attestation
            let keyid = envelope.signatures[0].keyid.as_deref().unwrap_or_default();
            if let Some(reg_key) = self.registry_keys.get(keyid) {
                reg_key.clone()
            } else if !self.registry_keys.is_empty() {
                return Err(RegistryError::InvalidSignature(format!(
                    "No corresponding public key found for attestation keyid '{keyid}'"
                )));
            } else {
                return Err(RegistryError::InvalidSigstoreBundle(
                    "Missing certificate chain in verification material and no registry keys available".into(),
                ));
            }
        };

        // 5. Verify DSSE envelope cryptographic signature over PAE
        verify_dsse_envelope(envelope, &signing_key)?;

        // 6. Verify Rekor signedEntryTimestamp (SET)
        if !self.rekor_public_keys.is_empty() {
            verify_rekor_set(&self.rekor_public_keys, primary_tlog)?;
        }

        // 7. Verify RFC 6962 Merkle inclusion proof
        verify_merkle_inclusion_proof(primary_tlog)?;

        // 8. Parse and validate in-toto statement
        let statement = envelope.parse_statement()?;
        if statement.subject.is_empty() {
            return Err(RegistryError::ProvenanceVerificationFailed(
                "in-toto Statement has no subjects".into(),
            ));
        }

        // 9. Match subject with expected package name / PURL
        let matched_subject = Self::find_matching_subject(&statement.subject, package_name)?;

        // 10. Verify tarball integrity digest against subject.digest
        Self::verify_subject_digest(matched_subject, tarball_integrity, tarball_bytes)?;

        // 11. Extract build provenance details
        let mut source_repository = statement.predicate.source_repository();
        let mut commit_sha = statement.predicate.commit_sha();
        let mut workflow_path = statement.predicate.workflow_path();
        let mut issuer = None;

        if let Some(cert) = &parsed_leaf_cert {
            if source_repository.is_none() {
                source_repository = cert
                    .fulcio_extensions
                    .get(crate::asn1::OID_FULCIO_GITHUB_WORKFLOW_REPOSITORY)
                    .map(|r| normalize_repository_url(r));
            }
            if commit_sha.is_none() {
                commit_sha = cert
                    .fulcio_extensions
                    .get(crate::asn1::OID_FULCIO_RUN_COMMIT_SHA)
                    .or_else(|| {
                        cert.fulcio_extensions
                            .get(crate::asn1::OID_FULCIO_GITHUB_WORKFLOW_SHA)
                    })
                    .cloned();
            }
            if workflow_path.is_none() {
                workflow_path = cert
                    .fulcio_extensions
                    .get(crate::asn1::OID_FULCIO_GITHUB_WORKFLOW_REF)
                    .cloned();
            }
            issuer = cert
                .fulcio_extensions
                .get(crate::asn1::OID_FULCIO_ISSUER)
                .cloned();
        }

        let build = BuildProvenance {
            builder_id: statement
                .predicate
                .builder_id()
                .unwrap_or_default()
                .to_string(),
            source_repository,
            commit_sha,
            workflow_path,
            build_type: statement.predicate.build_type().map(|s| s.to_string()),
            issuer,
        };

        // 12. Enforce repository policy if required
        if let ProvenancePolicy::RequireRepository {
            expected_repository,
        } = &self.policy
        {
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
            // PURL matching
            if let Some(purl_rest) = s.strip_prefix("pkg:npm/") {
                let purl_name = purl_rest.split('@').next().unwrap_or(purl_rest);
                let decoded_purl_name = purl_name.replace("%40", "@");
                if decoded_purl_name == package_name || decoded_purl_name == unscoped_name {
                    return Ok(subj);
                }
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
            "Neither tarball_bytes nor tarball_integrity was provided for digest verification"
                .into(),
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
    ProvenanceVerifier::new(policy.clone()).verify(
        package_name,
        bundle,
        tarball_integrity,
        tarball_bytes,
    )
}

// ---------------------------------------------------------------------------
// PROVENANCE GENERATION (EPHEMERAL KEYS, SLSA V1, FULCIO, REKOR)
// ---------------------------------------------------------------------------

/// Ephemeral ECDSA P-256 signer for Sigstore provenance generation.
pub struct EphemeralSigner {
    key_pair: ring::signature::EcdsaKeyPair,
    public_key_spki: Vec<u8>,
}

impl EphemeralSigner {
    /// Generates a new ephemeral ECDSA P-256 keypair.
    pub fn new() -> Result<Self, RegistryError> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .map_err(|e| {
            RegistryError::Other(format!("Failed to generate ephemeral ECDSA P-256 keypair: {e}"))
        })?;

        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .map_err(|e| {
            RegistryError::Other(format!("Failed to parse generated PKCS#8 key: {e}"))
        })?;

        // Format 91-byte P-256 SubjectPublicKeyInfo DER
        let spki_prefix = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        let mut public_key_spki = Vec::with_capacity(91);
        public_key_spki.extend_from_slice(&spki_prefix);
        public_key_spki.extend_from_slice(key_pair.public_key().as_ref());

        Ok(Self {
            key_pair,
            public_key_spki,
        })
    }

    pub fn public_key_spki(&self) -> &[u8] {
        &self.public_key_spki
    }

    pub fn public_key_uncompressed(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    pub fn public_key_spki_pem(&self) -> String {
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            BASE64.encode(&self.public_key_spki)
        )
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RegistryError> {
        let rng = ring::rand::SystemRandom::new();
        self.key_pair
            .sign(&rng, message)
            .map(|sig| sig.as_ref().to_vec())
            .map_err(|e| RegistryError::Other(format!("ECDSA signing failed: {e}")))
    }
}

/// Information extracted from CI environment for SLSA provenance predicate.
#[derive(Debug, Clone, Default)]
pub struct CiEnvironmentInfo {
    pub ci_name: String,
    pub server_url: String,
    pub repository: String,
    pub ref_name: String,
    pub commit_sha: String,
    pub workflow_path: String,
    pub workflow_ref: String,
    pub run_id: String,
    pub run_attempt: String,
    pub runner_environment: String,
    pub event_name: String,
    pub repository_id: String,
    pub repository_owner_id: String,
}

impl CiEnvironmentInfo {
    /// Detects CI environment from environment variables.
    pub fn detect() -> Self {
        if std::env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true") {
            let server_url = std::env::var("GITHUB_SERVER_URL")
                .unwrap_or_else(|_| "https://github.com".to_string());
            let repository = std::env::var("GITHUB_REPOSITORY").unwrap_or_default();
            let workflow_ref_raw = std::env::var("GITHUB_WORKFLOW_REF").unwrap_or_default();
            let relative_ref = workflow_ref_raw
                .strip_prefix(&format!("{repository}/"))
                .unwrap_or(&workflow_ref_raw);

            let (workflow_path, workflow_ref) = if let Some((path, r)) = relative_ref.split_once('@')
            {
                (path.to_string(), r.to_string())
            } else {
                (relative_ref.to_string(), String::new())
            };

            Self {
                ci_name: "GitHub Actions".to_string(),
                server_url,
                repository,
                ref_name: std::env::var("GITHUB_REF").unwrap_or_default(),
                commit_sha: std::env::var("GITHUB_SHA").unwrap_or_default(),
                workflow_path,
                workflow_ref,
                run_id: std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "1".to_string()),
                run_attempt: std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "1".to_string()),
                runner_environment: std::env::var("RUNNER_ENVIRONMENT")
                    .unwrap_or_else(|_| "github-hosted".to_string()),
                event_name: std::env::var("GITHUB_EVENT_NAME").unwrap_or_default(),
                repository_id: std::env::var("GITHUB_REPOSITORY_ID").unwrap_or_default(),
                repository_owner_id: std::env::var("GITHUB_REPOSITORY_OWNER_ID").unwrap_or_default(),
            }
        } else if std::env::var_os("GITLAB_CI").is_some() {
            Self {
                ci_name: "GitLab CI".to_string(),
                server_url: std::env::var("CI_SERVER_URL")
                    .unwrap_or_else(|_| "https://gitlab.com".to_string()),
                repository: std::env::var("CI_PROJECT_PATH").unwrap_or_default(),
                ref_name: std::env::var("CI_COMMIT_REF_NAME").unwrap_or_default(),
                commit_sha: std::env::var("CI_COMMIT_SHA").unwrap_or_default(),
                workflow_path: std::env::var("CI_CONFIG_PATH").unwrap_or_default(),
                workflow_ref: std::env::var("CI_COMMIT_REF_NAME").unwrap_or_default(),
                run_id: std::env::var("CI_PIPELINE_ID").unwrap_or_else(|_| "1".to_string()),
                run_attempt: "1".to_string(),
                runner_environment: std::env::var("CI_RUNNER_DESCRIPTION")
                    .unwrap_or_else(|_| "gitlab-runner".to_string()),
                event_name: std::env::var("CI_PIPELINE_SOURCE").unwrap_or_default(),
                repository_id: std::env::var("CI_PROJECT_ID").unwrap_or_default(),
                repository_owner_id: std::env::var("CI_PROJECT_NAMESPACE_ID").unwrap_or_default(),
            }
        } else {
            Self {
                ci_name: "CI".to_string(),
                server_url: "https://github.com".to_string(),
                repository: "unknown/unknown".to_string(),
                ..Default::default()
            }
        }
    }
}

/// Constructs an in-toto SLSA v1 statement for the given package tarball.
pub fn build_slsa_v1_statement(
    package_name: &str,
    package_version: &str,
    tarball_sha512_hex: &str,
    ci: &CiEnvironmentInfo,
) -> InTotoStatement {
    let mut digest = HashMap::new();
    digest.insert("sha512".to_string(), tarball_sha512_hex.to_string());

    let purl_encoded_name = if let Some(stripped) = package_name.strip_prefix('@') {
        format!("%40{}", stripped)
    } else {
        package_name.to_string()
    };
    let purl = format!("pkg:npm/{purl_encoded_name}@{package_version}");

    let mut resolved_digest = HashMap::new();
    resolved_digest.insert("gitCommit".to_string(), ci.commit_sha.clone());

    let external_parameters = serde_json::json!({
        "workflow": {
            "ref": ci.workflow_ref,
            "repository": format!("{}/{}", ci.server_url.trim_end_matches('/'), ci.repository),
            "path": ci.workflow_path,
        }
    });

    let internal_parameters = serde_json::json!({
        "github": {
            "event_name": ci.event_name,
            "repository_id": ci.repository_id,
            "repository_owner_id": ci.repository_owner_id,
        }
    });

    let resolved_dependencies = vec![SlsaMaterial {
        uri: Some(format!(
            "git+{}/{}@{}",
            ci.server_url.trim_end_matches('/'),
            ci.repository,
            ci.ref_name
        )),
        digest: resolved_digest,
    }];

    let run_details = SlsaRunDetails {
        builder: Some(SlsaBuilder {
            id: format!("https://github.com/actions/runner/{}", ci.runner_environment),
        }),
        metadata: Some(serde_json::json!({
            "invocationId": format!("{}/{}/actions/runs/{}/attempts/{}", ci.server_url.trim_end_matches('/'), ci.repository, ci.run_id, ci.run_attempt)
        })),
    };

    InTotoStatement {
        statement_type: "https://in-toto.io/Statement/v1".into(),
        subject: vec![InTotoSubject { name: purl, digest }],
        predicate_type: "https://slsa.dev/provenance/v1".into(),
        predicate: SlsaPredicate {
            builder: None,
            build_type: None,
            invocation: None,
            recipe: None,
            materials: Vec::new(),
            build_definition: Some(SlsaBuildDefinition {
                build_type: Some(
                    "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1".into(),
                ),
                external_parameters: Some(external_parameters),
                internal_parameters: Some(internal_parameters),
                resolved_dependencies,
            }),
            run_details: Some(run_details),
        },
    }
}

/// Signs an in-toto statement with an EphemeralSigner and returns the DSSE envelope.
pub fn sign_dsse_envelope(
    statement: &InTotoStatement,
    signer: &EphemeralSigner,
) -> Result<DsseEnvelope, RegistryError> {
    let statement_json = serde_json::to_vec(statement)
        .map_err(|e| RegistryError::Other(format!("Failed to serialize in-toto statement: {e}")))?;
    let payload_type = "application/vnd.in-toto+json";
    let pae = dsse_pre_auth_encoding(payload_type, &statement_json);
    let sig_bytes = signer.sign(&pae)?;

    Ok(DsseEnvelope {
        payload_type: payload_type.to_string(),
        payload: BASE64.encode(&statement_json),
        signatures: vec![DsseSignature {
            keyid: None,
            sig: BASE64.encode(&sig_bytes),
        }],
    })
}

/// Requests a signing certificate from Fulcio using an OIDC token and EphemeralSigner proof of possession.
pub async fn request_fulcio_signing_cert(
    fulcio_url: &str,
    oidc_token: &str,
    signer: &EphemeralSigner,
) -> Result<Vec<u8>, RegistryError> {
    // 1. Extract subject claim from OIDC JWT
    let parts: Vec<&str> = oidc_token.split('.').collect();
    if parts.len() < 2 {
        return Err(RegistryError::Other("Invalid OIDC JWT structure".into()));
    }
    let payload_bytes = decode_base64(parts[1])?;
    let payload_json: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| RegistryError::Other(format!("Invalid OIDC JWT payload JSON: {e}")))?;
    let subject = payload_json["sub"]
        .as_str()
        .ok_or_else(|| RegistryError::Other("OIDC JWT missing 'sub' claim".into()))?;

    // 2. Sign proof of possession
    let challenge_sig = signer.sign(subject.as_bytes())?;

    // 3. Request signing certificate
    let request_body = serde_json::json!({
        "credentials": {
            "oidcIdentityToken": oidc_token,
        },
        "publicKeyRequest": {
            "publicKey": {
                "algorithm": "ECDSA",
                "content": signer.public_key_spki_pem(),
            },
            "proofOfPossession": BASE64.encode(&challenge_sig),
        }
    });

    let client = reqwest::Client::new();
    let url = if fulcio_url.ends_with("/api/v2/signingCert") {
        fulcio_url.to_string()
    } else {
        format!("{}/api/v2/signingCert", fulcio_url.trim_end_matches('/'))
    };

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(RegistryError::Other(format!(
            "Fulcio request failed with status {status}: {text}"
        )));
    }

    let resp_json: serde_json::Value = resp.json().await?;
    let cert_chain = resp_json
        .get("signedCertificateEmbeddedSct")
        .or_else(|| resp_json.get("signedCertificateDetachedSct"))
        .and_then(|c| c.get("chain"))
        .and_then(|ch| ch.get("certificates"))
        .and_then(|certs| certs.as_array())
        .ok_or_else(|| {
            RegistryError::Other("Fulcio response missing certificates chain".into())
        })?;

    if cert_chain.is_empty() {
        return Err(RegistryError::Other("Fulcio returned empty certificate chain".into()));
    }

    let leaf_pem = cert_chain[0].as_str().unwrap_or_default();
    let leaf_der = decode_pem_to_der(leaf_pem)?;
    Ok(leaf_der)
}

/// Decodes a PEM-formatted certificate or key into raw DER bytes.
pub fn decode_pem_to_der(pem: &str) -> Result<Vec<u8>, RegistryError> {
    let clean: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    decode_base64(&clean)
}

/// Submits a DSSE entry to Rekor and returns the created TlogEntry.
pub async fn submit_rekor_dsse_entry(
    rekor_url: &str,
    dsse_envelope: &DsseEnvelope,
    leaf_cert_der: &[u8],
) -> Result<TlogEntry, RegistryError> {
    let envelope_json = serde_json::to_string(dsse_envelope)
        .map_err(|e| RegistryError::Other(format!("Failed to serialize DSSE envelope: {e}")))?;
    let leaf_b64 = BASE64.encode(leaf_cert_der);

    let proposed_entry = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "proposedContent": {
                "envelope": envelope_json,
                "verifiers": [leaf_b64],
            }
        }
    });

    let client = reqwest::Client::new();
    let url = if rekor_url.ends_with("/api/v1/log/entries") {
        rekor_url.to_string()
    } else {
        format!("{}/api/v1/log/entries", rekor_url.trim_end_matches('/'))
    };

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&proposed_entry)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(RegistryError::Other(format!(
            "Rekor request failed with status {status}: {text}"
        )));
    }

    let resp_json: serde_json::Value = resp.json().await?;
    let obj = resp_json
        .as_object()
        .ok_or_else(|| RegistryError::Other("Rekor response is not an object".into()))?;

    let (_uuid, entry) = obj
        .iter()
        .next()
        .ok_or_else(|| RegistryError::Other("Empty Rekor entries map in response".into()))?;

    let log_index = entry["logIndex"].as_u64().unwrap_or(0);
    let log_id = entry["logID"].as_str().unwrap_or_default().to_string();
    let integrated_time = entry["integratedTime"].as_i64().unwrap_or(0);

    let inclusion_promise = entry.get("inclusionPromise").map(|p| InclusionPromise {
        signed_entry_timestamp: p["signedEntryTimestamp"].as_str().unwrap_or_default().to_string(),
    });
    let inclusion_proof = entry.get("inclusionProof").cloned();
    let canonicalized_body = entry.get("body").and_then(|b| b.as_str()).map(str::to_string);

    Ok(TlogEntry {
        log_index,
        log_id: LogId { key_id: log_id },
        integrated_time,
        inclusion_promise,
        inclusion_proof,
        canonicalized_body,
    })
}

/// Assembles a complete Sigstore v0.2 bundle from envelope, certificate, and Rekor entry.
pub fn assemble_sigstore_bundle(
    dsse_envelope: DsseEnvelope,
    leaf_cert_der: &[u8],
    tlog_entry: TlogEntry,
) -> SigstoreBundle {
    SigstoreBundle {
        media_type: Some("application/vnd.dev.sigstore.bundle+json;version=0.2".into()),
        verification_material: Some(VerificationMaterial {
            x509_certificate_chain: None,
            certificate: Some(X509Certificate {
                raw_bytes: BASE64.encode(leaf_cert_der),
            }),
            tlog_entries: vec![tlog_entry],
            timestamp_verification_data: None,
        }),
        dsse_envelope: Some(dsse_envelope),
    }
}

/// Generates a full Sigstore provenance bundle for package publish.
pub async fn generate_sigstore_provenance(
    package_name: &str,
    package_version: &str,
    tarball_sha512_hex: &str,
    oidc_token: &str,
    custom_fulcio_url: Option<&str>,
    custom_rekor_url: Option<&str>,
) -> Result<(SigstoreBundle, String), RegistryError> {
    let env_fulcio = std::env::var("SIGSTORE_FULCIO_URL").ok();
    let fulcio_url = custom_fulcio_url
        .or(env_fulcio.as_deref())
        .unwrap_or("https://fulcio.sigstore.dev");
    let env_rekor = std::env::var("SIGSTORE_REKOR_URL").ok();
    let rekor_url = custom_rekor_url
        .or(env_rekor.as_deref())
        .unwrap_or("https://rekor.sigstore.dev");

    // 1. Generate ephemeral ECDSA P-256 keypair
    let signer = EphemeralSigner::new()?;

    // 2. Request Fulcio leaf certificate
    let leaf_cert = request_fulcio_signing_cert(fulcio_url, oidc_token, &signer).await?;

    // 3. Build in-toto SLSA v1 statement
    let ci = CiEnvironmentInfo::detect();
    let statement = build_slsa_v1_statement(package_name, package_version, tarball_sha512_hex, &ci);

    // 4. Sign DSSE envelope over PAE
    let envelope = sign_dsse_envelope(&statement, &signer)?;

    // 5. Submit DSSE entry to Rekor
    let tlog_entry = submit_rekor_dsse_entry(rekor_url, &envelope, &leaf_cert).await?;
    let log_index = tlog_entry.log_index;

    // 6. Assemble bundle
    let bundle = assemble_sigstore_bundle(envelope, &leaf_cert, tlog_entry);
    let tlog_url = format!("https://search.sigstore.dev/?logIndex={log_index}");

    Ok((bundle, tlog_url))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_valid_signed_test_bundle(
        pkg: &str,
        version: &str,
        tarball_bytes: &[u8],
        repo: &str,
        commit: &str,
    ) -> (SigstoreBundle, EphemeralSigner) {
        let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));
        let signer = EphemeralSigner::new().unwrap();

        let ci = CiEnvironmentInfo {
            ci_name: "GitHub Actions".into(),
            server_url: "https://github.com".into(),
            repository: repo.into(),
            commit_sha: commit.into(),
            workflow_path: ".github/workflows/release.yml".into(),
            workflow_ref: "refs/heads/main".into(),
            ..Default::default()
        };

        let statement = build_slsa_v1_statement(pkg, version, &sha512_hex, &ci);
        let envelope = sign_dsse_envelope(&statement, &signer).unwrap();

        let now = 1700000000i64;
        let fulcio_exts = [
            (
                crate::asn1::OID_FULCIO_ISSUER,
                "https://token.actions.githubusercontent.com",
            ),
            (
                crate::asn1::OID_FULCIO_GITHUB_WORKFLOW_REPOSITORY,
                repo,
            ),
            (crate::asn1::OID_FULCIO_RUN_COMMIT_SHA, commit),
        ];

        let cert_der = crate::asn1::create_test_x509_certificate(
            "test-signer",
            "sigstore",
            signer.public_key_uncompressed(),
            Some("https://github.com/actions/runner"),
            &fulcio_exts,
            now - 60,
            now + 600,
            &|tbs| signer.sign(tbs).unwrap(),
        );

        let tlog_entry = TlogEntry {
            log_index: 42,
            log_id: LogId {
                key_id: REKOR_DEFAULT_LOG_ID.into(),
            },
            integrated_time: now,
            inclusion_promise: None,
            inclusion_proof: None,
            canonicalized_body: Some(BASE64.encode(b"canonical-body")),
        };

        let bundle = assemble_sigstore_bundle(envelope, &cert_der, tlog_entry);
        (bundle, signer)
    }

    #[test]
    fn test_cryptographic_verification_pass() {
        let tarball_bytes = b"real tarball bytes for signature verification";
        let (bundle, _) = generate_valid_signed_test_bundle(
            "test-pkg",
            "1.0.0",
            tarball_bytes,
            "my-org/test-pkg",
            "abcdef1234567890abcdef1234567890abcdef12",
        );

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
        let res = verifier.verify("test-pkg", &bundle, None, Some(tarball_bytes));
        assert!(res.is_ok(), "Verification failed: {:?}", res.err());

        let verified = res.unwrap();
        assert_eq!(verified.package_name, "test-pkg");
        assert_eq!(
            verified.build.source_repository.as_deref(),
            Some("my-org/test-pkg")
        );
        assert_eq!(
            verified.build.commit_sha.as_deref(),
            Some("abcdef1234567890abcdef1234567890abcdef12")
        );
    }

    #[test]
    fn test_cryptographic_verification_fail_on_tampered_payload() {
        let tarball_bytes = b"real tarball bytes";
        let (mut bundle, _) = generate_valid_signed_test_bundle(
            "test-pkg",
            "1.0.0",
            tarball_bytes,
            "my-org/test-pkg",
            "abcdef1234567890abcdef1234567890abcdef12",
        );

        // Tamper with DSSE payload
        bundle.dsse_envelope.as_mut().unwrap().payload = BASE64.encode(b"tampered payload");

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
        let err = verifier
            .verify("test-pkg", &bundle, None, Some(tarball_bytes))
            .unwrap_err();
        match err {
            RegistryError::InvalidSignature(_) | RegistryError::InvalidSigstoreBundle(_) => {}
            other => panic!("Expected signature verification error, got: {other:?}"),
        }
    }

    #[test]
    fn test_cryptographic_verification_fail_on_wrong_signature() {
        let tarball_bytes = b"real tarball bytes";
        let (mut bundle, _) = generate_valid_signed_test_bundle(
            "test-pkg",
            "1.0.0",
            tarball_bytes,
            "my-org/test-pkg",
            "abcdef1234567890abcdef1234567890abcdef12",
        );

        // Tamper with signature bytes
        let mut sig_bytes = decode_base64(&bundle.dsse_envelope.as_ref().unwrap().signatures[0].sig).unwrap();
        sig_bytes[10] ^= 0xFF;
        bundle.dsse_envelope.as_mut().unwrap().signatures[0].sig = BASE64.encode(&sig_bytes);

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
        let err = verifier
            .verify("test-pkg", &bundle, None, Some(tarball_bytes))
            .unwrap_err();
        match err {
            RegistryError::InvalidSignature(_) => {}
            other => panic!("Expected InvalidSignature, got: {other:?}"),
        }
    }

    #[test]
    fn test_cryptographic_verification_fail_on_digest_mismatch() {
        let tarball_bytes = b"real tarball bytes";
        let (bundle, _) = generate_valid_signed_test_bundle(
            "test-pkg",
            "1.0.0",
            tarball_bytes,
            "my-org/test-pkg",
            "abcdef1234567890abcdef1234567890abcdef12",
        );

        let tampered_tarball = b"modified tarball bytes";
        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
        let err = verifier
            .verify("test-pkg", &bundle, None, Some(tampered_tarball))
            .unwrap_err();
        match err {
            RegistryError::AttestationDigestMismatch { .. } => {}
            other => panic!("Expected AttestationDigestMismatch, got: {other:?}"),
        }
    }

    #[test]
    fn test_cryptographic_verification_fail_on_expired_cert() {
        let tarball_bytes = b"real tarball bytes";
        let (mut bundle, _) = generate_valid_signed_test_bundle(
            "test-pkg",
            "1.0.0",
            tarball_bytes,
            "my-org/test-pkg",
            "abcdef1234567890abcdef1234567890abcdef12",
        );

        // Integrated time far in the future
        bundle.verification_material.as_mut().unwrap().tlog_entries[0].integrated_time = 1800000000;

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
        let err = verifier
            .verify("test-pkg", &bundle, None, Some(tarball_bytes))
            .unwrap_err();
        match err {
            RegistryError::InvalidSigstoreBundle(msg) => {
                assert!(msg.contains("Certificate not valid"), "{msg}");
            }
            other => panic!("Expected InvalidSigstoreBundle, got: {other:?}"),
        }
    }

    #[test]
    fn test_rekor_merkle_inclusion_proof_pass_and_fail() {
        let body = b"canonical-rekor-body";
        let mut leaf_prefixed = vec![0x00];
        leaf_prefixed.extend_from_slice(body);
        let leaf_hash = Sha256::digest(&leaf_prefixed).to_vec();

        let sibling = Sha256::digest(b"sibling-hash").to_vec();
        let mut hasher = Sha256::new();
        hasher.update([0x01]);
        hasher.update(&leaf_hash);
        hasher.update(&sibling);
        let root_hash = hasher.finalize().to_vec();

        let entry = TlogEntry {
            log_index: 0,
            log_id: LogId {
                key_id: "test-log".into(),
            },
            integrated_time: 1700000000,
            inclusion_promise: None,
            inclusion_proof: Some(serde_json::json!({
                "logIndex": 0,
                "treeSize": 2,
                "hashes": [HEXLOWER.encode(&sibling)],
                "rootHash": HEXLOWER.encode(&root_hash),
            })),
            canonicalized_body: Some(BASE64.encode(body)),
        };

        // Valid proof
        assert!(verify_merkle_inclusion_proof(&entry).is_ok());

        // Tampered proof
        let mut bad_entry = entry.clone();
        bad_entry.inclusion_proof = Some(serde_json::json!({
            "logIndex": 0,
            "treeSize": 2,
            "hashes": [HEXLOWER.encode(&sibling)],
            "rootHash": HEXLOWER.encode(&Sha256::digest(b"wrong-root")),
        }));
        assert!(verify_merkle_inclusion_proof(&bad_entry).is_err());
    }

    #[test]
    fn test_rekor_set_verification_pass_and_fail() {
        let rekor_signer = EphemeralSigner::new().unwrap();
        let body_b64 = BASE64.encode(b"rekor-entry-body");
        let integrated_time = 1700000000i64;
        let log_index = 100u64;
        let log_id_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let payload = format!(
            r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
            body_b64, integrated_time, log_id_hex, log_index
        );
        let set_sig = rekor_signer.sign(payload.as_bytes()).unwrap();

        let entry = TlogEntry {
            log_index,
            log_id: LogId {
                key_id: log_id_hex.into(),
            },
            integrated_time,
            inclusion_promise: Some(InclusionPromise {
                signed_entry_timestamp: BASE64.encode(&set_sig),
            }),
            inclusion_proof: None,
            canonicalized_body: Some(body_b64),
        };

        let pubkeys = vec![rekor_signer.public_key_spki().to_vec()];
        assert!(verify_rekor_set(&pubkeys, &entry).is_ok());

        // Wrong payload/key fail
        let wrong_signer = EphemeralSigner::new().unwrap();
        let wrong_pubkeys = vec![wrong_signer.public_key_spki().to_vec()];
        assert!(verify_rekor_set(&wrong_pubkeys, &entry).is_err());
    }
}
