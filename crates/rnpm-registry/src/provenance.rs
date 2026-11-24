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

/// The well-known default Rekor public key SPKI base64 string from Sigstore TUF roots (P-256).
pub const REKOR_DEFAULT_PUBKEY_SPKI_B64: &str =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==";

/// Rekor log2025-1 Ed25519 public key SPKI base64 string from Sigstore TUF roots.
pub const REKOR_2025_PUBKEY_SPKI_B64: &str =
    "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=";

/// The well-known default Rekor log identifier.
pub const REKOR_DEFAULT_LOG_ID: &str =
    "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d";

/// Sigstore Fulcio Root CA v1 DER base64 from `@sigstore/tuf` trusted_root.json.
pub const FULCIO_ROOT_CA_1_DER_B64: &str =
    "MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==";

/// Sigstore Fulcio Intermediate CA v2 DER base64 from `@sigstore/tuf` trusted_root.json.
pub const FULCIO_INTERMEDIATE_CA_2_DER_B64: &str =
    "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow=";

/// Sigstore Fulcio Root CA v2 DER base64 from `@sigstore/tuf` trusted_root.json.
pub const FULCIO_ROOT_CA_2_DER_B64: &str =
    "MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ";

/// Test Mock Fulcio Root CA PKCS#8 private key for testing and deterministic mock verification.
pub const TEST_MOCK_CA_PRIV_PKCS8_B64: &str =
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRfFeraBu/sx/La4TCipYT2NStC89bWdnjT1xzNDBWtehRANCAASrqBpyXJ8MH6YcDTQMT9/w1s1dEzmN0swCZhqFRWS7X8yqJLdaWQqe107R5SXQn7cj58+P2so2YSZ0LMH2Qcuz";

/// Test Mock Rekor PKCS#8 private key for testing and deterministic mock verification.
pub const TEST_MOCK_REKOR_PRIV_PKCS8_B64: &str =
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwzdX7/ELLDeKuMzw3faqvdQ3XRNLwZ19280+W9FEdFGhRANCAAS9ORz4OsMqQzKTBCJbFFA99c/NNVIxmilUsIWM0OCw42Ru/0NrZ6b09D/UkB1YHzyTQF/DAhd4qU+b1BNAyqKz";

/// Test Mock Rekor Public Key SPKI base64.
pub const TEST_MOCK_REKOR_PUB_SPKI_B64: &str =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvTkc+DrDKkMykwQiWxRQPfXPzTVSMZopVLCFjNDgsONkbv9Da2em9PQ/1JAdWB88k0BfwwIXeKlPm9QTQMqisw==";

/// Returns the test mock Fulcio root CA DER certificate bytes.
pub fn test_mock_fulcio_root_cert() -> Vec<u8> {
    let rng = ring::rand::SystemRandom::new();
    let ca_priv = decode_base64(TEST_MOCK_CA_PRIV_PKCS8_B64).expect("valid mock CA pkcs8");
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &ca_priv,
        &rng,
    )
    .expect("parse mock CA keypair");
    crate::asn1::create_test_x509_certificate(
        "sigstore",
        "sigstore",
        key_pair.public_key().as_ref(),
        None,
        &[],
        1500000000,
        2000000000,
        &|tbs| key_pair.sign(&rng, tbs).expect("mock CA sign").as_ref().to_vec(),
    )
}

/// Returns the test mock Rekor public key SPKI bytes.
pub fn test_mock_rekor_pubkey() -> Vec<u8> {
    decode_base64(TEST_MOCK_REKOR_PUB_SPKI_B64).expect("valid mock Rekor SPKI")
}

/// Custom serde deserializer for fields that may appear as numbers or strings in Sigstore JSON.
pub fn deserialize_u64_or_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct U64OrStringVisitor;
    impl<'de> serde::de::Visitor<'de> for U64OrStringVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an unsigned integer or string integer")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v)
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if v >= 0 {
                Ok(v as u64)
            } else {
                Err(E::custom(format!("invalid negative value for u64: {v}")))
            }
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            v.trim().parse::<u64>().map_err(E::custom)
        }
    }
    deserializer.deserialize_any(U64OrStringVisitor)
}

/// Custom serde deserializer for fields that may appear as numbers or strings in Sigstore JSON.
pub fn deserialize_i64_or_string<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct I64OrStringVisitor;
    impl<'de> serde::de::Visitor<'de> for I64OrStringVisitor {
        type Value = i64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an integer or string integer")
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v)
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v as i64)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            v.trim().parse::<i64>().map_err(E::custom)
        }
    }
    deserializer.deserialize_any(I64OrStringVisitor)
}

/// Safely extracts a u64 from a serde_json::Value that can be a number or a string.
pub fn parse_u64_from_value(val: &serde_json::Value) -> Option<u64> {
    if let Some(n) = val.as_u64() {
        Some(n)
    } else if let Some(s) = val.as_str() {
        s.trim().parse::<u64>().ok()
    } else {
        None
    }
}

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

    if signature.is_empty() {
        return Err(RegistryError::InvalidSignature("Empty signature".into()));
    }

    // Raw Ed25519 keys may start with the DER sequence tag.
    if public_key.len() != 32 && public_key.first() == Some(&0x30) {
        let (algo_oid, curve_oid, pk_bytes) = parse_spki(public_key)?;
        if algo_oid == crate::asn1::OID_EC_PUBLIC_KEY {
            if curve_oid.as_deref() == Some(crate::asn1::OID_EC_P256) {
                if pk_bytes.len() != 65 || pk_bytes[0] != 0x04 {
                    return Err(RegistryError::InvalidSignature(
                        "Invalid P-256 public key point length or format".into(),
                    ));
                }
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
            } else if curve_oid.as_deref() == Some(crate::asn1::OID_EC_P384) {
                if pk_bytes.len() != 97 || pk_bytes[0] != 0x04 {
                    return Err(RegistryError::InvalidSignature(
                        "Invalid P-384 public key point length or format".into(),
                    ));
                }
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
            } else {
                return Err(RegistryError::InvalidSignature(format!(
                    "Unsupported elliptic curve OID: {curve_oid:?}"
                )));
            }
        } else if algo_oid == crate::asn1::OID_ED25519 {
            if pk_bytes.len() != 32 {
                return Err(RegistryError::InvalidSignature(
                    "Invalid Ed25519 public key length".into(),
                ));
            }
            if UnparsedPublicKey::new(&ED25519, &pk_bytes)
                .verify(message, signature)
                .is_ok()
            {
                return Ok(());
            }
        } else {
            return Err(RegistryError::InvalidSignature(format!(
                "Unsupported public key algorithm OID: {algo_oid}"
            )));
        }
        return Err(RegistryError::InvalidSignature(
            "Cryptographic signature verification failed".into(),
        ));
    }

    // 2. Direct raw key formats (uncompressed EC points or raw 32-byte Ed25519)
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
    } else if public_key.len() == 97 && public_key[0] == 0x04 {
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
    } else if public_key.len() == 32
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

/// Verifies a DSSE envelope against the given public key over DSSE PAE,
/// returning all signatures that cryptographically verify under that key.
pub fn verify_dsse_signatures<'a>(
    envelope: &'a DsseEnvelope,
    public_key: &[u8],
) -> Result<Vec<&'a DsseSignature>, RegistryError> {
    if envelope.signatures.is_empty() {
        return Err(RegistryError::InvalidSignature(
            "DSSE envelope has no signatures".into(),
        ));
    }
    let payload = envelope.decode_payload()?;
    let pae = dsse_pre_auth_encoding(&envelope.payload_type, &payload);

    let mut verified = Vec::new();
    for s in &envelope.signatures {
        if s.sig.trim().is_empty() {
            continue;
        }
        if let Ok(sig_bytes) = decode_base64(&s.sig) {
            if !sig_bytes.is_empty() && verify_signature(public_key, &pae, &sig_bytes).is_ok() {
                verified.push(s);
            }
        }
    }

    if verified.is_empty() {
        return Err(RegistryError::InvalidSignature(
            "None of the DSSE signatures matched the expected public key".into(),
        ));
    }
    Ok(verified)
}

/// Verifies that a DSSE envelope is authentically signed by the given public key over DSSE PAE,
/// returning a reference to the first verified signature.
pub fn verify_dsse_signature<'a>(
    envelope: &'a DsseEnvelope,
    public_key: &[u8],
) -> Result<&'a DsseSignature, RegistryError> {
    verify_dsse_signatures(envelope, public_key).map(|sigs| sigs[0])
}

/// Verifies that a DSSE envelope is authentically signed by the given public key over DSSE PAE.
pub fn verify_dsse_envelope(
    envelope: &DsseEnvelope,
    public_key: &[u8],
) -> Result<(), RegistryError> {
    verify_dsse_signature(envelope, public_key).map(|_| ())
}

/// Verifies a Rekor Signed Entry Timestamp (SET) over canonicalized JSON.
pub fn verify_rekor_set(rekor_pubkeys: &[Vec<u8>], entry: &TlogEntry) -> Result<(), RegistryError> {
    let Some(promise) = &entry.inclusion_promise else {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Missing inclusionPromise for Rekor SET verification".into(),
        ));
    };
    if promise.signed_entry_timestamp.trim().is_empty() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Empty signedEntryTimestamp in inclusionPromise".into(),
        ));
    }
    let sig_bytes = decode_base64(&promise.signed_entry_timestamp)?;

    let body = entry.canonicalized_body.as_deref().ok_or_else(|| {
        RegistryError::InvalidSigstoreBundle(
            "Missing canonicalizedBody for Rekor SET verification".into(),
        )
    })?;
    let body_b64 = if body.trim_start().starts_with('{') {
        BASE64.encode(body.as_bytes())
    } else {
        body.to_string()
    };

    let log_id_str = &entry.log_id.key_id;
    let log_id_hex = if log_id_str.len() == 64 && log_id_str.chars().all(|c| c.is_ascii_hexdigit())
    {
        log_id_str.to_ascii_lowercase()
    } else if let Ok(bytes) = decode_base64(log_id_str) {
        HEXLOWER.encode(&bytes)
    } else {
        log_id_str.to_ascii_lowercase()
    };

    // Canonical JSON format: keys sorted lexicographically
    let canonical_json = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        body_b64, entry.integrated_time, log_id_hex, entry.log_index
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
            "Rekor transparency log evidence missing or unauthenticated: Rekor signedEntryTimestamp verification failed against trusted Rekor public keys"
                .into(),
        ));
    }
    Ok(())
}

/// Verifies transparency-dev Signed Note checkpoint signature and extracts the authenticated root hash.
pub fn verify_checkpoint_signature(
    rekor_pubkeys: &[Vec<u8>],
    entry: &TlogEntry,
) -> Result<Option<Vec<u8>>, RegistryError> {
    let Some(proof_val) = &entry.inclusion_proof else {
        return Ok(None);
    };

    let checkpoint_str = if let Some(s) = proof_val.get("checkpoint").and_then(|v| v.as_str()) {
        s
    } else if let Some(env) = proof_val
        .get("checkpoint")
        .and_then(|v| v.get("envelope"))
        .and_then(|e| e.as_str())
    {
        env
    } else {
        return Ok(None);
    };

    let split_pos = checkpoint_str.find("\n\n").ok_or_else(|| {
        RegistryError::InvalidSigstoreBundle("Missing checkpoint separator in signed note".into())
    })?;

    let note = &checkpoint_str[..split_pos + 1];
    let sig_data = &checkpoint_str[split_pos + 2..];

    let note_lines: Vec<&str> = note.lines().collect();
    if note_lines.len() < 3 {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Too few lines in checkpoint note header".into(),
        ));
    }
    let root_hash = decode_base64(note_lines[2].trim())?;

    let mut verified = false;
    for line in sig_data.lines() {
        let trimmed = line.trim();
        let sig_part = if let Some(rest) = trimmed.strip_prefix("\u{2014}") {
            rest.trim()
        } else if let Some(rest) = trimmed.strip_prefix('—') {
            rest.trim()
        } else if let Some(rest) = trimmed.strip_prefix("--") {
            rest.trim()
        } else {
            continue;
        };

        let parts: Vec<&str> = sig_part.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let sig_b64 = parts[1];
        let Ok(sig_bytes) = decode_base64(sig_b64) else {
            continue;
        };
        if sig_bytes.len() < 5 {
            continue;
        }
        // First 4 bytes is key_hint, rest is signature
        let raw_sig = &sig_bytes[4..];

        for pk in rekor_pubkeys {
            if verify_signature(pk, note.as_bytes(), raw_sig).is_ok() {
                verified = true;
                break;
            }
        }
        if verified {
            break;
        }
    }

    if !verified {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Rekor checkpoint signature verification failed against trusted Rekor public keys"
                .into(),
        ));
    }

    Ok(Some(root_hash))
}

/// Verifies an RFC 6962 Merkle tree inclusion proof against the authenticated root hash.
pub fn verify_merkle_inclusion_proof(
    entry: &TlogEntry,
    authenticated_root: Option<&[u8]>,
) -> Result<(), RegistryError> {
    let Some(proof_val) = &entry.inclusion_proof else {
        return Ok(());
    };

    let log_index = proof_val
        .get("logIndex")
        .and_then(parse_u64_from_value)
        .unwrap_or(entry.log_index);
    let tree_size = proof_val
        .get("treeSize")
        .and_then(parse_u64_from_value)
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

    let expected_root = if let Some(auth_root) = authenticated_root {
        auth_root.to_vec()
    } else {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Inclusion proof root hash is unauthenticated: checkpoint missing or invalid".into(),
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

fn matches_rekor_signature(entry_sig: &str, expected_sig_b64: &str, expected_sig_bytes: &[u8]) -> bool {
    let trimmed = entry_sig.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed == expected_sig_b64 {
        return true;
    }
    if let Ok(dec) = decode_base64(trimmed) {
        if dec == expected_sig_bytes {
            return true;
        }
        if let Ok(double_str) = std::str::from_utf8(&dec) {
            let double_trimmed = double_str.trim();
            if double_trimmed == expected_sig_b64 {
                return true;
            }
            if let Ok(dec2) = decode_base64(double_trimmed) {
                if dec2 == expected_sig_bytes {
                    return true;
                }
            }
        }
    }
    false
}

fn matches_rekor_verifier(verifier_str: &str, leaf_cert_or_key: &[u8]) -> bool {
    let Ok(verifier_der) = decode_rekor_verifier(verifier_str) else {
        return false;
    };
    if verifier_der == leaf_cert_or_key {
        return true;
    }
    // If the expected verifier is a Fulcio X.509 leaf certificate, require an exact
    // certificate DER match so another certificate reusing the same keypair cannot pass.
    if parse_x509_certificate(leaf_cert_or_key).is_ok() {
        return false;
    }
    // Otherwise leaf_cert_or_key is a registry public key SPKI; also accept an X.509 cert
    // whose SPKI matches that key.
    if let Ok(v_cert) = parse_x509_certificate(&verifier_der) {
        if v_cert.spki_bytes == leaf_cert_or_key {
            return true;
        }
    }
    false
}

fn verify_rekor_body_binding_any(
    entry: &TlogEntry,
    envelope: &DsseEnvelope,
    verified_sigs: &[&DsseSignature],
    leaf_cert_or_key: &[u8],
) -> Result<(), RegistryError> {
    let mut last_err = None;
    for sig in verified_sigs {
        match verify_rekor_body_binding(entry, envelope, sig, leaf_cert_or_key) {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        RegistryError::InvalidSigstoreBundle("No verified DSSE signatures available for Rekor binding".into())
    }))
}

/// Binds a Rekor transparency log entry's canonicalizedBody to the DSSE envelope, verified signature, and leaf certificate/key.
pub fn verify_rekor_body_binding(
    entry: &TlogEntry,
    envelope: &DsseEnvelope,
    verified_sig: &DsseSignature,
    leaf_cert_or_key: &[u8],
) -> Result<(), RegistryError> {
    let body_str = entry.canonicalized_body.as_deref().ok_or_else(|| {
        RegistryError::InvalidSigstoreBundle("Missing canonicalizedBody in Rekor entry".into())
    })?;

    let body_bytes = decode_base64(body_str).unwrap_or_else(|_| body_str.as_bytes().to_vec());
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
        RegistryError::InvalidSigstoreBundle(format!("Invalid Rekor canonicalizedBody JSON: {e}"))
    })?;

    let kind = body_json
        .get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or_default()
        .trim();

    // Allow ONLY supported entry schemas (dsse, intoto, hashedrekord) and REJECT any unknown/unsupported kind
    if !matches!(kind, "dsse" | "intoto" | "hashedrekord") {
        return Err(RegistryError::InvalidSigstoreBundle(format!(
            "Unsupported Rekor entry kind: '{kind}' - only 'dsse', 'intoto', and 'hashedrekord' are supported"
        )));
    }

    let payload_bytes = decode_base64(&envelope.payload)?;
    let expected_payload_hash_hex = HEXLOWER.encode(&Sha256::digest(&payload_bytes));

    let expected_sig_b64 = verified_sig.sig.trim();
    if expected_sig_b64.is_empty() {
        return Err(RegistryError::InvalidSigstoreBundle("DSSE envelope signature is empty".into()));
    }
    let expected_sig_bytes = decode_base64(expected_sig_b64)?;

    match kind {
        "dsse" => {
            let spec = body_json.get("spec").ok_or_else(|| {
                RegistryError::InvalidSigstoreBundle("Missing spec in Rekor dsse entry".into())
            })?;

            // 1. Verify payload hash is present, non-empty, and matches
            let payload_hash = spec
                .get("payloadHash")
                .and_then(|ph| ph.get("value").or_else(|| ph.get("digest")))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    RegistryError::InvalidSigstoreBundle(
                        "Missing or empty payloadHash in Rekor dsse entry".into(),
                    )
                })?;

            let norm_ph = payload_hash;
            let matches = if norm_ph.len() == 64 {
                norm_ph.eq_ignore_ascii_case(&expected_payload_hash_hex)
            } else if let Ok(dec) = decode_base64(norm_ph) {
                HEXLOWER.encode(&dec).eq_ignore_ascii_case(&expected_payload_hash_hex)
            } else {
                false
            };
            if !matches {
                return Err(RegistryError::InvalidSigstoreBundle(format!(
                    "Rekor dsse payloadHash mismatch: expected {expected_payload_hash_hex}, got {payload_hash}"
                )));
            }

            // 2. Verify signature and verifier match BOTH verified signature and leaf certificate/key
            let sigs = spec
                .get("signatures")
                .and_then(|s| s.as_array())
                .filter(|arr| !arr.is_empty())
                .ok_or_else(|| {
                    RegistryError::InvalidSigstoreBundle(
                        "Missing or empty signatures in Rekor dsse entry".into(),
                    )
                })?;

            let default_verifier = spec
                .get("verifiers")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str());

            let mut sig_matched = false;
            let mut matched = false;
            let mut has_empty_verifier = false;
            for sig_entry in sigs {
                let entry_sig = sig_entry
                    .get("signature")
                    .or_else(|| sig_entry.get("content"))
                    .and_then(|s| s.as_str())
                    .unwrap_or_default();

                if !matches_rekor_signature(entry_sig, expected_sig_b64, &expected_sig_bytes) {
                    continue;
                }
                sig_matched = true;

                let verifier = sig_entry
                    .get("verifier")
                    .and_then(|v| v.as_str())
                    .or(default_verifier)
                    .map(str::trim)
                    .unwrap_or_default();

                if verifier.is_empty() {
                    has_empty_verifier = true;
                    continue;
                }

                if matches_rekor_verifier(verifier, leaf_cert_or_key) {
                    matched = true;
                    break;
                }
            }

            if !matched {
                if has_empty_verifier && !sig_matched {
                    return Err(RegistryError::InvalidSigstoreBundle(
                        "Rekor dsse signature mismatch with DSSE envelope".into(),
                    ));
                } else if has_empty_verifier {
                    return Err(RegistryError::InvalidSigstoreBundle(
                        "Missing or empty verifier in Rekor dsse entry".into(),
                    ));
                } else if sig_matched {
                    return Err(RegistryError::InvalidSigstoreBundle(
                        "Rekor dsse verifier mismatch with leaf certificate or public key".into(),
                    ));
                } else {
                    return Err(RegistryError::InvalidSigstoreBundle(
                        "Rekor dsse signature mismatch with DSSE envelope".into(),
                    ));
                }
            }
        }
        "intoto" => {
            let spec = body_json.get("spec").ok_or_else(|| {
                RegistryError::InvalidSigstoreBundle("Missing spec in Rekor intoto entry".into())
            })?;
            let content = spec.get("content").unwrap_or(spec);

            // 1. Verify payloadHash is present, non-empty, and matches
            let payload_hash = content
                .get("payloadHash")
                .and_then(|p| p.get("value").or_else(|| p.get("digest")))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    RegistryError::InvalidSigstoreBundle(
                        "Missing or empty payloadHash in Rekor intoto entry".into(),
                    )
                })?;

            let norm_ph = payload_hash;
            let matches = if norm_ph.len() == 64 {
                norm_ph.eq_ignore_ascii_case(&expected_payload_hash_hex)
            } else if let Ok(dec) = decode_base64(norm_ph) {
                HEXLOWER.encode(&dec).eq_ignore_ascii_case(&expected_payload_hash_hex)
            } else {
                false
            };
            if !matches {
                return Err(RegistryError::InvalidSigstoreBundle(format!(
                    "Rekor intoto payloadHash mismatch: expected {expected_payload_hash_hex}, got {payload_hash}"
                )));
            }

            // 2. Verify signature in envelope matches BOTH verified signature and leaf certificate/key
            let env_val = content.get("envelope").ok_or_else(|| {
                RegistryError::InvalidSigstoreBundle(
                    "Missing envelope in Rekor intoto entry".into(),
                )
            })?;
            let sigs = env_val
                .get("signatures")
                .and_then(|s| s.as_array())
                .filter(|arr| !arr.is_empty())
                .ok_or_else(|| {
                    RegistryError::InvalidSigstoreBundle(
                        "Missing or empty signatures in Rekor intoto entry".into(),
                    )
                })?;

            let default_verifier = spec
                .get("verifiers")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str());

            let mut sig_matched = false;
            let mut matched = false;
            let mut has_empty_verifier = false;
            for sig_entry in sigs {
                let entry_sig = sig_entry
                    .get("sig")
                    .or_else(|| sig_entry.get("signature"))
                    .and_then(|s| s.as_str())
                    .unwrap_or_default();

                if !matches_rekor_signature(entry_sig, expected_sig_b64, &expected_sig_bytes) {
                    continue;
                }
                sig_matched = true;

                let verifier = sig_entry
                    .get("publicKey")
                    .or_else(|| sig_entry.get("verifier"))
                    .and_then(|v| v.as_str())
                    .or(default_verifier)
                    .map(str::trim)
                    .unwrap_or_default();

                if verifier.is_empty() {
                    has_empty_verifier = true;
                    continue;
                }

                if matches_rekor_verifier(verifier, leaf_cert_or_key) {
                    matched = true;
                    break;
                }
            }

            if !matched {
                if has_empty_verifier && !sig_matched {
                    return Err(RegistryError::InvalidSigstoreBundle(
                        "Rekor intoto signature mismatch with DSSE envelope".into(),
                    ));
                } else if has_empty_verifier {
                    return Err(RegistryError::InvalidSigstoreBundle(
                        "Missing or empty verifier/publicKey in Rekor intoto entry".into(),
                    ));
                } else if sig_matched {
                    return Err(RegistryError::InvalidSigstoreBundle(
                        "Rekor intoto verifier mismatch with leaf certificate or public key".into(),
                    ));
                } else {
                    return Err(RegistryError::InvalidSigstoreBundle(
                        "Rekor intoto signature mismatch with DSSE envelope".into(),
                    ));
                }
            }
        }
        "hashedrekord" => {
            let spec = body_json.get("spec").ok_or_else(|| {
                RegistryError::InvalidSigstoreBundle(
                    "Missing spec in Rekor hashedrekord entry".into(),
                )
            })?;

            // 1. Verify data.hash is present, non-empty, and matches
            let hash_val = spec
                .get("data")
                .and_then(|d| d.get("hash"))
                .and_then(|h| h.get("value").or_else(|| h.get("digest")))
                .or_else(|| spec.get("digest"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    RegistryError::InvalidSigstoreBundle(
                        "Missing or empty data.hash in Rekor hashedrekord entry".into(),
                    )
                })?;

            let pae_bytes = dsse_pre_auth_encoding(&envelope.payload_type, &payload_bytes);
            let pae_hash_hex = HEXLOWER.encode(&Sha256::digest(&pae_bytes));

            let hash_matches = if hash_val.len() == 64 {
                hash_val.eq_ignore_ascii_case(&expected_payload_hash_hex)
                    || hash_val.eq_ignore_ascii_case(&pae_hash_hex)
            } else if let Ok(dec) = decode_base64(hash_val) {
                let dec_hex = HEXLOWER.encode(&dec);
                dec_hex.eq_ignore_ascii_case(&expected_payload_hash_hex)
                    || dec_hex.eq_ignore_ascii_case(&pae_hash_hex)
            } else {
                false
            };
            if !hash_matches {
                return Err(RegistryError::InvalidSigstoreBundle(format!(
                    "Rekor hashedrekord data.hash mismatch: expected {expected_payload_hash_hex}, got {hash_val}"
                )));
            }

            // 2. Verify signature is present, non-empty, and matches verified DSSE signature
            let sig_obj = spec.get("signature").ok_or_else(|| {
                RegistryError::InvalidSigstoreBundle(
                    "Missing signature in Rekor hashedrekord entry".into(),
                )
            })?;
            let entry_sig = sig_obj
                .get("content")
                .and_then(|c| c.as_str())
                .unwrap_or_default();

            if !matches_rekor_signature(entry_sig, expected_sig_b64, &expected_sig_bytes) {
                return Err(RegistryError::InvalidSigstoreBundle(
                    "Rekor hashedrekord signature mismatch with DSSE envelope".into(),
                ));
            }

            // 3. Verify verifier / publicKey matches leaf certificate or registry key
            let verifier = sig_obj
                .get("publicKey")
                .and_then(|pk| pk.get("content"))
                .and_then(|c| c.as_str())
                .map(str::trim)
                .unwrap_or_default();

            if verifier.is_empty() {
                return Err(RegistryError::InvalidSigstoreBundle(
                    "Missing or empty signature.publicKey.content in Rekor hashedrekord entry".into(),
                ));
            }

            if !matches_rekor_verifier(verifier, leaf_cert_or_key) {
                return Err(RegistryError::InvalidSigstoreBundle(
                    "Rekor hashedrekord verifier mismatch with leaf certificate or public key".into(),
                ));
            }
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// Cryptographically validates an X.509 certificate chain up to a trusted Fulcio root certificate.
pub fn verify_fulcio_certificate_chain(
    chain_certs_raw: &[&str],
    trusted_roots: &[Vec<u8>],
    integrated_time: i64,
) -> Result<ParsedCertificate, RegistryError> {
    if chain_certs_raw.is_empty() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Empty certificate chain in verification material".into(),
        ));
    }

    let mut parsed_chain = Vec::with_capacity(chain_certs_raw.len());
    for raw in chain_certs_raw {
        let der = decode_base64(raw)?;
        let parsed = parse_x509_certificate(&der)?;
        parsed_chain.push(parsed);
    }

    let leaf = &parsed_chain[0];

    // Check validity window of all certificates in the chain against Rekor integratedTime
    if integrated_time > 0 {
        for (idx, cert) in parsed_chain.iter().enumerate() {
            if integrated_time < cert.not_before || integrated_time > cert.not_after {
                let role = if idx == 0 { "Leaf" } else { "Intermediate" };
                return Err(RegistryError::InvalidSigstoreBundle(format!(
                    "{role} certificate not valid at integratedTime {}: validity window [{}, {}]",
                    integrated_time, cert.not_before, cert.not_after
                )));
            }
        }
    }

    // Check if leaf cert is self-signed:
    let is_leaf_self_signed = leaf.issuer_raw == leaf.subject_raw;

    // Parse all trusted roots
    let mut parsed_roots = Vec::new();
    for root_der in trusted_roots {
        if let Ok(parsed) = parse_x509_certificate(root_der) {
            parsed_roots.push(parsed);
        }
    }

    if is_leaf_self_signed {
        let matches_trusted = parsed_roots.iter().any(|r| r.raw_der == leaf.raw_der);
        if !matches_trusted {
            return Err(RegistryError::InvalidSigstoreBundle(
                "Self-signed leaf certificate is not in trusted Fulcio root authorities".into(),
            ));
        }
        return Ok(leaf.clone());
    }

    // Verify chain from leaf upwards
    let mut current = leaf;
    for parent in &parsed_chain[1..] {
        if current.issuer_raw != parent.subject_raw {
            return Err(RegistryError::InvalidSigstoreBundle(
                "Certificate chain issuer/subject mismatch".into(),
            ));
        }
        if verify_signature(&parent.spki_bytes, &current.tbs_bytes, &current.signature_value).is_err() {
            return Err(RegistryError::InvalidSigstoreBundle(
                "Certificate cryptographic signature verification failed along the chain".into(),
            ));
        }
        current = parent;
    }

    // The topmost certificate in chain (or leaf if chain length is 1) must be signed by or match a trusted root
    let mut trusted = false;
    for root in &parsed_roots {
        if current.raw_der == root.raw_der {
            trusted = true;
            break;
        }
        if current.issuer_raw == root.subject_raw
            && verify_signature(&root.spki_bytes, &current.tbs_bytes, &current.signature_value).is_ok()
        {
            trusted = true;
            break;
        }
    }

    if !trusted {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Certificate chain does not terminate in a trusted Fulcio root CA".into(),
        ));
    }

    Ok(leaf.clone())
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
    #[serde(rename = "publicKey", default)]
    pub public_key: Option<PublicKeyHint>,
    #[serde(rename = "tlogEntries", default)]
    pub tlog_entries: Vec<TlogEntry>,
    #[serde(rename = "timestampVerificationData", default)]
    pub timestamp_verification_data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PublicKeyHint {
    #[serde(default)]
    pub hint: Option<String>,
    #[serde(rename = "rawBytes", default)]
    pub raw_bytes: Option<String>,
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
    #[serde(rename = "logIndex", deserialize_with = "deserialize_u64_or_string")]
    pub log_index: u64,
    #[serde(rename = "logId")]
    pub log_id: LogId,
    #[serde(rename = "integratedTime", deserialize_with = "deserialize_i64_or_string")]
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
        let trimmed = json_str.trim();
        if trimmed.is_empty() {
            return Err(RegistryError::InvalidSigstoreBundle(
                "Empty JSON string".into(),
            ));
        }

        if let Ok(bundle) = serde_json::from_str::<SigstoreBundle>(trimmed) {
            if bundle.dsse_envelope.is_some() {
                return Ok(bundle);
            }
        }

        if let Ok(response) = serde_json::from_str::<AttestationResponse>(trimmed) {
            for item in response.attestations {
                if let Some(bundle) = item.bundle {
                    if bundle.dsse_envelope.is_some() {
                        return Ok(bundle);
                    }
                }
            }
        }

        if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
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

    /// Extracts all valid Sigstore bundles from JSON payload (supporting direct bundle or array of attestations).
    pub fn from_json_all(json_str: &str) -> Result<Vec<Self>, RegistryError> {
        let trimmed = json_str.trim();
        if trimmed.is_empty() {
            return Err(RegistryError::InvalidSigstoreBundle(
                "Empty JSON string".into(),
            ));
        }
        let mut bundles = Vec::new();
        if let Ok(response) = serde_json::from_str::<AttestationResponse>(trimmed) {
            for item in response.attestations {
                if let Some(bundle) = item.bundle {
                    if bundle.dsse_envelope.is_some() {
                        bundles.push(bundle);
                    }
                }
            }
        }
        if bundles.is_empty() {
            if let Ok(bundle) = Self::from_json(trimmed) {
                bundles.push(bundle);
            }
        }
        if bundles.is_empty() {
            return Err(RegistryError::InvalidSigstoreBundle(
                "No valid Sigstore bundles found in JSON payload".into(),
            ));
        }
        Ok(bundles)
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
    fulcio_root_certs: Vec<Vec<u8>>,
    rekor_public_keys: Vec<Vec<u8>>,
    registry_keys: HashMap<String, Vec<u8>>,
    registry_key_expiries: HashMap<String, (String, i64)>,
}

impl ProvenanceVerifier {
    pub fn new(policy: ProvenancePolicy) -> Self {
        let mut fulcio_root_certs = Vec::new();
        if let Ok(c) = decode_base64(FULCIO_ROOT_CA_1_DER_B64) {
            fulcio_root_certs.push(c);
        }
        if let Ok(c) = decode_base64(FULCIO_ROOT_CA_2_DER_B64) {
            fulcio_root_certs.push(c);
        }
        if let Ok(c) = decode_base64(FULCIO_INTERMEDIATE_CA_2_DER_B64) {
            fulcio_root_certs.push(c);
        }

        let mut rekor_public_keys = Vec::new();
        if let Ok(k) = decode_base64(REKOR_DEFAULT_PUBKEY_SPKI_B64) {
            rekor_public_keys.push(k);
        }
        if let Ok(k) = decode_base64(REKOR_2025_PUBKEY_SPKI_B64) {
            rekor_public_keys.push(k);
        }

        let mut verifier = Self {
            policy,
            fulcio_root_certs,
            rekor_public_keys,
            registry_keys: HashMap::new(),
            registry_key_expiries: HashMap::new(),
        };

        if cfg!(test) || std::env::var_os("RNPM_TEST_MOCK_ROOTS").is_some() {
            verifier = verifier.with_test_mock_roots();
        }

        verifier
    }

    pub fn without_default_roots(mut self) -> Self {
        self.fulcio_root_certs.clear();
        self.rekor_public_keys.clear();
        self
    }

    pub fn with_test_mock_roots(mut self) -> Self {
        self.fulcio_root_certs.push(test_mock_fulcio_root_cert());
        self.rekor_public_keys.push(test_mock_rekor_pubkey());
        self
    }

    pub fn with_fulcio_root_cert(mut self, cert: Vec<u8>) -> Self {
        self.fulcio_root_certs.push(cert);
        self
    }

    pub fn with_rekor_public_key(mut self, key: Vec<u8>) -> Self {
        self.rekor_public_keys.push(key);
        self
    }

    pub fn with_registry_keys(mut self, keys: HashMap<String, Vec<u8>>) -> Self {
        self.registry_keys = keys;
        self
    }

    pub fn with_registry_key_expiries(
        mut self,
        expiries: HashMap<String, (String, i64)>,
    ) -> Self {
        self.registry_key_expiries = expiries;
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
                let verified = self.verify_package(&version.name, Some(&version.version), bundle, integrity, tarball_bytes)?;
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
        self.verify_package(package_name, None, bundle, tarball_integrity, tarball_bytes)
    }

fn current_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

    /// Verifies that a Sigstore bundle is authentic, matches exact package name and version,
    /// matches tarball digests, and conforms to the configured `ProvenancePolicy`.
    pub fn verify_package(
        &self,
        package_name: &str,
        package_version: Option<&str>,
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

        // 3. Extract certificates or registry key
        let mut raw_cert_chain = Vec::new();
        if let Some(chain) = &vm.x509_certificate_chain {
            for c in &chain.certificates {
                if !c.raw_bytes.trim().is_empty() {
                    raw_cert_chain.push(c.raw_bytes.as_str());
                }
            }
        } else if let Some(cert) = &vm.certificate {
            if !cert.raw_bytes.trim().is_empty() {
                raw_cert_chain.push(cert.raw_bytes.as_str());
            }
        }

        let mut parsed_leaf_cert: Option<ParsedCertificate> = None;
        let mut primary_tlog: Option<&TlogEntry> = None;
        let mut resolved_keyid: Option<String> = None;
        let cert_count = raw_cert_chain.len();

        let (signing_key, verified_sigs) = if !raw_cert_chain.is_empty() {
            // Fulcio-backed bundle
            if vm.tlog_entries.is_empty() {
                return Err(RegistryError::InvalidSigstoreBundle(
                    "Missing Rekor tlogEntries in Fulcio verification material".into(),
                ));
            }
            let tlog = &vm.tlog_entries[0];
            if tlog.log_id.key_id.trim().is_empty() {
                return Err(RegistryError::InvalidSigstoreBundle(
                    "Rekor entry logId.keyId is empty".into(),
                ));
            }
            if tlog.integrated_time <= 0 {
                return Err(RegistryError::InvalidSigstoreBundle(format!(
                    "Invalid Rekor entry integratedTime: {}",
                    tlog.integrated_time
                )));
            }

            let leaf = verify_fulcio_certificate_chain(
                &raw_cert_chain,
                &self.fulcio_root_certs,
                tlog.integrated_time,
            )?;
            let spki = leaf.spki_bytes.clone();
            parsed_leaf_cert = Some(leaf);

            // Fulcio certificates are short-lived. A Rekor checkpoint authenticates
            // ONLY the log root and carries NO entry timestamp. Therefore, Fulcio certificate validity
            // checking strictly requires an authenticated signing time (a cryptographically verified
            // Rekor SET covering integratedTime). Reject checkpoint-only bundles that have no authenticated timestamp!
            if tlog.inclusion_promise.is_none() {
                return Err(RegistryError::InvalidSigstoreBundle(
                    "Rekor transparency log evidence missing or unauthenticated: Fulcio certificate validity requires an authenticated signing time (verified Rekor SET), but bundle has no inclusionPromise (checkpoint-only bundles without an authenticated timestamp are rejected)".into(),
                ));
            }
            verify_rekor_set(&self.rekor_public_keys, tlog)?;

            primary_tlog = Some(tlog);
            let v_sigs = verify_dsse_signatures(envelope, &spki)?;
            (spki, v_sigs)
        } else {
            // Keyed publish attestation
            let explicit_hint = vm
                .public_key
                .as_ref()
                .and_then(|pk| pk.hint.as_deref())
                .map(str::trim)
                .filter(|h| !h.is_empty());

            let mut candidate_keys: Vec<(String, Vec<u8>)> = Vec::new();

            if let Some(hint) = explicit_hint {
                if let Some(key) = self.registry_keys.get(hint) {
                    candidate_keys.push((hint.to_string(), key.clone()));
                } else {
                    return Err(RegistryError::InvalidSignature(format!(
                        "No corresponding public key found for attestation keyid '{hint}'"
                    )));
                }
            } else {
                for s in &envelope.signatures {
                    if let Some(ref kid) = s.keyid {
                        let kid_trimmed = kid.trim();
                        if !kid_trimmed.is_empty() {
                            if let Some(key) = self.registry_keys.get(kid_trimmed) {
                                if !candidate_keys.iter().any(|(k, _)| k == kid_trimmed) {
                                    candidate_keys.push((kid_trimmed.to_string(), key.clone()));
                                }
                            }
                        }
                    }
                }
                if candidate_keys.is_empty() {
                    for (kid, key) in &self.registry_keys {
                        candidate_keys.push((kid.clone(), key.clone()));
                    }
                }
            }

            if candidate_keys.is_empty() {
                return Err(RegistryError::InvalidSigstoreBundle(
                    "Missing certificate chain in verification material and no keyid hint for registry key matching".into(),
                ));
            }

            let mut match_found = None;
            for (kid, key_bytes) in candidate_keys {
                if let Ok(v_sigs) = verify_dsse_signatures(envelope, &key_bytes) {
                    match_found = Some((kid, key_bytes, v_sigs));
                    break;
                }
            }

            let (kid, signing_key_bytes, v_sigs) = match_found.ok_or_else(|| {
                RegistryError::InvalidSignature(
                    "None of the DSSE signatures matched the expected public key".into(),
                )
            })?;

            resolved_keyid = Some(kid);
            (signing_key_bytes, v_sigs)
        };

        // Enforce key expiry for keyed attestation using the exact resolved keyid
        if let Some(ref keyid) = resolved_keyid {
            if let Some((expires_str, expires_ms)) = self.registry_key_expiries.get(keyid.as_str()) {
                let signing_time_ms = if let Some(tlog) = vm.tlog_entries.first() {
                    let now_ms = Self::current_time_ms();
                    // A timestamp in the future (> now + 5m clock skew) is forged/invalid
                    let not_future = tlog.integrated_time > 0
                        && (tlog.integrated_time * 1000) <= (now_ms + 300_000);

                    // Checkpoint-only bundles do not carry an authenticated timestamp; require a verified SET!
                    let valid_set = not_future
                        && tlog.inclusion_promise.is_some()
                        && verify_rekor_set(&self.rekor_public_keys, tlog).is_ok();
                    let valid_binding = verify_rekor_body_binding_any(
                        tlog,
                        envelope,
                        &verified_sigs,
                        &signing_key,
                    )
                    .is_ok();

                    if valid_set && valid_binding {
                        tlog.integrated_time * 1000
                    } else {
                        now_ms
                    }
                } else {
                    Self::current_time_ms()
                };

                if *expires_ms <= 0 || signing_time_ms >= *expires_ms {
                    return Err(RegistryError::InvalidSignature(format!(
                        "Registry public key for keyid '{keyid}' has expired {expires_str}"
                    )));
                }
            }
        }

        // 5. For Fulcio-backed bundles: require authenticated Rekor evidence and bind Rekor body
        let mut tlog_metadata = TransparencyLogMetadata {
            log_index: 0,
            log_id: String::new(),
            integrated_time: 0,
        };

        if let Some(tlog) = primary_tlog {
            tlog_metadata = TransparencyLogMetadata {
                log_index: tlog.log_index,
                log_id: tlog.log_id.key_id.clone(),
                integrated_time: tlog.integrated_time,
            };

            // SET was already cryptographically verified above.
            // If inclusion proof is present, verify checkpoint & Merkle inclusion proof:
            if tlog.inclusion_proof.is_some() {
                if let Ok(Some(auth_root)) = verify_checkpoint_signature(&self.rekor_public_keys, tlog) {
                    verify_merkle_inclusion_proof(tlog, Some(&auth_root))?;
                } else {
                    return Err(RegistryError::InvalidSigstoreBundle(
                        "Inclusion proof present but checkpoint signature failed verification against trusted Rekor keys".into(),
                    ));
                }
            }

            // Bind Rekor body to DSSE envelope & leaf certificate (matching any verified signature paired with leaf cert)
            if let Some(leaf_cert) = parsed_leaf_cert.as_ref() {
                verify_rekor_body_binding_any(tlog, envelope, &verified_sigs, &leaf_cert.raw_der)?;
            } else {
                return Err(RegistryError::InvalidSigstoreBundle(
                    "Missing parsed leaf certificate for Fulcio verification".into(),
                ));
            }
        } else if let Some(tlog) = vm.tlog_entries.first() {
            let valid_set = tlog.integrated_time > 0
                && tlog.inclusion_promise.is_some()
                && verify_rekor_set(&self.rekor_public_keys, tlog).is_ok();
            let valid_binding =
                verify_rekor_body_binding_any(tlog, envelope, &verified_sigs, &signing_key).is_ok();
            if valid_set && valid_binding {
                tlog_metadata = TransparencyLogMetadata {
                    log_index: tlog.log_index,
                    log_id: tlog.log_id.key_id.clone(),
                    integrated_time: tlog.integrated_time,
                };
            }
        }

        // 6. Parse and validate in-toto statement
        let statement = envelope.parse_statement()?;
        if statement.subject.is_empty() {
            return Err(RegistryError::ProvenanceVerificationFailed(
                "in-toto Statement has no subjects".into(),
            ));
        }

        // 7. Match subject with expected package name & version strictly
        let matched_subject = Self::find_matching_subject(&statement.subject, package_name, package_version)?;

        // 8. Verify tarball integrity digest against subject.digest
        Self::verify_subject_digest(matched_subject, tarball_integrity, tarball_bytes)?;

        // 9. Extract build provenance details
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

        // 10. Enforce repository policy if required
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
        package_version: Option<&str>,
    ) -> Result<&'a InTotoSubject, RegistryError> {
        let is_scoped = package_name.starts_with('@');
        let stripped_scope = package_name.strip_prefix('@');

        for subj in subjects {
            let s = subj.name.trim();

            // Strict versioned PURL matching: must start with "pkg:npm/"
            let Some(purl_rest) = s.strip_prefix("pkg:npm/") else {
                continue;
            };

            // Require an exact versioned PURL with '@<version>'
            let Some((name_part, version_part)) = purl_rest.rsplit_once('@') else {
                // NEVER accept a subject missing '@<version>'!
                continue;
            };

            if name_part.is_empty() || version_part.trim().is_empty() {
                continue;
            }

            // Name part and version part must not contain qualifiers '?' or fragments '#'
            if name_part.contains('?') || name_part.contains('#') {
                continue;
            }

            // Version part must not contain subpaths '/', qualifiers '?', or fragments '#'
            if version_part.contains('/') || version_part.contains('?') || version_part.contains('#') {
                continue;
            }

            // Path segment count validation:
            // Unscoped packages MUST have 0 slashes in name_part: e.g. "pkg"
            // Scoped packages MUST have at most 1 slash: e.g. "@scope/pkg" or "%40scope/pkg" (or "%40scope%2fpkg")
            let slash_count = name_part.matches('/').count();
            if is_scoped {
                if slash_count > 1 {
                    continue;
                }
            } else if slash_count != 0 {
                continue;
            }

            if let Some(expected_ver) = package_version {
                if version_part != expected_ver {
                    continue;
                }
            }

            // Verify name part matches package_name strictly:
            // For scoped package `@scope/pkg`:
            // npm encodes as `%40scope/pkg` or allows `@scope/pkg` or `%40scope%2Fpkg`.
            // NEVER match unscoped `pkg` against `@scope/pkg`!
            // For unscoped package `pkg`:
            // name_part MUST be `pkg`. NEVER match `@scope/pkg` or `%40scope/pkg`!
            let name_matches = if let Some(stripped) = stripped_scope {
                let encoded_at = format!("%40{}", stripped);
                let encoded_full = format!("%40{}", stripped.replace('/', "%2F"));
                let encoded_full_lower = format!("%40{}", stripped.replace('/', "%2f"));
                name_part == encoded_at
                    || name_part == package_name
                    || name_part == encoded_full
                    || name_part == encoded_full_lower
            } else {
                name_part == package_name
            };

            if name_matches {
                return Ok(subj);
            }
        }

        let found_names = subjects
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let expected_desc = if let Some(ver) = package_version {
            format!("{package_name}@{ver}")
        } else {
            package_name.to_string()
        };
        Err(RegistryError::ProvenanceVerificationFailed(format!(
            "Attestation subject name mismatch: expected '{expected_desc}', found [{found_names}]"
        )))
    }

    fn verify_subject_digest(
        subject: &InTotoSubject,
        tarball_integrity: Option<&str>,
        tarball_bytes: Option<&[u8]>,
    ) -> Result<(), RegistryError> {
        let subject_sha512 = subject.digest.get("sha512").map(|s| s.trim()).filter(|s| !s.is_empty());
        let subject_sha256 = subject.digest.get("sha256").map(|s| s.trim()).filter(|s| !s.is_empty());

        if subject_sha512.is_none() && subject_sha256.is_none() {
            return Err(RegistryError::ProvenanceVerificationFailed(
                "Subject digest map does not contain sha512 or sha256 algorithm".into(),
            ));
        }

        if let Some(bytes) = tarball_bytes {
            let mut checked = false;
            if let Some(expected_512) = subject_sha512 {
                let actual_hex = HEXLOWER.encode(&Sha512::digest(bytes));
                if !Self::digest_matches(expected_512, &actual_hex) {
                    return Err(RegistryError::AttestationDigestMismatch {
                        algorithm: "sha512".into(),
                        expected: expected_512.to_string(),
                        actual: actual_hex,
                    });
                }
                checked = true;
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
                checked = true;
            }

            if checked {
                return Ok(());
            }
        }

        if let Some(integrity_str) = tarball_integrity {
            let trimmed = integrity_str.trim();

            for token in trimmed.split_whitespace() {
                if let Some((algo, b64)) = token.split_once('-') {
                    let algo_lower = algo.to_ascii_lowercase();
                    let Ok(decoded) = decode_base64(b64) else {
                        continue;
                    };
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
        if exp.is_empty() {
            return false;
        }
        if exp.eq_ignore_ascii_case(actual_hex) {
            return true;
        }
        if let Ok(bytes) = decode_base64(exp) {
            if bytes.is_empty() {
                return false;
            }
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

/// Constructs a GitLab CI provenance statement matching npm's `libnpmpublish`.
pub fn build_gitlab_provenance_statement(
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

    let project_url = std::env::var("CI_PROJECT_URL")
        .unwrap_or_else(|_| format!("{}/{}", ci.server_url.trim_end_matches('/'), ci.repository));
    let runner_id = std::env::var("CI_RUNNER_ID").unwrap_or_default();
    let runner_desc = std::env::var("CI_RUNNER_DESCRIPTION")
        .unwrap_or_else(|_| "gitlab-runner".to_string());
    let runner_arch = std::env::var("CI_RUNNER_EXECUTABLE_ARCH").unwrap_or_default();
    let job_id = std::env::var("CI_JOB_ID").unwrap_or_default();
    let pipeline_id = std::env::var("CI_PIPELINE_ID").unwrap_or_default();
    let config_path = std::env::var("CI_CONFIG_PATH").unwrap_or_default();
    let job_url = std::env::var("CI_JOB_URL").unwrap_or_default();
    let job_name = std::env::var("CI_JOB_NAME").unwrap_or_default();

    let mut gitlab_params = serde_json::Map::new();
    let gitlab_env_vars = [
        "CI", "CI_API_GRAPHQL_URL", "CI_API_V4_URL", "CI_BUILD_BEFORE_SHA", "CI_BUILD_ID",
        "CI_BUILD_NAME", "CI_BUILD_REF", "CI_BUILD_REF_NAME", "CI_BUILD_REF_SLUG",
        "CI_BUILD_STAGE", "CI_COMMIT_BEFORE_SHA", "CI_COMMIT_BRANCH", "CI_COMMIT_REF_NAME",
        "CI_COMMIT_REF_PROTECTED", "CI_COMMIT_REF_SLUG", "CI_COMMIT_SHA", "CI_COMMIT_SHORT_SHA",
        "CI_COMMIT_TIMESTAMP", "CI_COMMIT_TITLE", "CI_CONFIG_PATH", "CI_DEFAULT_BRANCH",
        "CI_DEPENDENCY_PROXY_DIRECT_GROUP_IMAGE_PREFIX", "CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX",
        "CI_DEPENDENCY_PROXY_SERVER", "CI_DEPENDENCY_PROXY_USER", "CI_JOB_ID", "CI_JOB_NAME",
        "CI_JOB_NAME_SLUG", "CI_JOB_STAGE", "CI_JOB_STARTED_AT", "CI_JOB_URL", "CI_NODE_TOTAL",
        "CI_PAGES_DOMAIN", "CI_PAGES_URL", "CI_PIPELINE_CREATED_AT", "CI_PIPELINE_ID",
        "CI_PIPELINE_IID", "CI_PIPELINE_SOURCE", "CI_PIPELINE_URL",
        "CI_PROJECT_CLASSIFICATION_LABEL", "CI_PROJECT_DESCRIPTION", "CI_PROJECT_ID",
        "CI_PROJECT_NAME", "CI_PROJECT_NAMESPACE", "CI_PROJECT_NAMESPACE_ID", "CI_PROJECT_PATH",
        "CI_PROJECT_PATH_SLUG", "CI_PROJECT_REPOSITORY_LANGUAGES", "CI_PROJECT_ROOT_NAMESPACE",
        "CI_PROJECT_TITLE", "CI_PROJECT_URL", "CI_PROJECT_VISIBILITY", "CI_REGISTRY",
        "CI_REGISTRY_IMAGE", "CI_REGISTRY_USER", "CI_RUNNER_DESCRIPTION", "CI_RUNNER_ID",
        "CI_RUNNER_TAGS", "CI_SERVER_HOST", "CI_SERVER_NAME", "CI_SERVER_PORT",
        "CI_SERVER_PROTOCOL", "CI_SERVER_REVISION", "CI_SERVER_SHELL_SSH_HOST",
        "CI_SERVER_SHELL_SSH_PORT", "CI_SERVER_URL", "CI_SERVER_VERSION",
        "CI_SERVER_VERSION_MAJOR", "CI_SERVER_VERSION_MINOR", "CI_SERVER_VERSION_PATCH",
        "CI_TEMPLATE_REGISTRY_HOST", "GITLAB_CI", "GITLAB_FEATURES", "GITLAB_USER_ID",
        "GITLAB_USER_LOGIN", "RUNNER_GENERATE_ARTIFACTS_METADATA",
    ];
    for var_name in gitlab_env_vars {
        if let Ok(val) = std::env::var(var_name) {
            gitlab_params.insert(var_name.to_string(), serde_json::Value::String(val));
        }
    }

    let environment = serde_json::json!({
        "name": runner_desc,
        "architecture": runner_arch,
        "server": ci.server_url,
        "project": ci.repository,
        "job": { "id": job_id },
        "pipeline": {
            "id": pipeline_id,
            "ref": config_path,
        }
    });

    let mut git_digest = HashMap::new();
    git_digest.insert("sha1".to_string(), ci.commit_sha.clone());

    let invocation = SlsaInvocation {
        config_source: Some(SlsaConfigSource {
            uri: Some(format!("git+{project_url}")),
            digest: git_digest.clone(),
            entry_point: if job_name.is_empty() { None } else { Some(job_name) },
        }),
        parameters: Some(serde_json::Value::Object(gitlab_params)),
        environment: Some(environment),
    };

    let materials = vec![SlsaMaterial {
        uri: Some(format!("git+{project_url}")),
        digest: git_digest,
    }];

    InTotoStatement {
        statement_type: "https://in-toto.io/Statement/v0.1".into(),
        subject: vec![InTotoSubject { name: purl, digest }],
        predicate_type: "https://slsa.dev/provenance/v0.2".into(),
        predicate: SlsaPredicate {
            builder: Some(SlsaBuilder {
                id: format!("{project_url}/-/runners/{runner_id}"),
            }),
            build_type: Some("https://github.com/npm/cli/gitlab/v0alpha1".into()),
            invocation: Some(invocation),
            recipe: None,
            materials,
            build_definition: None,
            run_details: Some(SlsaRunDetails {
                builder: Some(SlsaBuilder {
                    id: format!("{project_url}/-/runners/{runner_id}"),
                }),
                metadata: Some(serde_json::json!({
                    "buildInvocationId": job_url,
                    "completeness": {
                        "parameters": true,
                        "environment": true,
                        "materials": false,
                    },
                    "reproducible": false,
                })),
            }),
        },
    }
}

/// Constructs an in-toto SLSA statement for the given package tarball.
pub fn build_slsa_v1_statement(
    package_name: &str,
    package_version: &str,
    tarball_sha512_hex: &str,
    ci: &CiEnvironmentInfo,
) -> InTotoStatement {
    if ci.ci_name == "GitLab CI" {
        return build_gitlab_provenance_statement(
            package_name,
            package_version,
            tarball_sha512_hex,
            ci,
        );
    }

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
    let trimmed = pem.trim();
    let begin_idx = trimmed.find("-----BEGIN ").ok_or_else(|| {
        RegistryError::InvalidSigstoreBundle("Missing PEM BEGIN header".into())
    })?;
    let after_begin = &trimmed[begin_idx..];
    let header_line_end = after_begin.find('\n').ok_or_else(|| {
        RegistryError::InvalidSigstoreBundle("Malformed PEM header line".into())
    })?;
    let header_line = after_begin[..header_line_end].trim();
    let label = header_line
        .strip_prefix("-----BEGIN ")
        .and_then(|s| s.strip_suffix("-----"))
        .ok_or_else(|| {
            RegistryError::InvalidSigstoreBundle("Malformed PEM BEGIN header line".into())
        })?;

    let expected_end = format!("-----END {label}-----");
    let end_idx = after_begin.find(&expected_end).ok_or_else(|| {
        RegistryError::InvalidSigstoreBundle(format!(
            "Missing matching PEM END header for label '{label}'"
        ))
    })?;

    if header_line_end >= end_idx {
        return Err(RegistryError::InvalidSigstoreBundle("Empty PEM body".into()));
    }
    let body = &after_begin[header_line_end + 1..end_idx];
    let clean: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() {
        return Err(RegistryError::InvalidSigstoreBundle("Empty PEM body".into()));
    }
    decode_base64(&clean)
}

/// Encodes raw DER certificate bytes into standard PEM format with 64-character lines.
pub fn der_to_pem_cert(der: &[u8]) -> String {
    let b64 = BASE64.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        if let Ok(line) = std::str::from_utf8(chunk) {
            pem.push_str(line);
            pem.push('\n');
        }
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// Decodes a Rekor verifier string in any supported format:
/// (a) raw PEM string -> DER bytes,
/// (b) base64-encoded DER bytes -> DER bytes,
/// (c) base64-encoded PEM string -> UTF-8 PEM -> DER bytes.
pub fn decode_rekor_verifier(verifier: &str) -> Result<Vec<u8>, RegistryError> {
    let trimmed = verifier.trim();
    if trimmed.is_empty() {
        return Err(RegistryError::InvalidSigstoreBundle("Empty verifier".into()));
    }
    if trimmed.contains("-----BEGIN ") {
        return decode_pem_to_der(trimmed);
    }
    let raw = decode_base64(trimmed)?;
    if let Ok(as_str) = std::str::from_utf8(&raw) {
        let trimmed_str = as_str.trim();
        if trimmed_str.contains("-----BEGIN ") {
            return decode_pem_to_der(trimmed_str);
        }
    }
    Ok(raw)
}

/// Submits a DSSE entry to Rekor and returns the created TlogEntry.
pub async fn submit_rekor_dsse_entry(
    rekor_url: &str,
    dsse_envelope: &DsseEnvelope,
    leaf_cert_der: &[u8],
) -> Result<TlogEntry, RegistryError> {
    let envelope_json = serde_json::to_string(dsse_envelope)
        .map_err(|e| RegistryError::Other(format!("Failed to serialize DSSE envelope: {e}")))?;
    let pem_cert = der_to_pem_cert(leaf_cert_der);
    let leaf_b64 = BASE64.encode(pem_cert.as_bytes());

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
    parse_rekor_log_entry_json(&resp_json)
}

/// Parses a Rekor /api/v1/log/entries JSON response into a `TlogEntry`.
/// Reads `signedEntryTimestamp` and `inclusionProof` from `entry["verification"]` (with fallback if top-level),
/// matching Rekor's actual response shape and npm's parser, preserving both SET and inclusion proof.
pub fn parse_rekor_log_entry_json(resp_json: &serde_json::Value) -> Result<TlogEntry, RegistryError> {
    let obj = resp_json
        .as_object()
        .ok_or_else(|| RegistryError::Other("Rekor response is not an object".into()))?;

    let (_uuid, entry) = obj
        .iter()
        .next()
        .ok_or_else(|| RegistryError::Other("Empty Rekor entries map in response".into()))?;

    let log_index = entry
        .get("logIndex")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0);
    let log_id = entry
        .get("logID")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let integrated_time = entry
        .get("integratedTime")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0);

    let verification = entry.get("verification");

    let signed_entry_timestamp = verification
        .and_then(|v| v.get("signedEntryTimestamp"))
        .and_then(|s| s.as_str())
        .or_else(|| {
            entry
                .get("signedEntryTimestamp")
                .and_then(|s| s.as_str())
        })
        .or_else(|| {
            entry
                .get("inclusionPromise")
                .and_then(|p| p.get("signedEntryTimestamp"))
                .and_then(|s| s.as_str())
        });

    let inclusion_promise = signed_entry_timestamp
        .filter(|s| !s.trim().is_empty())
        .map(|s| InclusionPromise {
            signed_entry_timestamp: s.to_string(),
        });

    let inclusion_proof = verification
        .and_then(|v| v.get("inclusionProof"))
        .cloned()
        .or_else(|| entry.get("inclusionProof").cloned());

    let canonicalized_body = entry
        .get("body")
        .and_then(|b| b.as_str())
        .or_else(|| entry.get("canonicalizedBody").and_then(|b| b.as_str()))
        .map(str::to_string);

    Ok(TlogEntry {
        log_index,
        log_id: LogId { key_id: log_id },
        integrated_time,
        inclusion_promise,
        inclusion_proof,
        canonicalized_body,
    })
}

/// Assembles a complete Sigstore bundle from envelope, certificate, and Rekor entry.
pub fn assemble_sigstore_bundle(
    dsse_envelope: DsseEnvelope,
    leaf_cert_der: &[u8],
    tlog_entry: TlogEntry,
) -> SigstoreBundle {
    SigstoreBundle {
        media_type: Some("application/vnd.sigstore.bundle+json;version=0.1".into()),
        verification_material: Some(VerificationMaterial {
            x509_certificate_chain: None,
            certificate: Some(X509Certificate {
                raw_bytes: BASE64.encode(leaf_cert_der),
            }),
            public_key: None,
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

/// Generates a valid cryptographically signed test bundle for testing and mock verification.
pub fn generate_valid_signed_test_bundle(
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

    // Sign leaf certificate with Mock Fulcio CA
    let rng = ring::rand::SystemRandom::new();
    let ca_priv = decode_base64(TEST_MOCK_CA_PRIV_PKCS8_B64).unwrap();
    let ca_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &ca_priv,
        &rng,
    )
    .unwrap();

    let cert_der = crate::asn1::create_test_x509_certificate(
        "test-signer",
        "sigstore",
        signer.public_key_uncompressed(),
        Some("https://github.com/actions/runner"),
        &fulcio_exts,
        now - 60,
        now + 600,
        &|tbs| ca_key_pair.sign(&rng, tbs).unwrap().as_ref().to_vec(),
    );

    // Build canonical Rekor body binding to DSSE envelope & leaf cert
    let payload_bytes = decode_base64(&envelope.payload).unwrap();
    let payload_hash_hex = HEXLOWER.encode(&Sha256::digest(&payload_bytes));
    let leaf_b64 = BASE64.encode(&cert_der);
    let canonical_body_json = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "payloadHash": {
                "algorithm": "sha256",
                "value": payload_hash_hex,
            },
            "signatures": [
                {
                    "signature": envelope.signatures[0].sig,
                    "verifier": leaf_b64,
                }
            ]
        }
    });
    let canonical_body_str = serde_json::to_string(&canonical_body_json).unwrap();
    let body_b64 = BASE64.encode(canonical_body_str.as_bytes());

    // Sign SET with Mock Rekor Key
    let rekor_priv = decode_base64(TEST_MOCK_REKOR_PRIV_PKCS8_B64).unwrap();
    let rekor_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rekor_priv,
        &rng,
    )
    .unwrap();

    let set_canonical_json = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        body_b64, now, REKOR_DEFAULT_LOG_ID, 42
    );
    let rekor_sig = rekor_key_pair
        .sign(&rng, set_canonical_json.as_bytes())
        .unwrap();

    let tlog_entry = TlogEntry {
        log_index: 42,
        log_id: LogId {
            key_id: REKOR_DEFAULT_LOG_ID.into(),
        },
        integrated_time: now,
        inclusion_promise: Some(InclusionPromise {
            signed_entry_timestamp: BASE64.encode(rekor_sig.as_ref()),
        }),
        inclusion_proof: None,
        canonicalized_body: Some(body_b64),
    };

    let bundle = assemble_sigstore_bundle(envelope, &cert_der, tlog_entry);
    (bundle, signer)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

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
    fn test_self_signed_leaf_rejected() {
        let tarball_bytes = b"test bytes";
        let (mut bundle, signer) = generate_valid_signed_test_bundle(
            "self-signed-pkg",
            "1.0.0",
            tarball_bytes,
            "my-org/self-signed",
            "abcdef",
        );

        // Replace certificate with self-signed certificate (signed by leaf signer, not CA)
        let now = 1700000000i64;
        let self_signed_der = crate::asn1::create_test_x509_certificate(
            "test-signer",
            "test-signer",
            signer.public_key_uncompressed(),
            None,
            &[],
            now - 60,
            now + 600,
            &|tbs| signer.sign(tbs).unwrap(),
        );

        bundle.verification_material.as_mut().unwrap().certificate = Some(X509Certificate {
            raw_bytes: BASE64.encode(&self_signed_der),
        });

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
        let err = verifier
            .verify("self-signed-pkg", &bundle, None, Some(tarball_bytes))
            .unwrap_err();
        match err {
            RegistryError::InvalidSigstoreBundle(msg) => {
                assert!(msg.contains("Self-signed leaf certificate is not in trusted Fulcio root authorities"), "{msg}");
            }
            other => panic!("Expected self-signed rejection, got: {other:?}"),
        }
    }

    #[test]
    fn test_untrusted_ca_rejected() {
        let tarball_bytes = b"test bytes";
        let (bundle, _) = generate_valid_signed_test_bundle(
            "untrusted-ca-pkg",
            "1.0.0",
            tarball_bytes,
            "my-org/untrusted",
            "abcdef",
        );

        // Verifier configured with NO trusted roots
        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny).without_default_roots();
        let err = verifier
            .verify("untrusted-ca-pkg", &bundle, None, Some(tarball_bytes))
            .unwrap_err();
        match err {
            RegistryError::InvalidSigstoreBundle(msg) => {
                assert!(msg.contains("Certificate chain does not terminate in a trusted Fulcio root CA")
                    || msg.contains("Self-signed"), "{msg}");
            }
            other => panic!("Expected untrusted CA rejection, got: {other:?}"),
        }
    }

    #[test]
    fn test_missing_rekor_evidence_rejected() {
        let tarball_bytes = b"test bytes";
        let (mut bundle, _) = generate_valid_signed_test_bundle(
            "missing-rekor-pkg",
            "1.0.0",
            tarball_bytes,
            "my-org/missing-rekor",
            "abcdef",
        );

        // Clear both inclusion_promise and inclusion_proof
        let tlog = &mut bundle.verification_material.as_mut().unwrap().tlog_entries[0];
        tlog.inclusion_promise = None;
        tlog.inclusion_proof = None;

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
        let err = verifier
            .verify("missing-rekor-pkg", &bundle, None, Some(tarball_bytes))
            .unwrap_err();
        match err {
            RegistryError::InvalidSigstoreBundle(msg) => {
                assert!(msg.contains("Rekor transparency log evidence missing or unauthenticated"), "{msg}");
            }
            other => panic!("Expected missing Rekor rejection, got: {other:?}"),
        }
    }

    #[test]
    fn test_rekor_body_payload_hash_mismatch_rejected() {
        let tarball_bytes = b"test bytes";
        let (mut bundle, _) = generate_valid_signed_test_bundle(
            "mismatch-pkg",
            "1.0.0",
            tarball_bytes,
            "my-org/mismatch",
            "abcdef",
        );

        // Modify payloadHash in canonical body, with valid SET signature over the tampered body
        let cert_raw = bundle
            .verification_material
            .as_ref()
            .unwrap()
            .certificate
            .as_ref()
            .unwrap()
            .raw_bytes
            .clone();
        let sig_str = bundle.dsse_envelope.as_ref().unwrap().signatures[0].sig.clone();
        let bad_body = serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": {
                "payloadHash": {
                    "algorithm": "sha256",
                    "value": "0000000000000000000000000000000000000000000000000000000000000000",
                },
                "signatures": [
                    {
                        "signature": sig_str,
                        "verifier": cert_raw,
                    }
                ]
            }
        });
        let body_b64 = BASE64.encode(serde_json::to_string(&bad_body).unwrap().as_bytes());
        let rng = ring::rand::SystemRandom::new();
        let rekor_priv = decode_base64(TEST_MOCK_REKOR_PRIV_PKCS8_B64).unwrap();
        let rekor_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rekor_priv,
            &rng,
        )
        .unwrap();
        let set_canonical_json = format!(
            r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
            body_b64, 1700000000, REKOR_DEFAULT_LOG_ID, 42
        );
        let rekor_sig = rekor_key_pair
            .sign(&rng, set_canonical_json.as_bytes())
            .unwrap();

        let tlog = &mut bundle.verification_material.as_mut().unwrap().tlog_entries[0];
        tlog.canonicalized_body = Some(body_b64);
        tlog.inclusion_promise = Some(InclusionPromise {
            signed_entry_timestamp: BASE64.encode(rekor_sig.as_ref()),
        });

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
        let err = verifier
            .verify("mismatch-pkg", &bundle, None, Some(tarball_bytes))
            .unwrap_err();
        match err {
            RegistryError::InvalidSigstoreBundle(msg) => {
                assert!(msg.contains("payloadHash mismatch"), "{msg}");
            }
            other => panic!("Expected payloadHash mismatch, got: {other:?}"),
        }
    }

    #[test]
    fn test_rekor_body_verifier_mismatch_rejected() {
        let tarball_bytes = b"test bytes";
        let (mut bundle, _) = generate_valid_signed_test_bundle(
            "mismatch-verifier-pkg",
            "1.0.0",
            tarball_bytes,
            "my-org/mismatch-verifier",
            "abcdef",
        );

        let payload_bytes = decode_base64(&bundle.dsse_envelope.as_ref().unwrap().payload).unwrap();
        let payload_hash_hex = HEXLOWER.encode(&Sha256::digest(&payload_bytes));
        let bad_body = serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": {
                "payloadHash": {
                    "algorithm": "sha256",
                    "value": payload_hash_hex,
                },
                "signatures": [
                    {
                        "signature": bundle.dsse_envelope.as_ref().unwrap().signatures[0].sig,
                        "verifier": BASE64.encode(b"wrong-cert-der"),
                    }
                ]
            }
        });
        let body_b64 = BASE64.encode(serde_json::to_string(&bad_body).unwrap().as_bytes());
        let rng = ring::rand::SystemRandom::new();
        let rekor_priv = decode_base64(TEST_MOCK_REKOR_PRIV_PKCS8_B64).unwrap();
        let rekor_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rekor_priv,
            &rng,
        )
        .unwrap();
        let set_canonical_json = format!(
            r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
            body_b64, 1700000000, REKOR_DEFAULT_LOG_ID, 42
        );
        let rekor_sig = rekor_key_pair
            .sign(&rng, set_canonical_json.as_bytes())
            .unwrap();

        let tlog = &mut bundle.verification_material.as_mut().unwrap().tlog_entries[0];
        tlog.canonicalized_body = Some(body_b64);
        tlog.inclusion_promise = Some(InclusionPromise {
            signed_entry_timestamp: BASE64.encode(rekor_sig.as_ref()),
        });

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
        let err = verifier
            .verify("mismatch-verifier-pkg", &bundle, None, Some(tarball_bytes))
            .unwrap_err();
        match err {
            RegistryError::InvalidSigstoreBundle(msg) => {
                assert!(msg.contains("verifier mismatch"), "{msg}");
            }
            other => panic!("Expected verifier mismatch, got: {other:?}"),
        }
    }

    #[test]
    fn test_string_encoded_tlog_integers_verified() {
        let tarball_bytes = b"test bytes";
        let (bundle, _) = generate_valid_signed_test_bundle(
            "string-int-pkg",
            "1.0.0",
            tarball_bytes,
            "my-org/string-int",
            "abcdef",
        );

        let mut bundle_json = serde_json::to_value(&bundle).unwrap();
        // Mutate integratedTime and logIndex to strings
        let tlog_val = &mut bundle_json["verificationMaterial"]["tlogEntries"][0];
        tlog_val["integratedTime"] = serde_json::json!("1700000000");
        tlog_val["logIndex"] = serde_json::json!("42");

        let deserialized_bundle: SigstoreBundle = serde_json::from_value(bundle_json).unwrap();
        assert_eq!(
            deserialized_bundle.verification_material.as_ref().unwrap().tlog_entries[0].integrated_time,
            1700000000
        );
        assert_eq!(
            deserialized_bundle.verification_material.as_ref().unwrap().tlog_entries[0].log_index,
            42
        );

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
        let res = verifier.verify("string-int-pkg", &deserialized_bundle, None, Some(tarball_bytes));
        assert!(res.is_ok(), "Verification of string integers failed: {:?}", res.err());
    }

    #[test]
    fn test_registry_keyed_publish_attestation_verified() {
        let tarball_bytes = b"publish attestation tarball";
        let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));
        let signer = EphemeralSigner::new().unwrap();

        let ci = CiEnvironmentInfo {
            ci_name: "GitHub Actions".into(),
            server_url: "https://github.com".into(),
            repository: "my-org/keyed-pkg".into(),
            commit_sha: "abcdef".into(),
            workflow_path: ".github/workflows/deploy.yml".into(),
            workflow_ref: "refs/heads/main".into(),
            ..Default::default()
        };

        let statement = build_slsa_v1_statement("keyed-pkg", "1.0.0", &sha512_hex, &ci);
        let mut envelope = sign_dsse_envelope(&statement, &signer).unwrap();
        let keyid = "SHA256:test-registry-key-hint";
        envelope.signatures[0].keyid = Some(keyid.to_string());

        let bundle = SigstoreBundle {
            media_type: Some("application/vnd.sigstore.bundle+json;version=0.1".into()),
            verification_material: Some(VerificationMaterial {
                x509_certificate_chain: None,
                certificate: None,
                public_key: Some(PublicKeyHint {
                    hint: Some(keyid.to_string()),
                    raw_bytes: Some(BASE64.encode(signer.public_key_spki())),
                }),
                tlog_entries: Vec::new(),
                timestamp_verification_data: None,
            }),
            dsse_envelope: Some(envelope),
        };

        let mut reg_keys = HashMap::new();
        reg_keys.insert(keyid.to_string(), signer.public_key_spki().to_vec());

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny)
            .with_registry_keys(reg_keys);

        let res = verifier.verify_package("keyed-pkg", Some("1.0.0"), &bundle, None, Some(tarball_bytes));
        assert!(res.is_ok(), "Registry-keyed verification failed: {:?}", res.err());
    }

    #[test]
    fn test_exact_purl_version_mismatch_rejected() {
        let tarball_bytes = b"tarball bytes";
        let (bundle, _) = generate_valid_signed_test_bundle(
            "purl-pkg",
            "1.0.0",
            tarball_bytes,
            "my-org/purl-pkg",
            "abcdef",
        );

        let verifier = ProvenanceVerifier::new(ProvenancePolicy::AllowAny);
        // Expecting version 2.0.0 but bundle has 1.0.0
        let err = verifier
            .verify_package("purl-pkg", Some("2.0.0"), &bundle, None, Some(tarball_bytes))
            .unwrap_err();
        match err {
            RegistryError::ProvenanceVerificationFailed(msg) => {
                assert!(msg.contains("Attestation subject name mismatch"), "{msg}");
            }
            other => panic!("Expected ProvenanceVerificationFailed, got: {other:?}"),
        }
    }

    #[test]
    fn test_gitlab_ci_statement_generation() {
        let ci = CiEnvironmentInfo {
            ci_name: "GitLab CI".into(),
            server_url: "https://gitlab.com".into(),
            repository: "my-group/my-project".into(),
            commit_sha: "1234567890abcdef1234567890abcdef12345678".into(),
            workflow_path: ".gitlab-ci.yml".into(),
            workflow_ref: "main".into(),
            ..Default::default()
        };

        let stmt = build_slsa_v1_statement("gitlab-pkg", "1.0.0", "abcdef512", &ci);
        assert_eq!(stmt.statement_type, "https://in-toto.io/Statement/v0.1");
        assert_eq!(stmt.predicate_type, "https://slsa.dev/provenance/v0.2");
        assert_eq!(
            stmt.predicate.build_type.as_deref(),
            Some("https://github.com/npm/cli/gitlab/v0alpha1")
        );
        assert_eq!(stmt.subject[0].name, "pkg:npm/gitlab-pkg@1.0.0");
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
                assert!(msg.contains("Certificate not valid") || msg.contains("validity window"), "{msg}");
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

        // Valid proof with authenticated root
        assert!(verify_merkle_inclusion_proof(&entry, Some(&root_hash)).is_ok());

        // Tampered proof with wrong root
        let bad_root = Sha256::digest(b"wrong-root").to_vec();
        assert!(verify_merkle_inclusion_proof(&entry, Some(&bad_root)).is_err());
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

    #[test]
    fn test_rekor_set_canonical_body_raw_json_and_uppercase_logid() {
        let rekor_signer = EphemeralSigner::new().unwrap();
        let raw_body = r#"{"apiVersion":"0.0.1","kind":"dsse"}"#;
        let body_b64 = BASE64.encode(raw_body.as_bytes());
        let integrated_time = 1700000000i64;
        let log_index = 100u64;
        let log_id_hex_lower = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let log_id_hex_upper = log_id_hex_lower.to_ascii_uppercase();

        let payload = format!(
            r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
            body_b64, integrated_time, log_id_hex_lower, log_index
        );
        let set_sig = rekor_signer.sign(payload.as_bytes()).unwrap();

        let entry = TlogEntry {
            log_index,
            log_id: LogId {
                key_id: log_id_hex_upper,
            },
            integrated_time,
            inclusion_promise: Some(InclusionPromise {
                signed_entry_timestamp: BASE64.encode(&set_sig),
            }),
            inclusion_proof: None,
            // Provide raw JSON string instead of pre-base64-encoded body
            canonicalized_body: Some(raw_body.to_string()),
        };

        let pubkeys = vec![rekor_signer.public_key_spki().to_vec()];
        assert!(verify_rekor_set(&pubkeys, &entry).is_ok());
    }

    #[test]
    fn test_verify_intermediate_cert_expiry() {
        let rng = ring::rand::SystemRandom::new();
        let ca_priv = decode_base64(TEST_MOCK_CA_PRIV_PKCS8_B64).unwrap();
        let ca_key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &ca_priv,
            &rng,
        )
        .unwrap();

        let inter_signer = EphemeralSigner::new().unwrap();
        let leaf_signer = EphemeralSigner::new().unwrap();

        let integrated_time = 1700000000i64;

        // Leaf certificate is valid at integrated_time
        let leaf_der = crate::asn1::create_test_x509_certificate(
            "leaf-signer",
            "inter-ca",
            leaf_signer.public_key_uncompressed(),
            None,
            &[],
            integrated_time - 60,
            integrated_time + 600,
            &|tbs| inter_signer.sign(tbs).unwrap(),
        );

        // Intermediate certificate is EXPIRED at integrated_time
        let inter_der = crate::asn1::create_test_x509_certificate(
            "inter-ca",
            "sigstore",
            inter_signer.public_key_uncompressed(),
            None,
            &[],
            integrated_time - 1000,
            integrated_time - 100, // expired before integrated_time!
            &|tbs| ca_key_pair.sign(&rng, tbs).unwrap().as_ref().to_vec(),
        );

        let root_der = test_mock_fulcio_root_cert();
        let chain_raw = [BASE64.encode(&leaf_der), BASE64.encode(&inter_der)];
        let chain_refs = [chain_raw[0].as_str(), chain_raw[1].as_str()];

        let err = verify_fulcio_certificate_chain(&chain_refs, &[root_der], integrated_time)
            .unwrap_err();
        match err {
            RegistryError::InvalidSigstoreBundle(msg) => {
                assert!(
                    msg.contains("Intermediate certificate not valid at integratedTime"),
                    "{msg}"
                );
            }
            other => panic!("Expected InvalidSigstoreBundle, got: {other:?}"),
        }
    }

    #[test]
    fn test_verify_subject_digest_multiple_integrity_tokens() {
        let tarball_bytes = b"sample tarball payload";
        let sha512_hex = HEXLOWER.encode(&Sha512::digest(tarball_bytes));
        let sha512_b64 = BASE64.encode(&Sha512::digest(tarball_bytes));

        let mut digests = HashMap::new();
        digests.insert("sha512".to_string(), sha512_hex);
        let subject = InTotoSubject {
            name: "pkg@1.0.0".into(),
            digest: digests,
        };

        // Multiple tokens with invalid / unsupported first token
        let integrity = format!("sha384-invalidBase64!! sha512-{sha512_b64}");
        assert!(ProvenanceVerifier::verify_subject_digest(
            &subject,
            Some(&integrity),
            None
        )
        .is_ok());
    }
}
