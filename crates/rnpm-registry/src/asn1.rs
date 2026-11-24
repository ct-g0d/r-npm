//! ASN.1 DER parser for X.509 certificates and Sigstore verification.
//! Pure Rust implementation without external dependencies.

use std::collections::HashMap;

use crate::error::RegistryError;

/// Tag constants for ASN.1 DER encoding.
pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_UTF8_STRING: u8 = 0x0C;
pub const TAG_PRINTABLE_STRING: u8 = 0x13;
pub const TAG_IA5_STRING: u8 = 0x16;
pub const TAG_UTC_TIME: u8 = 0x17;
pub const TAG_GENERALIZED_TIME: u8 = 0x18;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;
pub const TAG_CONTEXT_0: u8 = 0xA0;
pub const TAG_CONTEXT_3: u8 = 0xA3;

/// Well-known Fulcio and X.509 OIDs.
pub const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const OID_EC_P256: &str = "1.2.840.10045.3.1.7";
pub const OID_EC_P384: &str = "1.3.132.0.34";
pub const OID_ED25519: &str = "1.3.101.112";
pub const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
pub const OID_SUBJECT_ALT_NAME: &str = "2.5.29.17";

// Fulcio OIDs
pub const OID_FULCIO_ISSUER: &str = "1.3.6.1.4.1.57264.1.1";
pub const OID_FULCIO_GITHUB_WORKFLOW_TRIGGER: &str = "1.3.6.1.4.1.57264.1.2";
pub const OID_FULCIO_GITHUB_WORKFLOW_SHA: &str = "1.3.6.1.4.1.57264.1.3";
pub const OID_FULCIO_GITHUB_WORKFLOW_NAME: &str = "1.3.6.1.4.1.57264.1.4";
pub const OID_FULCIO_GITHUB_WORKFLOW_REPOSITORY: &str = "1.3.6.1.4.1.57264.1.5";
pub const OID_FULCIO_GITHUB_WORKFLOW_REF: &str = "1.3.6.1.4.1.57264.1.6";
pub const OID_FULCIO_BUILD_TRIGGER: &str = "1.3.6.1.4.1.57264.1.8";
pub const OID_FULCIO_RUN_COMMIT_SHA: &str = "1.3.6.1.4.1.57264.1.9";

/// Parsed X.509 leaf certificate details for Sigstore verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCertificate {
    pub raw_der: Vec<u8>,
    pub tbs_bytes: Vec<u8>,
    pub signature_value: Vec<u8>,
    pub signature_algorithm_oid: String,
    pub issuer_raw: Vec<u8>,
    pub subject_raw: Vec<u8>,
    pub spki_bytes: Vec<u8>,
    pub public_key_bytes: Vec<u8>,
    pub algorithm_oid: String,
    pub curve_oid: Option<String>,
    pub not_before: i64,
    pub not_after: i64,
    pub san_uris: Vec<String>,
    pub fulcio_extensions: HashMap<String, String>,
}

/// Reads a single DER Tag-Length-Value from `input`.
/// Returns `(tag, value_slice, remaining_slice)`.
pub fn read_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), RegistryError> {
    if input.is_empty() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Unexpected end of DER input".into(),
        ));
    }
    let tag = input[0];
    if input.len() < 2 {
        return Err(RegistryError::InvalidSigstoreBundle(
            "DER input truncated at length byte".into(),
        ));
    }

    let (len, header_len) = if input[1] & 0x80 == 0 {
        (input[1] as usize, 2)
    } else {
        let num_bytes = (input[1] & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            return Err(RegistryError::InvalidSigstoreBundle(format!(
                "Invalid DER length multi-byte count: {num_bytes}"
            )));
        }
        if input.len() < 2 + num_bytes {
            return Err(RegistryError::InvalidSigstoreBundle(
                "DER input truncated in multi-byte length".into(),
            ));
        }
        let mut l = 0usize;
        for &b in &input[2..2 + num_bytes] {
            l = (l << 8) | (b as usize);
        }
        // Non-canonical DER: multi-byte length must not have redundant leading zeros
        if input[2] == 0 {
            return Err(RegistryError::InvalidSigstoreBundle(
                "Non-canonical DER: leading zero in multi-byte length".into(),
            ));
        }
        // Non-canonical DER: lengths < 128 must use short form
        if l < 128 {
            return Err(RegistryError::InvalidSigstoreBundle(
                "Non-canonical DER: multi-byte encoding used for length < 128".into(),
            ));
        }
        (l, 2 + num_bytes)
    };

    let total_len = match header_len.checked_add(len) {
        Some(t) => t,
        None => {
            return Err(RegistryError::InvalidSigstoreBundle(
                "DER element length overflow".into(),
            ));
        }
    };

    if input.len() < total_len {
        return Err(RegistryError::InvalidSigstoreBundle(format!(
            "DER element requires {} bytes but only {} available",
            total_len,
            input.len()
        )));
    }

    let value = &input[header_len..total_len];
    let rest = &input[total_len..];
    Ok((tag, value, rest))
}

/// Parses all elements inside a constructed sequence or set.
pub fn parse_sequence(mut input: &[u8]) -> Result<Vec<(u8, &[u8])>, RegistryError> {
    let mut elements = Vec::new();
    while !input.is_empty() {
        let (tag, val, rest) = read_tlv(input)?;
        elements.push((tag, val));
        input = rest;
    }
    Ok(elements)
}

/// Decodes ASN.1 Object Identifier bytes into dot notation string (e.g. "1.2.840.10045.2.1").
pub fn decode_oid(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    let mut val = 0u64;
    let mut cursor = 0;

    // Decode first subidentifier (X * 40 + Y) using VLQ
    while cursor < bytes.len() {
        let b = bytes[cursor];
        cursor += 1;
        if let Some(new_val) = val
            .checked_mul(128)
            .and_then(|v| v.checked_add((b & 0x7F) as u64))
        {
            val = new_val;
        } else {
            return String::new();
        }
        if (b & 0x80) == 0 {
            break;
        }
    }
    if cursor == 0 || (bytes[cursor - 1] & 0x80) != 0 {
        // Malformed/truncated first subidentifier
        return String::new();
    }

    // ITU-T X.690 Section 8.19.4:
    // If the first component X is 0 or 1, the second component Y is 0..39.
    // If X is 2, Y can be any value, and (X*40)+Y = 80+Y.
    if val < 80 {
        parts.push((val / 40).to_string());
        parts.push((val % 40).to_string());
    } else {
        parts.push("2".to_string());
        parts.push((val - 80).to_string());
    }

    // Decode subsequent subidentifiers
    val = 0;
    let rest = &bytes[cursor..];
    for (i, &b) in rest.iter().enumerate() {
        if let Some(new_val) = val
            .checked_mul(128)
            .and_then(|v| v.checked_add((b & 0x7F) as u64))
        {
            val = new_val;
        } else {
            return String::new();
        }
        if (b & 0x80) == 0 {
            parts.push(val.to_string());
            val = 0;
        } else if i == rest.len() - 1 {
            // Malformed/truncated OID: last byte has continuation bit set
            return String::new();
        }
    }
    parts.join(".")
}

/// Encodes an OID string into ASN.1 DER bytes.
pub fn encode_oid(oid: &str) -> Vec<u8> {
    let parts: Vec<u64> = oid.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() < 2 {
        return Vec::new();
    }
    let mut res = Vec::new();
    let first_subid = if parts[0] == 2 && parts[1] > 39 {
        80 + parts[1]
    } else {
        parts[0] * 40 + parts[1]
    };
    let mut v = first_subid;
    let mut buf = Vec::new();
    buf.push((v & 0x7F) as u8);
    v >>= 7;
    while v > 0 {
        buf.push(((v & 0x7F) as u8) | 0x80);
        v >>= 7;
    }
    buf.reverse();
    res.extend_from_slice(&buf);

    for &p in &parts[2..] {
        let mut v = p;
        let mut buf = Vec::new();
        buf.push((v & 0x7F) as u8);
        v >>= 7;
        while v > 0 {
            buf.push(((v & 0x7F) as u8) | 0x80);
            v >>= 7;
        }
        buf.reverse();
        res.extend_from_slice(&buf);
    }
    res
}

/// Encodes DER length bytes.
pub fn encode_der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else if len <= 0xFF_FFFF {
        vec![
            0x83,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    } else {
        vec![
            0x84,
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    }
}

/// Wraps content in a DER TLV.
pub fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_der_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// Parses UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`) into Unix epoch seconds.
pub fn parse_der_time(tag: u8, bytes: &[u8]) -> Result<i64, RegistryError> {
    if bytes.is_empty() || !bytes.iter().all(|&b| b.is_ascii_digit() || b == b'Z') {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Invalid non-ASCII or non-digit characters in certificate time".into(),
        ));
    }
    let s = std::str::from_utf8(bytes).map_err(|e| {
        RegistryError::InvalidSigstoreBundle(format!("Invalid UTF-8 in certificate time: {e}"))
    })?;
    let s = s.trim_end_matches('Z');

    let (year, rest) = if tag == TAG_UTC_TIME {
        if s.len() < 12 {
            return Err(RegistryError::InvalidSigstoreBundle(format!(
                "UTCTime string too short: {s}"
            )));
        }
        let yy: i32 = s[0..2].parse().map_err(|e| {
            RegistryError::InvalidSigstoreBundle(format!("Failed to parse UTCTime year: {e}"))
        })?;
        let full_year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        (full_year, &s[2..])
    } else if tag == TAG_GENERALIZED_TIME {
        if s.len() < 14 {
            return Err(RegistryError::InvalidSigstoreBundle(format!(
                "GeneralizedTime string too short: {s}"
            )));
        }
        let yyyy: i32 = s[0..4].parse().map_err(|e| {
            RegistryError::InvalidSigstoreBundle(format!(
                "Failed to parse GeneralizedTime year: {e}"
            ))
        })?;
        (yyyy, &s[4..])
    } else {
        return Err(RegistryError::InvalidSigstoreBundle(format!(
            "Unsupported time tag in certificate: 0x{tag:02x}"
        )));
    };

    if rest.len() < 10 {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Certificate time string too short for month/day/time".into(),
        ));
    }

    let month: u32 = rest[0..2].parse().map_err(|e| {
        RegistryError::InvalidSigstoreBundle(format!("Failed to parse time month: {e}"))
    })?;
    let day: u32 = rest[2..4].parse().map_err(|e| {
        RegistryError::InvalidSigstoreBundle(format!("Failed to parse time day: {e}"))
    })?;
    let hour: u32 = rest[4..6].parse().map_err(|e| {
        RegistryError::InvalidSigstoreBundle(format!("Failed to parse time hour: {e}"))
    })?;
    let min: u32 = rest[6..8].parse().map_err(|e| {
        RegistryError::InvalidSigstoreBundle(format!("Failed to parse time minute: {e}"))
    })?;
    let sec: u32 = rest[8..10].parse().map_err(|e| {
        RegistryError::InvalidSigstoreBundle(format!("Failed to parse time second: {e}"))
    })?;

    if !(1..=12).contains(&month) {
        return Err(RegistryError::InvalidSigstoreBundle(format!(
            "Invalid month in certificate time: {month}"
        )));
    }
    if !(1..=31).contains(&day) {
        return Err(RegistryError::InvalidSigstoreBundle(format!(
            "Invalid day in certificate time: {day}"
        )));
    }
    if hour > 23 || min > 59 || sec > 60 {
        return Err(RegistryError::InvalidSigstoreBundle(format!(
            "Invalid hour/minute/second in certificate time: {hour}:{min}:{sec}"
        )));
    }

    let days = date_to_epoch_days(year, month, day);
    let total_secs = days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64);
    Ok(total_secs)
}

fn date_to_epoch_days(year: i32, month: u32, day: u32) -> i64 {
    let m = month as i64;
    let y = year as i64 - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as i64 - 1;
    let doe = (yoe as i64) * 365 + (yoe as i64) / 4 - (yoe as i64) / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parses a leaf X.509 DER certificate.
pub fn parse_x509_certificate(der: &[u8]) -> Result<ParsedCertificate, RegistryError> {
    let (tag, cert_val, rest) = read_tlv(der)?;
    if !rest.is_empty() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Trailing garbage after certificate DER sequence".into(),
        ));
    }
    if tag != TAG_SEQUENCE {
        return Err(RegistryError::InvalidSigstoreBundle(format!(
            "Expected certificate SEQUENCE (0x30), got 0x{tag:02x}"
        )));
    }

    let cert_elems = parse_sequence(cert_val)?;
    if cert_elems.len() < 3 {
        return Err(RegistryError::InvalidSigstoreBundle(
            "X.509 certificate sequence requires tbsCertificate, signatureAlgorithm, and signatureValue".into(),
        ));
    }

    let (tbs_tag, tbs_val) = cert_elems[0];
    if tbs_tag != TAG_SEQUENCE {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Expected TBSCertificate SEQUENCE".into(),
        ));
    }
    let tbs_bytes = der_tlv(tbs_tag, tbs_val);

    let sig_algo_elems = parse_sequence(cert_elems[1].1)?;
    let signature_algorithm_oid = if !sig_algo_elems.is_empty() {
        decode_oid(sig_algo_elems[0].1)
    } else {
        String::new()
    };

    if cert_elems[2].0 != TAG_BIT_STRING {
        return Err(RegistryError::InvalidSigstoreBundle(format!(
            "Expected certificate signatureValue BIT STRING (0x03), got 0x{:02x}",
            cert_elems[2].0
        )));
    }
    let sig_bitstring = cert_elems[2].1;
    if sig_bitstring.is_empty() || sig_bitstring[0] != 0 {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Invalid or empty signature BIT STRING in certificate".into(),
        ));
    }
    let signature_value = sig_bitstring[1..].to_vec();
    if signature_value.is_empty() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Empty signature value in certificate".into(),
        ));
    }

    let tbs_elems = parse_sequence(tbs_val)?;
    let mut cursor = 0;
    if cursor >= tbs_elems.len() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Malformed TBSCertificate".into(),
        ));
    }

    // Optional version [0]
    if tbs_elems[cursor].0 == TAG_CONTEXT_0 {
        cursor += 1;
    }

    // serialNumber (INTEGER)
    if cursor >= tbs_elems.len() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Missing serialNumber in TBSCertificate".into(),
        ));
    }
    cursor += 1;

    // signature (AlgorithmIdentifier)
    if cursor >= tbs_elems.len() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Missing signature in TBSCertificate".into(),
        ));
    }
    cursor += 1;

    // issuer (Name)
    if cursor >= tbs_elems.len() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Missing issuer in TBSCertificate".into(),
        ));
    }
    let issuer_raw = der_tlv(tbs_elems[cursor].0, tbs_elems[cursor].1);
    cursor += 1;

    // validity (Validity)
    if cursor >= tbs_elems.len() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Missing validity in TBSCertificate".into(),
        ));
    }
    let validity_elems = parse_sequence(tbs_elems[cursor].1)?;
    if validity_elems.len() < 2 {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Validity sequence requires notBefore and notAfter".into(),
        ));
    }
    let not_before = parse_der_time(validity_elems[0].0, validity_elems[0].1)?;
    let not_after = parse_der_time(validity_elems[1].0, validity_elems[1].1)?;
    cursor += 1;

    // subject (Name)
    if cursor >= tbs_elems.len() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Missing subject in TBSCertificate".into(),
        ));
    }
    let subject_raw = der_tlv(tbs_elems[cursor].0, tbs_elems[cursor].1);
    cursor += 1;

    // subjectPublicKeyInfo (SubjectPublicKeyInfo)
    if cursor >= tbs_elems.len() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Missing subjectPublicKeyInfo in TBSCertificate".into(),
        ));
    }
    let spki_raw = tbs_elems[cursor];
    let spki_bytes = der_tlv(spki_raw.0, spki_raw.1);
    let (algorithm_oid, curve_oid, public_key_bytes) = parse_spki_internal(spki_raw.1)?;
    cursor += 1;

    // Optional extensions: scan remaining elements for [3] (0xA3)
    let mut san_uris = Vec::new();
    let mut fulcio_extensions = HashMap::new();

    while cursor < tbs_elems.len() {
        if tbs_elems[cursor].0 == TAG_CONTEXT_3 {
            // Extensions SEQUENCE is inside [3]
            let (ext_seq_tag, ext_seq_val, _) = read_tlv(tbs_elems[cursor].1)?;
            if ext_seq_tag == TAG_SEQUENCE {
                let extensions = parse_sequence(ext_seq_val)?;
                for ext in extensions {
                    if ext.0 == TAG_SEQUENCE {
                        let ext_parts = parse_sequence(ext.1)?;
                        if ext_parts.len() >= 2 {
                            let oid = decode_oid(ext_parts[0].1);
                            // last element is extnValue OCTET STRING
                            let octet_value = ext_parts.last().unwrap();
                            if octet_value.0 == TAG_OCTET_STRING {
                                parse_extension(
                                    &oid,
                                    octet_value.1,
                                    &mut san_uris,
                                    &mut fulcio_extensions,
                                );
                            }
                        }
                    }
                }
            }
            break;
        }
        cursor += 1;
    }

    Ok(ParsedCertificate {
        raw_der: der.to_vec(),
        tbs_bytes,
        signature_value,
        signature_algorithm_oid,
        issuer_raw,
        subject_raw,
        spki_bytes,
        public_key_bytes,
        algorithm_oid,
        curve_oid,
        not_before,
        not_after,
        san_uris,
        fulcio_extensions,
    })
}

/// Parses SubjectPublicKeyInfo SEQUENCE content into (algorithm_oid, optional_curve_oid, public_key_bytes).
fn parse_spki_internal(
    spki_val: &[u8],
) -> Result<(String, Option<String>, Vec<u8>), RegistryError> {
    let elems = parse_sequence(spki_val)?;
    if elems.len() < 2 {
        return Err(RegistryError::InvalidSigstoreBundle(
            "SubjectPublicKeyInfo must contain algorithm and subjectPublicKey".into(),
        ));
    }

    // 1. AlgorithmIdentifier
    let algo_elems = parse_sequence(elems[0].1)?;
    if algo_elems.is_empty() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "AlgorithmIdentifier is empty".into(),
        ));
    }
    let algo_oid = decode_oid(algo_elems[0].1);
    let curve_oid = if algo_elems.len() > 1 && algo_elems[1].0 == TAG_OID {
        Some(decode_oid(algo_elems[1].1))
    } else {
        None
    };

    // 2. subjectPublicKey BIT STRING
    let bit_string = elems[1].1;
    if bit_string.is_empty() || bit_string[0] != 0 {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Invalid or empty BIT STRING in SPKI".into(),
        ));
    }
    // First byte is unused bits count (usually 0)
    let pk_bytes = bit_string[1..].to_vec();
    if pk_bytes.is_empty() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Empty public key in SPKI".into(),
        ));
    }

    Ok((algo_oid, curve_oid, pk_bytes))
}

/// Parses SubjectPublicKeyInfo from full SPKI DER bytes.
pub fn parse_spki(der: &[u8]) -> Result<(String, Option<String>, Vec<u8>), RegistryError> {
    let (tag, val, rest) = read_tlv(der)?;
    if !rest.is_empty() {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Trailing garbage after SPKI SEQUENCE".into(),
        ));
    }
    if tag != TAG_SEQUENCE {
        return Err(RegistryError::InvalidSigstoreBundle(
            "Expected SPKI SEQUENCE".into(),
        ));
    }
    parse_spki_internal(val)
}

fn parse_extension(
    oid: &str,
    extn_value: &[u8],
    san_uris: &mut Vec<String>,
    fulcio_extensions: &mut HashMap<String, String>,
) {
    if oid == OID_SUBJECT_ALT_NAME {
        // GeneralNames SEQUENCE
        if let Ok((tag, gn_val, _)) = read_tlv(extn_value) {
            if tag == TAG_SEQUENCE {
                if let Ok(names) = parse_sequence(gn_val) {
                    for (gn_tag, gn_data) in names {
                        // 0x86 is uniformResourceIdentifier, 0x81 is rfc822Name, 0x82 is dNSName
                        if gn_tag == 0x86 || gn_tag == 0x81 || gn_tag == 0x82 {
                            if let Ok(s) = std::str::from_utf8(gn_data) {
                                san_uris.push(s.to_string());
                            }
                        }
                    }
                }
            }
        }
    } else if oid.starts_with("1.3.6.1.4.1.57264.1.") {
        // String extension
        let s = if let Ok((inner_tag, inner_val, _)) = read_tlv(extn_value) {
            if inner_tag == TAG_UTF8_STRING
                || inner_tag == TAG_IA5_STRING
                || inner_tag == TAG_PRINTABLE_STRING
            {
                std::str::from_utf8(inner_val).ok().map(str::to_string)
            } else {
                std::str::from_utf8(extn_value).ok().map(str::to_string)
            }
        } else {
            std::str::from_utf8(extn_value).ok().map(str::to_string)
        };
        if let Some(text) = s {
            fulcio_extensions.insert(oid.to_string(), text);
        }
    }
}

/// Helper for constructing an X.509 v3 certificate for deterministic testing and mock Fulcio.
#[allow(clippy::too_many_arguments)]
pub fn create_test_x509_certificate(
    subject_cn: &str,
    issuer_cn: &str,
    public_key_uncompressed_point: &[u8],
    san_uri: Option<&str>,
    fulcio_exts: &[(&str, &str)],
    not_before: i64,
    not_after: i64,
    signer: &dyn Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    // 1. [0] Version 3
    let version_val = der_tlv(TAG_INTEGER, &[0x02]);
    let version = der_tlv(TAG_CONTEXT_0, &version_val);

    // 2. Serial number
    let serial = der_tlv(TAG_INTEGER, &[0x01]);

    // 3. Signature AlgorithmIdentifier: ecdsa-with-SHA256
    let sig_algo = der_tlv(
        TAG_SEQUENCE,
        &[
            der_tlv(TAG_OID, &encode_oid(OID_ECDSA_SHA256)),
            der_tlv(TAG_NULL, &[]),
        ]
        .concat(),
    );

    // 4. Issuer Name
    let issuer = der_tlv(
        TAG_SEQUENCE,
        &der_tlv(
            TAG_SET,
            &der_tlv(
                TAG_SEQUENCE,
                &[
                    der_tlv(TAG_OID, &encode_oid("2.5.4.3")), // CommonName
                    der_tlv(TAG_UTF8_STRING, issuer_cn.as_bytes()),
                ]
                .concat(),
            ),
        ),
    );

    // 5. Validity: notBefore and notAfter
    fn format_generalized_time(secs: i64) -> String {
        // Convert secs to date/time components
        let days = (secs / 86400) + 719468;
        let rem_secs = secs.rem_euclid(86400);
        let hour = rem_secs / 3600;
        let min = (rem_secs % 3600) / 60;
        let sec = rem_secs % 60;

        let era = (if days >= 0 { days } else { days - 146096 }) / 146097;
        let doe = (days - era * 146097) as u32;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = (yoe as i64) + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = y + if m <= 2 { 1 } else { 0 };

        format!("{year:04}{m:02}{d:02}{hour:02}{min:02}{sec:02}Z")
    }

    let validity = der_tlv(
        TAG_SEQUENCE,
        &[
            der_tlv(
                TAG_GENERALIZED_TIME,
                format_generalized_time(not_before).as_bytes(),
            ),
            der_tlv(
                TAG_GENERALIZED_TIME,
                format_generalized_time(not_after).as_bytes(),
            ),
        ]
        .concat(),
    );

    // 6. Subject Name
    let subject = der_tlv(
        TAG_SEQUENCE,
        &der_tlv(
            TAG_SET,
            &der_tlv(
                TAG_SEQUENCE,
                &[
                    der_tlv(TAG_OID, &encode_oid("2.5.4.3")), // CommonName
                    der_tlv(TAG_UTF8_STRING, subject_cn.as_bytes()),
                ]
                .concat(),
            ),
        ),
    );

    // 7. SubjectPublicKeyInfo (P-256)
    let spki_algo = der_tlv(
        TAG_SEQUENCE,
        &[
            der_tlv(TAG_OID, &encode_oid(OID_EC_PUBLIC_KEY)),
            der_tlv(TAG_OID, &encode_oid(OID_EC_P256)),
        ]
        .concat(),
    );
    let mut pk_bitstring = vec![0x00]; // 0 unused bits
    pk_bitstring.extend_from_slice(public_key_uncompressed_point);
    let spki = der_tlv(
        TAG_SEQUENCE,
        &[spki_algo, der_tlv(TAG_BIT_STRING, &pk_bitstring)].concat(),
    );

    // 8. Extensions
    let mut extensions = Vec::new();
    if let Some(uri) = san_uri {
        let gn_uri = der_tlv(0x86, uri.as_bytes());
        let gn_seq = der_tlv(TAG_SEQUENCE, &gn_uri);
        let ext = der_tlv(
            TAG_SEQUENCE,
            &[
                der_tlv(TAG_OID, &encode_oid(OID_SUBJECT_ALT_NAME)),
                der_tlv(TAG_OCTET_STRING, &gn_seq),
            ]
            .concat(),
        );
        extensions.push(ext);
    }
    for (oid, val) in fulcio_exts {
        let inner = der_tlv(TAG_UTF8_STRING, val.as_bytes());
        let ext = der_tlv(
            TAG_SEQUENCE,
            &[
                der_tlv(TAG_OID, &encode_oid(oid)),
                der_tlv(TAG_OCTET_STRING, &inner),
            ]
            .concat(),
        );
        extensions.push(ext);
    }

    let mut tbs_content = [version, serial, sig_algo.clone(), issuer, validity, subject, spki].concat();
    if !extensions.is_empty() {
        let ext_seq = der_tlv(TAG_SEQUENCE, &extensions.concat());
        let ext_context = der_tlv(TAG_CONTEXT_3, &ext_seq);
        tbs_content.extend_from_slice(&ext_context);
    }
    let tbs = der_tlv(TAG_SEQUENCE, &tbs_content);

    // Sign TBSCertificate
    let sig_bytes = signer(&tbs);
    let mut sig_bitstring = vec![0x00]; // 0 unused bits
    sig_bitstring.extend_from_slice(&sig_bytes);

    der_tlv(
        TAG_SEQUENCE,
        &[tbs, sig_algo, der_tlv(TAG_BIT_STRING, &sig_bitstring)].concat(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_der_length_boundaries() {
        assert_eq!(encode_der_length(0), vec![0x00]);
        assert_eq!(encode_der_length(127), vec![0x7F]);
        assert_eq!(encode_der_length(128), vec![0x81, 0x80]);
        assert_eq!(encode_der_length(255), vec![0x81, 0xFF]);
        assert_eq!(encode_der_length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(encode_der_length(0xFFFF), vec![0x82, 0xFF, 0xFF]);
        assert_eq!(encode_der_length(0x10000), vec![0x83, 0x01, 0x00, 0x00]);
        assert_eq!(encode_der_length(0xFF_FFFF), vec![0x83, 0xFF, 0xFF, 0xFF]);
        // Over 16MB requires 4 length octets (0x84)
        assert_eq!(
            encode_der_length(0x100_0000),
            vec![0x84, 0x01, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encode_der_length(0x1234_5678),
            vec![0x84, 0x12, 0x34, 0x56, 0x78]
        );
    }

    #[test]
    fn test_oid_encode_decode_roundtrip_all_arcs() {
        let test_cases = [
            "1.2.840.10045.2.1",
            "1.3.6.1.4.1.57264.1.1",
            "2.5.4.3",
            "2.999.1",
            "0.9.2342.19200300.100.1.1",
        ];
        for oid in test_cases {
            let encoded = encode_oid(oid);
            let decoded = decode_oid(&encoded);
            assert_eq!(decoded, oid);
        }
    }

    #[test]
    fn test_oid_malformed_handling() {
        assert_eq!(decode_oid(&[]), "");
        // Continuation bit set on last byte (truncated VLQ)
        assert_eq!(decode_oid(&[0x2A, 0x86]), "");
        // First byte continuation bit set but truncated
        assert_eq!(decode_oid(&[0x81]), "");
    }
}
