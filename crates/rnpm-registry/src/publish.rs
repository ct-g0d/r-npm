use crate::client::encode_package_name;
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use url::Url;

/// Tarball metadata and bytes for publish payload attachment.
#[derive(Debug, Clone)]
pub struct PublishTarballData<'a> {
    pub filename: &'a str,
    pub bytes: &'a [u8],
    pub shasum: &'a str,
    pub integrity: &'a str,
}

/// Options for generating npm publish payload document.
#[derive(Debug, Clone)]
pub struct PublishPayloadOptions<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub description: Option<&'a str>,
    pub tag: &'a str,
    pub access: Option<&'a str>,
    pub manifest: &'a serde_json::Value,
    pub tarball: PublishTarballData<'a>,
    pub registry_url: &'a Url,
    pub provenance_attestation: Option<&'a serde_json::Value>,
}

/// CouchDB/npm registry attachment format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishAttachment {
    pub content_type: String,
    pub data: String,
    pub length: usize,
    pub shasum: String,
    pub integrity: String,
}

/// Construct the canonical npm registry HTTP PUT body.
///
/// Payload format: JSON object with:
/// - `_id`: package name (e.g. `foo` or `@scope/foo`)
/// - `name`: package name
/// - `description`: package description
/// - `dist-tags`: `{ [tag]: version }`
/// - `versions`: `{ [version]: manifest_with_dist }`
/// - `_attachments`: containing base64-encoded tarball with shasum and integrity
/// - `access`: public or restricted (optional)
pub fn create_publish_payload(opts: &PublishPayloadOptions) -> serde_json::Value {
    let base = opts.registry_url.as_str().trim_end_matches('/');
    let encoded_pkg = encode_package_name(opts.name);
    let tarball_url = format!(
        "{base}/{encoded_pkg}/-/{filename}",
        filename = opts.tarball.filename
    );

    let mut dist = serde_json::json!({
        "shasum": opts.tarball.shasum,
        "integrity": opts.tarball.integrity,
        "tarball": tarball_url,
    });

    if let Some(attestation) = opts.provenance_attestation {
        if let Some(dist_obj) = dist.as_object_mut() {
            dist_obj.insert("attestations".to_string(), attestation.clone());
        }
    }

    let mut manifest_version = match opts.manifest {
        serde_json::Value::Object(map) => serde_json::Value::Object(map.clone()),
        _ => serde_json::json!({}),
    };

    if let Some(map) = manifest_version.as_object_mut() {
        map.insert(
            "_id".to_string(),
            serde_json::json!(format!("{}@{}", opts.name, opts.version)),
        );
        map.insert("name".to_string(), serde_json::json!(opts.name));
        map.insert("version".to_string(), serde_json::json!(opts.version));
        if let Some(desc) = opts.description {
            map.insert("description".to_string(), serde_json::json!(desc));
        }
        map.insert("dist".to_string(), dist);

        if let Some(access) = opts.access {
            let mut pub_cfg = match map.get("publishConfig") {
                Some(serde_json::Value::Object(cfg)) => cfg.clone(),
                _ => serde_json::Map::new(),
            };
            pub_cfg.insert("access".to_string(), serde_json::json!(access));
            map.insert(
                "publishConfig".to_string(),
                serde_json::Value::Object(pub_cfg),
            );
        }
    }

    let encoded_tarball = BASE64.encode(opts.tarball.bytes);

    let attachment = serde_json::json!({
        "content_type": "application/octet-stream",
        "data": encoded_tarball,
        "length": opts.tarball.bytes.len(),
        "shasum": opts.tarball.shasum,
        "integrity": opts.tarball.integrity,
    });

    let mut doc = serde_json::json!({
        "_id": opts.name,
        "name": opts.name,
        "description": opts.description.unwrap_or(""),
        "dist-tags": {
            opts.tag: opts.version,
        },
        "versions": {
            opts.version: manifest_version,
        },
        "_attachments": {
            opts.tarball.filename: attachment,
        }
    });

    if let Some(access) = opts.access {
        if let Some(doc_obj) = doc.as_object_mut() {
            doc_obj.insert("access".to_string(), serde_json::json!(access));
        }
    }

    doc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_publish_payload_unscoped() {
        let registry_url = Url::parse("https://registry.npmjs.org/").unwrap();
        let manifest = serde_json::json!({
            "name": "my-pkg",
            "version": "1.0.0",
            "description": "A sample package",
            "main": "index.js",
        });

        let tarball_bytes = b"fake tarball data";
        let tarball = PublishTarballData {
            filename: "my-pkg-1.0.0.tgz",
            bytes: tarball_bytes,
            shasum: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            integrity: "sha512-dummy==",
        };

        let opts = PublishPayloadOptions {
            name: "my-pkg",
            version: "1.0.0",
            description: Some("A sample package"),
            tag: "latest",
            access: Some("public"),
            manifest: &manifest,
            tarball,
            registry_url: &registry_url,
            provenance_attestation: None,
        };

        let payload = create_publish_payload(&opts);

        assert_eq!(payload["_id"], "my-pkg");
        assert_eq!(payload["name"], "my-pkg");
        assert_eq!(payload["description"], "A sample package");
        assert_eq!(payload["dist-tags"]["latest"], "1.0.0");
        assert_eq!(payload["access"], "public");

        // Verify versions
        let version_doc = &payload["versions"]["1.0.0"];
        assert_eq!(version_doc["_id"], "my-pkg@1.0.0");
        assert_eq!(version_doc["name"], "my-pkg");
        assert_eq!(version_doc["version"], "1.0.0");
        assert_eq!(
            version_doc["dist"]["shasum"],
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(version_doc["dist"]["integrity"], "sha512-dummy==");
        assert_eq!(
            version_doc["dist"]["tarball"],
            "https://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz"
        );

        // Verify attachments
        let attachment = &payload["_attachments"]["my-pkg-1.0.0.tgz"];
        assert_eq!(attachment["content_type"], "application/octet-stream");
        assert_eq!(attachment["length"], tarball_bytes.len());
        assert_eq!(
            attachment["shasum"],
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(attachment["integrity"], "sha512-dummy==");
        assert_eq!(attachment["data"], BASE64.encode(tarball_bytes));
    }

    #[test]
    fn test_create_publish_payload_scoped() {
        let registry_url = Url::parse("https://registry.npmjs.org/").unwrap();
        let manifest = serde_json::json!({
            "name": "@my-org/my-pkg",
            "version": "2.1.0-beta.1",
        });

        let tarball_bytes = b"scoped tarball content";
        let tarball = PublishTarballData {
            filename: "my-org-my-pkg-2.1.0-beta.1.tgz",
            bytes: tarball_bytes,
            shasum: "aabbcc112233",
            integrity: "sha512-scoped==",
        };

        let opts = PublishPayloadOptions {
            name: "@my-org/my-pkg",
            version: "2.1.0-beta.1",
            description: None,
            tag: "next",
            access: Some("restricted"),
            manifest: &manifest,
            tarball,
            registry_url: &registry_url,
            provenance_attestation: None,
        };

        let payload = create_publish_payload(&opts);

        assert_eq!(payload["_id"], "@my-org/my-pkg");
        assert_eq!(payload["name"], "@my-org/my-pkg");
        assert_eq!(payload["description"], "");
        assert_eq!(payload["dist-tags"]["next"], "2.1.0-beta.1");
        assert_eq!(payload["access"], "restricted");

        let version_doc = &payload["versions"]["2.1.0-beta.1"];
        assert_eq!(
            version_doc["dist"]["tarball"],
            "https://registry.npmjs.org/@my-org%2fmy-pkg/-/my-org-my-pkg-2.1.0-beta.1.tgz"
        );
    }
}
