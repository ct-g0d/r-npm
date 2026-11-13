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
///
/// Build the publish document like libnpmpublish's `buildMetadata`: the
/// manifest is stored as-is plus `_id` and `dist`, `access` is always
/// present (null when unset), and the tarball URL and attachment key use the
/// raw package name.
pub fn create_publish_payload(opts: &PublishPayloadOptions) -> serde_json::Value {
    let tarball_name = format!("{}-{}.tgz", opts.name, opts.version);
    let tarball_url = opts
        .registry_url
        .join(&format!("{}/-/{tarball_name}", opts.name))
        .map(|u| u.to_string())
        .unwrap_or_else(|_| {
            format!(
                "{}/{}/-/{tarball_name}",
                opts.registry_url.as_str().trim_end_matches('/'),
                opts.name
            )
        });
    let tarball_url = match tarball_url.strip_prefix("https://") {
        Some(rest) => format!("http://{rest}"),
        None => tarball_url,
    };

    let mut dist = serde_json::Map::new();
    if let Some(serde_json::Value::Object(existing)) = opts.manifest.get("dist") {
        dist.extend(existing.clone());
    }
    dist.insert("integrity".into(), serde_json::json!(opts.tarball.integrity));
    dist.insert("shasum".into(), serde_json::json!(opts.tarball.shasum));
    dist.insert("tarball".into(), serde_json::json!(tarball_url));
    if let Some(attestation) = opts.provenance_attestation {
        dist.insert("attestations".into(), attestation.clone());
    }

    let mut manifest = match opts.manifest {
        serde_json::Value::Object(map) => map.clone(),
        _ => serde_json::Map::new(),
    };
    manifest.insert(
        "_id".into(),
        serde_json::json!(format!("{}@{}", opts.name, opts.version)),
    );
    manifest.insert("dist".into(), serde_json::Value::Object(dist));

    let mut doc = serde_json::Map::new();
    doc.insert("_id".into(), serde_json::json!(opts.name));
    doc.insert("name".into(), serde_json::json!(opts.name));
    if let Some(desc) = opts.description {
        doc.insert("description".into(), serde_json::json!(desc));
    }
    doc.insert("dist-tags".into(), serde_json::json!({ opts.tag: opts.version }));
    doc.insert(
        "versions".into(),
        serde_json::json!({ opts.version: serde_json::Value::Object(manifest) }),
    );
    doc.insert(
        "access".into(),
        opts.access.map(serde_json::Value::from).unwrap_or(serde_json::Value::Null),
    );
    doc.insert(
        "_attachments".into(),
        serde_json::json!({
            tarball_name: {
                "content_type": "application/octet-stream",
                "data": BASE64.encode(opts.tarball.bytes),
                "length": opts.tarball.bytes.len(),
            }
        }),
    );
    serde_json::Value::Object(doc)
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
        // libnpmpublish rewrites https to http in dist.tarball.
        assert_eq!(
            version_doc["dist"]["tarball"],
            "http://registry.npmjs.org/my-pkg/-/my-pkg-1.0.0.tgz"
        );

        // Verify attachments
        let attachment = &payload["_attachments"]["my-pkg-1.0.0.tgz"];
        assert_eq!(attachment["content_type"], "application/octet-stream");
        assert_eq!(attachment["length"], tarball_bytes.len());
        assert!(attachment.get("shasum").is_none());
        assert!(attachment.get("integrity").is_none());
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
        assert!(payload.get("description").is_none());
        assert_eq!(payload["dist-tags"]["next"], "2.1.0-beta.1");
        assert_eq!(payload["access"], "restricted");

        let version_doc = &payload["versions"]["2.1.0-beta.1"];
        assert_eq!(
            version_doc["dist"]["tarball"],
            "http://registry.npmjs.org/@my-org/my-pkg/-/@my-org/my-pkg-2.1.0-beta.1.tgz"
        );
    }
}
