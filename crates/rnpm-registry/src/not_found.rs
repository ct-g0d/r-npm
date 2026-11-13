//! Remembers registry 404 responses for packuments so the CLI can render
//! npm's E404 message (URL and `error` body field) after resolution fails.

use std::collections::HashMap;
use std::sync::Mutex;

static NOT_FOUND: Mutex<Option<HashMap<String, (String, String)>>> = Mutex::new(None);

/// Records the URL and body of a 404 packument response for `package`.
pub fn record(package: &str, url: &str, body: &str) {
    if let Ok(mut guard) = NOT_FOUND.lock() {
        guard
            .get_or_insert_with(HashMap::new)
            .insert(package.to_string(), (url.to_string(), body.to_string()));
    }
}

/// The URL and body of the recorded 404 for `package`, if any.
pub fn lookup(package: &str) -> Option<(String, String)> {
    NOT_FOUND.lock().ok()?.as_ref()?.get(package).cloned()
}
