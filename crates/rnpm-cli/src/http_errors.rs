//! npm-compatible rendering of registry HTTP failures.
//!
//! Mirrors npm-registry-fetch's `check-response.js` / `errors.js` (which error
//! class a response maps to) and npm's `lib/utils/error-message.js` (how the
//! E401/EOTP/E404 cases are printed).

static NODE_BUILTINS: &str = include_str!("data/node-builtin-modules.txt");

/// The `error` field of a JSON error body, as npm's `HttpErrorGeneral` uses it.
pub(crate) fn body_error(body: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    match parsed.get("error")? {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Null | serde_json::Value::Bool(false) => None,
        serde_json::Value::String(_) => None,
        other => Some(other.to_string()),
    }
}

/// `HttpErrorGeneral.message`: `<status> <statusText> - <METHOD> <url>[ - <body.error>]`.
pub(crate) fn general_message(method: &str, url: &str, status: reqwest::StatusCode, body: &str) -> String {
    let reason = status.canonical_reason().unwrap_or("");
    let mut msg = format!("{} {} - {} {}", status.as_u16(), reason, method.to_ascii_uppercase(), url);
    if let Some(err) = body_error(body) {
        msg.push_str(" - ");
        msg.push_str(&err);
    }
    msg
}

/// Problems validate-npm-package-name reports (errors first, then warnings).
pub(crate) fn package_name_problems(name: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    if name.is_empty() {
        errors.push("name length must be greater than zero".to_string());
    }
    if name.starts_with('.') {
        errors.push("name cannot start with a period".to_string());
    }
    if name.starts_with('-') {
        errors.push("name cannot start with a hyphen".to_string());
    }
    if name.starts_with('_') {
        errors.push("name cannot start with an underscore".to_string());
    }
    if name.trim() != name {
        errors.push("name cannot contain leading or trailing spaces".to_string());
    }
    for excluded in ["node_modules", "favicon.ico"] {
        if name.to_lowercase() == excluded {
            errors.push(format!("{excluded} is not a valid package name"));
        }
    }
    let lower = name.to_lowercase();
    if NODE_BUILTINS.lines().any(|b| b == lower) {
        warnings.push(format!("{name} is a core module name"));
    }
    if name.encode_utf16().count() > 214 {
        warnings.push("name can no longer contain more than 214 characters".to_string());
    }
    if lower != name {
        warnings.push("name can no longer contain capital letters".to_string());
    }
    let last = name.rsplit('/').next().unwrap_or(name);
    if last.chars().any(|c| "~'!()*".contains(c)) {
        warnings.push("name can no longer contain special characters (\"~'!()*\")".to_string());
    }
    if encode_uri_component(name) != name {
        let scoped = name
            .strip_prefix('@')
            .and_then(|rest| rest.split_once('/'))
            .filter(|(user, pkg)| !user.is_empty() && !pkg.is_empty() && !pkg.contains('/'));
        let mut ok = false;
        if let Some((user, pkg)) = scoped {
            if pkg.starts_with('.') {
                errors.push("name cannot start with a period".to_string());
            }
            ok = encode_uri_component(user) == user && encode_uri_component(pkg) == pkg;
        }
        if !ok {
            errors.push("name can only contain URL-friendly characters".to_string());
        }
    }
    errors.extend(warnings);
    errors
}

/// JavaScript `encodeURIComponent`.
pub(crate) fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// npm's E404 block for a failed request on `pkgid` (`name@rawSpec`).
pub(crate) fn e404_block(message: &str, pkgid: Option<&str>) -> String {
    let summary = message.strip_prefix("404").map(str::trim_start).unwrap_or(message);
    let mut out = format!("npm error code E404\nnpm error 404 {summary}");
    if let Some(pkgid) = pkgid.filter(|p| *p != "-") {
        let name = match pkgid.char_indices().skip(1).find(|(_, c)| *c == '@') {
            Some((i, _)) => &pkgid[..i],
            None => pkgid,
        };
        out.push_str("\nnpm error 404");
        out.push_str(&format!(
            "\nnpm error 404  The requested resource '{pkgid}' could not be found or you do not have permission to access it."
        ));
        let problems = package_name_problems(name);
        if !problems.is_empty() {
            out.push_str("\nnpm error 404 This package name is not valid, because ");
            for (i, p) in problems.iter().enumerate() {
                out.push_str(&format!("\nnpm error 404  {}. {p}", i + 1));
            }
        }
        out.push_str("\nnpm error 404\nnpm error 404 Note that you can also install from a\nnpm error 404 tarball, folder, http url, or git url.");
    }
    out
}

/// npm-registry-fetch's `packageName(href)`: the package a registry URL names.
pub(crate) fn package_name_from_url(url: &reqwest::Url) -> Option<String> {
    let path = url.path().strip_prefix('/').unwrap_or(url.path());
    if path.starts_with('-') {
        return None;
    }
    let parts: Vec<&str> = path.split('/').collect();
    let index = match parts.iter().position(|p| *p == "_rewrite") {
        Some(i) => i + 1,
        None => parts.len() - 1,
    };
    let raw = parts.get(index)?;
    Some(percent_decode(raw))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// How npm classifies a 401 (check-response.js), rendered per error-message.js.
/// Returns `None` for any other status.
pub(crate) fn auth_error_block(
    method: &str,
    url: &str,
    status: reqwest::StatusCode,
    www_authenticate: Option<&str>,
    body: &str,
) -> Option<String> {
    if status.as_u16() != 401 {
        return None;
    }
    let parsed: Option<serde_json::Value> = serde_json::from_str(body).ok();
    let challenge: Vec<String> = www_authenticate
        .map(|h| h.split(',').map(|s| s.trim_start().to_ascii_lowercase()).collect())
        .unwrap_or_default();
    let general = general_message(method, url, status, body);
    let (code, message) = if www_authenticate.is_some() {
        if challenge.iter().any(|s| s == "ipaddress") {
            ("EAUTHIP", "Login is not allowed from your IP address".to_string())
        } else if challenge.iter().any(|s| s == "otp") {
            ("EOTP", "OTP required for authentication".to_string())
        } else {
            ("E401", format!("Unable to authenticate, need: {}", www_authenticate.unwrap_or_default()))
        }
    } else if body.contains("one-time pass") {
        ("EOTP", "OTP required for authentication".to_string())
    } else {
        ("E401", general)
    };
    if code == "EAUTHIP" {
        return Some(format!("npm error code EAUTHIP\nnpm error {message}"));
    }
    if code == "EOTP" || message.contains("one-time pass") {
        let auth_url = parsed.as_ref().and_then(|v| v.get("authUrl")).and_then(|v| v.as_str());
        let done_url = parsed.as_ref().and_then(|v| v.get("doneUrl")).and_then(|v| v.as_str());
        return Some(match (auth_url, done_url) {
            (Some(auth), Some(done)) => format!(
                "npm error code {code}\nnpm error This operation requires a one-time password.\nnpm error Open this URL in your browser to authenticate:\nnpm error   {auth}\nnpm error\nnpm error After authenticating, your token can be retrieved from:\nnpm error   {done}"
            ),
            _ => format!(
                "npm error code {code}\nnpm error This operation requires a one-time password from your authenticator.\nnpm error You can provide a one-time password by passing --otp=<code> to the command you ran.\nnpm error If you already provided a one-time password then it is likely that you either typoed it, or it timed out. Please try again."
            ),
        });
    }
    let scheme: Vec<&str> = www_authenticate
        .map(|h| h.split([',', ' ', '\t']).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    Some(if scheme.contains(&"Bearer") {
        "npm error code E401\nnpm error Unable to authenticate, your authentication token seems to be invalid.\nnpm error To correct this please try logging in again with:\nnpm error   npm login".to_string()
    } else if scheme.contains(&"Basic") {
        "npm error code E401\nnpm error Incorrect or missing password.\nnpm error If you were trying to login, change your password, create an authentication token or enable two-factor authentication then that means you likely typed your password in incorrectly.\nnpm error Please try again, or recover your password at:\nnpm error   https://www.npmjs.com/forgot\nnpm error\nnpm error If you were doing some other operation then your saved credentials are probably out of date.\nnpm error To correct this please try logging in again with:\nnpm error   npm login".to_string()
    } else {
        format!("npm error code E401\nnpm error {message}")
    })
}

/// True when an error block is npm's EOTP failure, which `otplease` may retry.
pub(crate) fn is_otp_error(err: &anyhow::Error) -> bool {
    err.to_string().starts_with("npm error code EOTP")
}

/// npm's `otplease` prompt: only on an interactive terminal, mirroring
/// `read.otp('This operation requires a one-time password.\nEnter OTP:')`.
pub(crate) fn prompt_otp() -> Option<String> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return None;
    }
    let mut stdout = std::io::stdout();
    let _ = write!(stdout, "This operation requires a one-time password.\nEnter OTP: ");
    let _ = stdout.flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).ok()?;
    let otp = line.trim().to_string();
    (!otp.is_empty()).then_some(otp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_problems_match_validate_npm_package_name() {
        assert!(package_name_problems("express").is_empty());
        assert!(package_name_problems("@scope/pkg").is_empty());
        assert_eq!(package_name_problems("BadName"), vec!["name can no longer contain capital letters"]);
        assert_eq!(package_name_problems("http"), vec!["http is a core module name"]);
        assert_eq!(
            package_name_problems("_x y"),
            vec!["name cannot start with an underscore", "name can only contain URL-friendly characters"]
        );
    }

    #[test]
    fn otp_detection_follows_check_response() {
        let s = reqwest::StatusCode::UNAUTHORIZED;
        let block = auth_error_block("PUT", "u", s, Some("OTP"), "{}").unwrap();
        assert!(block.starts_with("npm error code EOTP\n"));
        let block = auth_error_block("PUT", "u", s, None, "{\"error\":\"one-time pass required\"}").unwrap();
        assert!(block.starts_with("npm error code EOTP\n"));
        let block = auth_error_block("PUT", "u", s, Some("Bearer realm=\"x\""), "{}").unwrap();
        assert!(block.contains("token seems to be invalid"));
        let block = auth_error_block("PUT", "u", s, None, "{\"error\":\"nope\"}").unwrap();
        assert_eq!(block, "npm error code E401\nnpm error 401 Unauthorized - PUT u - nope");
    }

    #[test]
    fn package_name_from_registry_urls() {
        let u = reqwest::Url::parse("http://r/@s%2fp").unwrap();
        assert_eq!(package_name_from_url(&u).as_deref(), Some("@s/p"));
        let u = reqwest::Url::parse("http://r/-/package/x/dist-tags").unwrap();
        assert_eq!(package_name_from_url(&u), None);
    }
}
