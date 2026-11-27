use std::error::Error;
use std::io::ErrorKind;

/// Match minipass-fetch's system errors and npm's error-message.js display.
pub fn diagnostic(error: &reqwest::Error) -> Option<(&'static str, String)> {
    let url = error.url()?;
    let host = url.host_str()?;
    let mut source = error.source();
    let mut kind = None;
    let mut dns = false;
    while let Some(cause) = source {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            kind = Some(io.kind());
        }
        dns |= cause.to_string().to_ascii_lowercase().contains("dns error");
        source = cause.source();
    }
    let (code, syscall, reason) = if dns {
        (
            "ENOTFOUND",
            Some("getaddrinfo"),
            format!("getaddrinfo ENOTFOUND {host}"),
        )
    } else if kind == Some(ErrorKind::ConnectionRefused) {
        let port = url.port_or_known_default()?;
        (
            "ECONNREFUSED",
            Some("connect"),
            format!("connect ECONNREFUSED {host}:{port}"),
        )
    } else if kind == Some(ErrorKind::TimedOut) || (error.is_timeout() && error.is_connect()) {
        (
            "ETIMEDOUT",
            Some("connect"),
            format!("connect ETIMEDOUT {host}:{}", url.port_or_known_default()?),
        )
    } else if error.is_timeout() {
        // minipass-fetch's request timer has no system syscall/errno.
        return Some((
            "FETCH_ERROR",
            format!("errno FETCH_ERROR\nnpm error network timeout at: {url}"),
        ));
    } else if matches!(
        kind,
        Some(ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::UnexpectedEof)
    ) || format!("{error:?}").contains("IncompleteMessage")
    {
        ("ECONNRESET", None, "socket hang up".into())
    } else {
        return None;
    };
    let message = format_diagnostic_message(url, host, code, syscall, &reason);
    Some((code, message))
}

fn format_diagnostic_message(
    url: &url::Url,
    host: &str,
    code: &str,
    syscall: Option<&str>,
    reason: &str,
) -> String {
    let mut lines = Vec::new();
    if let Some(syscall) = syscall {
        lines.push(format!("syscall {syscall}"));
    }
    lines.push(format!("errno {code}"));
    let message = format!("request to {url} failed, reason: {reason}");
    if code == "ECONNREFUSED" {
        let port = url.port_or_known_default().unwrap_or(80);
        lines.extend([
            format!("FetchError: {message}"),
            "{".into(),
            format!("  code: '{code}',"),
            format!("  errno: '{code}',"),
            "  syscall: 'connect',".into(),
            format!("  address: '{host}',"),
            format!("  port: {port},"),
            "  type: 'system'".into(),
            "}".into(),
            String::new(),
            "If you are behind a proxy, please make sure that the 'proxy' config is set properly.  See: 'npm help config'".into(),
        ]);
    } else {
        lines.extend([
            format!("network {message}"),
            "network This is a problem related to network connectivity.".into(),
            "network In most cases you are behind a proxy or have bad network settings.".into(),
            "network".into(),
            "network If you are behind a proxy, please make sure that the 'proxy' config is set properly.  See: 'npm help config'".into(),
        ]);
    }
    lines
        .join("\nnpm error ")
        .replace("npm error \n", "npm error\n")
}

/// Format a direct IO/transport error for npm error-contract parity.
pub(crate) fn format_io_error(
    url: &url::Url,
    err: &std::io::Error,
    is_connect_phase: bool,
    is_timeout: bool,
) -> String {
    let Some(host) = url.host_str() else {
        return format!("HTTP error: {err}");
    };
    let port = url.port_or_known_default().unwrap_or(80);
    let kind = err.kind();
    let msg_lower = err.to_string().to_ascii_lowercase();
    let dns = msg_lower.contains("dns")
        || msg_lower.contains("failed to lookup address")
        || msg_lower.contains("no such host")
        || msg_lower.contains("name or service not known")
        || msg_lower.contains("temporary failure in name resolution");

    let (code, syscall, reason) = if dns {
        (
            "ENOTFOUND",
            Some("getaddrinfo"),
            format!("getaddrinfo ENOTFOUND {host}"),
        )
    } else if kind == ErrorKind::ConnectionRefused {
        (
            "ECONNREFUSED",
            Some("connect"),
            format!("connect ECONNREFUSED {host}:{port}"),
        )
    } else if kind == ErrorKind::TimedOut || (is_timeout && is_connect_phase) {
        (
            "ETIMEDOUT",
            Some("connect"),
            format!("connect ETIMEDOUT {host}:{port}"),
        )
    } else if is_timeout {
        return format!("npm error code FETCH_ERROR\nnpm error errno FETCH_ERROR\nnpm error network timeout at: {url}");
    } else if matches!(
        kind,
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof
    ) {
        ("ECONNRESET", None, "socket hang up".into())
    } else {
        return format!("HTTP error: {err}");
    };

    let body = format_diagnostic_message(url, host, code, syscall, &reason);
    format!("npm error code {code}\nnpm error {body}")
}

/// Retain the npm error contract through string-based metadata-provider errors.
pub fn format_http(error: &reqwest::Error) -> String {
    if let Some((code, message)) = diagnostic(error) {
        format!("npm error code {code}\nnpm error {message}")
    } else {
        let mut msg = format!("HTTP error: {error}");
        let mut source = error.source();
        while let Some(cause) = source {
            let cause_str = cause.to_string();
            if !cause_str.is_empty() && !msg.contains(&cause_str) {
                msg.push_str(&format!(": {cause_str}"));
            }
            source = cause.source();
        }
        msg
    }
}
