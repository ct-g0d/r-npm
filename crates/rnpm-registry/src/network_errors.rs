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
        ("ENOTFOUND", Some("getaddrinfo"), format!("getaddrinfo ENOTFOUND {host}"))
    } else if kind == Some(ErrorKind::ConnectionRefused) {
        let port = url.port_or_known_default()?;
        ("ECONNREFUSED", Some("connect"), format!("connect ECONNREFUSED {host}:{port}"))
    } else if error.is_timeout() {
        // minipass-fetch's request timer has no system syscall/errno.
        return Some(("FETCH_ERROR", format!("errno FETCH_ERROR\nnpm error network timeout at: {url}")));
    } else if kind == Some(ErrorKind::TimedOut) {
        ("ETIMEDOUT", Some("connect"), format!("connect ETIMEDOUT {host}:{}", url.port_or_known_default()?))
    } else if matches!(kind, Some(ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::UnexpectedEof))
        || format!("{error:?}").contains("IncompleteMessage")
    {
        ("ECONNRESET", None, "socket hang up".into())
    } else {
        return None;
    };
    let mut lines = Vec::new();
    if let Some(syscall) = syscall {
        lines.push(format!("syscall {syscall}"));
    }
    lines.push(format!("errno {code}"));
    let message = format!("request to {url} failed, reason: {reason}");
    if code == "ECONNREFUSED" {
        lines.extend([
            format!("FetchError: {message}"),
            "{".into(),
            format!("  code: '{code}',"),
            format!("  errno: '{code}',"),
            "  syscall: 'connect',".into(),
            format!("  address: '{host}',"),
            format!("  port: {},", url.port_or_known_default()?),
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
    Some((code, lines.join("\nnpm error ").replace("npm error \n", "npm error\n")))
}

/// Retain the npm error contract through string-based metadata-provider errors.
pub fn format_http(error: &reqwest::Error) -> String {
    if let Some((code, message)) = diagnostic(error) {
        format!("npm error code {code}\nnpm error {message}")
    } else {
        format!("HTTP error: {error}")
    }
}
