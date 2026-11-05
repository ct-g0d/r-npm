/// Dangerous command pattern analyzer for lifecycle script sandboxing.
///
/// Inspects shell scripts and command invocations for:
/// 1. Unauthorized network calls (`curl`, `wget`, `Invoke-WebRequest`, `Invoke-Expression`, `iwr`, `iex`, `nc`, `bash -i`, `sh -i`).
/// 2. Obfuscated execution and base64 decoding (`base64 -d`, `FromBase64String`, `eval(`).
/// 3. Sensitive file and directory path access (`~/.ssh`, `~/.npmrc`, `~/.aws`, `%USERPROFILE%/.ssh`, `/etc/passwd`, `/etc/shadow`).
pub struct CommandPatternAnalyzer;

impl CommandPatternAnalyzer {
    /// Analyzes a script command string. Returns `Ok(())` if clean, or `Err(reason)` if a dangerous pattern is detected.
    pub fn analyze(cmd: &str) -> Result<(), String> {
        if let Some(reason) = check_dangerous_command_patterns(cmd) {
            Err(reason)
        } else {
            Ok(())
        }
    }
}

/// Inspects a command string and returns `Some(reason)` if a dangerous pattern is found.
pub fn check_dangerous_command_patterns(cmd: &str) -> Option<String> {
    let lower = cmd.to_ascii_lowercase();
    let normalized_paths = lower.replace('\\', "/");

    // 1. Sensitive path accesses
    let sensitive_paths = [
        ("~/.ssh", "Access to SSH keys directory (~/.ssh)"),
        ("~/.npmrc", "Access to user npm configuration (~/.npmrc)"),
        ("~/.aws", "Access to AWS credentials directory (~/.aws)"),
        ("%userprofile%/.ssh", "Access to Windows user SSH keys (%USERPROFILE%/.ssh)"),
        ("%userprofile%/.npmrc", "Access to Windows user npm config (%USERPROFILE%/.npmrc)"),
        ("%userprofile%/.aws", "Access to Windows user AWS credentials (%USERPROFILE%/.aws)"),
        ("/etc/passwd", "Access to system accounts file (/etc/passwd)"),
        ("/etc/shadow", "Access to system password hashes (/etc/shadow)"),
        ("$home/.ssh", "Access to user SSH keys ($HOME/.ssh)"),
        ("${home}/.ssh", "Access to user SSH keys (${HOME}/.ssh)"),
        ("$home/.npmrc", "Access to user npm config ($HOME/.npmrc)"),
        ("${home}/.npmrc", "Access to user npm config (${HOME}/.npmrc)"),
        ("$home/.aws", "Access to user AWS credentials ($HOME/.aws)"),
        ("${home}/.aws", "Access to user AWS credentials (${HOME}/.aws)"),
    ];

    for (pattern, description) in sensitive_paths {
        if normalized_paths.contains(pattern) {
            return Some(format!("Sensitive path access detected: {description}"));
        }
    }

    // 2. Obfuscated execution & base64 decoding
    if lower.contains("base64 -d") || lower.contains("base64 --decode") {
        return Some("Obfuscated execution detected: base64 decoding invocation ('base64 -d')".to_string());
    }
    if lower.contains("frombase64string") {
        return Some("Obfuscated execution detected: .NET/PowerShell base64 decoder ('FromBase64String')".to_string());
    }
    if lower.contains("eval(") {
        return Some("Obfuscated or dynamic code execution detected: 'eval('".to_string());
    }

    // 3. Unauthorized network calls and interactive shells
    let direct_phrases = [
        ("invoke-webrequest", "PowerShell web download command ('Invoke-WebRequest')"),
        ("invoke-expression", "PowerShell arbitrary expression execution ('Invoke-Expression')"),
        ("bash -i", "Interactive reverse shell invocation ('bash -i')"),
        ("sh -i", "Interactive reverse shell invocation ('sh -i')"),
        ("zsh -i", "Interactive reverse shell invocation ('zsh -i')"),
    ];

    for (phrase, desc) in direct_phrases {
        if lower.contains(phrase) {
            return Some(format!("Unauthorized network or interactive shell detected: {desc}"));
        }
    }

    // Token-based detection for network utilities: curl, wget, nc, netcat, ncat, iwr, iex
    if let Some(util) = detect_disallowed_command_token(&lower) {
        return Some(format!("Unauthorized network utility detected: '{util}'"));
    }

    None
}

/// Splits a shell command string into sub-command segments (delimited by ;, &&, ||, |, &, \n, etc.)
/// and checks if any executed command token is a disallowed utility.
fn detect_disallowed_command_token(lower_cmd: &str) -> Option<&'static str> {
    // Split by shell command boundaries and pipes
    for segment in lower_cmd.split(|c: char| c == ';' || c == '&' || c == '|' || c == '\n' || c == '\r' || c == '`' || c == '(' || c == ')') {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Take the first whitespace-separated token of the clause
        let first_token = trimmed.split_whitespace().next().unwrap_or_default();
        let clean_token = clean_command_token(first_token);

        for &disallowed in &["curl", "wget", "nc", "netcat", "ncat", "iwr", "iex"] {
            if clean_token == disallowed {
                return Some(disallowed);
            }
        }

        // Also check subshells or command substitution within the segment like `$(curl ...)`
        for word in trimmed.split_whitespace() {
            let clean_word = clean_command_token(word);
            for &disallowed in &["curl", "wget", "nc", "netcat", "ncat", "iwr", "iex"] {
                if clean_word == disallowed {
                    return Some(disallowed);
                }
            }
        }
    }

    None
}

fn clean_command_token(raw: &str) -> &str {
    let mut s = raw.trim();
    // Strip quotes and parentheses
    s = s.trim_matches(|c: char| c == '"' || c == '\'' || c == '(' || c == ')' || c == '$');

    // Strip path prefixes: e.g. /usr/bin/curl -> curl, C:\curl.exe -> curl
    if let Some(pos) = s.rfind(|c: char| c == '/' || c == '\\') {
        s = &s[pos + 1..];
    }

    // Strip executable extensions: .exe, .cmd, .bat
    if let Some(stripped) = s.strip_suffix(".exe") {
        s = stripped;
    } else if let Some(stripped) = s.strip_suffix(".cmd") {
        s = stripped;
    } else if let Some(stripped) = s.strip_suffix(".bat") {
        s = stripped;
    }

    s
}
