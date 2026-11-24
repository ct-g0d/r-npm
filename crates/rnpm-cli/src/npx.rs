use std::path::PathBuf;

/// Check if argv[0] matches npx binary names.
/// Matches "npx", "npx.exe", "rnpm-npx", "rnpm-npx.exe" regardless of directory path or case.
pub fn is_npx_argv0(argv0: &str) -> bool {
    let base = argv0
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(argv0)
        .to_ascii_lowercase();
    if base == "npx"
        || base == "npx.exe"
        || base == "rnpm-npx"
        || base == "rnpm-npx.exe"
    {
        return true;
    }
    let stem = base
        .rsplit_once('.')
        .map(|(s, _)| s)
        .unwrap_or(&base);
    stem == "npx" || stem == "rnpm-npx"
}

/// Translates npx CLI arguments into equivalent `rnpm exec` CLI arguments,
/// adhering strictly to `npm 11.20.0` npx argument handling behavior.
///
/// If `--` is encountered, option parsing stops and remaining arguments are forwarded.
/// As soon as a positional argument (the target package / executable) is encountered,
/// `--` is inserted before it and all remaining arguments are forwarded verbatim to the target.
pub fn translate_npx_args(tokens: &[String]) -> Vec<String> {
    let mut result = vec!["exec".to_string()];
    let mut i = 0;
    let mut saw_removed_flags = false;

    while i < tokens.len() {
        let token = &tokens[i];
        let next_token = tokens.get(i + 1).map(|s| s.as_str());

        if token == "--" {
            result.push("--".to_string());
            result.extend(tokens[i + 1..].iter().cloned());
            break;
        }

        if token.starts_with('-') {
            // Check for key=value
            let (key, inline_val) = if let Some(stripped) = token.strip_prefix("--") {
                if let Some((k, v)) = stripped.split_once('=') {
                    (k, Some(v))
                } else {
                    (stripped, None)
                }
            } else if let Some(stripped) = token.strip_prefix('-') {
                if let Some((k, v)) = stripped.split_once('=') {
                    (k, Some(v))
                } else {
                    (stripped, None)
                }
            } else {
                ("", None)
            };

            // Handle removed flags from npm 11.20.0 npx-cli.js
            match key {
                "always-spawn" | "ignore-existing" | "shell-auto-fallback" => {
                    eprintln!("npx: the --{key} argument has been removed.");
                    saw_removed_flags = true;
                    i += 1;
                    continue;
                }
                "npm" | "node-arg" | "n" => {
                    eprintln!("npx: the --{key} argument has been removed.");
                    saw_removed_flags = true;
                    if inline_val.is_none()
                        && next_token.is_some_and(|next| !next.starts_with('-'))
                    {
                        i += 2;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                _ => {}
            }

            match key {
                // Shorthands & aliases
                "y" | "yes" => {
                    if let Some(val) = inline_val {
                        if val == "false" || val == "0" || val == "no" || val == "off" {
                            result.push("--no-yes".to_string());
                        } else {
                            result.push("--yes".to_string());
                        }
                    } else {
                        result.push("--yes".to_string());
                    }
                    i += 1;
                    continue;
                }
                "no" | "no-yes" => {
                    if let Some(val) = inline_val {
                        if val == "false" || val == "0" || val == "no" || val == "off" {
                            result.push("--yes".to_string());
                        } else {
                            result.push("--no-yes".to_string());
                        }
                    } else {
                        result.push("--no-yes".to_string());
                    }
                    i += 1;
                    continue;
                }
                // Match npm 11.20.0 bin/npx-cli.js (`case 'no-install': process.argv[i] = '--yes=false'`)
                "no-install" => {
                    result.push("--no-yes".to_string());
                    i += 1;
                    continue;
                }
                "p" | "package" => {
                    if let Some(val) = inline_val {
                        result.push(format!("--package={val}"));
                        i += 1;
                    } else if let Some(next) = next_token {
                        result.push("--package".to_string());
                        result.push(next.to_string());
                        i += 2;
                    } else {
                        result.push("--package".to_string());
                        i += 1;
                    }
                    continue;
                }
                "c" | "call" => {
                    if let Some(val) = inline_val {
                        result.push(format!("--call={val}"));
                        i += 1;
                    } else if let Some(next) = next_token {
                        result.push("--call".to_string());
                        result.push(next.to_string());
                        i += 2;
                    } else {
                        result.push("--call".to_string());
                        i += 1;
                    }
                    continue;
                }
                "shell" => {
                    if let Some(val) = inline_val {
                        result.push(format!("--script-shell={val}"));
                        i += 1;
                    } else if let Some(next) = next_token {
                        result.push("--script-shell".to_string());
                        result.push(next.to_string());
                        i += 2;
                    } else {
                        result.push("--script-shell".to_string());
                        i += 1;
                    }
                    continue;
                }
                "q" | "quiet" => {
                    result.push("--quiet".to_string());
                    i += 1;
                    continue;
                }
                "offline" => {
                    result.push("--offline".to_string());
                    i += 1;
                    continue;
                }
                "prefer-offline" => {
                    result.push("--prefer-offline".to_string());
                    i += 1;
                    continue;
                }
                "prefer-online" => {
                    result.push("--prefer-online".to_string());
                    i += 1;
                    continue;
                }
                "registry" => {
                    if let Some(val) = inline_val {
                        result.push(format!("--registry={val}"));
                        i += 1;
                    } else if let Some(next) = next_token {
                        result.push("--registry".to_string());
                        result.push(next.to_string());
                        i += 2;
                    } else {
                        result.push("--registry".to_string());
                        i += 1;
                    }
                    continue;
                }
                "cache" => {
                    if let Some(val) = inline_val {
                        result.push(format!("--cache={val}"));
                        i += 1;
                    } else if let Some(next) = next_token {
                        result.push("--cache".to_string());
                        result.push(next.to_string());
                        i += 2;
                    } else {
                        result.push("--cache".to_string());
                        i += 1;
                    }
                    continue;
                }
                "userconfig" => {
                    if let Some(val) = inline_val {
                        result.push(format!("--userconfig={val}"));
                        i += 1;
                    } else if let Some(next) = next_token {
                        result.push("--userconfig".to_string());
                        result.push(next.to_string());
                        i += 2;
                    } else {
                        result.push("--userconfig".to_string());
                        i += 1;
                    }
                    continue;
                }
                "w" | "workspace" => {
                    if let Some(val) = inline_val {
                        result.push(format!("--workspace={val}"));
                        i += 1;
                    } else if let Some(next) = next_token {
                        result.push("--workspace".to_string());
                        result.push(next.to_string());
                        i += 2;
                    } else {
                        result.push("--workspace".to_string());
                        i += 1;
                    }
                    continue;
                }
                "ws" | "workspaces" => {
                    result.push("--workspaces".to_string());
                    i += 1;
                    continue;
                }
                "workspace-root" | "include-workspace-root" => {
                    result.push("--workspace-root".to_string());
                    i += 1;
                    continue;
                }
                "no-prefer-local" => {
                    result.push("--no-prefer-local".to_string());
                    i += 1;
                    continue;
                }
                "v" | "version" => {
                    result.push("--version".to_string());
                    i += 1;
                    continue;
                }
                "h" | "help" => {
                    result.push("--help".to_string());
                    i += 1;
                    continue;
                }
                _ => {
                    // Forward any other flag
                    result.push(token.clone());
                    i += 1;
                    continue;
                }
            }
        } else {
            // Positional argument encountered!
            // In npm 11.20.0: process.argv.splice(i, 0, '--')
            // Put '--' in front of positional arg and stop parsing.
            result.push("--".to_string());
            result.extend(tokens[i..].iter().cloned());
            break;
        }
    }

    if saw_removed_flags {
        eprintln!("See `npm help exec` for more information");
    }

    result
}

/// Pure lookup implementation for finding the companion `rnpm` or `npm` binary.
///
/// Sibling/parent directories of `current_exe` check `["rnpm.exe", "npm.exe"]` (or `["rnpm", "npm"]`)
/// to seamlessly support drop-in installation setups where the binary was named `npm`.
///
/// However, when searching `PATH`, lookup is STRICTLY restricted to `rnpm` / `rnpm.exe`.
/// This prevents standalone Rust `npx` from delegating to Node's JS `/usr/local/bin/npm` if Node's npm
/// appears earlier in `PATH`.
fn is_native_companion_binary(path: &std::path::Path) -> bool {
    if !path.is_file() {
        return false;
    }
    // Reject text/script launchers (e.g. Node's `#!/usr/bin/env node` npm script,
    // or Windows batch/cmd scripts) so standalone Rust `npx` never silently falls
    // back to Node's JS npm.
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut header = [0u8; 2];
    let Ok(()) = file.read_exact(&mut header) else {
        return false;
    };
    if cfg!(windows) {
        &header == b"MZ"
    } else {
        &header != b"#!"
    }
}

pub fn find_rnpm_executable_in(
    current_exe: Option<&std::path::Path>,
    path_dirs: &[PathBuf],
) -> Option<PathBuf> {
    let rnpm_name = if cfg!(windows) { "rnpm.exe" } else { "rnpm" };
    let npm_name = if cfg!(windows) { "npm.exe" } else { "npm" };

    // 1. Prefer `rnpm` everywhere first (sibling, parent, then PATH)
    if let Some(current_exe) = current_exe {
        if let Some(dir) = current_exe.parent() {
            let sibling = dir.join(rnpm_name);
            if sibling.is_file() {
                return Some(sibling);
            }
            if let Some(parent) = dir.parent() {
                let parent_bin = parent.join(rnpm_name);
                if parent_bin.is_file() {
                    return Some(parent_bin);
                }
            }
        }
    }

    for dir in path_dirs {
        let candidate = dir.join(rnpm_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    // 2. Fall back to a renamed native companion `npm` binary beside `npx` (never a `#!` JS launcher)
    if let Some(current_exe) = current_exe {
        if let Some(dir) = current_exe.parent() {
            let sibling_npm = dir.join(npm_name);
            if is_native_companion_binary(&sibling_npm) {
                return Some(sibling_npm);
            }
            if let Some(parent) = dir.parent() {
                let parent_npm = parent.join(npm_name);
                if is_native_companion_binary(&parent_npm) {
                    return Some(parent_npm);
                }
            }
        }
    }

    None
}

/// Locate sibling `rnpm` or `rnpm.exe` binary.
#[allow(dead_code)]
pub fn find_rnpm_executable() -> Option<PathBuf> {
    if let Some(exe) =
        std::env::var_os("RNPM_EXE").or_else(|| std::env::var_os("CARGO_BIN_EXE_rnpm"))
    {
        let p = PathBuf::from(exe);
        if p.is_file() {
            return Some(p);
        }
    }

    let current = std::env::current_exe().ok();
    let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();

    find_rnpm_executable_in(current.as_deref(), &path_dirs)
}

/// Standalone `npx` execution handler.
#[allow(dead_code)]
pub fn run_npx(raw_args: &[String]) -> i32 {
    let tokens = if raw_args.is_empty() {
        &[][..]
    } else {
        &raw_args[1..]
    };

    // Fast-path: standalone npx --version / npx -v
    if tokens.len() == 1 && (tokens[0] == "--version" || tokens[0] == "-v" || tokens[0] == "-V") {
        println!("{}", crate::version::NPM_VERSION);
        return 0;
    }

    let translated = translate_npx_args(tokens);

    let rnpm_exe = match find_rnpm_executable() {
        Some(exe) => exe,
        None => {
            eprintln!(
                "npx error: could not locate rnpm executable (checked sibling directory and PATH)"
            );
            return 1;
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(&rnpm_exe)
            .args(&translated)
            .exec();
        eprintln!("npx error: failed to exec rnpm: {err}");
        1
    }

    #[cfg(windows)]
    {
        let status = std::process::Command::new(&rnpm_exe)
            .args(&translated)
            .status();
        match status {
            Ok(s) => s.code().unwrap_or(1),
            Err(e) => {
                eprintln!("npx error: failed to execute rnpm: {e}");
                1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_npx_argv0() {
        assert!(is_npx_argv0("npx"));
        assert!(is_npx_argv0("npx.exe"));
        assert!(is_npx_argv0("NPX"));
        assert!(is_npx_argv0("NPX.EXE"));
        assert!(is_npx_argv0("rnpm-npx"));
        assert!(is_npx_argv0("rnpm-npx.exe"));
        assert!(is_npx_argv0("/usr/local/bin/npx"));
        assert!(is_npx_argv0("/usr/bin/rnpm-npx"));
        assert!(is_npx_argv0("C:\\Program Files\\nodejs\\npx.exe"));
        assert!(is_npx_argv0("D:\\tools\\rnpm-npx.exe"));

        assert!(!is_npx_argv0("rnpm"));
        assert!(!is_npx_argv0("rnpm.exe"));
        assert!(!is_npx_argv0("npm"));
        assert!(!is_npx_argv0("node"));
        assert!(!is_npx_argv0("my-npx-tool"));
    }

    #[test]
    fn test_translate_npx_args_forwarding() {
        // Positional target followed by flags: flags belong to the tool, NOT npx
        let input: Vec<String> = vec![
            "mytool".into(),
            "--help".into(),
            "--custom-flag".into(),
            "value".into(),
        ];
        let translated = translate_npx_args(&input);
        assert_eq!(
            translated,
            vec!["exec", "--", "mytool", "--help", "--custom-flag", "value"]
        );
    }

    #[test]
    fn test_translate_npx_flags() {
        // -y flag before positional
        let input: Vec<String> = vec!["-y".into(), "cowsay".into(), "moo".into()];
        assert_eq!(
            translate_npx_args(&input),
            vec!["exec", "--yes", "--", "cowsay", "moo"]
        );

        // --no-install
        let input: Vec<String> = vec!["--no-install".into(), "cowsay".into()];
        assert_eq!(
            translate_npx_args(&input),
            vec!["exec", "--no-yes", "--", "cowsay"]
        );

        // --no and --no-yes
        assert_eq!(
            translate_npx_args(&["--no".into(), "cowsay".into()]),
            vec!["exec", "--no-yes", "--", "cowsay"]
        );
        assert_eq!(
            translate_npx_args(&["--no-yes".into(), "cowsay".into()]),
            vec!["exec", "--no-yes", "--", "cowsay"]
        );
        assert_eq!(
            translate_npx_args(&["--no=false".into(), "cowsay".into()]),
            vec!["exec", "--yes", "--", "cowsay"]
        );
        assert_eq!(
            translate_npx_args(&["--no-install=false".into(), "cowsay".into()]),
            vec!["exec", "--no-yes", "--", "cowsay"]
        );

        // -n removed flag (legacy --node-arg switch from npm 11.20.0)
        assert_eq!(
            translate_npx_args(&["-n=val".into(), "cowsay".into()]),
            vec!["exec", "--", "cowsay"]
        );
        assert_eq!(
            translate_npx_args(&["-n".into(), "val".into(), "cowsay".into()]),
            vec!["exec", "--", "cowsay"]
        );

        // --yes=false / --yes=0 / -y=false / -y=0 / --yes=true / --yes=1 / -y=true / -y=1
        assert_eq!(
            translate_npx_args(&["--yes=false".into(), "nonexistent-pkg".into()]),
            vec!["exec", "--no-yes", "--", "nonexistent-pkg"]
        );
        assert_eq!(
            translate_npx_args(&["--yes=0".into(), "nonexistent-pkg".into()]),
            vec!["exec", "--no-yes", "--", "nonexistent-pkg"]
        );
        assert_eq!(
            translate_npx_args(&["-y=false".into(), "nonexistent-pkg".into()]),
            vec!["exec", "--no-yes", "--", "nonexistent-pkg"]
        );
        assert_eq!(
            translate_npx_args(&["-y=0".into(), "nonexistent-pkg".into()]),
            vec!["exec", "--no-yes", "--", "nonexistent-pkg"]
        );
        assert_eq!(
            translate_npx_args(&["--yes=true".into(), "cowsay".into()]),
            vec!["exec", "--yes", "--", "cowsay"]
        );
        assert_eq!(
            translate_npx_args(&["--yes=1".into(), "cowsay".into()]),
            vec!["exec", "--yes", "--", "cowsay"]
        );
        assert_eq!(
            translate_npx_args(&["-y=true".into(), "cowsay".into()]),
            vec!["exec", "--yes", "--", "cowsay"]
        );
        assert_eq!(
            translate_npx_args(&["-y=1".into(), "cowsay".into()]),
            vec!["exec", "--yes", "--", "cowsay"]
        );
        assert_eq!(
            translate_npx_args(&["--no-yes=false".into(), "cowsay".into()]),
            vec!["exec", "--yes", "--", "cowsay"]
        );

        // -p / --package
        assert_eq!(
            translate_npx_args(&["-p".into(), "local-pkg".into(), "mytool".into()]),
            vec!["exec", "--package", "local-pkg", "--", "mytool"]
        );
        assert_eq!(
            translate_npx_args(&["--package=local-pkg".into(), "mytool".into()]),
            vec!["exec", "--package=local-pkg", "--", "mytool"]
        );

        // -c / --call
        assert_eq!(
            translate_npx_args(&["-c".into(), "mytool arg1".into()]),
            vec!["exec", "--call", "mytool arg1"]
        );
        assert_eq!(
            translate_npx_args(&["--call=mytool arg1".into()]),
            vec!["exec", "--call=mytool arg1"]
        );

        // -q / --quiet
        assert_eq!(
            translate_npx_args(&["-q".into(), "mytool".into()]),
            vec!["exec", "--quiet", "--", "mytool"]
        );

        // --offline / --prefer-offline / --prefer-online
        assert_eq!(
            translate_npx_args(&["--offline".into(), "mytool".into()]),
            vec!["exec", "--offline", "--", "mytool"]
        );
        assert_eq!(
            translate_npx_args(&["--prefer-offline".into(), "mytool".into()]),
            vec!["exec", "--prefer-offline", "--", "mytool"]
        );
        assert_eq!(
            translate_npx_args(&["--prefer-online".into(), "mytool".into()]),
            vec!["exec", "--prefer-online", "--", "mytool"]
        );

        // --registry / --cache / --userconfig
        assert_eq!(
            translate_npx_args(&[
                "--registry".into(),
                "https://reg.example".into(),
                "mytool".into()
            ]),
            vec![
                "exec",
                "--registry",
                "https://reg.example",
                "--",
                "mytool"
            ]
        );
        assert_eq!(
            translate_npx_args(&["--cache=/path".into(), "mytool".into()]),
            vec!["exec", "--cache=/path", "--", "mytool"]
        );
        assert_eq!(
            translate_npx_args(&["--userconfig=/path".into(), "mytool".into()]),
            vec!["exec", "--userconfig=/path", "--", "mytool"]
        );

        // -w / --workspace / --workspaces
        assert_eq!(
            translate_npx_args(&["-w".into(), "pkg-a".into(), "mytool".into()]),
            vec!["exec", "--workspace", "pkg-a", "--", "mytool"]
        );
        assert_eq!(
            translate_npx_args(&["--workspaces".into(), "mytool".into()]),
            vec!["exec", "--workspaces", "--", "mytool"]
        );

        // --ignore-existing removed flag
        assert_eq!(
            translate_npx_args(&["--ignore-existing".into(), "mytool".into()]),
            vec!["exec", "--", "mytool"]
        );

        // -- separator
        assert_eq!(
            translate_npx_args(&["--".into(), "mytool".into(), "--yes".into()]),
            vec!["exec", "--", "mytool", "--yes"]
        );

        // --version and --help standalone
        assert_eq!(
            translate_npx_args(&["--version".into()]),
            vec!["exec", "--version"]
        );
        assert_eq!(
            translate_npx_args(&["-v".into()]),
            vec!["exec", "--version"]
        );
        assert_eq!(
            translate_npx_args(&["--help".into()]),
            vec!["exec", "--help"]
        );
        assert_eq!(
            translate_npx_args(&["-h".into()]),
            vec!["exec", "--help"]
        );
    }

    #[test]
    fn test_find_rnpm_executable_lookup_behavior() {
        use std::fs;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();

        let sibling_name = if cfg!(windows) { "npm.exe" } else { "npm" };
        let rnpm_name = if cfg!(windows) { "rnpm.exe" } else { "rnpm" };

        // 1. Sibling fallback to npm when rnpm is absent
        let install_dir = root.join("install");
        fs::create_dir_all(&install_dir).unwrap();
        let fake_npx = install_dir.join(if cfg!(windows) { "npx.exe" } else { "npx" });
        let fake_npm = install_dir.join(sibling_name);
        let native_bytes = if cfg!(windows) { &b"MZ_native"[..] } else { &b"\x7fELF_native"[..] };
        fs::write(&fake_npx, native_bytes).unwrap();
        fs::write(&fake_npm, native_bytes).unwrap();

        let found = find_rnpm_executable_in(Some(&fake_npx), &[]);
        assert_eq!(found, Some(fake_npm));

        // 2. PATH search ignores foreign npm and only finds rnpm
        let node_bin_dir = root.join("node_bin");
        let rnpm_bin_dir = root.join("rnpm_bin");
        fs::create_dir_all(&node_bin_dir).unwrap();
        fs::create_dir_all(&rnpm_bin_dir).unwrap();

        // Node's npm is earlier in PATH
        let node_npm = node_bin_dir.join(sibling_name);
        let actual_rnpm = rnpm_bin_dir.join(rnpm_name);
        fs::write(&node_npm, native_bytes).unwrap();
        fs::write(&actual_rnpm, native_bytes).unwrap();

        let search_path = vec![node_bin_dir.clone(), rnpm_bin_dir];
        let found = find_rnpm_executable_in(None, &search_path);
        // Must NOT pick node's npm, must pick rnpm
        assert_eq!(found, Some(actual_rnpm));

        // If only node's npm is on PATH without rnpm, returns None
        let found_none = find_rnpm_executable_in(None, &[node_bin_dir]);
        assert_eq!(found_none, None);
    }

    #[test]
    fn test_find_rnpm_executable_skips_shebang_js_npm_and_selects_rnpm() {
        use std::fs;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();

        let sibling_name = if cfg!(windows) { "npm.exe" } else { "npm" };
        let rnpm_name = if cfg!(windows) { "rnpm.exe" } else { "rnpm" };

        let install_dir = root.join("install");
        let path_dir = root.join("path_dir");
        fs::create_dir_all(&install_dir).unwrap();
        fs::create_dir_all(&path_dir).unwrap();

        let native_bytes = if cfg!(windows) { &b"MZ_native"[..] } else { &b"\x7fELF_native"[..] };
        let fake_npx = install_dir.join(if cfg!(windows) { "npx.exe" } else { "npx" });
        // Sibling npm is a JS script starting with #!
        let fake_npm_script = install_dir.join(sibling_name);
        fs::write(&fake_npx, native_bytes).unwrap();
        fs::write(&fake_npm_script, b"#!/usr/bin/env node\nconsole.log('hi');").unwrap();

        // Valid rnpm in PATH
        let actual_rnpm = path_dir.join(rnpm_name);
        fs::write(&actual_rnpm, native_bytes).unwrap();

        let found = find_rnpm_executable_in(Some(&fake_npx), &[path_dir]);
        assert_eq!(found, Some(actual_rnpm), "Should skip #! JS npm and pick native rnpm");
    }

    #[test]
    fn test_find_rnpm_executable_skips_batch_script_npm_and_selects_rnpm() {
        use std::fs;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();

        let sibling_name = if cfg!(windows) { "npm.exe" } else { "npm" };
        let rnpm_name = if cfg!(windows) { "rnpm.exe" } else { "rnpm" };

        let install_dir = root.join("install");
        let path_dir = root.join("path_dir");
        fs::create_dir_all(&install_dir).unwrap();
        fs::create_dir_all(&path_dir).unwrap();

        let native_bytes = if cfg!(windows) { &b"MZ_native"[..] } else { &b"\x7fELF_native"[..] };
        let fake_npx = install_dir.join(if cfg!(windows) { "npx.exe" } else { "npx" });
        // Sibling npm is a Windows batch script or shell launcher
        let fake_npm_script = install_dir.join(sibling_name);
        fs::write(&fake_npx, native_bytes).unwrap();
        fs::write(&fake_npm_script, b"@echo off\r\nnode npm-cli.js\r\n").unwrap();

        let actual_rnpm = path_dir.join(rnpm_name);
        fs::write(&actual_rnpm, native_bytes).unwrap();

        let found = find_rnpm_executable_in(Some(&fake_npx), &[path_dir]);
        assert_eq!(found, Some(actual_rnpm), "Should skip batch script npm and pick native rnpm");
    }
}
