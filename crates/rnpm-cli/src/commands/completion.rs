use anyhow::Result;
use std::path::Path;

const COMMANDS: &str = "install ci test start restart stop run exec pack uninstall update audit prune dedupe find-dupes rebuild pkg init create cache diff sbom version list outdated view query publish whoami ping login logout token approve-scripts deny-scripts completion dist-tag owner unpublish deprecate undeprecate access profile org team doctor fund explain search stars star unstar fix bugs docs edit explore help-search install-ci-test install-scripts install-test shrinkwrap trust config link unlink prefix root bin";

const SUBCOMMANDS: &[&str] = &[
    "access", "adduser", "audit", "bin", "bugs", "cache", "ci", "completion", "config",
    "create", "dedupe", "deprecate", "diff", "dist-tag", "docs", "doctor", "edit",
    "exec", "explain", "explore", "find-dupes", "fix", "fund", "help", "help-search",
    "init", "install", "install-ci-test", "install-scripts", "install-test", "link",
    "list", "ll", "login", "logout", "ls", "org", "outdated", "owner", "pack", "ping",
    "pkg", "prefix", "profile", "prune", "publish", "query", "rebuild", "repo", "restart",
    "root", "run", "run-script", "sbom", "search", "shrinkwrap", "star", "stars",
    "start", "stop", "team", "test", "token", "trust", "uninstall", "unlink",
    "unpublish", "unstar", "update", "version", "view", "whoami",
];

const GLOBAL_FLAGS: &[&str] = &[
    "--help",
    "-h",
    "--version",
    "-v",
    "--json",
    "--global",
    "-g",
    "--location",
    "--loglevel",
    "--registry",
    "--prefix",
    "--workspace",
    "-w",
    "--workspaces",
    "--include-workspace-root",
    "--include",
    "--omit",
    "--save",
    "--save-dev",
    "-D",
    "--save-prod",
    "-P",
    "--save-peer",
    "--save-optional",
    "--no-save",
    "--dry-run",
    "--force",
    "-f",
    "--silent",
    "--verbose",
    "--long",
    "-l",
    "--ignore-scripts",
    "--package-lock",
    "--no-package-lock",
    "--if-present",
];

const CONFIG_SUBCOMMANDS: &[&str] = &[
    "set", "get", "delete", "rm", "list", "ls", "edit", "fix",
];

const CONFIG_KEYS: &[&str] = &[
    "registry",
    "userconfig",
    "globalconfig",
    "prefix",
    "proxy",
    "https-proxy",
    "ca",
    "cert",
    "key",
    "strict-ssl",
    "package-lock",
    "install-strategy",
    "omit",
    "include",
    "tag-version-prefix",
    "commit-hooks",
    "shell",
    "init-author-name",
    "init-author-email",
    "init-author-url",
    "init-license",
    "init-version",
    "init-type",
    "init-module",
];

const CACHE_SUBCOMMANDS: &[&str] = &["clean", "verify", "ls", "add"];

pub fn run(args: Vec<String>, current_dir: &Path) -> Result<()> {
    let env_cword = std::env::var("COMP_CWORD").ok();
    let env_line = std::env::var("COMP_LINE").ok();
    let env_point = std::env::var("COMP_POINT").ok();

    let clean_args: Vec<String> = args
        .into_iter()
        .filter(|a| a != "--")
        .collect();

    let has_env = env_cword.is_some() || env_line.is_some() || env_point.is_some();
    let has_command_args = !clean_args.is_empty()
        && (clean_args[0] == "rnpm"
            || clean_args[0] == "npm"
            || clean_args.iter().any(|a| a.starts_with('-'))
            || clean_args.len() > 1);

    if !has_env && !has_command_args {
        #[cfg(windows)]
        {
            let msystem = std::env::var("MSYSTEM").unwrap_or_default();
            let term = std::env::var("TERM").unwrap_or_default();
            let is_mingw = msystem == "MINGW32" || msystem == "MINGW64";
            let is_cygwin = term == "cygwin";
            let requested_shell = clean_args.first().map(|s| s.as_str());
            if !is_mingw
                && !is_cygwin
                && requested_shell != Some("powershell")
                && requested_shell != Some("fish")
            {
                anyhow::bail!(
                    "npm error code ENOTSUP\nnpm error npm completion supported only in MINGW / Git bash on Windows"
                );
            }
        }
        print_init_script(clean_args.first().map(|s| s.as_str()));
        return Ok(());
    }

    // Dynamic completion mode
    let (preceding, current_word) = if let Some(line) = env_line {
        let point = env_point
            .and_then(|p| p.parse::<usize>().ok())
            .unwrap_or(line.len());
        let slice = if point <= line.len() {
            let mut p = point;
            while p > 0 && !line.is_char_boundary(p) {
                p -= 1;
            }
            &line[..p]
        } else {
            &line
        };

        if slice.ends_with(char::is_whitespace) {
            let words: Vec<String> = slice
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            (words, String::new())
        } else {
            let mut words: Vec<String> = slice
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            let curr = words.pop().unwrap_or_default();
            (words, curr)
        }
    } else {
        let cword_idx = env_cword.and_then(|s| s.parse::<usize>().ok());
        if let Some(idx) = cword_idx {
            if idx < clean_args.len() {
                let curr = clean_args[idx].clone();
                let prec = clean_args[..idx].to_vec();
                (prec, curr)
            } else {
                (clean_args, String::new())
            }
        } else if clean_args.is_empty() {
            (Vec::new(), String::new())
        } else if clean_args.last().map(|s| s.is_empty()).unwrap_or(false) {
            let mut prec = clean_args;
            prec.pop();
            (prec, String::new())
        } else if clean_args.len() >= 2
            && (clean_args.last().unwrap() == "run"
                || clean_args.last().unwrap() == "config"
                || clean_args.last().unwrap() == "cache")
        {
            (clean_args, String::new())
        } else {
            let mut prec = clean_args;
            let curr = prec.pop().unwrap_or_default();
            (prec, curr)
        }
    };

    let completions = compute_completions(&preceding, &current_word, current_dir);
    for c in completions {
        println!("{c}");
    }

    Ok(())
}

fn compute_completions(
    preceding: &[String],
    current_word: &str,
    current_dir: &Path,
) -> Vec<String> {
    let mut results = Vec::new();

    // 1. If completing a flag (starts with '-')
    if current_word.starts_with('-') {
        for &flag in GLOBAL_FLAGS {
            if flag.starts_with(current_word) {
                results.push(flag.to_string());
            }
        }
        return results;
    }

    // 2. Identify subcommand in preceding arguments
    let pos_tokens: Vec<&str> = preceding
        .iter()
        .map(|s| s.as_str())
        .filter(|s| !s.starts_with('-'))
        .collect();

    // Skip program binary name (rnpm or npm)
    let non_binary_tokens = if let Some(&first) = pos_tokens.first() {
        if first == "rnpm" || first == "npm" {
            &pos_tokens[1..]
        } else {
            &pos_tokens[..]
        }
    } else {
        &pos_tokens[..]
    };

    if non_binary_tokens.is_empty() {
        // Complete top-level subcommands
        for &cmd in SUBCOMMANDS {
            if cmd.starts_with(current_word) {
                results.push(cmd.to_string());
            }
        }
        return results;
    }

    let subcmd = non_binary_tokens[0];
    let subcmd_args = &non_binary_tokens[1..];

    match subcmd {
        "run" | "run-script" => {
            // Complete scripts from local package.json
            if subcmd_args.is_empty() || (subcmd_args.len() == 1 && !current_word.is_empty()) {
                let pkg_json_path = current_dir.join("package.json");
                if let Ok(content) = std::fs::read_to_string(&pkg_json_path) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(scripts_obj) = val.get("scripts").and_then(|s| s.as_object()) {
                            let mut script_names: Vec<String> = scripts_obj
                                .keys()
                                .filter(|k| k.starts_with(current_word))
                                .cloned()
                                .collect();
                            script_names.sort();
                            results.extend(script_names);
                        }
                    }
                }
            }
        }
        "config" => {
            if subcmd_args.is_empty() {
                // Complete config subactions: set, get, delete, rm, list, ls, edit, fix
                for &action in CONFIG_SUBCOMMANDS {
                    if action.starts_with(current_word) {
                        results.push(action.to_string());
                    }
                }
            } else {
                // Complete known config keys
                for &key in CONFIG_KEYS {
                    if key.starts_with(current_word) {
                        results.push(key.to_string());
                    }
                }
            }
        }
        "cache" if subcmd_args.is_empty() => {
            // Complete cache subactions: clean, verify, ls, add
            for &action in CACHE_SUBCOMMANDS {
                if action.starts_with(current_word) {
                    results.push(action.to_string());
                }
            }
        }
        _ => {}
    }

    results
}

const BASH_ZSH_INIT_SCRIPT: &str = r#"#!/bin/bash
###-begin-npm-completion-###
#
# npm command completion script
#
# Installation: npm completion >> ~/.bashrc  (or ~/.zshrc)
# Or, maybe: npm completion > /usr/local/etc/bash_completion.d/npm
#

if type complete &>/dev/null; then
  _npm_completion () {
    local words cword
    if type _get_comp_words_by_ref &>/dev/null; then
      _get_comp_words_by_ref -n = -n @ -n : -w words -i cword
    else
      cword="$COMP_CWORD"
      words=("${COMP_WORDS[@]}")
    fi

    local si="$IFS"
    if ! IFS=$'\n' COMPREPLY=($(COMP_CWORD="$cword" \
                           COMP_LINE="$COMP_LINE" \
                           COMP_POINT="$COMP_POINT" \
                           npm completion -- "${words[@]}" \
                           2>/dev/null)); then
      local ret=$?
      IFS="$si"
      return $ret
    fi
    IFS="$si"
    if type __ltrim_colon_completions &>/dev/null; then
      __ltrim_colon_completions "${words[cword]}"
    fi
  }
  complete -o default -F _npm_completion npm
elif type compdef &>/dev/null; then
  _npm_completion() {
    local si=$IFS
    compadd -- $(COMP_CWORD=$((CURRENT-1)) \
                 COMP_LINE=$BUFFER \
                 COMP_POINT=0 \
                 npm completion -- "${words[@]}" \
                 2>/dev/null)
    IFS=$si
  }
  compdef _npm_completion npm
elif type compctl &>/dev/null; then
  _npm_completion () {
    local cword line point words si
    read -Ac words
    read -cn cword
    let cword-=1
    read -l line
    read -ln point
    si="$IFS"
    if ! IFS=$'\n' reply=($(COMP_CWORD="$cword" \
                       COMP_LINE="$line" \
                       COMP_POINT="$point" \
                       npm completion -- "${words[@]}" \
                       2>/dev/null)); then

      local ret=$?
      IFS="$si"
      return $ret
    fi
    IFS="$si"
  }
  compctl -K _npm_completion npm
fi
###-end-npm-completion-###
"#;

fn print_init_script(shell: Option<&str>) {
    match shell.unwrap_or("bash") {
        "fish" => println!("complete -c rnpm -f -a '{COMMANDS}'"),
        "powershell" => {
            let quoted = COMMANDS
                .split_whitespace()
                .map(|cmd| format!("'{cmd}'"))
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "Register-ArgumentCompleter -Native -CommandName rnpm -ScriptBlock {{ param($wordToComplete) {quoted} | Where-Object {{ $_ -like \"$wordToComplete*\" }} }}"
            );
        }
        _ => {
            print!("{BASH_ZSH_INIT_SCRIPT}");
        }
    }
}
