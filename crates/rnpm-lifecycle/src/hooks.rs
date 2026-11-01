use std::path::Path;
use rnpm_core::manifest::Manifest;
use crate::env::{build_lifecycle_env, LifecycleOptions};
use crate::error::LifecycleError;
use crate::process::{execute_shell_command, ScriptOutput};

/// Recognized npm lifecycle events.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LifecycleEvent {
    Preinstall,
    Install,
    Postinstall,
    Prepare,
    Pretest,
    Test,
    Posttest,
    Custom(String),
}

impl LifecycleEvent {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Preinstall => "preinstall",
            Self::Install => "install",
            Self::Postinstall => "postinstall",
            Self::Prepare => "prepare",
            Self::Pretest => "pretest",
            Self::Test => "test",
            Self::Posttest => "posttest",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl From<&str> for LifecycleEvent {
    fn from(s: &str) -> Self {
        match s {
            "preinstall" => Self::Preinstall,
            "install" => Self::Install,
            "postinstall" => Self::Postinstall,
            "prepare" => Self::Prepare,
            "pretest" => Self::Pretest,
            "test" => Self::Test,
            "posttest" => Self::Posttest,
            _ => Self::Custom(s.to_string()),
        }
    }
}

/// Helper function to append command line arguments to a script string.
pub fn format_command_with_args(script: &str, args: &[String]) -> String {
    if args.is_empty() {
        return script.to_string();
    }
    let mut full = script.to_string();
    for arg in args {
        full.push(' ');
        if arg.contains(' ') || arg.contains('\t') || arg.contains('"') {
            full.push('"');
            full.push_str(&arg.replace('"', "\\\""));
            full.push('"');
        } else {
            full.push_str(arg);
        }
    }
    full
}

/// Run an arbitrary package script (`rnpm run <name> [args]`).
/// Executes:
/// 1. `pre<script_name>` (if present in manifest.scripts)
/// 2. `<script_name> [args]`
/// 3. `post<script_name>` (if present in manifest.scripts)
pub async fn run_script(
    manifest: &Manifest,
    package_dir: &Path,
    script_name: &str,
    args: &[String],
    options: &LifecycleOptions,
) -> Result<ScriptOutput, LifecycleError> {
    if options.ignore_scripts {
        return Ok(ScriptOutput::success());
    }

    let script_cmd = manifest
        .scripts
        .get(script_name)
        .ok_or_else(|| LifecycleError::ScriptNotFound {
            script_name: script_name.to_string(),
        })?;

    // 1. Run pre<script_name> hook if declared
    let pre_hook = format!("pre{script_name}");
    if let Some(pre_cmd) = manifest.scripts.get(&pre_hook) {
        let env = build_lifecycle_env(package_dir, manifest, &pre_hook, pre_cmd, options);
        execute_shell_command(pre_cmd, &pre_hook, package_dir, &env, options.capture_output).await?;
    }

    // 2. Run main script with arguments
    let full_cmd = format_command_with_args(script_cmd, args);
    let env = build_lifecycle_env(package_dir, manifest, script_name, &full_cmd, options);
    let output = execute_shell_command(&full_cmd, script_name, package_dir, &env, options.capture_output).await?;

    // 3. Run post<script_name> hook if declared
    let post_hook = format!("post{script_name}");
    if let Some(post_cmd) = manifest.scripts.get(&post_hook) {
        let env = build_lifecycle_env(package_dir, manifest, &post_hook, post_cmd, options);
        execute_shell_command(post_cmd, &post_hook, package_dir, &env, options.capture_output).await?;
    }

    Ok(output)
}

/// Run a single lifecycle hook (e.g. `preinstall`, `install`, `postinstall`, `prepare`).
/// If the script is not defined in manifest:
/// - For `install`, checks if `binding.gyp` exists in `package_dir`; if so, runs `node-gyp rebuild`.
/// - Otherwise returns `Ok(None)`.
pub async fn run_lifecycle_hook(
    manifest: &Manifest,
    package_dir: &Path,
    event: &str,
    options: &LifecycleOptions,
) -> Result<Option<ScriptOutput>, LifecycleError> {
    if options.ignore_scripts {
        return Ok(None);
    }

    let maybe_cmd = if let Some(cmd) = manifest.scripts.get(event) {
        Some(cmd.clone())
    } else if event == "install" && package_dir.join("binding.gyp").exists() {
        Some("node-gyp rebuild".to_string())
    } else {
        None
    };

    if let Some(cmd) = maybe_cmd {
        let env = build_lifecycle_env(package_dir, manifest, event, &cmd, options);
        let out = execute_shell_command(&cmd, event, package_dir, &env, options.capture_output).await?;
        Ok(Some(out))
    } else {
        Ok(None)
    }
}
