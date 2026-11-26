use std::path::Path;

/// Version string for the active `node` executable (`v26.13.0` or `unknown`),
/// avoiding a subprocess spawn on Windows when reading an official `node.exe`.
pub(crate) fn node_version() -> String {
    rnpm_lifecycle::node_version()
}

/// Returns the trimmed `node --version` output for `path`, or empty string on failure.
pub(crate) fn node_version_for(path: &Path) -> String {
    rnpm_lifecycle::node_version_for(path)
}

/// Fast-path equivalent of `rnpm_lifecycle::npm_user_agent()` using `node_version()`.
pub(crate) fn npm_user_agent() -> String {
    rnpm_lifecycle::npm_user_agent()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_version_matches_subprocess_output() {
        let Some(node) = rnpm_lifecycle::node_executable() else {
            return;
        };
        let spawned = std::process::Command::new(&node)
            .arg("--version")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
        if let Some(expected) = spawned {
            assert_eq!(node_version_for(&node), expected);
            assert_eq!(node_version(), expected);
        }
        assert_eq!(npm_user_agent(), rnpm_lifecycle::npm_user_agent());
    }

    #[test]
    fn non_node_binary_falls_back_cleanly() {
        let exe = std::env::current_exe().unwrap();
        assert_eq!(rnpm_lifecycle::read_official_node_pe_version(&exe), None);
    }
}
