use serde::{Deserialize, Serialize};

/// Current host platform or simulated target platform for optional dependency filtering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    pub os: String,
    pub cpu: String,
}

impl Platform {
    pub fn new(os: impl Into<String>, cpu: impl Into<String>) -> Self {
        Self {
            os: os.into(),
            cpu: cpu.into(),
        }
    }

    /// Detect current platform matching Node.js `process.platform` and `process.arch`.
    pub fn current() -> Self {
        let os = if cfg!(target_os = "windows") {
            "win32"
        } else if cfg!(target_os = "macos") {
            "darwin"
        } else if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "freebsd") {
            "freebsd"
        } else if cfg!(target_os = "openbsd") {
            "openbsd"
        } else if cfg!(target_os = "android") {
            "android"
        } else {
            std::env::consts::OS
        };

        let cpu = if cfg!(target_arch = "x86_64") {
            "x64"
        } else if cfg!(target_arch = "aarch64") {
            "arm64"
        } else if cfg!(target_arch = "x86") {
            "ia32"
        } else if cfg!(target_arch = "arm") {
            "arm"
        } else if cfg!(target_arch = "mips") {
            "mips"
        } else if cfg!(target_arch = "powerpc") {
            "ppc"
        } else if cfg!(target_arch = "s390x") {
            "s390x"
        } else if cfg!(target_arch = "riscv64") {
            "riscv64"
        } else {
            std::env::consts::ARCH
        };

        Self {
            os: os.to_string(),
            cpu: cpu.to_string(),
        }
    }

    /// Evaluates if this platform matches both `os` and `cpu` constraints.
    ///
    /// Rules according to npm / package.json:
    /// - If list is None or empty: matches all.
    /// - If any negated item (starts with `!`) matches current: rejected.
    /// - If positive items exist, current MUST match at least one positive item.
    /// - If only negated items exist, passes as long as no negation matched.
    pub fn matches(&self, os_list: Option<&[String]>, cpu_list: Option<&[String]>) -> bool {
        self.matches_list(&self.os, os_list) && self.matches_list(&self.cpu, cpu_list)
    }

    fn matches_list(&self, current: &str, list_opt: Option<&[String]>) -> bool {
        let Some(list) = list_opt else {
            return true;
        };
        if list.is_empty() {
            return true;
        }

        let mut has_positive = false;
        let mut matched_positive = false;

        for item in list {
            let item = item.trim();
            if let Some(negated) = item.strip_prefix('!') {
                if current.eq_ignore_ascii_case(negated.trim()) {
                    return false;
                }
            } else {
                has_positive = true;
                if current.eq_ignore_ascii_case(item) {
                    matched_positive = true;
                }
            }
        }

        if has_positive {
            matched_positive
        } else {
            true
        }
    }
}

impl Default for Platform {
    fn default() -> Self {
        Self::current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_matching() {
        let win = Platform::new("win32", "x64");
        let mac = Platform::new("darwin", "arm64");
        let linux = Platform::new("linux", "x64");

        // Positive OS list
        let os_darwin = vec!["darwin".to_string()];
        assert!(!win.matches(Some(&os_darwin), None));
        assert!(mac.matches(Some(&os_darwin), None));
        assert!(!linux.matches(Some(&os_darwin), None));

        // Negated OS list
        let not_win = vec!["!win32".to_string()];
        assert!(!win.matches(Some(&not_win), None));
        assert!(mac.matches(Some(&not_win), None));
        assert!(linux.matches(Some(&not_win), None));

        // CPU positive
        let arm_only = vec!["arm64".to_string()];
        assert!(!win.matches(None, Some(&arm_only)));
        assert!(mac.matches(None, Some(&arm_only)));

        // Combined OS and CPU
        let darwin_arm = vec!["darwin".to_string()];
        let x64_only = vec!["x64".to_string()];
        assert!(!mac.matches(Some(&darwin_arm), Some(&x64_only)));
        assert!(mac.matches(Some(&darwin_arm), Some(&arm_only)));

        // Empty / None
        assert!(win.matches(None, None));
        assert!(win.matches(Some(&[]), Some(&[])));
    }
}
