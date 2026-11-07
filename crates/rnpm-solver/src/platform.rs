use serde::{Deserialize, Serialize};

/// Current host platform or simulated target platform for optional dependency filtering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    pub os: String,
    pub cpu: String,
    pub libc: Option<String>,
}

impl Platform {
    pub fn new(os: impl Into<String>, cpu: impl Into<String>) -> Self {
        Self {
            os: os.into(),
            cpu: cpu.into(),
            libc: None,
        }
    }

    pub fn with_libc(os: impl Into<String>, cpu: impl Into<String>, libc: Option<String>) -> Self {
        Self {
            os: os.into(),
            cpu: cpu.into(),
            libc,
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
        } else if cfg!(target_arch = "wasm32") {
            "wasm32"
        } else {
            std::env::consts::ARCH
        };

        let libc = if cfg!(target_os = "linux") {
            if cfg!(target_env = "musl") {
                Some("musl".to_string())
            } else {
                Some("glibc".to_string())
            }
        } else {
            None
        };

        Self {
            os: os.to_string(),
            cpu: cpu.to_string(),
            libc,
        }
    }

    /// Evaluates whether a package with given `os`, `cpu`, and optional `libc` constraints
    /// is compatible with this platform.
    pub fn is_compatible(
        &self,
        os_list: Option<&[String]>,
        cpu_list: Option<&[String]>,
        libc_list: Option<&[String]>,
    ) -> bool {
        self.matches_with_libc(os_list, cpu_list, libc_list)
    }

    /// Evaluates if this platform matches both `os` and `cpu` constraints.
    pub fn matches(&self, os_list: Option<&[String]>, cpu_list: Option<&[String]>) -> bool {
        self.matches_with_libc(os_list, cpu_list, None)
    }

    /// Evaluates if this platform matches `os`, `cpu`, and optional `libc` constraints.
    ///
    /// Rules according to npm / package.json:
    /// - If list is None or empty: matches all.
    /// - If any negated item (starts with `!`) matches current: rejected.
    /// - If positive items exist, current MUST match at least one positive item.
    /// - If only negated items exist, passes as long as no negation matched.
    pub fn matches_with_libc(
        &self,
        os_list: Option<&[String]>,
        cpu_list: Option<&[String]>,
        libc_list: Option<&[String]>,
    ) -> bool {
        self.matches_list(&self.os, os_list)
            && self.matches_list(&self.cpu, cpu_list)
            && self.matches_libc_list(libc_list)
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

    fn matches_libc_list(&self, list_opt: Option<&[String]>) -> bool {
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
                if let Some(ref current_libc) = self.libc {
                    if current_libc.eq_ignore_ascii_case(negated.trim()) {
                        return false;
                    }
                }
            } else {
                has_positive = true;
                if let Some(ref current_libc) = self.libc {
                    if current_libc.eq_ignore_ascii_case(item) {
                        matched_positive = true;
                    }
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

/// Evaluates whether a package with given `os`, `cpu`, and optional `libc` constraints
/// is compatible with the specified target platform.
pub fn is_platform_compatible(
    platform: &Platform,
    os_list: Option<&[String]>,
    cpu_list: Option<&[String]>,
    libc_list: Option<&[String]>,
) -> bool {
    platform.matches_with_libc(os_list, cpu_list, libc_list)
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

    #[test]
    fn test_platform_libc_matching() {
        let linux_glibc = Platform::with_libc("linux", "x64", Some("glibc".to_string()));
        let linux_musl = Platform::with_libc("linux", "x64", Some("musl".to_string()));
        let win = Platform::new("win32", "x64");

        let glibc_only = vec!["glibc".to_string()];
        let musl_only = vec!["musl".to_string()];
        let not_musl = vec!["!musl".to_string()];

        // Glibc only
        assert!(linux_glibc.matches_with_libc(None, None, Some(&glibc_only)));
        assert!(!linux_musl.matches_with_libc(None, None, Some(&glibc_only)));
        assert!(!win.matches_with_libc(None, None, Some(&glibc_only)));

        // Musl only
        assert!(!linux_glibc.matches_with_libc(None, None, Some(&musl_only)));
        assert!(linux_musl.matches_with_libc(None, None, Some(&musl_only)));
        assert!(!win.matches_with_libc(None, None, Some(&musl_only)));

        // Negated musl (!musl)
        assert!(linux_glibc.matches_with_libc(None, None, Some(&not_musl)));
        assert!(!linux_musl.matches_with_libc(None, None, Some(&not_musl)));
        assert!(win.matches_with_libc(None, None, Some(&not_musl)));
    }

    #[test]
    fn test_is_platform_compatible_wasm32_and_os() {
        let win_x64 = Platform::new("win32", "x64");
        let mac_arm = Platform::new("darwin", "arm64");
        let linux_x64 = Platform::new("linux", "x64");

        // wasm32 cpu filter
        let wasm_cpu = vec!["wasm32".to_string()];
        assert!(!is_platform_compatible(
            &win_x64,
            None,
            Some(&wasm_cpu),
            None
        ));
        assert!(!is_platform_compatible(
            &mac_arm,
            None,
            Some(&wasm_cpu),
            None
        ));
        assert!(!is_platform_compatible(
            &linux_x64,
            None,
            Some(&wasm_cpu),
            None
        ));

        // darwin & linux os filter
        let darwin_linux = vec!["darwin".to_string(), "linux".to_string()];
        assert!(!is_platform_compatible(
            &win_x64,
            Some(&darwin_linux),
            None,
            None
        ));
        assert!(is_platform_compatible(
            &mac_arm,
            Some(&darwin_linux),
            None,
            None
        ));
        assert!(is_platform_compatible(
            &linux_x64,
            Some(&darwin_linux),
            None,
            None
        ));

        // win32 x64 positive match
        let win_os = vec!["win32".to_string()];
        let x64_cpu = vec!["x64".to_string()];
        assert!(is_platform_compatible(
            &win_x64,
            Some(&win_os),
            Some(&x64_cpu),
            None
        ));
        assert!(!is_platform_compatible(
            &mac_arm,
            Some(&win_os),
            Some(&x64_cpu),
            None
        ));

        // Negated wasm32
        let not_wasm = vec!["!wasm32".to_string()];
        assert!(is_platform_compatible(
            &win_x64,
            None,
            Some(&not_wasm),
            None
        ));
    }
}
