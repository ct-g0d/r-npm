use std::path::Path;
use std::sync::OnceLock;

/// Version string for the active `node` executable (`v26.13.0` or `unknown`),
/// avoiding a subprocess spawn on Windows when reading an official `node.exe`.
pub(crate) fn node_version() -> String {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            rnpm_lifecycle::node_executable()
                .map(|path| node_version_for(&path))
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "unknown".to_string())
        })
        .clone()
}

/// Returns the trimmed `node --version` output for `path`, or empty string on failure.
pub(crate) fn node_version_for(path: &Path) -> String {
    if let Some(version) = read_official_node_pe_version(path) {
        return version;
    }
    std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Fast-path equivalent of `rnpm_lifecycle::npm_user_agent()` using `node_version()`.
pub(crate) fn npm_user_agent() -> String {
    let platform = match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        other => other,
    };
    let is_github_actions = std::env::var_os("GITHUB_ACTIONS").is_some_and(|v| !v.is_empty());
    let ci_name = if is_github_actions {
        Some("github-actions")
    } else {
        [
            ("GITLAB_CI", "gitlab-ci"),
            ("CIRCLECI", "circleci"),
            ("TRAVIS", "travis-ci"),
            ("BUILDKITE", "buildkite"),
            ("TF_BUILD", "azure-pipelines"),
        ]
        .iter()
        .find(|(var, _)| std::env::var_os(var).is_some_and(|v| !v.is_empty()))
        .map(|(_, name)| *name)
    };
    let sub_ci_name = if is_github_actions {
        let server_url = std::env::var("GITHUB_SERVER_URL").unwrap_or_default();
        let runner_env = std::env::var("RUNNER_ENVIRONMENT").unwrap_or_default();
        github_actions_sub_ci(&server_url, &runner_env)
    } else {
        None
    };
    let ci = match (ci_name, sub_ci_name) {
        (Some(name), Some(sub)) => format!(" ci/{name}/{sub}"),
        (Some(name), None) => format!(" ci/{name}"),
        (None, _) => String::new(),
    };
    format!(
        "npm/{} node/{} {platform} {arch} workspaces/false{ci}",
        crate::version::NPM_VERSION,
        node_version()
    )
}

fn url_hostname(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let after_scheme = trimmed.split_once("://")?.1;
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next()?
    } else {
        host_port.split(':').next()?
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn github_actions_sub_ci(server_url: &str, runner_env: &str) -> Option<&'static str> {
    let runner_env = runner_env.trim();
    match url_hostname(server_url).as_deref() {
        Some("github.com") => match runner_env {
            "github-hosted" => Some("dotcom-hosted"),
            "self-hosted" => Some("dotcom-selfhosted"),
            _ => Some("dotcom"),
        },
        Some(host) if host == "ghe.com" || host.ends_with(".ghe.com") => Some("ghecom"),
        Some(_) => Some("ghes"),
        None => None,
    }
}

#[cfg(windows)]
mod pe_version {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    use std::path::Path;

    /// Reads `RT_VERSION` (`VS_VERSION_INFO`) directly from an official Windows `node.exe`
    /// using bounded header/resource seeks instead of spawning `node.exe --version`.
    pub(super) fn read_official_node_pe_version(path: &Path) -> Option<String> {
        let mut file = File::open(path).ok()?;
        let mut header = [0u8; 4096];
        let n = file.read(&mut header).ok()?;
        let hdr = &header[..n];
        if hdr.len() < 64 || &hdr[0..2] != b"MZ" {
            return None;
        }

        let e_lfanew = read_u32(hdr, 60)? as usize;
        let pe_end = e_lfanew.checked_add(24)?;
        let full_hdr: Vec<u8>;
        let h = if pe_end <= hdr.len() {
            hdr
        } else if e_lfanew < 65536 {
            file.seek(SeekFrom::Start(0)).ok()?;
            full_hdr = read_exact_up_to(&mut file, pe_end.max(4096))?;
            &full_hdr
        } else {
            return None;
        };

        if h.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
            return None;
        }
        let num_sections = read_u16(h, e_lfanew + 6)? as usize;
        let size_of_opt = read_u16(h, e_lfanew + 20)? as usize;
        let opt_off = e_lfanew + 24;
        let sec_off = opt_off.checked_add(size_of_opt)?;
        let sec_table_end = sec_off.checked_add(num_sections.checked_mul(40)?)?;
        if num_sections == 0 || num_sections > 96 || sec_table_end > 65536 {
            return None;
        }

        let extended_hdr: Vec<u8>;
        let h = if sec_table_end <= h.len() {
            h
        } else {
            file.seek(SeekFrom::Start(0)).ok()?;
            extended_hdr = read_exact_up_to(&mut file, sec_table_end)?;
            &extended_hdr
        };

        let opt = h.get(opt_off..sec_off)?;
        let magic = read_u16(opt, 0)?;
        let (rva_count_off, dd_off) = match magic {
            0x010b => (92usize, 96usize),   // PE32
            0x020b => (108usize, 112usize), // PE32+
            _ => return None,
        };
        let num_rva = read_u32(opt, rva_count_off)? as usize;
        if num_rva <= 2 {
            return None;
        }
        let rsrc_dir_rva = read_u32(opt, dd_off + 2 * 8)?;
        let rsrc_dir_size = read_u32(opt, dd_off + 2 * 8 + 4)?;
        if rsrc_dir_rva == 0 || rsrc_dir_size == 0 {
            return None;
        }

        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let base = sec_off + i * 40;
            sections.push(PeSection {
                virtual_size: read_u32(h, base + 8)?,
                virtual_address: read_u32(h, base + 12)?,
                size_of_raw_data: read_u32(h, base + 16)?,
                pointer_to_raw_data: read_u32(h, base + 20)?,
            });
        }

        let rsrc_base = rva_to_file_offset(&sections, rsrc_dir_rva)?;
        let version_bytes = read_rt_version_resource(&mut file, &sections, rsrc_base)?;
        parse_node_version_info(&version_bytes)
    }

    #[derive(Clone, Copy)]
    struct PeSection {
        virtual_size: u32,
        virtual_address: u32,
        size_of_raw_data: u32,
        pointer_to_raw_data: u32,
    }

    fn rva_to_file_offset(sections: &[PeSection], rva: u32) -> Option<u64> {
        for sec in sections {
            let span = sec.virtual_size.max(sec.size_of_raw_data);
            let end = sec.virtual_address.checked_add(span)?;
            if rva >= sec.virtual_address && rva < end {
                let delta = rva - sec.virtual_address;
                if delta < sec.size_of_raw_data {
                    return Some(u64::from(sec.pointer_to_raw_data) + u64::from(delta));
                }
            }
        }
        None
    }

    fn read_exact_up_to(file: &mut File, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut read_total = 0;
        while read_total < len {
            match file.read(&mut buf[read_total..]) {
                Ok(0) => break,
                Ok(k) => read_total += k,
                Err(_) => return None,
            }
        }
        buf.truncate(read_total);
        Some(buf)
    }

    fn read_at(file: &mut File, offset: u64, len: usize) -> Option<Vec<u8>> {
        file.seek(SeekFrom::Start(offset)).ok()?;
        let buf = read_exact_up_to(file, len)?;
        if buf.len() < len {
            None
        } else {
            Some(buf)
        }
    }

    fn read_resource_dir_entries(file: &mut File, dir_offset: u64) -> Option<Vec<(u32, u32)>> {
        let hdr = read_at(file, dir_offset, 16)?;
        let num_named = read_u16(&hdr, 12)? as usize;
        let num_id = read_u16(&hdr, 14)? as usize;
        let total = num_named.checked_add(num_id)?;
        if total == 0 || total > 512 {
            return None;
        }
        let raw = read_at(file, dir_offset.checked_add(16)?, total * 8)?;
        let mut entries = Vec::with_capacity(total);
        for i in 0..total {
            let base = i * 8;
            entries.push((read_u32(&raw, base)?, read_u32(&raw, base + 4)?));
        }
        Some(entries)
    }

    fn read_rt_version_resource(
        file: &mut File,
        sections: &[PeSection],
        rsrc_base: u64,
    ) -> Option<Vec<u8>> {
        const RT_VERSION: u32 = 16;
        const SUBDIR_FLAG: u32 = 0x8000_0000;

        let type_entries = read_resource_dir_entries(file, rsrc_base)?;
        let (_, type_off) = type_entries
            .into_iter()
            .find(|(id, off)| *id == RT_VERSION && (*off & SUBDIR_FLAG) != 0)?;

        let name_entries = read_resource_dir_entries(
            file,
            rsrc_base.checked_add(u64::from(type_off & !SUBDIR_FLAG))?,
        )?;
        let (_, name_off) = name_entries
            .into_iter()
            .find(|(_, off)| (*off & SUBDIR_FLAG) != 0)?;

        let lang_entries = read_resource_dir_entries(
            file,
            rsrc_base.checked_add(u64::from(name_off & !SUBDIR_FLAG))?,
        )?;
        let (_, leaf_off) = lang_entries
            .into_iter()
            .find(|(_, off)| (*off & SUBDIR_FLAG) == 0)?;

        let data_entry = read_at(file, rsrc_base.checked_add(u64::from(leaf_off))?, 16)?;
        let data_rva = read_u32(&data_entry, 0)?;
        let data_size = read_u32(&data_entry, 4)? as usize;
        if data_size < 64 || data_size > 65536 {
            return None;
        }
        let data_offset = rva_to_file_offset(sections, data_rva)?;
        read_at(file, data_offset, data_size)
    }

    fn parse_node_version_info(buf: &[u8]) -> Option<String> {
        let (key, w_type, val_start, val_len, children_start, node_end) =
            parse_ver_node(buf, 0, buf.len())?;
        if key != "VS_VERSION_INFO" || w_type != 0 || val_len < 52 {
            return None;
        }
        let fixed_end = val_start.checked_add(52)?;
        let fixed = buf.get(val_start..fixed_end)?;
        if read_u32(fixed, 0)? != 0xFEEF_04BD {
            return None;
        }
        let prod_ms = read_u32(fixed, 16)?;
        let prod_ls = read_u32(fixed, 20)?;
        if (prod_ls & 0xFFFF) != 0 {
            return None;
        }
        let expected_ver = format!("{}.{}.{}", prod_ms >> 16, prod_ms & 0xFFFF, prod_ls >> 16);

        let mut original_filename: Option<String> = None;
        let mut file_description: Option<String> = None;
        let mut product_name: Option<String> = None;
        let mut product_version: Option<String> = None;

        let mut sfi_off = children_start;
        while sfi_off + 6 <= node_end {
            let Some((sfi_key, _, _, _, sfi_children, sfi_end)) =
                parse_ver_node(buf, sfi_off, node_end)
            else {
                break;
            };
            if sfi_key == "StringFileInfo" {
                let mut tbl_off = sfi_children;
                while tbl_off + 6 <= sfi_end {
                    let Some((_, _, _, _, tbl_children, tbl_end)) =
                        parse_ver_node(buf, tbl_off, sfi_end)
                    else {
                        break;
                    };
                    let mut str_off = tbl_children;
                    while str_off + 6 <= tbl_end {
                        let Some((str_key, str_type, sv_start, sv_len, _, str_end)) =
                            parse_ver_node(buf, str_off, tbl_end)
                        else {
                            break;
                        };
                        if str_type == 1 {
                            let byte_len = sv_len.saturating_mul(2);
                            let sv_end = sv_start.saturating_add(byte_len).min(str_end);
                            if let Some(val) = decode_utf16le_trimmed(buf.get(sv_start..sv_end)?) {
                                match str_key.as_str() {
                                    "OriginalFilename" => original_filename = Some(val),
                                    "FileDescription" => file_description = Some(val),
                                    "ProductName" => product_name = Some(val),
                                    "ProductVersion" => product_version = Some(val),
                                    _ => {}
                                }
                            }
                        }
                        let next = align4(str_end);
                        if next <= str_off {
                            break;
                        }
                        str_off = next;
                    }
                    let next = align4(tbl_end);
                    if next <= tbl_off {
                        break;
                    }
                    tbl_off = next;
                }
            }
            let next = align4(sfi_end);
            if next <= sfi_off {
                break;
            }
            sfi_off = next;
        }

        if !original_filename.as_deref()?.eq_ignore_ascii_case("node.exe") {
            return None;
        }
        if file_description.as_deref()? != "Node.js JavaScript Runtime" {
            return None;
        }
        if product_name.as_deref()? != "Node.js" {
            return None;
        }
        let pv = product_version?;
        if pv != expected_ver {
            return None;
        }
        Some(format!("v{pv}"))
    }

    fn parse_ver_node(
        buf: &[u8],
        offset: usize,
        limit: usize,
    ) -> Option<(String, u16, usize, usize, usize, usize)> {
        let w_len = read_u16(buf, offset)? as usize;
        let w_val_len = read_u16(buf, offset + 2)? as usize;
        let w_type = read_u16(buf, offset + 4)?;
        if w_len < 6 {
            return None;
        }
        let node_end = offset.checked_add(w_len)?.min(limit);
        let (key, key_end) = read_utf16le_cstr(buf, offset + 6, node_end)?;
        let val_start = align4(key_end).min(node_end);
        let val_bytes = if w_type == 1 {
            w_val_len.saturating_mul(2)
        } else {
            w_val_len
        };
        let children_start = align4(val_start.saturating_add(val_bytes).min(node_end)).min(node_end);
        Some((key, w_type, val_start, w_val_len, children_start, node_end))
    }

    fn read_utf16le_cstr(buf: &[u8], start: usize, limit: usize) -> Option<(String, usize)> {
        let mut pos = start;
        let mut units = Vec::new();
        while pos + 2 <= limit {
            let unit = u16::from_le_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
            if unit == 0 {
                return Some((String::from_utf16(&units).ok()?, pos));
            }
            units.push(unit);
        }
        None
    }

    fn decode_utf16le_trimmed(bytes: &[u8]) -> Option<String> {
        let mut units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        String::from_utf16(&units).ok()
    }

    fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
        let slice = buf.get(off..off.checked_add(2)?)?;
        Some(u16::from_le_bytes([slice[0], slice[1]]))
    }

    fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
        let slice = buf.get(off..off.checked_add(4)?)?;
        Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    const fn align4(n: usize) -> usize {
        (n + 3) & !3
    }
}

#[cfg(windows)]
use pe_version::read_official_node_pe_version;

#[cfg(not(windows))]
fn read_official_node_pe_version(_path: &Path) -> Option<String> {
    None
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
        assert_eq!(read_official_node_pe_version(&exe), None);
    }
}
