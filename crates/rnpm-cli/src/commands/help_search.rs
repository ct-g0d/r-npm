use anyhow::Result;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

const EMBEDDED_DOCS_DEFLATE: &[u8] = include_bytes!("help_docs.deflate");

/// Result of searching a single documentation file.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub file: String,
    pub cmd: String,
    pub lines: Vec<Option<String>>,
    pub found: Vec<String>,
    pub hits: BTreeMap<String, usize>,
    pub total_hits: usize,
}

/// Strip YAML front-matter matching npm: `^---\n(.*\n)*?---\n` and trim.
pub fn clean_front_matter(content: &str) -> String {
    if let Some(rest) = content.strip_prefix("---\n") {
        if let Some(pos) = rest.find("\n---\n") {
            let after = &rest[pos + 5..];
            return after.trim().to_string();
        }
    }
    content.trim().to_string()
}

/// Emulates JavaScript `content.split(/\n+/)` preserving trailing `\r` on Windows lines.
pub fn split_by_newlines(s: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut in_delim = false;
    let mut start = 0;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            if !in_delim {
                result.push(s[start..i].to_string());
                in_delim = true;
            }
        } else if in_delim {
            start = i;
            in_delim = false;
        }
    }
    if in_delim {
        result.push(String::new());
    } else {
        result.push(s[start..].to_string());
    }
    result
}

/// Search documentation entries matching the npm algorithm.
pub fn search_documents(terms: &[String], docs: &[(String, String)]) -> Vec<SearchResult> {
    if terms.is_empty() {
        return Vec::new();
    }

    let mut results = Vec::new();

    for (file_path, raw_content) in docs {
        let content = clean_front_matter(raw_content);
        let lower_content = content.to_lowercase();

        // Skip if no terms match at all
        let any_match = terms.iter().any(|t| lower_content.contains(&t.to_lowercase()));
        if !any_match {
            continue;
        }

        // Split into lines matching JavaScript content.split(/\n+/)
        let raw_lines = split_by_newlines(&content);

        // npm line matching logic:
        // if next line has search term, keep current line and skip next 2
        // else if current line has search term, keep current line and skip next 1
        // otherwise, set to null
        let mut lines: Vec<Option<String>> = raw_lines.into_iter().map(Some).collect();

        let mut i = 0;
        while i < lines.len() {
            let next_line = lines.get(i + 1).and_then(|opt| opt.as_deref());
            if let Some(nl) = next_line {
                let nl_lower = nl.to_lowercase();
                let match_next = terms.iter().any(|t| nl_lower.contains(&t.to_lowercase()));
                if match_next {
                    i += 3;
                    continue;
                }
            }

            let cur_line = lines.get(i).and_then(|opt| opt.as_deref()).unwrap_or("");
            let cur_lower = cur_line.to_lowercase();
            let match_cur = terms.iter().any(|t| cur_lower.contains(&t.to_lowercase()));
            if match_cur {
                i += 2;
                continue;
            }

            lines[i] = None;
            i += 1;
        }

        // Squish consecutive nulls into a single null
        let mut pruned: Vec<Option<String>> = Vec::new();
        for line in lines {
            if line.is_none() && matches!(pruned.last(), Some(None)) {
                continue;
            }
            pruned.push(line);
        }

        // Trim leading and trailing null
        if matches!(pruned.last(), Some(None)) {
            pruned.pop();
        }
        if matches!(pruned.first(), Some(None)) {
            pruned.remove(0);
        }

        // Count hits for each search term across non-null lines
        let mut found: BTreeMap<String, usize> = BTreeMap::new();
        let mut total_hits = 0;
        for line in pruned.iter().flatten() {
            let line_lower = line.to_lowercase();
            for term in terms {
                let term_lower = term.to_lowercase();
                if term_lower.is_empty() {
                    continue;
                }
                let count = line_lower.matches(&term_lower).count();
                if count > 0 {
                    *found.entry(term.clone()).or_insert(0) += count;
                    total_hits += count;
                }
            }
        }

        // Derive command name from file path: e.g. commands/npm-install.md -> npm help install
        let base_name = Path::new(file_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(file_path);
        let topic = base_name.strip_prefix("npm-").unwrap_or(base_name);
        let cmd = format!("npm help {topic}");

        let found_keys: Vec<String> = found.keys().cloned().collect();

        results.push(SearchResult {
            file: file_path.clone(),
            cmd,
            lines: pruned,
            found: found_keys,
            hits: found,
            total_hits,
        });
    }

    // Sort: found.len() desc, total_hits desc, lines.len() desc, stable for ties
    results.sort_by(|a, b| {
        b.found
            .len()
            .cmp(&a.found.len())
            .then_with(|| b.total_hits.cmp(&a.total_hits))
            .then_with(|| b.lines.len().cmp(&a.lines.len()))
    });

    if results.len() > 10 {
        results.truncate(10);
    }

    results
}

/// Format search results according to npm help-search output specification.
pub fn format_search_results(terms: &[String], results: &[SearchResult], long: bool) -> String {
    if results.is_empty() {
        return format!("No matches in help for: {}\n", terms.join(" "));
    }

    const COLS: usize = 81; // 80 cols + 1

    let formatted_output = results
        .iter()
        .map(|res| {
            let out = res.cmd.clone();
            let r = res
                .hits
                .iter()
                .map(|(k, v)| format!("{k}:{v}"))
                .collect::<Vec<_>>()
                .join(" ");

            let spaces_len = if COLS > out.len() + r.len() + 1 {
                COLS - out.len() - r.len() - 1
            } else {
                1
            };
            let line = format!("{}{}{}", out, " ".repeat(spaces_len), r);

            if !long {
                line
            } else {
                let mut out_parts = Vec::new();
                out_parts.push("\n\n".to_string());
                out_parts.push(line);
                out_parts.push("\n".to_string());
                out_parts.push(format!("{}\n", "-".repeat(COLS - 1)));

                for (i, line_opt) in res.lines.iter().enumerate() {
                    if i > 3 {
                        break;
                    }
                    if let Some(line) = line_opt {
                        // For uncolored output (matching npm --color=false), each search term
                        // repeats the original line context directly as npm does, avoiding
                        // unsafe byte slicing across multi-byte or expanding Unicode characters.
                        let mut highlight_line = Vec::new();
                        for _arg in terms {
                            highlight_line.push(line.as_str());
                        }
                        out_parts.push(format!("{}\n", highlight_line.join("")));
                    }
                }

                out_parts.join("")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let final_out = if !long {
        let quoted_terms = terms
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(" ");
        let separator = "\u{2014}".repeat(COLS - 1);
        format!(
            "Top hits for {quoted_terms}\n{separator}\n{formatted_output}\n{separator}\n(run with -l or --long to see more context)"
        )
    } else {
        formatted_output
    };

    let trimmed = final_out.trim();
    let mut out = String::new();
    for line in trimmed.split('\n') {
        let clean = line.strip_suffix('\r').unwrap_or(line);
        out.push_str(clean);
        out.push('\n');
    }
    out
}

/// Load documentation documents from an explicit directory, standard paths, or embedded data.
pub fn load_documentation(custom_dir: Option<&Path>) -> Result<Vec<(String, String)>> {
    // 1. Explicit directory if given and exists
    if let Some(dir) = custom_dir {
        if dir.is_dir() {
            return load_docs_from_dir(dir);
        }
    }

    // 2. Environment variable override
    if let Ok(env_path) = std::env::var("RNPM_DOCS_PATH")
        .or_else(|_| std::env::var("npm_config_docs_path"))
    {
        let p = PathBuf::from(env_path);
        if p.is_dir() {
            return load_docs_from_dir(&p);
        }
    }

    // 3. Fallback to embedded documentation (fast, offline, self-contained)
    load_embedded_docs()
}

fn load_docs_from_dir(dir: &Path) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    walk_md_files(dir, dir, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn walk_md_files(root: &Path, current: &Path, out: &mut Vec<(String, String)>) -> Result<()> {
    if !current.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_md_files(root, &path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "md") {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let content = std::fs::read_to_string(&path)?;
            out.push((rel, content));
        }
    }
    Ok(())
}

fn load_embedded_docs() -> Result<Vec<(String, String)>> {
    let mut decoder = flate2::read::ZlibDecoder::new(EMBEDDED_DOCS_DEFLATE);
    let mut json_bytes = Vec::new();
    decoder.read_to_end(&mut json_bytes)?;
    let entries: Vec<(String, String)> = serde_json::from_slice(&json_bytes)?;
    Ok(entries)
}

/// Execute help-search command.
pub async fn run(
    terms: Vec<String>,
    long: bool,
    custom_docs_dir: Option<&Path>,
) -> Result<()> {
    if terms.is_empty() {
        return Err(anyhow::anyhow!(
            "npm error code EUSAGE\n\
             npm error\n\
             npm error Search npm help documentation\n\
             npm error\n\
             npm error Usage:\n\
             npm error npm help-search <text>\n\
             npm error\n\
             npm error Options:\n\
             npm error [-l|--long]\n\
             npm error\n\
             npm error   -l|--long\n\
             npm error     Show extended information in `ls`, `search`, and `help-search`.\n\
             npm error\n\
             npm error\n\
             npm error Run \"npm help help-search\" for more info"
        ));
    }

    let docs = load_documentation(custom_docs_dir)?;
    let results = search_documents(&terms, &docs);
    let output = format_search_results(&terms, &results, long);
    print!("{output}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_docs_load() {
        let docs = load_embedded_docs().expect("Embedded docs must decompress");
        assert_eq!(docs.len(), 91);
        assert!(docs.iter().any(|(p, _)| p.contains("install")));
    }

    #[test]
    fn test_help_search_install_top_hit() {
        let docs = load_embedded_docs().expect("Embedded docs must decompress");
        let results = search_documents(&["install".to_string()], &docs);
        assert!(!results.is_empty());
        assert_eq!(results[0].cmd, "npm help install");
        assert!(results[0].hits.contains_key("install"));
        assert!(results[0].total_hits > 100);
    }

    #[test]
    fn test_help_search_format_no_match() {
        let docs = load_embedded_docs().expect("Embedded docs must decompress");
        let results = search_documents(&["nonexistenttopicxyz999".to_string()], &docs);
        let formatted = format_search_results(&["nonexistenttopicxyz999".to_string()], &results, false);
        assert_eq!(formatted, "No matches in help for: nonexistenttopicxyz999\n");
    }

    #[test]
    fn test_help_search_format_short_structure() {
        let docs = load_embedded_docs().expect("Embedded docs must decompress");
        let results = search_documents(&["prune".to_string()], &docs);
        let formatted = format_search_results(&["prune".to_string()], &results, false);
        assert!(formatted.starts_with("Top hits for \"prune\"\n"));
        assert!(formatted.contains("\u{2014}"));
        assert!(formatted.contains("npm help prune"));
        assert!(formatted.contains("(run with -l or --long to see more context)"));
        assert!(formatted.ends_with('\n'));
    }

    #[test]
    fn test_help_search_multiterm_long_parity() {
        const ORACLE_EXPECTED_LONG: &str =
            include_str!("../../../../tests/fixtures/help-search/expected-long.utf8.txt");
        let docs = load_embedded_docs().expect("Embedded docs must decompress");
        let terms = vec!["install".to_string(), "package".to_string()];
        let results = search_documents(&terms, &docs);
        assert!(!results.is_empty());
        let formatted = format_search_results(&terms, &results, true);
        assert_eq!(formatted, ORACLE_EXPECTED_LONG);
    }

    #[test]
    fn test_help_search_unicode_multibyte_and_lowercase_expansions() {
        // Turkish dotted I U+0130 expands in lowercase from 2 bytes to 3 bytes (i + combining dot)
        // German sharp S U+00DF expands in uppercase from 2 bytes to 4 bytes ("SS")
        // Chinese multibyte characters around match
        let unicode_docs = vec![(
            "commands/npm-unicode-test.md".to_string(),
            "\u{0130} install\n\nContext with \u{4e2d}\u{6587} and \u{00df} test\nMore install details here"
                .to_string(),
        )];

        let terms = vec!["install".to_string()];
        let results = search_documents(&terms, &unicode_docs);
        assert_eq!(results.len(), 1);

        // Verify long formatting does not panic and contains expected Unicode lines
        let formatted = format_search_results(&terms, &results, true);
        assert!(formatted.contains("npm help unicode-test"));
        assert!(formatted.contains("\u{0130} install"));
        assert!(formatted.contains("\u{4e2d}\u{6587}"));
    }

    #[test]
    fn test_help_search_formatter_edge_cases() {
        // Empty terms
        let empty_terms: Vec<String> = Vec::new();
        let formatted_empty = format_search_results(&empty_terms, &[], false);
        assert_eq!(formatted_empty, "No matches in help for: \n");

        // No matches with terms (short mode)
        let terms = vec!["nonexistent_term_123".to_string()];
        let formatted_no_match = format_search_results(&terms, &[], false);
        assert_eq!(formatted_no_match, "No matches in help for: nonexistent_term_123\n");

        // No matches with terms (long mode)
        let formatted_long_no_match = format_search_results(&terms, &[], true);
        assert_eq!(formatted_long_no_match, "No matches in help for: nonexistent_term_123\n");
    }
}
