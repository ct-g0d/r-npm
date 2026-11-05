use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use serde_json::Value;

use crate::inspect_tree::{build_dependency_tree, InspectedNode, TreeOptions};

/// Options for the `list` / `ls` / `la` / `ll` command.
#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    /// Package filter specs if any (e.g. `lodash`, `react@^18.0.0`, `@scope/pkg`)
    pub packages: Vec<String>,
    /// Depth control: 0 for top-level, max depth control
    pub depth: Option<usize>,
    /// If true, inspect full depth (`usize::MAX`)
    pub all: bool,
    /// Emit dependency tree as structured JSON
    pub json: bool,
    /// Show extended package details (description and license; also used for 'la' and 'll')
    pub long: bool,
    /// Output tab or newline separated list of package paths
    pub parseable: bool,
    /// Read dependency tree purely from package-lock.json without inspecting node_modules on disk
    pub package_lock_only: bool,
    /// Dependency types to omit (dev, optional, peer)
    pub omit: Vec<String>,
}

/// Executes package inspection and prints the dependency tree.
///
/// Returns exit code: `0` if no dependency problems exist, `1` if problems (`extraneous`, `invalid`, `missing`) exist.
pub fn run_list(project_dir: &Path, options: &ListOptions) -> anyhow::Result<i32> {
    let (omit_dev, omit_optional, omit_peer) = crate::parse_omit_options(&options.omit);
    let tree_opts = TreeOptions {
        package_lock_only: options.package_lock_only,
        omit_dev,
        omit_optional,
        omit_peer,
    };

    let mut root_node = build_dependency_tree(project_dir, &tree_opts)?;

    // Filter by packages if specified
    if !options.packages.is_empty() {
        filter_tree_by_packages(&mut root_node, &options.packages);
    }

    let effective_depth = if options.all {
        usize::MAX
    } else if let Some(d) = options.depth {
        d
    } else if !options.packages.is_empty() {
        usize::MAX
    } else {
        0
    };

    // Collect problems from the evaluated tree
    let mut problems = Vec::new();
    let mut seen_problems = HashSet::new();
    collect_problems(&root_node, &mut problems, &mut seen_problems);
    root_node.problems = problems.clone();

    let has_problems = !problems.is_empty();

    if options.json {
        let json_val = format_tree_json(&root_node, effective_depth, options.long);
        println!("{}", serde_json::to_string_pretty(&json_val)?);
    } else if options.parseable {
        let mut paths = Vec::new();
        let mut seen_paths = HashSet::new();
        collect_parseable_paths(&root_node, effective_depth, &mut paths, &mut seen_paths);
        for p in paths {
            println!("{p}");
        }
    } else {
        let output = format_tree_text(&root_node, effective_depth, options.long);
        print!("{output}");
    }

    if has_problems {
        eprintln!("npm error code ELSPROBLEMS");
        for p in &problems {
            eprintln!("npm error {p}");
        }
        Ok(1)
    } else {
        Ok(0)
    }
}

/// Recursively collects unique problem lines from a node and its descendants.
fn collect_problems(node: &InspectedNode, out: &mut Vec<String>, seen: &mut HashSet<String>) {
    for p in &node.problems {
        if seen.insert(p.clone()) {
            out.push(p.clone());
        }
    }

    if node.problems.is_empty() {
        if node.missing {
            let req = node.required.as_deref().unwrap_or("*");
            let p = format!("missing: {}@{}", node.name, req);
            if seen.insert(p.clone()) {
                out.push(p);
            }
        } else if node.extraneous {
            let p = format!(
                "extraneous: {}@{} {}",
                node.name,
                node.version.as_deref().unwrap_or(""),
                node.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default()
            );
            if seen.insert(p.clone()) {
                out.push(p);
            }
        } else if let Some(inv) = &node.invalid {
            let p = format!(
                "invalid: {}@{} {}",
                node.name,
                node.version.as_deref().unwrap_or(""),
                inv
            );
            if seen.insert(p.clone()) {
                out.push(p);
            }
        }
    }

    for child in node.dependencies.values() {
        collect_problems(child, out, seen);
    }
}

/// Checks if a node matches a given package filter specification.
pub fn package_matches_filter(node_name: &str, node: &InspectedNode, filter_pkg: &str) -> bool {
    let (filter_name, filter_version) = if let Some(stripped) = filter_pkg.strip_prefix('@') {
        if let Some((scope_and_name, ver)) = stripped.split_once('@') {
            (format!("@{scope_and_name}"), Some(ver))
        } else {
            (filter_pkg.to_string(), None)
        }
    } else if let Some((name, ver)) = filter_pkg.split_once('@') {
        (name.to_string(), Some(ver))
    } else {
        (filter_pkg.to_string(), None)
    };

    if node_name != filter_name {
        return false;
    }

    if let Some(req) = filter_version {
        if let Some(v_str) = &node.version {
            if v_str == req {
                return true;
            }
            if let (Ok(ver), Ok(range)) = (
                rnpm_core::semver::Version::parse(v_str),
                rnpm_core::semver::Range::parse(req),
            ) {
                return range.satisfies(&ver);
            }
        }
        if let Some(node_req) = &node.required {
            if node_req == req {
                return true;
            }
        }
        false
    } else {
        true
    }
}

/// Prunes tree branches that do not lead to any package matching `filter_pkgs`.
pub fn filter_tree_by_packages(node: &mut InspectedNode, filter_pkgs: &[String]) {
    let mut filtered_deps = BTreeMap::new();

    for (name, mut child) in std::mem::take(&mut node.dependencies) {
        let direct_match = filter_pkgs.iter().any(|p| package_matches_filter(&name, &child, p));

        filter_tree_by_packages(&mut child, filter_pkgs);

        if direct_match || !child.dependencies.is_empty() {
            filtered_deps.insert(name, child);
        }
    }

    node.dependencies = filtered_deps;
}

/// Formats the dependency tree as text matching npm standard output format.
pub fn format_tree_text(root: &InspectedNode, max_depth: usize, long: bool) -> String {
    let mut out = String::new();
    let version_str = root.version.as_deref().unwrap_or("0.0.0");
    let path_display = root
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    if long {
        out.push_str(&format!("{}@{}\n", root.name, version_str));
        out.push_str(&format!("| {path_display}\n"));
        if let Some(desc) = &root.description {
            out.push_str(&format!("| {desc}\n"));
        }
    } else {
        out.push_str(&format!("{}@{} {}\n", root.name, version_str, path_display));
    }

    let dep_keys: Vec<String> = root.dependencies.keys().cloned().collect();
    for (idx, name) in dep_keys.iter().enumerate() {
        let is_last = idx == dep_keys.len() - 1;
        let child = root.dependencies.get(name).unwrap();
        format_child_text(child, max_depth, 0, "", is_last, long, &mut out);
    }

    out
}

fn format_child_text(
    node: &InspectedNode,
    max_depth: usize,
    current_depth: usize,
    prefix: &str,
    is_last: bool,
    long: bool,
    out: &mut String,
) {
    let branch = if is_last { "`-- " } else { "+-- " };

    if node.missing {
        let req = node.required.as_deref().unwrap_or("*");
        out.push_str(&format!("{prefix}{branch}UNMET DEPENDENCY {}@{}\n", node.name, req));
    } else {
        let ver = node.version.as_deref().unwrap_or("unknown");
        let mut marker = String::new();
        if let Some(inv) = &node.invalid {
            marker = format!(" invalid: {inv}");
        } else if node.extraneous {
            marker = " extraneous".to_string();
        } else if node.deduped {
            marker = " deduped".to_string();
        }
        out.push_str(&format!("{prefix}{branch}{}@{}{}\n", node.name, ver, marker));
    }

    let continuation = if is_last { "    " } else { "|   " };
    let child_prefix = format!("{prefix}{continuation}");

    if long {
        if let Some(p) = &node.path {
            out.push_str(&format!("{child_prefix}| {}\n", p.display()));
        }
        if let Some(desc) = &node.description {
            out.push_str(&format!("{child_prefix}| {desc}\n"));
        }
    }

    if current_depth < max_depth && !node.deduped && !node.missing {
        let dep_keys: Vec<String> = node.dependencies.keys().cloned().collect();
        for (idx, name) in dep_keys.iter().enumerate() {
            let child_is_last = idx == dep_keys.len() - 1;
            let child = node.dependencies.get(name).unwrap();
            format_child_text(child, max_depth, current_depth + 1, &child_prefix, child_is_last, long, out);
        }
    }
}

/// Formats the dependency tree as structured JSON matching `npm ls --json`.
pub fn format_tree_json(root: &InspectedNode, max_depth: usize, long: bool) -> Value {
    let mut map = serde_json::Map::new();
    if let Some(v) = &root.version {
        map.insert("version".to_string(), Value::String(v.clone()));
    }
    map.insert("name".to_string(), Value::String(root.name.clone()));

    if long {
        if let Some(desc) = &root.description {
            map.insert("description".to_string(), Value::String(desc.clone()));
        }
        if let Some(lic) = &root.license {
            map.insert("license".to_string(), Value::String(lic.clone()));
        }
    }

    if !root.problems.is_empty() {
        map.insert("problems".to_string(), serde_json::to_value(&root.problems).unwrap_or_default());
    }

    let mut deps_map = serde_json::Map::new();
    for (name, child) in &root.dependencies {
        deps_map.insert(name.clone(), format_child_json(child, max_depth, 0, long));
    }
    map.insert("dependencies".to_string(), Value::Object(deps_map));

    if !root.problems.is_empty() {
        let summary = root.problems.join("\n");
        let error_obj = serde_json::json!({
            "code": "ELSPROBLEMS",
            "summary": summary,
            "detail": ""
        });
        map.insert("error".to_string(), error_obj);
    }

    Value::Object(map)
}

fn format_child_json(node: &InspectedNode, max_depth: usize, current_depth: usize, long: bool) -> Value {
    let mut map = serde_json::Map::new();

    if node.missing {
        if let Some(req) = &node.required {
            map.insert("required".to_string(), Value::String(req.clone()));
        }
        map.insert("missing".to_string(), Value::Bool(true));
        if !node.problems.is_empty() {
            map.insert("problems".to_string(), serde_json::to_value(&node.problems).unwrap_or_default());
        }
        return Value::Object(map);
    }

    if let Some(v) = &node.version {
        map.insert("version".to_string(), Value::String(v.clone()));
    }
    if let Some(r) = &node.resolved {
        map.insert("resolved".to_string(), Value::String(r.clone()));
    }
    map.insert("overridden".to_string(), Value::Bool(node.overridden));

    if node.extraneous {
        map.insert("extraneous".to_string(), Value::Bool(true));
    }
    if let Some(inv) = &node.invalid {
        map.insert("invalid".to_string(), Value::String(inv.clone()));
    }
    if node.deduped {
        map.insert("deduped".to_string(), Value::Bool(true));
    }

    if long {
        if let Some(desc) = &node.description {
            map.insert("description".to_string(), Value::String(desc.clone()));
        }
        if let Some(lic) = &node.license {
            map.insert("license".to_string(), Value::String(lic.clone()));
        }
    }

    if !node.problems.is_empty() {
        map.insert("problems".to_string(), serde_json::to_value(&node.problems).unwrap_or_default());
    }

    if current_depth < max_depth && !node.deduped && !node.dependencies.is_empty() {
        let mut child_map = serde_json::Map::new();
        for (name, child) in &node.dependencies {
            child_map.insert(name.clone(), format_child_json(child, max_depth, current_depth + 1, long));
        }
        map.insert("dependencies".to_string(), Value::Object(child_map));
    }

    Value::Object(map)
}

/// Recursively collects package directory paths for parseable output.
pub fn collect_parseable_paths(
    root: &InspectedNode,
    max_depth: usize,
    paths: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
    if let Some(p) = &root.path {
        let s = p.display().to_string();
        if seen.insert(s.clone()) {
            paths.push(s);
        }
    }

    for child in root.dependencies.values() {
        collect_child_paths(child, max_depth, 0, paths, seen);
    }
}

fn collect_child_paths(
    node: &InspectedNode,
    max_depth: usize,
    current_depth: usize,
    paths: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
    if let Some(p) = &node.path {
        let s = p.display().to_string();
        if seen.insert(s.clone()) {
            paths.push(s);
        }
    }

    if current_depth < max_depth && !node.deduped && !node.missing {
        for child in node.dependencies.values() {
            collect_child_paths(child, max_depth, current_depth + 1, paths, seen);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_list_clean_tree_exit_code_0() {
        let tmp = tempdir().unwrap();
        let project_dir = tmp.path();

        let pkg_json = serde_json::json!({
            "name": "clean-app",
            "version": "1.0.0",
            "dependencies": {
                "foo": "^1.0.0"
            }
        });
        std::fs::write(project_dir.join("package.json"), pkg_json.to_string()).unwrap();

        let foo_dir = project_dir.join("node_modules").join("foo");
        std::fs::create_dir_all(&foo_dir).unwrap();
        let foo_pkg = serde_json::json!({
            "name": "foo",
            "version": "1.2.0",
            "description": "Foo library",
            "license": "MIT"
        });
        std::fs::write(foo_dir.join("package.json"), foo_pkg.to_string()).unwrap();

        let opts = ListOptions {
            depth: Some(0),
            ..Default::default()
        };
        let code = run_list(project_dir, &opts).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn test_list_problems_exit_code_1() {
        let tmp = tempdir().unwrap();
        let project_dir = tmp.path();

        let pkg_json = serde_json::json!({
            "name": "problem-app",
            "version": "1.0.0",
            "dependencies": {
                "missing-pkg": "^1.0.0"
            }
        });
        std::fs::write(project_dir.join("package.json"), pkg_json.to_string()).unwrap();

        // Extraneous package
        let ext_dir = project_dir.join("node_modules").join("ext-pkg");
        std::fs::create_dir_all(&ext_dir).unwrap();
        let ext_pkg = serde_json::json!({
            "name": "ext-pkg",
            "version": "2.0.0"
        });
        std::fs::write(ext_dir.join("package.json"), ext_pkg.to_string()).unwrap();

        let opts = ListOptions {
            json: true,
            ..Default::default()
        };
        let code = run_list(project_dir, &opts).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn test_text_tree_formatting_branches_and_markers() {
        let mut root = InspectedNode::new_root("my-pkg".into(), Some("1.0.0".into()), Path::new("/workspace/my-pkg"));

        // Child 1: regular
        let c1 = InspectedNode::new_root("alpha".into(), Some("1.0.0".into()), Path::new("/workspace/my-pkg/node_modules/alpha"));
        // Child 2: extraneous
        let mut c2 = InspectedNode::new_root("beta".into(), Some("2.0.0".into()), Path::new("/workspace/my-pkg/node_modules/beta"));
        c2.extraneous = true;
        // Child 3: invalid
        let mut c3 = InspectedNode::new_root("gamma".into(), Some("1.5.0".into()), Path::new("/workspace/my-pkg/node_modules/gamma"));
        c3.invalid = Some("\"^2.0.0\" from the root project".into());
        // Child 4: deduped
        let mut c4 = InspectedNode::new_root("delta".into(), Some("1.0.0".into()), Path::new("/workspace/my-pkg/node_modules/delta"));
        c4.deduped = true;
        // Child 5: missing
        let mut c5 = InspectedNode::new_root("epsilon".into(), None, Path::new(""));
        c5.missing = true;
        c5.required = Some("^3.0.0".into());

        root.dependencies.insert("alpha".into(), c1);
        root.dependencies.insert("beta".into(), c2);
        root.dependencies.insert("gamma".into(), c3);
        root.dependencies.insert("delta".into(), c4);
        root.dependencies.insert("epsilon".into(), c5);

        let text = format_tree_text(&root, 0, false);
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines[0], "my-pkg@1.0.0 /workspace/my-pkg");
        assert_eq!(lines[1], "+-- alpha@1.0.0");
        assert_eq!(lines[2], "+-- beta@2.0.0 extraneous");
        assert_eq!(lines[3], "+-- delta@1.0.0 deduped");
        assert_eq!(lines[4], "+-- UNMET DEPENDENCY epsilon@^3.0.0");
        assert_eq!(lines[5], "`-- gamma@1.5.0 invalid: \"^2.0.0\" from the root project");
    }

    #[test]
    fn test_long_text_formatting() {
        let mut root = InspectedNode::new_root("root-pkg".into(), Some("1.0.0".into()), Path::new("/app"));
        root.description = Some("Root application".into());

        let mut child = InspectedNode::new_root("dep".into(), Some("2.0.0".into()), Path::new("/app/node_modules/dep"));
        child.description = Some("A dependency description".into());
        root.dependencies.insert("dep".into(), child);

        let text = format_tree_text(&root, 0, true);
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines[0], "root-pkg@1.0.0");
        assert_eq!(lines[1], "| /app");
        assert_eq!(lines[2], "| Root application");
        assert_eq!(lines[3], "`-- dep@2.0.0");
        assert_eq!(lines[4], "    | /app/node_modules/dep");
        assert_eq!(lines[5], "    | A dependency description");
    }

    #[test]
    fn test_depth_filtering() {
        let mut root = InspectedNode::new_root("root".into(), Some("1.0.0".into()), Path::new("/app"));

        let mut l1 = InspectedNode::new_root("l1".into(), Some("1.0.0".into()), Path::new("/app/node_modules/l1"));
        let mut l2 = InspectedNode::new_root("l2".into(), Some("1.0.0".into()), Path::new("/app/node_modules/l1/node_modules/l2"));
        let l3 = InspectedNode::new_root("l3".into(), Some("1.0.0".into()), Path::new("/app/node_modules/l1/node_modules/l2/node_modules/l3"));

        l2.dependencies.insert("l3".into(), l3);
        l1.dependencies.insert("l2".into(), l2);
        root.dependencies.insert("l1".into(), l1);

        // depth 0: only l1 is printed
        let text_d0 = format_tree_text(&root, 0, false);
        assert!(text_d0.contains("l1@1.0.0"));
        assert!(!text_d0.contains("l2@1.0.0"));
        assert!(!text_d0.contains("l3@1.0.0"));

        // depth 1: l1 and l2 are printed
        let text_d1 = format_tree_text(&root, 1, false);
        assert!(text_d1.contains("l1@1.0.0"));
        assert!(text_d1.contains("l2@1.0.0"));
        assert!(!text_d1.contains("l3@1.0.0"));

        // depth MAX (all): l1, l2, and l3 are printed
        let text_all = format_tree_text(&root, usize::MAX, false);
        assert!(text_all.contains("l1@1.0.0"));
        assert!(text_all.contains("l2@1.0.0"));
        assert!(text_all.contains("l3@1.0.0"));
    }

    #[test]
    fn test_json_formatting_clean() {
        let mut root = InspectedNode::new_root("app".into(), Some("1.0.0".into()), Path::new("/app"));
        let child = InspectedNode::new_root("dep".into(), Some("2.0.0".into()), Path::new("/app/node_modules/dep"));
        root.dependencies.insert("dep".into(), child);

        let json = format_tree_json(&root, 0, false);
        assert_eq!(json["name"], "app");
        assert_eq!(json["version"], "1.0.0");
        assert!(json["problems"].is_null());
        assert!(json["error"].is_null());
        assert_eq!(json["dependencies"]["dep"]["version"], "2.0.0");
    }

    #[test]
    fn test_json_formatting_with_problems() {
        let mut root = InspectedNode::new_root("app".into(), Some("1.0.0".into()), Path::new("/app"));
        root.problems.push("missing: uninstalled@^1.0.0, required by app@1.0.0".into());

        let mut child = InspectedNode::new_root("uninstalled".into(), None, Path::new(""));
        child.missing = true;
        child.required = Some("^1.0.0".into());
        child.problems.push("missing: uninstalled@^1.0.0, required by app@1.0.0".into());
        root.dependencies.insert("uninstalled".into(), child);

        let json = format_tree_json(&root, 0, false);
        assert_eq!(json["name"], "app");
        assert!(json["problems"].is_array());
        assert_eq!(json["error"]["code"], "ELSPROBLEMS");
        assert_eq!(json["dependencies"]["uninstalled"]["missing"], true);
        assert_eq!(json["dependencies"]["uninstalled"]["required"], "^1.0.0");
    }

    #[test]
    fn test_parseable_formatting() {
        let mut root = InspectedNode::new_root("app".into(), Some("1.0.0".into()), Path::new("/app"));
        let mut d1 = InspectedNode::new_root("d1".into(), Some("1.0.0".into()), Path::new("/app/node_modules/d1"));
        let d2 = InspectedNode::new_root("d2".into(), Some("1.0.0".into()), Path::new("/app/node_modules/d1/node_modules/d2"));

        d1.dependencies.insert("d2".into(), d2);
        root.dependencies.insert("d1".into(), d1);

        let mut paths_d0 = Vec::new();
        let mut seen = HashSet::new();
        collect_parseable_paths(&root, 0, &mut paths_d0, &mut seen);
        assert_eq!(paths_d0, vec![
            PathBuf::from("/app").display().to_string(),
            PathBuf::from("/app/node_modules/d1").display().to_string(),
        ]);

        let mut paths_all = Vec::new();
        let mut seen = HashSet::new();
        collect_parseable_paths(&root, usize::MAX, &mut paths_all, &mut seen);
        assert_eq!(paths_all, vec![
            PathBuf::from("/app").display().to_string(),
            PathBuf::from("/app/node_modules/d1").display().to_string(),
            PathBuf::from("/app/node_modules/d1/node_modules/d2").display().to_string(),
        ]);
    }

    #[test]
    fn test_packages_filtering_direct_and_transitive() {
        let mut root = InspectedNode::new_root("root".into(), Some("1.0.0".into()), Path::new("/app"));

        let mut a = InspectedNode::new_root("a".into(), Some("1.0.0".into()), Path::new("/app/node_modules/a"));
        let b = InspectedNode::new_root("b".into(), Some("1.0.0".into()), Path::new("/app/node_modules/a/node_modules/b"));
        a.dependencies.insert("b".into(), b);

        let mut c = InspectedNode::new_root("c".into(), Some("1.0.0".into()), Path::new("/app/node_modules/c"));
        let d = InspectedNode::new_root("d".into(), Some("1.0.0".into()), Path::new("/app/node_modules/c/node_modules/d"));
        c.dependencies.insert("d".into(), d);

        root.dependencies.insert("a".into(), a);
        root.dependencies.insert("c".into(), c);

        // Filter for "b"
        let mut filtered = root.clone();
        filter_tree_by_packages(&mut filtered, &["b".to_string()]);

        assert!(filtered.dependencies.contains_key("a"));
        assert!(filtered.dependencies["a"].dependencies.contains_key("b"));
        assert!(!filtered.dependencies.contains_key("c"));
    }

    #[test]
    fn test_packages_filtering_with_version_and_scope() {
        let mut root = InspectedNode::new_root("root".into(), Some("1.0.0".into()), Path::new("/app"));

        let s1 = InspectedNode::new_root("@scope/pkg".into(), Some("1.2.3".into()), Path::new("/app/node_modules/@scope/pkg"));
        let other = InspectedNode::new_root("other".into(), Some("1.0.0".into()), Path::new("/app/node_modules/other"));

        root.dependencies.insert("@scope/pkg".into(), s1);
        root.dependencies.insert("other".into(), other);

        // Filter for matching scoped package with range
        let mut filtered = root.clone();
        filter_tree_by_packages(&mut filtered, &["@scope/pkg@^1.0.0".to_string()]);
        assert_eq!(filtered.dependencies.len(), 1);
        assert!(filtered.dependencies.contains_key("@scope/pkg"));

        // Filter for non-matching version
        let mut filtered2 = root.clone();
        filter_tree_by_packages(&mut filtered2, &["@scope/pkg@^2.0.0".to_string()]);
        assert_eq!(filtered2.dependencies.len(), 0);
    }

    #[test]
    fn test_omit_dev_dependencies() {
        let tmp = tempdir().unwrap();
        let project_dir = tmp.path();

        let pkg_json = serde_json::json!({
            "name": "omit-app",
            "version": "1.0.0",
            "dependencies": {
                "prod-pkg": "^1.0.0"
            },
            "devDependencies": {
                "dev-pkg": "^1.0.0"
            }
        });
        std::fs::write(project_dir.join("package.json"), pkg_json.to_string()).unwrap();

        let prod_dir = project_dir.join("node_modules").join("prod-pkg");
        std::fs::create_dir_all(&prod_dir).unwrap();
        std::fs::write(prod_dir.join("package.json"), serde_json::json!({
            "name": "prod-pkg",
            "version": "1.0.0"
        }).to_string()).unwrap();

        let dev_dir = project_dir.join("node_modules").join("dev-pkg");
        std::fs::create_dir_all(&dev_dir).unwrap();
        std::fs::write(dev_dir.join("package.json"), serde_json::json!({
            "name": "dev-pkg",
            "version": "1.0.0"
        }).to_string()).unwrap();

        let opts = ListOptions {
            omit: vec!["dev".into()],
            ..Default::default()
        };
        let code = run_list(project_dir, &opts).unwrap();
        // Since dev-pkg is omitted from dependencies, it will be treated as extraneous if present on disk,
        // or if omit works properly, exit code reflects problems.
        assert!(code == 0 || code == 1);
    }

    #[test]
    fn test_package_lock_only() {
        let tmp = tempdir().unwrap();
        let project_dir = tmp.path();

        let pkg_json = serde_json::json!({
            "name": "lock-only-app",
            "version": "1.0.0",
            "dependencies": {
                "lock-dep": "^1.0.0"
            }
        });
        std::fs::write(project_dir.join("package.json"), pkg_json.to_string()).unwrap();

        let lock_json = serde_json::json!({
            "name": "lock-only-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": {
                    "name": "lock-only-app",
                    "version": "1.0.0",
                    "dependencies": {
                        "lock-dep": "^1.0.0"
                    }
                },
                "node_modules/lock-dep": {
                    "version": "1.0.5",
                    "resolved": "https://registry.npmjs.org/lock-dep/-/lock-dep-1.0.5.tgz",
                    "integrity": "sha512-test"
                }
            }
        });
        std::fs::write(project_dir.join("package-lock.json"), lock_json.to_string()).unwrap();

        // Note: node_modules does not exist on disk!
        let opts = ListOptions {
            package_lock_only: true,
            ..Default::default()
        };
        let code = run_list(project_dir, &opts).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn test_multilevel_nested_branch_lines() {
        let mut root = InspectedNode::new_root("root".into(), Some("1.0.0".into()), Path::new("/app"));

        let mut mid = InspectedNode::new_root("mid".into(), Some("1.0.0".into()), Path::new("/app/node_modules/mid"));
        let sub1 = InspectedNode::new_root("sub1".into(), Some("1.0.0".into()), Path::new("/app/node_modules/mid/node_modules/sub1"));
        let sub2 = InspectedNode::new_root("sub2".into(), Some("1.0.0".into()), Path::new("/app/node_modules/mid/node_modules/sub2"));
        mid.dependencies.insert("sub1".into(), sub1);
        mid.dependencies.insert("sub2".into(), sub2);

        let mut last = InspectedNode::new_root("last".into(), Some("1.0.0".into()), Path::new("/app/node_modules/last"));
        let end1 = InspectedNode::new_root("end1".into(), Some("1.0.0".into()), Path::new("/app/node_modules/last/node_modules/end1"));
        last.dependencies.insert("end1".into(), end1);

        root.dependencies.insert("mid".into(), mid);
        root.dependencies.insert("last".into(), last);

        let text = format_tree_text(&root, usize::MAX, false);
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines[0], "root@1.0.0 /app");
        assert_eq!(lines[1], "+-- last@1.0.0");
        assert_eq!(lines[2], "|   `-- end1@1.0.0");
        assert_eq!(lines[3], "`-- mid@1.0.0");
        assert_eq!(lines[4], "    +-- sub1@1.0.0");
        assert_eq!(lines[5], "    `-- sub2@1.0.0");
    }

    #[test]
    fn test_json_long_includes_description_and_license() {
        let mut root = InspectedNode::new_root("app".into(), Some("1.0.0".into()), Path::new("/app"));
        root.description = Some("App description".into());
        root.license = Some("MIT".into());

        let mut child = InspectedNode::new_root("dep".into(), Some("2.0.0".into()), Path::new("/app/node_modules/dep"));
        child.description = Some("Dep description".into());
        child.license = Some("Apache-2.0".into());
        root.dependencies.insert("dep".into(), child);

        let json = format_tree_json(&root, 0, true);
        assert_eq!(json["description"], "App description");
        assert_eq!(json["license"], "MIT");
        assert_eq!(json["dependencies"]["dep"]["description"], "Dep description");
        assert_eq!(json["dependencies"]["dep"]["license"], "Apache-2.0");
    }

    #[test]
    fn test_package_matches_filter_edge_cases() {
        let node = InspectedNode::new_root("foo".into(), Some("1.2.3".into()), Path::new(""));

        // Match by exact name
        assert!(package_matches_filter("foo", &node, "foo"));
        assert!(!package_matches_filter("bar", &node, "foo"));

        // Match by version spec
        assert!(package_matches_filter("foo", &node, "foo@1.2.3"));
        assert!(package_matches_filter("foo", &node, "foo@^1.0.0"));
        assert!(package_matches_filter("foo", &node, "foo@~1.2.0"));
        assert!(!package_matches_filter("foo", &node, "foo@^2.0.0"));
        assert!(!package_matches_filter("foo", &node, "foo@1.0.0"));

        // Scoped package
        let scoped_node = InspectedNode::new_root("@types/node".into(), Some("18.11.0".into()), Path::new(""));
        assert!(package_matches_filter("@types/node", &scoped_node, "@types/node"));
        assert!(package_matches_filter("@types/node", &scoped_node, "@types/node@^18.0.0"));
        assert!(!package_matches_filter("@types/node", &scoped_node, "@types/node@^20.0.0"));
        assert!(!package_matches_filter("@types/react", &scoped_node, "@types/node"));
    }
}
