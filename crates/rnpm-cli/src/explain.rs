use crate::inspect_tree::{build_dependency_tree, InspectedNode, TreeOptions};
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Explanation<'a> {
    name: &'a str,
    version: Option<&'a str>,
    location: &'a str,
    is_workspace: bool,
    dependents: Vec<Dependent<'a>>,
    dev: bool,
    optional: bool,
    dev_optional: bool,
    peer: bool,
    bundled: bool,
    overridden: bool,
}

#[derive(Serialize)]
struct Dependent<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    name: &'a str,
    spec: &'a str,
    #[serde(rename = "rawSpec", skip_serializing_if = "Option::is_none")]
    raw_spec: Option<&'a str>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    overridden: bool,
    from: FromNode<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FromNode<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    location: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_workspace: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dependents: Option<Vec<Dependent<'a>>>,
}

fn dependents<'a>(
    node: &InspectedNode,
    nodes: &[&'a InspectedNode],
    root_path: &'a str,
    visited: &mut Vec<String>,
) -> Vec<Dependent<'a>> {
    if visited.contains(&node.location) {
        return Vec::new();
    }
    visited.push(node.location.clone());
    let mut result = Vec::new();
    for parent in nodes {
        for child in parent.dependencies.values() {
            if child.missing || child.location != node.location {
                continue;
            }
            let kind = parent
                .raw_manifest
                .as_ref()
                .map(|manifest| {
                    if manifest
                        .get("optionalDependencies")
                        .and_then(|v| v.get(&child.name))
                        .is_some()
                    {
                        "optional"
                    } else if manifest
                        .get("peerDependencies")
                        .and_then(|v| v.get(&child.name))
                        .is_some()
                    {
                        if manifest
                            .get("peerDependenciesMeta")
                            .and_then(|v| v.get(&child.name))
                            .and_then(|v| v.get("optional"))
                            .and_then(|v| v.as_bool())
                            == Some(true)
                        {
                            "peerOptional"
                        } else {
                            "peer"
                        }
                    } else if parent.location.is_empty()
                        && manifest
                            .get("devDependencies")
                            .and_then(|v| v.get(&child.name))
                            .is_some()
                    {
                        "dev"
                    } else {
                        "prod"
                    }
                })
                .unwrap_or("prod");
            let field = match kind {
                "dev" => "devDependencies",
                "optional" => "optionalDependencies",
                "peer" | "peerOptional" => "peerDependencies",
                _ => "dependencies",
            };
            let spec = parent
                .raw_manifest
                .as_ref()
                .and_then(|manifest| manifest.get(field))
                .and_then(|deps| deps.get(&child.name))
                .and_then(|value| value.as_str())
                .or(child.required.as_deref())
                .unwrap_or("*");
            let from = if parent.location.is_empty() {
                FromNode {
                    name: None,
                    version: None,
                    location: root_path,
                    is_workspace: None,
                    dependents: None,
                }
            } else {
                FromNode {
                    name: Some(&parent.name),
                    version: parent.version.as_deref(),
                    location: &parent.location,
                    is_workspace: Some(!parent.location.starts_with("node_modules/")),
                    dependents: Some(dependents(parent, nodes, root_path, visited)),
                }
            };
            result.push(Dependent {
                kind,
                name: &child.name,
                spec: if child.overridden {
                    child.required.as_deref().unwrap_or(spec)
                } else {
                    spec
                },
                raw_spec: child.overridden.then_some(spec),
                overridden: child.overridden,
                from,
            });
        }
    }
    visited.pop();
    result
}

pub fn run_explain(project_dir: &Path, package: &str, json: bool) -> anyhow::Result<()> {
    let root = build_dependency_tree(project_dir, &TreeOptions::default())?;
    let nodes = root.collect_all_nodes();
    let root_path = project_dir.to_string_lossy();
    let matches: Vec<_> = nodes
        .iter()
        .filter(|node| {
            !node.location.is_empty()
                && !node.missing
                && (node.location == package.replace('\\', "/")
                    || crate::list::package_matches_filter(&node.name, node, package))
        })
        .map(|node| Explanation {
            name: &node.name,
            version: node.version.as_deref(),
            location: &node.location,
            is_workspace: !node.location.starts_with("node_modules/"),
            dependents: dependents(node, &nodes, &root_path, &mut Vec::new()),
            dev: node.dev,
            optional: node.optional,
            dev_optional: node.dev && node.optional,
            peer: node.peer,
            bundled: node.in_bundle,
            overridden: node.overridden,
        })
        .collect();
    if matches.is_empty() {
        anyhow::bail!("npm error code EUSAGE\nnpm error No dependencies found matching {package}");
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&matches)?);
    } else {
        for (i, node) in matches.iter().enumerate() {
            if i > 0 {
                println!();
            }
            let mut flags = String::new();
            for (flag, enabled) in [
                ("dev", node.dev),
                ("optional", node.optional),
                ("peer", node.peer),
                ("bundled", node.bundled),
                ("overridden", node.overridden),
            ] {
                if enabled {
                    flags.push_str(&format!(" {flag}"));
                }
            }
            println!(
                "{}@{}{}\n{}",
                node.name,
                node.version.unwrap_or("unknown"),
                flags,
                node.location
            );
            print_dependents(&node.dependents, "  ");
        }
    }
    Ok(())
}

fn print_dependents(edges: &[Dependent<'_>], indent: &str) {
    for edge in edges {
        let kind = if edge.kind == "prod" {
            String::new()
        } else {
            format!("{} ", edge.kind)
        };
        let overridden = if edge.overridden { "overridden " } else { "" };
        let was = edge
            .raw_spec
            .map(|s| format!(" (was \"{s}\")"))
            .unwrap_or_default();
        let source = edge
            .from
            .name
            .map(|name| format!("{name}@{}", edge.from.version.unwrap_or("unknown")))
            .unwrap_or_else(|| "the root project".to_string());
        println!(
            "{indent}{kind}{overridden}{}@\"{}\"{was} from {source}",
            edge.name, edge.spec
        );
        if edge.from.name.is_some() {
            println!("{indent}{}", edge.from.location);
            if let Some(edges) = &edge.from.dependents {
                print_dependents(edges, &format!("{indent}  "));
            }
        }
    }
}
