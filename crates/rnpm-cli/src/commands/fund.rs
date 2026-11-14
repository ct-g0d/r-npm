use crate::inspect_tree::{build_dependency_tree, InspectedNode, TreeOptions};
use rnpm_core::ordered_json::{OrderedJsonMap as Map, OrderedJsonValue as Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

fn manifest(node: &InspectedNode) -> Value {
    node.path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p.join("package.json")).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn normalize(funding: &Value) -> Value {
    match funding {
        Value::String(url) => Value::Object(
            [(String::from("url"), Value::String(url.clone()))]
                .into_iter()
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
        value => value.clone(),
    }
}

fn valid(funding: &Value) -> bool {
    match funding {
        Value::Array(items) => items.iter().all(|v| !v.is_array() && valid(v)),
        value => value
            .get("url")
            .and_then(Value::as_str)
            .or_else(|| value.as_str())
            .and_then(|s| reqwest::Url::parse(s).ok())
            .is_some_and(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some()),
    }
}

fn ordered_children<'a>(node: &'a InspectedNode, raw: &Value) -> Vec<&'a InspectedNode> {
    let mut children = Vec::new();
    let mut seen = BTreeSet::new();
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        for (name, _) in raw
            .get(section)
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            if let Some(child) = node.dependencies.get(name) {
                if seen.insert(name.clone()) && !child.missing && !child.extraneous {
                    children.push(child);
                }
            }
        }
    }
    children
}

fn funding_dependencies(
    node: &InspectedNode,
    seen: &mut BTreeSet<(String, Option<String>)>,
    count: &mut usize,
) -> Map {
    let raw = manifest(node);
    // libnpmfund marks every direct edge before recursing, so a shared node
    // appears at the first direct occurrence rather than under a deeper branch.
    let children: Vec<_> = ordered_children(node, &raw)
        .into_iter()
        .filter(|child| seen.insert((child.name.clone(), child.version.clone())))
        .collect();
    let mut result = Map::new();
    let mut trailing = Map::new();
    for child in children {
        let raw = manifest(child);
        let mut item = Map::new();
        if let Some(version) = &child.version {
            item.insert("version".into(), Value::String(version.clone()));
        }
        let funding = raw.get("funding").filter(|f| valid(f)).map(normalize);
        if let Some(funding) = &funding {
            item.insert("funding".into(), funding.clone());
            *count += 1;
        }
        let deps = funding_dependencies(child, seen, count);
        if !deps.is_empty() {
            item.insert("dependencies".into(), Value::Object(deps.clone()));
        }
        if funding.is_some() {
            result.insert(child.name.clone(), Value::Object(item));
        } else {
            trailing.extend(deps);
        }
    }
    result.extend(trailing);
    result
}

#[derive(Default)]
struct HumanNode {
    label: String,
    children: Vec<usize>,
}

fn human_node(
    name: &str,
    data: &Value,
    nodes: &mut Vec<HumanNode>,
    urls: &mut BTreeMap<String, usize>,
    unicode: bool,
) -> Option<usize> {
    let pkg = format!(
        "{name}{}",
        data.get("version")
            .and_then(Value::as_str)
            .map(|v| format!("@{v}"))
            .unwrap_or_default()
    );
    let funding = data.get("funding").cloned().unwrap_or_default();
    let first = funding
        .as_array()
        .and_then(|a| a.first())
        .unwrap_or(&funding);
    let url = first.get("url").and_then(Value::as_str);
    let id = if let Some(url) = url {
        if let Some(id) = urls.get(url).copied() {
            nodes[id].label.push_str(&format!(", {pkg}"));
            None
        } else {
            let id = nodes.len();
            urls.insert(url.to_string(), id);
            nodes.push(HumanNode {
                label: format!(
                    "{url}\n{} {pkg}",
                    if unicode {
                        "\u{2514}\u{2500}\u{2500}"
                    } else {
                        "`--"
                    }
                ),
                children: Vec::new(),
            });
            Some(id)
        }
    } else {
        let id = nodes.len();
        nodes.push(HumanNode {
            label: pkg,
            children: Vec::new(),
        });
        Some(id)
    };
    let children: Vec<_> = data
        .get("dependencies")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(name, data)| human_node(name, data, nodes, urls, unicode))
        .collect();
    if let Some(id) = id {
        nodes[id].children = children;
    }
    id
}

// archy labels can span multiple lines; continuation branches depend on whether
// the labelled item has children of its own.
fn archy(id: usize, nodes: &[HumanNode], prefix: &str, unicode: bool) -> String {
    let node = &nodes[id];
    let vertical = if unicode { "\u{2502}" } else { "|" };
    let mut out = format!(
        "{prefix}{}\n",
        node.label.replace(
            '\n',
            &format!(
                "\n{prefix}{} ",
                if node.children.is_empty() {
                    " "
                } else {
                    vertical
                }
            )
        )
    );
    for (i, child) in node.children.iter().enumerate() {
        let last = i + 1 == node.children.len();
        let more = !nodes[*child].children.is_empty();
        let branch = match (unicode, last, more) {
            (true, true, true) => "\u{2514}\u{2500}\u{252c}",
            (true, true, false) => "\u{2514}\u{2500}\u{2500}",
            (true, false, true) => "\u{251c}\u{2500}\u{252c}",
            (true, false, false) => "\u{251c}\u{2500}\u{2500}",
            (false, true, _) => "`--",
            (false, false, _) => "+--",
        };
        let child_prefix = format!("{prefix}{} ", if last { " " } else { vertical });
        let rendered = archy(*child, nodes, &child_prefix, unicode);
        out.push_str(&format!(
            "{prefix}{branch} {}",
            &rendered[child_prefix.len()..]
        ));
    }
    out
}

pub async fn run(dir: &Path, package: Option<String>, json: bool) -> anyhow::Result<()> {
    let tree = build_dependency_tree(dir, &TreeOptions::default())?;
    let config = rnpm_config::Config::load(Some(dir))?;
    if let Some(package) = package {
        let nodes = tree.collect_all_nodes();
        let selected = if package == "." {
            Some(&tree)
        } else {
            nodes
                .into_iter()
                .filter(|n| n.name == package)
                .max_by_key(|n| {
                    n.version
                        .as_deref()
                        .and_then(|v| rnpm_core::semver::Version::parse(v).ok())
                })
        };
        let mut raw = selected.map(manifest).unwrap_or_default();
        if selected.is_none() {
            let client = super::client_helper::CommandClient::new(dir, None)?;
            let url = client
                .registry_url
                .join(&rnpm_registry::client::encode_package_name(&package))?;
            if let Ok(response) = client.request(reqwest::Method::GET, url, None).send().await {
                if let Ok(metadata) = response.json::<serde_json::Value>().await {
                    if let Some(version) = metadata["dist-tags"]["latest"].as_str() {
                        raw = serde_json::from_value(metadata["versions"][version].clone())?;
                    }
                }
            }
        }
        let funding = normalize(raw.get("funding").unwrap_or(&Value::Null));
        let sources: Vec<_> = match &funding {
            Value::Array(items) => items.iter().filter(|f| valid(f)).collect(),
            item if valid(item) => vec![item],
            _ => Vec::new(),
        };
        if sources.is_empty() {
            anyhow::bail!("npm error code ENOFUND\nnpm error No valid funding method available for: {package}");
        }
        let which = config.get("which").map(str::parse::<usize>).transpose().map_err(|_| anyhow::anyhow!("npm error code EFUNDNUMBER\nnpm error `npm fund [<package-spec>] --which=fundingSourceNumber` must be given a positive integer"))?;
        if which == Some(0) {
            anyhow::bail!("npm error code EFUNDNUMBER\nnpm error `npm fund [<package-spec>] --which=fundingSourceNumber` must be given a positive integer");
        }
        let message = |source: &Value| {
            let kind = source
                .get("type")
                .and_then(Value::as_str)
                .map(|t| format!("{t} funding"))
                .unwrap_or_else(|| "Funding".into());
            format!("{kind} available at the following URL")
        };
        if let Some(source) = which.and_then(|n| sources.get(n - 1).copied()).or_else(|| {
            if which.is_none() && sources.len() == 1 {
                Some(sources[0])
            } else {
                None
            }
        }) {
            let url = source.get("url").and_then(Value::as_str).unwrap_or("");
            if config.get("browser") == Some("false") {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({"title":message(source),"url":url})
                        )?
                    );
                } else {
                    println!("{}:\n{url}", message(source));
                }
            } else {
                let browser = config.get("browser").filter(|b| *b != "true");
                let command = browser.unwrap_or(if cfg!(windows) {
                    "explorer.exe"
                } else if cfg!(target_os = "macos") {
                    "open"
                } else {
                    "xdg-open"
                });
                let _ = std::process::Command::new(command).arg(url).status()?;
            }
        } else {
            if let Some(which) = which {
                println!("--which={which} is not a valid index");
            }
            for (i, source) in sources.iter().enumerate() {
                println!(
                    "{}: {}: {}",
                    i + 1,
                    message(source),
                    source.get("url").and_then(Value::as_str).unwrap_or("")
                );
            }
            println!("Run `npm fund [<package-spec>] --which=1`, for example, to open the first funding URL listed in that package");
        }
        return Ok(());
    }
    let mut count = 0;
    let deps = funding_dependencies(&tree, &mut BTreeSet::new(), &mut count);
    let mut report = Map::new();
    report.insert("length".into(), Value::Number(count.into()));
    report.insert("name".into(), Value::String(tree.name.clone()));
    if let Some(version) = &tree.version {
        report.insert("version".into(), Value::String(version.clone()));
    }
    let raw = manifest(&tree);
    if let Some(funding) = raw.get("funding") {
        report.insert("funding".into(), normalize(funding));
    }
    report.insert("dependencies".into(), Value::Object(deps));
    let report = Value::Object(report);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let mut nodes = Vec::new();
        let unicode = crate::use_unicode(dir);
        if let Some(id) = human_node(
            &tree.name,
            &report,
            &mut nodes,
            &mut BTreeMap::new(),
            unicode,
        ) {
            println!("{}", archy(id, &nodes, "", unicode));
        }
    }
    Ok(())
}
