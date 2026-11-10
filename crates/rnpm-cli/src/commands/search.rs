use anyhow::Result;
use std::path::PathBuf;

pub(crate) struct SearchArgs {
    pub terms: Vec<String>,
    pub search_limit: usize,
    pub json: bool,
    pub parseable: bool,
    pub no_description: bool,
    pub registry: Option<String>,
}

pub(crate) async fn run(args: SearchArgs, current_dir: PathBuf) -> Result<()> {
    let (registry_url, client) = crate::make_registry_client(&current_dir, args.registry)?;
    let text = args.terms.join(" ");
    let value = client
        .search(Some(&registry_url), &text, args.search_limit, 0)
        .await?;

    let objects = value
        .get("objects")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let packages: Vec<serde_json::Value> = objects
        .into_iter()
        .map(|item| {
            if let Some(pkg) = item.get("package") {
                pkg.clone()
            } else {
                item
            }
        })
        .collect();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&packages)?);
    } else if args.parseable {
        for p in &packages {
            let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let version = p.get("version").and_then(|v| v.as_str()).unwrap_or("");
            let description = p.get("description").and_then(|v| v.as_str()).unwrap_or("");
            let date_str = p
                .get("date")
                .and_then(|v| v.as_str())
                .map(|d| d.split('T').next().unwrap_or(d))
                .unwrap_or("");
            let keywords = p
                .get("keywords")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|k| k.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            println!("{name}\t{description}\t{date_str}\t{version}\t{keywords}");
        }
    } else {
        for p in &packages {
            let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let version = p.get("version").and_then(|v| v.as_str()).unwrap_or("");
            let description = p.get("description").and_then(|v| v.as_str()).unwrap_or("");
            let date_str = p
                .get("date")
                .and_then(|v| v.as_str())
                .map(|d| d.split('T').next().unwrap_or(d))
                .unwrap_or("");
            let publisher = p
                .get("publisher")
                .and_then(|v| {
                    if let Some(s) = v.as_str() {
                        Some(s.to_string())
                    } else {
                        v.get("username")
                            .and_then(|u| u.as_str())
                            .map(|s| s.to_string())
                    }
                })
                .unwrap_or_default();
            let maintainers: Vec<&str> = p
                .get("maintainers")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|m| {
                            if let Some(s) = m.as_str() {
                                Some(s)
                            } else {
                                m.get("username").and_then(|u| u.as_str())
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            let keywords: Vec<&str> = p
                .get("keywords")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|k| k.as_str()).collect())
                .unwrap_or_default();

            println!("{name}");
            if !args.no_description && !description.is_empty() {
                println!("{description}");
            }
            if !publisher.is_empty() {
                println!("Version {version} published {date_str} by {publisher}");
            } else if !date_str.is_empty() {
                println!("Version {version} published {date_str}");
            } else {
                println!("Version {version}");
            }
            if !maintainers.is_empty() {
                println!("Maintainers: {}", maintainers.join(" "));
            }
            if !keywords.is_empty() {
                println!("Keywords: {}", keywords.join(" "));
            }
            println!("https://npm.im/{name}\n");
        }
    }
    Ok(())
}
