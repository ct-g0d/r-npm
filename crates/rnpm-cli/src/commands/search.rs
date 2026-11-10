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
    if args.json {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else if let Some(objects) = value.get("objects").and_then(|v| v.as_array()) {
        for item in objects {
            let p = item.get("package").unwrap_or(item);
            let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let version = p.get("version").and_then(|v| v.as_str()).unwrap_or("");
            let description = p.get("description").and_then(|v| v.as_str()).unwrap_or("");
            if args.parseable {
                println!("{name}\t{version}\t{description}");
            } else if args.no_description {
                println!("{name}@{version}");
            } else {
                println!("{name}@{version}\t{description}");
            }
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&value)?);
    }
    Ok(())
}
