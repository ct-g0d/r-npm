//! Port of npm's lib/utils/reify-output.js: the summary printed after
//! install, ci, update, dedupe, prune, uninstall and audit fix.

use crate::audit::AuditReport;
use rnpm_install::{ReifyChange, ReifyEntry, ReifyReport};
use serde_json::{json, Value};
use std::path::Path;

pub(crate) struct ReifyOutputOptions {
    pub json: bool,
    pub silent: bool,
    /// Warnings reach stderr unless loglevel is error or silent.
    pub warnings: bool,
    pub dry_run: bool,
    pub long: bool,
    pub fund: bool,
    pub global: bool,
    /// `npm audit fix` prints the detailed report instead of the install summary.
    pub audit_command: bool,
}

impl ReifyOutputOptions {
    pub fn from_config_loaded(
        config: &rnpm_config::Config,
        json: bool,
        dry_run: bool,
        fund: bool,
    ) -> Self {
        Self {
            json: json || config.get_bool("json").unwrap_or(false),
            silent: config.get("loglevel") == Some("silent")
                || config.get_bool("silent").unwrap_or(false),
            warnings: !matches!(config.get("loglevel"), Some("silent" | "error"))
                && !config.get_bool("silent").unwrap_or(false),
            dry_run: dry_run || config.get_bool("dry-run").unwrap_or(false),
            long: config.get_bool("long").unwrap_or(false),
            fund,
            global: config.get_bool("global").unwrap_or(false),
            audit_command: false,
        }
    }
}

fn entry_json(project_dir: &Path, e: &ReifyEntry) -> Value {
    let mut path = project_dir.to_path_buf();
    for part in e.location.split('/') {
        path.push(part);
    }
    json!({ "name": e.name, "version": e.version, "path": path.to_string_lossy() })
}

/// npm-audit-report's install reporter.
pub(crate) fn install_audit_report(report: &AuditReport) -> String {
    let counts = &report.metadata.vulnerabilities;
    if counts.total == 0 {
        return "found 0 vulnerabilities".to_string();
    }
    let mut out: Vec<String> = Vec::new();
    let (mut fixable, mut force, mut major, mut unfixable) = (false, false, false, false);
    for vuln in report.vulnerabilities.values() {
        fixable |= vuln.fix_available == Value::Bool(true);
        unfixable |= vuln.fix_available == Value::Bool(false);
        if vuln.fix_available.is_object() {
            force = true;
            major |= vuln.fix_available["isSemVerMajor"] == Value::Bool(true);
        }
    }
    let sevs: Vec<(&str, usize)> = [
        ("low", counts.low),
        ("moderate", counts.moderate),
        ("high", counts.high),
        ("critical", counts.critical),
    ]
    .into_iter()
    .filter(|(_, c)| *c > 0)
    .collect();
    if sevs.len() > 1 {
        let list = sevs
            .iter()
            .map(|(s, c)| format!("{c} {s}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(format!("{} vulnerabilities ({list})", counts.total));
    } else if let Some((sev, count)) = sevs.first() {
        out.push(format!(
            "{count} {sev} severity vulnerabilit{}",
            if *count == 1 { "y" } else { "ies" }
        ));
    }
    if fixable {
        out.push(String::new());
        out.push(format!(
            "To address {}, run:\n  npm audit fix",
            if force || unfixable {
                "issues that do not require attention"
            } else {
                "all issues"
            }
        ));
    }
    if force {
        out.push(String::new());
        out.push(format!(
            "To address all issues{}{}, run:\n  npm audit fix --force",
            if unfixable { " possible" } else { "" },
            if major {
                " (including breaking changes)"
            } else {
                ""
            }
        ));
    }
    if unfixable {
        out.push(String::new());
        out.push("Some issues need review, and may require choosing".to_string());
        out.push("a different dependency.".to_string());
    }
    format!("{}\n\nRun `npm audit` for details.", out.join("\n"))
}

/// npm warns once for every package it reifies whose metadata is deprecated
/// (arborist reify.js, after extracting the node). The note is read from the
/// lockfile written for the new tree.
fn warn_deprecated(project_dir: &Path, report: &ReifyReport) {
    let read = |file: &str| -> Option<Value> {
        serde_json::from_slice(&std::fs::read(project_dir.join(file)).ok()?).ok()
    };
    let Some(lock) = read("node_modules/.package-lock.json")
        .or_else(|| read("npm-shrinkwrap.json"))
        .or_else(|| read("package-lock.json"))
    else {
        return;
    };
    let Some(packages) = lock.get("packages") else {
        return;
    };
    for change in &report.changes {
        let entry = match change {
            ReifyChange::Add(entry) | ReifyChange::Change { to: entry, .. } => entry,
            ReifyChange::Remove(_) => continue,
        };
        let Some(meta) = packages.get(&entry.location) else {
            continue;
        };
        let Some(message) = meta
            .get("deprecated")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        // _id uses the real package name, so an alias reports its target.
        let name = meta
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(&entry.name);
        let text = format!("{name}@{}: {message}", entry.version);
        for line in text.lines() {
            eprintln!("{}", format!("npm warn deprecated {line}").trim_end());
        }
    }
}

pub(crate) fn print(
    project_dir: &Path,
    report: &ReifyReport,
    audit: Option<&AuditReport>,
    funding: usize,
    opts: &ReifyOutputOptions,
    elapsed: std::time::Duration,
) -> anyhow::Result<()> {
    if opts.warnings && !opts.silent {
        for warning in &report.peer_warnings {
            for line in warning.split('\n') {
                eprintln!("{}", format!("npm warn {line}").trim_end());
            }
        }
    }
    if opts.warnings && !opts.silent && !opts.dry_run {
        warn_deprecated(project_dir, report);
    }
    if opts.silent {
        return Ok(());
    }
    let show_diff = !opts.json && (opts.dry_run || opts.long);
    let (mut add, mut change, mut remove) = (Vec::new(), Vec::new(), Vec::new());
    for c in &report.changes {
        match c {
            ReifyChange::Remove(e) => {
                if show_diff {
                    println!("remove {} {}", e.name, e.version);
                }
                remove.push(entry_json(project_dir, e));
            }
            ReifyChange::Add(e) => {
                if show_diff {
                    println!("add {} {}", e.name, e.version);
                }
                add.push(entry_json(project_dir, e));
            }
            ReifyChange::Change { from, to } => {
                if show_diff {
                    println!("change {} {} => {}", from.name, from.version, to.version);
                }
                change.push(json!({ "from": entry_json(project_dir, from), "to": entry_json(project_dir, to) }));
            }
        }
    }
    let audited = if audit.is_some() { report.inventory } else { 0 };
    let funding = if opts.fund { funding } else { 0 };
    let (added, changed, removed) = (add.len(), change.len(), remove.len());

    if opts.json {
        let mut summary = serde_json::Map::new();
        summary.insert("add".into(), Value::Array(add));
        summary.insert("added".into(), added.into());
        summary.insert("audited".into(), audited.into());
        summary.insert("change".into(), Value::Array(change));
        summary.insert("changed".into(), changed.into());
        summary.insert("funding".into(), funding.into());
        summary.insert("remove".into(), Value::Array(remove));
        summary.insert("removed".into(), removed.into());
        if let Some(audit) = audit {
            summary.insert(
                "audit".into(),
                if opts.audit_command {
                    serde_json::to_value(audit)?
                } else {
                    serde_json::to_value(&audit.metadata)?
                },
            );
        }
        println!("{}", serde_json::to_string_pretty(&Value::Object(summary))?);
        return Ok(());
    }

    let plural = |n: usize| if n == 1 { "" } else { "s" };
    let mut msg = String::from("\n");
    if added == 0 && removed == 0 && changed == 0 {
        msg.push_str("up to date");
        if audited > 0 {
            msg.push_str(", ");
        }
    } else {
        if added > 0 {
            msg.push_str(&format!("added {added} package{}", plural(added)));
        }
        if removed > 0 {
            if added > 0 {
                msg.push_str(", ");
            }
            if added > 0 && audited == 0 && changed == 0 {
                msg.push_str("and ");
            }
            msg.push_str(&format!("removed {removed} package{}", plural(removed)));
        }
        if changed > 0 {
            if added > 0 || removed > 0 {
                msg.push_str(", ");
            }
            if audited == 0 && (added > 0 || removed > 0) {
                msg.push_str("and ");
            }
            msg.push_str(&format!("changed {changed} package{}", plural(changed)));
        }
        if audited > 0 {
            msg.push_str(", and ");
        }
    }
    if audited > 0 {
        msg.push_str(&format!("audited {audited} package{}", plural(audited)));
    }
    msg.push_str(&format!(" in {}", crate::format_duration(elapsed)));
    println!("{msg}");

    if funding > 0 && !opts.global {
        println!();
        println!(
            "{funding} {} looking for funding",
            if funding == 1 {
                "package is"
            } else {
                "packages are"
            }
        );
        println!("  run `npm fund` for details");
    }

    if let Some(audit) = audit {
        if opts.audit_command {
            println!();
            crate::audit::print_human_audit_report(audit);
        } else {
            println!("\n{}", install_audit_report(audit));
        }
    }
    Ok(())
}

pub(crate) type Tree = std::collections::BTreeMap<String, rnpm_lockfile::LockfilePackage>;

/// The tree on disk, as arborist's loadActual sees it.
pub(crate) fn snapshot(project_dir: &Path) -> Tree {
    let (lock_path, _) = rnpm_install::resolve_lockfile_path(project_dir);
    let lock = rnpm_lockfile::load_and_migrate(&lock_path)
        .ok()
        .map(|l| l.packages);
    rnpm_install::reify_report::load_actual(
        project_dir,
        rnpm_install::validate_hidden_lockfile_simple(project_dir),
        lock.as_ref(),
    )
}

/// The reify diff between two on-disk snapshots of a project.
pub(crate) fn report_between(before: &Tree, after: &Tree) -> ReifyReport {
    let mut report =
        rnpm_install::reify_report::compute(after, before, None, |_, _| false, |_| true);
    report.inventory = after.keys().filter(|k| !k.is_empty()).count() + 1;
    report
}

/// Prints reify output for a command that mutated (or, in a dry run,
/// planned) the tree, auditing the result unless audit is disabled.
#[allow(dead_code)]
pub(crate) async fn finish(
    project_dir: &Path,
    report: &ReifyReport,
    json: bool,
    dry_run: bool,
    silent: bool,
    elapsed: std::time::Duration,
) -> anyhow::Result<()> {
    finish_with_config(project_dir, report, json, dry_run, silent, elapsed, None).await
}

pub(crate) async fn finish_with_config(
    project_dir: &Path,
    report: &ReifyReport,
    json: bool,
    dry_run: bool,
    silent: bool,
    elapsed: std::time::Duration,
    preloaded_config: Option<&rnpm_config::Config>,
) -> anyhow::Result<()> {
    let owned_config;
    let config = match preloaded_config {
        Some(cfg) => cfg,
        None => {
            owned_config = rnpm_config::Config::load(Some(project_dir)).unwrap_or_default();
            &owned_config
        }
    };
    let audit_enabled = config.get_bool("audit").unwrap_or(true);
    let fund_enabled = config.get_bool("fund").unwrap_or(true);
    let mut opts = ReifyOutputOptions::from_config_loaded(config, json, dry_run, fund_enabled);
    opts.silent |= silent;
    let parsed_lock = if !opts.dry_run && audit_enabled && fund_enabled {
        let (lock_path, _) = rnpm_install::resolve_lockfile_path(project_dir);
        if lock_path.exists() {
            rnpm_lockfile::load_and_migrate(&lock_path).ok()
        } else {
            None
        }
    } else {
        None
    };
    let audit = if audit_enabled && !opts.dry_run && project_dir.join("package-lock.json").exists()
    {
        crate::audit::build_audit_report_with_config_and_lockfile(
            project_dir,
            None,
            Some(config),
            parsed_lock.as_ref(),
        )
        .await
        .ok()
        .map(|(r, _)| r)
    } else {
        None
    };
    let funding = if fund_enabled && !opts.dry_run {
        crate::audit::count_funding_packages_with_lockfile(project_dir, parsed_lock.as_ref())
    } else {
        0
    };
    print(project_dir, report, audit.as_ref(), funding, &opts, elapsed)
}
