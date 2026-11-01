use crate::*;
use tempfile::tempdir;
use std::fs;

#[test]
fn test_generate_shims_content() {
    let posix = generate_posix_shim("typescript/bin/tsc.js");
    assert!(posix.starts_with("#!/bin/sh"));
    assert!(posix.contains("\"$basedir/../typescript/bin/tsc.js\""));

    let cmd = generate_cmd_shim("typescript/bin/tsc.js");
    assert!(cmd.starts_with("@ECHO off"));
    assert!(cmd.contains("%dp0%\\..\\typescript\\bin\\tsc.js"));

    let ps1 = generate_ps1_shim("typescript/bin/tsc.js");
    assert!(ps1.starts_with("#!/usr/bin/env pwsh"));
    assert!(ps1.contains("$basedir/../typescript/bin/tsc.js"));
}

#[test]
fn test_create_shims_on_disk() {
    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("node_modules").join(".bin");
    create_shims(&bin_dir, "tsc", "typescript/bin/tsc.js").unwrap();

    assert!(bin_dir.join("tsc").exists());
    assert!(bin_dir.join("tsc.cmd").exists());
    assert!(bin_dir.join("tsc.ps1").exists());
}

#[test]
fn test_normalize_shebang() {
    let dir = tempdir().unwrap();
    let script = dir.path().join("cli.js");
    fs::write(&script, b"#!/usr/bin/env node\r\nconsole.log(1);\r\n").unwrap();

    normalize_shebang(&script).unwrap();
    let content = fs::read(&script).unwrap();
    assert_eq!(&content[..20], b"#!/usr/bin/env node\n");
}
