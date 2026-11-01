# Lockfile v3 Serialization & Migration Contract

## 1. Specification Overview

`package-lock.json` is the authoritative record of the exact dependency tree resolved for a project. `rnpm` targets **Lockfile Version 3**, the standard format introduced in npm v7 and maintained through npm v11.

---

## 2. Lockfile v3 Schema Definition

A canonical lockfile v3 file contains:

```json
{
  "name": "my-application",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "my-application",
      "version": "1.0.0",
      "dependencies": {
        "express": "^4.18.2"
      },
      "devDependencies": {
        "typescript": "^5.3.3"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-5/PsL6iVEkiGu9SUtUwNdZmxUNYfyc55uvykSTZWB51xF7D6MKnZRCZ4qe0QYWU9QiSJBfjZdPYQ2m6h4VsE5Q==",
      "license": "MIT",
      "dependencies": {
        "accepts": "~1.3.8",
        "array-flatten": "1.1.1"
      },
      "engines": {
        "node": ">= 0.10.0"
      }
    }
  }
}
```

### 2.1. Top-Level Fields
- `name`: String, package name from root `package.json`.
- `version`: String, version from root `package.json`.
- `lockfileVersion`: Integer, strictly `3`.
- `packages`: Map associating POSIX directory paths to package descriptors.

### 2.2. Package Descriptors & Flags
Every entry inside `packages` represents a package installed at a specific path:
- `""` (Empty string key): **The Root Package**. Mirrors root `package.json` manifest (`dependencies`, `devDependencies`, `peerDependencies`, `workspaces`).
- `"node_modules/<name>"`: Direct dependency placed at top-level.
- `"node_modules/<parent>/node_modules/<child>"`: Nested dependency required to resolve version conflicts.
- `"node_modules/@scope/<name>"`: Scoped dependency.

#### Descriptor Properties:
- `version`: Exact resolved semver string.
- `resolved`: Canonical URL of the tarball archive or path for local files.
- `integrity`: Full SSRI hash string (e.g. `sha512-...`).
- `dependencies`: Map of dependency package names to requested range specifiers.
- `devDependencies`: Map of development dependencies (only on root or workspaces).
- `peerDependencies`: Map of declared peer dependencies.
- `peerDependenciesMeta`: Metadata describing optional peers.
- `optionalDependencies`: Map of optional dependencies.
- `bin`: Path or map of executable binaries.
- `engines`: Supported node/npm versions.
- `os`, `cpu`, `libc`: Platform compatibility lists.
- `license`: SPDX license identifier.
- `link`: Boolean, indicates that this node is a symbolic link or junction pointing to a target.
- `inBundle`: Boolean (`true` only). Indicates the package is bundled inside its parent archive.
- `hasInstallScript`: Boolean (`true` only). Indicates the package defines a `preinstall`, `install`, or `postinstall` script.
- `dev`: Boolean (`true` only). Indicates the package is exclusively needed for development.
- `optional`: Boolean (`true` only). Indicates the package is optional.
- `devOptional`: Boolean (`true` only). Package is both a dev dependency and optional.

---

## 3. Deterministic Serialization Contract

To prevent spurious git diffs across machines, operating systems, and toolchains, `package-lock.json` must be serialized with strict determinism.

### 3.1. Formatting Rules
1. **Indentation:** Exactly two spaces (`  `), no tabs.
2. **Line Delimiters:** Strictly LF (`\n`). CRLF (`\r\n`) is **forbidden**, even when running on Windows.
3. **Trailing Newline:** Exactly one newline at the end of the file.
4. **Boolean Normalization:** Flags with false values (`"dev": false`, `"optional": false`, `"inBundle": false`) are omitted entirely.

### 3.2. Lexicographical Key Sorting
1. **Top-Level:** `name`, `version`, `lockfileVersion`, `requires`, `packages`.
2. **Packages Map:** Keys are sorted by ASCII code point:
   - Root package `""` always comes first.
   - Followed by `"node_modules/..."` sorted alphabetically.
3. **Sub-Objects:** All key-value maps (`dependencies`, `devDependencies`, `bin`, `engines`) are sorted alphabetically by key name.

### 3.3. POSIX Path Normalization
- On Windows hosts, path keys must **NEVER** contain backslashes (`\`).
- Windows paths must be normalized to forward slashes (`/`):
  - Correct: `"node_modules/@scope/pkg"`
  - Forbidden: `"node_modules\\@scope\\pkg"`

---

## 4. Legacy Lockfile Migration (v1 / v2 to v3)

`rnpm` transparently ingests legacy lockfile versions and upgrades them to Lockfile v3.

### 4.1. Lockfile v1 Migration (`lockfileVersion: 1`)
- **Structure:** Lockfile v1 uses a nested `dependencies` tree instead of a flat `packages` map.
- **Algorithm:**
  1. Initialize empty `packages` map. Add root entry `packages[""]` from root `package.json`.
  2. Perform depth-first traversal of the `dependencies` tree.
  3. Track path location: starting from `"node_modules/<name>"`. For nested dependencies, append `/node_modules/<child>`.
  4. Convert each v1 entry into a v3 descriptor: extract `version`, `resolved`, `integrity`, and map child keys.
  5. Set `lockfileVersion: 3`.

### 4.2. Lockfile v2 Migration (`lockfileVersion: 2`)
- **Structure:** Lockfile v2 is a hybrid containing both `packages` (v3 format) and a legacy `dependencies` object.
- **Algorithm:**
  1. Retain the existing `packages` map.
  2. Strip the top-level `dependencies` object.
  3. Bump `lockfileVersion` from `2` to `3`.

### 4.3. Migration Execution Policy
- During `rnpm install` or `rnpm update`, the upgraded lockfile v3 is written to disk.
- During `rnpm ci`, legacy lockfiles are migrated in-memory to build the virtual tree without modifying the file on disk.

---

## 5. The Hidden Lockfile (`node_modules/.package-lock.json`)

Whenever `node_modules` is modified, `rnpm` writes a hidden lockfile at `node_modules/.package-lock.json`.

### 5.1. Purpose & Guarantees
- Represents the **actual physical layout** currently present on disk.
- Enables instant, zero-I/O freshness checks on subsequent `rnpm install` invocations.
- If `node_modules/.package-lock.json` matches the root `package-lock.json` and `package.json` has not changed, the install is a complete **no-op** (sub-millisecond execution).

---

## 6. Strict Lockfile Drift Detection in `rnpm ci`

The `ci` command guarantees reproducible environments by adhering to the following contract:

1. **Prerequisite:** `package-lock.json` (or `npm-shrinkwrap.json`) must exist. If missing, exit immediately with error:
   ```text
   npm error code ENOKEY
   npm error The `npm ci` command can only install with an existing package-lock.json
   ```
2. **Drift Verification:**
   - Parse `package.json` dependencies and `package-lock.json` `packages[""]`.
   - Verify that every dependency declared in `package.json` exists in `packages[""]` and has an identical specifier.
   - Verify that no extra or deleted dependencies exist.
3. **Drift Failure Behavior:**
   - If any discrepancy is found, terminate immediately with exit code `1` and error code `ELOCKFILE_DRIFT`.
   - **Zero Filesystem Mutation:** Do not remove or touch `node_modules`.
   - **Zero Network Traffic:** Do not dispatch any HTTP requests to the registry.
