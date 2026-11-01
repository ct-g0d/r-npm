# Dependency Resolver & node-semver Contract

## 1. node-semver Compatibility Specification

The standard Rust `semver` crate implements Cargo's semver specification, which deviates materially from `node-semver`. `rnpm` requires an explicit, frozen `node-semver` implementation that guarantees 100% behavioral parity with `semver@7.x`.

### 1.1. Version Grammar & Structure
A version string conforms to:
```text
<version> ::= <major> "." <minor> "." <patch> ["-" <prerelease>] ["+" <build>]
<major>   ::= [0-9]+
<minor>   ::= [0-9]+
<patch>   ::= [0-9]+
```
- **Major, Minor, Patch:** Non-negative integers with no leading zeroes (unless the number is `0`).
- **Build Metadata:** One or more dot-separated identifiers `[0-9A-Za-z-]+`. Build metadata is stored for exact equality checks, but is strictly **ignored** when determining version precedence.

### 1.2. Prerelease Sorting & Precedence Rules
A prerelease consists of dot-separated identifiers (e.g. `1.0.0-alpha.1.beta`).
- A version without a prerelease has higher precedence than a version with a prerelease on the same major.minor.patch tuple:
  `1.0.0 > 1.0.0-rc.1 > 1.0.0-beta > 1.0.0-alpha`.
- Comparing two prereleases on the same major.minor.patch tuple:
  1. Compare each dot-separated identifier from left to right.
  2. Numeric identifiers are compared as integers: `2 < 10`.
  3. Alphanumeric identifiers are compared lexicographically using ASCII order: `alpha < beta`.
  4. Numeric identifiers always have lower precedence than alphanumeric identifiers: `1 < alpha`.
  5. A larger set of pre-release identifiers has a higher precedence than a smaller set, if all of the preceding identifiers are equal: `1.0.0-alpha < 1.0.0-alpha.1`.

### 1.3. Prerelease Range Matching Contract
**The Prerelease Isolation Rule:** A range comparator tuple does **NOT** match a prerelease version unless the comparator itself includes a prerelease tag on the **exact same** major.minor.patch tuple:
- `^1.2.3` does NOT match `1.2.4-alpha.0`.
- `>=1.2.0` does NOT match `1.2.3-beta`.
- `^1.2.3-alpha.0` DOES match `1.2.3-alpha.1` (same major.minor.patch).
- `^1.2.3-alpha.0` does NOT match `1.2.4-alpha.0` (different patch).

### 1.4. Range Grammar & Operators
Ranges are expressed in Disjunctive Normal Form (DNF): a set of comparator sets joined by `||`. A version satisfies a range if it satisfies at least one comparator set.

#### 1.4.1. Caret (`^`) Operator
The caret operator permits updates that do not modify the leftmost non-zero digit in the `[major, minor, patch]` tuple:
- **Major > 0:** `^1.2.3` -> `>=1.2.3 <2.0.0`
- **Major = 0, Minor > 0:** `^0.2.3` -> `>=0.2.3 <0.3.0` (zero major freezes minor)
- **Major = 0, Minor = 0:** `^0.0.3` -> `=0.0.3` (zero major and minor freezes patch)
- **Truncated Caret:**
  - `^1.x` / `^1` -> `>=1.0.0 <2.0.0`
  - `^0.x` / `^0` -> `>=0.0.0 <1.0.0`
  - `^0.0.x` / `^0.0` -> `>=0.0.0 <0.1.0`

#### 1.4.2. Tilde (`~`) Operator
The tilde operator allows patch-level changes if minor is specified, or minor-level changes if minor is omitted:
- `~1.2.3` -> `>=1.2.3 <1.3.0`
- `~1.2` / `~1.2.x` -> `>=1.2.0 <1.3.0`
- `~1` / `~1.x` -> `>=1.0.0 <2.0.0`
- `~0.2.3` -> `>=0.2.3 <0.3.0`
- `~0` -> `>=0.0.0 <1.0.0`

#### 1.4.3. Hyphen (`-`) Ranges
- Inclusive range when both ends are fully specified:
  - `1.2.3 - 2.3.4` -> `>=1.2.3 <=2.3.4`
- Partial right-hand side extends to the end of the specified tuple:
  - `1.2.3 - 2.3` -> `>=1.2.3 <2.4.0`
  - `1.2.3 - 2` -> `>=1.2.3 <3.0.0`
  - `1.2 - 2.3.4` -> `>=1.2.0 <=2.3.4`

#### 1.4.4. Wildcards & Partials
- `*`, `x`, `X`, or empty string `""`: Matches any version `>=0.0.0` (excluding prereleases).
- `1.x` / `1.*` -> `>=1.0.0 <2.0.0`.
- `1.2.x` / `1.2.*` -> `>=1.2.0 <1.3.0`.

#### 1.4.5. Loose Mode
When parsing in loose mode:
- Strip leading `v`, `V`, or `=`: e.g. `v1.2.3` -> `1.2.3`.
- Allow spaces between operators and versions: `>= 1.2.3` -> `>=1.2.3`.
- Tolerate single or double number versions: `1` -> `1.0.0`, `1.2` -> `1.2.0`.

---

## 2. Package Specifier Grammar (`npm-package-arg`)

Package specifiers conform to the following classification:

| Type | Syntax Example | Meaning |
|---|---|---|
| `tag` | `react@latest`, `vue@next` | Distribution tag mapped via registry packument `dist-tags` |
| `version` | `lodash@4.17.21` | Exact semver version |
| `range` | `express@^4.18.2`, `debug@~2.6.9` | Semver range specification |
| `alias` | `my-pkg@npm:real-pkg@^1.0.0` | Alias mapping `my-pkg` to `real-pkg` |
| `file` (dir) | `local@file:../packages/ui` | Local filesystem directory linked via junction/symlink |
| `file` (tgz) | `archive@file:./libs/pkg-1.0.0.tgz` | Local tarball extracted and verified |
| `remote` | `https://example.com/pkg.tgz` | Direct HTTP(S) tarball download |

### Scoped Package Name Constraints
- Scoped format: `@<scope>/<name>`.
- Scope and name must consist of URL-safe characters: `[a-z0-9_.-]`.
- Max length: 214 characters total.
- Scopes must not contain uppercase characters.
- Must be URL-encoded when querying the registry (e.g. `@scope%2fname`).

---

## 3. Dependency Graph Data Model & Hoisting Algorithm

### 3.1. Graph Data Model
- `DependencyGraph`:
  - `root`: Root workspace or project package.
  - `nodes`: Map of package locations on disk (e.g. `""`, `"node_modules/foo"`, `"node_modules/bar/node_modules/foo"`).
  - `edges`: Outgoing and incoming dependencies connecting nodes.
- `Node`:
  - `name`: Real package name.
  - `version`: Resolved exact version.
  - `location`: POSIX path relative to root (e.g. `"node_modules/foo"`).
  - `manifest`: Parsed `package.json`.
  - `integrity`: SSRI string.
  - `resolved`: URL or file path.
  - `flags`: `dev`, `optional`, `peer`, `bundled`, `hasInstallScript`.

### 3.2. Hoisting & Deduplication Rules (Arborist Parity)
1. **Deduplication Priority:** Always reuse an existing node in an ancestor scope if its resolved version satisfies the dependency's semver range.
2. **Top-Level Hoisting:**
   - Attempt to place every dependency at the highest possible directory level (`node_modules/<name>`).
   - If `node_modules/<name>` is vacant, place it there.
   - If `node_modules/<name>` is occupied by an identical version, reuse the existing node (deduplicated).
   - If `node_modules/<name>` is occupied by an incompatible version (conflict), traverse down the tree to the dependent's local `node_modules` directory (`node_modules/<parent>/node_modules/<name>`).
3. **Deterministic Traversal:** Dependency resolution and edge evaluation must proceed in lexicographical order of package names to ensure identical tree geometry across runs.

---

## 4. Aliases Engine (`npm:`)

`npm:` aliases decouple the dependency name exposed in `package.json` from the physical package name downloaded from the registry.

### Contract:
1. Manifest declaration:
   ```json
   "dependencies": {
     "my-chalk": "npm:chalk@^5.3.0"
   }
   ```
2. Resolution:
   - Dependency edge key is `my-chalk`.
   - Registry lookup queries `chalk`.
   - Version resolved matches `^5.3.0` of `chalk`.
3. Filesystem Placement:
   - Placed at `node_modules/my-chalk`.
   - The directory contains the contents of `chalk`, with its `package.json` retaining `name: "chalk"`.
4. Lockfile Serialization:
   ```json
   "node_modules/my-chalk": {
     "name": "chalk",
     "version": "5.3.0",
     "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.3.0.tgz",
     "integrity": "sha512-..."
   }
   ```

---

## 5. Overrides Engine (npm RFC 36)

`overrides` allow the root package to forcefully replace package versions across the entire dependency graph.

### Syntax Support & Evaluation Rules:
1. **Global Package Override:**
   ```json
   "overrides": { "semver": "7.5.4" }
   ```
   Every request for `semver` anywhere in the tree resolves to `7.5.4`.
2. **Nested Dependent Override:**
   ```json
   "overrides": {
     "foo": {
       "bar": "2.0.0"
     }
   }
   ```
   Only when `bar` is required by `foo` (or a descendant of `foo`) is it overridden to `2.0.0`.
3. **Spec-Targeted Override:**
   ```json
   "overrides": {
     "debug@^2.0.0": "2.6.9"
   }
   ```
   Overrides `debug` only when the requested specifier matches `^2.0.0`.
4. **Reference Overrides:**
   ```json
   "overrides": {
     "foo": "$foo"
   }
   ```
   Pins transitive dependencies on `foo` to match the exact version declared in root `dependencies["foo"]`.

---

## 6. Peer Dependencies Engine

### 6.1. Peer Auto-Installation (npm v7+ Parity)
- By default, peer dependencies are automatically resolved and installed into the tree.
- When package `A` declares `"peerDependencies": { "B": "^1.0.0" }`, the resolver attempts to hoist `B` alongside `A` in the same `node_modules` scope.

### 6.2. Cyclic Peer Dependencies
- Cyclic peer relationships (e.g. `Package A` peers `Package B`, and `Package B` peers `Package A`) are valid and common in ecosystems like React / React-DOM.
- The resolver graph must represent cyclic peer edges without infinite recursion or stack overflow.

### 6.3. Peer Dependency Conflicts & `ERESOLVE`
- If package `A` requires peer `C@^1.0.0`, and package `B` requires peer `C@^2.0.0`, and both `A` and `B` require `C` to reside in the same execution scope:
  - In strict mode (default): Terminate resolution with structured error `ERESOLVE` detailing the conflict tree.
  - With `--legacy-peer-deps`: Ignore peer dependencies completely during tree construction.
  - With `--force`: Resolve both versions by duplicating or isolating scopes where possible.

### 6.4. Optional Peer Dependencies
- Declared via `peerDependenciesMeta`:
  ```json
  "peerDependencies": {
    "canvas": "^2.8.0"
  },
  "peerDependenciesMeta": {
    "canvas": {
      "optional": true
    }
  }
  ```
- If an optional peer dependency cannot be resolved or conflicts with an existing node, the resolver silently skips installing it. No error is raised.
