# rnpm Windows Speed Plan: 5x npm on an i7-8750H

Design plan, 2026-11-07. Target machine: the dev laptop rnpm is built on. Every number below
was measured on it unless marked **(estimate)**.

Status today: rnpm is about 50% of the way to replacing npm (see section 2) and **slower than
npm** on real installs. This plan fixes that order: correctness first, then a Windows-native
install engine.

---

## 1. The machine and the physics

### 1.1 Hardware profile

| Part | Value | What it means for the design |
|---|---|---|
| CPU | i7-8750H, 6 cores / 12 threads, 2018, laptop (throttles under load) | Keep CPU work low and short. Unpack each package once, ever. |
| RAM | 32 GB | Plenty of room to cache packages and metadata in memory. |
| C: | Samsung PM981 256 GB NVMe, NTFS, **40 GB free** | Fast. This is where the package store must live. |
| D: | **WD 2 TB 5400rpm HDD**, SATA, NTFS | **The rnpm repo and your projects live here.** Every tool is slow on it. |
| Defender | Real-time protection on, 1 exclusion | Every new file gets scanned. This is the single biggest cost. |
| OS | Windows 11 build 26300 | Dev Drive (ReFS + Defender performance mode) is available. |

### 1.2 Measured baselines (warm cache, scripts off, median of 3)

Fresh install from a lockfile (`node_modules` deleted first):

| Project | Files | npm ci | pnpm | pnpm hoisted | bun 1.4.4 | rnpm today | Copy floor\* |
|---|---|---|---|---|---|---|---|
| next 15 | 8,543 (321 MB) | 14.9s | 12.9s | 11.5s | 4.4s | 16.6s | 2.5s |
| mocha + nyc | 3,737 (28 MB) | 3.5s | 3.5s | 3.3s | 8.8s | 6.0s | 1.1s |
| eslint airbnb | 7,153 (27 MB) | 5.6s | 6.3s | 6.2s | 15.9s | 12.7s | 1.9s |

\* Copy floor = `robocopy /MT:32` of the finished `node_modules` to C:, Defender on. That's
roughly the fastest any tool that copies files can go on this machine.

Everyday commands:

| Command | npm | rnpm today |
|---|---|---|
| `install` when nothing changed (next) | 1.2s | **18.9s** (reinstalls everything; bug B7) |
| `install` when nothing changed (eslint) | 1.4s | **11.5s** (same bug) |
| `run <script>` | 733ms | 109ms (already 6.7x faster) |

How file writing scales (eslint tree, 7,153 files, copied to C:):

| Method | Time |
|---|---|
| robocopy, 1 thread | 6.2s (about the same as npm ci: npm effectively writes one file at a time) |
| robocopy, 32 threads | 2.2s |
| robocopy, 32 threads, to D: (HDD) | 1.7-5.1s (fast when the write cache absorbs it, slow when cold) |

### 1.3 What this tells us

1. **Creating files is the bottleneck, not the CPU, the network or the language.** About
   0.25-0.3ms per file with Defender on, even at 32 threads. Unpacking `next` takes well under
   1 CPU-second; writing its 8.5k files takes 2.5s at best.
2. **Running file writes in parallel is worth about 2.8x** on its own. npm doesn't do this.
3. **pnpm and bun don't win here.** Hardlinks are still one file creation each, so NTFS +
   Defender charge the same cost. The fastest Windows package manager is still up for grabs.
4. **5x on a from-scratch install is physically impossible with copies, NTFS and Defender on
   for small-file projects.** 5x on eslint means 1.1s, below its 1.9s copy floor. To get there
   you have to **create fewer files** or **make each file cheaper** (Dev Drive). The plan does
   both.

### 1.4 What "5x" means in this plan

| Scenario | npm | Target | Speedup | Mechanism |
|---|---|---|---|---|
| `install` with nothing changed | 1.2-1.4s | **<= 100ms** | 12x+ | Fast path (section 4.2) |
| `install` after adding/removing a few deps | ~2-6s **(estimate)** | **<= 400ms** | 5x+ | Only touch what changed (4.3) |
| `run` / `exec` / `test` | 733ms | **<= 60ms** | 12x | Lean startup (4.10) |
| Fresh `ci`, linked mode, any volume | 3.5-14.9s | **<= 0.7-1.5s** | 5-10x | Junctions to a global store (4.6) |
| Fresh `ci`, npm layout, Dev Drive | 3.5-14.9s | **5x (estimate)** | 5x | Block cloning + Defender performance mode (4.5, 4.7) |
| Fresh `ci`, npm layout, plain NTFS + Defender | 3.5-14.9s | **0.7-3.0s** | 2.5-5x | Parallel native file writer (4.5) |
| Cold cache (first download) | n/a | **1.5-2x** | 1.5-2x | Network-bound; streaming pipeline (4.8) |

The headline: **5x or better on everything you do every day**, 5x on fresh installs with
linked mode or a Dev Drive, and 2.5-5x on fresh installs that keep npm's exact layout on
plain NTFS.

---

## 2. Phase 0: correctness prerequisites

A fast installer that builds the wrong tree is a failed installer. These come first, and all
but B4 are small.

| ID | Bug | Location | Fix |
|---|---|---|---|
| B1 | Tarball entries with `./` (webpack-cli 5.1.4, `@rollup/pluginutils`) abort with a false "case collision" | `crates/rnpm-fs/src/tarball.rs` ~255-285 | Same path (case preserved) = later entry wins, as node-tar does. Only raise an error when paths differ only by case. |
| B2 | Package metadata cache keyed only by package name, so cached data from the test registry was served for registry.npmjs.org (wrong integrity, `127.0.0.1:4873` URLs in lockfiles) | `crates/rnpm-cache/src/storage.rs:517` | Key by registry URL + name + accept header. Benchmarks always use a throwaway `--cache`. |
| B3 | `ci` crashes on npm-written lockfiles where `engines` is an array (`concat-stream`) | `crates/rnpm-lockfile/src/model.rs:95` | Keep any field rnpm doesn't interpret as raw JSON and write it back unchanged. |
| B5 | Lockfile metadata differs: `license`, `libc`, `devOptional` missing; `funding`/`bin` reshaped; extra `directories`, `deprecated: false`, root `overrides` | lockfile writer | Mirror Arborist's `Shrinkwrap.metaFromNode` field for field. |
| B7 | `install` with nothing changed reinstalls everything (11-19s vs npm's 1.2-1.4s) | install pipeline | Fixed by the fast path in 4.2. Until then, at least diff against the hidden lockfile. |
| B4 | Package placement differs from npm's Arborist in 6 of 14 test projects (tailwind, mocha, nest, eslint, overrides, workspaces) | `crates/rnpm-solver` | Port Arborist's `build-ideal-tree` / `place-dep` / `can-place-dep` directly instead of fixing placement case by case. |

**Gate:** 100-project corpus (section 6), tree diff = 0, lockfile byte diff = 0, with a fresh
cache for every run.

---

## 3. Architecture overview

```
                       +------------------------------------------+
 package.json  ----->  |  Planner                                 |
 package-lock.json     |  fast path? -> exit                      |
 hidden lockfile       |  diff ideal tree vs actual -> change list|
                       +--------------------+---------------------+
                                            | change list
             +------------------------------+----------------------------+
             v                              v                            v
     +---------------+           +--------------------+        +------------------+
     | Fetcher       | stream -> | Store (C: NVMe)    | -----> | Materializer     |
     | HTTP/2, 48    |           | unpacked once per  |        | npm layout:      |
     | in flight     |           | integrity; pack +  |        |  parallel writer |
     | (cold only)   |           | index format       |        |  / block clone   |
     +---------------+           +--------------------+        | linked layout:   |
                                                               |  junctions       |
                                                               +--------+---------+
                                                                        v
                                                     bins + lifecycle (topological, parallel)
                                                                        v
                                                     write hidden lockfile LAST (commit marker)
```

Rules:
- **Never do work twice.** Unpack each package once into the store, and skip any package that
  hasn't changed.
- **Never create a file you don't have to.** In linked mode, one junction per package
  replaces hundreds of files.
- **Run the slow part in parallel.** File creation runs on a dedicated I/O thread pool sized
  for the disk type.
- **No phase waits on another phase.** Remove today's depth-tier barriers completely.

---

## 4. Design

### 4.1 Instrumentation first (milestone M1)

- `tracing` spans for: plan, metadata, fetch, verify, inflate, store-write, materialize,
  bins, lifecycle, lockfile. `--timing` prints a per-phase table (npm has `--timing` too).
- Count files created, junctions created, bytes written and Defender-visible file closes.
- Profile once with Windows Performance Recorder (`wpr -start GeneralProfile -start FileIO`)
  to confirm how much of each file creation is Defender (`MsMpEng.exe`) versus NTFS. Every
  later decision depends on this split.
- Benchmark harness: the 3 projects above plus the 10 largest corpus projects, median of 5,
  Defender on (the realistic case), store on C:, projects on C: **and** D:.

### 4.2 The fast path when nothing changed (M2, fixes B7)

Goal: `rnpm install` with nothing to do in **under 100ms** on `next`.

1. Hash `package.json` (+ workspace manifests), `package-lock.json` and `.npmrc` inputs.
2. Read `node_modules/.package-lock.json` (npm's hidden lockfile) and apply npm's own
   trust rule: the hidden lockfile is valid when it's at least as new as every package folder
   it lists. Checking that is one `stat` per package folder (about 300-1,000 stats, about 10-20ms
   in Rust), **not** one read per `package.json` like npm does.
3. If the inputs match the last successful install (fingerprint kept in the rnpm cache, keyed
   by project path, so nothing extra goes into `node_modules`) and the hidden lockfile is valid,
   exit 0.

On Windows, use `FindFirstFileExW` with `FIND_FIRST_EX_LARGE_FETCH` (or
`GetFileInformationByHandleEx(FileIdBothDirectoryInfo)`) to list each `node_modules` folder in
one call per directory instead of one `stat` per entry.

### 4.3 Only touch what changed (M3)

- Diff the ideal tree (from the lockfile or resolver) against the actual tree (from the hidden
  lockfile). Produce `add` / `remove` / `replace` / `move` actions, like Arborist's reify diff.
- Only those packages hit the materializer. Removals are renamed into a
  `node_modules/.rnpm-trash-<id>` folder (fast, one operation) and deleted in the background
  after the command returns. Deleting thousands of files is itself slow on Windows.
- `ci` keeps npm's rule (wipe and rebuild), but the wipe uses the same rename-then-delete-
  in-background trick so it costs about 0ms on the critical path.

### 4.4 The store (M4)

Location: `%LOCALAPPDATA%\rnpm\store-v1` on the **fastest local volume** (C: NVMe here), no
matter where the project lives.

Format, one entry per package integrity hash:

```
store-v1/
  packs/<sha512-prefix>/<integrity>.pack    # all file contents, each 4 KiB-aligned
  packs/<sha512-prefix>/<integrity>.idx     # path, mode, size, offset per file
```

Why a pack file instead of an unpacked tree like pnpm:
- Adding a package to the store creates **2 files, not N**. Defender scans 2 files.
  That makes the store itself cheap to fill, which matters on the cold path.
- The materializer memory-maps one pack and writes out of memory (no per-file source opens).
- 4 KiB alignment means block cloning can clone byte ranges straight out of the pack on ReFS
  (4.7).
- 32 GB RAM: keep recently used packs memory-mapped across the process lifetime. The OS page
  cache does the rest.

The npm-compatible `content-v2` cacache stays as the download cache, for interop with npm's
cache layout.

**Linked mode** (4.6) additionally needs an unpacked, ready-to-use copy per package+dependency
set. That's stored once globally under `store-v1/linked/<name>@<version>-<deps-hash>/` and
reused by every project.

### 4.5 The Windows-native parallel writer (M5): npm layout on NTFS

The default materializer. It produces exactly npm's `node_modules`.

1. **Directories first, in one pass.** Sort all target directories and create them breadth-
   first (`CreateDirectoryW`), removing every `exists` check from the file loop.
2. **Dedicated I/O pool,** separate from the async runtime. Size it from the disk:
   `IOCTL_STORAGE_QUERY_PROPERTY` -> `StorageDeviceSeekPenaltyProperty`. No seek penalty
   (SSD): start at 24 threads, then tune with M1 data (robocopy: 32 threads = 2.8x over 1).
   Seek penalty (HDD): 4 threads, and write files grouped by package to keep the disk head
   sequential.
3. **One cheap operation per file:**
   - `CreateFileW(CREATE_NEW, FILE_ATTRIBUTE_NORMAL)`. No extra `exists` / `metadata` calls.
   - For files >= 64 KiB: preallocate (`SetFileInformationByHandle(FileAllocationInfo)`).
   - One `WriteFile` straight from the memory-mapped pack.
   - Only set timestamps and attributes if npm does (match pacote/node-tar behavior exactly;
     skip `SetFileTime` if npm doesn't preserve mtimes).
   - `CloseHandle`. This is where Defender scans, so many threads let many scans overlap.
4. **Large-file batching:** dispatch the biggest files first (longest-processing-time
   scheduling) so a 50 MB `.node` binary doesn't finish last.
5. **No temp-dir + rename per package.** Write straight into place. The hidden lockfile is
   written last, atomically. A crash before that point leaves a hidden lockfile that doesn't
   match, which the next run detects and repairs (npm's model).
6. **No `fsync` per file.** Durability comes from the commit marker, as npm does.
7. **Long paths:** use `\\?\` prefixed paths throughout, so the writer never hits the
   260-character limit, whatever the registry setting.

Expected on plain NTFS + Defender: close to the copy floor, so 2.5-6x vs npm (best on big
packages like next, worst on many-tiny-file trees like mocha).

### 4.6 Linked mode: junctions (M6), the 5-10x path on any disk

npm itself ships an experimental `--install-strategy=linked` (isolated layout like pnpm's).
rnpm implements **that strategy**, so npm's behavior defines what "correct" means. The speed
comes from where the bytes live:

- Each package+dependency set exists **once, globally** in
  `store-v1/linked/<name>@<ver>-<deps-hash>/node_modules/<name>`, with its own dependencies
  wired as junctions inside it. (pnpm 10 added the same idea as a "global virtual store".)
- A project install creates `node_modules/.store/...` and top-level entries as **NTFS
  junctions** (`FSCTL_SET_REPARSE_POINT`) pointing into the global store.
- `next`: about 8,500 file creations become about 100-300 junction creations. Junctions are
  directory reparse points: one metadata operation each, no file contents, nothing for
  Defender to scan.
- Junctions **work across volumes** (project on D: HDD, store on C: NVMe) and **don't need
  admin or Developer Mode**, unlike symlinks.

Known trade-offs, documented in `rnpm help install-strategy`:
- Packages that rely on dependencies they didn't declare (phantom deps) break, as with pnpm
  and npm's linked mode.
- Editing a file inside `node_modules` edits the global store copy. `rnpm patch`-style
  workflows must copy-on-write the package into the project first.
- Lifecycle scripts that change their own package folder run once per store entry, not once
  per project. Packages whose build output depends on the project fall back to a per-project
  copy (detected via `binding.gyp` / `install` scripts plus an allowlist).

Target: fresh `ci` of `next` in under 1s on this laptop, on C: or D:.

### 4.7 Dev Drive + block cloning (M7): npm layout at 5x

A Dev Drive is a ReFS volume where Defender runs in **performance mode** (scanning happens
after the file is opened, without blocking) and copies can be **block clones** (shared
extents, no data written).

- `rnpm doctor perf` detects: Dev Drive present, whether the store and project are on it,
  Defender performance mode status, project on a seek-penalty disk.
- When the store and project are on the same ReFS volume, the materializer clones ranges out
  of the pack with `FSCTL_DUPLICATE_EXTENTS_TO_FILE` (cluster-aligned, hence the 4 KiB pack
  alignment) instead of writing bytes.
- **This laptop's catch:** a Dev Drive needs at least 50 GB, and C: has 40 GB free. A Dev
  Drive on the D: HDD would get the Defender benefit but keep HDD seek times. Recommended
  setup: free about 60 GB on C:, create a 50 GB Dev Drive VHDX, and move the store + active
  projects (including this repo) onto it.
- Numbers here are **estimates** until M7 measures them. Microsoft reports large build-time
  improvements from Dev Drive, but this plan only counts what the M1 harness measures.

### 4.8 Cold path: network and metadata (M8)

- **One streaming pipeline:** download -> verify ssri hash while streaming -> inflate
  (`zlib-rs`) -> write pack. No buffering whole tarballs in memory (today's
  `Cursor::new(bytes)`).
- **Start fetching during resolution:** queue a tarball the moment its version is picked. With
  a lockfile, start every fetch immediately.
- **HTTP/2, 48 requests in flight** on one connection pool per registry, separate from the CPU
  pool (6 threads: one per physical core, so hyperthreads don't fight the I/O pool).
- **Abbreviated metadata** (`Accept: application/vnd.npm.install-v1+json`), conditional
  requests (`If-None-Match`), and a parsed binary metadata cache (`rkyv`) so JSON isn't
  re-parsed on every install.

### 4.9 Lifecycle scripts and bins (M9)

- Create `.bin` shims while materializing, not in a separate pass.
- Run install scripts in dependency order, in parallel where no dependency links them, at most
  6 at once (physical cores). Scripts are usually the long pole of real installs once file I/O
  is fixed.
- Cache native build output (`build/Release/*.node`) in the store keyed by
  package + node ABI + platform, so `node-gyp` runs once per machine, not per project.

### 4.10 Lean startup for everyday commands (M10)

- `run` / `exec` / `test` / `prefix` / `config get`: no async runtime, lazy `.npmrc` parsing,
  no registry client creation, no `package-lock.json` read. Target under 60ms (today 109ms).
- Most of the remaining time is `cmd.exe` startup (npm runs scripts through
  `cmd.exe /d /s /c` on Windows). Keep that for parity. Only skip it under an explicit
  opt-in (`script-shell` config) when the user chooses.
- Use `mimalloc` and LTO + `codegen-units=1` + `panic=abort` for the release binary.

### 4.11 HDD awareness

Your projects are on a 5400rpm drive. Every tool suffers there, but rnpm can suffer less:
- Detect the seek penalty (4.5) and switch to the HDD writer profile.
- Linked mode puts almost all bytes on the NVMe store, so the HDD only gets junctions.
- `rnpm doctor perf` prints a one-line warning with the measured difference, plus a
  suggestion to move active projects to C: or a Dev Drive.

### 4.12 What rnpm will NOT do

- **Change Defender settings itself.** No automatic exclusions. Excluding `node_modules`
  from scanning is a real security trade-off (malicious packages land there).
  `rnpm doctor perf` can *explain* the option and print the PowerShell command, but the user
  runs it.
- Change npm's default layout. The npm layout stays the default. Linked mode is opt-in, the
  same as npm's own experimental flag.

---

## 5. Milestones and exit criteria

All timings on this laptop, Defender on, median of 5, unless stated.

| M | Deliverable | Exit criteria |
|---|---|---|
| M0 | Phase 0 fixes (B1-B3, B5, B7 interim) | webpack/storybook install; nest `ci` works; clean-cache corpus with no lockfile metadata diffs |
| M1 | `--timing`, WPR profile, benchmark harness | Per-phase table for 3 baseline projects; Defender vs NTFS split known |
| M2 | Fast path when nothing changed | next `install` (no changes) <= 100ms |
| M3 | Diff-based install + background deletes | Adding 1 dep to eslint project <= 400ms; `ci` wipe off the critical path |
| M4 | Pack store | Store fill = 2 files per package; warm `ci` reads only packs |
| M5 | Native parallel writer | Fresh `ci` within 1.3x of the copy floor: next <= 3.2s, eslint <= 2.5s, mocha <= 1.4s |
| M6 | Linked mode via junctions | Fresh `ci`, linked: next <= 1.0s, eslint <= 0.8s, mocha <= 0.5s, on C: and D: |
| M7 | Dev Drive support + `doctor perf` | Measured 5x vs npm with npm layout on a Dev Drive, or documented why not |
| M8 | Streaming cold path | Cold install >= 1.5x faster than npm on the 3 baseline projects |
| M9 | Parallel lifecycle + native build cache | Second project with `sharp`/`sqlite3` skips node-gyp entirely |
| M10 | Lean startup | `rnpm run` <= 60ms |
| B4 | Arborist placement port (runs alongside M2-M6) | Corpus tree diff = 0 |

Order: M0 -> M1 -> M2 -> M3 -> M5 -> M4 -> M6 -> M10 -> M8 -> M9 -> M7. M2 and M3 give the
biggest everyday wins for the least work, and M5 has to exist before M4's format can be
tuned against real numbers.

---

## 6. Corpus and gates

- **Correctness:** 100 real projects pinned by lockfile (frameworks, toolchains, native
  packages, workspaces, overrides, aliases, git/file/tarball specs, peer conflicts). Every PR:
  tree diff 0, lockfile byte diff 0, matching exit and error codes, fresh cache per run.
- **Speed:** the 3 baseline projects plus the 10 largest corpus projects, for each of: no-op
  install, 1-dep add, fresh `ci` (npm layout), fresh `ci` (linked), cold install, `run`.
  A >10% regression fails the PR. Record machine, Defender state, volume and disk type with
  every result.

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| Defender is still most of the per-file cost even with 32 threads | Linked mode and Dev Drive avoid the cost instead of trying to outrun it; M1 measures the split before M5 |
| Laptop throttling makes benchmarks noisy | Plugged in, high-performance power plan, cool-down between runs, median of 5, report spread |
| Junction edge cases (tools that `realpath`, watchers, Docker bind mounts) | Linked mode stays opt-in; document known tool issues; corpus runs project test suites in linked mode |
| Fast path trusts a stale hidden lockfile | Use npm's exact validity rule; `install --force` bypasses it; fuzz test by mutating `node_modules` between runs |
| Pack format bugs corrupt many projects at once | Verify the integrity hash on store write, store `.idx` checksums, `rnpm cache verify` covers packs |
| Parity drift while optimizing | M0 corpus gate runs on every PR; speed work can't merge with parity diffs |
