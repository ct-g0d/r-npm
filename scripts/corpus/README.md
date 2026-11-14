# Real registry corpus

`index.json` pins 100 unmodified published package manifests, 10 official
workspace manifest sets, and 15 native/script consumer projects. Every input
has a SHA-256 hash and dated source. Published manifests are extracted directly
from the named registry tarball, including their development dependencies.
Consumers deliberately install the pinned published package itself so its
installation scripts and entry point are exercised. They are identified as
generated consumers, not upstream application manifests.

Run `cargo build --release`, then `node scripts/check-real-corpus.mjs`.
The default run checks every case. `--case substring`, `--jobs N`, `--root path`,
`--binary path`, and `--npm-cli path` support diagnosis; a filtered run is not
a passing full gate. Use a new evidence directory for every run.

For each case the runner compares fresh `install --ignore-scripts`, `ci` from
npm's successful install lockfile, and `ci --omit=dev`. Script consumers also
compare a fresh full install and a Node require smoke test. Every public
lockfile field and every installed file byte is compared. Directories and
symlink targets are compared too. Only the project root's
`node_modules/.package-lock.json` is excluded: npm Arborist's `lib/shrinkwrap.js`
describes this as its hidden, mtime-validated inventory, omitting public root
and legacy metadata. Package-owned lockfiles are not excluded. Both trees
are inspected by the real npm `ls --all`, never by rnpm as its own oracle.

All phases use separate projects, config files, home directories, cache,
store, and prefix for each tool. Reports record actual executable paths,
versions, source revision, dirty status, binary hash, process exits, raw
stdout/stderr, full tree hashes and differences. Nonzero commands, missing
inputs, failed smoke tests, npm oracle failures and incomplete comparisons
all fail the gate. Equal failures never count as a match. Inputs are never
refreshed by running the gate.

Published development manifests and workspace sets may reference repository
files absent from the published tarball, unsupported workspace protocols, or
incompatible peer sets. These are explicit oracle failures and cannot prove
rnpm correctness. Additional repository files may be needed to turn those
cases into useful application fixtures. Do not remove failing cases or claim
that corpus size equals the number of verified projects.

Pinned manifests alone do not freeze the transitive registry: ranges can
resolve differently after future publications. Each measured run retains
npm's actual lockfiles and raw evidence. Registry snapshots or committed
oracle lockfiles are needed for reproducibility across registry changes.

`import-published.mjs` and `import-templates.mjs` are explicit maintenance
commands for refreshing sources. Review and commit their resulting changes;
they are not part of validation.
