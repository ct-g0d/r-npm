// Discard only generated, already-compared artifacts; retain all raw logs,
// manifests, public lockfiles, process results and complete tree hash inventories.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function cleanPhase(evidenceRoot, location, phase) {
  const root = fs.realpathSync(evidenceRoot);
  const remove = candidate => {
    if (!fs.existsSync(candidate)) return;
    const resolved = fs.realpathSync(candidate);
    const relative = path.relative(root, resolved);
    if (!relative || relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) {
      throw new Error(`Refusing artifact cleanup outside evidence root: ${resolved}`);
    }
    fs.rmSync(candidate, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  };
  for (const tool of ['npm', 'rnpm']) {
    // No cleanup until that exact phase's inventories and process logs exist.
    if (!fs.existsSync(path.join(location, `${phase}-${tool}-tree.json`))) continue;
    const project = path.join(location, phase, tool, 'project');
    const walk = dir => {
      if (!fs.existsSync(dir)) return;
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
        const file = path.join(dir, entry.name);
        if (entry.name === 'node_modules') remove(file);
        else walk(file);
      }
    };
    walk(project);
    remove(path.join(location, phase, tool, 'isolation/store'));
    remove(path.join(location, phase, tool, 'isolation/cache/_cacache'));
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const evidenceRoot = path.resolve(process.argv[2] || '');
  if (!fs.existsSync(path.join(evidenceRoot, 'identity.json'))) throw new Error('Expected corpus evidence root with identity.json');
  for (const entry of fs.readdirSync(evidenceRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const location = path.join(evidenceRoot, entry.name);
    const result = path.join(location, 'result.json');
    if (!fs.existsSync(result)) continue;
    for (const phase of JSON.parse(fs.readFileSync(result)).phases) cleanPhase(evidenceRoot, location, phase.phase);
  }
  console.log(`Removed compared generated artifacts only: ${evidenceRoot}`);
}
