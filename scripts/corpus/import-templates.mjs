import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const indexFile = path.join(root, 'index.json');
const index = JSON.parse(fs.readFileSync(indexFile));
const date = new Date().toISOString();
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const get = async url => {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url}: ${response.status}`);
  return response;
};
// Preserve complete official workspace sets, including workspace protocols that
// npm may reject. Such oracle errors are visible failures, never skipped cases.
const repository = 'vercel/turborepo';
const revision = (await (await get(`https://api.github.com/repos/${repository}/commits/main`)).json()).sha;
const tree = await (await get(`https://api.github.com/repos/${repository}/git/trees/${revision}?recursive=1`)).json();
if (tree.truncated) throw new Error('GitHub truncated the source tree');
const paths = tree.tree.filter(entry => entry.type === 'blob' && /^examples\/[^/]+\/(?:.*\/)?package.json$/.test(entry.path)).map(entry => entry.path);
let added = 0;
for (const main of paths.filter(file => /^examples\/[^/]+\/package.json$/.test(file)).sort()) {
  if (added === 10) break;
  const base = main.slice(0, -'package.json'.length);
  const source = `https://raw.githubusercontent.com/${repository}/${revision}/`;
  const manifest = await (await get(source + main)).text();
  if (!JSON.parse(manifest).workspaces) continue;
  const id = 'workspace-' + base.split('/')[1];
  const project = { id, kind: 'official-workspace-template', category: 'workspaces', source: { repository, revision, date, source: source + main }, files: {} };
  for (const file of paths.filter(file => file.startsWith(base))) {
    const relative = file.slice(base.length);
    const content = relative === 'package.json' ? manifest : await (await get(source + file)).text();
    const destination = `templates/${id}/${relative}`;
    fs.mkdirSync(path.dirname(path.join(root, destination)), { recursive: true });
    fs.writeFileSync(path.join(root, destination), content);
    project.files[relative] = { path: destination, sha256: sha256(content) };
  }
  index.projects.push(project); added++;
  console.log(`${id}: ${Object.keys(project.files).length} manifests`);
}
for (const repository of ['npm/cli', 'lerna/lerna']) {
  const info = await (await get(`https://api.github.com/repos/${repository}`)).json();
  const revision = (await (await get(`https://api.github.com/repos/${repository}/commits/${info.default_branch}`)).json()).sha;
  const source = `https://raw.githubusercontent.com/${repository}/${revision}/`;
  const manifest = await (await get(source + 'package.json')).text();
  const workspaces = JSON.parse(manifest).workspaces;
  if (!Array.isArray(workspaces)) throw new Error(`Expected workspaces in ${repository}`);
  const tree = await (await get(`https://api.github.com/repos/${repository}/git/trees/${revision}?recursive=1`)).json();
  if (tree.truncated) throw new Error(`Truncated source tree for ${repository}`);
  const patterns = workspaces.map(pattern => new RegExp('^' + pattern.split('*').map(piece => piece.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('[^/]+') + '/package\\.json$'));
  const paths = tree.tree.filter(entry => entry.type === 'blob' && patterns.some(pattern => pattern.test(entry.path))).map(entry => entry.path);
  const id = 'workspace-' + repository.replace('/', '-');
  const project = { id, kind: 'official-workspace-manifests', category: 'workspaces', source: { repository, revision, date, source: source + 'package.json' }, files: {} };
  for (const file of ['package.json', ...paths]) {
    const content = file === 'package.json' ? manifest : await (await get(source + file)).text();
    const destination = `templates/${id}/${file}`;
    fs.mkdirSync(path.dirname(path.join(root, destination)), { recursive: true });
    fs.writeFileSync(path.join(root, destination), content);
    project.files[file] = { path: destination, sha256: sha256(content) };
  }
  index.projects.push(project); added++;
  console.log(`${id}: ${Object.keys(project.files).length} manifests`);
}
if (added !== 10) throw new Error(`Expected 10 workspace sets, found ${added}`);
const smokeNames = ['sharp', 'bcrypt', 'sqlite3', 'better-sqlite3', 'canvas', 'argon2', 'node-pty', 'utf-8-validate', 'bufferutil', 'lmdb', 'level', 'snappy', 'keytar', 'esbuild', '@swc/core'];
for (const name of smokeNames) {
  const published = index.projects.find(project => project.source.package === name);
  if (!published) throw new Error(`Missing pinned package: ${name}`);
  const id = 'scripts-' + published.id;
  const manifest = { name: id, version: '1.0.0', private: true, dependencies: { [name]: published.source.version } };
  const bytes = JSON.stringify(manifest, null, 2) + '\n';
  const destination = `consumers/${id}/package.json`;
  fs.mkdirSync(path.dirname(path.join(root, destination)), { recursive: true });
  fs.writeFileSync(path.join(root, destination), bytes);
  index.projects.push({ id, kind: 'script-consumer', category: 'native-scripts', source: published.source,
    smoke: `require(${JSON.stringify(name)})`, files: { 'package.json': { path: destination, sha256: sha256(bytes) } } });
}
fs.writeFileSync(indexFile, JSON.stringify(index, null, 2) + '\n');
console.log(`Pinned ${index.projects.length} cases, including ${added} official workspace sets and ${smokeNames.length} script consumers`);
