// Minimal npm oracle probe for skipped scopes, production reachability and bins.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const option = (name, fallback) => args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
const root = path.resolve(option('--root', path.join(repo, 'target/f2-install-probe', String(Date.now()))));
if (fs.existsSync(root)) throw new Error(`Use fresh probe root: ${root}`);
fs.mkdirSync(root, { recursive: true });
const archives = new Map();
const manifests = {
  prod: { name: 'prod', version: '1.0.0', license: 'MIT', dependencies: { shared: '1.0.0' } },
  shared: { name: 'shared', version: '1.0.0', license: 'MIT' },
  devtool: { name: 'devtool', version: '1.0.0', license: 'MIT', bin: { devtool: 'cli.js' } },
  '@foreign/native': { name: '@foreign/native', version: '1.0.0', license: 'MIT', os: ['never-platform'] },
};
for (const [name, manifest] of Object.entries(manifests)) {
  const staging = path.join(root, 'archives', name.replaceAll('/', '-'));
  fs.mkdirSync(path.join(staging, 'package'), { recursive: true });
  fs.writeFileSync(path.join(staging, 'package/package.json'), JSON.stringify(manifest));
  fs.writeFileSync(path.join(staging, 'package/index.js'), name === 'prod' ? 'module.exports = require("shared");\n' : 'module.exports = 42;\n');
  fs.writeFileSync(path.join(staging, 'package/cli.js'), '#!/usr/bin/env node\n');
  archives.set(name, execFileSync('tar', ['-czf', '-', '-C', staging, 'package'], { maxBuffer: 1024 * 1024 }));
}
const requests = [];
let registry;
const server = http.createServer((req, res) => {
  const name = decodeURIComponent(req.url.slice(1)); requests.push(name);
  if (name.endsWith('.tgz')) {
    const packageName = name.slice(0, -4);
    if (packageName === '@foreign/native') { res.writeHead(500); res.end('Incompatible optional tarball was requested'); return; }
    const archive = archives.get(packageName);
    if (archive) { res.end(archive); return; }
  }
  if (manifests[name]) {
    const manifest = manifests[name];
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ name, 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': { ...manifest, dist: {
      tarball: `${registry}${encodeURIComponent(name)}.tgz`, integrity: 'sha512-' + createHash('sha512').update(archives.get(name)).digest('base64'),
    } } } })); return;
  }
  res.writeHead(404); res.end('{}');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
registry = `http://127.0.0.1:${server.address().port}/`;
const corpus = path.join(root, 'inputs'); fs.mkdirSync(corpus);
const manifest = JSON.stringify({ name: 'f2-regression', version: '1.0.0', dependencies: { prod: '1.0.0' },
  devDependencies: { shared: '1.0.0', devtool: '1.0.0' }, optionalDependencies: { '@foreign/native': '1.0.0' } }, null, 2) + '\n';
fs.writeFileSync(path.join(corpus, 'package.json'), manifest);
fs.writeFileSync(path.join(corpus, 'index.json'), JSON.stringify({ projects: [{ id: 'f2-install-regression', kind: 'regression', files: {
  'package.json': { path: 'package.json', sha256: createHash('sha256').update(manifest).digest('hex') },
} }] }));
try {
  const argv = [path.join(repo, 'scripts/check-real-corpus.mjs'), '--corpus', corpus, '--registry', registry, '--root', path.join(root, 'evidence')];
  if (option('--binary')) argv.push('--binary', path.resolve(option('--binary')));
  const exit = await new Promise(resolve => {
    const child = spawn(process.execPath, argv, { cwd: repo, windowsHide: true, stdio: 'inherit' });
    child.on('close', resolve);
  });
  fs.writeFileSync(path.join(root, 'requests.json'), JSON.stringify(requests, null, 2));
  process.exitCode = exit === 0 && !requests.includes('@foreign/native.tgz') ? 0 : 1;
} finally { server.closeAllConnections(); server.close(); }
