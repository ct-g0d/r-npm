// Real-registry resolver evidence. Separate npm/rnpm projects, caches, and stores.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const option = (key, fallback) => args.includes(key) ? args[args.indexOf(key) + 1] : fallback;
const root = path.resolve(option('--root', path.join(repo, 'target/lane-a2-real')));
const binary = path.resolve(option('--binary', path.join(repo, 'target/release/rnpm.exe')));
const npmCli = path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js');
fs.mkdirSync(root, { recursive: true });
const write = (file, value) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n');
};
const read = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const baseEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(npm_config_|rnpm_|npm_token$|node_auth_token$)/i.test(key)));
write(path.join(root, 'empty.npmrc'), '');
write(path.join(root, 'global.npmrc'), '');
const envFor = (cache, store) => ({ ...baseEnv,
  NPM_CONFIG_USERCONFIG: path.join(root, 'empty.npmrc'),
  NPM_CONFIG_GLOBALCONFIG: path.join(root, 'global.npmrc'),
  NPM_CONFIG_PREFIX: path.join(root, 'prefix'),
  NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org/',
  NPM_CONFIG_CACHE: cache, RNPM_STORE_DIR: store,
  NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false', NPM_CONFIG_UPDATE_NOTIFIER: 'false',
});
async function run(tool, command, dir, cache, store, log) {
  const start = performance.now();
  const result = await new Promise(resolve => {
    const child = spawn(tool === 'npm' ? process.execPath : binary,
      tool === 'npm' ? [npmCli, ...command] : command,
      { cwd: dir, env: envFor(cache, store), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', data => stdout += data);
    child.stderr.on('data', data => stderr += data);
    child.on('error', error => stderr += String(error));
    child.on('close', exit => resolve({ exit, ms: Math.round(performance.now() - start), stdout, stderr }));
  });
  write(log + '.json', result);
  console.log(`${tool} ${path.basename(dir)}: exit=${result.exit}, ${result.ms}ms`);
  return result;
}
function differences(a, b, key = '') {
  if (isDeepStrictEqual(a, b)) return [];
  if (a && b && typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b)) {
    return [...new Set([...Object.keys(a), ...Object.keys(b)])].sort().flatMap(k => differences(a[k], b[k], `${key}/${k}`));
  }
  return [{ path: key, npm: a, rnpm: b }];
}
const manifestFile = path.join(root, 'manifests.json');
if (!fs.existsSync(manifestFile)) {
  const sources = {
    vite: 'https://raw.githubusercontent.com/vitejs/vite/main/packages/create-vite/template-react/package.json',
    cra: 'https://raw.githubusercontent.com/facebook/create-react-app/main/packages/create-react-app/package.json',
    craTemplate: 'https://raw.githubusercontent.com/facebook/create-react-app/main/packages/cra-template/template.json',
  };
  const downloaded = {};
  for (const [key, url] of Object.entries(sources)) {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`${url}: ${response.status}`);
    downloaded[key] = await response.json();
  }
  const project = dependencies => ({ name: 'lane-a2-project', version: '1.0.0', dependencies });
  write(manifestFile, {
    sources, downloaded,
    projects: {
      'express-typescript': project({ express: '5.1.0', typescript: 'latest', '@types/node': 'latest' }),
      express: project({ express: '5.1.0' }),
      'next-sharp': { ...project({ next: '15' }), devDependencies: { sharp: '0.33' } },
      'bcrypt-esbuild': project({ bcrypt: 'latest', esbuild: 'latest' }),
      'vite-react': downloaded.vite,
      'create-react-app': downloaded.cra,
      'cra-generated': { ...project({ react: '^19.0.0', 'react-dom': '^19.0.0', 'react-scripts': '5.0.1', ...downloaded.craTemplate.package.dependencies }), private: true },
    },
  });
}
const { projects } = read(manifestFile);
const revision = () => ({
  head: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim(),
  node: process.version,
  npm: execFileSync(process.execPath, [npmCli, '--version'], { env: envFor(path.join(root, 'version-cache'), path.join(root, 'version-store')), encoding: 'utf8' }).trim(),
  binary_sha256: fs.existsSync(binary) ? createHash('sha256').update(fs.readFileSync(binary)).digest('hex') : null,
});
if (args.includes('--benchmark')) {
  const results = [];
  for (const name of ['express-typescript', 'vite-react']) {
    for (const tool of ['npm', 'rnpm']) {
      const warm = path.join(root, 'bench', name, tool, 'warm');
      const cache = path.join(warm, 'cache'), store = path.join(warm, 'store');
      const seed = path.join(warm, 'seed');
      write(path.join(seed, 'package.json'), projects[name]);
      const seeded = await run(tool, ['install', '--ignore-scripts'], seed, cache, store, path.join(warm, 'seed-log'));
      if (seeded.exit !== 0) throw new Error(seeded.stderr);
      const lock = fs.readFileSync(path.join(seed, 'package-lock.json'), 'utf8');
      for (const kind of ['warm-no-lock', 'cold-ci']) {
        const runs = [];
        for (let index = 1; index <= 3; index++) {
          const dir = path.join(root, 'bench', name, tool, `${kind}-${index}`);
          if (fs.existsSync(dir)) throw new Error(`Use a fresh benchmark root: ${dir}`);
          write(path.join(dir, 'package.json'), projects[name]);
          if (kind === 'cold-ci') write(path.join(dir, 'package-lock.json'), lock);
          const result = await run(tool, [kind === 'cold-ci' ? 'ci' : 'install', '--ignore-scripts'], dir,
            kind === 'cold-ci' ? path.join(dir, 'cache') : cache,
            kind === 'cold-ci' ? path.join(dir, 'store') : store, dir + '-log');
          if (result.exit !== 0) throw new Error(result.stderr);
          runs.push(result.ms);
        }
        results.push({ name, tool, kind, runs, median_ms: [...runs].sort((a,b) => a-b)[1] });
        write(path.join(root, 'benchmarks.json'), { ...revision(), flags: ['--ignore-scripts', 'audit=false', 'fund=false'], results });
      }
    }
  }
} else {
  const results = [];
  let failed = false;
  const command = ['install', ...args.includes('--materialize') ? [] : ['--package-lock-only'], '--ignore-scripts'];
  if (!Object.keys(projects).some(name => name.includes(option('--case', '')))) throw new Error('No projects matched --case');
  for (const [name, manifest] of Object.entries(projects)) {
    if (option('--case', '') && !name.includes(option('--case', ''))) continue;
    const tools = option('--tool', 'both') === 'both' ? ['npm', 'rnpm'] : [option('--tool')];
    const exits = {};
    for (const tool of args.includes('--compare-only') ? [] : tools) {
      const dir = path.join(root, name, tool);
      if (['package-lock.json', 'node_modules'].some(name => fs.existsSync(path.join(dir, name)))) throw new Error(`Fresh no-lockfile run required: ${dir}`);
      write(path.join(dir, 'package.json'), manifest);
      exits[tool] = await run(tool, command, dir,
        path.join(root, name, `${tool}-cache`), path.join(root, name, `${tool}-store`), path.join(root, name, `${tool}-log`));
      if (exits[tool].exit !== 0 || !fs.existsSync(path.join(dir, 'package-lock.json'))) failed = true;
    }
    const npmLock = path.join(root, name, 'npm/package-lock.json');
    const rnpmLock = path.join(root, name, 'rnpm/package-lock.json');
    if (fs.existsSync(npmLock) && fs.existsSync(rnpmLock)) {
      const npm = read(npmLock), rnpm = read(rnpmLock);
      const diff = differences(npm, rnpm);
      if (diff.length) failed = true;
      results.push({ name, npm_packages: Object.keys(npm.packages).length - 1, rnpm_packages: Object.keys(rnpm.packages).length - 1, differences: diff });
      console.log(`${name}: ${diff.length} exact JSON differences`);
    }
  }
  write(path.join(root, `identity-${option('--tool', 'both')}.json`), { ...revision(), flags: [...command, 'audit=false', 'fund=false'], results });
  if (failed) process.exitCode = 1;
}
console.log(`Evidence: ${root}`);
