// Strict real-registry differential gate. See corpus/README.md for provenance.
import fs from 'node:fs';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import { cleanPhase } from './corpus/clean-artifacts.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const option = (name, fallback) => args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
const corpus = path.resolve(option('--corpus', path.join(repo, 'scripts/corpus')));
const root = path.resolve(option('--root', path.join(repo, 'target/real-corpus', new Date().toISOString().replaceAll(':', '-'))));
const binary = path.resolve(option('--binary', path.join(repo, 'target/release', process.platform === 'win32' ? 'rnpm.exe' : 'rnpm')));
const npmCli = path.resolve(option('--npm-cli', path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js')));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const write = (file, value) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n');
};
const read = file => JSON.parse(fs.readFileSync(file, 'utf8'));
if (fs.existsSync(root)) throw new Error(`Use a fresh evidence directory: ${root}`);
fs.mkdirSync(root, { recursive: true });
const baseEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
  !/^(npm_config_|rnpm_|npm_token$|node_auth_token$|node_env$|userconfig$|globalconfig$|prefix$|cache$)/i.test(key)));
function envFor(isolation) {
  const env = { ...baseEnv };
  for (const name of ['user.npmrc', 'global.npmrc']) write(path.join(isolation, name), '');
  for (const name of ['home', 'cache', 'store', 'prefix', 'appdata', 'localappdata', 'xdg-config', 'xdg-cache', 'xdg-data']) fs.mkdirSync(path.join(isolation, name), { recursive: true });
  return { ...env, HOME: path.join(isolation, 'home'), USERPROFILE: path.join(isolation, 'home'),
    APPDATA: path.join(isolation, 'appdata'), LOCALAPPDATA: path.join(isolation, 'localappdata'),
    XDG_CONFIG_HOME: path.join(isolation, 'xdg-config'), XDG_CACHE_HOME: path.join(isolation, 'xdg-cache'), XDG_DATA_HOME: path.join(isolation, 'xdg-data'),
    NPM_CONFIG_USERCONFIG: path.join(isolation, 'user.npmrc'), NPM_CONFIG_GLOBALCONFIG: path.join(isolation, 'global.npmrc'),
    NPM_CONFIG_PREFIX: path.join(isolation, 'prefix'), NPM_CONFIG_CACHE: path.join(isolation, 'cache'),
    RNPM_STORE_DIR: path.join(isolation, 'store'), NPM_CONFIG_REGISTRY: option('--registry', 'https://registry.npmjs.org/'),
    NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false', NPM_CONFIG_UPDATE_NOTIFIER: 'false' };
}
async function run(tool, command, cwd, isolation, log) {
  const executable = tool === 'rnpm' ? binary : process.execPath;
  const argv = tool === 'npm' ? [npmCli, ...command] : command;
  const start = Date.now();
  const stdout = fs.createWriteStream(log + '.stdout.log');
  const stderr = fs.createWriteStream(log + '.stderr.log');
  const result = await new Promise(resolve => {
    const child = spawn(executable, argv, { cwd, env: envFor(isolation), windowsHide: true, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
    let error = null, timedOut = false;
    // This is a deadlock bound, not a performance gate. Kill the entire process tree.
    const timer = setTimeout(() => {
      timedOut = true;
      if (process.platform === 'win32' && child.pid) {
        spawn('taskkill.exe', ['/pid', String(child.pid), '/t', '/f'], { windowsHide: true, stdio: 'ignore' });
      } else if (child.pid) {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
      }
    }, 20 * 60 * 1000);
    child.stdout.pipe(stdout); child.stderr.pipe(stderr);
    child.on('error', e => { error = String(e); });
    child.on('close', (exit, signal) => {
      clearTimeout(timer);
      resolve({ executable, argv, exit, signal, error, timedOut, ms: Date.now() - start });
    });
  });
  await Promise.all([stdout, stderr].map(stream => stream.closed ? undefined : new Promise(resolve => stream.on('close', resolve))));
  write(log + '.json', result);
  return result;
}
function differences(a, b, key = '') {
  if (isDeepStrictEqual(a, b)) return [];
  if (a && b && typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b)) {
    return [...new Set([...Object.keys(a), ...Object.keys(b)])].sort().flatMap(k => differences(a[k], b[k], `${key}/${k}`));
  }
  return [{ path: key, npm: a, rnpm: b }];
}
function tree(dir) {
  const files = {};
  const walk = (absolute, relative, installed = false) => {
    if (!fs.existsSync(absolute)) return;
    for (const entry of fs.readdirSync(absolute, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const key = relative ? `${relative}/${entry.name}` : entry.name;
      // Arborist shrinkwrap.js: hiddenLockfile saves node_modules/.package-lock.json
      // as an mtime-based inventory cache, without the public root/legacy entries.
      // Only the project-root cache is excluded, never package-owned lockfiles.
      if (key === 'node_modules/.package-lock.json') continue;
      const file = path.join(absolute, entry.name);
      const inTree = installed || entry.name === 'node_modules';
      if (entry.isSymbolicLink()) {
        if (!inTree) continue;
        const target = fs.readlinkSync(file);
        files[key] = { link: path.relative(dir, path.resolve(path.dirname(file), target)).replaceAll('\\', '/') };
      } else if (entry.isDirectory()) {
        if (inTree) files[key + '/'] = { directory: true };
        walk(file, key, inTree);
      } else if (inTree) files[key] = { sha256: hash(fs.readFileSync(file)) };
    }
  };
  walk(dir, '');
  return files;
}
const isolation = path.join(root, 'identity');
const identityEnv = envFor(isolation);
const identity = {
  head: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim(),
  dirty: execFileSync('git', ['status', '--porcelain'], { cwd: repo, encoding: 'utf8' }).trim(),
  node: process.version, node_binary: process.execPath, npm_cli: npmCli,
  npm: execFileSync(process.execPath, [npmCli, '--version'], { env: identityEnv, encoding: 'utf8' }).trim(),
  rnpm: execFileSync(binary, ['--version'], { env: identityEnv, encoding: 'utf8' }).trim(),
  rnpm_binary: binary, binary_sha256: hash(fs.readFileSync(binary)), platform: process.platform, arch: process.arch,
  started: new Date().toISOString(), corpus_sha256: hash(fs.readFileSync(path.join(corpus, 'index.json'))),
};
if (identity.npm !== '11.20.0') throw new Error(`Expected real npm 11.20.0; found ${identity.npm}`);
const projects = read(path.join(corpus, 'index.json')).projects;
const selected = projects.filter(project => !option('--case', '') || project.id.includes(option('--case', '')));
if (!selected.length) throw new Error('No projects matched');
const results = [];
write(path.join(root, 'identity.json'), identity);
const persist = () => write(path.join(root, 'results.json'), { ...identity, expected: selected.length, completed: results.length, results });
function prepare(project, dir, lock) {
  for (const [name, source] of Object.entries(project.files)) {
    const destination = path.resolve(dir, name);
    if (!destination.startsWith(dir + path.sep)) throw new Error(`Invalid fixture path: ${name}`);
    const bytes = fs.readFileSync(path.join(corpus, source.path));
    if (hash(bytes) !== source.sha256) throw new Error(`Fixture hash mismatch: ${source.path}`);
    write(destination, bytes.toString('utf8'));
  }
  if (lock) write(path.join(dir, 'package-lock.json'), lock);
}
async function checkProject(project) {
  const location = path.join(root, project.id);
  fs.mkdirSync(location, { recursive: true });
  const result = { id: project.id, kind: project.kind, phases: [], failures: [] };
  try {
    let oracleLock;
    const phases = ['install', 'ci', 'ci-omit-dev', ...Object.keys(project.locks || {}).map(version => `upgrade-v${version}`), ...(project.smoke ? ['scripts'] : [])];
    for (const phase of phases) {
      const commands = phase === 'install' || phase.startsWith('upgrade-') ? ['install', '--ignore-scripts'] : phase === 'scripts' ? ['install'] : ['ci', '--ignore-scripts', ...(phase === 'ci-omit-dev' ? ['--omit=dev'] : [])];
      const stage = { phase, commands, processes: {}, ls: {}, smoke: {}, differences: [] };
      const dirs = {};
      for (const tool of ['npm', 'rnpm']) {
        const dir = path.join(location, phase, tool, 'project'); dirs[tool] = dir;
        const iso = path.join(location, phase, tool, 'isolation');
        let lock = phase.startsWith('ci') ? oracleLock : undefined;
        if (phase.startsWith('upgrade-')) {
          const input = project.locks[phase.slice(-1)];
          const bytes = fs.readFileSync(path.join(corpus, input.path));
          if (hash(bytes) !== input.sha256) throw new Error(`Lockfile hash mismatch: ${input.path}`);
          lock = bytes.toString('utf8');
        }
        prepare(project, dir, lock);
        const log = path.join(location, `${phase}-${tool}`);
        if (phase.startsWith('ci') && !oracleLock) {
          stage.processes[tool] = { exit: null, error: 'npm install did not produce a usable lockfile; ci input unavailable' };
          continue;
        }
        stage.processes[tool] = await run(tool, commands, dir, iso, log);
        const lockFile = path.join(dir, 'package-lock.json');
        if (phase === 'install' && tool === 'npm' && stage.processes[tool].exit === 0 && fs.existsSync(lockFile)) oracleLock = fs.readFileSync(lockFile, 'utf8');
        // Always use npm, including to inspect the rnpm-created tree.
        stage.ls[tool] = await run('npm', ['ls', '--all', '--json', ...(phase === 'ci-omit-dev' ? ['--omit=dev'] : [])], dir, iso, log + '-ls');
        if (phase === 'scripts') stage.smoke[tool] = await run('node', ['-e', project.smoke], dir, iso, log + '-smoke');
        write(log + '-tree.json', tree(dir));
      }
      for (const tool of ['npm', 'rnpm']) {
        if (stage.processes[tool]?.exit !== 0) stage.differences.push({ check: `${tool}-command`, actual: stage.processes[tool] });
        if (stage.ls[tool]?.exit !== 0) stage.differences.push({ check: `${tool}-npm-ls`, actual: stage.ls[tool] });
        if (phase === 'scripts' && stage.smoke[tool]?.exit !== 0) stage.differences.push({ check: `${tool}-smoke`, actual: stage.smoke[tool] });
      }
      if (stage.ls.npm?.exit !== stage.ls.rnpm?.exit) stage.differences.push({ check: 'npm-ls-exit', npm: stage.ls.npm?.exit, rnpm: stage.ls.rnpm?.exit });
      const locks = ['npm', 'rnpm'].map(tool => path.join(dirs[tool], 'package-lock.json'));
      if (locks.every(file => fs.existsSync(file))) stage.differences.push(...differences(read(locks[0]), read(locks[1])).map(diff => ({ check: 'lock', ...diff })));
      else stage.differences.push({ check: 'missing-lockfile', files: locks.filter(file => !fs.existsSync(file)) });
      stage.differences.push(...differences(tree(dirs.npm), tree(dirs.rnpm)).map(diff => ({ check: 'tree', ...diff })));
      result.phases.push(stage);
      write(path.join(location, 'result.json'), result);
      console.log(`${project.id} ${phase}: ${stage.differences.length} differences`);
      if (!args.includes('--keep-artifacts')) cleanPhase(root, location, phase);
    }
  } catch (error) { result.failures.push(String(error.stack || error)); }
  result.match = result.failures.length === 0 && result.phases.length >= 3 && result.phases.every(phase => phase.differences.length === 0);
  results.push(result); results.sort((a, b) => a.id.localeCompare(b.id)); persist();
}
let cursor = 0;
const jobs = Number(option('--jobs', '4'));
if (!Number.isInteger(jobs) || jobs < 1) throw new Error('--jobs must be a positive integer');
await Promise.all(Array.from({ length: Math.min(jobs, selected.length) }, async () => {
  while (cursor < selected.length) await checkProject(selected[cursor++]);
}));
if (results.length !== selected.length || results.some(result => !result.match)) process.exitCode = 1;
console.log(`Corpus: ${results.filter(result => result.match).length}/${selected.length} exact matches; evidence: ${root}`);
