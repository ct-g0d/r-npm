// Reproducible, unfiltered cold/warm-tarball gate. Node is already an rnpm prerequisite.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const option = (name, fallback) => args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
const runs = Number(option('--runs', '3'));
if (!Number.isSafeInteger(runs) || runs < 1) throw new Error('--runs must be a positive integer');
const keepTemp = args.includes('--keep-temp');
const binary = path.resolve(option('--binary', path.join(repo, 'target/release', process.platform === 'win32' ? 'rnpm.exe' : 'rnpm')));
const fixture = path.join(repo, 'benchmarks/fixtures/project-486');
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const output = path.resolve(option('--output', path.join(repo, 'benchmarks/results', `lane4-${stamp}.json`)));
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rnpm-lane4-'));
const logDir = output.replace(/\.json$/, '') + '-logs';
fs.mkdirSync(logDir, { recursive: true });
fs.writeFileSync(path.join(root, 'empty.npmrc'), '');
fs.writeFileSync(path.join(root, 'global.npmrc'), '');

function remove(candidate) {
  const relative = path.relative(root, path.resolve(candidate));
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw new Error(`Unsafe cleanup: ${candidate}`);
  fs.rmSync(candidate, { recursive: true, force: true });
}
function project(name) {
  const dir = path.join(root, name);
  fs.mkdirSync(dir);
  for (const name of ['package.json', 'package-lock.json']) fs.copyFileSync(path.join(fixture, name), path.join(dir, name));
  return dir;
}
function findNpmCli() {
  const candidates = [path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js')];
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    candidates.push(path.join(dir, 'node_modules/npm/bin/npm-cli.js'));
    const shim = path.join(dir, 'npm');
    try { candidates.push(fs.realpathSync(shim)); } catch { /* Try the next PATH entry. */ }
  }
  const cli = candidates.find(p => p.endsWith('npm-cli.js') && fs.existsSync(p));
  if (!cli) throw new Error('Cannot locate npm-cli.js next to Node or on PATH');
  return cli;
}
const npmCli = findNpmCli();
const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(npm_config_|rnpm_|uv_threadpool_size$|cache$|prefix$|userconfig$|globalconfig$)/i.test(key)));
const isolation = {
  NPM_CONFIG_USERCONFIG: path.join(root, 'empty.npmrc'),
  NPM_CONFIG_GLOBALCONFIG: path.join(root, 'global.npmrc'),
  NPM_CONFIG_PREFIX: path.join(root, 'prefix'),
  APPDATA: path.join(root, 'appdata'),
  LOCALAPPDATA: path.join(root, 'localappdata'),
};
for (const key of ['NPM_CONFIG_PREFIX', 'APPDATA', 'LOCALAPPDATA']) fs.mkdirSync(isolation[key], { recursive: true });
const digest = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const git = (...args) => execFileSync('git', args, { cwd: repo, encoding: 'utf8' }).trim();
const report = {
  timestamp: new Date().toISOString(), git_head: git('rev-parse', 'HEAD'),
  source_dirty: git('status', '--porcelain', '--untracked-files=no') !== '',
  source_diff_sha256: createHash('sha256').update(git('diff', 'HEAD')).digest('hex'),
  binary_sha256: digest(binary), fixture_lock_sha256: digest(path.join(fixture, 'package-lock.json')),
  environment: { os: `${os.platform()} ${os.release()}`, node: process.version, npm: execFileSync(process.execPath, [npmCli, '--version'], { env: { ...cleanEnv, ...isolation }, encoding: 'utf8' }).trim(), cpu_count: os.availableParallelism(), writer: 'default', load_before: os.loadavg() },
  conditions: { runs, order: 'npm/rnpm on odd rounds, rnpm/npm on even rounds; cold then warm', cache: 'empty per cold invocation; separate tarball caches seeded before warm samples; store empty per rnpm invocation', logs: path.basename(logDir) },
  samples: [], setup: [], thresholds: { speedup: 2, spread_pct: 25 }, gate_passed: false,
};

async function invoke(tool, argv, cwd, cache, store, label) {
  const env = { ...cleanEnv, ...isolation, NPM_CONFIG_CACHE: cache, RNPM_STORE_DIR: store };
  const exe = tool === 'npm' ? process.execPath : binary;
  const cliArgs = tool === 'npm' ? [npmCli, ...argv] : argv;
  const stdout = fs.openSync(path.join(logDir, label + '.stdout'), 'w');
  const stderr = fs.openSync(path.join(logDir, label + '.stderr'), 'w');
  const start = performance.now();
  try {
    const result = await new Promise((resolve, reject) => {
      const child = spawn(exe, cliArgs, { cwd, env, windowsHide: true, stdio: ['ignore', stdout, stderr] });
      child.on('error', reject);
      child.on('close', (code, signal) => resolve({ code, signal }));
    });
    return { tool, elapsed_ms: performance.now() - start, exit_code: result.code, signal: result.signal, log: label };
  } finally { fs.closeSync(stdout); fs.closeSync(stderr); }
}
function successful(sample) {
  if (sample.exit_code !== 0) throw new Error(`${sample.log} failed: exit ${sample.exit_code}; see ${logDir}`);
}
function tree(dir) {
  const entries = new Map();
  function visit(current, prefix = '') {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (entry.name.startsWith('.rnpm') || entry.name === '.package-lock.json') continue;
      const rel = prefix + entry.name;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) visit(full, rel + '/');
      else if (entry.isSymbolicLink()) entries.set(rel, `link:${fs.readlinkSync(full)}`);
      else entries.set(rel, digest(full));
    }
  }
  visit(path.join(dir, 'node_modules'));
  return entries;
}
function sameTree(a, b) {
  return a.size === b.size && [...a].every(([name, hash]) => b.get(name) === hash);
}
function firstBlob(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) { const found = firstBlob(full); if (found) return found; }
    else if (entry.isFile() && fs.statSync(full).size > 100) return full;
  }
}
function summarize(samples) {
  const values = samples.map(s => s.elapsed_ms).sort((a, b) => a - b);
  const median = values.length % 2 ? values[(values.length - 1) / 2] : (values[values.length / 2 - 1] + values[values.length / 2]) / 2;
  return { median_ms: median, spread_pct: (values.at(-1) - values[0]) / values[0] * 100 };
}
let reference;
try {
  console.log(`Lane 4: ${runs} unfiltered alternating rounds; npm ${report.environment.npm}; ${report.git_head}`);
  for (const tool of ['npm', 'rnpm']) {
    const dir = project(`seed-${tool}`);
    const seed = await invoke(tool, ['ci', '--no-audit', '--no-fund'], dir, path.join(root, `${tool}-warm-cache`), path.join(dir, 'store'), `seed-${tool}`);
    report.setup.push(seed);
    successful(seed);
    if (tool === 'npm') reference = tree(dir);
    remove(dir);
  }
  for (let round = 1; round <= runs; round++) {
    for (const scenario of ['cold', 'warm-tar']) {
      for (const tool of round % 2 ? ['npm', 'rnpm'] : ['rnpm', 'npm']) {
        const label = `${round}-${scenario}-${tool}`;
        const dir = project(label);
        const cache = scenario === 'cold' ? path.join(dir, 'cache') : path.join(root, `${tool}-warm-cache`);
        const sample = { round, scenario, ...await invoke(tool, ['ci', '--no-audit', '--no-fund'], dir, cache, path.join(dir, 'store'), label) };
        report.samples.push(sample);
        console.log(`${label}: ${sample.elapsed_ms.toFixed(1)} ms, exit ${sample.exit_code}`);
        successful(sample);
        // Verify both scenarios; no extra install is substituted for a measured result.
        if (tool === 'rnpm') {
          const actual = tree(dir);
          sample.parity = { identical: sameTree(reference, actual), files: actual.size };
          if (!sample.parity.identical) throw new Error(`Installed tree differs from npm: ${label}`);
          const ls = await invoke('npm', ['ls', '--all'], dir, cache, path.join(dir, 'store'), `${label}-ls`);
          sample.npm_ls_exit_code = ls.exit_code;
          successful(ls);
        }
        remove(dir);
      }
    }
  }
  report.summary = {};
  for (const scenario of ['cold', 'warm-tar']) {
    const npm = summarize(report.samples.filter(s => s.scenario === scenario && s.tool === 'npm'));
    const rnpm = summarize(report.samples.filter(s => s.scenario === scenario && s.tool === 'rnpm'));
    report.summary[scenario] = { npm, rnpm, speedup: npm.median_ms / rnpm.median_ms };
  }
  const dir = project('corruption');
  const cache = path.join(root, 'rnpm-warm-cache');
  const store = path.join(dir, 'store');
  successful(await invoke('rnpm', ['ci', '--no-audit', '--no-fund'], dir, cache, store, 'corruption-seed'));
  const victim = firstBlob(path.join(store, 'cas'));
  if (!victim) throw new Error('No CAS blob available for corruption test');
  const before = fs.readFileSync(victim);
  const corrupted = Buffer.from(before);
  corrupted[10] ^= 0xaa;
  fs.writeFileSync(victim, corrupted);
  remove(path.join(dir, 'node_modules'));
  const repaired = await invoke('rnpm', ['ci', '--no-audit', '--no-fund'], dir, cache, store, 'corruption-recovery');
  report.corruption = { exit_code: repaired.exit_code, repaired: repaired.exit_code === 0 && fs.readFileSync(victim).equals(before), installed_tree_identical: repaired.exit_code === 0 && sameTree(reference, tree(dir)) };
  if (repaired.exit_code === 0 && (!report.corruption.repaired || !report.corruption.installed_tree_identical)) throw new Error('Successful corruption recovery left invalid bytes');
  report.gate_passed = Object.values(report.summary).every(s => s.speedup >= 2 && s.npm.spread_pct <= 25 && s.rnpm.spread_pct <= 25);
  console.log(JSON.stringify(report.summary, null, 2));
} catch (error) {
  report.error = error.message;
  console.error(error.message);
} finally {
  report.finished = new Date().toISOString();
  report.binary_unchanged = digest(binary) === report.binary_sha256;
  if (!report.binary_unchanged) report.gate_passed = false;
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
  console.log(`Evidence: ${output}\nGate: ${report.gate_passed ? 'PASS' : 'FAIL'}`);
  if (!keepTemp) {
    // root is the exact directory returned by mkdtemp; never a user-supplied path.
    for (const entry of fs.readdirSync(root)) remove(path.join(root, entry));
    fs.rmdirSync(root);
  } else console.log(`Kept temporary data: ${root}`);
}
process.exitCode = report.gate_passed ? 0 : 1;
