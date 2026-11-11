// Run sequential differential fixtures outside the checkout. No timing benchmarks.
// Usage: node scripts/audit-wave2.cjs <label> [case-name ...]
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const binary = path.resolve('target/release/rnpm.exe');
if (!fs.existsSync(binary)) throw new Error('Build target/release/rnpm.exe first');
const root = fs.mkdtempSync(path.join(os.tmpdir(), `rnpm-wave2-${process.argv[2] || 'audit'}-`));
const selected = process.argv.slice(3);
const cases = [];
const write = (dir, file, data) => {
  fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
  fs.writeFileSync(path.join(dir, file), data);
};
const edit = (dir, fn) => {
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'package.json')));
  fn(manifest);
  write(dir, 'package.json', JSON.stringify(manifest, null, 2) + '\n');
};
const hookNames = ['preinstall', 'install', 'postinstall', 'prepublish', 'preprepare',
  'prepare', 'postprepare', 'prepack', 'postpack', 'preversion', 'version', 'postversion', 'prex', 'x', 'postx'];
function fixture(dir) {
  write(dir, 'package.json', JSON.stringify({ name: 'wave2', version: '1.0.0', description: 'hello',
    scripts: Object.fromEntries(hookNames.map(name => [name, 'node probe.cjs'])) }, null, 2) + '\n');
  write(dir, 'probe.cjs', "require('fs').appendFileSync('events.txt',process.env.npm_lifecycle_event+'\\n');console.log(process.env.npm_lifecycle_event);\n");
}
function workspace(dir) {
  fixture(dir);
  edit(dir, m => { m.workspaces = ['packages/*']; });
  for (const name of ['a', 'b']) {
    const member = path.join(dir, 'packages', name);
    fixture(member);
    edit(member, m => { m.name = name; if (name === 'a') m.dependencies = { b: '1.0.0' }; });
  }
}
function packFixture(dir) {
  fixture(dir);
  edit(dir, m => { delete m.scripts; });
  for (const file of ['README.md', 'LICENSE', 'keep.js', 'omit.js']) write(dir, file, file + '\n');
}
const add = (name, args, setup = fixture, subdir = '') => cases.push({ name, args, setup, subdir });
add('run-hooks', ['run', 'x']);
add('run-ignore', ['run', 'x', '--ignore-scripts']);
add('run-foreground', ['run', 'x', '--foreground-scripts']);
add('run-failure', ['run', 'x'], dir => { fixture(dir); write(dir, 'fail.cjs', 'process.exit(7)'); edit(dir, m => { m.scripts.x = 'node fail.cjs'; }); });
add('install-failure', ['install'], dir => { fixture(dir); write(dir, 'probe.cjs', 'process.exit(7)'); });
add('pack-failure', ['pack', '--dry-run'], dir => { fixture(dir); write(dir, 'probe.cjs', 'process.exit(7)'); });
for (const [name, args] of [['run-env', ['run', 'x', '--ignore-scripts', '--custom=hello']],
  ['run-env-foreground', ['run', 'x', '--foreground-scripts']]]) {
  add(name, args, dir => { fixture(dir); write(dir, 'probe.cjs', `const p=require('path');
const keys=['npm_lifecycle_event','npm_lifecycle_script','npm_package_name','npm_package_version','npm_package_json','npm_package_description','npm_config_ignore_scripts','npm_config_foreground_scripts','npm_config_custom','INIT_CWD'];
for(const k of keys) console.log(k+'='+(process.env[k]??'<unset>'));
console.log('PATH='+process.env.PATH.split(p.delimiter).slice(0,4).join('|'));\n`); });
}
add('install-hooks', ['install']);
add('install-ignore', ['install', '--ignore-scripts']);
add('install-foreground', ['install', '--foreground-scripts']);
add('ci-hooks', ['ci'], dir => { fixture(dir); write(dir, 'package-lock.json', JSON.stringify({ name: 'wave2', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'wave2', version: '1.0.0', hasInstallScript: true } } }, null, 2) + '\n'); });
add('pack-hooks', ['pack', '--dry-run']);
add('pack-ignore', ['pack', '--dry-run', '--ignore-scripts']);
add('pack-silent', ['pack', '--dry-run', '--silent']);
add('pack-json-hooks', ['pack', '--dry-run', '--json']);
add('version-hooks', ['version', 'patch', '--no-git-tag-version']);
for (const [name, args] of [
  ['ws-run', ['run', 'x', '-ws']], ['ws-select', ['run', 'x', '-w', 'a']],
  ['ws-root', ['run', 'x', '-ws', '--include-workspace-root']],
  ['ws-ignore', ['run', 'x', '-ws', '--ignore-scripts']],
  ['ws-missing', ['run', 'absent', '-ws']], ['ws-if-present', ['run', 'absent', '-ws', '--if-present']],
  ['ws-exec', ['exec', '-ws', '--call=node probe.cjs']],
  ['ws-version', ['version', 'patch', '-ws', '--no-git-tag-version']], ['ws-ls', ['ls', '-ws']],
]) add(name, args, workspace);
add('ws-preonly', ['run', 'x', '-ws', '--if-present'], dir => { workspace(dir); edit(path.join(dir, 'packages/a'), m => { delete m.scripts.x; }); });
add('ws-install-subdir', ['install', '--ignore-scripts'], workspace, 'packages/a');
add('pack-files', ['pack', '--dry-run', '--json'], dir => { packFixture(dir); edit(dir, m => { m.files = ['keep.js']; }); });
add('pack-npmignore', ['pack', '--dry-run', '--json'], dir => { packFixture(dir); write(dir, '.npmignore', 'omit.js\nREADME.md\nLICENSE\npackage.json\n'); });
add('pack-gitignore', ['pack', '--dry-run', '--json'], dir => { packFixture(dir); write(dir, '.gitignore', 'omit.js\n'); });
add('pack-files-ignore', ['pack', '--dry-run', '--json'], dir => { packFixture(dir); edit(dir, m => { m.files = ['keep.js']; }); write(dir, '.npmignore', 'keep.js\n'); });
add('pack-nested-ignore', ['pack', '--dry-run', '--json'], dir => { packFixture(dir); edit(dir, m => { m.files = ['lib']; }); write(dir, 'lib/keep.js', 'keep\n'); write(dir, 'lib/omit.js', 'omit\n'); write(dir, 'lib/.npmignore', 'omit.js\n'); });
add('pack-bundle', ['pack', '--json'], dir => { packFixture(dir); edit(dir, m => { m.dependencies = { dep: '1.0.0' }; m.bundleDependencies = ['dep']; }); write(dir, 'node_modules/dep/package.json', '{"name":"dep","version":"1.0.0"}'); write(dir, 'node_modules/dep/index.js', 'hi\n'); });
add('publish-dry', ['publish', '--dry-run', '--json'], packFixture);
add('publish-hooks', ['publish', '--dry-run', '--silent']);
add('error-script', ['run', 'absent']);
add('error-no-manifest', ['run', 'x'], dir => fs.mkdirSync(dir, { recursive: true }));
add('error-invalid', ['run', 'x'], dir => { fixture(dir); write(dir, 'package.json', '{invalid'); });
add('error-unknown', ['nonesuch']);
add('error-target', ['install', 'is-number@99999.0.0', '--ignore-scripts']);
add('error-404', ['install', 'rnpm-wave2-definitely-nonexistent-8950123', '--ignore-scripts']);
function normalize(text, dir) {
  return text.replaceAll(dir, '<fixture>').replaceAll(dir.replaceAll('\\', '/'), '<fixture>')
    .replaceAll(root, '<temp>').replaceAll(root.replaceAll('\\', '/'), '<temp>')
    .replace(/\bin \d+(?:\.\d+)?(?:ms|s)\b/g, 'in <time>');
}
function snapshot(dir) {
  const result = {};
  function walk(current) {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      const relative = path.relative(dir, full).replaceAll('\\', '/');
      if (entry.isSymbolicLink()) result[relative] = 'link:' + normalize(fs.readlinkSync(full), dir);
      else if (entry.isDirectory()) walk(full);
      else result[relative] = crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex');
    }
  }
  walk(dir);
  return result;
}
const reports = [];
console.log(root);
for (const scenario of cases) {
  if (selected.length && !selected.includes(scenario.name)) continue;
  const report = { name: scenario.name, args: scenario.args };
  for (const tool of ['npm', 'rnpm']) {
    const dir = path.join(root, scenario.name, tool);
    scenario.setup(dir);
    const configDir = path.join(root, 'config', scenario.name, tool);
    fs.mkdirSync(configDir, { recursive: true });
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.toLowerCase().startsWith('npm_config_')));
    Object.assign(env, { NPM_CONFIG_CACHE: path.join(configDir, 'cache'),
      NPM_CONFIG_USERCONFIG: path.join(configDir, 'user.npmrc'), NPM_CONFIG_GLOBALCONFIG: path.join(configDir, 'global.npmrc'),
      NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org/', NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false', NPM_CONFIG_UPDATE_NOTIFIER: 'false', NO_COLOR: '1' });
    const options = { cwd: path.join(dir, scenario.subdir), env, encoding: 'utf8', timeout: 120000 };
    if (scenario.args.some(arg => !/^[\w@./= -]+$/.test(arg))) throw new Error('Fixture argument needs explicit shell escaping');
    const output = tool === 'npm'
      ? cp.spawnSync('cmd.exe', ['/d', '/s', '/c', 'npm.cmd ' + scenario.args.map(arg => arg.includes(' ') ? '"' + arg + '"' : arg).join(' ')], { ...options, windowsVerbatimArguments: true })
      : cp.spawnSync(binary, scenario.args, options);
    if (output.error) throw output.error;
    report[tool] = { code: output.status, stdout: normalize(output.stdout, dir), stderr: normalize(output.stderr, dir), files: snapshot(dir) };
  }
  const { npm, rnpm } = report;
  const differentFiles = [...new Set([...Object.keys(npm.files), ...Object.keys(rnpm.files)])].filter(file => {
    const left = npm.files[file];
    const right = rnpm.files[file];
    if (!left || !right || left.startsWith('link:') || right.startsWith('link:')) return left !== right;
    return !fs.readFileSync(path.join(root, scenario.name, 'npm', file))
      .equals(fs.readFileSync(path.join(root, scenario.name, 'rnpm', file)));
  });
  report.match = { code: npm.code === rnpm.code, stdout: npm.stdout === rnpm.stdout, stderr: npm.stderr === rnpm.stderr,
    files: differentFiles };
  console.log(JSON.stringify({ name: report.name, npm: npm.code, rnpm: rnpm.code, ...report.match }));
  reports.push(report);
  fs.writeFileSync(path.join(root, 'results.json'), JSON.stringify(reports, null, 2));
}
