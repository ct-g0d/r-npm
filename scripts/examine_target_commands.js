const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const RNPM_BIN = path.resolve('target/debug/rnpm.exe');
const NPM_BIN = 'npm.cmd';

function makeFreshDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'npm-diag-'));
}

function runCmd(bin, args, cwd) {
  const env = Object.assign({}, process.env, {
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    npm_config_update_notifier: 'false',
    NO_COLOR: '1'
  });
  const res = spawnSync(bin, args, { cwd, env, encoding: 'utf8', timeout: 35000 });
  return {
    status: res.status,
    stdout: res.stdout || '',
    stderr: res.stderr || ''
  };
}

const commandsToExamine = [
  // 1. outdated
  { name: 'outdated', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'outdated-test',
      version: '1.0.0',
      dependencies: { 'is-number': '6.0.0' }
    }));
  }, args: ['outdated'] },

  // 2. update
  { name: 'update', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'update-test',
      version: '1.0.0',
      dependencies: { 'is-number': '^6.0.0' }
    }));
  }, args: ['update'] },

  // 3. version
  { name: 'version', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'ver-test',
      version: '1.0.0'
    }));
  }, args: ['version', 'patch', '--no-git-tag-version'] },

  // 4. pack
  { name: 'pack', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'pack-test',
      version: '1.0.0'
    }));
  }, args: ['pack', '--dry-run'] },

  // 5. prune
  { name: 'prune', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'prune-test',
      version: '1.0.0',
      devDependencies: { 'is-number': '7.0.0' }
    }));
    fs.mkdirSync(path.join(dir, 'node_modules', 'is-number'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'node_modules', 'is-number', 'package.json'), JSON.stringify({ name: 'is-number', version: '7.0.0' }));
  }, args: ['prune', '--production'] },

  // 6. dedupe
  { name: 'dedupe', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'dedupe-test',
      version: '1.0.0'
    }));
  }, args: ['dedupe'] },

  // 7. rebuild
  { name: 'rebuild', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'rebuild-test',
      version: '1.0.0'
    }));
  }, args: ['rebuild'] },

  // 8. link
  { name: 'link', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'link-test',
      version: '1.0.0'
    }));
  }, args: ['link', '--help'] },

  // 9. config
  { name: 'config-get', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'cfg', version: '1.0.0' }));
  }, args: ['config', 'get', 'registry'] },
  { name: 'config-delete', setup: (dir) => {
    fs.writeFileSync(path.join(dir, '.npmrc'), 'foo=bar\n');
  }, args: ['config', 'delete', 'foo'] },

  // 10. cache
  { name: 'cache-ls', setup: () => {}, args: ['cache', 'ls'] },
  { name: 'cache-verify', setup: () => {}, args: ['cache', 'verify'] },
  { name: 'cache-clean', setup: () => {}, args: ['cache', 'clean', '--force'] },

  // 11. init -y
  { name: 'init -y', setup: () => {}, args: ['init', '-y'] },

  // 12. query
  { name: 'query', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'qry', version: '1.0.0' }));
  }, args: ['query', ':root'] },

  // 13. pkg
  { name: 'pkg-get', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'pkg-t', version: '1.2.3' }));
  }, args: ['pkg', 'get', 'name'] },
  { name: 'pkg-set', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'pkg-t', version: '1.2.3' }));
  }, args: ['pkg', 'set', 'description=test description'] },
  { name: 'pkg-delete', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'pkg-t', version: '1.2.3', extra: 'drop' }));
  }, args: ['pkg', 'delete', 'extra'] },

  // 14. install-test
  { name: 'install-test', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'it-t',
      version: '1.0.0',
      scripts: { test: 'node -e "console.log(\'test_ok\')"' }
    }));
  }, args: ['install-test', '--package-lock-only'] },

  // 15. shrinkwrap
  { name: 'shrinkwrap', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'shrink-t', version: '1.0.0' }));
    fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({ name: 'shrink-t', version: '1.0.0', lockfileVersion: 3 }));
  }, args: ['shrinkwrap'] },

  // 16. sbom
  { name: 'sbom', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'sbom-t', version: '1.0.0' }));
  }, args: ['sbom'] },

  // 17. view
  { name: 'view', setup: () => {}, args: ['view', 'is-number', 'version'] },

  // 18. ping
  { name: 'ping', setup: () => {}, args: ['ping'] },

  // 19. whoami
  { name: 'whoami', setup: () => {}, args: ['whoami'] },

  // 20. prefix
  { name: 'prefix', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'pfx-t', version: '1.0.0' }));
  }, args: ['prefix'] },

  // 21. root
  { name: 'root', setup: (dir) => {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'rt-t', version: '1.0.0' }));
  }, args: ['root'] }
];

for (const test of commandsToExamine) {
  const npmDir = makeFreshDir();
  const rnpmDir = makeFreshDir();
  test.setup(npmDir);
  test.setup(rnpmDir);

  const npmRes = runCmd(NPM_BIN, test.args, npmDir);
  const rnpmRes = runCmd(RNPM_BIN, test.args, rnpmDir);

  console.log(`=== ${test.name} (\`${test.args.join(' ')}\`) ===`);
  console.log(`npm  exit: ${npmRes.status}, stdout: ${JSON.stringify(npmRes.stdout.trim().slice(0, 100))}, stderr: ${JSON.stringify(npmRes.stderr.trim().slice(0, 100))}`);
  console.log(`rnpm exit: ${rnpmRes.status}, stdout: ${JSON.stringify(rnpmRes.stdout.trim().slice(0, 100))}, stderr: ${JSON.stringify(rnpmRes.stderr.trim().slice(0, 100))}`);
  console.log('');
}
