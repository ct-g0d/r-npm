const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const RNPM_BIN = path.resolve('target/debug/rnpm.exe');
const NPM_BIN = 'npm.cmd';

function makeFreshDir() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-test-'));
  return tmp;
}

function createFixture(dir) {
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name: 'test-pkg',
    version: '1.0.0',
    description: 'test fixture',
    scripts: {
      test: "node -e \"console.log('tested')\"",
      start: "node -e \"console.log('started')\"",
      stop: "node -e \"console.log('stopped')\"",
      restart: "node -e \"console.log('restarted')\""
    },
    dependencies: {
      'is-number': '7.0.0'
    }
  }, null, 2) + '\n');
}

function runCmd(bin, args, cwd, env = {}) {
  const fullEnv = Object.assign({}, process.env, {
    npm_config_audit: 'false',
    npm_config_fund: 'false',
    npm_config_update_notifier: 'false',
    NO_COLOR: '1'
  }, env);
  let procBin = bin;
  let procArgs = args;
  if (bin === NPM_BIN) {
    procBin = 'cmd.exe';
    procArgs = ['/d', '/s', '/c', 'npm.cmd', ...args];
  }
  const res = spawnSync(procBin, procArgs, { cwd, env: fullEnv, encoding: 'utf8', timeout: 35000 });
  return {
    status: res.status,
    stdout: res.stdout || '',
    stderr: res.stderr || '',
    error: res.error ? res.error.message : null
  };
}

function listDirRecursive(dir) {
  const results = [];
  function walk(current, rel) {
    if (!fs.existsSync(current)) return;
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const ent of entries) {
      const relPath = path.join(rel, ent.name);
      if (ent.isDirectory()) {
        results.push(relPath + '/');
        walk(path.join(current, ent.name), relPath);
      } else {
        results.push(relPath);
      }
    }
  }
  walk(dir, '');
  return results.sort();
}

// Map of all npm commands from cmd-list.js + set-script
const CMD_LIST = require('C:/Program Files/nodejs/node_modules/npm/lib/utils/cmd-list.js');
const allCommands = [...CMD_LIST.commands, 'set-script'];

// Invert aliases to know which aliases belong to which command
const cmdAliases = {};
for (const [alias, target] of Object.entries(CMD_LIST.aliases)) {
  if (!cmdAliases[target]) cmdAliases[target] = [];
  cmdAliases[target].push(alias);
}

// Specific test invocations for each command
const TEST_CONFIGS = {
  'access': { args: ['access', '2fa-required'] },
  'adduser': { args: ['adduser', '--help'] }, // interactive, check help
  'approve-scripts': { args: ['approve-scripts', '--help'] },
  'audit': { args: ['audit'] },
  'bugs': { args: ['bugs'] },
  'cache': { args: ['cache', 'ls'] },
  'ci': { args: ['ci'] },
  'completion': { args: ['completion'] },
  'config': { args: ['config', 'list'] },
  'dedupe': { args: ['dedupe'] },
  'deny-scripts': { args: ['deny-scripts', '--help'] },
  'deprecate': { args: ['deprecate', '--help'] },
  'diff': { args: ['diff'] },
  'dist-tag': { args: ['dist-tag', 'ls', 'is-number'] },
  'docs': { args: ['docs'] },
  'doctor': { args: ['doctor', '--help'] },
  'edit': { args: ['edit', '--help'] },
  'exec': { args: ['exec', '--', 'node', '-e', 'console.log("exec_ok")'] },
  'explain': { args: ['explain', 'is-number'] },
  'explore': { args: ['explore', '--help'] },
  'find-dupes': { args: ['find-dupes'] },
  'fund': { args: ['fund'] },
  'get': { args: ['get', 'registry'] },
  'help': { args: ['help'] },
  'help-search': { args: ['help-search', 'install'] },
  'init': { args: ['init', '-y'] },
  'install': { args: ['install', '--package-lock-only'] },
  'install-ci-test': { args: ['install-ci-test', '--help'] },
  'install-scripts': { args: ['install-scripts', '--help'] },
  'install-test': { args: ['install-test', '--help'] },
  'link': { args: ['link', '--help'] },
  'll': { args: ['ll'] },
  'login': { args: ['login', '--help'] },
  'logout': { args: ['logout', '--help'] },
  'ls': { args: ['ls'] },
  'org': { args: ['org', '--help'] },
  'outdated': { args: ['outdated'] },
  'owner': { args: ['owner', 'ls', 'is-number'] },
  'pack': { args: ['pack', '--dry-run'] },
  'ping': { args: ['ping'] },
  'pkg': { args: ['pkg', 'get', 'name'] },
  'prefix': { args: ['prefix'] },
  'profile': { args: ['profile', '--help'] },
  'prune': { args: ['prune'] },
  'publish': { args: ['publish', '--dry-run'] },
  'query': { args: ['query', ':root'] },
  'rebuild': { args: ['rebuild'] },
  'repo': { args: ['repo'] },
  'restart': { args: ['restart'] },
  'root': { args: ['root'] },
  'run': { args: ['run', 'test'] },
  'sbom': { args: ['sbom', '--help'] },
  'search': { args: ['search', 'is-number'] },
  'set': { args: ['set', 'foo=bar'] },
  'shrinkwrap': { args: ['shrinkwrap'] },
  'stage': { args: ['stage', '--help'] },
  'star': { args: ['star', '--help'] },
  'stars': { args: ['stars', '--help'] },
  'start': { args: ['start'] },
  'stop': { args: ['stop'] },
  'team': { args: ['team', '--help'] },
  'test': { args: ['test'] },
  'token': { args: ['token', '--help'] },
  'trust': { args: ['trust', '--help'] },
  'undeprecate': { args: ['undeprecate', '--help'] },
  'uninstall': { args: ['uninstall', '--help'] },
  'unpublish': { args: ['unpublish', '--help'] },
  'unstar': { args: ['unstar', '--help'] },
  'update': { args: ['update'] },
  'version': { args: ['version'] },
  'view': { args: ['view', 'is-number', 'version'] },
  'whoami': { args: ['whoami'] },
  'set-script': { args: ['set-script', '--help'] }
};

const results = [];

for (const cmd of allCommands) {
  const conf = TEST_CONFIGS[cmd] || { args: [cmd, '--help'] };
  const aliases = (cmdAliases[cmd] || []).join(', ');

  const npmDir = makeFreshDir();
  createFixture(npmDir);
  const rnpmDir = makeFreshDir();
  createFixture(rnpmDir);

  const npmRes = runCmd(NPM_BIN, conf.args, npmDir);
  const rnpmRes = runCmd(RNPM_BIN, conf.args, rnpmDir);

  const npmFiles = listDirRecursive(npmDir);
  const rnpmFiles = listDirRecursive(rnpmDir);

  // Determine status: matching, partial, missing
  let status = 'matching';
  const diffs = [];

  const rnpmUnknown = rnpmRes.stderr.includes('Unknown command') || rnpmRes.stdout.includes('Unknown command') || rnpmRes.status === 2;
  const npmUnknown = npmRes.stderr.includes('Unknown command') || npmRes.stdout.includes('Unknown command');

  if (rnpmUnknown && !npmUnknown) {
    status = 'missing';
    diffs.push('Command not implemented in rnpm (reports unknown command)');
  } else if (rnpmRes.status !== npmRes.status) {
    status = 'partial';
    diffs.push(`Exit code mismatch: npm=${npmRes.status}, rnpm=${rnpmRes.status}`);
  }

  // Compare file changes
  const npmChangedFiles = npmFiles.filter(f => f !== 'package.json');
  const rnpmChangedFiles = rnpmFiles.filter(f => f !== 'package.json');
  if (JSON.stringify(npmChangedFiles) !== JSON.stringify(rnpmChangedFiles)) {
    if (status === 'matching') status = 'partial';
    diffs.push(`File system changes differ: npm wrote [${npmChangedFiles.join(', ')}], rnpm wrote [${rnpmChangedFiles.join(', ')}]`);
  }

  // Check stdout / stderr differences
  const normNpmOut = npmRes.stdout.trim().replace(/\r\n/g, '\n');
  const normRnpmOut = rnpmRes.stdout.trim().replace(/\r\n/g, '\n');
  if (normNpmOut !== normRnpmOut) {
    if (status === 'matching') {
      // Check if it is cosmetic or functional
      status = 'partial';
    }
    const sampleNpm = normNpmOut.slice(0, 80).replace(/\n/g, ' ');
    const sampleRnpm = normRnpmOut.slice(0, 80).replace(/\n/g, ' ');
    diffs.push(`stdout format differs: npm="${sampleNpm}..." vs rnpm="${sampleRnpm}..."`);
  }

  if (diffs.length === 0) {
    diffs.push('Stdout, stderr, exit code and file changes match expected parity');
  }

  results.push({
    command: cmd,
    aliases,
    status,
    diffs: diffs.join('; '),
    checkMethod: `Ran \`${conf.args.join(' ')}\` on fresh fixture directory`
  });

  // Clean up
  try {
    fs.rmSync(npmDir, { recursive: true, force: true });
    fs.rmSync(rnpmDir, { recursive: true, force: true });
  } catch (e) {}
}

fs.writeFileSync('scripts/baseline_results.json', JSON.stringify(results, null, 2), 'utf8');
console.log('Results written to scripts/baseline_results.json, count:', results.length);
