// Pin npm-generated v1/v2/v3 upgrade inputs for a small native/optional case.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(root, '../..');
const index = JSON.parse(fs.readFileSync(path.join(root, 'index.json')));
const npmCli = path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js');
const date = new Date().toISOString();
for (const id of ['scripts-bcrypt', 'scripts-esbuild', 'scripts-sharp']) {
  const project = index.projects.find(project => project.id === id);
  project.locks = {};
  for (const version of [1, 2, 3]) {
    const dir = path.join(repo, 'target/f2-pin-locks', id, String(version));
    if (fs.existsSync(dir)) throw new Error(`Use fresh lock generation dirs: ${dir}`);
    fs.mkdirSync(dir, { recursive: true });
    const isolation = dir + '-isolation';
    fs.mkdirSync(isolation, { recursive: true });
    fs.writeFileSync(path.join(isolation, 'user.npmrc'), '');
    fs.writeFileSync(path.join(isolation, 'global.npmrc'), '');
    fs.copyFileSync(path.join(root, project.files['package.json'].path), path.join(dir, 'package.json'));
    const baseEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(npm_config_|rnpm_|npm_token$|node_auth_token$)/i.test(key)));
    const output = execFileSync(process.execPath, [npmCli, 'install', '--ignore-scripts', '--package-lock-only', `--lockfile-version=${version}`], {
      cwd: dir, env: { ...baseEnv, NPM_CONFIG_USERCONFIG: path.join(isolation, 'user.npmrc'), NPM_CONFIG_GLOBALCONFIG: path.join(isolation, 'global.npmrc'),
        NPM_CONFIG_PREFIX: path.join(isolation, 'prefix'), NPM_CONFIG_CACHE: path.join(isolation, 'cache'), NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org/', NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false' },
      encoding: 'utf8', windowsHide: true,
    });
    fs.writeFileSync(path.join(isolation, 'npm.stdout.log'), output);
    const bytes = fs.readFileSync(path.join(dir, 'package-lock.json'));
    const destination = `locks/${id}-v${version}.json`;
    fs.mkdirSync(path.join(root, 'locks'), { recursive: true });
    fs.writeFileSync(path.join(root, destination), bytes);
    project.locks[version] = { path: destination, sha256: createHash('sha256').update(bytes).digest('hex'), date, npm: execFileSync(process.execPath, [npmCli, '--version'], { encoding: 'utf8' }).trim() };
    console.log(`${id}: pinned npm lockfileVersion ${version}`);
  }
}
fs.writeFileSync(path.join(root, 'index.json'), JSON.stringify(index, null, 2) + '\n');
