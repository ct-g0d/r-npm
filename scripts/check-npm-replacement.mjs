import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const option = (name, fallback) => args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
const binary = path.resolve(option('--binary', path.join(repo, 'target/release', process.platform === 'win32' ? 'rnpm.exe' : 'rnpm')));
const output = path.resolve(option('--output', path.join(repo, 'target/npm-replacement-smoke.json')));
const root = fs.mkdtempSync(path.join(repo, 'target/readiness-smoke-'));
const npmCli = path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js');
const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(npm_config_|rnpm_)/i.test(k)));
fs.writeFileSync(path.join(root, 'empty.npmrc'), '');
fs.writeFileSync(path.join(root, 'global.npmrc'), '');
Object.assign(env, { NPM_CONFIG_USERCONFIG:path.join(root,'empty.npmrc'), NPM_CONFIG_GLOBALCONFIG:path.join(root,'global.npmrc'), NPM_CONFIG_PREFIX:path.join(root,'prefix'), NPM_CONFIG_CACHE:path.join(root,'cache'), RNPM_STORE_DIR:path.join(root,'store') });
const cases = [
  { name:'pack-explicit-file-vs-root-ignore', args:['pack','--dry-run','--json','--ignore-scripts'], manifest:{files:['keep.js']}, files:{'keep.js':'hello','.npmignore':'keep.js\n'} },
  { name:'pack-nested-ignore', args:['pack','--dry-run','--json','--ignore-scripts'], manifest:{files:['lib']}, files:{'lib/keep.js':'hello','lib/omit.js':'omit','lib/.npmignore':'omit.js\n'} },
  { name:'empty-install-hidden-lock', args:['install','--no-audit','--no-fund','--ignore-scripts'], manifest:{}, files:{} },
  { name:'failing-lifecycle-public-lock', args:['install','--no-audit','--no-fund'], manifest:{scripts:{postinstall:'node -e "process.exit(7)"'}}, files:{} },
];
const results=[];
for(const c of cases){
  const result={name:c.name,args:c.args,manifest:c.manifest,fixture_files:c.files};
  for(const tool of ['npm','rnpm']){
    const dir=path.join(root,c.name+'-'+tool);fs.mkdirSync(dir);
    fs.writeFileSync(path.join(dir,'package.json'),JSON.stringify({name:'readiness-case',version:'1.0.0',...c.manifest}));
    for(const [name,content] of Object.entries(c.files)){fs.mkdirSync(path.dirname(path.join(dir,name)),{recursive:true});fs.writeFileSync(path.join(dir,name),content);}
    const exe=tool==='npm'?process.execPath:binary;
    const args=tool==='npm'?[npmCli,...c.args]:c.args;
    const p=spawnSync(exe,args,{cwd:dir,env,encoding:'utf8',windowsHide:true});
    result[tool]={exit:p.status,public_lock:fs.existsSync(path.join(dir,'package-lock.json')),hidden_lock:fs.existsSync(path.join(dir,'node_modules/.package-lock.json'))};
    if(c.args[0]==='pack')try{result[tool].files=JSON.parse(p.stdout)[0].files.map(f=>f.path).sort();}catch{result[tool].parse_error=p.stdout.slice(0,300);}
    fs.writeFileSync(path.join(root,c.name+'-'+tool+'.log'),p.stdout+p.stderr);
  }
  result.match=JSON.stringify(result.npm)===JSON.stringify(result.rnpm);results.push(result);
}
const git = (...args) => execFileSync('git',args,{cwd:repo,encoding:'utf8'}).trim();
fs.mkdirSync(path.dirname(output),{recursive:true});
fs.writeFileSync(output,JSON.stringify({head:git('rev-parse','HEAD'),source_dirty:git('status','--porcelain','--untracked-files=no')!=='',binary_sha256:createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),node:process.version,npm:execFileSync(process.execPath,[npmCli,'--version'],{env,encoding:'utf8'}).trim(),note:'Four targeted smoke cases; not a complete npm compatibility audit',results},null,2)+'\n');
console.log(JSON.stringify(results,null,2));
console.log('Evidence: '+output);
process.exitCode=results.every(r=>r.match)?0:1;
