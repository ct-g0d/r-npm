// Differential behavioral gate. All registry traffic stays on a loopback mock.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { gunzipSync } from 'node:zlib';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = process.argv.slice(2);
const option = (name, fallback) => cli.includes(name) ? cli[cli.indexOf(name) + 1] : fallback;
const binary = path.resolve(option('--binary', path.join(repo, 'target/release', process.platform === 'win32' ? 'rnpm.exe' : 'rnpm')));
const output = path.resolve(option('--output', path.join(repo, 'target/npm-replacement-smoke.json')));
// Long real path: npm compares realpaths, so an 8.3 short temp path would
// make npm's own path-keyed policies miss.
const root = fs.mkdtempSync(path.join(fs.realpathSync.native(os.tmpdir()), 'rnpm-replacement-'));
console.log(`Fixtures and raw logs: ${root}`);
const npmCli = path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js');
const baseEnv = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(npm_config_|rnpm_|npm_token$|node_auth_token$)/i.test(k)));
const write = (dir, name, value) => { const p=path.join(dir,name); fs.mkdirSync(path.dirname(p),{recursive:true}); fs.writeFileSync(p,typeof value==='string'||Buffer.isBuffer(value)?value:JSON.stringify(value,null,2)+'\n'); };
const manifest = (dir, fields={}) => write(dir,'package.json',{name:'readiness-case',version:'1.0.0',...fields});
const edit = (dir, fn) => { const p=JSON.parse(fs.readFileSync(path.join(dir,'package.json'))); fn(p); write(dir,'package.json',p); };
async function run(exe,args,cwd,env,input=[]) {
  return await new Promise(resolve=>{
    const p=spawn(exe,args,{cwd,env,windowsHide:true,stdio:[input.length?'pipe':'ignore','pipe','pipe']});
    let nextInput=0;
    let stdout='',stderr='',error=''; const timer=setTimeout(()=>{
      error=`Timeout after 120 seconds: ${args.join(' ')}`;
      if(process.platform==='win32'&&p.pid)spawn('taskkill.exe',['/pid',String(p.pid),'/t','/f'],{windowsHide:true,stdio:'ignore'});else p.kill('SIGKILL');
    },120000);
    p.stdout.on('data',b=>{stdout+=b;const item=input[nextInput];if(item&&stdout.includes(item.prompt)){nextInput++;p.stdin.write(item.value+'\n');}}); p.stderr.on('data',b=>stderr+=b); p.on('error',e=>{error=String(e);});
    p.on('close',exit=>{clearTimeout(timer);resolve({exit,stdout,stderr,error});});
  });
}
const STAGE_ID='6d8ce1e2-9bca-496a-b8b5-3e0fa10728ed';
const tarballs=new Map(); const requests=[]; let generation=1,authScenario='',authPolls=0;
const server=http.createServer((req,res)=>{
  const url=decodeURIComponent(req.url.split('?')[0]);
  const request={method:req.method,url,etag:req.headers['if-none-match']};requests.push(request);
  const chunks=[];req.on('data',b=>chunks.push(b));req.on('end',()=>{let body=Buffer.concat(chunks);if(req.headers['content-encoding']==='gzip')body=gunzipSync(body);if(body.length){try{request.body=JSON.parse(body.toString());}catch{request.body=body.toString();}}});
  const json=(data,status=200)=>{res.writeHead(status,{'content-type':'application/json','cache-control':'max-age=0','etag':`"generation-${generation}"`});res.end(JSON.stringify(data));};
  if(tarballs.has(url)){res.writeHead(200,{'content-type':'application/octet-stream'});res.end(tarballs.get(url));return;}
  if(url===`/-/stage/${STAGE_ID}/tarball`){res.writeHead(200,{'content-type':'application/octet-stream'});res.end(tarballs.get('/dep-1.0.0.tgz'));return;}
  if(url==='/-/ping')return json({});
  if(url.includes('/security/advisories/bulk'))return json({});
  if(url.includes('/security/audits/quick'))return json({actions:[],advisories:{},metadata:{vulnerabilities:{info:0,low:0,moderate:0,high:0,critical:0},dependencies:0,devDependencies:0,optionalDependencies:0,totalDependencies:0}});
  if(url==='/-/whoami')return json({username:'mock-user'});
  if(url==='/-/v1/login')return authScenario==='web'?json({loginUrl:`${registry}auth/login`,doneUrl:`${registry}auth/done`}):json({error:'Mock registry does not provide browser login'},400);
  if(url==='/auth/done'){if(authPolls++===0){res.setHeader('retry-after','0.01');return json({},202);}return json({token:'mock-login-token'});}
  if(url.startsWith('/-/user/org.couchdb.user:')&&req.method==='PUT')return json({token:'mock-login-token'});
  if(url.endsWith('/trust')&&req.method==='POST'){req.on('end',()=>json(request.body.map((item,i)=>({id:`created-${i+1}`,...item}))));return;}
  if(url.startsWith('/-/stage/package/')&&req.method==='POST')return json({stageId:STAGE_ID});
  if(req.method==='PUT'&&url==='/rejected-pkg')return json({error:'You do not have permission to publish "rejected-pkg"'},403);
  if(req.method==='PUT'||req.method==='DELETE'||req.method==='POST')return json({ok:true});
  if(url==='/-/user/mock-user/package')return json({});
  if(url==='/-/org/mock-org/user')return json({'mock-user':'developer'});
  if(url==='/-/org/mock-org/team')return json([]);
  if(url==='/-/npm/v1/user')return json({name:'mock-user',email:'mock@example.invalid',tfa:false});
  if(url==='/-/npm/v1/tokens')return json({objects:[],total:0,urls:{}});
  if(url==='/-/_view/starredByUser')return json({rows:[]});
  const stageItem={id:STAGE_ID,packageName:'dep',version:'1.2.0',status:'pending',tag:'latest',createdAt:'2026-11-13T00:00:00.000Z',actor:'mock-user',actorType:'user',shasum:'0123456789abcdef',extra:'kept'};
  if(url==='/-/stage'){const pkg=new URL(req.url,'http://x').searchParams.get('package');return json(pkg==='empty-pkg'?{items:[],total:0}:{items:[stageItem],total:1});}
  if(url===`/-/stage/${STAGE_ID}`)return json(stageItem);
  if(url==='/-/package/dep/trust')return json([{id:'trust-1',type:'github',claims:{repository:'mock/repo',workflow_ref:{file:'publish.yml'},environment:'prod'},permissions:['createPackage','createStagedPackage']},{id:'trust-2',type:'gitlab',claims:{project_path:'group/proj',ci_config_ref_uri:{file:'.gitlab-ci.yml'}},permissions:['createPackage']}]);
  if(url.endsWith('/trust'))return json([]);
  if(url.includes('/stages')||url.includes('/trusted-publishers'))return json([]);
  if(url==='/-/v1/search')return json({objects:[],total:0,time:'2026-11-13T00:00:00.000Z'});
  if(url.startsWith('/-/package/')&&url.endsWith('/dist-tags'))return json({latest:'1.0.0'});
  const name=url.slice(1);
  if(['dep','parent','changing'].includes(name)){
    const versions={};
    for(const version of (name==='changing'&&generation===1?['1.0.0']:['1.0.0','1.1.0','2.0.0'])){
      const bytes=tarballs.get(`/${name}-${version}.tgz`);
      versions[version]={name,version,...(name==='parent'?{dependencies:{dep:'^1.0.0'}}:{}),dist:{tarball:`${registry}${name}-${version}.tgz`,shasum:createHash('sha1').update(bytes).digest('hex'),integrity:'sha512-'+createHash('sha512').update(bytes).digest('base64')}};
    }
    return json({name,_id:name,_rev:'1-mock',maintainers:[{name:'mock-user',email:'mock@example.invalid'}],users:{},'dist-tags':{latest:name==='changing'&&generation===1?'1.0.0':'2.0.0',next:'1.1.0'},versions});
  }
  return json({error:'not found'},404);
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const registry=`http://127.0.0.1:${server.address().port}/`;
const oracleEnv={...baseEnv,NPM_CONFIG_USERCONFIG:path.join(root,'empty.npmrc'),NPM_CONFIG_GLOBALCONFIG:path.join(root,'global.npmrc'),NPM_CONFIG_CACHE:path.join(root,'oracle-cache'),NPM_CONFIG_PREFIX:path.join(root,'oracle-prefix'),NPM_CONFIG_REGISTRY:registry,NPM_CONFIG_UPDATE_NOTIFIER:'false',NPM_CONFIG_AUDIT:'false',NPM_CONFIG_FUND:'false'};
write(root,'empty.npmrc','');write(root,'global.npmrc','');
for(const name of ['dep','parent','changing'])for(const version of ['1.0.0','1.1.0','2.0.0']){
  const dir=path.join(root,'tarballs',`${name}-${version}`);manifest(dir,{name,version,...(name==='parent'?{dependencies:{dep:'^1.0.0'}}:{})});write(dir,'index.js','module.exports = 1;\n');
  const p=await run(process.execPath,[npmCli,'pack','--ignore-scripts','--silent'],dir,oracleEnv);if(p.exit!==0)throw new Error(p.stderr);
  tarballs.set(`/${name}-${version}.tgz`,fs.readFileSync(path.join(dir,`${name}-${version}.tgz`)));
}
const cases=[];
const add=(name,command,args,setup=dir=>manifest(dir),extra={})=>cases.push({name,command,args,setup,...extra});
const packArgs=['pack','--dry-run','--json','--ignore-scripts'];
for(const [name,fields,files] of [
  ['pack-explicit-file-vs-root-ignore',{files:['keep.js']},{'keep.js':'hello','.npmignore':'keep.js\n'}],
  ['pack-nested-ignore',{files:['lib']},{'lib/keep.js':'hello','lib/omit.js':'omit','lib/.npmignore':'omit.js\n'}],
  ['pack-explicit-nested-file',{files:['lib/keep.js']},{'lib/keep.js':'hello','lib/.npmignore':'keep.js\n'}],
  ['pack-nested-gitignore',{files:['lib']},{'lib/keep.js':'hello','lib/omit.js':'omit','lib/.gitignore':'omit.js\n'}],
  ['pack-ignore-globstar',{},{'index.js':'1','.npmignore':'secrets/**/*.pem\n','secrets/prod/key.pem':'FAKE-KEY','secrets/top.pem':'FAKE-KEY'}],
  ['pack-ignore-anchored-dir',{},{'index.js':'1','.npmignore':'config/private\n','config/private/a.json':'{}','config/public.json':'{}'}],
  ['pack-files-globstar',{files:['dist/**/*.js']},{'dist/sub/index.js':'1','dist/sub/index.ts':'1','dist/top.js':'1'}],
  ['pack-files-brace-class',{files:['lib/*.{js,cjs}','bin/v[0-9].js']},{'lib/a.js':'1','lib/b.cjs':'1','lib/c.ts':'1','bin/v1.js':'1','bin/vx.js':'1'}],
  ['pack-nested-ignore-negation',{}, {'lib/keep.js':'hello','lib/omit.js':'omit','.npmignore':'*.js\n','lib/.npmignore':'!keep.js\n'}],
])add(name,'pack',packArgs,dir=>{manifest(dir,fields);for(const [p,v]of Object.entries(files))write(dir,p,v);});
add('empty-install-hidden-lock','install',['install','--ignore-scripts']);
add('failing-lifecycle-public-lock','install',['install'],dir=>manifest(dir,{scripts:{postinstall:'node -e "process.exit(7)"'}}));
add('explicit-install-skips-root-hooks','install',['install','dep@1.0.0'],dir=>manifest(dir,{scripts:{postinstall:'node -e "process.exit(7)"'}}));
add('failing-ci-preserves-hidden-lock','ci',['ci'],dir=>manifest(dir,{dependencies:{dep:'1.0.0'},scripts:{postinstall:'node -e "process.exit(7)"'}}),{before:async ctx=>{const p=await ctx.exec(['install','--ignore-scripts']);if(p.exit!==0)throw new Error(p.stderr);fs.rmSync(path.join(ctx.dir,'node_modules'),{recursive:true});}});
const workspace=dir=>{manifest(dir,{workspaces:['packages/*']});for(const name of ['a','b'])manifest(path.join(dir,'packages',name),{name,scripts:{probe:'node -p process.env.npm_package_name'}});};
for(const [name,flags]of [['name',['-w','a']],['long-equals',['--workspace=a']],['short-attached',['-wa']],['path',['-w','./packages/a']],['bare-directory',['-w','packages/a']],['parent-directory',['-w','packages']],['multiple',['-w','a','--workspace','b']]]){
  add(`workspace-run-${name}`,'run',['run','probe',...flags],workspace);
  add(`workspace-install-${name}`,'install',['install','dep@1.0.0','--ignore-scripts',...flags],workspace);
}
for(const [name,spec,flags] of [['default','dep@1.0.0',[]],['prefix','dep@1.0.0',['--save-prefix=~']],['exact','dep@1.0.0',['--save-exact']],['range','dep@~1.0.0',[]],['tag','dep@next',[]],['alias','aliased@npm:dep@1.0.0',[]],['url',()=>`${registry}dep-1.0.0.tgz`,[]],['file','./dep.tgz',[]]]){
  add(`save-${name}`,'install',['install',typeof spec==='function'?spec():spec,'--ignore-scripts',...flags],dir=>{manifest(dir);if(name==='file')write(dir,'dep.tgz',tarballs.get('/dep-1.0.0.tgz'));});
}
add('shadow-url-registry','install',['install','--ignore-scripts'],dir=>manifest(dir,{dependencies:{dep:`${registry}dep-2.0.0.tgz`,parent:'1.0.0'}}));
add('shadow-file-registry','install',['install','--ignore-scripts'],dir=>{manifest(dir,{dependencies:{dep:'file:dep.tgz',parent:'1.0.0'}});write(dir,'dep.tgz',tarballs.get('/dep-2.0.0.tgz'));});
const gitDir=path.join(root,'git-dependency');manifest(gitDir,{name:'dep',version:'2.0.0'});write(gitDir,'index.js','module.exports = 2;\n');
const gitEnv={...baseEnv,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:path.join(root,'empty.npmrc'),GIT_AUTHOR_DATE:'2026-11-13T00:00:00Z',GIT_COMMITTER_DATE:'2026-11-13T00:00:00Z'};
for(const args of [['init','--initial-branch=main'],['add','.'],['-c','user.name=Mock Author','-c','user.email=mock@example.invalid','-c','commit.gpgsign=false','-c',`core.hooksPath=${root}/empty-hooks`,'commit','-m','Fixture']])execFileSync('git',args,{cwd:gitDir,env:gitEnv,stdio:'pipe'});
const gitSpec='git+'+pathToFileURL(gitDir).href;
add('shadow-git-registry','install',['install','--ignore-scripts'],dir=>manifest(dir,{dependencies:{dep:gitSpec,parent:'1.0.0'}}));
add('save-git','install',['install',gitSpec,'--ignore-scripts']);
add('save-alias-range','install',['install','aliased@npm:dep@~1.0.0','--ignore-scripts']);
for(const [key,value]of [['save-prefix','~'],['save-exact','true']])add(`save-config-${key}`,'install',['install','dep@1.0.0','--ignore-scripts'],dir=>{manifest(dir);write(dir,'.npmrc',`${key}=${value}\n`);});
add('cache-revalidate-changed-packument','install',['install','changing','--ignore-scripts'],dir=>manifest(dir),{before:async ctx=>{generation=1;await ctx.exec(['install','changing','--ignore-scripts']);edit(ctx.dir,p=>{delete p.dependencies;});for(const p of ['package-lock.json','node_modules'])fs.rmSync(path.join(ctx.dir,p),{recursive:true,force:true});generation=2;}});
const lsFixture=(kind)=>(dir)=>{
  manifest(dir,{dependencies:{required:'^1.0.0'},optionalDependencies:{optional:'1.0.0'},peerDependencies:{peer:'^1.0.0',optionalPeer:'1.0.0'},peerDependenciesMeta:{optionalPeer:{optional:true}}});
  if(kind!=='missing')manifest(path.join(dir,'node_modules/required'),{name:'required',version:kind==='invalid'?'2.0.0':'1.0.0'});
  if(kind==='extraneous')manifest(path.join(dir,'node_modules/extra'),{name:'extra'});
  if(kind==='complete')manifest(path.join(dir,'node_modules/peer'),{name:'peer'});
};
for(const kind of ['missing','invalid','extraneous','complete'])for(const flags of [[],['--json'],['--all'],['--all','--json']])add(`ls-${kind}${flags.join('-')}`,'ls',['ls',...flags],lsFixture(kind));
add('ls-single-missing-json','ls',['ls','--json'],dir=>manifest(dir,{dependencies:{required:'^1.0.0'}}));
for(const flags of [[],['--json'],['--all','--json']])add(`ls-only-extraneous${flags.join('-')}`,'ls',['ls',...flags],dir=>{manifest(dir);manifest(path.join(dir,'node_modules/extra'),{name:'extra'});});
const simple=[['ci',['ci']],['uninstall',['uninstall','dep']],['update',['update']],['outdated',['outdated','--json']],['audit',['audit','--json']],['fund',['fund','--json']],['exec',['exec','--call=node -p 123']],['npx',['exec','--call=node -p 123']],['init',['init','-y','--silent']],['version',['version','patch','--no-git-tag-version']],['publish',['publish','--dry-run','--json','--ignore-scripts']],['config',['config','get','registry']],['cache',['cache','ls']],['link',['link','--ignore-scripts']],['pkg',['pkg','get','name']],['prefix',['prefix']],['root',['root']],['get',['get','registry']],['ping',['ping','--json']],['search',['search','--json','mock']],['whoami',['whoami','--json']],['rebuild',['rebuild']],['prune',['prune']],['dedupe',['dedupe']],['find-dupes',['find-dupes']],['shrinkwrap',['shrinkwrap']],['query',['query',':root']],['sbom',['sbom','--sbom-format=cyclonedx']]];
for(const [command,args]of simple)add(`command-${command}`,command,args,dir=>manifest(dir),{before:async ctx=>{if(['ci','audit','shrinkwrap'].includes(command))await ctx.exec(['install','--ignore-scripts']);}});
const installed=dir=>{manifest(dir,{dependencies:{dep:'^1.0.0'}});manifest(path.join(dir,'node_modules/dep'),{name:'dep'});};
for(const command of ['start','stop','restart','test','run'])add(`command-${command}`,command,command==='run'?['run','probe']:[command],dir=>manifest(dir,{scripts:{[command==='run'?'probe':command]:'node -p process.env.npm_lifecycle_event'}}));
for(const command of ['install-test','install-ci-test'])add(`command-${command}`,command,[command],dir=>manifest(dir,{scripts:{test:'node -p 123'}}),{before:async ctx=>{if(command==='install-ci-test')await ctx.exec(['install','--ignore-scripts']);}});
for(const [command,args]of [['ll',['ll','--json']],['explain',['explain','dep','--json']],['explore',['explore','dep','--','node','-p','123']],['edit',['edit','dep','--editor=node editor.cjs']]])add(`command-${command}`,command,args,dir=>{installed(dir);if(command==='edit')write(dir,'editor.cjs','require("fs").writeFileSync("edited.txt","edited");\n');});
for(const [command,field,url]of [['bugs','bugs','https://example.invalid/issues'],['docs','homepage','https://example.invalid/docs'],['repo','repository','https://example.invalid/repo.git']])add(`command-${command}`,command,[command,'--browser=false'],dir=>manifest(dir,{[field]:url}));
for(const [command,args]of [
  ['access',['access','list','packages','mock-user','--json']],['org',['org','ls','mock-org','--json']],['profile',['profile','get','--json']],['team',['team','ls','mock-org','--json']],['token',['token','list','--json']],['owner',['owner','ls','dep']],['dist-tag',['dist-tag','ls','dep']],['view',['view','dep@1.0.0','version','--json']],['whoami',['whoami','--json']],['logout',['logout']],['deprecate',['deprecate','dep@1.0.0','old']],['undeprecate',['undeprecate','dep@1.0.0']],['unpublish',['unpublish','dep@1.0.0','--force']],['star',['star','dep']],['unstar',['unstar','dep']],['stars',['stars','mock-user']],['stage',['stage','list','dep','--json']],['trust',['trust','list','dep','--json']],
])add(`registry-${command}`,command,args,dir=>manifest(dir),{auth:true});
for(const command of ['login','adduser'])add(`registry-${command}`,command,[command,'--auth-type=web']);
for(const command of ['login','adduser']){
  add(`registry-${command}-web-success`,command,[command,'--auth-type=web','--browser=false'],undefined,{authScenario:'web'});
  for(const authType of ['legacy','web'])add(`registry-${command}-${authType}-couch-success`,command,[command,`--auth-type=${authType}`],undefined,{input:[{prompt:'Username:',value:'mock-user'},{prompt:'Password:',value:'mock-password'},...(command==='adduser'?[{prompt:'Email (this will be public):',value:'mock@example.invalid'}]:[])]});
}
for(const command of ['approve-scripts','deny-scripts'])add(`command-${command}`,command,[command,'dep'],dir=>{installed(dir);edit(path.join(dir,'node_modules/dep'),p=>{p.scripts={install:'node -p 123'};});});
add('command-install-scripts','install-scripts',['install-scripts','ls'],installed);
add('command-set','set',['set','fund','false']);
add('command-set-script','set-script',['set-script','probe','node -p 123']);
add('command-completion','completion',['completion']);
add('command-help','help',['help']);
add('command-help-search','help-search',['help-search','install']);
add('command-doctor','doctor',['doctor','connection']);
for(const group of ['registry','environment','unknown'])add(`doctor-${group}`,'doctor',['doctor',group]);
const sbomTree=dir=>manifest(dir,{license:'MIT',dependencies:{parent:'1.0.0'},devDependencies:{dep:'2.0.0'},optionalDependencies:{changing:'1.0.0'}});
const sbomInstall={before:async ctx=>{generation=1;const p=await ctx.exec(['install','--ignore-scripts']);if(p.exit!==0)throw new Error(`sbom seed failed: ${p.stderr}`);}};
for(const [name,args] of [['spdx',['--sbom-format=spdx']],['cyclonedx',['--sbom-format=cyclonedx']],['cyclonedx-application',['--sbom-format=cyclonedx','--sbom-type=application']],['omit-dev',['--sbom-format=spdx','--omit=dev']],['lock-only',['--sbom-format=cyclonedx','--package-lock-only']]])add(`sbom-populated-${name}`,'sbom',['sbom',...args],sbomTree,sbomInstall);
add('sbom-missing-format','sbom',['sbom']);
add('sbom-lock-only-without-lock','sbom',['sbom','--sbom-format=spdx','--package-lock-only']);
add('sbom-missing-dependency','sbom',['sbom','--sbom-format=spdx'],dir=>manifest(dir,{dependencies:{dep:'1.0.0'}}));
for(const [name,args] of [
  ['list',['stage','list']],['list-json',['stage','list','--json']],['list-filter-empty',['stage','list','empty-pkg']],['list-version-spec',['stage','list','dep@1']],
  ['bare',['stage']],['view',['stage','view',STAGE_ID]],['view-json',['stage','view',STAGE_ID,'--json']],['view-missing-id',['stage','view']],['view-invalid-id',['stage','view','nope']],
  ['approve',['stage','approve',STAGE_ID]],['reject',['stage','reject',STAGE_ID]],['approve-missing-id',['stage','approve']],
])add(`stage-${name}`,'stage',args,dir=>manifest(dir),{auth:true});
for(const [name,args] of [
  ['list',['trust','list','dep']],['list-json',['trust','list','dep','--json']],['list-empty',['trust','list','parent']],['list-from-manifest',['trust','list']],
  ['revoke',['trust','revoke','dep','--id=trust-1']],['revoke-dry-run',['trust','revoke','dep','--id=trust-1','--dry-run']],['revoke-missing-id',['trust','revoke','dep']],['bare',['trust']],
])add(`trust-${name}`,'trust',args,dir=>manifest(dir,{name:'dep'}),{auth:true});
const scriptDep=(dir,fields={})=>{manifest(dir,{dependencies:{'script-dep':'file:./script-dep'},...fields});manifest(path.join(dir,'script-dep'),{name:'script-dep',version:'1.0.0',scripts:{postinstall:'node -e "require(\'fs\').writeFileSync(\'RAN.txt\',\'yes\')"'}});};
for(const [name,args,fields] of [
  ['allow-directory-none',['install','--allow-directory=none'],{}],
  ['allow-directory-root',['install','--allow-directory=root'],{}],
  ['strict-allow-scripts',['install','--strict-allow-scripts'],{}],
  ['strict-allow-scripts-approved',['install','--strict-allow-scripts'],{allowScripts:{'file:./script-dep':true}}],
  ['deny-by-name',['install'],{allowScripts:{'script-dep':false}}],
  ['allow-by-path',['install'],{allowScripts:{'file:./script-dep':true}}],
  ['advisory',['install'],{}],
  ['range-key-dropped',['install'],{allowScripts:{'script-dep@^1.0.0':true}}],
  ['dangerously-allow-all',['install','--strict-allow-scripts','--dangerously-allow-all-scripts'],{}],
])add(`policy-${name}`,'install',args,dir=>scriptDep(dir,fields));
add('policy-allow-file-none','install',['install','--allow-file=none'],dir=>{manifest(dir,{dependencies:{dep:'file:./dep.tgz'}});write(dir,'dep.tgz',tarballs.get('/dep-1.0.0.tgz'));});
add('policy-allow-registry-none','install',['install','--allow-registry=none'],dir=>manifest(dir,{dependencies:{dep:'1.0.0'}}));
add('repeat-install-runs-prepare','install',['install'],dir=>manifest(dir,{dependencies:{dep:'1.0.0'},scripts:{prepare:'node -e "require(\'fs\').appendFileSync(\'hooks.txt\',\'prepare\\n\')"'}}),{before:async ctx=>{const p=await ctx.exec(['install']);if(p.exit!==0)throw new Error(p.stderr);}});
const hookPkg=(name)=>dir=>{const hooks=['prepublishOnly','prepack','prepare','postpack','publish','postpublish'];manifest(dir,{name,version:'1.0.0',scripts:Object.fromEntries(hooks.map(h=>[h,`node -e "require('fs').appendFileSync('events.txt','${h}\\n')"`]))});write(dir,'index.js','module.exports=1\n');};
add('publish-hook-order','publish',['publish'],hookPkg('hooked-pkg'),{auth:true});
add('publish-rejected-skips-publish-hook','publish',['publish'],hookPkg('rejected-pkg'),{auth:true});
add('publish-provenance-unsupported-provider','publish',['publish','--provenance','--access','public','--ignore-scripts'],dir=>{manifest(dir,{name:'prov-pkg'});write(dir,'index.js','1\n');},{auth:true});
add('publish-basic-auth','publish',['publish','--ignore-scripts'],dir=>{manifest(dir,{name:'basic-pkg'});write(dir,'index.js','1\n');},{auth:'basic'});
add('publish-no-auth','publish',['publish','--ignore-scripts'],dir=>{manifest(dir,{name:'noauth-pkg'});write(dir,'index.js','1\n');});
add('publish-tarball','publish',['publish','./dep.tgz'],dir=>{manifest(dir,{name:'wrapper'});write(dir,'dep.tgz',tarballs.get('/dep-1.0.0.tgz'));},{auth:true});
add('publish-tarball-json','publish',['publish','./dep.tgz','--json'],dir=>{manifest(dir,{name:'wrapper'});write(dir,'dep.tgz',tarballs.get('/dep-1.0.0.tgz'));},{auth:true});
for(const [name,args] of [['registry-version',['pack','dep@1.0.0']],['registry-range-json',['pack','dep@^1','--json']],['registry-dry-run',['pack','dep@1.1.0','--dry-run']],['tarball-file',['pack','./dep.tgz']]])add(`pack-spec-${name}`,'pack',args,dir=>{manifest(dir);write(dir,'dep.tgz',tarballs.get('/dep-2.0.0.tgz'));});
add('json-error-ci-no-lock','ci',['ci','--json']);
add('json-error-invalid-manifest','install',['install','--json'],dir=>write(dir,'package.json','{"name":'));
add('json-error-missing-script','run',['run','nope','--json']);
add('ci-no-lock','ci',['ci']);
const engineDep=dir=>{manifest(dir,{dependencies:{'engine-dep':'file:./engine-dep'}});manifest(path.join(dir,'engine-dep'),{name:'engine-dep',version:'1.0.0',engines:{node:'>=99.0.0'}});};
add('engines-warn','install',['install'],engineDep);
add('engines-strict','install',['install','--engine-strict'],engineDep);
add('engines-strict-force','install',['install','--engine-strict','--force'],engineDep);
const failingDep=dir=>{manifest(dir,{dependencies:{'failing-dep':'file:./failing-dep'}});manifest(path.join(dir,'failing-dep'),{name:'failing-dep',version:'1.0.0',scripts:{install:'node -e "console.log(\x27building\x27);process.exit(42)"'}});};
add('dependency-script-exit-code','install',['install'],failingDep);
add('version-flag','version',['--version']);
add('version-short-flag','version',['-v']);
add('lockfile-indent-one-line-manifest','install',['install','dep@1.0.0'],dir=>write(dir,'package.json','{"name":"readiness-case","version":"1.0.0"}'));
add('script-env-contract','run',['run','env'],dir=>manifest(dir,{scripts:{env:"node -e \"for(const k of ['npm_config_user_agent','npm_node_execpath','npm_config_local_prefix','npm_config_prefix','npm_config_global_prefix','npm_config_cache','npm_config_userconfig','npm_config_node_gyp','npm_config_npm_version'])console.log(k+'='+process.env[k])\"",child:'node -p 123',nested:"node -e \"process.exit(require('child_process').spawnSync(process.execPath,[process.env.npm_execpath,'run','child'],{stdio:'inherit'}).status)\""}}));
add('script-npm-execpath-node','run',['run','nested'],dir=>manifest(dir,{scripts:{child:'node -p 123',nested:"node -e \"process.exit(require('child_process').spawnSync(process.execPath,[process.env.npm_execpath,'run','child'],{stdio:'inherit'}).status)\""}}));
add('production-flag','install',['install','--production'],dir=>manifest(dir,{dependencies:{dep:'1.0.0'},devDependencies:{parent:'1.0.0'}}));
add('override-conflicts-direct','install',['install'],dir=>manifest(dir,{dependencies:{dep:'1.0.0'},overrides:{dep:'2.0.0'}}));
add('override-reference-ok','install',['install'],dir=>manifest(dir,{dependencies:{dep:'1.0.0',parent:'1.0.0'},overrides:{dep:'$dep'}}));
add('config-get-several','config',['config','get','fetch-retries','strict-ssl','save-prefix']);
for(const command of ['ci','install'])add(`lockfile-without-resolved-${command}`,command,[command],dir=>manifest(dir,{dependencies:{parent:'1.0.0'}}),{before:async ctx=>{const p=await ctx.exec(['install','--omit-lockfile-registry-resolved']);if(p.exit!==0)throw new Error(p.stderr);fs.rmSync(path.join(ctx.dir,'node_modules'),{recursive:true,force:true});}});
add('command-diff','diff',['diff','--diff=dep@1.0.0','--diff=dep@1.1.0']);
for(const provider of ['github','gitlab','circleci']){
  const flags=provider==='circleci'?['--org-id',STAGE_ID,'--project-id',STAGE_ID,'--pipeline-definition-id',STAGE_ID,'--vcs-origin','github.com/mock/repo','--context-id',STAGE_ID]:['--file',provider==='github'?'publish.yml':'.gitlab-ci.yml',provider==='github'?'--repository':'--project','mock/repo','--environment','prod'];
  for(const [name,extra] of [['create',['--yes']],['create-json',['--yes','--json']],['dry-run',['--dry-run']]])add(`trust-create-${provider}-${name}`,'trust',['trust',provider,'dep',...flags,'--allow-publish','--allow-stage-publish',...extra],undefined,{auth:true});
}
for(const [name,args] of [['download',['download',STAGE_ID]],['download-json',['download',STAGE_ID,'--json']],['download-missing',['download']],['download-invalid',['download','nope']]])add(`stage-${name}`,'stage',['stage',...args],undefined,{auth:true});
for(const [name,flags] of [['publish',['--ignore-scripts']],['publish-json',['--ignore-scripts','--json']],['publish-dry-run',['--dry-run','--ignore-scripts']],['publish-dry-run-json',['--dry-run','--ignore-scripts','--json']]])add(`stage-${name}`,'stage',['stage','publish',...flags],undefined,{auth:true});
for(const command of ['install','ci','uninstall','update','outdated','audit','fund'])add(`populated-${command}`,command,command==='uninstall'?['uninstall','parent']:command==='outdated'||command==='audit'||command==='fund'?[command,'--json']:[command,'--ignore-scripts'],dir=>manifest(dir,{dependencies:{parent:'^1.0.0'}}),{before:async ctx=>{const p=await ctx.exec(['install','--ignore-scripts']);if(p.exit!==0)throw new Error(`Failed populated setup: ${p.stderr}`);}});
add('cache-add-registry','cache',['cache','add','dep@1.0.0']);
add('cache-list-populated','cache',['cache','ls'],dir=>manifest(dir),{before:async ctx=>{const p=await ctx.exec(['cache','add','dep@1.0.0']);if(p.exit!==0)throw new Error(`Cache seed failed: ${p.stderr}`);}});
const normalize=(str,dir,config)=>str.replaceAll(dir.replaceAll('\\','\\\\'),'<fixture>').replaceAll(dir,'<fixture>').replaceAll(dir.replaceAll('\\','/'),'<fixture>').replaceAll(config.replaceAll('\\','\\\\'),'<config>').replaceAll(config,'<config>').replaceAll(config.replaceAll('\\','/'),'<config>').replaceAll(registry,'<registry>/').replace(/\bin \d+(?:\.\d+)?(?:ms|s)\b/g,'in <time>').replace(/("time": )\d+/g,'$10').replace(/PONG \d+ms/g,'PONG <time>').replace(/\d{4}-\d\d-\d\dT\d\d_\d\d_\d\d_\d{3}Z-debug-\d+\.log/g,'<timestamp>-debug-0.log').replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,'<uuid>').replace(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z/g,'<iso-time>').replace(/^(npm@\d+\.\d+\.\d+) .+$/m,'$1 <npm-root>').replace(/\r\n/g,'\n');
function snapshot(dir,config){
  if(!fs.existsSync(dir))return {};
  const result={};const walk=current=>{for(const e of fs.readdirSync(current,{withFileTypes:true})){
    const p=path.join(current,e.name),rel=path.relative(dir,p).replaceAll('\\','/');
    if(e.isSymbolicLink())result[rel]={link:normalize(fs.readlinkSync(p),dir,config)};
    else if(e.isDirectory())walk(p);
    else if(rel.endsWith('.json')){try{result[rel]=JSON.parse(normalize(fs.readFileSync(p,'utf8'),dir,config));}catch{result[rel]=createHash('sha256').update(fs.readFileSync(p)).digest('hex');}}
    else result[rel]=createHash('sha256').update(fs.readFileSync(p)).digest('hex');
  }};walk(dir);return result;
}
const stable=v=>JSON.stringify(v,(_,value)=>value&&typeof value==='object'&&!Array.isArray(value)?Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b))):value);
const results=[];
try{
for(const c of cases){
  if(option('--case','')&&!c.name.includes(option('--case','')))continue;
  const result={name:c.name,command:c.command,args:c.args};
  for(const tool of ['npm','rnpm']){
    const dir=path.join(root,c.name,tool,'project'),config=path.join(root,'config',c.name,tool);fs.mkdirSync(dir,{recursive:true});write(config,'user.npmrc',c.auth==='basic'?`//127.0.0.1:${server.address().port}/:_auth=${Buffer.from('mock-user:mock-pass').toString('base64')}\n`:c.auth?`//127.0.0.1:${server.address().port}/:_authToken=mock-token\n`:'');write(config,'global.npmrc','');c.setup(dir);
    const env={...baseEnv,NPM_CONFIG_USERCONFIG:path.join(config,'user.npmrc'),NPM_CONFIG_GLOBALCONFIG:path.join(config,'global.npmrc'),NPM_CONFIG_PREFIX:path.join(config,'prefix'),NPM_CONFIG_CACHE:path.join(config,'cache'),RNPM_STORE_DIR:path.join(config,'store'),NPM_CONFIG_REGISTRY:registry,NPM_CONFIG_UPDATE_NOTIFIER:'false',NPM_CONFIG_AUDIT:'false',NPM_CONFIG_FUND:'false',NO_COLOR:'1',NPM_CONFIG_UNICODE:'true'};
    const exec=async args=>{const p=await run(tool==='npm'?process.execPath:binary,tool==='npm'?[npmCli,...args]:args,dir,env,c.input);return p;};
    if(c.before)await c.before({dir,env,exec});
    authScenario=c.authScenario||'';authPolls=0;
    const start=requests.length;const p=await exec(c.args);
    write(path.join(root,'logs'),`${c.name}-${tool}.stdout`,p.stdout);write(path.join(root,'logs'),`${c.name}-${tool}.stderr`,p.stderr);
    const files=snapshot(dir,config);
    files['<userconfig>']=fs.existsSync(path.join(config,'user.npmrc'))?normalize(fs.readFileSync(path.join(config,'user.npmrc'),'utf8'),dir,config):null;
    if(c.command==='link')files['<global-prefix>']=JSON.parse(normalize(JSON.stringify(snapshot(path.join(config,'prefix'),config)),dir,config));
    result[tool]={exit:p.exit,execution_error:p.error,stdout:normalize(p.stdout,dir,config),stderr:normalize(p.stderr,dir,config),files,requests:requests.slice(start)};
  }
  const a=result.npm,b=result.rnpm;
  const mutations=tool=>tool.requests.filter(r=>['PUT','DELETE','POST'].includes(r.method)).map(({method,url,body})=>({method,url,body:body&&typeof body==='object'&&/^org\.couchdb\.user:/.test(body._id)&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(body.date)?{...body,date:'<timestamp>'}:body}));
  result.comparison={execution:!a.execution_error&&!b.execution_error&&a.exit!==null&&b.exit!==null,exit:a.exit===b.exit,stdout:a.stdout===b.stdout,stderr:a.stderr===b.stderr,files:stable(a.files)===stable(b.files),mutations:stable(mutations(a))===stable(mutations(b))};
  result.match=Object.values(result.comparison).every(Boolean);results.push(result);
  // Keep complete comparisons and raw logs without committing multi-megabyte
  // package patches into the report. Hash the full normalized stream first.
  for(const tool of ['npm','rnpm'])for(const stream of ['stdout','stderr']){
    const value=result[tool][stream];result[tool][`${stream}_sha256`]=createHash('sha256').update(value).digest('hex');
    if(value.length>16000){result[tool][`${stream}_truncated`]=true;result[tool][stream]=value.slice(0,16000);}
  }
  console.log(`${result.match?'MATCH':'DIFF'} ${c.name} ${JSON.stringify(result.comparison)}`);
}
}catch(error){results.push({name:'harness-error',match:false,error:String(error.stack||error)});console.error(error);}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
const git=(...args)=>execFileSync('git',args,{cwd:repo,encoding:'utf8'}).trim();
const expectedCases=cases.filter(c=>!option('--case','')||c.name.includes(option('--case',''))).length;
write(path.dirname(output),path.basename(output),{head:git('rev-parse','HEAD'),binary_revision:option('--binary-revision',null),source_dirty:git('status','--porcelain','--untracked-files=no')!=='',binary_sha256:createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),node:process.version,npm:execFileSync(process.execPath,[npmCli,'--version'],{env:oracleEnv,encoding:'utf8'}).trim(),platform:process.platform,root,expected_cases:expectedCases,normalization:'Fixture/config paths (including JSON escaping), loopback registry origin, CRLF, elapsed summary/ping times, and diagnostic log timestamps. JSON file key order ignored; all fields retained. Full normalized stream hashes retained; streams over 16KB truncated in this report, with complete raw streams in root/logs. No stderr suppression.',results});
console.log(`Evidence: ${output}; ${results.filter(r=>r.match).length}/${results.length} match`);
process.exitCode=results.length>0&&results.length===expectedCases&&results.every(r=>r.match)?0:1;
