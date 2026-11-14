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
const tarballs=new Map(); const probePackages=new Map(); const probeCacheControl=new Map(); const requests=[]; let generation=1,authScenario='',authPolls=0,securityAdvisories={},securityRequireAuth=false;
const server=http.createServer((req,res)=>{
  const url=decodeURIComponent(req.url.split('?')[0]);
  const request={method:req.method,url,etag:req.headers['if-none-match'],headers:{'npm-command':req.headers['npm-command']??null,'npm-session':req.headers['npm-session']??null,'user-agent':req.headers['user-agent']??null}};requests.push(request);
  const chunks=[];req.on('data',b=>chunks.push(b));req.on('end',()=>{let body=Buffer.concat(chunks);if(req.headers['content-encoding']==='gzip')body=gunzipSync(body);if(body.length){try{request.body=JSON.parse(body.toString());}catch{request.body=body.toString();}}});
  const json=(data,status=200)=>{res.writeHead(status,{'content-type':'application/json','cache-control':probeCacheControl.get(url.slice(1))||'max-age=0','etag':`"generation-${generation}"`});res.end(JSON.stringify(data));};
  if(tarballs.has(url)){res.writeHead(200,{'content-type':'application/octet-stream'});res.end(tarballs.get(url));return;}
  if(url===`/-/stage/${STAGE_ID}/tarball`){res.writeHead(200,{'content-type':'application/octet-stream'});res.end(tarballs.get('/dep-1.0.0.tgz'));return;}
  if(url==='/network-reset')return req.socket.destroy();
  if(url==='/network-timeout')return;
  if(url==='/-/ping')return json({});
  if(url.includes('/security/advisories/bulk'))return json(securityAdvisories);
  if(url.includes('/security/audits/quick'))return json({actions:[],advisories:{},metadata:{vulnerabilities:{info:0,low:0,moderate:0,high:0,critical:0},dependencies:0,devDependencies:0,optionalDependencies:0,totalDependencies:0}});
  if(url==='/-/whoami')return json({username:'mock-user'});
  if(url==='/oidc/id-token')return json({value:'mock-id-token'});
  if(url.startsWith('/-/npm/v1/oidc/token/exchange/package/'))return json({token:'mock-exchanged-token'});
  if(authScenario.startsWith('mutation-otp')&&['PUT','POST','DELETE'].includes(req.method)&&!url.includes('/security/')&&req.headers['npm-otp']!=='123456'){res.writeHead(401,{'content-type':'application/json','www-authenticate':'OTP'});res.end(JSON.stringify({error:'one-time pass required',authUrl:`${registry}auth/login`,doneUrl:`${registry}auth/done`}));return;}
  if(url==='/-/v1/login')return authScenario==='web'?json({loginUrl:`${registry}auth/login`,doneUrl:`${registry}auth/done`}):json({error:'Mock registry does not provide browser login'},400);
  if(url==='/auth/done'){if(authPolls++===0){res.setHeader('retry-after','0.01');return json({},202);}return json({token:'mock-login-token'});}
  if(url.startsWith('/-/user/org.couchdb.user:')&&req.method==='PUT')return json({token:'mock-login-token'});
  if(url==='/-/user/org.couchdb.user:mock-user'&&req.method==='GET')return json({name:'mock-user',email:'mock@example.invalid'});
  if(url==='/-/user/org.couchdb.user:new-user'&&req.method==='GET')return json({name:'new-user',email:'new@example.invalid',extra:'dropped'});
  if(url.endsWith('/trust')&&req.method==='POST'){req.on('end',()=>json(request.body.map((item,i)=>({id:`created-${i+1}`,...item}))));return;}
  if(url.startsWith('/-/stage/package/')&&req.method==='POST')return json({stageId:STAGE_ID});
  if((req.method==='PUT'&&url==='/otp-pkg')||(url==='/-/package/otp-pkg/dist-tags/beta'))if(req.headers['npm-otp']!=='123456'){res.writeHead(401,{'content-type':'application/json','www-authenticate':'OTP'});res.end(JSON.stringify({error:'one-time pass required'}));return;}
  if(req.method==='PUT'&&url==='/denied-pkg'){res.writeHead(401,{'content-type':'application/json'});res.end(JSON.stringify({error:'invalid token'}));return;}
  if(url==='/-/package/bearer-pkg/dist-tags/beta'){res.writeHead(401,{'content-type':'application/json','www-authenticate':'Bearer realm="mock"'});res.end(JSON.stringify({error:'bad token'}));return;}
  if(url==='/-/package/heuristic-pkg/dist-tags/beta'){res.writeHead(401,{'content-type':'application/json'});res.end(JSON.stringify({error:'one-time pass required'}));return;}
  if(req.method==='PUT'&&url==='/rejected-pkg')return json({error:'You do not have permission to publish "rejected-pkg"'},403);
  if(req.method==='PUT'||req.method==='DELETE'||req.method==='POST')return json({ok:true});
  if(url==='/-/user/mock-user/package')return json({});
  if(url==='/-/org/mock-org/user')return json({'mock-user':'developer'});
  if(url==='/-/org/mock-org/team')return json([]);
  if(url==='/-/npm/v1/user')return json({name:'mock-user',email:'mock@example.invalid',tfa:false});
  if(url==='/-/npm/v1/tokens')return json({objects:authScenario==='mutation-otp-valid-token'?[{key:'mock-key',token:'mock-token',created:'2026-11-13T00:00:00.000Z'}]:[],total:authScenario==='mutation-otp-valid-token'?1:0,urls:{}});
  if(url==='/-/_view/starredByUser')return json({rows:[]});
  const stageItem={id:STAGE_ID,packageName:'dep',version:'1.2.0',status:'pending',tag:'latest',createdAt:'2026-11-13T00:00:00.000Z',actor:'mock-user',actorType:'user',shasum:'0123456789abcdef',extra:'kept'};
  if(url==='/-/stage'){const pkg=new URL(req.url,'http://x').searchParams.get('package');return json(pkg==='empty-pkg'?{items:[],total:0}:{items:[stageItem],total:1});}
  if(url===`/-/stage/${STAGE_ID}`)return json(stageItem);
  if(url==='/-/package/dep/trust')return json([{id:'trust-1',type:'github',claims:{repository:'mock/repo',workflow_ref:{file:'publish.yml'},environment:'prod'},permissions:['createPackage','createStagedPackage']},{id:'trust-2',type:'gitlab',claims:{project_path:'group/proj',ci_config_ref_uri:{file:'.gitlab-ci.yml'}},permissions:['createPackage']}]);
  if(url.endsWith('/trust'))return json([]);
  if(url.includes('/stages')||url.includes('/trusted-publishers'))return json([]);
  if(url==='/-/v1/search')return json({objects:[],total:0,time:'2026-11-13T00:00:00.000Z'});
  if(url==='/-/package/tags-pkg/dist-tags')return json({latest:'1.0.0',beta:'2.0.0-beta.1',alpha:'0.1.0',_etag:'W/"x"'});
  if(url.startsWith('/-/package/')&&url.endsWith('/visibility'))return json({public:url.includes('@auth/')});
  if(url==='/-/package/dep/collaborators')return json({'mock-user':'write','z-reader':'read','a-admin':'admin'});
  if(url==='/-/package/missing-tags/dist-tags')return json({error:'Not found'},404);
  if(url==='/-/package/empty-tags/dist-tags')return json({});
  if(url.startsWith('/-/package/')&&url.endsWith('/dist-tags'))return json({latest:'1.0.0'});
  const name=url.slice(1);
  if(securityRequireAuth&&['audit-leaf','audit-branch'].includes(name)&&req.headers.authorization!=='Bearer mock-token')return json({error:'Authentication required'},401);
  if(['audit-leaf','audit-branch'].includes(name))return json({name,'dist-tags':{latest:'2.0.0'},versions:Object.fromEntries(['1.0.0','1.1.0','2.0.0'].map(version=>[version,{name,version,...(name==='audit-branch'?{dependencies:{'audit-leaf':version==='2.0.0'?'^2.0.0':'^1.0.0'}}:{})}]))});
  if(probePackages.has(name)){
    const metadata=probePackages.get(name);
    if(name==='metadata-probe'&&req.headers.accept?.includes('install-v1'))return json({...metadata,versions:Object.fromEntries(Object.entries(metadata.versions).map(([v,m])=>{const {license,...abbreviated}=m;return [v,abbreviated];}))});
    return json(metadata);
  }
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
// CLI/auth lane fixtures: real registry tarballs, with observable executable output.
for(const [name,bin] of [['create-argv','create-argv'],['@argv/create','scoped-create'],['argv-tool','argv-tool'],['second-tool','second-tool']]){
  const dir=path.join(root,'bin-tarballs',name.replaceAll('/','-'));
  manifest(dir,{name,version:'1.0.0',bin:{[bin]:'bin.cjs'}});
  write(dir,'bin.cjs',`#!/usr/bin/env node\nrequire('fs').writeFileSync('${bin}.json',JSON.stringify(process.argv.slice(2)));\n`);
  const packed=await run(process.execPath,[npmCli,'pack','--ignore-scripts','--silent'],dir,oracleEnv);
  if(packed.exit!==0)throw new Error(packed.stderr);
  const filename=packed.stdout.trim();tarballs.set('/'+filename,fs.readFileSync(path.join(dir,filename)));
  probePackages.set(name,{name,'dist-tags':{latest:'1.0.0'},versions:{'1.0.0':{name,version:'1.0.0',bin:{[bin]:'bin.cjs'},dist:{tarball:registry+filename}}}});
}
for(const [name,args]of [
  ['init-forward',['init','-y','argv','--','hello','--flag','two words']],
  ['create-forward',['create','-y','argv','--','hello','--flag']],
  ['init-version',['init','-y','argv@1.0.0','--','versioned']],
  ['init-scope',['init','-y','@argv','--','scoped']],
  ['init-yes-after',['init','argv','-y','--','hello']],
  ['exec-yes',['exec','--yes','argv-tool','--','hello','two words']],
  ['exec-call-package',['exec','--yes','-c','argv-tool hello','--package','argv-tool']],
  ['exec-call-multiple',['exec','--yes','--package','argv-tool','--package','second-tool','-c','argv-tool first && second-tool second']],
  ['exec-call-env',['exec','--yes','-c','node env.cjs','--package','argv-tool','--save-exact']],
])add(`f1-${name}`,args[0],args,dir=>{manifest(dir);if(name==='exec-call-env')write(dir,'env.cjs',`require('fs').writeFileSync('env.json',JSON.stringify(Object.fromEntries(['npm_command','npm_lifecycle_event','npm_config_registry','npm_config_save_exact','npm_config_yes'].map(k=>[k,process.env[k]??null]))));\n`);});
for(const [name,fields]of [['missing-name',{name:undefined}],['missing-version',{version:undefined}],['invalid-version',{version:'banana'}],['private',{private:true}],['publish-config',{publishConfig:{tag:'next',access:'public'}}]])add(`f1-publish-${name}`,'publish',['publish','--ignore-scripts'],dir=>manifest(dir,{name:'validation-pkg',...fields}),{auth:true});
add('f1-publish-range-tag','publish',['publish','--tag','^1','--ignore-scripts'],dir=>manifest(dir,{name:'tag-pkg'}),{auth:true});
add('f1-publish-provenance-config','publish',['publish','--access','public','--ignore-scripts'],dir=>{manifest(dir,{name:'prov-config-pkg'});write(dir,'.npmrc','provenance=true\n');},{auth:true});
for(const command of ['publish','stage'])for(const [name,spec]of [['registry','dep@1.0.0'],['url',`${registry}dep-1.0.0.tgz`]])add(`f1-${command}-remote-${name}`,command,[command,...(command==='stage'?['publish']:[]),spec,'--force','--ignore-scripts'],undefined,{auth:true});
for(const provider of ['github','gitlab'])add(`f1-publish-oidc-${provider}`,'publish',['publish','--provenance=false','--ignore-scripts'],dir=>manifest(dir,{name:'oidc-pkg'}),{env:provider==='github'?{GITHUB_ACTIONS:'true',ACTIONS_ID_TOKEN_REQUEST_URL:`${registry}oidc/id-token`,ACTIONS_ID_TOKEN_REQUEST_TOKEN:'mock-request-token'}:{GITLAB_CI:'true',NPM_ID_TOKEN:'mock-id-token'},observe:ctx=>ctx.requests.filter(r=>r.url.includes('oidc')).map(r=>({method:r.method,url:r.url,body:r.body}))});
for(const [name,args]of [['publish',['publish','--ignore-scripts']],['dist-tag',['dist-tag','add','dep@1.0.0','beta']],['access',['access','set','status=public','dep']],['owner',['owner','add','other-user','dep']],['deprecate',['deprecate','dep@1.0.0','old']],['unpublish',['unpublish','dep@1.0.0','--force']],['token',['token','revoke','mock-id']],['profile',['profile','set','fullname','Mock User']]])add(`f1-otp-nontty-${name}`,args[0],args,dir=>manifest(dir,{name:'challenge-pkg'}),{auth:true,authScenario:'mutation-otp'});
for(const [name,args,scenario]of [['access-scoped',['access','set','status=public','@auth/pkg'],'mutation-otp'],['owner-user',['owner','add','mock-user','parent'],'mutation-otp'],['token-valid',['token','revoke','mock-key'],'mutation-otp-valid-token']])add(`f1-otp-nontty-${name}`,args[0],args,undefined,{auth:true,authScenario:scenario});
// npm owner/access protocol: user lookup + packument maintainers PUT, libnpmaccess endpoints.
for(const [name,args,scenario]of [['owner-add-new',['owner','add','new-user','dep']],['owner-add-existing',['owner','add','mock-user','dep']],['owner-rm-last',['owner','rm','mock-user','dep']],['owner-rm-absent',['owner','rm','new-user','dep']],['owner-add-missing-user',['owner','add','ghost-user','dep']],['owner-add-missing-pkg',['owner','add','new-user','missing-pkg']],['owner-add-new-otp',['owner','add','new-user','dep'],'mutation-otp'],['owner-add-manifest',['owner','add','new-user']]])add('f1-'+name,'owner',args,dir=>manifest(dir,{name:'dep'}),{auth:true,...(scenario?{authScenario:scenario}:{})});
for(const [name,args,scenario]of [['get-status-scoped',['access','get','status','@auth/pkg']],['get-status-json',['access','get','status','dep','--json']],['set-private',['access','set','status=private','@auth/pkg']],['set-public-json',['access','set','status=public','@auth/pkg','--json']],['collaborators',['access','list','collaborators','dep']],['collaborators-json',['access','list','collaborators','dep','--json']],['collaborators-limit',['access','list','collaborators','dep','z-reader']],['mfa-publish',['access','set','mfa=publish','dep']],['mfa-automation-otp',['access','set','2fa=automation','dep'],'mutation-otp'],['grant',['access','grant','read-only','@mock-org:dev','dep']],['grant-bad-perm',['access','grant','admin','@mock-org:dev','dep']],['grant-no-team',['access','grant','read-write']],['revoke',['access','revoke','@mock-org:dev','dep']],['bad-command',['access','bogus','x']],['bad-set',['access','set','status=hidden','dep']],['bad-get',['access','get','visibility','dep']],['missing-sub',['access','list']],['list-packages-self',['access','list','packages']],['status-manifest',['access','get','status']]])add('f1-access-'+name,'access',args,dir=>manifest(dir,{name:'dep'}),{auth:true,...(scenario?{authScenario:scenario}:{})});
for(const command of ['login','adduser'])add(`f1-${command}-saved-defaults`,command,[command,'--auth-type=legacy'],undefined,{userconfig:`//127.0.0.1:${server.address().port}/:username=mock-user\n//127.0.0.1:${server.address().port}/:_password=${Buffer.from('mock-password').toString('base64')}\n//127.0.0.1:${server.address().port}/:email=mock@example.invalid\n`,input:[{prompt:'Username:',value:''},{prompt:'Password:',value:''},...(command==='adduser'?[{prompt:'Email (this will be public):',value:''}]:[])]});
for(const [name,flags]of [['global',['-g']],['workspace',['-w','a']],['workspaces',['--workspaces']]])for(const [format,flags2]of [['long',['--long']],['json-long',['--json','--long']],['parseable',['--parseable']],['parseable-long',['--parseable','--long']]])add(`f1-outdated-${name}-${format}`,'outdated',['outdated',...flags,...flags2],dir=>{
  manifest(dir,{workspaces:['modules/*']});
  for(const [member,dep]of [['a','dep'],['b','parent']])manifest(path.join(dir,'modules',member),{name:member,dependencies:{[dep]:'^1.0.0'}});
  for(const dep of ['dep','parent'])manifest(path.join(dir,'node_modules',dep),{name:dep});
},{before:async ctx=>{if(name==='global')manifest(path.join(ctx.env.NPM_CONFIG_PREFIX,'node_modules/dep'),{name:'dep'});}});
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
add('flags-dev-optional-overlap','install',['install'],dir=>manifest(dir,{optionalDependencies:{parent:'1.0.0'},devDependencies:{dep:'1.1.0'}}));
add('flags-dev-and-prod-overlap','install',['install'],dir=>manifest(dir,{dependencies:{parent:'1.0.0'},devDependencies:{dep:'1.1.0'}}));
add('flags-omit-dev-keeps-dev-optional','install',['install','--omit=dev'],dir=>manifest(dir,{optionalDependencies:{parent:'1.0.0'},devDependencies:{dep:'1.1.0'}}));
add('flags-ci-omit-dev-keeps-dev-optional','ci',['ci','--omit=dev'],dir=>manifest(dir,{optionalDependencies:{parent:'1.0.0'},devDependencies:{dep:'1.1.0'}}),{before:async ctx=>{const p=await ctx.exec(['install']);if(p.exit!==0)throw new Error(p.stderr);fs.rmSync(path.join(ctx.dir,'node_modules'),{recursive:true,force:true});}});
// Read-only CLI lane: advisory propagation and top-level remediation.
const auditTree=dir=>{
  manifest(dir,{dependencies:{'audit-branch':'^1.0.0'}});
  write(dir,'package-lock.json',{name:'readiness-case',version:'1.0.0',lockfileVersion:3,requires:true,packages:{'':{name:'readiness-case',version:'1.0.0',dependencies:{'audit-branch':'^1.0.0'}},'node_modules/audit-branch':{version:'1.0.0',dependencies:{'audit-leaf':'^1.0.0'}},'node_modules/audit-leaf':{version:'1.0.0'}}});
};
for(const name of ['audit-top','audit-middle'])probePackages.set(name,{name,'dist-tags':{latest:'2.0.0'},versions:Object.fromEntries(['1.0.0','1.1.0','2.0.0'].map(version=>[version,{name,version,dependencies:{[name==='audit-top'?'audit-middle':'audit-branch']:version==='2.0.0'?'^2.0.0':'^1.0.0'}}]))});
for(const [name,args]of [['json',['audit','--json']],['text',['audit']],['fix-dry-json',['audit','fix','--dry-run','--json']],['fix-dry-text',['audit','fix','--dry-run']]])add(`f1-audit-chain-${name}`,'audit',args,dir=>{
  const packages={'':{name:'readiness-case',version:'1.0.0',dependencies:{'audit-top':'^1.0.0'}}};
  for(const [name,child]of [['audit-top','audit-middle'],['audit-middle','audit-branch'],['audit-branch','audit-leaf'],['audit-leaf',null]])packages['node_modules/'+name]={version:'1.0.0',...(child?{dependencies:{[child]:'^1.0.0'}}:{})};
  manifest(dir,{dependencies:{'audit-top':'^1.0.0'}});write(dir,'package-lock.json',{name:'readiness-case',version:'1.0.0',lockfileVersion:3,requires:true,packages});
},{advisories:{'audit-leaf':[{id:106,name:'audit-leaf',url:'https://example.invalid/advisory/106',title:'Deep chain advisory',severity:'high',vulnerable_versions:'<2.0.0',cwe:[],cvss:{score:7.5,vectorString:null}}]}});
probePackages.set('audit-bundler',{name:'audit-bundler','dist-tags':{latest:'2.0.0'},versions:Object.fromEntries(['1.0.0','1.1.0','2.0.0'].map(version=>[version,{name:'audit-bundler',version,dependencies:{'audit-leaf':version==='2.0.0'?'^2.0.0':'^1.0.0'},bundleDependencies:['audit-leaf']}]))});
for(const flags of [[],['--json']])add(`f1-audit-bundled${flags.length?'-json':''}`,'audit',['audit',...flags],dir=>{
  manifest(dir,{dependencies:{'audit-bundler':'^1.0.0'}});write(dir,'package-lock.json',{name:'readiness-case',version:'1.0.0',lockfileVersion:3,requires:true,packages:{'':{name:'readiness-case',version:'1.0.0',dependencies:{'audit-bundler':'^1.0.0'}},'node_modules/audit-bundler':{version:'1.0.0',dependencies:{'audit-leaf':'^1.0.0'},bundleDependencies:['audit-leaf']},'node_modules/audit-bundler/node_modules/audit-leaf':{version:'1.0.0',inBundle:true}}});
},{advisories:{'audit-leaf':[{id:107,name:'audit-leaf',url:'https://example.invalid/advisory/107',title:'Bundled advisory',severity:'high',vulnerable_versions:'<1.1.0',cwe:[],cvss:{score:7.5,vectorString:null}}]}});
for(const [name,range] of [['breaking','<2.0.0'],['in-range','<1.1.0'],['unfixable','*']])for(const flags of [[],['--json']])add(`cli-audit-${name}${flags.length?'-json':''}`,'audit',['audit',...flags],auditTree,{advisories:{'audit-leaf':[{id:101,name:'audit-leaf',url:'https://example.invalid/advisory/101',title:'Fixture advisory',severity:'moderate',vulnerable_versions:range,cwe:['CWE-400'],cvss:{score:5.3,vectorString:null}}]}});
for(const spec of ['1','>=1'])for(const fields of [['version'],['name','version']])for(const flags of [[],['--json']])add(`cli-view-${spec.replace('>=','gte-')}-${fields.join('-')}${flags.length?'-json':''}`,'view',['view',`dep@${spec}`,...fields,...flags]);
const fundingTree=dir=>{manifest(dir,{dependencies:{parent:'1.0.0',dep:'1.0.0'}});manifest(path.join(dir,'node_modules/parent'),{name:'parent',funding:[{type:'individual',url:'https://example.invalid/parent'},'https://example.invalid/other'],dependencies:{child:'1.0.0'}});manifest(path.join(dir,'node_modules/parent/node_modules/child'),{name:'child',funding:'https://example.invalid/child'});manifest(path.join(dir,'node_modules/dep'),{name:'dep',funding:'https://example.invalid/parent'});};
for(const flags of [[],['--json']])add(`cli-fund-tree${flags.length?'-json':''}`,'fund',['fund',...flags],fundingTree);
add('cli-fund-package','fund',['fund','dep','--browser=false'],fundingTree);
add('cli-fund-package-missing','fund',['fund','parent','--browser=false'],installed);

for(const [name,flags] of [['json',['--json']],['human',[]]])add(`cli-fund-normalize-${name}`,'fund',['fund',...flags],dir=>{
  manifest(dir,{funding:'https://example.invalid/root',dependencies:{parent:'1.0.0',dep:'1.0.0'}});
  manifest(path.join(dir,'node_modules/parent'),{name:'parent',funding:[{url:'ftp://invalid'},'https://example.invalid/partial'],dependencies:{child:'1.0.0'}});
  manifest(path.join(dir,'node_modules/parent/node_modules/child'),{name:'child',funding:{type:'individual',url:'https://example.invalid/child'}});
  manifest(path.join(dir,'node_modules/dep'),{name:'dep',funding:[]});
});
for(const which of ['1','2','9','0'])add(`cli-fund-which-${which}`,'fund',['fund','parent',`--which=${which}`,'--browser=false'],fundingTree);
const overrideTree=dir=>{manifest(dir,{dependencies:{parent:'1.0.0'},overrides:{parent:{dep:'2.0.0'}}});manifest(path.join(dir,'node_modules/parent'),{name:'parent',dependencies:{dep:'^1.0.0'}});manifest(path.join(dir,'node_modules/dep'),{name:'dep',version:'2.0.0'});};
for(const flags of [[],['--json']])add(`cli-ls-nested-override${flags.length?'-json':''}`,'ls',['ls','--all',...flags],overrideTree);
for(const flags of [[],['--json']])add(`cli-explain-nested-override${flags.length?'-json':''}`,'explain',['explain','dep',...flags],overrideTree);

const cliWorkspaceTree=dir=>{
  manifest(dir,{workspaces:['modules/*']});
  manifest(path.join(dir,'modules/a'),{name:'a',dependencies:{dep:'^1.0.0'},private:true});
  manifest(path.join(dir,'modules/b'),{name:'b',dependencies:{parent:'^1.0.0'}});
  manifest(path.join(dir,'node_modules/dep'),{name:'dep'});
  manifest(path.join(dir,'node_modules/parent'),{name:'parent'});
  for(const name of ['a','b'])fs.symlinkSync(path.join(dir,'modules',name),path.join(dir,'node_modules',name),'junction');
};
for(const [name,args] of [['workspace',['ls','-w','a']],['workspace-json',['ls','-w','a','--json']],['global',['ls','-g']]])add(`cli-ls-${name}`,'ls',args,cliWorkspaceTree,{before:async ctx=>{if(args.includes('-g'))manifest(path.join(ctx.env.NPM_CONFIG_PREFIX,'node_modules/dep'),{name:'dep'});}});
for(const [name,args] of [['workspace',['outdated','-w','a']],['workspace-json',['outdated','-w','a','--json']],['global',['outdated','-g']],['global-json',['outdated','-g','--json']]])add(`cli-outdated-${name}`,'outdated',args,cliWorkspaceTree,{before:async ctx=>{if(args.includes('-g'))manifest(path.join(ctx.env.NPM_CONFIG_PREFIX,'node_modules/dep'),{name:'dep'});}});
for(const [name,selector] of [['workspace','.workspace'],['private',':private'],['is',':is(.workspace, #dep)'],['attribute','[name|=readiness]'],['array','[keywords~=tool]']])add(`cli-query-${name}`,'query',['query',selector],dir=>{cliWorkspaceTree(dir);edit(path.join(dir,'node_modules/dep'),p=>{p.keywords=['build','tool'];});});
for(const [name,flags] of [['list',[]],['json',['--json']],['long',['-l']]])add(`cli-config-${name}`,'config',['config','list',...flags],dir=>{manifest(dir);write(dir,'.npmrc','save-prefix=~\n');});

for(const flags of [[],['--json'],['--silent']])add(`cli-audit-fix-unfixable${flags.join('')}`,'audit',['audit','fix',...flags],dir=>manifest(dir,{dependencies:{dep:'^1.0.0'}}),{before:async ctx=>{securityAdvisories={};const result=await ctx.exec(['install','--ignore-scripts']);if(result.exit!==0)throw new Error(result.stderr);},advisories:{dep:[{id:102,name:'dep',url:'https://example.invalid/advisory/102',title:'No patched release',severity:'high',vulnerable_versions:'*',cwe:[],cvss:{score:7.5,vectorString:null}}]}});

for(const flags of [[],['--json']])add(`cli-audit-multiple-severities${flags.join('')}`,'audit',['audit',...flags],auditTree,{advisories:{'audit-leaf':['low','high'].map((severity,i)=>({id:103+i,name:'audit-leaf',url: 'https://example.invalid/advisory/'+(103+i),title:severity+' advisory',severity,vulnerable_versions:'<2.0.0',cwe:[],cvss:{score:i?7.5:3,vectorString:null}}))}});
for(const flags of [[],['--json']])add(`cli-audit-authenticated${flags.join('')}`,'audit',['audit',...flags],auditTree,{auth:true,advisoryAuth:true,advisories:{'audit-leaf':[{id:105,name:'audit-leaf',url:'https://example.invalid/advisory/105',title:'Authenticated advisory',severity:'high',vulnerable_versions:'<2.0.0',cwe:[],cvss:{score:7.5,vectorString:null}}]}});
add('cli-query-workspace-with-file-link','query',['query','.workspace'],dir=>{cliWorkspaceTree(dir);edit(dir,p=>{p.dependencies={local:'file:./local'};});manifest(path.join(dir,'local'),{name:'local'});fs.symlinkSync(path.join(dir,'local'),path.join(dir,'node_modules/local'),'junction');});
// Small registry graphs isolate Arborist's placement order from network state.
for(const [name,versions] of Object.entries({
  branch:{'1.0.0':{dependencies:{'alpha-parent':'1.0.0',shared:'2.0.0'}}},
  'alpha-parent':{'1.0.0':{dependencies:{shared:'1.0.0'}}},
  'a-dev':{'1.0.0':{dependencies:{shared:'1.0.0'}}},
  'z-prod':{'1.0.0':{dependencies:{shared:'2.0.0'}}},
  shared:{'1.0.0':{},'2.0.0':{}},
  'metadata-probe':{'1.0.0':{license:'MIT',funding:'https://example.invalid/funding'}},
  'fresh-packument':{'1.0.0':{}},
  'historic-metadata':{'1.0.0':{deprecated:false,license:{type:'MIT'},bundleDependencies:[],bundledDependencies:[],scripts:{postinstall:'node -p 123'}}},
  'bundle-owner':{'1.0.0':{dependencies:{'bundled-leaf':'1.0.0'},bundleDependencies:['bundled-leaf']}},
  'peer-entry':{'1.0.0':{peerDependencies:{'peer-parent':'1.0.0'}}},
  'peer-parent':{'1.0.0':{dependencies:{shared:'1.0.0'}}},
  'z-peer-entry':{'1.0.0':{peerDependencies:{'a-peer-parent':'1.0.0'}}},
  'a-peer-parent':{'1.0.0':{dependencies:{shared:'1.0.0'}}},
  'b-regular':{'1.0.0':{dependencies:{shared:'2.0.0'}}},
  'b-mid':{'1.0.0':{dependencies:{'c-old':'2.0.0','d-new':'2.0.0'}},'2.0.0':{dependencies:{'c-old':'3.0.0','d-new':'2.0.0'}}},
  'c-old':{'1.0.0':{},'2.0.0':{dependencies:{shared:'^1.0.0'}},'3.0.0':{dependencies:{'z-passive':'2.0.0'}}},
  'd-new':{'1.0.0':{},'2.0.0':{dependencies:{shared:'^2.0.0'}}},
  'z-passive':{'1.0.0':{},'2.0.0':{dependencies:{shared:'^1.0.0'}}},
  'optional-peer-owner':{'1.0.0':{dependencies:{'peer-consumer':'1.0.0'},peerDependencies:{shared:'^1.0.0'},peerDependenciesMeta:{shared:{optional:true}}}},
  'peer-consumer':{'1.0.0':{peerDependencies:{shared:'*'}}},
  'legacy-engines':{'1.0.0':{engines:['node >= 0.8.0']}},
  'z-peer-source':{'1.0.0':{dependencies:{'a-peer-plugin':'1.0.0',shared:'2.0.0'}}},
  'a-peer-plugin':{'1.0.0':{peerDependencies:{shared:'^2.0.0'}}},
  'z-normal-peer-owner':{'1.0.0':{dependencies:{'a-broad-peer-plugin':'1.0.0',shared:'1.0.0'}}},
  'a-broad-peer-plugin':{'1.0.0':{peerDependencies:{shared:'*'}}},
  'nested-optional-owner':{'1.0.0':{dependencies:{'nested-optional-plugin':'1.0.0'}}},
  'nested-optional-plugin':{'1.0.0':{peerDependencies:{shared:'^2.0.0'},peerDependenciesMeta:{shared:{optional:true}}}},
})){
  const packed={};
  for(const [version,fields]of Object.entries(versions)){
    const dir=path.join(root,'tarballs',`${name}-${version}`);manifest(dir,{name,version,...fields});write(dir,'index.js','module.exports = 1;\n');
    if(name==='bundle-owner'){
      manifest(path.join(dir,'node_modules/bundled-leaf'),{name:'bundled-leaf',license:'MIT',dependencies:{'bundled-transitive':'1.0.0'}});
      manifest(path.join(dir,'node_modules/bundled-leaf/node_modules/bundled-transitive'),{name:'bundled-transitive',license:'ISC'});
    }
    const p=await run(process.execPath,[npmCli,'pack','--ignore-scripts','--silent'],dir,oracleEnv);if(p.exit!==0)throw new Error(p.stderr);
    const bytes=fs.readFileSync(path.join(dir,`${name}-${version}.tgz`));tarballs.set(`/${name}-${version}.tgz`,bytes);
    packed[version]={name,version,...fields,dist:{tarball:`${registry}${name}-${version}.tgz`,integrity:'sha512-'+createHash('sha512').update(bytes).digest('base64')}};
  }
  probePackages.set(name,{name,'dist-tags':{latest:Object.keys(versions).at(-1)},versions:packed});
}
add('resolver-places-parent-edges-together','install',['install','--ignore-scripts'],dir=>manifest(dir,{dependencies:{branch:'1.0.0'}}));
add('resolver-depth-path-before-dev-class','install',['install','--ignore-scripts'],dir=>manifest(dir,{dependencies:{'z-prod':'1.0.0'},devDependencies:{'a-dev':'1.0.0'}}));
add('resolver-peer-flags-reach-transitives','install',['install','--ignore-scripts'],dir=>manifest(dir,{dependencies:{'peer-entry':'1.0.0'}}));
add('resolver-places-peer-set-before-expansion','install',['install','--ignore-scripts'],dir=>manifest(dir,{dependencies:{'b-regular':'1.0.0','z-peer-entry':'1.0.0'}}));
add('resolver-nesting-preserves-descendant-resolution','install',['install','--ignore-scripts'],dir=>manifest(dir,{dependencies:{'b-mid':'1.0.0','c-old':'1.0.0','d-new':'1.0.0',shared:'1.0.0'}}));
add('resolver-peer-set-uses-parent-advisory','install',['install','--ignore-scripts'],dir=>manifest(dir,{dependencies:{'optional-peer-owner':'1.0.0'}}));
add('resolver-peer-set-waits-for-sibling-provider','install',['install','--ignore-scripts'],dir=>manifest(dir,{dependencies:{shared:'1.0.0','z-peer-source':'1.0.0'}}));
add('install-preserves-legacy-engines-lock-only','install',['install','--ignore-scripts','--package-lock-only'],dir=>manifest(dir,{dependencies:{'legacy-engines':'1.0.0'}}));
add('install-full-packument-metadata-lock-only','install',['install','--ignore-scripts','--package-lock-only'],dir=>manifest(dir,{dependencies:{'metadata-probe':'1.0.0'}}));
add('install-normalizes-historical-full-metadata','install',['install','--ignore-scripts','--package-lock-only'],dir=>manifest(dir,{dependencies:{'historic-metadata':'1.0.0'}}));
for(const flags of [[],['--package-lock-only']])add(`install-bundled-lock-entries${flags.length?'-lock-only':''}`,'install',['install','--ignore-scripts',...flags],dir=>manifest(dir,{devDependencies:{'bundle-owner':'1.0.0'}}));
add('ci-bundled-lock-entries','ci',['ci','--ignore-scripts'],dir=>manifest(dir,{devDependencies:{'bundle-owner':'1.0.0'}}),{before:async ctx=>{const p=await ctx.exec(['install','--ignore-scripts']);if(p.exit!==0)throw new Error(p.stderr);fs.rmSync(path.join(ctx.dir,'node_modules'),{recursive:true,force:true});}});
probeCacheControl.set('fresh-packument','public, max-age=300');
add('cache-fresh-packument-skips-revalidation','install',['install','--ignore-scripts'],dir=>manifest(dir,{dependencies:{'fresh-packument':'1.0.0'}}),{before:async ctx=>{const p=await ctx.exec(['install','--ignore-scripts']);if(p.exit!==0)throw new Error(p.stderr);for(const name of ['package-lock.json','node_modules'])fs.rmSync(path.join(ctx.dir,name),{recursive:true,force:true});},observe:({requests})=>({packumentRequests:requests.filter(r=>r.method==='GET'&&r.url==='/fresh-packument').length})});
add('cache-clean-removes-install-store','cache',['cache','clean','--force'],dir=>manifest(dir,{dependencies:{dep:'1.0.0'}}),{before:async ctx=>{const p=await ctx.exec(['install','--ignore-scripts']);if(p.exit!==0)throw new Error(p.stderr);},observe:({env})=>({storeExists:fs.existsSync(env.RNPM_STORE_DIR)})});
for(const [name,args]of [['install',['install','dep@1.0.0','--ignore-scripts']],['alias',['i','dep@1.0.0','--ignore-scripts']],['view',['view','dep@1.0.0','version']],['ping',['ping','--json']],['custom-agent',['install','dep@1.0.0','--ignore-scripts','--user-agent=parity-probe/1.0']]])add(`registry-request-headers-${name}`,args[0],args,undefined,{observe:({requests})=>requests.filter(r=>r.method==='GET').map(({url,headers})=>({url,headers})).sort((a,b)=>a.url.localeCompare(b.url))});
add('publish-otp-required','publish',['publish','--ignore-scripts'],dir=>{manifest(dir,{name:'otp-pkg'});write(dir,'index.js','1\n');},{auth:true});
add('publish-otp-supplied','publish',['publish','--ignore-scripts','--otp','123456'],dir=>{manifest(dir,{name:'otp-pkg'});write(dir,'index.js','1\n');},{auth:true});
add('publish-otp-required-json','publish',['publish','--ignore-scripts','--json'],dir=>{manifest(dir,{name:'otp-pkg'});write(dir,'index.js','1\n');},{auth:true});
add('publish-401-invalid-token','publish',['publish','--ignore-scripts'],dir=>{manifest(dir,{name:'denied-pkg'});write(dir,'index.js','1\n');},{auth:true});
add('dist-tag-otp-required','dist-tag',['dist-tag','add','otp-pkg@1.0.0','beta'],dir=>manifest(dir,{name:'root'}),{auth:true});
add('dist-tag-otp-supplied','dist-tag',['dist-tag','add','otp-pkg@1.0.0','beta','--otp=123456'],dir=>manifest(dir,{name:'root'}),{auth:true});
add('dist-tag-ls-sorted','dist-tag',['dist-tag','ls','tags-pkg'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-bare-name-lists','dist-tag',['dist-tag','tags-pkg'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-ls-from-manifest','dist-tag',['dist-tag','ls'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-ls-json','dist-tag',['dist-tag','ls','tags-pkg','--json'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-ls-missing','dist-tag',['dist-tag','ls','missing-tags'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-ls-empty','dist-tag',['dist-tag','ls','empty-tags'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-add-already-set','dist-tag',['dist-tag','add','tags-pkg@1.0.0','latest'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-add-range-tag','dist-tag',['dist-tag','add','tags-pkg@1.0.0','^1'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-add-no-version','dist-tag',['dist-tag','add','tags-pkg'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-add-default-tag','dist-tag',['dist-tag','add','tags-pkg@1.1.0','--tag','next'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-set-alias','dist-tag',['dist-tag','set','tags-pkg@1.1.0','next'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-rm','dist-tag',['dist-tag','rm','tags-pkg','beta'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-rm-missing-tag','dist-tag',['dist-tag','rm','tags-pkg','nope'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-unknown-subcommand','dist-tag',['dist-tag','frob','tags-pkg'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-401-bearer','dist-tag',['dist-tag','add','bearer-pkg@1.0.0','beta'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('dist-tag-401-otp-heuristic','dist-tag',['dist-tag','add','heuristic-pkg@1.0.0','beta'],dir=>manifest(dir,{name:'tags-pkg'}),{auth:true});
add('install-missing-package','install',['install','nope-missing']);
add('install-missing-package-range','install',['install','nope-missing@^1.2.0']);
add('install-missing-package-invalid-name','install',['install','BadName']);
add('install-missing-transitive','install',['install'],dir=>manifest(dir,{dependencies:{'nope-missing':'^1.0.0'}}));
add('view-missing-package','view',['view','nope-missing']);
add('view-missing-package-json','view',['view','nope-missing','--json']);
// Transport failures use isolated endpoints and disable retries.
for(const command of ['view','install'])for(const [name,pkg,origin] of [['refused','dep','http://127.0.0.1:1/'],['dns','dep','http://rnpm-network-test.invalid/'],['reset','network-reset',registry],['timeout','network-timeout',registry]])add(`errors-network-${command}-${name}`,command,command==='view'?['view',pkg,'version']:['install',pkg,'--ignore-scripts'],undefined,{before:async({env})=>{env.NPM_CONFIG_REGISTRY=origin;env.NPM_CONFIG_FETCH_RETRIES='0';env.NPM_CONFIG_FETCH_TIMEOUT=name==='timeout'?'500':'10000';env.NO_PROXY='*';}});
for(const [name,flags] of [['missing',[]],['missing-lock-only',['--package-lock-only']]])add('errors-file-'+name,'install',['install','--ignore-scripts',...flags],dir=>manifest(dir,{dependencies:{x:'file:missing'}}));
add('errors-git-unreadable','install',['install','--ignore-scripts'],dir=>manifest(dir,{dependencies:{x:'git+'+pathToFileURL(path.join(dir,'absent repo')).href}}),{before:async({env})=>{env.GIT_TERMINAL_PROMPT='0';}});
for(const [name,flags,pkg] of [['prod',[],'dep'],['dev',['--save-dev'],'dep'],['optional',['--save-optional'],'dep'],['peer',['--save-peer'],'dep'],['no-save',['--no-save'],'dep'],['transitive',[],'parent']])add('save-bundle-'+name,'install',['install',pkg+'@1.0.0','--ignore-scripts','--save-bundle',...flags]);
add('save-bundle-sort','install',['install','dep@1.0.0','--ignore-scripts','--save-bundle'],dir=>manifest(dir,{dependencies:{'foo-bar':'npm:dep@1.0.0',foo_bar:'npm:dep@1.0.0'},bundleDependencies:['foo-bar','foo_bar','foo-bar']}));
for(const [name,manifestEol,lockEol] of [['manifest-lf-lock-crlf','\n','\r\n'],['manifest-crlf-lock-lf','\r\n','\n']])add('lock-newlines-'+name,'install',['install','--ignore-scripts'],dir=>{manifest(dir,{dependencies:{dep:'1.0.0'}});write(dir,'package.json',fs.readFileSync(path.join(dir,'package.json'),'utf8').replace(/\n/g,manifestEol));const lock={name:'readiness-case',version:'1.0.0',lockfileVersion:3,requires:true,packages:{'':{name:'readiness-case',version:'1.0.0',dependencies:{dep:'1.0.0'}}}};write(dir,'package-lock.json',(JSON.stringify(lock,null,2)+'\n').replace(/\n/g,lockEol));write(dir,'node_modules/.package-lock.json',(JSON.stringify({...lock,packages:{}},null,2)+'\n').replace(/\n/g,lockEol));},{observe:({dir})=>Object.fromEntries(['package-lock.json','node_modules/.package-lock.json'].map(file=>[file,fs.readFileSync(path.join(dir,file),'utf8').match(/\r\n|\n|\r/g)]))});

const queryMetadataTree=dir=>{installed(dir);edit(path.join(dir,'node_modules/dep'),p=>{p.funding=[{type:'individual',url:'https://example.invalid/support'}];p.engines={node:'>=18'};p.private=true;});};
for(const [name,selector] of [['insensitive','[name=DEP i]'],['attr-object',':attr(engines,[node])'],['attr-object-match',':attr(engines,[node^=">="])'],['attr-array',':attr(funding,[url*="example.invalid"])'],['attr-nested',':attr(funding,:attr([type=individual]))'],['boolean-attribute','[private=true]']])add(`cli-query-${name}`,'query',['query',selector],queryMetadataTree);
add('resolver-nesting-preserves-pending-descendant-edges','install',['install','--ignore-scripts'],dir=>manifest(dir,{dependencies:{'b-mid':'2.0.0','c-old':'1.0.0','d-new':'1.0.0',shared:'1.0.0','z-passive':'1.0.0'}}));
add('resolver-peer-set-prefers-parent-dependency','install',['install','--ignore-scripts'],dir=>manifest(dir,{dependencies:{'z-normal-peer-owner':'1.0.0'}}));
add('resolver-nested-optional-peer-conflict','install',['install','--ignore-scripts'],dir=>manifest(dir,{dependencies:{'nested-optional-owner':'1.0.0',shared:'1.0.0'}}));
add('unknown-command','frobnicate-xyz',['frobnicate-xyz']);
add('unknown-command-with-args','frobnicate-xyz',['frobnicate-xyz','a','--json']);
add('install-no-package-lock-writes-hidden','install',['install','--no-package-lock','--ignore-scripts'],dir=>manifest(dir,{dependencies:{dep:'1.0.0'}}));
add('install-no-package-lock-rewrites-stale-hidden','install',['install','--no-package-lock','--ignore-scripts'],dir=>{manifest(dir,{dependencies:{dep:'1.0.0'}});write(dir,'node_modules/.package-lock.json',JSON.stringify({name:'readiness-case',version:'1.0.0',lockfileVersion:3,requires:true,packages:{}},null,4)+'\n');});
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
// Only stack frames inside npm's JavaScript dependencies or Node internals differ
// by runtime. Preserve the inspected error properties, including its brace.
const normalizeJsFrames=str=>str.replace(/^npm error {5}at .*?(?:node:|[\\/]node_modules[\\/]npm[\\/]node_modules[\\/]).*\r?\n/gm,line=>line.trimEnd().endsWith('{')?'npm error {\n':'');
const normalize=(str,dir,config)=>normalizeJsFrames(str).replaceAll(dir.replaceAll('\\','\\\\'),'<fixture>').replaceAll(dir,'<fixture>').replaceAll(dir.replaceAll('\\','/'),'<fixture>').replaceAll(config.replaceAll('\\','\\\\'),'<config>').replaceAll(config,'<config>').replaceAll(config.replaceAll('\\','/'),'<config>').replaceAll(registry,'<registry>/').replace(/\bin \d+(?:\.\d+)?(?:ms|s|m|h)\b/g,'in <time>').replace(/("time": )\d+/g,'$10').replace(/PONG \d+ms/g,'PONG <time>').replace(/\d{4}-\d\d-\d\dT\d\d_\d\d_\d\d_\d{3}Z-debug-\d+\.log/g,'<timestamp>-debug-0.log').replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,'<uuid>').replace(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z/g,'<iso-time>').replace(/^(npm@\d+\.\d+\.\d+) .+$/m,'$1 <npm-root>').replace(/\r\n/g,'\n');
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
    Object.assign(env,c.env||{});
    if(c.userconfig)write(config,'user.npmrc',c.userconfig);
    const exec=async args=>{const p=await run(tool==='npm'?process.execPath:binary,tool==='npm'?[npmCli,...args]:args,dir,env,c.input);return p;};
    if(c.before)await c.before({dir,env,exec});
    authScenario=c.authScenario||'';authPolls=0;securityAdvisories=c.advisories||{};securityRequireAuth=!!c.advisoryAuth;
    const start=requests.length;const p=await exec(c.args);
    write(path.join(root,'logs'),`${c.name}-${tool}.stdout`,p.stdout);write(path.join(root,'logs'),`${c.name}-${tool}.stderr`,p.stderr);
    const files=snapshot(dir,config);
    files['<userconfig>']=fs.existsSync(path.join(config,'user.npmrc'))?normalize(fs.readFileSync(path.join(config,'user.npmrc'),'utf8'),dir,config):null;
    if(c.command==='link')files['<global-prefix>']=JSON.parse(normalize(JSON.stringify(snapshot(path.join(config,'prefix'),config)),dir,config));
    result[tool]={exit:p.exit,execution_error:p.error,stdout:normalize(p.stdout,dir,config),stderr:normalize(p.stderr,dir,config),files,requests:requests.slice(start)};
    if(c.observe)result[tool].observation=c.observe({dir,env,requests:requests.slice(start)});
  }
  const a=result.npm,b=result.rnpm;
  const mutations=tool=>tool.requests.filter(r=>['PUT','DELETE','POST'].includes(r.method)).map(({method,url,body})=>({method,url,body:body&&typeof body==='object'&&/^org\.couchdb\.user:/.test(body._id)&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(body.date)?{...body,date:'<timestamp>'}:body}));
  result.comparison={execution:!a.execution_error&&!b.execution_error&&a.exit!==null&&b.exit!==null,exit:a.exit===b.exit,stdout:a.stdout===b.stdout,stderr:a.stderr===b.stderr,files:stable(a.files)===stable(b.files),mutations:stable(mutations(a))===stable(mutations(b))};
  if(c.observe)result.comparison.observation=stable(a.observation)===stable(b.observation);
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
write(path.dirname(output),path.basename(output),{head:git('rev-parse','HEAD'),binary_revision:option('--binary-revision',null),source_dirty:git('status','--porcelain','--untracked-files=no')!=='',binary_sha256:createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),node:process.version,npm:execFileSync(process.execPath,[npmCli,'--version'],{env:oracleEnv,encoding:'utf8'}).trim(),platform:process.platform,root,expected_cases:expectedCases,normalization:'Fixture/config paths (including JSON escaping), loopback registry origin, CRLF, elapsed summary/ping times, and diagnostic log timestamps. JSON file key order ignored; all fields retained. Full normalized stream hashes retained; streams over 16KB truncated in this report, with complete raw streams in root/logs. Only npm/Node internal JavaScript stack frames removed; error messages and properties retained.',results});
console.log(`Evidence: ${output}; ${results.filter(r=>r.match).length}/${results.length} match`);
process.exitCode=results.length>0&&results.length===expectedCases&&results.every(r=>r.match)?0:1;
