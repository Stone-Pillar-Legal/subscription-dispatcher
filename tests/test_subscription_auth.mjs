import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, realpath, chmod, readFile, stat, rm, symlink, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { begin, complete, saveNewCredential, ISSUER } from '../subscription_dispatcher/auth/siwc.mjs';

const hostId='urn:uuid:11111111-1111-4111-8111-111111111111';
const redirectUri='http://127.0.0.1:1455/auth/callback';
const start=(extra={})=>begin({hostId,redirectUri,appName:'Generic Dispatcher',...extra},100);
const tokens=()=>({token_type:'Bearer',access_token:'synthetic-access',refresh_token:'synthetic-refresh',
  id_token:'synthetic-id-token',expires_in:3600,
  scope:'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct'});
function callback(pending,extra={}) {
  return redirectUri+'?'+new URLSearchParams({state:pending.state,code:'synthetic-code',client_id:'oaiapp_test',...extra});
}
function mocks(overrides={}) {
  const calls=[];
  return {calls,now:101,
    request:async(url,options)=>{calls.push({url,options}); return url.endsWith('jwks.json')?{keys:[]}:tokens();},
    // Protocol tests only. Cryptographic identity verification is separate.
    verify:async()=>({sub:'synthetic-owner'}),...overrides};
}

test('fresh PKCE, nonce and state; fixed subscription scopes and callback',()=>{
  const a=start(),b=start();
  const params=new URL(a.url).searchParams;
  assert.notEqual(a.pending.state,b.pending.state);
  assert.notEqual(a.pending.nonce,b.pending.nonce);
  assert.equal(params.get('code_challenge'),createHash('sha256').update(a.pending.verifier).digest('base64url'));
  assert.equal(params.get('resource'),'https://api.openai.com/v1');
  assert.equal(params.get('client_id'),'dynamic_agent_client');
  assert.equal(params.get('redirect_uri'),redirectUri);
  assert.ok(params.get('scope').includes('chatgpt.tokens.use.direct'));
});

test('only exact loopback callbacks and bound returning identities',()=>{
  for(const value of ['https://example.com/auth/callback','http://localhost:1455/auth/callback',redirectUri+'#fragment'])
    assert.throws(()=>start({redirectUri:value}));
  assert.throws(()=>start({clientId:'oaiapp_test'}));
  const a=start({clientId:'oaiapp_test',subject:'owner'});
  assert.equal(new URL(a.url).searchParams.get('agent_name_hint'),null);
});

test('state, duplicate, wrong callback and expiry fail before token exchange',async()=>{
  for(const kind of ['state','duplicate','origin','expired','denied']) {
    const {pending}=start(); const fake=mocks();
    let url=callback(pending);
    if(kind==='state') url=callback(pending,{state:'wrong'});
    if(kind==='duplicate') url+='&code=other';
    if(kind==='origin') url=url.replace(':1455',':1456');
    if(kind==='expired') fake.now=1000;
    if(kind==='denied') url=callback(pending,{error:'access_denied'});
    await assert.rejects(complete(pending,url,fake));
    assert.equal(fake.calls.length,0);
  }
});

test('exchange binds issued client, original callback and verifier; attempt is single-use',async()=>{
  const {pending}=start(); const fake=mocks();
  const record=await complete(pending,callback(pending),fake);
  const body=new URLSearchParams(fake.calls[0].options.body);
  assert.equal(body.get('client_id'),'oaiapp_test');
  assert.equal(body.get('redirect_uri'),redirectUri);
  assert.equal(body.get('code_verifier'),pending.verifier);
  assert.equal(record.issuer,ISSUER); assert.equal(record.subject,'synthetic-owner');
  assert.equal(record.expires_at,3701);
  await assert.rejects(complete(pending,callback(pending),fake));
  assert.equal(fake.calls.length,2);
});

test('missing plan scope, API key, invalid lifetime and invalid identity are refused',async()=>{
  for(const change of [{scope:'openid'},{access_token:'sk-test'},{expires_in:NaN},{expires_in:0}]) {
    const {pending}=start(); let verified=false;
    await assert.rejects(complete(pending,callback(pending),mocks({
      request:async()=>({...tokens(),...change}),verify:async()=>{verified=true;return {sub:'owner'};}})));
    assert.equal(verified,false);
  }
  const {pending}=start();
  await assert.rejects(complete(pending,callback(pending),mocks({verify:async()=>{throw new Error('secret provider text');}})),error=>!error.message.includes('secret provider text'));
});

test('returning registration cannot switch client or subject',async()=>{
  let {pending}=start({clientId:'oaiapp_original',subject:'owner'});
  const fake=mocks();
  await assert.rejects(complete(pending,callback(pending),fake));
  assert.equal(fake.calls.length,0);
  ({pending}=start({clientId:'oaiapp_test',subject:'owner'}));
  await assert.rejects(complete(pending,callback(pending),mocks()));
});

test('new credential storage is private, atomic and refuses replacement',async()=>{
  const dir=await realpath(await mkdtemp(path.join(tmpdir(),'subscription-auth-')));
  try {
    await chmod(dir,0o700);
    const {pending}=start(); const record=await complete(pending,callback(pending),mocks());
    const file=await saveNewCredential(dir,record);
    assert.equal((await stat(file)).mode&0o777,0o600);
    assert.equal(JSON.parse(await readFile(file,'utf8')).subject,'synthetic-owner');
    await assert.rejects(saveNewCredential(dir,{...record,access_token:'replacement'}));
    assert.equal(JSON.parse(await readFile(file,'utf8')).access_token,'synthetic-access');
    assert.deepEqual(await readdir(dir),['oaiapp_test.json']);
    await chmod(dir,0o755); await assert.rejects(saveNewCredential(dir,record));
  } finally { await rm(dir,{recursive:true,force:true}); }
});

test('missing dependency cannot turn into unverified acceptance',async()=>{
  const {pending}=start(); const fake=mocks(); delete fake.verify;
  // An empty JWKS and synthetic token cannot pass even after jose is installed.
  await assert.rejects(complete(pending,callback(pending),fake));
});

 test('Node credential writer and Python loader agree without exposing refresh tokens',async()=>{
  const dir=await realpath(await mkdtemp(path.join(tmpdir(),'subscription-contract-')));
  try {
    await chmod(dir,0o700);
    const {pending}=start();
    const file=await saveNewCredential(dir,await complete(pending,callback(pending),mocks()));
    const output=execFileSync('python3',['-c',
      "import sys; from subscription_dispatcher.credentials import load_credentials; s=load_credentials(sys.argv[1],now=102); assert s.subject=='synthetic-owner'; assert not hasattr(s,'refresh_token'); assert 'synthetic-access' not in repr(s); print('validated')",file],
      {cwd:fileURLToPath(new URL('..',import.meta.url)),encoding:'utf8'});
    assert.equal(output.trim(),'validated');
  } finally {await rm(dir,{recursive:true,force:true});}
});

test('identical protected credential retries reconcile; differing bytes refuse',async()=>{
  const dir=await realpath(await mkdtemp(path.join(tmpdir(),'subscription-reconcile-')));
  try {
    const {pending}=start(); const record=await complete(pending,callback(pending),mocks());
    const first=await saveNewCredential(dir,record);
    assert.equal(await saveNewCredential(dir,record),first);
    await assert.rejects(saveNewCredential(dir,{...record,subject:'different'}));
    assert.equal(JSON.parse(await readFile(first,'utf8')).subject,record.subject);
  } finally {await rm(dir,{recursive:true,force:true});}
});

test('descriptor writer refuses directory redirection without writing into replacement',()=>{
  const helper=fileURLToPath(new URL('../subscription_dispatcher/auth/credential_writer.py',import.meta.url));
  const output=execFileSync('python3',['-I','-B','-c',String.raw`
import importlib.util, os, pathlib, tempfile
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('writer',__import__('sys').argv[1]); w=importlib.util.module_from_spec(spec); spec.loader.exec_module(w)
with tempfile.TemporaryDirectory() as t:
 root=pathlib.Path(t).resolve(); private=root/'private'; private.mkdir(mode=0o700); other=root/'other'; other.mkdir(mode=0o700)
 original=os.open; swapped=False
 def opened(name,*args,**kwargs):
  global swapped
  if str(name).startswith('.pending-') and not swapped:
   swapped=True;private.rename(root/'old');private.symlink_to(other,target_is_directory=True)
  return original(name,*args,**kwargs)
 with patch.object(w.os,'open',opened):
  result=w.save(str(private),{'format':'siwc-validated-v1','client_id':'oaiapp_fixture','access_token':'synthetic'})
 assert result['status']=='refused',result
 assert list(other.iterdir())==[]
 assert not (root/'old'/'oaiapp_fixture.json').exists()
 print('refused safely')
`,helper],{encoding:'utf8'});
  assert.equal(output.trim(),'refused safely');
});

test('post-publication fsync failure reports uncertainty and exact retry reconciles',()=>{
  const helper=fileURLToPath(new URL('../subscription_dispatcher/auth/credential_writer.py',import.meta.url));
  const output=execFileSync('python3',['-I','-B','-c',String.raw`
import importlib.util, os, pathlib, stat, tempfile
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('writer',__import__('sys').argv[1]);w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
with tempfile.TemporaryDirectory() as t:
 directory=str(pathlib.Path(t).resolve()); record={'format':'siwc-validated-v1','client_id':'oaiapp_fixture','access_token':'synthetic'}
 original=os.fsync
 def sync(fd):
  if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('injected')
  return original(fd)
 with patch.object(w.os,'fsync',sync): result=w.save(directory,record)
 assert result['status']=='published-but-durability-unconfirmed',result
 assert w.save(directory,dict(record,access_token='different'))['status']=='refused'
 assert w.save(directory,record)['status']=='reconciled'
 target=pathlib.Path(directory)/'oaiapp_fixture.json';before=target.read_bytes()
 os.link(target,pathlib.Path(directory)/'sibling')
 assert w.save(directory,record)['status']=='refused'
 assert target.read_bytes()==before
 print('reconciled safely')
`,helper],{encoding:'utf8'});
  assert.equal(output.trim(),'reconciled safely');
});

test('writer rejects symlink ancestors, public directory and oversized stdin',async()=>{
  const root=await realpath(await mkdtemp(path.join(tmpdir(),'subscription-paths-')));
  try {
    const {pending}=start();const record=await complete(pending,callback(pending),mocks());
    const alias=path.join(root,'alias');await symlink(root,alias);
    await assert.rejects(saveNewCredential(alias,record));
    await chmod(root,0o755);await assert.rejects(saveNewCredential(root,record));
    await chmod(root,0o700);
    await assert.rejects(saveNewCredential(root,{...record,id_token:'x'.repeat(65536)}));
    const helper=fileURLToPath(new URL('../subscription_dispatcher/auth/credential_writer.py',import.meta.url));
    for(const input of ['x'.repeat(65537),'{"directory":NaN}','{"record":1,"record":2}']) {
      const output=execFileSync('python3',['-I','-B',helper],{input,encoding:'utf8'});
      assert.deepEqual(JSON.parse(output),{status:'refused'});
    }
    assert.deepEqual(await readdir(root),['alias']);
  } finally {await rm(root,{recursive:true,force:true});}
});
