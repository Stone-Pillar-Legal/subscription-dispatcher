import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {mkdtemp,realpath,chmod,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {startLogin} from '../login.mjs';
import {complete,ISSUER} from '../siwc.mjs';

test('real loopback callback verifies signature, saves privately and loads in dispatcher',async()=>{
 const dir=await realpath(await mkdtemp(path.join(tmpdir(),'siwc-local-integration-')));
 await chmod(dir,0o700);
 const pair=await generateKeyPair('RS256');
 const jwk={...await exportJWK(pair.publicKey),kid:'synthetic'};
 let attempt,exchanges=0;
 try {
  attempt=await startLogin({hostId:'urn:uuid:11111111-1111-4111-8111-111111111111',appName:'Synthetic Test',directory:dir},{
   complete:(pending,url)=>complete(pending,url,{request:async(endpoint,init)=>{
    if(endpoint.endsWith('jwks.json')) return {keys:[jwk]};
    exchanges++;
    const body=new URLSearchParams(init.body);
    assert.equal(body.get('redirect_uri'),pending.redirectUri);
    assert.equal(body.get('code_verifier'),pending.verifier);
    const now=Math.floor(Date.now()/1000);
    return {access_token:'synthetic-access',refresh_token:'synthetic-refresh',token_type:'Bearer',expires_in:3600,
     scope:'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct',
     id_token:await new SignJWT({iss:ISSUER,aud:'oaiapp_integration',sub:'synthetic-owner',nonce:pending.nonce,iat:now,exp:now+3600}).setProtectedHeader({alg:'RS256',kid:'synthetic'}).sign(pair.privateKey)};
   }})});
  const params=new URL(attempt.url).searchParams;
  const callback=new URL(params.get('redirect_uri'));
  callback.search=new URLSearchParams({state:params.get('state'),client_id:'oaiapp_integration',code:'synthetic-code'}).toString();
  const response=await fetch(callback,{redirect:'error'});
  assert.equal(response.status,200); assert.equal(response.headers.get('cache-control'),'no-store');
  await attempt.done; assert.equal(exchanges,1);
  const target=path.join(dir,'oaiapp_integration.json');
  assert.equal(JSON.parse(await readFile(target,'utf8')).subject,'synthetic-owner');
  const result=execFileSync('python3',['-c',"import sys; from subscription_dispatcher.credentials import load_credentials; s=load_credentials(sys.argv[1]); assert s.subject=='synthetic-owner'; print('verified')",target],
   {cwd:fileURLToPath(new URL('../../..',import.meta.url)),encoding:'utf8'});
  assert.equal(result.trim(),'verified');
 } finally {attempt?.cancel();await rm(dir,{recursive:true,force:true});}
});
