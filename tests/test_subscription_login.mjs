import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {startLogin} from '../subscription_dispatcher/auth/login.mjs';
const config={hostId:'urn:uuid:12345678-1234-4123-8123-123456789abc',appName:'Synthetic',directory:'/unused'};
async function setup(t, deps={}) {
  const calls={complete:0,save:0};
  const login=await startLogin(config,{
    complete:async()=>{calls.complete++;return {access_token:'secret-token'};},
    save:async(dir,record)=>{calls.save++;assert.equal(dir,'/unused');assert.equal(record.access_token,'secret-token');},
    ...deps});
  t.after(()=>login.cancel());
  const auth=new URL(login.url), callback=new URL(auth.searchParams.get('redirect_uri'));
  callback.search=new URLSearchParams({state:auth.searchParams.get('state'),client_id:'oaiapp_test',code:'private-code'});
  return {login,callback,calls};
}
function request(url, {method='GET',host=url.host,path=url.pathname+url.search}={}) {
  return new Promise((resolve,reject)=>{
    const req=http.request({hostname:'127.0.0.1',port:url.port,method,path,headers:{Host:host}},res=>{
      let body='';res.on('data',chunk=>body+=chunk);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body}));
    });req.on('error',reject);req.end();
  });
}
test('success saves once, sanitized response and replay listener closed',async t=>{
  const {login,callback,calls}=await setup(t);
  const response=await request(callback);
  assert.equal(response.status,200);
  assert.equal(response.headers['cache-control'],'no-store');
  assert.equal(response.headers['referrer-policy'],'no-referrer');
  assert.match(response.headers['content-security-policy'],/default-src 'none'/);
  assert.doesNotMatch(response.body,/private-code|secret-token/);
  assert.deepEqual(await login.done,{status:'saved'});
  assert.deepEqual(calls,{complete:1,save:1});
  await assert.rejects(request(callback));
  login.cancel();
});
test('wrong host, state, method, path and malformed probes do not consume attempt',async t=>{
  const {login,callback,calls}=await setup(t);
  for (const options of [{host:'localhost:'+callback.port},{method:'POST'},
    {path:'/other'+callback.search},{path:callback.pathname+callback.search+'&state=duplicate'},
    {path:callback.pathname+'?state=wrong&code=x'},
    {path:callback.pathname+callback.search+'&bad=%QQ'},
    {path:'/auth/callback?'+new URLSearchParams({state:callback.searchParams.get('state')})},
    {path:callback.pathname+callback.search+'&padding='+'x'.repeat(17000)}]) {
    assert.equal((await request(callback,options)).status,400);
    assert.deepEqual(calls,{complete:0,save:0});
  }
  assert.equal((await request(callback)).status,200);await login.done;
});
test('only one valid callback admitted while completion pending',async t=>{
  let release, entered;
  const waiting=new Promise(r=>entered=r);
  const {login,callback,calls}=await setup(t,{complete:()=>{entered();return new Promise(r=>release=r);}});
  const first=request(callback);await waiting;
  assert.equal((await request(callback)).status,409);
  release({access_token:'secret-token'});
  assert.equal((await first).status,200);await login.done;assert.equal(calls.save,1);
});
test('exchange and save failures are sanitized and close listener',async t=>{
  for (const name of ['complete','save']) {
    const {login,callback}=await setup(t,{[name]:async()=>{throw Error('secret-token private-code');}});
    const failure=assert.rejects(login.done,error=>!error.message.includes('secret-token'));
    const response=await request(callback);assert.equal(response.status,400);
    assert.doesNotMatch(response.body,/secret-token|private-code/);await failure;
    await assert.rejects(request(callback));
  }
});
test('expiry and cancel close listener',async t=>{
  const expiring=await setup(t,{timeoutMs:20});
  await assert.rejects(expiring.login.done,/expired/);
  await assert.rejects(request(expiring.callback));
  const cancelled=await setup(t);cancelled.login.cancel();
  await assert.rejects(cancelled.login.done,/cancelled/);
  await assert.rejects(request(cancelled.callback));
});
test('cancel during exchange prevents subsequent save',async t=>{
  let release, entered;const waiting=new Promise(r=>entered=r);
  const {login,callback,calls}=await setup(t,{complete:()=>{entered();return new Promise(r=>release=r);}});
  const response=request(callback).catch(()=>null);await waiting;login.cancel();
  await assert.rejects(login.done,/cancelled/);release({access_token:'secret-token'});
  await response;await new Promise(r=>setImmediate(r));assert.equal(calls.save,0);
});

test('valid provider denial closes attempt without exchange or save',async t=>{
  const {complete}=await import('../subscription_dispatcher/auth/siwc.mjs');
  const {login,callback,calls}=await setup(t,{complete});
  callback.searchParams.delete('code');callback.searchParams.set('error','access_denied');
  const failure=assert.rejects(login.done,/Sign-in failed/);
  assert.equal((await request(callback)).status,400);await failure;
  assert.equal(calls.save,0);await assert.rejects(request(callback));
});
test('cancel during save rejects without claiming to retract persistence',async t=>{
  let release,entered;const waiting=new Promise(r=>entered=r);
  let saves=0;
  const {login,callback}=await setup(t,{save:()=>{saves++;entered();return new Promise(r=>release=r);}});
  const response=request(callback).catch(()=>null);await waiting;login.cancel();
  await assert.rejects(login.done,/in-flight save may require reconciliation/);
  release();await response;await new Promise(r=>setImmediate(r));assert.equal(saves,1);
});
