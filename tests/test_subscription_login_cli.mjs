import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {main,options} from '../subscription_dispatcher/auth/login-cli.mjs';
const args=['--host-id','urn:uuid:11111111-1111-4111-8111-111111111111','--directory','/synthetic/private','--app-name','Synthetic App'];
test('requires explicit options and rejects fallback flags or partial identities',()=>{
 assert.equal(options(args).appName,'Synthetic App');
 for(const input of [[],[...args,'--api-key','sk-test'],[...args,'--host-id','other'],[...args,'--client-id','oaiapp_test'],args.map(x=>x==='/synthetic/private'?'relative':x)]) assert.throws(()=>options(input));
});
test('help never starts authentication',async()=>{
 let calls=0; assert.equal(await main(['--help'],{start:()=>{calls++;},output:()=>{}}),0); assert.equal(calls,0);
});
test('successful command cleans up listener and logs no credential result',async()=>{
 const output=[],signals=new EventEmitter(); let cancelled=0;
 assert.equal(await main(args,{signals,output:x=>output.push(x),start:async()=>({url:'https://auth.openai.com/synthetic',done:Promise.resolve({access_token:'secret'}),cancel:()=>cancelled++})}),0);
 assert.equal(cancelled,1); assert.equal(signals.listenerCount('SIGINT'),0); assert.ok(!output.join('').includes('secret'));
});
test('failure sanitises diagnostics and offers no model/provider fallback',async()=>{
 const output=[];
 assert.equal(await main(args,{signals:new EventEmitter(),output:x=>output.push(x),start:async()=>{throw new Error('secret refresh token');}}),1);
 assert.ok(!output.join('').includes('secret refresh token'));
});
test('interrupt cancels pending sign-in and removes both signal listeners',async()=>{
 const signals=new EventEmitter(),output=[]; let reject, cancelled=0;
 const done=new Promise((_,r)=>{reject=r;});
 const result=main(args,{signals,output:x=>{output.push(x);if(x==='https://auth.openai.com/synthetic') signals.emit('SIGINT');},
   start:async()=>({url:'https://auth.openai.com/synthetic',done,cancel:()=>{cancelled++;reject(new Error('cancelled'));}})});
 assert.equal(await result,1); assert.ok(cancelled>=1);
 assert.equal(signals.listenerCount('SIGINT'),0); assert.equal(signals.listenerCount('SIGTERM'),0);
});
