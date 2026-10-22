import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { verifyIdentity, ISSUER } from '../siwc.mjs';

const now = 1800000000;
const clientId = 'oaiapp_synthetic';
const nonce = 'synthetic-nonce';
const pair = await generateKeyPair('RS256');
const publicKey = {...await exportJWK(pair.publicKey), kid:'test-key', alg:'RS256'};
const jwks = {keys:[publicKey]};
const options = {clientId, nonce, now};
const claims = {iss:ISSUER, aud:clientId, sub:'synthetic-owner', nonce, iat:now, exp:now+600};
async function signed(overrides={}, key=pair.privateKey, header={alg:'RS256',kid:'test-key'}) {
  return new SignJWT({...claims,...overrides}).setProtectedHeader(header).sign(key);
}

test('accepts a correctly signed identity bound to the application and nonce', async()=>{
  assert.equal((await verifyIdentity(await signed(),jwks,options)).sub,'synthetic-owner');
});
test('rejects wrong issuer, audience, nonce, time and missing subject', async()=>{
  for (const override of [{iss:'https://invalid.example'}, {aud:'oaiapp_other'}, {nonce:'other'},
    {exp:now-60}, {iat:now+60}, {sub:''}, {sub:null}, {nonce:null}, {iat:null}]) {
    await assert.rejects(verifyIdentity(await signed(override),jwks,options));
  }
});
test('rejects payload tampering, wrong signature and unknown signing key', async()=>{
  const valid=await signed(); const parts=valid.split('.');
  parts[1]=Buffer.from(JSON.stringify({...claims,sub:'attacker'})).toString('base64url');
  await assert.rejects(verifyIdentity(parts.join('.'),jwks,options));
  const other=await generateKeyPair('RS256');
  await assert.rejects(verifyIdentity(await signed({},other.privateKey),jwks,options));
  await assert.rejects(verifyIdentity(await signed({},pair.privateKey,{alg:'RS256',kid:'unknown'}),jwks,options));
});
test('rejects unsigned and symmetric algorithm substitution', async()=>{
  const unsigned=Buffer.from(JSON.stringify({alg:'none'})).toString('base64url')+'.'+Buffer.from(JSON.stringify(claims)).toString('base64url')+'.';
  await assert.rejects(verifyIdentity(unsigned,jwks,options));
  const symmetric=await signed({},new Uint8Array(32).fill(1),{alg:'HS256',kid:'test-key'});
  await assert.rejects(verifyIdentity(symmetric,jwks,options));
});
test('multiple audiences require the application as authorised party', async()=>{
  for (const azp of [undefined,'oaiapp_other']) {
    await assert.rejects(verifyIdentity(await signed({aud:[clientId,'other'],azp}),jwks,options));
  }
  assert.equal((await verifyIdentity(await signed({aud:[clientId,'other'],azp:clientId}),jwks,options)).sub,claims.sub);
  await assert.rejects(verifyIdentity(await signed({azp:'oaiapp_other'}),jwks,options));
});
