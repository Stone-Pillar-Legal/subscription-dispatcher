/** Application-owned SIWC registration. No login starts on import.
 * JWT verification requires the separately approved pinned jose dependency.
 * No desktop token discovery, API key path, hosted connector or billing fallback.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const ISSUER = 'https://auth.openai.com';
const AUTHORIZE = ISSUER + '/api/accounts/authorize';
const TOKEN = ISSUER + '/api/accounts/oauth/token';
const JWKS = ISSUER + '/.well-known/jwks.json';
const RESOURCE = 'https://api.openai.com/v1';
const SCOPES = ['openid','profile','email','offline_access','resource.invoke','chatgpt.tokens.use.direct'];
export class AuthError extends Error {}
const fail = message => { throw new AuthError(message); };
const random = () => randomBytes(32).toString('base64url');
const equal = (a,b) => typeof a==='string' && typeof b==='string' && Buffer.byteLength(a)===Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a),Buffer.from(b));
const issued = value => typeof value==='string' && /^oaiapp_[A-Za-z0-9_-]+$/.test(value);

export function begin({hostId,redirectUri,appName,clientId=null,subject=null}, now=Date.now()/1000) {
  if (!/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(hostId) || !Number.isFinite(now)) fail('Invalid host identity or clock');
  const callback = new URL(redirectUri);
  if (callback.protocol!=='http:' || callback.hostname!=='127.0.0.1' || !callback.port || callback.pathname!=='/auth/callback' || callback.search || callback.hash || callback.username || callback.password) fail('Expected exact loopback callback');
  if (clientId!==null && (!issued(clientId) || typeof subject!=='string' || !subject)) fail('Returning registration identity required');
  if (typeof appName!=='string' || !appName.trim() || appName.length>128) fail('Application name required');
  const state=random(), nonce=random(), verifier=random();
  const values={client_id:clientId??'dynamic_agent_client',ext_agent_host_id:hostId,
    response_type:'code',redirect_uri:redirectUri,scope:SCOPES.join(' '),resource:RESOURCE,
    state,nonce,code_challenge_method:'S256',code_challenge:createHash('sha256').update(verifier).digest('base64url')};
  if (!clientId) values.agent_name_hint=appName;
  return {url:AUTHORIZE+'?'+new URLSearchParams(values),
    pending:{hostId,redirectUri,clientId,subject,state,nonce,verifier,created:now,used:false}};
}

export async function boundedJson(url,init={}) {
  if (![TOKEN,JWKS].includes(url)) fail('Unapproved authentication endpoint');
  const response=await fetch(url,{...init,redirect:'error',signal:AbortSignal.timeout(30000)});
  if (!response.ok) { await response.body?.cancel(); fail('Authentication provider refused request'); }
  const reader=response.body.getReader(); const chunks=[]; let length=0;
  for (;;) {
    const {done,value}=await reader.read(); if (done) break;
    length+=value.length;
    if (length>1024*1024) { await reader.cancel(); fail('Authentication response too large'); }
    chunks.push(Buffer.from(value));
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { fail('Unreadable authentication response'); }
}

export async function verifyIdentity(token,jwks,{clientId,nonce,now}) {
  // Dynamic import fails closed if the dependency has not been approved/installed.
  const {jwtVerify,createLocalJWKSet}=await import('jose');
  const {payload}=await jwtVerify(token,createLocalJWKSet(jwks),{
    issuer:ISSUER,audience:clientId,algorithms:['RS256'],clockTolerance:5,
    requiredClaims:['sub','exp','iat','nonce'],currentDate:new Date(now*1000)});
  if (!equal(payload.nonce,nonce) || typeof payload.sub!=='string' || !payload.sub
      || !Number.isFinite(payload.iat) || payload.iat>now+5
      || (Array.isArray(payload.aud) && payload.aud.length>1 && payload.azp!==clientId)
      || (payload.azp!==undefined && payload.azp!==clientId)) fail('Identity token binding failed');
  return payload;
}

export async function complete(pending,callbackUrl,{request=boundedJson,verify=verifyIdentity,now=Date.now()/1000}={}) {
  const callback=new URL(callbackUrl), expected=new URL(pending.redirectUri);
  if (callback.origin!==expected.origin || callback.pathname!==expected.pathname || callback.hash || callback.username || callback.password) fail('Callback destination mismatch');
  for (const name of new Set(callback.searchParams.keys())) {
    if (callback.searchParams.getAll(name).length!==1) fail('Duplicate callback parameter');
  }
  if (!equal(callback.searchParams.get('state'),pending.state)) fail('Callback state mismatch');
  if (pending.used || !Number.isFinite(pending.created) || !Number.isFinite(now) || now<pending.created || now-pending.created>600) fail('Authorization attempt expired or already used');
  pending.used=true;
  if (callback.searchParams.has('iss') && callback.searchParams.get('iss')!==ISSUER) fail('Authorization issuer mismatch');
  if (callback.searchParams.has('error')) fail('Authorization was not granted');
  const clientId=callback.searchParams.get('client_id')??pending.clientId;
  if (!issued(clientId) || (pending.clientId && clientId!==pending.clientId)) fail('Registration identity mismatch');
  const code=callback.searchParams.get('code');
  if (!code || code.length>8192) fail('Authorization code missing or invalid');
  try {
    const response=await request(TOKEN,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:new URLSearchParams({grant_type:'authorization_code',client_id:clientId,code,
        code_verifier:pending.verifier,redirect_uri:pending.redirectUri,resource:RESOURCE}).toString()});
    const scopes=typeof response.scope==='string'?response.scope.split(/\s+/).filter(Boolean):[];
    if (!SCOPES.every(s=>scopes.includes(s)) || response.token_type?.toLowerCase()!=='bearer'
        || typeof response.access_token!=='string' || !response.access_token || response.access_token.startsWith('sk-')
        || /\s/.test(response.access_token) || typeof response.refresh_token!=='string' || !response.refresh_token
        || typeof response.id_token!=='string' || !Number.isFinite(response.expires_in)
        || response.expires_in<=30 || response.expires_in>86400) fail('Required subscription grant missing');
    const jwks=await request(JWKS);
    const claims=await verify(response.id_token,jwks,{clientId,nonce:pending.nonce,now});
    if (typeof claims.sub!=='string' || !claims.sub || (pending.subject && claims.sub!==pending.subject)) fail('Account identity changed');
    return {format:'siwc-validated-v1',issuer:ISSUER,subject:claims.sub,client_id:clientId,
      ext_agent_host_id:pending.hostId,access_token:response.access_token,refresh_token:response.refresh_token,
      id_token:response.id_token,scopes,expires_at:now+response.expires_in,validated_at:now,
      ...(typeof claims.email==='string'?{email:claims.email}:{})};
  } catch { fail('Subscription sign-in could not be verified; restart authorization'); }
}

export async function saveNewCredential(directory,record) {
  // Trusted caller only. Credentials travel on stdin, never argv or diagnostics.
  let input;
  try { input=JSON.stringify({directory,record}); }
  catch { fail('Credential record could not be serialized'); }
  if (Buffer.byteLength(input)>65536) fail('Credential record exceeds limit');
  const helper=fileURLToPath(new URL('./credential_writer.py',import.meta.url));
  const result=await new Promise((resolve,reject)=>{
    const child=spawn('python3',['-I','-B',helper],{stdio:['pipe','pipe','ignore']});
    let output='', failed=false;
    const timer=setTimeout(()=>{failed=true;child.kill('SIGTERM');},30000);
    child.stdout.on('data',chunk=>{
      output+=chunk.toString('utf8');
      if(Buffer.byteLength(output)>16384){failed=true;child.kill('SIGTERM');}
    });
    child.stdin.on('error',()=>{failed=true;});
    child.on('error',()=>{clearTimeout(timer);reject(new AuthError('Credential writer unavailable'));});
    child.on('close',code=>{
      clearTimeout(timer);
      if(failed || code!==0) return reject(new AuthError('Credential save outcome unknown; reconcile identical record before use'));
      try {resolve(JSON.parse(output));}
      catch {reject(new AuthError('Credential save outcome unknown; reconcile identical record before use'));}
    });
    child.stdin.end(input);
  });
  if(result.status==='published-but-durability-unconfirmed') {
    const error=new AuthError('Credential published but durability unconfirmed; reconcile identical record before use');
    error.status=result.status;
    error.path=result.path;
    throw error;
  }
  if(!['published','reconciled'].includes(result.status) || typeof result.path!=='string') fail('Credential save refused; existing records were not replaced');
  return result.path;
}
