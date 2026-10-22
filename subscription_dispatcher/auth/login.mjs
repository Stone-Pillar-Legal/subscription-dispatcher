/** Trusted local sign-in listener. No browser launch or login on import.
 * Injected functions are server/test dependencies, never request-controlled.
 * Cancellation stops admission and subsequent saving, but cannot undo a save
 * already in flight; a cancelled/failed save must be reconciled by the caller.
 */
import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { begin, complete as completeDefault, saveNewCredential, AuthError, ISSUER } from './siwc.mjs';

export async function startLogin(config, {
  complete = completeDefault, save = saveNewCredential, timeoutMs = 600000,
} = {}) {
  if (!config || typeof config.directory !== 'string' || !config.directory
      || typeof complete !== 'function' || typeof save !== 'function'
      || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600000) {
    throw new AuthError('Invalid local sign-in configuration');
  }
  let terminal = false, admitted = false, pending, host, timer;
  let resolveDone, rejectDone;
  const done = new Promise((resolve,reject) => { resolveDone=resolve; rejectDone=reject; });
  // A timeout may occur before the trusted caller awaits done.
  done.catch(() => {});
  const sockets = new Set();
  const server = http.createServer({maxHeaderSize:20480, requestTimeout:10000,
    headersTimeout:10000, keepAliveTimeout:1000}, (req,res) => {
    const reply = (status, text) => {
      res.writeHead(status, {'Content-Type':'text/plain; charset=utf-8',
        'Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",
        'Cache-Control':'no-store', 'Referrer-Policy':'no-referrer',
        'X-Content-Type-Options':'nosniff', 'Connection':'close'});
      res.end(text);
    };
    if (terminal || admitted) return reply(409,'Sign-in is not available.');
    let callback;
    try {
      const hosts = req.rawHeaders.filter((_,i) => i%2===0 && req.rawHeaders[i].toLowerCase()==='host');
      if (req.method!=='GET' || hosts.length!==1 || req.headers.host!==host
          || req.headers['transfer-encoding']!==undefined
          || (req.headers['content-length']!==undefined && req.headers['content-length']!=='0')
          || typeof req.url!=='string' || Buffer.byteLength(req.url)>16384
          || !req.url.startsWith('/auth/callback?') || /[\s#\\]/.test(req.url)
          || /%(?![0-9a-f]{2})/i.test(req.url)) throw Error();
      callback=new URL(req.url, pending.redirectUri);
      if (callback.pathname!=='/auth/callback' || callback.origin!==`http://${host}`) throw Error();
      const params=callback.searchParams;
      for (const key of new Set(params.keys())) if (params.getAll(key).length!==1) throw Error();
      const state=params.get('state');
      if (typeof state!=='string' || Buffer.byteLength(state)!==Buffer.byteLength(pending.state)
          || !timingSafeEqual(Buffer.from(state),Buffer.from(pending.state))) throw Error();
      if (params.has('iss') && params.get('iss')!==ISSUER) throw Error();
      if (params.has('error')) {
        if (!params.get('error') || params.has('code')) throw Error();
      } else {
        const client=params.get('client_id')??pending.clientId, code=params.get('code');
        if (!/^oaiapp_[A-Za-z0-9_-]+$/.test(client??'')
            || (pending.clientId && pending.clientId!==client)
            || !code || code.length>8192) throw Error();
      }
    } catch { return reply(400,'Invalid sign-in callback.'); }
    admitted=true; // Synchronous admission, before the first asynchronous operation.
    // Authentication has its own bounded requests and overall attempt deadline.
    // Do not cut the browser off at the pre-admission slow-client timeout.
    req.socket.setTimeout(0);
    void (async () => {
      try {
        const record=await complete(pending,callback.href);
        if (terminal) return;
        await save(config.directory,record);
        if (terminal) return;
        reply(200,'Sign-in saved. You may close this window.');
        finish(null);
      } catch {
        if (terminal) return;
        reply(400,'Sign-in failed. Restart authorization.');
        finish('Sign-in failed; any credential save outcome must be reconciled.');
      }
    })();
  });
  server.maxHeadersCount=64;
  server.on('connection', socket => {
    sockets.add(socket); socket.setTimeout(10000,()=>socket.destroy());
    socket.on('close',()=>sockets.delete(socket));
  });
  server.on('clientError', (_error,socket) => socket.destroy());
  function finish(error, destroy=false) {
    if (terminal) return;
    terminal=true; clearTimeout(timer);
    server.close();
    server.closeIdleConnections();
    if (destroy) for (const socket of sockets) socket.destroy();
    if (error) rejectDone(new AuthError(error)); else resolveDone({status:'saved'});
  }
  try {
    await new Promise((resolve,reject) => {
      server.once('error',reject);
      server.listen(0,'127.0.0.1',()=>{server.removeListener('error',reject);resolve();});
    });
    host=`127.0.0.1:${server.address().port}`;
    const started=begin({...config,redirectUri:`http://${host}/auth/callback`});
    pending=started.pending;
    server.on('error',()=>finish('Local sign-in listener failed.',true));
    timer=setTimeout(()=>finish('Sign-in expired; restart authorization.',true),timeoutMs);
    return {url:started.url, done,
      cancel:()=>finish('Sign-in cancelled; an in-flight save may require reconciliation.',true)};
  } catch {
    server.close();
    for (const socket of sockets) socket.destroy();
    throw new AuthError('Local sign-in could not be started.');
  }
}
