#!/usr/bin/env node
/** Explicit local consent command; importing this module never starts sign-in. */
import { pathToFileURL } from 'node:url';
import path from 'node:path';

export function options(argv) {
  const allowed=new Set(['--host-id','--directory','--app-name','--client-id','--subject']);
  const values={};
  for(let i=0;i<argv.length;i+=2) {
    const key=argv[i], value=argv[i+1];
    if(!allowed.has(key) || key in values || !value || value.startsWith('--')) throw new Error('Invalid sign-in options');
    values[key]=value;
  }
  if(!values['--host-id'] || !values['--directory'] || !values['--app-name'] || !path.isAbsolute(values['--directory'])) throw new Error('Explicit persisted host ID, private absolute directory and application name required');
  if(Boolean(values['--client-id'])!==Boolean(values['--subject'])) throw new Error('Returning account requires both client ID and subject');
  return {hostId:values['--host-id'],directory:values['--directory'],appName:values['--app-name'],
    ...(values['--client-id']?{clientId:values['--client-id'],subject:values['--subject']}:{})};
}

export async function main(argv,{start,output=console.log,signals=process}={}) {
  if(argv.length===1 && argv[0]==='--help') {
    output('Usage: node login-cli.mjs --host-id PERSISTED_UUID_URN --directory PRIVATE_ABSOLUTE_DIRECTORY --app-name APPLICATION_NAME [--client-id ISSUED_CLIENT --subject VERIFIED_SUBJECT]');
    output('Starts local ChatGPT consent only. No inference, API-key fallback or automatic browser launch. Keep the host ID stable.');
    return 0;
  }
  let attempt, onCancel;
  try {
    const config=options(argv);
    const startLogin=start??(await import('./login.mjs')).startLogin;
    attempt=await startLogin(config);
    onCancel=()=>attempt.cancel();
    signals.once('SIGINT',onCancel); signals.once('SIGTERM',onCancel);
    output('Continue with ChatGPT using this one-time authorization URL in your local browser:');
    output(attempt.url);
    await attempt.done;
    output('ChatGPT sign-in verified and saved. No model request was made.');
    return 0;
  } catch {
    output('Sign-in did not complete. No model request was made. Check the private credential record before retrying an uncertain save.');
    return 1;
  } finally {
    if(onCancel){signals.removeListener('SIGINT',onCancel);signals.removeListener('SIGTERM',onCancel);}
    if(attempt) attempt.cancel();
  }
}
if(process.argv[1] && import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode=await main(process.argv.slice(2));
}
