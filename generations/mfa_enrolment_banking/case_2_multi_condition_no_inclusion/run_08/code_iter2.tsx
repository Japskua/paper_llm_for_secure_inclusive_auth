
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const PORT = Number(Bun.env.PORT || 3000);
const COOKIE = "__Host-mfa_session";
const IDLE = 20 * 60_000, ABS = 8 * 60 * 60_000, LOCK = 15 * 60_000, MAX = 5;
const NONCE = "mfa-enrolment-ui-v1";

const securityHeaders = {
  "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${NONCE}'; style-src 'nonce-${NONCE}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Cache-Control": "no-store, private",
};

type Encrypted = { iv: string; ciphertext: string };
type Session = { id:string; csrf:string; accountId?:string; identityVerified:boolean; createdAt:number; lastSeen:number; failedMfa:number; mfaLockedUntil:number };
type Pending = { secret:Encrypted; expiresAt:number; used:boolean };
type Account = {
  id:string; email:string; passwordHash:string; phone:string;
  identityCode?:string; identityExpiresAt?:number; identityUsed?:boolean;
  identityFailures:number; identityLockedUntil:number;
  loginFailures:number; loginLockedUntil:number;
  mfaSecret?:Encrypted; pending?:Pending; backupCodes:{digest:string;used:boolean}[];
  mfaEnabled:boolean; mfaLockedUntil:number;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const keyPromise = crypto.subtle.generateKey({ name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]);
const pepper = randomText(32);

function bytes(n:number) { const x=new Uint8Array(n); crypto.getRandomValues(x); return x; }
function b64(x:Uint8Array) { return btoa(String.fromCharCode(...x)).replaceAll("+","-").replaceAll("/","_").replaceAll("=",""); }
function unb64(s:string) { return Uint8Array.from(atob(s.replaceAll("-","+").replaceAll("_","/")), x=>x.charCodeAt(0)); }
function randomText(n=32) { return b64(bytes(n)); }
function six() { return String(new DataView(bytes(4).buffer).getUint32(0)%1_000_000).padStart(6,"0"); }
function b32(x:Uint8Array) { let o="",v=0,b=0; for(const n of x){v=(v<<8)|n;b+=8;while(b>=5){o+="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(v>>>(b-5))&31];b-=5;}} return b?o+"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(v<<(5-b))&31]:o; }
function deb32(s:string):Uint8Array|null { s=s.replaceAll(/\s/g,"").toUpperCase();if(!/^[A-Z2-7]{16,128}$/.test(s))return null;let v=0,b=0,o:number[]=[];for(const c of s){v=(v<<5)|"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c);b+=5;if(b>=8){o.push((v>>>(b-8))&255);b-=8;}}return Uint8Array.from(o); }
async function hash(s:string) { return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",encoder.encode(s))),x=>x.toString(16).padStart(2,"0")).join(""); }
function equal(a:string,b:string) { let d=a.length^b.length,l=Math.max(a.length,b.length);for(let i=0;i<l;i++)d|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);return d===0; }
async function encrypt(value:string):Promise<Encrypted> { const iv=bytes(12),k=await keyPromise,c=await crypto.subtle.encrypt({name:"AES-GCM",iv},k,encoder.encode(value));return {iv:b64(iv),ciphertext:b64(new Uint8Array(c))}; }
async function decrypt(value:Encrypted) { return decoder.decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(value.iv)},await keyPromise,unb64(value.ciphertext))); }
async function otp(secret:string) {
  const raw=deb32(secret); if(!raw)return "000000";
  const msg=new Uint8Array(8);new DataView(msg.buffer).setUint32(4,Math.floor(Date.now()/30000),false);
  const key=await crypto.subtle.importKey("raw",raw,{name:"HMAC",hash:"SHA-1"},false,["sign"]);
  const sig=new Uint8Array(await crypto.subtle.sign("HMAC",key,msg)), off=sig[19]&15;
  return String((((sig[off]&127)<<24)|(sig[off+1]<<16)|(sig[off+2]<<8)|sig[off+3])%1_000_000).padStart(6,"0");
}
const PASSWORD_HASH = await hash("BankPass!9");
accounts.set("acct_marcus",{id:"acct_marcus",email:"marcus@example.test",passwordHash:PASSWORD_HASH,phone:"+15551234567",identityFailures:0,identityLockedUntil:0,loginFailures:0,loginLockedUntil:0,backupCodes:[],mfaEnabled:false,mfaLockedUntil:0});

function cookie(id:string) { return `${COOKIE}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABS/1000}`; }
function expired() { return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`; }
function newSession(accountId?:string) { const now=Date.now(),s:Session={id:randomText(),csrf:randomText(),accountId,identityVerified:false,createdAt:now,lastSeen:now,failedMfa:0,mfaLockedUntil:0};sessions.set(s.id,s);return s; }
function getCookies(r:Request) { const o:Record<string,string>={};for(const p of (r.headers.get("cookie")||"").split(";")){const i=p.indexOf("=");if(i>0)o[p.slice(0,i).trim()]=p.slice(i+1).trim();}return o; }
function session(r:Request) { const s=sessions.get(getCookies(r)[COOKIE]);if(!s)return null;const n=Date.now();if(n-s.lastSeen>IDLE||n-s.createdAt>ABS){sessions.delete(s.id);return null;}s.lastSeen=n;return s; }
function trusted(r:Request) { const o=r.headers.get("origin");try{const u=new URL(o||""),q=new URL(r.url);return u.protocol==="https:"&&["localhost","127.0.0.1","[::1]"].includes(u.hostname)&&u.origin===q.origin;}catch{return false;} }
function headers(r:Request,x:Record<string,string>={}) { const h=new Headers({...securityHeaders,...x});if(r.headers.get("origin")&&trusted(r)){h.set("Access-Control-Allow-Origin",r.headers.get("origin")!);h.set("Access-Control-Allow-Credentials","true");h.set("Vary","Origin");}return h; }
function out(r:Request,status:number,data:unknown,x:Record<string,string>={}) { return new Response(JSON.stringify(data),{status,headers:headers(r,{"Content-Type":"application/json; charset=utf-8",...x})}); }
function fail(r:Request,status=400) { return out(r,status,{ok:false,message:"We could not complete that request. Please try again."}); }
async function body(r:Request):Promise<Record<string,unknown>|null> { if(Number(r.headers.get("content-length")||0)>4096)return null;try{const x=await r.json();return x&&typeof x==="object"&&!Array.isArray(x)?x as Record<string,unknown>:null;}catch{return null;} }
function csrf(r:Request,s:Session) { const t=r.headers.get("x-csrf-token");return !!t&&/^[A-Za-z0-9_-]{40,64}$/.test(t)&&equal(t,s.csrf)&&trusted(r); }
function email(x:unknown):x is string{return typeof x==="string"&&/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(x);}
function phone(x:unknown):x is string{return typeof x==="string"&&/^\+[1-9][0-9]{7,14}$/.test(x);}
function code(x:unknown):x is string{return typeof x==="string"&&/^[0-9]{6}$/.test(x);}
function recovery(x:unknown):x is string{return typeof x==="string"&&/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(x);}

/* Security Evaluation 1: authenticated ownership is session-derived; no client account IDs are accepted. */
function requireAuthenticated(r:Request, checkCsrf=false):{session:Session;account:Account}|null {
  const s=session(r); if(!s?.accountId)return null;
  const a=accounts.get(s.accountId); if(!a||checkCsrf&&!csrf(r,s))return null;
  return {session:s,account:a};
}
/* Identity verification is additionally required only for MFA settings/provisioning operations. */
function requireIdentityVerified(r:Request, checkCsrf=false) {
  const required=requireAuthenticated(r,checkCsrf);
  return required?.session.identityVerified ? required : null;
}
function mfaLocked(s:Session,a:Account) { return s.mfaLockedUntil>Date.now()||a.mfaLockedUntil>Date.now(); }
function failMfa(s:Session,a:Account) { if(++s.failedMfa>=MAX){s.mfaLockedUntil=Date.now()+LOCK;a.mfaLockedUntil=Date.now()+LOCK;} }
function codes() { return Array.from({length:8},()=>{const v=b64(bytes(9)).toUpperCase().replaceAll(/[^A-Z0-9]/g,"X").padEnd(12,"A");return `${v.slice(0,4)}-${v.slice(4,8)}-${v.slice(8,12)}`;}); }
async function setCodes(a:Account) { const c=codes();a.backupCodes=await Promise.all(c.map(async x=>({digest:await hash(`${pepper}:${x}`),used:false})));return c; }

const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Northstar Bank MFA</title>
<style nonce="${NONCE}">:root{--n:#102a43;--b:#1261a0;--p:#edf6ff;--i:#172b3a;--e:#a12828}*{box-sizing:border-box}body{margin:0;background:#f2f6f8;color:var(--i);font:18px/1.5 Arial,sans-serif}header{background:var(--n);color:white;padding:1rem max(1rem,calc((100% - 680px)/2))}.wrap{max-width:680px;margin:auto;padding:1rem}main{background:#fff;padding:1.2rem;border-radius:12px;margin-top:1rem;box-shadow:0 2px 10px #102a4315}h1{font-size:1.55rem;line-height:1.2}label{display:block;font-weight:bold;margin-top:1rem}input{display:block;width:100%;font:inherit;padding:.65rem;margin-top:.25rem;border:2px solid #758897;border-radius:7px}button{font:inherit;font-weight:bold;background:var(--b);color:white;border:0;border-radius:7px;padding:.7rem 1rem;margin:.9rem .4rem 0 0}.secondary{background:#dfe8ed;color:var(--i)}.danger{background:var(--e)}.hint,.warning{padding:.8rem;margin:1rem 0;background:var(--p);border-left:5px solid var(--b)}.warning{background:#fff4dc;border-color:#8a5000}.error{color:var(--e);font-weight:bold}.secret,.logs pre{font-family:monospace;overflow-wrap:anywhere}.secret{padding:.7rem;background:#f3f5f6;border:1px dashed #9aa}.codes{font-family:monospace;columns:2}.logs{margin:1rem 0;border:1px solid #bcc;border-radius:8px}.logs h2{font-size:1rem;margin:0;padding:.6rem;background:#e9f0f5}.logs pre{margin:0;padding:.7rem;max-height:220px;overflow:auto;font-size:14px;white-space:pre-wrap}@media(max-width:420px){body{font-size:17px}.wrap{padding:.7rem}main{padding:1rem}.codes{columns:1}button{width:100%;margin-right:0}}</style></head>
<body><header><strong>Northstar Bank</strong><br><small>Secure MFA enrolment</small></header><div class="wrap"><main id="app" aria-live="polite">Loading…</main><section class="logs"><h2>Logs</h2><pre id="logs">Secure test log ready.</pre></section><footer>Never share a passcode or recovery code.</footer></div>
<script nonce="${NONCE}">(()=>{"use strict";let csrf="",page="signin",sent=false,provision=null,shown=null;const app=document.querySelector("#app"),logs=document.querySelector("#logs");
function log(n,v){const x="[TEST ONLY] "+n+": "+v;console.log(x);logs.textContent+="\\\\n"+x;logs.scrollTop=logs.scrollHeight}
async function api(path,opt={}){const r=await fetch(path,{method:opt.method||"GET",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:opt.body?JSON.stringify(opt.body):undefined});let d;try{d=await r.json()}catch{d={message:"We could not complete that request. Please try again."}}if(!r.ok)throw Error(d.message);return d}
function shell(t,c){app.innerHTML="<h1>"+t+"</h1><div id=status></div>"+c}function status(t,b){const n=document.querySelector("#status");n.textContent=t;n.className=b?"error":""}function bind(q,f){const n=document.querySelector(q);if(n)n.addEventListener("submit",f)}function nav(p){page=p;location.hash=p;render()}
function render(){if(page==="signin"){shell("Sign in to begin",'<p>Enrol MFA before authorising higher-value payments.</p><form id=sign><label>Email address<input name=email type=email required></label><label>Password<input name=password type=password required></label><button>Sign in</button></form><div class=hint><b>Academic demo account:</b><br>marcus@example.test<br>Password: BankPass!9</div>');bind("#sign",async e=>{e.preventDefault();let f=new FormData(e.currentTarget);try{let d=await api("/api/signin",{method:"POST",body:{email:String(f.get("email")||""),password:String(f.get("password")||"")}});csrf=d.csrf;sent=false;nav("identity")}catch(x){status(x.message,true)}})}
else if(page==="identity"){shell("Verify your identity",'<p>Confirm your mobile number. The test code is shown in Logs.</p><form id=send><label>Mobile number<input name=phone placeholder="+15551234567" required></label><button>Send verification code</button></form>'+(sent?'<form id=identity><label>6-digit verification code<input name=code inputmode=numeric required></label><button>Verify identity</button></form>':""));bind("#send",async e=>{e.preventDefault();try{let d=await api("/api/identity/send",{method:"POST",body:{phone:String(new FormData(e.currentTarget).get("phone")||"")}});sent=true;log("Mock identity verification code",d.mockCode);render()}catch(x){status(x.message,true)}});bind("#identity",async e=>{e.preventDefault();try{await api("/api/identity/verify",{method:"POST",body:{code:String(new FormData(e.currentTarget).get("code")||"")}});nav("setup")}catch(x){status(x.message,true)}})}
else if(page==="setup"){shell("Set up an authenticator",!provision?'<p>Create a setup secret and add it manually to your authenticator app.</p><button id=start>Create authenticator secret</button>':'<div class=warning><b>Save this setup secret in your authenticator now.</b></div><p class=secret id=secret></p><button id=continue>Continue to verification</button>');if(!provision)document.querySelector("#start").onclick=async()=>{try{provision=await api("/api/mfa/provision",{method:"POST",body:{}});log("Mock authenticator provisioning secret",provision.secret);log("Mock current authenticator OTP",provision.mockOtp);render()}catch(x){status(x.message,true)}};else{document.querySelector("#secret").textContent=provision.secret;document.querySelector("#continue").onclick=()=>nav("verify")}}
else if(page==="verify"){shell("Verify your authenticator",'<form id=mfa><label>Authenticator code<input name=otp inputmode=numeric required></label><label>Manual setup secret (optional)<input name=manualSecret></label><button>Enable MFA</button><button type=button id=back class=secondary>Back</button></form>');document.querySelector("#back").onclick=()=>nav("setup");bind("#mfa",async e=>{e.preventDefault();let f=new FormData(e.currentTarget);try{let d=await api("/api/mfa/verify",{method:"POST",body:{otp:String(f.get("otp")||""),manualSecret:String(f.get("manualSecret")||"")}});shown=d.codes;provision=null;log("Mock recovery codes",d.codes.join(", "));nav("backup")}catch(x){status(x.message,true)}})}
else if(page==="backup"){shell("Save your recovery codes",'<div class=warning><b>These codes are shown once.</b> Store them safely.</div><ul class=codes id=codes></ul><button id=done>I have saved these codes</button>');for(const x of shown||[]){let n=document.createElement("li");n.textContent=x;document.querySelector("#codes").append(n)}document.querySelector("#done").onclick=()=>{shown=null;nav("settings")}}
else{shell("MFA settings",'<p id=state>Loading settings…</p><form id=recovery><label>Test a recovery code<input name=code placeholder="ABCD-EFGH-IJKL"></label><button class=secondary>Verify recovery code</button></form><button id=regen>Regenerate recovery codes</button><button id=logout class=danger>Log out</button>');api("/api/mfa/status").then(d=>document.querySelector("#state").textContent=d.enabled?"MFA is enabled. "+d.backupRemaining+" recovery codes remain.":"MFA is not enabled.").catch(()=>nav("signin"));bind("#recovery",async e=>{e.preventDefault();try{await api("/api/mfa/recovery/verify",{method:"POST",body:{recoveryCode:String(new FormData(e.currentTarget).get("code")||"").toUpperCase()}});status("Recovery code accepted and used.")}catch(x){status(x.message,true)}});document.querySelector("#regen").onclick=async()=>{try{let d=await api("/api/mfa/recovery/regenerate",{method:"POST",body:{}});shown=d.codes;log("Mock regenerated recovery codes",d.codes.join(", "));nav("backup")}catch(x){status(x.message,true)}};document.querySelector("#logout").onclick=async()=>{try{await api("/api/logout",{method:"POST",body:{}})}catch{}csrf="";provision=null;shown=null;await init();nav("signin")}}}
async function init(){try{let c=await api("/api/csrf");csrf=c.csrf;let s=await api("/api/session");if(s.signedIn)page=s.identityVerified?(s.mfaEnabled?"settings":"setup"):"identity"}catch{page="signin"}}window.addEventListener("hashchange",()=>{let p=location.hash.slice(1);if(["signin","identity","setup","verify","backup","settings"].includes(p)){page=p;render()}});init().then(render)})()</script></body></html>`;

async function route(r:Request):Promise<Response> {
  const path=new URL(r.url).pathname;
  if(r.method==="OPTIONS"){if(!trusted(r))return fail(r,403);return new Response(null,{status:204,headers:headers(r,{"Access-Control-Allow-Methods":"GET, POST, OPTIONS","Access-Control-Allow-Headers":"Content-Type, X-CSRF-Token"})});}
  if(!path.startsWith("/api/")) {
    if(r.method==="GET"&&new Set(["/","/signin","/identity","/setup","/verify","/backup","/settings"]).has(path))return new Response(html,{headers:headers(r,{"Content-Type":"text/html; charset=utf-8"})});
    return new Response("Not found",{status:404,headers:headers(r,{"Content-Type":"text/plain"})});
  }
  if(path==="/api/csrf"&&r.method==="GET"){let s=session(r);if(!s)s=newSession();return out(r,200,{ok:true,csrf:s.csrf},{"Set-Cookie":cookie(s.id)});}
  if(path==="/api/session"&&r.method==="GET"){const s=session(r),a=s?.accountId&&accounts.get(s.accountId);return out(r,200,{ok:true,signedIn:!!a,identityVerified:!!s?.identityVerified,mfaEnabled:!!a?.mfaEnabled});}

  if(path==="/api/signin"&&r.method==="POST"){
    const s=session(r),x=await body(r);if(!s||!x||!csrf(r,s)||!email(x.email)||typeof x.password!=="string"||x.password.length<8||x.password.length>128)return fail(r);
    const a=accounts.get("acct_marcus")!;
    /* Security Evaluation 5: account-scoped sign-in throttling survives session replacement. */
    if(a.loginLockedUntil>Date.now())return fail(r,429);
    const valid=equal(x.email.toLowerCase(),a.email)&&equal(await hash(x.password),a.passwordHash);
    if(!valid){if(++a.loginFailures>=MAX)a.loginLockedUntil=Date.now()+LOCK;return fail(r,a.loginLockedUntil>Date.now()?429:401);}
    a.loginFailures=0;a.loginLockedUntil=0;sessions.delete(s.id);const fresh=newSession(a.id);return out(r,200,{ok:true,csrf:fresh.csrf},{"Set-Cookie":cookie(fresh.id)});
  }

  if(path==="/api/identity/send"&&r.method==="POST"){
    const q=requireAuthenticated(r,true),x=await body(r);
    if(!q||!x||!phone(x.phone))return fail(r,403);
    if(q.account.identityLockedUntil>Date.now())return fail(r,429);
    if(!equal(x.phone,q.account.phone))return fail(r);
    const c=six();q.account.identityCode=c;q.account.identityExpiresAt=Date.now()+5*60_000;q.account.identityUsed=false;return out(r,200,{ok:true,mockCode:c});
  }
  if(path==="/api/identity/verify"&&r.method==="POST"){
    const q=requireAuthenticated(r,true),x=await body(r);
    if(!q||!x||!code(x.code))return fail(r,403);
    const a=q.account;if(a.identityLockedUntil>Date.now())return fail(r,429);
    const valid=!!a.identityCode&&!a.identityUsed&&!!a.identityExpiresAt&&a.identityExpiresAt>Date.now()&&equal(x.code,a.identityCode);
    /* Security Evaluation 5: identity failures and lock are account scoped across new sessions. */
    if(!valid){if(++a.identityFailures>=MAX)a.identityLockedUntil=Date.now()+LOCK;return fail(r,a.identityLockedUntil>Date.now()?429:400);}
    a.identityCode=undefined;a.identityUsed=true;a.identityFailures=0;a.identityLockedUntil=0;q.session.identityVerified=true;return out(r,200,{ok:true});
  }

  if(path==="/api/mfa/status"&&r.method==="GET"){const q=requireIdentityVerified(r);if(!q)return fail(r,403);return out(r,200,{ok:true,enabled:q.account.mfaEnabled,backupRemaining:q.account.backupCodes.filter(x=>!x.used).length});}
  if(path==="/api/mfa/provision"&&r.method==="POST"){
    const q=requireIdentityVerified(r,true);if(!q||mfaLocked(q.session,q.account))return fail(r,403);if(q.account.mfaEnabled)return fail(r);
    const secret=b32(bytes(20));q.account.pending={secret:await encrypt(secret),expiresAt:Date.now()+10*60_000,used:false};return out(r,200,{ok:true,secret,mockOtp:await otp(secret)});
  }
  if(path==="/api/mfa/verify"&&r.method==="POST"){
    const q=requireIdentityVerified(r,true),x=await body(r);if(!q||!x||!code(x.otp)||typeof x.manualSecret!=="string"||x.manualSecret.length>128||mfaLocked(q.session,q.account))return fail(r,403);
    const p=q.account.pending;if(!p||p.used||p.expiresAt<=Date.now())return fail(r);const secret=await decrypt(p.secret),manual=x.manualSecret.replaceAll(/\s/g,"").toUpperCase();
    if(!(manual===""||(deb32(manual)&&equal(manual,secret)))||!equal(x.otp,await otp(secret))){failMfa(q.session,q.account);return fail(r,mfaLocked(q.session,q.account)?429:400);}
    p.used=true;q.account.mfaSecret=p.secret;q.account.pending=undefined;q.account.mfaEnabled=true;q.session.failedMfa=0;return out(r,200,{ok:true,codes:await setCodes(q.account)});
  }
  if(path==="/api/mfa/recovery/regenerate"&&r.method==="POST"){const q=requireIdentityVerified(r,true);if(!q||!q.account.mfaEnabled||mfaLocked(q.session,q.account))return fail(r,403);return out(r,200,{ok:true,codes:await setCodes(q.account)});}
  if(path==="/api/mfa/recovery/verify"&&r.method==="POST"){
    const q=requireIdentityVerified(r,true),x=await body(r);if(!q||!x||!recovery(x.recoveryCode)||!q.account.mfaEnabled||mfaLocked(q.session,q.account))return fail(r,403);
    const d=await hash(`${pepper}:${x.recoveryCode}`),m=q.account.backupCodes.find(v=>!v.used&&equal(v.digest,d));if(!m){failMfa(q.session,q.account);return fail(r,mfaLocked(q.session,q.account)?429:400);}m.used=true;q.session.failedMfa=0;return out(r,200,{ok:true});
  }
  if(path==="/api/logout"&&r.method==="POST"){const s=session(r);if(!s||!csrf(r,s))return fail(r,403);sessions.delete(s.id);return out(r,200,{ok:true},{"Set-Cookie":expired()});}
  return fail(r,404);
}

Bun.serve({
  port:PORT, hostname:"0.0.0.0",
  tls:{cert:Bun.file("certs/cert.pem"),key:Bun.file("certs/key.pem")},
  async fetch(r){try{return await route(r)}catch{return fail(r,500)}},
});
console.log(`MFA enrolment server listening securely on https://localhost:${PORT}`);
