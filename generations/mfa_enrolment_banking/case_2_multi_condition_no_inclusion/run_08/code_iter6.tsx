
const enc = new TextEncoder(), dec = new TextDecoder();
const PORT = Number(Bun.env.PORT || 3000), COOKIE = "__Host-mfa_session";
const IDLE = 20 * 60_000, ABS = 8 * 60 * 60_000, LOCK = 15 * 60_000, MAX = 5;

function bytes(n:number){const a=new Uint8Array(n);crypto.getRandomValues(a);return a}
function b64(a:Uint8Array){return btoa(String.fromCharCode(...a)).replaceAll("+","-").replaceAll("/","_").replaceAll("=","")}
function unb64(s:string){return Uint8Array.from(atob(s.replaceAll("-","+").replaceAll("_","/")),x=>x.charCodeAt(0))}
function rnd(n=32){return b64(bytes(n))}
function b32(a:Uint8Array){let o="",v=0,b=0;for(const n of a){v=(v<<8)|n;b+=8;while(b>=5){o+="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(v>>>(b-5))&31];b-=5}}return b?o+"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[(v<<(5-b))&31]:o}
function deb32(s:string){s=s.replaceAll(/\s/g,"").toUpperCase();if(!/^[A-Z2-7]{16,128}$/.test(s))return null;let v=0,b=0,o:number[]=[];for(const c of s){v=(v<<5)|"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c);b+=5;if(b>=8){o.push((v>>>(b-8))&255);b-=8}}return Uint8Array.from(o)}
async function hash(s:string){return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(s))),x=>x.toString(16).padStart(2,"0")).join("")}
function same(a:string,b:string){let d=a.length^b.length;for(let i=0,l=Math.max(a.length,b.length);i<l;i++)d|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);return d===0}
function six(){return String(new DataView(bytes(4).buffer).getUint32(0)%1e6).padStart(6,"0")}
async function otp(secret:string){const raw=deb32(secret);if(!raw)return "000000";const msg=new Uint8Array(8);new DataView(msg.buffer).setUint32(4,Math.floor(Date.now()/30000),false);const k=await crypto.subtle.importKey("raw",raw,{name:"HMAC",hash:"SHA-1"},false,["sign"]);const s=new Uint8Array(await crypto.subtle.sign("HMAC",k,msg)),i=s[19]&15;return String((((s[i]&127)<<24)|(s[i+1]<<16)|(s[i+2]<<8)|s[i+3])%1e6).padStart(6,"0")}

type Enc={iv:string;ciphertext:string};
type Session={id:string;csrf:string;accountId?:string;identityVerified:boolean;createdAt:number;lastSeen:number;failedMfa:number;mfaLockedUntil:number;genericLoginFailures:number;genericLoginLockedUntil:number};
type Pending={secret:Enc;expiresAt:number;used:boolean};
type Account={id:string;email:string;passwordHash:string;phone:string;identityCode?:string;identityExpiresAt?:number;identityUsed?:boolean;identityFailures:number;identityLockedUntil:number;loginFailures:number;loginLockedUntil:number;mfaSecret?:Enc;pending?:Pending;backupCodes:{digest:string;used:boolean}[];mfaEnabled:boolean;mfaLockedUntil:number;recoveryCodeOperation:boolean};

const sessions=new Map<string,Session>(), accounts=new Map<string,Account>();
const keyPromise=crypto.subtle.generateKey({name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
const pepper=rnd();
async function encrypt(value:string):Promise<Enc>{const iv=bytes(12),c=await crypto.subtle.encrypt({name:"AES-GCM",iv},await keyPromise,enc.encode(value));return{iv:b64(iv),ciphertext:b64(new Uint8Array(c))}}
async function decrypt(v:Enc){return dec.decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(v.iv)},await keyPromise,unb64(v.ciphertext)))}
const PASSWORD_HASH=await hash("BankPass!9");
accounts.set("acct_marcus",{id:"acct_marcus",email:"marcus@example.test",passwordHash:PASSWORD_HASH,phone:"+15551234567",identityFailures:0,identityLockedUntil:0,loginFailures:0,loginLockedUntil:0,backupCodes:[],mfaEnabled:false,mfaLockedUntil:0,recoveryCodeOperation:false});

/* Requirements 2/3: HTTPS security headers and secure HttpOnly session cookies. */
function sec(n:string){return{"Content-Security-Policy":`default-src 'self'; script-src 'nonce-${n}'; style-src 'nonce-${n}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,"Strict-Transport-Security":"max-age=31536000; includeSubDomains","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Cache-Control":"no-store, private"}}
function trusted(r:Request){const o=r.headers.get("origin");if(!o)return false;try{const a=new URL(o),b=new URL(r.url);return a.protocol==="https:"&&a.origin===b.origin&&["localhost","127.0.0.1","[::1]"].includes(a.hostname)}catch{return false}}
function hs(r:Request,extra:Record<string,string>={},n=rnd(18)){const h=new Headers({...sec(n),...extra});if(r.headers.get("origin")&&trusted(r)){h.set("Access-Control-Allow-Origin",r.headers.get("origin")!);h.set("Access-Control-Allow-Credentials","true");h.set("Vary","Origin")}return h}
function json(r:Request,status:number,data:unknown,extra:Record<string,string>={}){return new Response(JSON.stringify(data),{status,headers:hs(r,{"Content-Type":"application/json; charset=utf-8",...extra})})}
function fail(r:Request,status=400){return json(r,status,{ok:false,message:"We could not complete that request. Please try again."})}
function cookie(id:string){return`${COOKIE}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABS/1000}`}
function clearCookie(){return`${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`}
function cookies(r:Request){const o:Record<string,string>={};for(const x of (r.headers.get("cookie")||"").split(";")){const i=x.indexOf("=");if(i>0)o[x.slice(0,i).trim()]=x.slice(i+1).trim()}return o}
function fresh(accountId?:string){const n=Date.now(),s:Session={id:rnd(),csrf:rnd(),accountId,identityVerified:false,createdAt:n,lastSeen:n,failedMfa:0,mfaLockedUntil:0,genericLoginFailures:0,genericLoginLockedUntil:0};sessions.set(s.id,s);return s}
function session(r:Request){const s=sessions.get(cookies(r)[COOKIE]);if(!s)return null;const n=Date.now();if(n-s.lastSeen>IDLE||n-s.createdAt>ABS){sessions.delete(s.id);return null}s.lastSeen=n;return s}
async function body(r:Request){if(Number(r.headers.get("content-length")||0)>4096)return null;try{const x=await r.json();return x&&typeof x==="object"&&!Array.isArray(x)?x as Record<string,unknown>:null}catch{return null}}
function csrf(r:Request,s:Session){const t=r.headers.get("x-csrf-token");return !!t&&/^[\w-]{40,64}$/.test(t)&&same(t,s.csrf)&&trusted(r)}
function email(x:unknown):x is string{return typeof x==="string"&&/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(x)}
function phone(x:unknown):x is string{return typeof x==="string"&&/^\+[1-9][0-9]{7,14}$/.test(x)}
function code(x:unknown):x is string{return typeof x==="string"&&/^\d{6}$/.test(x)}
function recovery(x:unknown):x is string{return typeof x==="string"&&/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(x)}
function auth(r:Request,needCsrf=false){const s=session(r),a=s?.accountId&&accounts.get(s.accountId);return s&&a&&(!needCsrf||csrf(r,s))?{session:s,account:a}:null}
function verified(r:Request,c=false){const q=auth(r,c);return q?.session.identityVerified?q:null}

/* Requirement 5: reset expired lock state before its next verification attempt. */
function resetLogin(a:Account){if(a.loginLockedUntil&&a.loginLockedUntil<=Date.now()){a.loginLockedUntil=0;a.loginFailures=0}}
function resetGenericLogin(s:Session){if(s.genericLoginLockedUntil&&s.genericLoginLockedUntil<=Date.now()){s.genericLoginLockedUntil=0;s.genericLoginFailures=0}}
function resetIdentity(a:Account){if(a.identityLockedUntil&&a.identityLockedUntil<=Date.now()){a.identityLockedUntil=0;a.identityFailures=0}}
function resetMfa(s:Session,a:Account){const n=Date.now();if(s.mfaLockedUntil&&s.mfaLockedUntil<=n){s.mfaLockedUntil=0;s.failedMfa=0}if(a.mfaLockedUntil&&a.mfaLockedUntil<=n)a.mfaLockedUntil=0}
function mfaLocked(s:Session,a:Account){resetMfa(s,a);return s.mfaLockedUntil>Date.now()||a.mfaLockedUntil>Date.now()}
function badMfa(s:Session,a:Account){if(++s.failedMfa>=MAX){const until=Date.now()+LOCK;s.mfaLockedUntil=until;a.mfaLockedUntil=until}}
function badIdentity(a:Account){if(++a.identityFailures>=MAX)a.identityLockedUntil=Date.now()+LOCK}
function badLogin(a:Account){if(++a.loginFailures>=MAX)a.loginLockedUntil=Date.now()+LOCK}
/* Unknown-principal throttling is session-oriented and never changes an account lock. */
function badGenericLogin(s:Session){if(++s.genericLoginFailures>=MAX)s.genericLoginLockedUntil=Date.now()+LOCK}
function makeCodes(){return Array.from({length:8},()=>{const x=b64(bytes(9)).toUpperCase().replaceAll(/[^A-Z0-9]/g,"X").padEnd(12,"A");return`${x.slice(0,4)}-${x.slice(4,8)}-${x.slice(8,12)}`})}
async function setCodes(a:Account){const c=makeCodes();a.backupCodes=await Promise.all(c.map(async x=>({digest:await hash(pepper+":"+x),used:false})));return c}

const page=(nonce:string)=>`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Bank MFA</title><style nonce="${nonce}">:root{--n:#102a43;--b:#1261a0;--e:#a12828}*{box-sizing:border-box}body{margin:0;background:#f2f6f8;color:#172b3a;font:18px/1.5 Arial,sans-serif}header{background:var(--n);color:#fff;padding:1rem max(1rem,calc((100% - 680px)/2))}.wrap{max-width:680px;margin:auto;padding:1rem}main{background:#fff;padding:1.2rem;border-radius:12px;margin-top:1rem}h1{font-size:1.55rem;line-height:1.2}label{display:block;font-weight:bold;margin-top:1rem}input{display:block;width:100%;font:inherit;padding:.65rem;margin-top:.25rem;border:2px solid #758897;border-radius:7px}button{font:inherit;font-weight:bold;background:var(--b);color:#fff;border:0;border-radius:7px;padding:.7rem 1rem;margin:.9rem .4rem 0 0}.secondary{background:#dfe8ed;color:#172b3a}.danger{background:var(--e)}.hint,.warning{padding:.8rem;margin:1rem 0;background:#edf6ff;border-left:5px solid var(--b)}.warning{background:#fff4dc;border-color:#8a5000}.error{color:var(--e);font-weight:bold}.secret,pre,.codes{font-family:monospace;overflow-wrap:anywhere}.secret{padding:.7rem;background:#f3f5f6}.codes{columns:2}.logs{margin:1rem 0;border:1px solid #bcc;border-radius:8px}.logs h2{font-size:1rem;margin:0;padding:.6rem;background:#e9f0f5}.logs pre{margin:0;padding:.7rem;max-height:220px;overflow:auto;font-size:14px;white-space:pre-wrap}@media(max-width:420px){body{font-size:17px}.wrap{padding:.7rem}main{padding:1rem}.codes{columns:1}button{width:100%;margin-right:0}}</style></head><body><header><strong>Northstar Bank</strong><br><small>Secure MFA enrolment</small></header><div class="wrap"><main id="app" aria-live="polite">Loading…</main><section class="logs"><h2>Logs</h2><pre id="logs">Secure test log ready.</pre></section><footer>Never share a passcode or recovery code.</footer></div><script nonce="${nonce}">(()=>{"use strict";let csrf="",p="signin",sent=false,provision=null,shown=null;const app=document.querySelector("#app"),logs=document.querySelector("#logs");function log(a,b){const x="[TEST ONLY] "+a+": "+b;console.log(x);logs.textContent+="\\\\n"+x;logs.scrollTop=logs.scrollHeight}async function api(path,o={}){const r=await fetch(path,{method:o.method||"GET",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:o.body?JSON.stringify(o.body):undefined});let d;try{d=await r.json()}catch{d={message:"We could not complete that request. Please try again."}}if(!r.ok)throw Error(d.message);return d}function shell(t,c){app.innerHTML="<h1>"+t+"</h1><div id=status></div>"+c}function status(t,e){const n=document.querySelector("#status");n.textContent=t;n.className=e?"error":""}function bind(q,f){const n=document.querySelector(q);if(n)n.addEventListener("submit",f)}function nav(x){p=x;location.hash=x;render()}function render(){if(p==="signin"){provision=null;shown=null;shell("Sign in to begin",'<p>Enrol MFA before authorising higher-value payments.</p><form id=sign><label>Email address<input name=email type=email required></label><label>Password<input name=password type=password required></label><button>Sign in</button></form><div class=hint><b>Academic demo account:</b><br>marcus@example.test<br>Password: BankPass!9</div>');bind("#sign",async e=>{e.preventDefault();const f=new FormData(e.currentTarget);try{const d=await api("/api/signin",{method:"POST",body:{email:String(f.get("email")||""),password:String(f.get("password")||"")}});csrf=d.csrf;sent=false;nav("identity")}catch(x){status(x.message,true)}})}else if(p==="identity"){shell("Verify your identity",'<p>Confirm your mobile number. The test code is shown in the Logs panel and browser developer console.</p><form id=send><label>Mobile number<input name=phone placeholder="+15551234567" required></label><button>Send verification code</button></form>'+(sent?'<form id=identity><label>6-digit verification code<input name=code inputmode=numeric required></label><button>Verify identity</button></form>':""));bind("#send",async e=>{e.preventDefault();try{const d=await api("/api/identity/send",{method:"POST",body:{phone:String(new FormData(e.currentTarget).get("phone")||"")}});sent=true;log("Mock identity verification code",d.mockCode);render()}catch(x){status(x.message,true)}});bind("#identity",async e=>{e.preventDefault();try{await api("/api/identity/verify",{method:"POST",body:{code:String(new FormData(e.currentTarget).get("code")||"")}});nav("setup")}catch(x){status(x.message,true)}})}else if(p==="setup"){shell("Set up an authenticator",!provision?'<p>Create a setup secret and add it manually to your authenticator app.</p><button id=start>Create authenticator secret</button>':'<div class=warning><b>Save this setup secret in your authenticator now.</b></div><p class=secret id=secret></p><button id=continue>Continue to verification</button>');if(!provision)document.querySelector("#start").onclick=async()=>{try{provision=await api("/api/mfa/provision",{method:"POST",body:{}});log("Mock authenticator provisioning secret",provision.secret);log("Mock current authenticator OTP",provision.mockOtp);render()}catch(x){status(x.message,true)}};else{document.querySelector("#secret").textContent=provision.secret;document.querySelector("#continue").onclick=()=>{provision=null;nav("verify")}}}else if(p==="verify"){shell("Verify your authenticator",'<form id=mfa><label>Authenticator code<input name=otp inputmode=numeric required></label><label>Manual setup secret (optional)<input name=manualSecret></label><button>Enable MFA</button></form>');bind("#mfa",async e=>{e.preventDefault();const f=new FormData(e.currentTarget);try{const d=await api("/api/mfa/verify",{method:"POST",body:{otp:String(f.get("otp")||""),manualSecret:String(f.get("manualSecret")||"")}});shown=d.codes;log("Mock recovery codes",d.codes.join(", "));nav("backup")}catch(x){status(x.message,true)}})}else if(p==="backup"){shell("Save your recovery codes",'<div class=warning><b>These codes are shown once.</b> Store them safely.</div><ul class=codes id=codes></ul><button id=done>I have saved these codes</button>');for(const x of shown||[]){const n=document.createElement("li");n.textContent=x;document.querySelector("#codes").append(n)}document.querySelector("#done").onclick=()=>{shown=null;nav("settings")}}else{provision=null;shown=null;shell("MFA settings",'<p id=state>Loading settings…</p><form id=recovery><label>Test a recovery code<input name=code placeholder="ABCD-EFGH-IJKL"></label><button class=secondary>Verify recovery code</button></form><button id=regen>Regenerate recovery codes</button><button id=logout class=danger>Log out</button>');api("/api/mfa/status").then(d=>document.querySelector("#state").textContent=d.enabled?"MFA is enabled. "+d.backupRemaining+" recovery codes remain.":"MFA is not enabled.").catch(()=>nav("signin"));bind("#recovery",async e=>{e.preventDefault();try{await api("/api/mfa/recovery/verify",{method:"POST",body:{recoveryCode:String(new FormData(e.currentTarget).get("code")||"").toUpperCase()}});status("Recovery code accepted and used.")}catch(x){status(x.message,true)}});document.querySelector("#regen").onclick=async()=>{try{const d=await api("/api/mfa/recovery/regenerate",{method:"POST",body:{}});shown=d.codes;log("Mock regenerated recovery codes",d.codes.join(", "));nav("backup")}catch(x){status(x.message,true)}};document.querySelector("#logout").onclick=async()=>{try{await api("/api/logout",{method:"POST",body:{}})}catch{}csrf="";provision=null;shown=null;await init();nav("signin")}}}async function init(){try{const c=await api("/api/csrf");csrf=c.csrf;const s=await api("/api/session");if(s.signedIn)p=s.identityVerified?(s.mfaEnabled?"settings":"setup"):"identity"}catch{p="signin"}}window.addEventListener("hashchange",()=>{const x=location.hash.slice(1);if(["signin","identity","setup","verify","backup","settings"].includes(x)){p=x;render()}});init().then(render)})()</script></body></html>`;

async function route(r:Request):Promise<Response>{
 const path=new URL(r.url).pathname;
 if(r.method==="OPTIONS"){if(!trusted(r))return fail(r,403);return new Response(null,{status:204,headers:hs(r,{"Access-Control-Allow-Methods":"GET, POST, OPTIONS","Access-Control-Allow-Headers":"Content-Type, X-CSRF-Token"})})}
 if(!path.startsWith("/api/")){if(r.method==="GET"&&new Set(["/","/signin","/identity","/setup","/verify","/backup","/settings"]).has(path)){const n=rnd(18);return new Response(page(n),{headers:hs(r,{"Content-Type":"text/html; charset=utf-8"},n)})}return new Response("Not found",{status:404,headers:hs(r,{"Content-Type":"text/plain"})})}
 if(path==="/api/csrf"&&r.method==="GET"){let s=session(r);if(!s)s=fresh();return json(r,200,{ok:true,csrf:s.csrf},{"Set-Cookie":cookie(s.id)})}
 if(path==="/api/session"&&r.method==="GET"){const s=session(r),a=s?.accountId&&accounts.get(s.accountId);return json(r,200,{ok:true,signedIn:!!a,identityVerified:!!s?.identityVerified,mfaEnabled:!!a?.mfaEnabled})}

 if(path==="/api/signin"&&r.method==="POST"){
  const s=session(r),x=await body(r);
  if(!s||!csrf(r,s))return fail(r,403);

  /* Requirement 5: every credential submission performs one equivalent hash operation.
     Account lock state is only read after that work, preventing lock/account timing shortcuts. */
  const syntactic=!!x&&email(x.email)&&typeof x.password==="string"&&x.password.length>=8&&x.password.length<=128;
  const passwordWork=syntactic?(x!.password as string):"invalid-credential-password-work";
  const submittedHash=await hash(passwordWork);

  const submittedEmail=syntactic?(x!.email as string).toLowerCase():"";
  const a=submittedEmail?Array.from(accounts.values()).find(v=>same(v.email,submittedEmail)):undefined;
  if(a){
   resetLogin(a);
   if(a.loginLockedUntil>Date.now())return fail(r,429);
   const valid=same(submittedHash,a.passwordHash);
   if(!valid){badLogin(a);return fail(r,a.loginLockedUntil>Date.now()?429:401)}
   a.loginFailures=0;a.loginLockedUntil=0;sessions.delete(s.id);const n=fresh(a.id);return json(r,200,{ok:true,csrf:n.csrf},{"Set-Cookie":cookie(n.id)})
  }

  /* Unknown or malformed principals use a separate session throttle and cannot lock Marcus. */
  resetGenericLogin(s);
  if(s.genericLoginLockedUntil>Date.now())return fail(r,429);
  badGenericLogin(s);
  return fail(r,s.genericLoginLockedUntil>Date.now()?429:401);
 }
 if(path==="/api/identity/send"&&r.method==="POST"){const q=auth(r,true),x=await body(r);if(!q)return fail(r,403);resetIdentity(q.account);if(q.account.identityLockedUntil>Date.now())return fail(r,429);if(!x||!phone(x.phone)||!same(x.phone,q.account.phone))return fail(r);const c=six();q.account.identityCode=c;q.account.identityExpiresAt=Date.now()+300000;q.account.identityUsed=false;return json(r,200,{ok:true,mockCode:c})}
 if(path==="/api/identity/verify"&&r.method==="POST"){
  const q=auth(r,true),x=await body(r);if(!q)return fail(r,403);const a=q.account;resetIdentity(a);if(a.identityLockedUntil>Date.now())return fail(r,429);
  const valid=!!x&&code(x.code)&&!!a.identityCode&&!a.identityUsed&&!!a.identityExpiresAt&&a.identityExpiresAt>Date.now()&&same(x.code,a.identityCode);
  if(!valid){badIdentity(a);return fail(r,a.identityLockedUntil>Date.now()?429:400)}
  a.identityCode=undefined;a.identityUsed=true;a.identityFailures=0;a.identityLockedUntil=0;q.session.identityVerified=true;return json(r,200,{ok:true})
 }
 if(path==="/api/mfa/status"&&r.method==="GET"){const q=verified(r);if(!q)return fail(r,403);return json(r,200,{ok:true,enabled:q.account.mfaEnabled,backupRemaining:q.account.backupCodes.filter(x=>!x.used).length})}
 if(path==="/api/mfa/provision"&&r.method==="POST"){const q=verified(r,true);if(!q)return fail(r,403);if(mfaLocked(q.session,q.account))return fail(r,429);if(q.account.mfaEnabled)return fail(r);const secret=b32(bytes(20));q.account.pending={secret:await encrypt(secret),expiresAt:Date.now()+600000,used:false};return json(r,200,{ok:true,secret,mockOtp:await otp(secret)})}
 if(path==="/api/mfa/verify"&&r.method==="POST"){
  const q=verified(r,true),x=await body(r);if(!q)return fail(r,403);const a=q.account,s=q.session;if(mfaLocked(s,a))return fail(r,429);
  const inputOK=!!x&&code(x.otp)&&typeof x.manualSecret==="string"&&x.manualSecret.length<=128;
  const p=a.pending;
  if(!inputOK||!p||p.used||p.expiresAt<=Date.now()||a.mfaEnabled||a.recoveryCodeOperation){badMfa(s,a);return fail(r,mfaLocked(s,a)?429:400)}
  p.used=true;
  try{
   const secret=await decrypt(p.secret),manual=(x!.manualSecret as string).replaceAll(/\s/g,"").toUpperCase();
   const valid=(manual===""||!!deb32(manual)&&same(manual,secret))&&same(x!.otp as string,await otp(secret));
   if(!valid){if(a.pending===p&&!a.mfaEnabled)p.used=false;badMfa(s,a);return fail(r,mfaLocked(s,a)?429:400)}
   /* Reserve recovery-code creation before awaiting hashes. This prevents stale concurrent sets. */
   a.recoveryCodeOperation=true;
   let codes:string[];
   try{codes=await setCodes(a)}finally{a.recoveryCodeOperation=false}
   a.mfaSecret=p.secret;a.pending=undefined;a.mfaEnabled=true;s.failedMfa=0;s.mfaLockedUntil=0;
   return json(r,200,{ok:true,codes})
  }catch{if(a.pending===p&&!a.mfaEnabled)p.used=false;a.recoveryCodeOperation=false;badMfa(s,a);return fail(r,mfaLocked(s,a)?429:400)}
 }
 if(path==="/api/mfa/recovery/regenerate"&&r.method==="POST"){
  const q=verified(r,true);if(!q||!q.account.mfaEnabled)return fail(r,403);if(mfaLocked(q.session,q.account))return fail(r,429);
  const a=q.account;
  /* Requirement: atomically reserve one regeneration operation per account. */
  if(a.recoveryCodeOperation)return fail(r,429);
  a.recoveryCodeOperation=true;
  try{
   const codes=await setCodes(a);
   return json(r,200,{ok:true,codes})
  }catch{return fail(r,400)}finally{a.recoveryCodeOperation=false}
 }
 if(path==="/api/mfa/recovery/verify"&&r.method==="POST"){
  const q=verified(r,true),x=await body(r);if(!q)return fail(r,403);const a=q.account,s=q.session;if(mfaLocked(s,a))return fail(r,429);
  if(!x||!recovery(x.recoveryCode)||!a.mfaEnabled){badMfa(s,a);return fail(r,mfaLocked(s,a)?429:400)}
  const d=await hash(pepper+":"+x.recoveryCode),m=a.backupCodes.find(v=>!v.used&&same(v.digest,d));
  if(!m){badMfa(s,a);return fail(r,mfaLocked(s,a)?429:400)}m.used=true;s.failedMfa=0;s.mfaLockedUntil=0;return json(r,200,{ok:true})
 }
 if(path==="/api/logout"&&r.method==="POST"){const s=session(r);if(!s||!csrf(r,s))return fail(r,403);sessions.delete(s.id);return json(r,200,{ok:true},{"Set-Cookie":clearCookie()})}
 return fail(r,404)
}

Bun.serve({port:PORT,hostname:"0.0.0.0",tls:{cert:Bun.file("certs/cert.pem"),key:Bun.file("certs/key.pem")},async fetch(r){try{return await route(r)}catch{return fail(r,500)}}});
console.log(`MFA enrolment server listening securely on https://localhost:${PORT}`);
