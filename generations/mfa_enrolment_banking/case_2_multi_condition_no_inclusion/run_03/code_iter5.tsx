
import { readFileSync, existsSync } from "node:fs";

/*
 MFA Enrolment System — Requirements 1–5
 In-memory demonstration only. No external calls and no server-side secret logging.
*/
const PORT = Number(process.env.PORT || 3000);
const HTTP_PORT = Number(process.env.HTTP_PORT || 3001);
const IDLE = 15 * 60_000, ABSOLUTE = 8 * 60 * 60_000, LIFE = 5 * 60_000, LOCK = 10 * 60_000, MAX = 5;
const ORIGINS = new Set([`https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`]);

type Session = {
  id:string; csrf:string; stage:"anonymous"|"identity"|"authenticated"; userId?:string;
  pendingUserId?:string; ownershipVerified?:boolean; identityKey?:string; identityHash?:string;
  identityExpires?:number; identityUsed?:boolean; createdAt:number; lastSeen:number;
};
type Attempt = { failures:number; lockedUntil?:number };
type Account = { id:string; email:string; phone:string; credentialHash:string };
type User = {
  id:string; email:string; phone:string; mfaEnabled:boolean; encryptedTotp?:string;
  pendingTotpExpires?:number; pendingTotpUsed?:boolean; accepted:Set<number>; totpFailures:number;
  totpLockedUntil?:number; backupHashes:Set<string>; backupFailures:number; backupLockedUntil?:number;
};

const sessions = new Map<string,Session>(), users = new Map<string,User>(), identityAttempts = new Map<string,Attempt>();
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const pepper = crypto.getRandomValues(new Uint8Array(32));

/*
 Requirement task: a password/ownership proof is checked before an identity code can
 ever grant account access. This is deliberately separate from the browser-console
 mock delivery code. The credential hash is generated at startup and never returned,
 logged, placed in a URL, or stored in the browser.
*/
const approvedAccounts:Account[] = [{ id:"account-marcus-demo", email:"marcus@example.test", phone:"", credentialHash:"" }];
let dummyCredentialHash = "";

const b64 = (b:Uint8Array) => Buffer.from(b).toString("base64url");
const token = (n=32) => b64(crypto.getRandomValues(new Uint8Array(n)));
async function hash(value:string) {
  const v = new TextEncoder().encode(value), all = new Uint8Array(pepper.length + v.length);
  all.set(pepper); all.set(v, pepper.length);
  return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", all)));
}
function constantEqual(a:string,b:string) {
  let d = a.length ^ b.length, length = Math.max(a.length,b.length);
  for(let i=0;i<length;i++) d |= (a.charCodeAt(i % a.length) || 0) ^ (b.charCodeAt(i % b.length) || 0);
  return d === 0;
}
async function encrypt(value:string) {
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await crypto.subtle.importKey("raw",encryptionKey,"AES-GCM",false,["encrypt"]);
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,new TextEncoder().encode(value));
  return `${b64(iv)}.${b64(new Uint8Array(cipher))}`;
}
async function decrypt(value:string) {
  const [iv,cipher]=value.split(".");
  const key=await crypto.subtle.importKey("raw",encryptionKey,"AES-GCM",false,["decrypt"]);
  const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:Buffer.from(iv,"base64url")},key,Buffer.from(cipher,"base64url"));
  return new TextDecoder().decode(plain);
}
function base32(bytes:Uint8Array) {
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let out="", buffer=0,bits=0;
  for(const byte of bytes){buffer=(buffer<<8)|byte;bits+=8;while(bits>=5){out+=alphabet[(buffer>>>(bits-5))&31];bits-=5;}}
  return bits ? out+alphabet[(buffer<<(5-bits))&31] : out;
}
function unbase32(value:string) {
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", clean=value.toUpperCase().replace(/[=\s]/g,"");
  let buffer=0,bits=0; const out:number[]=[];
  for(const c of clean){const n=alphabet.indexOf(c);if(n<0)throw Error("bad");buffer=(buffer<<5)|n;bits+=5;if(bits>=8){out.push((buffer>>>(bits-8))&255);bits-=8;}}
  return new Uint8Array(out);
}
async function totp(secret:string,counter:number) {
  const c=new Uint8Array(8); let n=BigInt(counter);
  for(let i=7;i>=0;i--){c[i]=Number(n&255n);n>>=8n;}
  const key=await crypto.subtle.importKey("raw",unbase32(secret),{name:"HMAC",hash:"SHA-1"},false,["sign"]);
  const mac=new Uint8Array(await crypto.subtle.sign("HMAC",key,c)), o=mac[mac.length-1]&15;
  const binary=((mac[o]&127)<<24)|(mac[o+1]<<16)|(mac[o+2]<<8)|mac[o+3];
  return String(binary%1_000_000).padStart(6,"0");
}
const counter=()=>Math.floor(Date.now()/30_000);

/*
 The mock delivery code is challenge/session-bound only. It contains no account
 identifier, and is returned for both approved and unapproved identifiers.
*/
async function identityCode(sessionId:string) {
  const key=await crypto.subtle.importKey("raw",pepper,{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const sig=new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(`identity-demo:${sessionId}`)));
  return String((((sig[0]<<24)|(sig[1]<<16)|(sig[2]<<8)|sig[3])>>>0)%1_000_000).padStart(6,"0");
}
function backupCode() {
  const chars="ABCDEFGHJKLMNPQRSTUVWXYZ23456789", bytes=crypto.getRandomValues(new Uint8Array(10));
  let out=""; for(let i=0;i<10;i++)out+=chars[bytes[i]%chars.length]+(i===4?"-":""); return out;
}
function email(v:unknown) { if(typeof v!=="string")return null;v=v.trim().toLowerCase();return /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(v)?v:null; }
function phone(v:unknown) { if(v===undefined||v==="")return "";if(typeof v!=="string")return null;v=v.replace(/[()\s.-]/g,"");return /^\+?[0-9]{7,15}$/.test(v)?v:null; }
function password(v:unknown) { return typeof v==="string"&&v.length>=8&&v.length<=128?v:null; }
function otp(v:unknown) { return typeof v==="string"&&/^\d{6}$/.test(v.replace(/\s/g,""))?v.replace(/\s/g,""):null; }
function backup(v:unknown) { if(typeof v!=="string")return null;v=v.trim().toUpperCase().replace(/\s/g,"");return /^[A-Z2-9]{5}-?[A-Z2-9]{5}$/.test(v)?v.replace("-",""):null; }

function cookie(req:Request,name:string) {
  const m=(req.headers.get("cookie")||"").match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`)); return m?decodeURIComponent(m[1]):undefined;
}
const sessionCookie=(id:string)=>`mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE/1000}`;
const clearCookie=()=>`mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
function newSession(stage:Session["stage"],userId?:string):Session {
  const s={id:token(),csrf:token(),stage,userId,createdAt:Date.now(),lastSeen:Date.now()} as Session;sessions.set(s.id,s);return s;
}
function active(req:Request) {
  const id=cookie(req,"mfa_session"),s=id&&sessions.get(id); if(!s)return null;
  if(Date.now()-s.lastSeen>IDLE||Date.now()-s.createdAt>ABSOLUTE){sessions.delete(s.id);return null;} s.lastSeen=Date.now();return s;
}
function rotate(old:Session,stage:Session["stage"],userId?:string) { sessions.delete(old.id);return newSession(stage,userId); }
function originOK(req:Request) { const o=req.headers.get("origin");return !o||ORIGINS.has(o); }
function hdr(req:Request,extra:HeadersInit={},nonce=token(18)) {
  const h=new Headers(extra);
  h.set("Content-Security-Policy",`default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`);
  h.set("Strict-Transport-Security","max-age=31536000; includeSubDomains");h.set("X-Content-Type-Options","nosniff");h.set("X-Frame-Options","DENY");
  h.set("Referrer-Policy","no-referrer");h.set("Cache-Control","no-store");
  const o=req.headers.get("origin");if(o&&originOK(req)){h.set("Access-Control-Allow-Origin",o);h.set("Access-Control-Allow-Credentials","true");h.set("Access-Control-Allow-Headers","Content-Type, X-CSRF-Token");h.set("Access-Control-Allow-Methods","GET, POST, OPTIONS");h.set("Vary","Origin");}
  return h;
}
function out(req:Request,body:unknown,status=200,extra:HeadersInit={}) { const h=hdr(req,extra);h.set("Content-Type","application/json; charset=utf-8");return new Response(JSON.stringify(body),{status,headers:h}); }
const fail=(req:Request,status=400)=>out(req,{ok:false,message:"We could not complete that request. Please try again."},status);
async function body(req:Request):Promise<any|null> {
  try { if(!(req.headers.get("content-type")||"").includes("application/json"))return null;const b=await req.json();return b&&typeof b==="object"&&!Array.isArray(b)&&!("userId"in b)&&!("accountId"in b)?b:null; }catch{return null;}
}
function csrf(req:Request,s:Session|null) { return !!s&&originOK(req)&&req.headers.get("x-csrf-token")===s.csrf; }
function state(s:Session,u?:User) { return {ok:true,csrf:s.csrf,authenticated:s.stage==="authenticated",stage:s.stage,email:u?.email||"",mfaEnabled:!!u?.mfaEnabled}; }
function attempt(key:string) {
  let a=identityAttempts.get(key);if(!a){a={failures:0};identityAttempts.set(key,a);}
  if(a.lockedUntil&&a.lockedUntil<=Date.now()){a.lockedUntil=undefined;a.failures=0;}return a;
}
function available(a:Attempt|User,field:"totp"|"backup"|"identity"="identity") {
  const lu=field==="identity"?(a as Attempt).lockedUntil:field==="totp"?(a as User).totpLockedUntil:(a as User).backupLockedUntil;
  if(lu&&lu<=Date.now()){if(field==="identity"){(a as Attempt).lockedUntil=undefined;(a as Attempt).failures=0;}else if(field==="totp"){(a as User).totpLockedUntil=undefined;(a as User).totpFailures=0;}else{(a as User).backupLockedUntil=undefined;(a as User).backupFailures=0;}}
  const now=field==="identity"?(a as Attempt).lockedUntil:field==="totp"?(a as User).totpLockedUntil:(a as User).backupLockedUntil;return !now||now<=Date.now();
}
function accountFor(e:string,p:string) { return approvedAccounts.find(a=>a.email===e&&(!p||a.phone===p)); }
function userFor(a:Account) {
  let u=users.get(a.id);if(!u){u={id:a.id,email:a.email,phone:a.phone,mfaEnabled:false,accepted:new Set(),totpFailures:0,backupHashes:new Set(),backupFailures:0};users.set(a.id,u);}return u;
}
function authenticated(req:Request) { const s=active(req);if(!s||s.stage!=="authenticated"||!s.userId)return null;const u=users.get(s.userId);return u?{session:s,user:u}:null; }
async function hashes(codes:string[]) { return new Set(await Promise.all(codes.map(c=>hash(backup(c)!)))); }

function page(nonce:string) { return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Northstar Bank · MFA enrolment</title><style nonce="${nonce}">
:root{--n:#112a46;--b:#075aa8;--p:#eef6ff;--i:#18212b;--g:#17653d}*{box-sizing:border-box}body{margin:0;background:#f4f7fa;color:var(--i);font:18px/1.55 Arial,sans-serif}main{max-width:620px;margin:auto;padding:18px 16px 34px}.brand{color:var(--n);font-weight:bold;font-size:1.25rem;margin:4px 0 24px}.card{background:#fff;border:1px solid #d6e0e8;border-radius:14px;padding:22px}h1{font-size:1.65rem;line-height:1.25;margin:0 0 12px;color:var(--n)}.hint{background:var(--p);border-left:5px solid var(--b);padding:12px 14px;border-radius:5px}.success{color:var(--g);font-weight:bold}.error{color:#a12622;font-weight:bold;min-height:1.6em}label{display:block;font-weight:bold;margin:17px 0 6px}input{width:100%;font:inherit;padding:12px;border:2px solid #8294a5;border-radius:8px}button{display:block;width:100%;cursor:pointer;border:0;border-radius:8px;background:var(--b);color:#fff;font:bold 1rem Arial;padding:14px 16px;margin-top:18px}.secondary{color:var(--n);background:#e6edf3}.linkbutton{background:none;color:var(--b);padding:8px 0;text-decoration:underline}.codebox,.codes li{font:bold 1.05rem monospace;letter-spacing:.08em;background:#f3f6f8;padding:14px;border-radius:8px;word-break:break-all}.codes{list-style:none;padding:0}.codes li{margin:7px 0;padding:9px 12px}.logs{margin-top:20px;border-top:1px solid #b9c6d2;padding-top:12px}.logs summary{font-weight:bold;color:var(--n)}pre{white-space:pre-wrap;word-break:break-word;background:#111c27;color:#dcecff;border-radius:8px;padding:11px;font:13px/1.4 monospace;max-height:180px;overflow:auto}@media(max-width:390px){body{font-size:17px}main{padding:12px}.card{padding:18px}}</style></head><body><main><div class="brand">Northstar Bank</div><section class="card" id="app" aria-live="polite">Loading secure enrolment…</section><details class="logs"><summary>Logs (test simulation)</summary><pre id="logs">Ready.</pre></details></main><script nonce="${nonce}">(()=>{"use strict";let csrf="",state={};const app=document.querySelector("#app"),logs=document.querySelector("#logs");function log(x){console.log(x);logs.textContent+="\\\\n"+x;logs.parentElement.open=true}async function api(path,method="GET",data){const o={method,credentials:"same-origin",headers:{}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(data||{})}const r=await fetch(path,o),j=await r.json();if(!r.ok||!j.ok)throw Error(j.message||"We could not complete that request.");if(j.csrf)csrf=j.csrf;return j}function err(f,x){f.querySelector(".error").textContent=x}
function signin(){app.innerHTML='<h1>Sign in to enrol MFA</h1><p>Set up an extra check before higher-value payments.</p><form id="f" novalidate><label>Email address<input name="email" type="email" autocomplete="email" required></label><label>Mobile number (optional)<input name="phone" type="tel" autocomplete="tel"></label><label>Account password<input name="password" type="password" autocomplete="current-password" required></label><p class="hint">Your password confirms ownership separately from the demonstration verification code.</p><p class="error" role="alert"></p><button>Continue</button></form>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const f=e.currentTarget;err(f,"");try{const r=await api("/api/auth/signin","POST",{email:f.email.value,phone:f.phone.value,password:f.password.value,destination:"/"});state=r;log("Mock identity verification code (testing only): "+r.testCode);identity()}catch(x){err(f,x.message)}}}
function identity(){app.innerHTML='<h1>Verify your identity</h1><p>Enter the six-digit verification code.</p><p class="hint">For this demonstration, open Logs to find the test code. The code alone does not sign in or reveal account information.</p><form id="f"><label>Verification code<input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6"></label><p class="error" role="alert"></p><button>Verify identity</button></form><button class="linkbutton" id="back">Use another email</button>';document.querySelector("#back").onclick=signin;document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const f=e.currentTarget;err(f,"");try{const r=await api("/api/auth/identity","POST",{code:f.code.value});state=r;r.mfaEnabled?status():setup()}catch(x){err(f,x.message)}}}
function setup(){app.innerHTML='<h1>Set up your authenticator</h1><p>Use an authenticator app to scan or manually enter the setup key.</p><p class="hint">Keep the setup key private.</p><button id="start">Show setup key</button><button class="secondary" id="logout">Log out</button>';document.querySelector("#start").onclick=async()=>{try{const r=await api("/api/mfa/begin","POST",{});log("Mock authenticator test code for TOTP counter "+r.testCounter+" (testing only): "+r.testCode);provision(r)}catch(x){app.querySelector(".hint").textContent=x.message}};document.querySelector("#logout").onclick=logout}
function provision(r){app.innerHTML='<h1>Add authenticator</h1><p>Enter this setup key manually in your authenticator app.</p><div class="codebox" id="secret"></div><p>Type: Time-based, 6 digits</p><form id="f"><label>Authenticator code<input name="code" inputmode="numeric" maxlength="6"></label><p class="error" role="alert"></p><button>Confirm authenticator</button></form>';document.querySelector("#secret").textContent=r.manualSecret;document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const f=e.currentTarget;err(f,"");try{const x=await api("/api/mfa/verify","POST",{code:f.code.value});codes(x.codes)}catch(x){err(f,x.message)}}}
function codes(list){log("Mock backup recovery codes (testing only): "+list.join(", "));app.innerHTML='<h1>Save your recovery codes</h1><p>Each code works once if you cannot use your authenticator.</p><ul class="codes" id="c"></ul><p class="hint">These codes will not be shown again. They are in Logs for testing.</p><button id="saved">I have saved my codes</button>';const ul=document.querySelector("#c");list.forEach(x=>{const li=document.createElement("li");li.textContent=x;ul.append(li)});document.querySelector("#saved").onclick=status}
function status(){app.innerHTML='<h1>MFA is active</h1><p class="success">Your authenticator and recovery codes are ready.</p><button id="recovery">Use a recovery code</button><button class="secondary" id="regen">Generate new recovery codes</button><button class="linkbutton" id="logout">Log out</button>';document.querySelector("#recovery").onclick=recovery;document.querySelector("#regen").onclick=async()=>{try{codes((await api("/api/backup/regenerate","POST",{})).codes)}catch(x){alert(x.message)}};document.querySelector("#logout").onclick=logout}
function recovery(){app.innerHTML='<h1>Confirm recovery code</h1><form id="f"><label>Recovery code<input name="code" autocomplete="one-time-code"></label><p class="error" role="alert"></p><button>Confirm recovery code</button></form><button class="linkbutton" id="cancel">Back to MFA status</button>';document.querySelector("#cancel").onclick=status;document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const f=e.currentTarget;err(f,"");try{await api("/api/backup/verify","POST",{code:f.code.value});app.innerHTML='<h1>Recovery code confirmed</h1><p class="success">That recovery code has been used and cannot be used again.</p><button id="go">Return to MFA status</button>';document.querySelector("#go").onclick=status}catch(x){err(f,x.message)}}}
async function logout(){try{await api("/api/logout","POST",{})}catch{}csrf="";signin()}async function boot(){try{const r=await api("/api/bootstrap");state=r;if(r.authenticated)r.mfaEnabled?status():setup();else if(r.stage==="identity")identity();else signin()}catch{app.textContent="Unable to start secure enrolment."}}boot()})()</script></body></html>`; }

async function api(req:Request,url:URL):Promise<Response> {
  if(req.method==="OPTIONS")return originOK(req)?new Response(null,{status:204,headers:hdr(req)}):fail(req,403);
  if(!originOK(req))return fail(req,403);
  if(url.pathname==="/api/bootstrap"&&req.method==="GET"){let s=active(req);if(!s)s=newSession("anonymous");return out(req,state(s,s.userId?users.get(s.userId):undefined),200,{"Set-Cookie":sessionCookie(s.id)});}
  if(url.pathname==="/api/auth/signin"&&req.method==="POST"){
    const s=active(req);if(!csrf(req,s))return fail(req,403);const b=await body(req),e=email(b?.email),p=phone(b?.phone),pw=password(b?.password);
    /* Equal cryptographic work for approved and unapproved identifiers prevents enumeration timing. */
    const candidate=accountFor(e||"",p===null?"":p), supplied=await hash(pw||""), expected=candidate?.credentialHash||dummyCredentialHash;
    const owns=!!e&&p!==null&&!!pw&&b?.destination!==undefined?b.destination==="/"&&constantEqual(supplied,expected):!!e&&p!==null&&!!pw&&constantEqual(supplied,expected);
    if(!e||p===null||(b?.destination!==undefined&&b.destination!=="/"))return fail(req);
    const key=await hash(`identity-attempt:${e}:${p}`), a=attempt(key), r=rotate(s!,"identity");
    r.pendingUserId=candidate?.id;r.ownershipVerified=owns&&!!candidate;r.identityKey=key;
    const code=await identityCode(r.id);r.identityHash=await hash(code);r.identityExpires=Date.now()+LIFE;void a;
    return out(req,{...state(r),testCode:code},200,{"Set-Cookie":sessionCookie(r.id)});
  }
  if(url.pathname==="/api/auth/identity"&&req.method==="POST"){
    const s=active(req);if(!csrf(req,s)||s!.stage!=="identity"||!s!.identityKey)return fail(req,403);
    const b=await body(req),code=otp(b?.code),a=attempt(s!.identityKey),candidateHash=code?await hash(code):"",account=s!.pendingUserId&&approvedAccounts.find(x=>x.id===s!.pendingUserId);
    const ok=!!code&&!!account&&!!s!.ownershipVerified&&sessions.get(s!.id)===s&&!s!.identityUsed&&available(a)&&!!s!.identityExpires&&s!.identityExpires>=Date.now()&&candidateHash===s!.identityHash;
    if(!ok){a.failures++;if(a.failures>=MAX)a.lockedUntil=Date.now()+LOCK;return fail(req);}
    s!.identityUsed=true;a.failures=0;a.lockedUntil=undefined;const u=userFor(account!),r=rotate(s!,"authenticated",u.id);return out(req,state(r,u),200,{"Set-Cookie":sessionCookie(r.id)});
  }
  const auth=authenticated(req);if(!auth)return fail(req,401);
  if(url.pathname==="/api/mfa/status"&&req.method==="GET")return out(req,state(auth.session,auth.user));
  if(url.pathname==="/api/mfa/begin"&&req.method==="POST"){
    if(!csrf(req,auth.session)||!(await body(req)))return fail(req,403);available(auth.user,"totp");
    const secret=base32(crypto.getRandomValues(new Uint8Array(20))),c=counter(),testCode=await totp(secret,c);
    auth.user.encryptedTotp=await encrypt(secret);auth.user.pendingTotpExpires=Date.now()+LIFE;auth.user.pendingTotpUsed=false;auth.user.accepted=new Set();
    return out(req,{ok:true,csrf:auth.session.csrf,manualSecret:secret,testCode,testCounter:c,testWindowSeconds:30});
  }
  if(url.pathname==="/api/mfa/verify"&&req.method==="POST"){
    if(!csrf(req,auth.session))return fail(req,403);const b=await body(req),code=otp(b?.code);let match:number|undefined;
    if(code&&auth.user.encryptedTotp&&auth.user.pendingTotpExpires&&!auth.user.pendingTotpUsed)try{const secret=await decrypt(auth.user.encryptedTotp),now=counter();for(let i=-1;i<=1;i++){const c=now+i;if(c>=0&&await totp(secret,c)===code){match=c;break;}}}catch{}
    const owns=sessions.get(auth.session.id)===auth.session&&auth.session.userId===auth.user.id;
    if(match===undefined||!owns||!available(auth.user,"totp")||auth.user.pendingTotpUsed||!auth.user.pendingTotpExpires||auth.user.pendingTotpExpires<Date.now()||auth.user.accepted.has(match)){auth.user.totpFailures++;if(auth.user.totpFailures>=MAX)auth.user.totpLockedUntil=Date.now()+LOCK;return fail(req);}
    auth.user.accepted.add(match);auth.user.pendingTotpUsed=true;auth.user.mfaEnabled=true;auth.user.totpFailures=0;auth.user.totpLockedUntil=undefined;
    const codes=Array.from({length:8},backupCode);auth.user.backupHashes=await hashes(codes);return out(req,{ok:true,csrf:auth.session.csrf,mfaEnabled:true,codes});
  }
  if(url.pathname==="/api/backup/verify"&&req.method==="POST"){
    if(!csrf(req,auth.session))return fail(req,403);const b=await body(req),c=backup(b?.code),h=c?await hash(c):"";
    if(!auth.user.mfaEnabled||!c||!available(auth.user,"backup")||!auth.user.backupHashes.has(h)){auth.user.backupFailures++;if(auth.user.backupFailures>=MAX)auth.user.backupLockedUntil=Date.now()+LOCK;return fail(req);}
    auth.user.backupHashes.delete(h);auth.user.backupFailures=0;auth.user.backupLockedUntil=undefined;return out(req,{ok:true,csrf:auth.session.csrf});
  }
  if(url.pathname==="/api/backup/regenerate"&&req.method==="POST"){
    if(!csrf(req,auth.session)||!(await body(req))||!auth.user.mfaEnabled)return fail(req,403);const codes=Array.from({length:8},backupCode);auth.user.backupHashes=await hashes(codes);return out(req,{ok:true,csrf:auth.session.csrf,codes});
  }
  if(url.pathname==="/api/logout"&&req.method==="POST"){if(!csrf(req,auth.session)||!(await body(req)))return fail(req,403);sessions.delete(auth.session.id);return out(req,{ok:true},200,{"Set-Cookie":clearCookie()});}
  return fail(req,404);
}
async function fetch(req:Request) {
  try{const url=new URL(req.url);if(url.pathname.startsWith("/api/"))return await api(req,url);if(url.pathname==="/"&&req.method==="GET"){const nonce=token(18);return new Response(page(nonce),{headers:hdr(req,{"Content-Type":"text/html; charset=utf-8"},nonce)});}return fail(req,404);}catch{return fail(req,500);}
}

const certPath="certs/cert.pem",keyPath="certs/key.pem";
if(!existsSync(certPath)||!existsSync(keyPath))throw Error("TLS certificates are required at certs/cert.pem and certs/key.pem.");
/* Demo account credential is retained only as a startup seed to create a peppered hash. */
approvedAccounts[0].credentialHash=await hash("NorthstarDemo!54");
dummyCredentialHash=await hash("not-an-account-credential");
Bun.serve({port:PORT,tls:{cert:readFileSync(certPath),key:readFileSync(keyPath)},fetch});
Bun.serve({port:HTTP_PORT,fetch(req){const u=new URL(req.url);return new Response(null,{status:308,headers:{Location:`https://localhost:${PORT}${u.pathname}${u.search}`,"Cache-Control":"no-store"}});}});
console.log(`MFA demo available securely at https://localhost:${PORT}`);
