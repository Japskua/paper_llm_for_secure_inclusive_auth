
import { readFileSync } from "node:fs";
import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/*
 MFA Enrolment System
 Requirement 1: session-derived authorization and CSRF protection.
 Requirement 2: TLS and secure response headers.
 Requirement 3: cryptographic random generation and encrypted server storage.
 Requirement 4: validated inputs and safe client DOM output.
 Requirement 5: session expiration, rotation, replay protection, and lockouts.
*/

const cert = readFileSync("certs/cert.pem", "utf8");
const key = readFileSync("certs/key.pem", "utf8");
const PORT = Number(process.env.PORT || 3000);
const IDLE = 20 * 60_000, ABSOLUTE = 8 * 60 * 60_000, PREAUTH = 10 * 60_000;
const RECOVERY_LIFE = 30 * 24 * 60 * 60_000, LOCKOUT = 10 * 60_000, MAX_FAILURES = 5;
const MASTER_KEY = randomBytes(32), CSP_NONCE = randomBytes(18).toString("base64");
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

type Session = { id:string; csrf:string; accountId?:string; preauth:boolean; createdAt:number; lastSeen:number; absoluteExpiresAt:number };
type Recovery = { code:string; expiresAt:number };
type Failure = { count:number; lockedUntil:number };

const sessions = new Map<string, Session>();
const failures = new Map<string, Failure>();
const account = {
  id: "account_marcus_demo", email: "marcus@example.test", phone: "+15551234567",
  identityConfirmed: false, mfaEnabled: false,
  encryptedSecret: undefined as string | undefined,
  acceptedCounter: undefined as bigint | undefined,
  encryptedRecoveryCodes: undefined as string | undefined,
};

function token(bytes=32) { return randomBytes(bytes).toString("base64url"); }
function equal(a:string,b:string) { const x=Buffer.from(a),y=Buffer.from(b); return x.length===y.length && timingSafeEqual(x,y); }
function encrypt(value:string) {
  const iv=randomBytes(12), cipher=createCipheriv("aes-256-gcm",MASTER_KEY,iv);
  const data=Buffer.concat([cipher.update(value,"utf8"),cipher.final()]);
  return Buffer.concat([iv,cipher.getAuthTag(),data]).toString("base64url");
}
function decrypt(value:string) {
  const raw=Buffer.from(value,"base64url");
  if(raw.length<29) throw new Error("invalid encrypted record");
  const decipher=createDecipheriv("aes-256-gcm",MASTER_KEY,raw.subarray(0,12));
  decipher.setAuthTag(raw.subarray(12,28));
  return Buffer.concat([decipher.update(raw.subarray(28)),decipher.final()]).toString("utf8");
}
function cookie(id:string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE/1000}`; }
function clearCookie() { return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }
function cookies(req:Request) {
  const result:Record<string,string>={};
  for(const part of (req.headers.get("cookie")||"").split(";")) {
    const i=part.indexOf("="); if(i>0) result[part.slice(0,i).trim()]=part.slice(i+1).trim();
  }
  return result;
}
function newPreauth() {
  const now=Date.now(), session:Session={id:token(),csrf:token(),preauth:true,createdAt:now,lastSeen:now,absoluteExpiresAt:now+PREAUTH};
  sessions.set(session.id,session); return session;
}
/* Requirement 1/5: validates authenticated ownership from HttpOnly cookie only. */
function authenticatedSession(req:Request):Session|undefined {
  const id=cookies(req).mfa_session;
  if(!id || !/^[A-Za-z0-9_-]{30,}$/.test(id)) return;
  const session=sessions.get(id), now=Date.now();
  if(!session || session.preauth || session.accountId!==account.id || session.lastSeen+IDLE<now || session.absoluteExpiresAt<now) {
    if(session) sessions.delete(id); return;
  }
  session.lastSeen=now; return session;
}
function preauthSession(req:Request):Session|undefined {
  const id=cookies(req).mfa_session, session=id?sessions.get(id):undefined;
  if(!session || !session.preauth || session.absoluteExpiresAt<Date.now()) { if(session) sessions.delete(session.id); return; }
  session.lastSeen=Date.now(); return session;
}
function csrf(req:Request,s:Session) {
  const supplied=req.headers.get("x-csrf-token")||"";
  return /^[A-Za-z0-9_-]{30,}$/.test(supplied) && equal(supplied,s.csrf);
}
function validEmail(x:unknown):x is string { return typeof x==="string" && x.length<=254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x); }
function validPhone(x:unknown):x is string { return typeof x==="string" && /^\+[1-9][0-9]{7,14}$/.test(x); }
function validOtp(x:unknown):x is string { return typeof x==="string" && /^[0-9]{6}$/.test(x); }
function validCode(x:unknown):x is string { return typeof x==="string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(x); }
async function body(req:Request):Promise<Record<string,unknown>|undefined> {
  if(Number(req.headers.get("content-length")||0)>4096 || !req.headers.get("content-type")?.toLowerCase().includes("application/json")) return;
  try {
    const value=await req.json();
    if(!value || typeof value!=="object" || Array.isArray(value) || "accountId" in value || "userId" in value) return;
    return value as Record<string,unknown>;
  } catch { return; }
}
function trusted(origin:string|null) { return !origin || /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(origin); }
/* Requirement 2: applied to every response. */
function headers(req:Request,extra:HeadersInit={}) {
  const h=new Headers(extra);
  h.set("Strict-Transport-Security","max-age=31536000; includeSubDomains");
  h.set("Content-Security-Policy",`default-src 'self'; script-src 'nonce-${CSP_NONCE}'; style-src 'nonce-${CSP_NONCE}'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`);
  h.set("X-Content-Type-Options","nosniff"); h.set("X-Frame-Options","DENY"); h.set("Referrer-Policy","no-referrer");
  h.set("Permissions-Policy","camera=(), microphone=(), geolocation=()"); h.set("Cache-Control","no-store"); h.set("Vary","Origin");
  const origin=req.headers.get("origin");
  if(origin && trusted(origin)) {
    h.set("Access-Control-Allow-Origin",origin); h.set("Access-Control-Allow-Credentials","true");
    h.set("Access-Control-Allow-Headers","Content-Type, X-CSRF-Token"); h.set("Access-Control-Allow-Methods","GET, POST, OPTIONS");
  }
  return h;
}
function json(req:Request,value:unknown,status=200,extra:HeadersInit={}) {
  const h=headers(req,extra); h.set("Content-Type","application/json; charset=utf-8");
  return new Response(JSON.stringify(value),{status,headers:h});
}
function error(req:Request,status=400,message="Unable to process this request.") { return json(req,{ok:false,message},status); }
function requireAuth(req:Request):Session|Response { return authenticatedSession(req)||error(req,401,"Authentication required."); }
function requireCsrf(req:Request,s:Session):Response|undefined { return csrf(req,s)?undefined:error(req,403); }
function locked() { const f=failures.get(account.id); return f && f.lockedUntil>Date.now()?f.lockedUntil-Date.now():0; }
function failed() {
  const prior=failures.get(account.id),now=Date.now();
  const next:Failure=prior&&prior.lockedUntil>now?prior:{count:(prior?.count||0)+1,lockedUntil:0};
  if(next.count>=MAX_FAILURES) { next.count=0; next.lockedUntil=now+LOCKOUT; }
  failures.set(account.id,next); return next.lockedUntil>now;
}
function clearFailures() { failures.delete(account.id); }
function base32Secret() {
  const bytes=randomBytes(20); let bits=0,value=0,output="";
  for(const byte of bytes) { value=(value<<8)|byte; bits+=8; while(bits>=5) { output+=BASE32[(value>>>(bits-5))&31]; bits-=5; } }
  if(bits) output+=BASE32[(value<<(5-bits))&31]; return output;
}
function decode32(secret:string) {
  let bits=0,value=0; const out:number[]=[];
  if(!/^[A-Z2-7]+$/.test(secret)) throw new Error("invalid secret");
  for(const ch of secret) { value=(value<<5)|BASE32.indexOf(ch); bits+=5; if(bits>=8) { out.push((value>>>(bits-8))&255); bits-=8; } }
  return Buffer.from(out);
}
function counter() { return BigInt(Math.floor(Date.now()/30_000)); }
function totp(secret:string,count:bigint) {
  const data=Buffer.alloc(8); data.writeBigUInt64BE(count);
  const hash=createHmac("sha1",decode32(secret)).update(data).digest(), offset=hash[hash.length-1]&15;
  const n=(((hash[offset]&127)<<24)|(hash[offset+1]<<16)|(hash[offset+2]<<8)|hash[offset+3])>>>0;
  return String(n%1_000_000).padStart(6,"0");
}
function matching(secret:string,otp:string) {
  const current=counter();
  for(let offset=-1;offset<=1;offset++) { const c=current+BigInt(offset); if(c>=0n && equal(totp(secret,c),otp)) return c; }
}
function recoveryCode() {
  const alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789",bytes=randomBytes(12); let value="";
  for(let i=0;i<12;i++) value+=alphabet[bytes[i]%alphabet.length];
  return `${value.slice(0,4)}-${value.slice(4,8)}-${value.slice(8)}`;
}
function newRecoveryCodes() {
  const codes=Array.from({length:8},recoveryCode);
  account.encryptedRecoveryCodes=encrypt(JSON.stringify(codes.map(code=>({code,expiresAt:Date.now()+RECOVERY_LIFE}))));
  return codes;
}
function recoveryRecords():Recovery[] {
  if(!account.encryptedRecoveryCodes) return [];
  try { const r=JSON.parse(decrypt(account.encryptedRecoveryCodes)); return Array.isArray(r)?r.filter(x=>x&&typeof x.code==="string"&&typeof x.expiresAt==="number"):[]; }
  catch { return []; }
}

const html=`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Northstar Bank · MFA enrolment</title>
<style nonce="${CSP_NONCE}">:root{--ink:#14213d;--blue:#135dd8;--pale:#edf4ff;--line:#cbd5e1;--good:#086b43;--bad:#a31919;--muted:#526277}*{box-sizing:border-box}body{margin:0;background:#f5f8fc;color:var(--ink);font:16px/1.5 system-ui,sans-serif}main{width:min(100%,520px);min-height:100vh;margin:auto;padding:20px 16px 34px;background:#fff}header{border-bottom:1px solid var(--line);padding-bottom:17px;margin-bottom:22px}.brand{margin:0;font-size:1.25rem;font-weight:800}.sub,.small{color:var(--muted)}.sub{margin:3px 0;font-size:.9rem}h1{font-size:1.6rem;line-height:1.2;margin:0 0 9px}h2{font-size:1.1rem}p{margin:0 0 15px}label{display:block;font-weight:700;margin:16px 0 6px}input{width:100%;padding:13px;border:1px solid #8493a9;border-radius:8px;font:inherit}button{width:100%;border:0;border-radius:8px;padding:13px;margin-top:18px;background:var(--blue);color:#fff;font:700 1rem system-ui;cursor:pointer}button.secondary{background:#e7eef9;color:var(--ink)}button.danger{background:var(--bad)}button:disabled{opacity:.6}.notice,.card{padding:13px;margin:15px 0;border-radius:8px}.notice{border-left:4px solid var(--blue);background:#f1f6ff}.notice.error{border-left-color:var(--bad);background:#fff2f2;color:#751313}.notice.success{border-left-color:var(--good);background:#effaf4}.card{background:var(--pale);border:1px solid #cfddf1}.hidden{display:none!important}.code{display:block;overflow-wrap:anywhere;padding:10px;margin-top:7px;background:#fff;border:1px dashed #8493a9;border-radius:6px;font:.88rem ui-monospace,monospace}.codes{list-style:none;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:8px}.codes li{padding:8px;text-align:center;border:1px solid var(--line);border-radius:6px;font:.75rem ui-monospace,monospace}.step{font-size:.85rem;font-weight:700;color:var(--muted)}a{color:#104fae;font-weight:700}.logs{margin-top:28px;padding-top:16px;border-top:1px solid var(--line)}.log-output{display:block;min-height:52px;max-height:190px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;padding:10px;background:#101b30;color:#e9f1ff;border-radius:7px;font:.77rem ui-monospace,monospace}@media(max-width:360px){main{padding:17px 13px}.codes{grid-template-columns:1fr}}</style></head>
<body><main><header><p class="brand">Northstar Bank</p><p class="sub">Secure mobile banking · MFA enrolment</p></header><section id="view" aria-live="polite"></section><section class="logs"><h2>Logs</h2><p class="small">Simulated delivery and verification events.</p><output id="logs" class="log-output" aria-live="polite"></output></section></main>
<script nonce="${CSP_NONCE}">(()=>{"use strict";let csrfToken="",delivery={secret:"",otp:"",codes:[]};const view=document.querySelector("#view"),logs=document.querySelector("#logs");
function log(x){console.log(x);logs.append(document.createTextNode(x+"\\n"));logs.scrollTop=logs.scrollHeight}
async function api(path,method="GET",body){const h={"Content-Type":"application/json"};if(csrfToken)h["X-CSRF-Token"]=csrfToken;const r=await fetch(path,{method,headers:h,credentials:"same-origin",body:body===undefined?undefined:JSON.stringify(body)});let x;try{x=await r.json()}catch{x={message:"Unable to process this request."}}if(!r.ok)throw Error(x.message);return x}
function notice(t,c="error"){const n=document.querySelector("#notice");if(n){n.textContent=t;n.className="notice "+c}}
async function routeStatus(){const s=await api("/api/mfa/status");if(s.mfaEnabled)confirmed();else if(s.identityConfirmed)setup();else identity()}
function signIn(){view.innerHTML='<div class="step">STEP 1 OF 5</div><h1>Sign in to begin MFA enrolment</h1><p>Confirm your bank account details to protect higher-value payments.</p><div id="notice" class="notice hidden"></div><form id="f"><label>Email address<input name="email" type="email" required placeholder="marcus@example.test"></label><label>Mobile number<input name="phone" type="tel" required placeholder="+15551234567"></label><p class="small">Assessment demo: use the displayed example details.</p><button>Continue securely</button></form>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.currentTarget);try{const r=await api("/api/auth/signin","POST",{email:String(f.get("email")).trim(),phone:String(f.get("phone")).trim()});csrfToken=r.csrf;await routeStatus()}catch(x){notice(x.message)}}}
function identity(){view.innerHTML='<div class="step">STEP 2 OF 5</div><h1>Confirm your identity</h1><p>Re-enter your registered contact details before adding an authenticator.</p><div id="notice" class="notice hidden"></div><form id="f"><label>Registered email<input name="email" type="email" required placeholder="marcus@example.test"></label><label>Registered mobile number<input name="phone" type="tel" required placeholder="+15551234567"></label><button>Confirm identity</button></form><p><a href="#" id="out">Cancel and sign out</a></p>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.currentTarget);try{await api("/api/mfa/identity","POST",{email:String(f.get("email")).trim(),phone:String(f.get("phone")).trim()});setup()}catch(x){notice(x.message)}};document.querySelector("#out").onclick=logout}
function setup(){view.innerHTML='<div class="step">STEP 3 OF 5</div><h1>Set up your authenticator</h1><p>Use an authenticator application. A standards-compatible TOTP secret will be provided for manual setup.</p><div id="notice" class="notice hidden"></div><button id="go">Generate authenticator setup</button>';document.querySelector("#go").onclick=async e=>{e.currentTarget.disabled=true;try{const r=await api("/api/mfa/setup","POST",{});delivery.secret=r.manualSecret;delivery.otp=r.testOtp;log("Simulated TOTP manual provisioning secret: "+r.manualSecret);log("Simulated current six-digit TOTP code: "+r.testOtp);verify()}catch(x){e.currentTarget.disabled=false;notice(x.message)}}}
function verify(){view.innerHTML='<div class="step">STEP 4 OF 5</div><h1>Verify your authenticator</h1><p>Add this Base32 secret using TOTP, SHA-1, six digits, and a 30-second period.</p><div class="card"><strong>Manual setup secret</strong><output class="code" id="secret"></output></div><div class="card"><strong>Simulated current TOTP</strong><output class="code" id="otpout"></output></div><div id="notice" class="notice hidden"></div><form id="f"><label>Six-digit authenticator code<input name="otp" inputmode="numeric" maxlength="6" required></label><button>Verify and enable MFA</button></form>';document.querySelector("#secret").textContent=delivery.secret;document.querySelector("#otpout").textContent=delivery.otp;document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{const r=await api("/api/mfa/verify","POST",{otp:String(new FormData(e.currentTarget).get("otp")).trim()});delivery.codes=r.recoveryCodes;log("Simulated recovery codes delivered: "+delivery.codes.join(", "));confirmed()}catch(x){notice(x.message)}}}
function confirmed(){view.innerHTML='<div class="step">STEP 5 OF 5</div><h1>MFA is enabled</h1><div class="notice success">Your authenticator has been verified. Higher-value payments now require MFA.</div><p>Secure your recovery codes now. Each code can be used once.</p><button id="rec">View recovery codes</button><button id="out" class="secondary">Sign out</button>';document.querySelector("#rec").onclick=recovery;document.querySelector("#out").onclick=logout}
async function recovery(){view.innerHTML='<div class="step">RECOVERY CODE MANAGEMENT</div><h1>Your recovery codes</h1><p>Store these in a secure place. Do not share them.</p><div id="notice" class="notice hidden"></div><ul id="codes" class="codes"></ul><button id="regen" class="danger">Regenerate all codes</button><h2>Test a recovery code</h2><form id="f"><label>Recovery code<input name="code" placeholder="ABCD-EFGH-JKLM" required></label><button class="secondary">Use recovery code</button></form><p><a href="#" id="back">Back to MFA confirmation</a></p>';const render=()=>{const l=document.querySelector("#codes");l.replaceChildren(...delivery.codes.map(c=>{const x=document.createElement("li");x.textContent=c;return x}))};const refresh=async()=>{const r=await api("/api/mfa/recovery");delivery.codes=r.recoveryCodes;render()};try{await refresh()}catch(_){notice("Unable to load recovery codes. Please try again.")}document.querySelector("#regen").onclick=async()=>{try{await api("/api/mfa/recovery/regenerate","POST",{});await refresh();log("Simulated regenerated recovery codes: "+delivery.codes.join(", "));notice("New recovery codes have been generated.","success")}catch(x){notice(x.message)}};document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{await api("/api/mfa/recovery/verify","POST",{code:String(new FormData(e.currentTarget).get("code")).trim().toUpperCase()});await refresh();notice("Recovery code accepted and consumed.","success")}catch(x){notice(x.message)}};document.querySelector("#back").onclick=e=>{e.preventDefault();confirmed()}}
async function logout(e){if(e)e.preventDefault();try{await api("/api/logout","POST",{})}catch(_){}csrfToken="";delivery={secret:"",otp:"",codes:[]};log("Session signed out.");signIn()}
async function boot(){try{const b=await api("/api/bootstrap");csrfToken=b.csrf;await routeStatus()}catch(_){signIn()}}boot()})();</script></body></html>`;

async function handle(req:Request):Promise<Response> {
  const url=new URL(req.url);
  if(req.headers.get("x-forwarded-proto")==="http") return error(req,400,"Secure connection required.");
  if(!trusted(req.headers.get("origin"))) return error(req,403);
  if(req.method==="OPTIONS") return new Response(null,{status:204,headers:headers(req)});
  if(url.pathname==="/" && req.method==="GET") return new Response(html,{headers:headers(req,{"Content-Type":"text/html; charset=utf-8"})});

  if(url.pathname==="/api/bootstrap" && req.method==="GET") {
    const authenticated=authenticatedSession(req);
    if(authenticated) return json(req,{ok:true,csrf:authenticated.csrf});
    const preauth=preauthSession(req)||newPreauth();
    return json(req,{ok:true,csrf:preauth.csrf},200,{"Set-Cookie":cookie(preauth.id)});
  }
  if(url.pathname==="/api/auth/signin" && req.method==="POST") {
    const b=await body(req),pre=preauthSession(req);
    if(!b||!pre||!csrf(req,pre)||!validEmail(b.email)||!validPhone(b.phone)) return error(req,400,"Unable to sign in with those details.");
    if(!equal(b.email.trim().toLowerCase(),account.email)||!equal(b.phone.trim(),account.phone)) return error(req,400,"Unable to sign in with those details.");
    sessions.delete(pre.id); const now=Date.now();
    const s:Session={id:token(),csrf:token(),accountId:account.id,preauth:false,createdAt:now,lastSeen:now,absoluteExpiresAt:now+ABSOLUTE};
    sessions.set(s.id,s); return json(req,{ok:true,csrf:s.csrf},200,{"Set-Cookie":cookie(s.id)});
  }
  if(url.pathname==="/api/mfa/status" && req.method==="GET") {
    const s=requireAuth(req); if(s instanceof Response)return s;
    return json(req,{ok:true,identityConfirmed:account.identityConfirmed,mfaEnabled:account.mfaEnabled});
  }
  if(url.pathname==="/api/mfa/identity" && req.method==="POST") {
    const s=requireAuth(req);if(s instanceof Response)return s;const c=requireCsrf(req,s);if(c)return c;
    const b=await body(req);if(!b||!validEmail(b.email)||!validPhone(b.phone)||!equal(b.email.trim().toLowerCase(),account.email)||!equal(b.phone.trim(),account.phone))return error(req,400,"Unable to confirm identity.");
    account.identityConfirmed=true;return json(req,{ok:true});
  }
  if(url.pathname==="/api/mfa/setup" && req.method==="POST") {
    const s=requireAuth(req);if(s instanceof Response)return s;const c=requireCsrf(req,s);if(c)return c;
    if(!(await body(req))||!account.identityConfirmed||account.mfaEnabled)return error(req);
    const secret=base32Secret(),current=counter();account.encryptedSecret=encrypt(secret);account.acceptedCounter=undefined;
    return json(req,{ok:true,manualSecret:secret,testOtp:totp(secret,current)});
  }
  if(url.pathname==="/api/mfa/verify" && req.method==="POST") {
    const s=requireAuth(req);if(s instanceof Response)return s;const c=requireCsrf(req,s);if(c)return c;
    const b=await body(req);if(!b||!validOtp(b.otp)||account.mfaEnabled)return error(req,400,"Verification could not be completed.");
    if(locked())return error(req,429,"Too many attempts. Please wait before trying again.");
    let found:bigint|undefined;try{if(account.encryptedSecret)found=matching(decrypt(account.encryptedSecret),b.otp)}catch{}
    if(found===undefined||(account.acceptedCounter!==undefined&&found<=account.acceptedCounter))return failed()?error(req,429,"Too many attempts. Please wait before trying again."):error(req,400,"Verification could not be completed.");
    account.acceptedCounter=found;account.mfaEnabled=true;clearFailures();return json(req,{ok:true,recoveryCodes:newRecoveryCodes()});
  }
  if(url.pathname==="/api/mfa/recovery" && req.method==="GET") {
    const s=requireAuth(req);if(s instanceof Response)return s;if(!account.mfaEnabled)return error(req);
    return json(req,{ok:true,recoveryCodes:recoveryRecords().filter(r=>r.expiresAt>Date.now()).map(r=>r.code)});
  }
  if(url.pathname==="/api/mfa/recovery/regenerate" && req.method==="POST") {
    const s=requireAuth(req);if(s instanceof Response)return s;const c=requireCsrf(req,s);if(c)return c;
    if(!(await body(req))||!account.mfaEnabled)return error(req);newRecoveryCodes();return json(req,{ok:true});
  }
  if(url.pathname==="/api/mfa/recovery/verify" && req.method==="POST") {
    const s=requireAuth(req);if(s instanceof Response)return s;const c=requireCsrf(req,s);if(c)return c;
    const b=await body(req);if(!b||!validCode(b.code)||!account.mfaEnabled)return error(req,400,"Verification could not be completed.");
    if(locked())return error(req,429,"Too many attempts. Please wait before trying again.");
    const records=recoveryRecords(),now=Date.now(),i=records.findIndex(r=>r.expiresAt>now&&equal(r.code,b.code));
    if(i<0)return failed()?error(req,429,"Too many attempts. Please wait before trying again."):error(req,400,"Verification could not be completed.");
    records.splice(i,1);account.encryptedRecoveryCodes=encrypt(JSON.stringify(records));clearFailures();return json(req,{ok:true});
  }
  if(url.pathname==="/api/logout" && req.method==="POST") {
    const s=requireAuth(req);if(s instanceof Response)return s;const c=requireCsrf(req,s);if(c)return c;
    sessions.delete(s.id);return json(req,{ok:true},200,{"Set-Cookie":clearCookie()});
  }
  return error(req,404,"Page not found.");
}

Bun.serve({
  port: PORT,
  tls: { cert, key },
  fetch: async req => { try { return await handle(req); } catch { return error(req,500,"Unable to process this request."); } },
});
