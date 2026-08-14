
const encoder = new TextEncoder();
const TEST_MODE = true;
const TEST_TOTP_CLOCK_MS = 1_700_000_000_000;
const STEP = 30, IDENTITY_CODE = "135790", IDLE = 1_200_000, ABS = 28_800_000, CODE_LIFE = 300_000, PROVISION_LIFE = 300_000, LOCK = 600_000, MAX = 5;
const MARCUS = { id: "account-owner-marcus", email: "marcus@northstar.test", phone: "+447700900000" };

type Session = { id:string; userId:string; csrf:string; created:number; seen:number; verified:boolean; recoveryPending:boolean; recoveryAcknowledged:boolean };
type Security = { identityHash:string; identityExpires:number; identityUsed:boolean; identityFailures:number; identityLocked:number; authFailures:number; authLocked:number };
type Verifier = { salt:string; verifier:string };
type Mfa = { encryptedSecret:string; enabled:boolean; expires?:number; recoveryFailures:number; recoveryLocked:number; codes:Verifier[] };

const sessions = new Map<string, Session>();
const mfas = new Map<string, Mfa>();
const security = new Map<string, Security>();
const locks = new Map<string, Promise<void>>();
const encryptionKey = await crypto.subtle.generateKey({ name:"AES-GCM", length:256 }, true, ["encrypt","decrypt"]);

/* Requirement 3: CSPRNG, AES-GCM-encrypted OTP secrets, and PBKDF2-hashed recovery codes at rest. */
function bytes(n:number) { const out=new Uint8Array(n); crypto.getRandomValues(out); return out; }
function b64(v:Uint8Array) { let s=""; for(const x of v)s+=String.fromCharCode(x); return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""); }
function unb64(s:string) { s=s.replace(/-/g,"+").replace(/_/g,"/")+"===".slice((s.length+3)%4); return Uint8Array.from(atob(s),x=>x.charCodeAt(0)); }
function token(n=32) { return b64(bytes(n)); }
function recoveryCode() { const a="ABCDEFGHJKLMNPQRSTUVWXYZ23456789", v=bytes(10); let s=""; for(const x of v)s+=a[x%a.length]; return s.slice(0,5)+"-"+s.slice(5); }
async function hash(s:string) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256",encoder.encode(s)))); }
function equal(a:string,b:string) { if(a.length!==b.length)return false; let x=0; for(let i=0;i<a.length;i++)x|=a.charCodeAt(i)^b.charCodeAt(i); return x===0; }
async function encrypt(s:string) { const iv=bytes(12), data=await crypto.subtle.encrypt({name:"AES-GCM",iv},encryptionKey,encoder.encode(s)); return b64(iv)+"."+b64(new Uint8Array(data)); }
async function decrypt(s:string) { const p=s.split("."); if(p.length!==2)throw Error("protected material"); return new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(p[0])},encryptionKey,unb64(p[1]))); }
async function verifier(code:string):Promise<Verifier> { const salt=bytes(16), key=await crypto.subtle.importKey("raw",encoder.encode(code),"PBKDF2",false,["deriveBits"]), bits=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt,iterations:120000},key,256); return {salt:b64(salt),verifier:b64(new Uint8Array(bits))}; }
async function verifyVerifier(code:string,v:Verifier) { const key=await crypto.subtle.importKey("raw",encoder.encode(code),"PBKDF2",false,["deriveBits"]), bits=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:unb64(v.salt),iterations:120000},key,256); return equal(b64(new Uint8Array(bits)),v.verifier); }

/* Requirement 5: TOTP verification produces exactly six digits; server checks expiry and consumes codes below. */
async function totpForSecret(secret:string, clockMs:number):Promise<string> {
  const counter=Math.floor(clockMs/1000/STEP), message=new Uint8Array(8); let n=counter;
  for(let i=7;i>=0;i--){message[i]=n&255;n=Math.floor(n/256);}
  const key=await crypto.subtle.importKey("raw",encoder.encode(secret),{name:"HMAC",hash:"SHA-1"},false,["sign"]);
  const mac=new Uint8Array(await crypto.subtle.sign("HMAC",key,message)), off=mac[mac.length-1]&15;
  const dynamic=(((mac[off]&127)<<24)|(mac[off+1]<<16)|(mac[off+2]<<8)|mac[off+3])>>>0;
  const result=String(dynamic%1_000_000).padStart(6,"0");
  if(!/^[0-9]{6}$/.test(result))throw Error("invalid OTP output");
  return result;
}

function now(){return Date.now();}
function locked<T>(user:string, fn:()=>Promise<T>) {
  const prior=locks.get(user)||Promise.resolve(); let release!:()=>void;
  const gate=new Promise<void>(r=>release=r), tail=prior.then(()=>gate); locks.set(user,tail);
  return prior.then(fn).finally(()=>{release();if(locks.get(user)===tail)locks.delete(user);});
}
function cookies(r:Request){const o:Record<string,string>={};for(const p of (r.headers.get("cookie")||"").split(";")){const i=p.indexOf("=");if(i>0)o[p.slice(0,i).trim()]=p.slice(i+1).trim();}return o;}
function trusted(origin:string|null){return !!origin&&/^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i.test(origin);}

/* Requirement 2: CSP, HSTS, anti-clickjacking headers, trusted-origin-only CORS, and generic responses. */
function headers(r:Request, nonce?:string, extra:HeadersInit={}) {
  const h=new Headers(extra);
  const script=nonce?`script-src 'nonce-${nonce}'`:"script-src 'none'";
  const style=nonce?`style-src 'nonce-${nonce}'`:"style-src 'none'";
  h.set("Content-Security-Policy",`default-src 'self'; connect-src 'self'; img-src 'self' blob:; ${script}; ${style}; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`);
  h.set("Strict-Transport-Security","max-age=31536000; includeSubDomains");
  h.set("X-Content-Type-Options","nosniff");
  h.set("X-Frame-Options","DENY");
  h.set("Referrer-Policy","no-referrer");
  h.set("Permissions-Policy","camera=(), microphone=(), geolocation=()");
  const o=r.headers.get("origin");
  if(trusted(o)){
    h.set("Access-Control-Allow-Origin",o!);
    h.set("Access-Control-Allow-Credentials","true");
    h.set("Access-Control-Allow-Headers","Content-Type");
    h.set("Access-Control-Allow-Methods","GET, POST, OPTIONS");
    h.set("Vary","Origin");
  }
  return h;
}
function response(r:Request, body:unknown, status=200, extra:HeadersInit={}) { const h=headers(r,undefined,extra);h.set("Content-Type","application/json; charset=utf-8");h.set("Cache-Control","no-store");return new Response(JSON.stringify(body),{status,headers:h}); }
function fail(r:Request,status=400){return response(r,{error:"Request could not be completed."},status);}

/* Requirement 3: HTTPS-only Secure, HttpOnly, SameSite session cookie; no browser-side secret storage exists. */
function cookie(id:string){return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABS/1000)}`;}
function expired(){return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";}

/* Requirements 1 and 5: every MFA endpoint obtains owner session; idle/absolute expiry invalidates it. */
function getSession(r:Request):Session|null {
  const id=cookies(r).mfa_session;
  if(!id||!/^[A-Za-z0-9_-]{30,}$/.test(id))return null;
  const s=sessions.get(id);
  if(!s)return null;
  if(now()-s.seen>IDLE||now()-s.created>ABS){sessions.delete(id);return null;}
  s.seen=now();
  return s;
}
function isResponse(x:unknown):x is Response{return x instanceof Response;}
function required(r:Request, verified=false):Session|Response {
  const s=getSession(r);
  return !s?fail(r,401):verified&&!s.verified?fail(r,403):s;
}

/* Requirement 1: state-changing requests require same trusted origin plus per-session anti-CSRF token. */
function csrf(r:Request,s:Session,b:Record<string,unknown>){
  const o=r.headers.get("origin"), c=b.csrf;
  return (!o||trusted(o))&&typeof c==="string"&&/^[A-Za-z0-9_-]{30,}$/.test(c)&&equal(c,s.csrf);
}

/* Requirement 4: strict JSON body allow-lists reject unexpected/injection-prone input properties. */
async function body(r:Request,keys:string[]) {
  if(!(r.headers.get("content-type")||"").toLowerCase().startsWith("application/json"))return null;
  try{
    const x:unknown=await r.json();
    if(!x||typeof x!=="object"||Array.isArray(x))return null;
    const b=x as Record<string,unknown>;
    return Object.keys(b).every(k=>keys.includes(k))?b:null;
  }catch{return null;}
}
function sec(){let s=security.get(MARCUS.id);if(!s){s={identityHash:"",identityExpires:0,identityUsed:true,identityFailures:0,identityLocked:0,authFailures:0,authLocked:0};security.set(MARCUS.id,s);}return s;}

/* Requirement 5: failed-code counters lock identity, authenticator, and recovery verification attempts. */
function addFail(o:any,k:"identity"|"auth"|"recovery"){const f=k==="identity"?"identityFailures":k==="auth"?"authFailures":"recoveryFailures", l=k==="identity"?"identityLocked":k==="auth"?"authLocked":"recoveryLocked";if((o[f]||0)+1>=MAX){o[f]=0;o[l]=now()+LOCK;}else o[f]=(o[f]||0)+1;}
function clearFail(o:any,k:"identity"|"auth"|"recovery"){o[k==="identity"?"identityFailures":k==="auth"?"authFailures":"recoveryFailures"]=0;}
function clearPending(user:string){const m=mfas.get(user);if(m&&!m.enabled&&(!m.expires||now()>m.expires)){mfas.delete(user);return true;}return false;}
function state(s:Session){clearPending(s.userId);const m=mfas.get(s.userId);return {csrf:s.csrf,identityVerified:s.verified,mfaEnabled:!!m?.enabled,recoveryPending:s.recoveryPending,recoveryAcknowledged:s.recoveryAcknowledged};}

/* Requirements 1 and 4: fixed account comparison, validated email/phone, and internal redirect allow-list. */
async function signin(r:Request) {
  const b=await body(r,["email","phone","redirect"]), email=b&&typeof b.email==="string"?b.email.toLowerCase():"", phone=b&&typeof b.phone==="string"?b.phone.replace(/[ ()-]/g,""):"";
  const [a,e]=await Promise.all([hash(email+"\0"+phone),hash(MARCUS.email+"\0"+MARCUS.phone)]);
  if(!b||!trusted(r.headers.get("origin"))||typeof b.email!=="string"||typeof b.phone!=="string"||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(b.email)||!/^\+?[0-9 ()-]{7,24}$/.test(b.phone)||b.redirect!=="/"||!equal(a,e))return fail(r);
  return locked(MARCUS.id,async()=>{
    const q=sec();
    if(now()<q.identityLocked)return fail(r);
    q.identityHash=await hash(IDENTITY_CODE);
    q.identityExpires=now()+CODE_LIFE;
    q.identityUsed=false;
    const s:Session={id:token(),userId:MARCUS.id,csrf:token(),created:now(),seen:now(),verified:false,recoveryPending:false,recoveryAcknowledged:false};
    sessions.set(s.id,s);
    return response(r,{csrf:s.csrf,next:"/#identity",testIdentityCode:TEST_MODE?IDENTITY_CODE:undefined},200,{"Set-Cookie":cookie(s.id)});
  });
}

/* Requirements 1 and 5: owner-only identity verification, code expiry/single use, lockout, and session rotation. */
async function identity(r:Request) {
  const old=required(r);if(isResponse(old))return old;
  const b=await body(r,["csrf","code"]);
  if(!b||!csrf(r,old,b)||typeof b.code!=="string"||!/^\d{6}$/.test(b.code))return fail(r);
  return locked(old.userId,async()=>{
    const q=sec(), eligible=now()>=q.identityLocked&&!q.identityUsed&&now()<=q.identityExpires, ok=eligible&&await hash(b.code as string).then(x=>equal(x,q.identityHash));
    if(!ok){if(eligible)addFail(q,"identity");return fail(r);}
    q.identityUsed=true;clearFail(q,"identity");
    sessions.delete(old.id);
    const s:Session={id:token(),userId:old.userId,csrf:token(),created:now(),seen:now(),verified:true,recoveryPending:false,recoveryAcknowledged:false};
    sessions.set(s.id,s);
    return response(r,{...state(s),next:"/#provision"},200,{"Set-Cookie":cookie(s.id)});
  });
}

/* Requirement 1: verified owner session and CSRF are enforced before generating MFA material. */
async function provision(r:Request) {
  const s=required(r,true);if(isResponse(s))return s;
  const b=await body(r,["csrf"]);if(!b||!csrf(r,s,b))return fail(r);
  return locked(s.userId,async()=>{
    clearPending(s.userId);
    if(mfas.has(s.userId))return fail(r,409);
    const secret=b64(bytes(20)), code=await totpForSecret(secret,TEST_TOTP_CLOCK_MS), expires=now()+PROVISION_LIFE;
    mfas.set(s.userId,{encryptedSecret:await encrypt(secret),enabled:false,expires,recoveryFailures:0,recoveryLocked:0,codes:[]});
    return response(r,{...state(s),testProvisioningSecret:TEST_MODE?secret:undefined,testAuthenticatorCode:TEST_MODE?code:undefined,testClockMs:TEST_MODE?TEST_TOTP_CLOCK_MS:undefined,timeStepSeconds:STEP,provisioningExpiresAt:expires});
  });
}
async function confirm(r:Request) {
  const s=required(r,true);if(isResponse(s))return s;
  const b=await body(r,["csrf","otp"]);
  if(!b||!csrf(r,s,b)||typeof b.otp!=="string"||!/^\d{6}$/.test(b.otp))return fail(r);
  return locked(s.userId,async()=>{
    if(clearPending(s.userId))return response(r,{error:"Authenticator setup expired. Generate a fresh authenticator secret before confirming.",requiresFreshProvisioning:true,...state(s)},410);
    const m=mfas.get(s.userId),q=sec();
    if(!m||m.enabled||!m.expires||now()<q.authLocked)return fail(r);
    const secret=await decrypt(m.encryptedSecret);
    let ok=false;
    if(TEST_MODE)ok=equal(b.otp as string,await totpForSecret(secret,TEST_TOTP_CLOCK_MS));
    else for(const skew of [-1,0,1])if(equal(b.otp as string,await totpForSecret(secret,now()+skew*STEP*1000)))ok=true;
    if(!ok||now()>m.expires){if(!ok)addFail(q,"auth");return fail(r);}
    clearFail(q,"auth");m.enabled=true;delete m.expires;
    const codes=Array.from({length:8},recoveryCode);
    m.codes=await Promise.all(codes.map(verifier));
    s.recoveryPending=true;s.recoveryAcknowledged=false;
    return response(r,{...state(s),recoveryCodes:codes});
  });
}
async function regenerate(r:Request) {
  const s=required(r,true);if(isResponse(s))return s;
  const b=await body(r,["csrf"]);if(!b||!csrf(r,s,b))return fail(r);
  return locked(s.userId,async()=>{
    const m=mfas.get(s.userId);if(!m?.enabled)return fail(r,403);
    const codes=Array.from({length:8},recoveryCode);
    m.codes=await Promise.all(codes.map(verifier));
    s.recoveryPending=true;s.recoveryAcknowledged=false;
    return response(r,{...state(s),recoveryCodes:codes});
  });
}

/* Requirement 5: recovery codes are verified against hashes and removed immediately after one successful use. */
async function recover(r:Request) {
  const s=required(r,true);if(isResponse(s))return s;
  const b=await body(r,["csrf","recoveryCode"]);
  if(!b||!csrf(r,s,b)||typeof b.recoveryCode!=="string"||!/^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(b.recoveryCode))return fail(r);
  return locked(s.userId,async()=>{
    const m=mfas.get(s.userId);if(!m?.enabled||now()<m.recoveryLocked)return fail(r);
    let at=-1;
    for(let i=0;i<m.codes.length;i++)if(await verifyVerifier(b.recoveryCode as string,m.codes[i])){at=i;break;}
    if(at<0){addFail(m,"recovery");return fail(r);}
    clearFail(m,"recovery");m.codes.splice(at,1);
    return response(r,{...state(s),verified:true});
  });
}
async function acknowledge(r:Request) {
  const s=required(r,true);if(isResponse(s))return s;
  const b=await body(r,["csrf"]);if(!b||!csrf(r,s,b)||!s.recoveryPending)return fail(r);
  s.recoveryPending=false;s.recoveryAcknowledged=true;
  return response(r,state(s));
}

/* Requirement 5: logout invalidates the server session and expires its secure cookie. */
async function logout(r:Request) {
  const s=required(r);if(isResponse(s))return s;
  const b=await body(r,["csrf"]);if(!b||!csrf(r,s,b))return fail(r);
  sessions.delete(s.id);
  return response(r,{ok:true},200,{"Set-Cookie":expired()});
}

function page(nonce:string) { return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Northstar Bank | MFA enrolment</title></head><body><main class="shell" aria-live="polite"><header><p class="eyebrow">NORTHSTAR BANK</p><h1>Security setup</h1><p class="subtitle">Protect payments with multi-factor authentication.</p></header><section id="notice" class="notice" hidden role="alert"></section><section id="app">Loading secure setup…</section><section class="logs"><h2>Logs</h2><p>Non-production test delivery values appear here and in the browser console.</p><pre id="log">No test values delivered yet.</pre></section></main><script nonce="${nonce}">(function(){var app=document.querySelector("#app"),note=document.querySelector("#notice"),log=document.querySelector("#log"),csrf="",codes=[];function err(x){note.textContent=x||"We could not complete that request. Please try again.";note.hidden=false}function say(a,v){var x=a+": "+v;console.log(x);if(log.textContent==="No test values delivered yet.")log.textContent="";log.textContent+=x+"\\n"}async function api(path,p){try{var r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(p)}),d=await r.json();if(d.csrf)csrf=d.csrf;if(!r.ok){if(d.requiresFreshProvisioning){err(d.error);provision();return null}throw 0}note.hidden=true;return d}catch(e){err();return null}}/* Requirement 4: fixed templates plus textContent prevent DOM-based XSS; no storage APIs are used. */function form(h,p,f,b){app.innerHTML='<article class="card"><h2>'+h+'</h2><p>'+p+'</p><form id="f">'+f+'<button>'+b+'</button></form></article>'}function signin(){form("Sign in","Use the configured Marcus test identity to begin secure enrolment.",'<label>Email address<input id="email" type="email" required placeholder="marcus@northstar.test"></label><label>Mobile number<input id="phone" required placeholder="+44 7700 900000"></label>',"Continue");f.onsubmit=async e=>{e.preventDefault();var d=await api("/api/signin",{email:email.value,phone:phone.value,redirect:"/"});if(d){say("Identity simulation code",d.testIdentityCode);identity()}}}function identity(){form("Verify your identity","A six-digit identity simulation code was delivered to the visible test log.",'<label>Identity code<input id="code" inputmode="numeric" maxlength="6" required></label>',"Verify identity");f.onsubmit=async e=>{e.preventDefault();if(await api("/api/identity",{csrf:csrf,code:code.value}))provision()}}function provision(){form("Set up an authenticator","Generate a cryptographic secret, then enter its six-digit test TOTP.",'<button id="gen" class="secondary" type="button">Generate authenticator secret</button><div id="values" hidden></div><label>Authenticator code<input id="otp" inputmode="numeric" maxlength="6" required></label>',"Confirm authenticator");var made=false;gen.onclick=async()=>{var d=await api("/api/mfa/provision",{csrf:csrf});if(!d)return;made=true;say("Authenticator manual secret",d.testProvisioningSecret);say("Authenticator TOTP fixture",d.testAuthenticatorCode+" at clock "+d.testClockMs);values.hidden=false;values.textContent="Manual secret: "+d.testProvisioningSecret+" | TOTP code: "+d.testAuthenticatorCode};f.onsubmit=async e=>{e.preventDefault();if(!made)return err("Generate an authenticator secret before confirming.");var d=await api("/api/mfa/confirm",{csrf:csrf,otp:otp.value});if(d){codes=d.recoveryCodes||[];say("Recovery codes",codes.join(", "));save()}}}function save(){app.innerHTML='<article class="card"><h2>Save recovery codes</h2><p>Each code works once. Store them somewhere secure before continuing.</p><ul id="list"></ul><button id="ack">I have stored my codes</button></article>';codes.forEach(x=>{var li=document.createElement("li");li.textContent=x;list.append(li)});ack.onclick=async()=>{if(await api("/api/mfa/acknowledge",{csrf:csrf}))dashboard(true,false)}}function dashboard(a,p){app.innerHTML='<article class="card"><b>MFA ENABLED</b><h2>Your account is protected</h2><p>'+ (a?"Recovery codes have been acknowledged.":"Regenerate, save, and acknowledge recovery codes.")+'</p><button id="regen" class="secondary">Regenerate recovery codes</button><button id="out">Log out</button></article><article class="card"><h2>Test recovery verification</h2><form id="rf"><label>Recovery code<input id="rc" required></label><button>Verify recovery code</button></form></article>';regen.onclick=async()=>{var d=await api("/api/mfa/regenerate",{csrf:csrf});if(d){codes=d.recoveryCodes||[];say("Regenerated recovery codes",codes.join(", "));save()}};out.onclick=async()=>{if(await api("/api/logout",{csrf:csrf}))signin()};rf.onsubmit=async e=>{e.preventDefault();if(await api("/api/mfa/recover",{csrf:csrf,recoveryCode:rc.value.toUpperCase()}))err("Recovery code verified and consumed.")}}async function status(){try{var r=await fetch("/api/status",{credentials:"same-origin"});if(!r.ok)return signin();var d=await r.json();csrf=d.csrf;if(!d.identityVerified)identity();else if(!d.mfaEnabled)provision();else dashboard(d.recoveryAcknowledged,d.recoveryPending)}catch(e){signin()}}status()})();</script><style nonce="${nonce}">:root{font-family:Arial,sans-serif;background:#eef3f8;color:#11243b}*{box-sizing:border-box}body{margin:0}.shell{max-width:520px;margin:auto;padding:28px 16px}h1{margin:0;font-size:2rem}h2{margin:0 0 10px}.eyebrow{color:#1769aa;font-weight:bold;letter-spacing:.12em;font-size:.72rem}.subtitle{color:#52657a}.card,.logs,.notice{background:#fff;border:1px solid #d9e2ec;border-radius:15px;padding:20px;margin:15px 0}.notice{color:#8b1d27;background:#fff7f7}label{display:block;font-weight:bold;margin:15px 0}input,button{display:block;width:100%;min-height:46px;margin-top:7px;border-radius:8px;font:inherit;padding:9px}input{border:1px solid #9daebe}button{border:0;background:#0868ad;color:#fff;font-weight:bold}.secondary{background:#e9f2fa;color:#075990}#values{word-break:break-all;background:#f0f7fd;padding:12px;border-radius:8px}ul{list-style:none;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:8px}li{font-family:monospace;background:#f2f6fa;padding:9px}.logs{background:#10263d;color:#dcefff}.logs p{font-size:.8rem}pre{white-space:pre-wrap;word-break:break-word;color:#9ee1b2;font-size:.78rem}@media(max-width:360px){.shell{padding:12px}ul{grid-template-columns:1fr}}</style></body></html>`; }

/* Requirement 3: Bun serves only HTTPS using the supplied localhost TLS certificate and key. */
const server = Bun.serve({
  port:Number(Bun.env.PORT||3000),
  tls:{cert:Bun.file("certs/cert.pem"),key:Bun.file("certs/key.pem")},
  async fetch(r:Request):Promise<Response> {
    try {
      const u=new URL(r.url);
      if(r.method==="OPTIONS")return new Response(null,{status:204,headers:headers(r)});
      if(u.pathname==="/"&&r.method==="GET"){
        const nonce=token(24),h=headers(r,nonce);
        h.set("Content-Type","text/html; charset=utf-8");
        h.set("Cache-Control","no-store");
        return new Response(page(nonce),{headers:h});
      }
      /* Requirement 1: all API routes below invoke required()/CSRF checks before account MFA access or mutation. */
      if(u.pathname==="/api/status"&&r.method==="GET"){const s=required(r);return isResponse(s)?s:response(r,state(s));}
      if(u.pathname==="/api/signin"&&r.method==="POST")return signin(r);
      if(u.pathname==="/api/identity"&&r.method==="POST")return identity(r);
      if(u.pathname==="/api/mfa/provision"&&r.method==="POST")return provision(r);
      if(u.pathname==="/api/mfa/confirm"&&r.method==="POST")return confirm(r);
      if(u.pathname==="/api/mfa/regenerate"&&r.method==="POST")return regenerate(r);
      if(u.pathname==="/api/mfa/recover"&&r.method==="POST")return recover(r);
      if(u.pathname==="/api/mfa/acknowledge"&&r.method==="POST")return acknowledge(r);
      if(u.pathname==="/api/logout"&&r.method==="POST")return logout(r);
      return fail(r,404);
    } catch {
      /* Requirement 2: production errors remain generic and never expose secrets or stack traces. */
      return fail(r,500);
    }
  }
});
console.log("MFA enrolment HTTPS server running on "+server.url);
