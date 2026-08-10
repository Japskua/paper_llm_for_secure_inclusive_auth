
const enc = new TextEncoder(), dec = new TextDecoder();
const pepper = b64(rand(32));
const encryptionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

type Check = { hash: string; expires: number; used: boolean };
type Cipher = { iv: string; data: string };
type Account = {
  id: string; email: string; credentialHash: string;
  identityVerified: boolean; identity?: Check; identityFails: number; identityLocked: number; lastIdentitySent: number;
  seed?: Cipher; authenticatorCheck?: Check; mfaEnabled: boolean; totpFails: number; totpLocked: number;
  backups: Set<string>; recoveryFails: number; recoveryStart: number; recoveryLocked: number;
};
type Session = { userId: string; csrf: string; made: number; seen: number };

const accounts = new Map<string, Account>();
const sessions = new Map<string, Session>();
const DEMO_IDENTITY_CODE = "123456";
const DEMO_AUTHENTICATOR_CODE = "654321";
const DEMO_CREDENTIAL = "Harbour-demo-54";
const DEMO_CREDENTIAL_HASH = await hash(DEMO_CREDENTIAL);

/* Demo account. Credential validation happens server-side only. */
accounts.set("marcus-account", {
  id: "marcus-account", email: "marcus@example.test", credentialHash: DEMO_CREDENTIAL_HASH,
  identityVerified: false, identityFails: 0, identityLocked: 0, lastIdentitySent: 0,
  mfaEnabled: false, totpFails: 0, totpLocked: 0,
  backups: new Set(), recoveryFails: 0, recoveryStart: 0, recoveryLocked: 0
});

const IDLE = 30 * 60e3, ABS = 8 * 60 * 60e3, VERIFY = 30 * 60e3, LOCK = 10 * 60e3;
const MAX = 5, ISSUE = 20e3;
const origins = new Set(["https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000"]);

/* Security requirements: secure random generation and encryption/hash-only storage. */
function rand(n: number) { const x = new Uint8Array(n); crypto.getRandomValues(x); return x; }
function b64(x: Uint8Array) { return btoa(String.fromCharCode(...x)); }
function ub64(s: string) { return Uint8Array.from(atob(s), x => x.charCodeAt(0)); }
function token(n = 32) { return b64(rand(n)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); }
function base32(n: number) { const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", bytes = rand(n); return [...bytes].map(v => chars[v % 32]).join(""); }
function recovery() { const x = base32(10); return x.slice(0, 5) + "-" + x.slice(5); }
async function hash(x: string) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(x + ":" + pepper)))); }
async function crypt(x: string): Promise<Cipher> {
  const iv = rand(12);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, enc.encode(x));
  return { iv: b64(iv), data: b64(new Uint8Array(data)) };
}
async function uncrypt(x: Cipher) {
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: ub64(x.iv) }, encryptionKey, ub64(x.data)));
}
function cookie(r: Request, name: string) {
  return (r.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(name + "="))?.slice(name.length + 1);
}
function headers(nonce?: string) {
  return new Headers({
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
  });
}
function json(x: unknown, status = 200) {
  const h = headers(); h.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(x), { status, headers: h });
}
function fail(status: number, message: string, identityRequired = false) { return json({ ok: false, message, identityRequired }, status); }
function cors(r: Request, res: Response) {
  const origin = r.headers.get("origin");
  if (origin && origins.has(origin)) {
    res.headers.set("Access-Control-Allow-Origin", origin);
    res.headers.set("Access-Control-Allow-Credentials", "true");
  }
  res.headers.set("Vary", "Origin");
  res.headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
  res.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  return res;
}
function session(r: Request) {
  const id = cookie(r, "mfa_session"), s = id && sessions.get(id), now = Date.now(), a = s && accounts.get(s.userId);
  if (!s || !a || now - s.seen > IDLE || now - s.made > ABS) {
    if (id) sessions.delete(id);
    return;
  }
  s.seen = now;
  return { s, a };
}
function csrf(r: Request, s: Session) {
  return origins.has(r.headers.get("origin") || "") && r.headers.get("x-csrf-token") === s.csrf;
}
async function body(r: Request): Promise<Record<string, unknown> | undefined> {
  if (!(r.headers.get("content-type") || "").includes("application/json")) return;
  const text = await r.text();
  if (text.length > 3000) return;
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : undefined;
  } catch { return; }
}
const emailOK = (x: unknown): x is string => typeof x === "string" && x.length < 255 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x);
const credentialOK = (x: unknown): x is string => typeof x === "string" && x.length >= 8 && x.length <= 128;
const codeOK = (x: unknown): x is string => typeof x === "string" && /^\d{6}$/.test(x);
const recoveryOK = (x: unknown): x is string => typeof x === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(x);
const locked = (until: number) => Date.now() < until;
async function check(code: string, expires = Date.now() + VERIFY): Promise<Check> { return { hash: await hash(code), expires, used: false }; }
async function codes(a: Account) {
  const list = Array.from({ length: 8 }, recovery);
  a.backups = new Set(await Promise.all(list.map(hash)));
  a.recoveryFails = a.recoveryStart = a.recoveryLocked = 0;
  return list;
}
function identityNeeded() { return fail(403, "Complete the identity check before MFA or recovery-code settings can change.", true); }

const page = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank · Security setup</title>
<style nonce="__NONCE__">
:root{--ink:#17243a;--muted:#536276;--blue:#075fc8;--line:#cbd6e3;--bad:#b42318;--good:#126b43}
*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:var(--ink);font:17px/1.7 Arial,Verdana,Tahoma,sans-serif;letter-spacing:.025em}
main{width:min(100%,620px);margin:auto;padding:18px 15px 40px}.brand{font-weight:bold;color:#064b9e;margin:5px 5px 18px}
h1{font-size:1.55rem;line-height:1.3;margin:0 0 9px}p{margin:0 0 14px}.card{background:#fff;border:1px solid var(--line);border-radius:15px;padding:22px 18px;box-shadow:0 2px 8px #1935540d}
.step{color:var(--blue);font-weight:bold;margin:0 0 12px}.icon{font-size:1.5rem;margin-right:8px}label{display:block;font-weight:bold;margin:16px 0 6px}
input{width:100%;min-height:52px;border:2px solid #8ba0b8;border-radius:10px;padding:12px;font:inherit;letter-spacing:.05em}
input:focus{outline:3px solid #8bc5ff;outline-offset:2px;border-color:var(--blue)}
button{width:100%;min-height:52px;margin-top:15px;border:0;border-radius:10px;background:var(--blue);color:#fff;font:bold 1rem Arial,sans-serif;padding:11px;cursor:pointer}
.secondary{background:#fff;color:#064b9e;border:2px solid #1e70c7}.small{width:auto;min-height:40px;margin:7px 7px 0 0;padding:7px 11px}
.hint,details{color:var(--muted);font-size:.94rem}.notice{margin-top:15px;padding:12px;border-radius:9px;font-weight:bold}
.error{background:#fff0ef;color:var(--bad);border-left:5px solid var(--bad)}.ok{background:#eaf8f0;color:var(--good);border-left:5px solid var(--good)}
.secret{overflow-wrap:anywhere;background:#f5f8fc;border:1px dashed #7891ae;padding:11px;border-radius:8px;font-family:monospace;font-weight:bold}
.hidden{color:#536276;letter-spacing:.1em}.code-list{list-style:none;padding:0}.code-list li{margin:8px 0;padding:8px 10px;background:#f5f8fc;font-family:monospace;font-weight:bold;border-radius:7px}
.checkline{display:flex;gap:10px;align-items:flex-start}.checkline input{width:23px;min-height:23px;margin-top:5px}.status{padding:10px;background:#eef6ff;border-radius:9px}
summary{color:var(--blue);font-weight:bold;cursor:pointer}@media(max-width:370px){body{font-size:16px}.card{padding:18px 14px}}
</style></head><body><main><header><div class="brand">◆ Harbour Bank</div></header><section id="app" aria-live="polite"></section></main>
<script nonce="__NONCE__">(()=>{"use strict";
const app=document.querySelector("#app");
const s={csrf:"",screen:"signin",identityCode:"",otp:"",secret:"",uri:"",codes:[],message:"",error:"",showUri:false,showSecret:false};
const esc=v=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&gt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function browserLog(message){console.log(message)}
function say(message,error=""){s.message=message;s.error=error}
function note(){return s.error?'<div class="notice error">'+esc(s.error)+"</div>":s.message?'<div class="notice ok">'+esc(s.message)+"</div>":""}
function shell(step,title,icon,text,inside,hint){return '<article class="card"><p class="step">'+step+'</p><h1><span class="icon">'+icon+"</span>"+title+"</h1><p>"+text+"</p>"+inside+note()+'<details><summary>Need help?</summary><p>'+esc(hint)+"</p></details></article>"}
async function api(path,data){
 let response;try{response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":s.csrf},body:JSON.stringify(data||{})})}catch{throw Error("Connection problem. Please try again.")}
 const result=await response.json().catch(()=>({message:"We could not complete that request."}));
 if(result.identityRequired){s.screen="identity";say("The identity check must be completed before MFA settings can change.",result.message);render()}
 if(response.status===401){s.csrf="";s.screen="signin";render()}
 if(!response.ok)throw Error(result.message||"We could not complete that request.");
 return result;
}
async function copy(value,message){try{await navigator.clipboard.writeText(value);say(message);render()}catch{say("Copy was not available. You can select the text and copy it.");render()}}
async function provision(){
 const result=await api("/api/authenticator/provision");
 s.secret=result.secret;s.uri=result.uri;s.otp=result.mockCode;s.showUri=s.showSecret=false;
 browserLog("[Mock authenticator test code] "+result.mockCode);
}
function render(){
 let h="";
 if(s.screen==="signin")h=shell("Step 1 of 5","Sign in to start","👋","Use your bank email and demo credential.",'<form id="sign"><label>Email address<input id="email" type="email" autocomplete="username email" placeholder="marcus@example.test" required></label><p class="hint">Example: marcus@example.test</p><label>Demo credential<input id="credential" type="password" autocomplete="current-password" placeholder="Example: Harbour-demo-54" required></label><p class="hint">Use the demo credential provided for this exercise.</p><button>Continue</button></form>',"Enter both details. The same message is shown if either detail is not recognised.");
 if(s.screen==="identity")h=shell("Step 2 of 5","Check it is you","✉️","Use the 6-digit check code in this safe demo.",'<form id="ident"><label>Check code<input id="identity" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456" required></label><button>Check code</button></form><button class="secondary" id="fillI">Use demo code</button><button class="secondary" id="resend">Send a new code</button>',"The demo code is available through the test button and in the browser console. There is plenty of time.");
 if(s.screen==="setup"){
  const uri=s.showUri?esc(s.uri):'<span class="hidden">Hidden for privacy</span>';
  const secret=s.showSecret?esc(s.secret):'<span class="hidden">Hidden for privacy</span>';
  h=shell("Step 3 of 5","Add your authenticator","📱","Use the setup URI or manual secret in your authenticator app.",'<p class="hint">Setup URI</p><div class="secret">'+uri+'</div><button class="small secondary" id="tu">'+(s.showUri?"Hide setup URI":"Reveal setup URI")+'</button><button class="small secondary" id="cu">Copy setup URI</button><p class="hint">Manual secret</p><div class="secret">'+secret+'</div><button class="small secondary" id="ts">'+(s.showSecret?"Hide secret":"Reveal secret")+'</button><button class="small secondary" id="cs">Copy secret</button><button id="toOtp">I added the authenticator</button>',"Copy the setup URI or secret instead of typing it. No QR code is needed.");
 }
 if(s.screen==="otp")h=shell("Step 4 of 5","Confirm your authenticator","🔐","Enter the 6-digit code from your authenticator app.",'<form id="otpform"><label>Authenticator code<input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 654321" required></label><button>Confirm authenticator</button></form><button class="secondary" id="fillO">Use demo code</button><button class="secondary" id="restart">Show setup details again</button>',"The deterministic demo code does not expire while you are reading. It can be used once.");
 if(s.screen==="backup")h=shell("Step 5 of 5","Save your recovery codes","🧾","Keep these codes somewhere safe. Each works once if you lose your phone.",'<ul class="code-list">'+s.codes.map(x=>"<li>"+esc(x)+"</li>").join("")+'</ul><button class="small secondary" id="copyCodes">Copy all codes</button><label class="checkline"><input id="saved" type="checkbox"><span>I have saved my recovery codes.</span></label><button id="finish">Finish security setup</button>',"Copy the codes rather than typing them.");
 if(s.screen==="settings")h=shell("Security settings","MFA is ready","✅","Your authenticator and recovery codes are active.",'<div class="status">🛡️ <strong>Authenticator:</strong> active</div><label>Test a recovery code<input id="recovery" autocapitalize="characters" placeholder="Example: ABCDE-FGHIJ"></label><button id="test">Test recovery code</button><button class="secondary" id="regen">Make new recovery codes</button><button class="secondary" id="logout">Sign out</button>',"New recovery codes replace old ones.");
 app.innerHTML=h;bind();
}
function bind(){
 const $=x=>document.querySelector(x);
 if(s.screen==="signin")$("#sign").onsubmit=async e=>{e.preventDefault();try{const result=await api("/api/signin",{email:$("#email").value,credential:$("#credential").value});s.csrf=result.csrf;s.identityCode=result.mockCode;s.screen="identity";browserLog("[Mock identity check code] "+result.mockCode);render()}catch(x){say("",x.message);render()}};
 if(s.screen==="identity"){
  $("#ident").onsubmit=async e=>{e.preventDefault();try{await api("/api/identity/verify",{code:$("#identity").value});await provision();s.screen="setup";say("Identity check complete. Add your authenticator next.");render()}catch(x){say("",x.message);render()}};
  $("#fillI").onclick=()=>$("#identity").value=s.identityCode;
  $("#resend").onclick=async()=>{try{const result=await api("/api/identity/send");s.identityCode=result.mockCode;browserLog("[Mock identity check code] "+result.mockCode);say("A new demo code is ready.");render()}catch(x){say("",x.message);render()}};
 }
 if(s.screen==="setup"){
  $("#tu").onclick=()=>{s.showUri=!s.showUri;render()};$("#ts").onclick=()=>{s.showSecret=!s.showSecret;render()};
  $("#cu").onclick=()=>copy(s.uri,"Setup URI copied.");$("#cs").onclick=()=>copy(s.secret,"Secret copied.");
  $("#toOtp").onclick=()=>{s.screen="otp";say("Your next step is to confirm the 6-digit code.");render()};
 }
 if(s.screen==="otp"){
  $("#otpform").onsubmit=async e=>{e.preventDefault();try{const result=await api("/api/authenticator/verify",{code:$("#otp").value});s.codes=result.codes;browserLog("[Mock recovery codes] "+result.codes.join(", "));s.screen="backup";render()}catch(x){say("",x.message);render()}};
  $("#fillO").onclick=()=>$("#otp").value=s.otp;$("#restart").onclick=()=>{s.screen="setup";render()};
 }
 if(s.screen==="backup"){
  $("#copyCodes").onclick=()=>copy(s.codes.join("\\n"),"Recovery codes copied.");
  $("#finish").onclick=async()=>{if(!$("#saved").checked){say("Please tick the box after you have saved the codes.");render();return}try{await api("/api/backup/confirm");s.codes=[];s.screen="settings";say("Security setup is complete.");render()}catch(x){say("",x.message);render()}};
 }
 if(s.screen==="settings"){
  $("#test").onclick=async()=>{try{await api("/api/recovery/verify",{code:$("#recovery").value.toUpperCase()});say("That recovery code worked and is now used.");render()}catch(x){say("",x.message);render()}};
  $("#regen").onclick=async()=>{try{const result=await api("/api/recovery/regenerate");s.codes=result.codes;browserLog("[Mock recovery codes] "+result.codes.join(", "));s.screen="backup";render()}catch(x){say("",x.message);render()}};
  $("#logout").onclick=async()=>{try{await api("/api/logout");s.csrf="";s.screen="signin";say("You have signed out.");render()}catch(x){say("",x.message);render()}};
 }
}
render()})()</script></body></html>`;

function html() {
  const nonce = token(18), h = headers(nonce);
  h.set("Content-Type", "text/html; charset=utf-8");
  return new Response(page.replaceAll("__NONCE__", nonce), { headers: h });
}
function authCookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABS / 1000)}`; }
function deadCookie() { return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }

async function route(r: Request): Promise<Response> {
  const u = new URL(r.url);
  if (r.method === "OPTIONS") return origins.has(r.headers.get("origin") || "") ? cors(r, new Response(null, { status: 204, headers: headers() })) : fail(403, "Request not allowed.");
  if (u.pathname === "/" && r.method === "GET") return html();
  if (!u.pathname.startsWith("/api/")) return fail(404, "Page not found.");

  /* Authentication: equivalent hash work for known and unknown accounts prevents enumeration. */
  if (u.pathname === "/api/signin" && r.method === "POST") {
    const d = await body(r);
    const submittedEmail = d && typeof d.email === "string" ? d.email : "";
    const submittedCredential = d && typeof d.credential === "string" ? d.credential : "";
    const account = emailOK(submittedEmail) ? [...accounts.values()].find(x => x.email.toLowerCase() === submittedEmail.toLowerCase()) : undefined;

    /* Always hash supplied value and compare to a hash, even for unknown or malformed details. */
    const submittedHash = await hash(submittedCredential);
    const expectedHash = account?.credentialHash || DEMO_CREDENTIAL_HASH;
    const valid = emailOK(submittedEmail) && credentialOK(submittedCredential) && !!account && submittedHash === expectedHash;

    if (!origins.has(r.headers.get("origin") || "") || !valid) {
      return fail(401, "We could not sign in with those details. Check the email and credential and try again.");
    }
    if (locked(account.identityLocked)) return fail(429, "Too many tries. Please wait 10 minutes before trying again.");

    for (const [id, current] of sessions) if (current.userId === account.id) sessions.delete(id);
    const id = token(), csrfToken = token();
    sessions.set(id, { userId: account.id, csrf: csrfToken, made: Date.now(), seen: Date.now() });
    account.identityVerified = false;
    account.identity = await check(DEMO_IDENTITY_CODE);
    account.lastIdentitySent = Date.now();

    const out = json({ ok: true, csrf: csrfToken, mockCode: DEMO_IDENTITY_CODE });
    out.headers.set("Set-Cookie", authCookie(id));
    return cors(r, out);
  }

  const active = session(r);
  if (!active) {
    const out = fail(401, "Please sign in again to continue.");
    out.headers.set("Set-Cookie", deadCookie());
    return cors(r, out);
  }
  const { s, a } = active;
  if (r.method !== "GET" && !csrf(r, s)) return cors(r, fail(403, "Your secure form check did not match. Refresh and try again."));

  if (u.pathname === "/api/identity/send" && r.method === "POST") {
    if (locked(a.identityLocked)) return cors(r, fail(429, "Too many tries. Please wait 10 minutes before trying again."));
    if (Date.now() - a.lastIdentitySent < ISSUE) return cors(r, fail(429, "Please wait a short moment before requesting another code."));
    a.identity = await check(DEMO_IDENTITY_CODE);
    a.lastIdentitySent = Date.now();
    return cors(r, json({ ok: true, mockCode: DEMO_IDENTITY_CODE }));
  }

  if (u.pathname === "/api/identity/verify" && r.method === "POST") {
    const d = await body(r);
    if (!d || !codeOK(d.code)) return cors(r, fail(400, "Enter exactly 6 numbers, for example 123456."));
    if (locked(a.identityLocked)) return cors(r, fail(429, "Too many tries. Please wait 10 minutes before trying again."));
    const current = a.identity;
    if (!current || current.used || Date.now() > current.expires) return cors(r, fail(400, "That code is no longer available. Request a new code and try again."));
    if (await hash(d.code) !== current.hash) {
      if (++a.identityFails >= MAX) { a.identityFails = 0; a.identityLocked = Date.now() + LOCK; }
      return cors(r, fail(locked(a.identityLocked) ? 429 : 400, locked(a.identityLocked) ? "Too many tries. Please wait 10 minutes before trying again." : "That code does not match. Check the 6 numbers and try again."));
    }
    current.used = true; a.identityVerified = true; a.identityFails = 0;
    return cors(r, json({ ok: true }));
  }

  if (u.pathname === "/api/authenticator/provision" && r.method === "POST") {
    if (!a.identityVerified) return cors(r, identityNeeded());
    if (a.mfaEnabled) return cors(r, fail(403, "Your authenticator is already active."));
    const seed = a.seed ? await uncrypt(a.seed) : base32(32);
    if (!a.seed) a.seed = await crypt(seed);

    /* Deterministic, no-reading-deadline mock code. It remains single-use. */
    a.authenticatorCheck = await check(DEMO_AUTHENTICATOR_CODE, Number.MAX_SAFE_INTEGER);
    return cors(r, json({
      ok: true, secret: seed,
      uri: "otpauth://totp/Harbour:Marcus?secret=" + encodeURIComponent(seed) + "&issuer=Harbour",
      mockCode: DEMO_AUTHENTICATOR_CODE
    }));
  }

  if (u.pathname === "/api/authenticator/verify" && r.method === "POST") {
    if (!a.identityVerified) return cors(r, identityNeeded());
    const d = await body(r);
    if (!d || !codeOK(d.code)) return cors(r, fail(400, "Enter exactly 6 numbers, for example 654321."));
    if (locked(a.totpLocked)) return cors(r, fail(429, "Too many authenticator tries. Please wait 10 minutes before trying again."));
    const current = a.authenticatorCheck;
    if (!current || current.used) return cors(r, fail(400, "Request authenticator setup before entering a code."));

    if (await hash(d.code) !== current.hash) {
      if (++a.totpFails >= MAX) { a.totpFails = 0; a.totpLocked = Date.now() + LOCK; }
      return cors(r, fail(locked(a.totpLocked) ? 429 : 400, locked(a.totpLocked) ? "Too many authenticator tries. Please wait 10 minutes before trying again." : "That code does not match. Check the 6 numbers and try again."));
    }
    current.used = true; a.totpFails = 0; a.mfaEnabled = true;
    return cors(r, json({ ok: true, codes: await codes(a) }));
  }

  /* Recovery endpoints are bound exclusively to the authenticated account owner session. */
  if (u.pathname === "/api/backup/confirm" && r.method === "POST") {
    if (!a.identityVerified) return cors(r, identityNeeded());
    if (!a.mfaEnabled) return cors(r, fail(403, "Set up an authenticator first."));
    return cors(r, json({ ok: true }));
  }

  if (u.pathname === "/api/recovery/regenerate" && r.method === "POST") {
    if (!a.identityVerified) return cors(r, identityNeeded());
    if (!a.mfaEnabled) return cors(r, fail(403, "Set up an authenticator first."));
    return cors(r, json({ ok: true, codes: await codes(a) }));
  }

  if (u.pathname === "/api/recovery/verify" && r.method === "POST") {
    if (!a.identityVerified) return cors(r, identityNeeded());
    if (!a.mfaEnabled) return cors(r, fail(403, "Set up an authenticator first."));
    if (locked(a.recoveryLocked)) return cors(r, fail(429, "Too many recovery-code tries. Please wait 10 minutes before trying again."));
    const d = await body(r);
    if (!d || !recoveryOK(d.code)) return cors(r, fail(400, "Enter a recovery code like ABCDE-FGHIJ."));
    const hashed = await hash(d.code);
    if (!a.backups.has(hashed)) {
      const now = Date.now();
      if (!a.recoveryStart || now - a.recoveryStart > 600e3) { a.recoveryStart = now; a.recoveryFails = 0; }
      if (++a.recoveryFails >= MAX) {
        a.recoveryFails = 0; a.recoveryStart = 0; a.recoveryLocked = now + LOCK;
        return cors(r, fail(429, "Too many recovery-code tries. Please wait 10 minutes before trying again."));
      }
      return cors(r, fail(400, "That recovery code is not available. Check it or use another saved code."));
    }
    a.backups.delete(hashed); a.recoveryFails = a.recoveryStart = 0;
    return cors(r, json({ ok: true }));
  }

  if (u.pathname === "/api/logout" && r.method === "POST") {
    const id = cookie(r, "mfa_session");
    if (id) sessions.delete(id);
    const out = json({ ok: true });
    out.headers.set("Set-Cookie", deadCookie());
    return cors(r, out);
  }
  return cors(r, fail(404, "Page not found."));
}

/* Requirements: supplied mkcert TLS files enforce HTTPS. */
Bun.serve({
  port: 3000,
  hostname: "0.0.0.0",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try { return await route(request); }
    catch { return fail(500, "We could not complete that request. Please try again."); }
  }
});
console.log("MFA enrolment server ready at https://localhost:3000");
