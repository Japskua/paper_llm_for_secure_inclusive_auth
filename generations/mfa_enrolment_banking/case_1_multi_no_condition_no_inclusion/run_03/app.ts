
const encoder = new TextEncoder();
const TEST_MODE = true;
const STEP = 30, IDLE = 1_200_000, ABS = 28_800_000, CODE_LIFE = 300_000, PROVISION_LIFE = 300_000, LOCK = 600_000, MAX = 5;
const IDENTITY_CODE = "135790";
const MARCUS = { id: "account-owner-marcus", email: "marcus@northstar.test", phone: "+447700900000" };

type Session = { id:string; userId:string; csrf:string; created:number; seen:number; authenticated:boolean; verified:boolean; recoveryPending:boolean; recoveryAcknowledged:boolean };
type Security = { identityHash:string; identityExpires:number; identityUsed:boolean; identityFailures:number; identityLocked:number; authFailures:number; authLocked:number };
type Verifier = { salt:string; verifier:string };
type Mfa = { encryptedSecret:string; enabled:boolean; expires?:number; recoveryFailures:number; recoveryLocked:number; codes:Verifier[] };

const port = Number(Bun.env.PORT || 3000);
/* Requirement 2: explicit configured-origin allow-list. */
const trustedOrigins = new Set([
  `https://localhost:${port}`,
  `https://127.0.0.1:${port}`,
  `https://[::1]:${port}`
]);

const sessions = new Map<string, Session>();
const mfas = new Map<string, Mfa>();
const security = new Map<string, Security>();
const locks = new Map<string, Promise<void>>();
const encryptionKey = await crypto.subtle.generateKey({ name:"AES-GCM", length:256 }, true, ["encrypt", "decrypt"]);
const credentialSalt = encoder.encode("northstar-mfa-signin-credential-work-v1");

function bytes(n:number) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }
function b64(a:Uint8Array) { let s = ""; for (const x of a) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); }
function unb64(s:string) { return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), x => x.charCodeAt(0)); }
function token(n=32) { return b64(bytes(n)); }
function recoveryCode() { const a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", b = bytes(10); let s = ""; for (const x of b) s += a[x % a.length]; return s.slice(0, 5) + "-" + s.slice(5); }
async function hash(s:string) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(s)))); }
function equal(a:string, b:string) { if (a.length !== b.length) return false; let x = 0; for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i); return x === 0; }
async function encrypt(s:string) { const iv = bytes(12), v = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, encryptionKey, encoder.encode(s)); return b64(iv) + "." + b64(new Uint8Array(v)); }
async function decrypt(s:string) { const p = s.split("."); if (p.length !== 2) throw Error("protected"); return new TextDecoder().decode(await crypto.subtle.decrypt({ name:"AES-GCM", iv:unb64(p[0]) }, encryptionKey, unb64(p[1]))); }

/* Requirement 3: recovery codes are stored only as salted PBKDF2 verifiers. */
async function verifier(s:string):Promise<Verifier> {
  const salt = bytes(16), k = await crypto.subtle.importKey("raw", encoder.encode(s), "PBKDF2", false, ["deriveBits"]);
  const v = await crypto.subtle.deriveBits({ name:"PBKDF2", hash:"SHA-256", salt, iterations:120000 }, k, 256);
  return { salt:b64(salt), verifier:b64(new Uint8Array(v)) };
}
async function verifyVerifier(s:string, v:Verifier) {
  const k = await crypto.subtle.importKey("raw", encoder.encode(s), "PBKDF2", false, ["deriveBits"]);
  const x = await crypto.subtle.deriveBits({ name:"PBKDF2", hash:"SHA-256", salt:unb64(v.salt), iterations:120000 }, k, 256);
  return equal(b64(new Uint8Array(x)), v.verifier);
}
/* Requirement 5: accepted and rejected credentials share a costly PBKDF2 path. */
async function credentialDigest(value:string) {
  const bounded = value.slice(0, 256);
  const key = await crypto.subtle.importKey("raw", encoder.encode(bounded), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name:"PBKDF2", hash:"SHA-256", salt:credentialSalt, iterations:120000 }, key, 256);
  return b64(new Uint8Array(bits));
}

/* Task: current-time RFC-style TOTP calculation. A code is valid only in its current
   30-second period; therefore it expires automatically at that period boundary. */
async function totp(secret:string, ms:number) {
  let n = Math.floor(ms / 1000 / STEP), m = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) { m[i] = n & 255; n = Math.floor(n / 256); }
  const k = await crypto.subtle.importKey("raw", encoder.encode(secret), { name:"HMAC", hash:"SHA-1" }, false, ["sign"]);
  const a = new Uint8Array(await crypto.subtle.sign("HMAC", k, m)), o = a[19] & 15;
  const d = (((a[o] & 127) << 24) | (a[o + 1] << 16) | (a[o + 2] << 8) | a[o + 3]) >>> 0;
  return String(d % 1000000).padStart(6, "0");
}
function now() { return Date.now(); }
function periodEndsAt(ms=now()) { return (Math.floor(ms / (STEP * 1000)) + 1) * STEP * 1000; }
function trusted(o:string|null) { return !!o && trustedOrigins.has(o); }
function cookies(r:Request) {
  const o:Record<string,string> = {};
  for (const x of (r.headers.get("cookie") || "").split(";")) {
    const i = x.indexOf("=");
    if (i > 0) o[x.slice(0, i).trim()] = x.slice(i + 1).trim();
  }
  return o;
}
function cookie(id:string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABS / 1000)}`; }
function expired() { return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }

/* Requirement 2: security response headers and restricted CORS. */
function headers(r:Request, nonce?:string, extra:HeadersInit={}) {
  const h = new Headers(extra);
  const script = nonce ? `script-src 'nonce-${nonce}'` : "script-src 'none'";
  const style = nonce ? `style-src 'nonce-${nonce}'` : "style-src 'none'";
  h.set("Content-Security-Policy", `default-src 'self'; connect-src 'self'; img-src 'self'; ${script}; ${style}; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`);
  h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "no-referrer");
  const o = r.headers.get("origin");
  if (trusted(o)) {
    h.set("Access-Control-Allow-Origin", o!);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Access-Control-Allow-Headers", "Content-Type");
    h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    h.set("Vary", "Origin");
  }
  return h;
}
function response(r:Request, b:unknown, status=200, extra:HeadersInit={}) {
  const h = headers(r, undefined, extra);
  h.set("Content-Type", "application/json; charset=utf-8");
  h.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(b), { status, headers:h });
}
function fail(r:Request, status=400) { return response(r, { error:"Request could not be completed." }, status); }
function getSession(r:Request) {
  const id = cookies(r).mfa_session, s = id && sessions.get(id);
  if (!id || !s || !/^[A-Za-z0-9_-]{30,}$/.test(id)) return null;
  if (now() - s.seen > IDLE || now() - s.created > ABS) { sessions.delete(id); return null; }
  s.seen = now();
  return s;
}
/* Requirement 1: all MFA endpoints derive the account solely from the session. */
function required(r:Request, verified=false):Session|Response {
  const s = getSession(r);
  return !s || !s.authenticated || !s.userId ? fail(r, 401) : verified && !s.verified ? fail(r, 403) : s;
}
function isResponse(x:unknown):x is Response { return x instanceof Response; }
/* Requirement 1: every state-changing request needs trusted Origin and exact CSRF token. */
function csrf(r:Request, s:Session, b:Record<string,unknown>) {
  const c = b.csrf;
  return trusted(r.headers.get("origin")) && typeof c === "string" && /^[A-Za-z0-9_-]{30,}$/.test(c) && equal(c, s.csrf);
}
async function body(r:Request, keys:string[]) {
  if (!(r.headers.get("content-type") || "").toLowerCase().startsWith("application/json")) return null;
  try {
    const x:unknown = await r.json();
    if (!x || typeof x !== "object" || Array.isArray(x)) return null;
    const b = x as Record<string,unknown>;
    return Object.keys(b).every(k => keys.includes(k)) ? b : null;
  } catch { return null; }
}
function sec() {
  let s = security.get(MARCUS.id);
  if (!s) {
    s = { identityHash:"", identityExpires:0, identityUsed:true, identityFailures:0, identityLocked:0, authFailures:0, authLocked:0 };
    security.set(MARCUS.id, s);
  }
  return s;
}
function addFail(o:any, k:"identity"|"auth"|"recovery") {
  const f = k === "identity" ? "identityFailures" : k === "auth" ? "authFailures" : "recoveryFailures";
  const l = k === "identity" ? "identityLocked" : k === "auth" ? "authLocked" : "recoveryLocked";
  if ((o[f] || 0) + 1 >= MAX) { o[f] = 0; o[l] = now() + LOCK; } else o[f] = (o[f] || 0) + 1;
}
function clearFail(o:any, k:"identity"|"auth"|"recovery") { o[k === "identity" ? "identityFailures" : k === "auth" ? "authFailures" : "recoveryFailures"] = 0; }
function lock<T>(u:string, f:()=>Promise<T>) {
  const p = locks.get(u) || Promise.resolve();
  let release!:()=>void;
  const g = new Promise<void>(r => release = r), tail = p.then(() => g);
  locks.set(u, tail);
  return p.then(f).finally(() => { release(); if (locks.get(u) === tail) locks.delete(u); });
}
function clearPending(u:string) {
  const m = mfas.get(u);
  if (m && !m.enabled && (!m.expires || now() > m.expires)) { mfas.delete(u); return true; }
  return false;
}
function state(s:Session) {
  if (s.userId) clearPending(s.userId);
  const m = s.userId && mfas.get(s.userId);
  return { csrf:s.csrf, authenticated:s.authenticated, identityVerified:s.verified, mfaEnabled:!!m?.enabled, recoveryPending:s.recoveryPending, recoveryAcknowledged:s.recoveryAcknowledged };
}
function fresh():Session { return { id:token(), userId:"", csrf:token(), created:now(), seen:now(), authenticated:false, verified:false, recoveryPending:false, recoveryAcknowledged:false }; }

async function signin(r:Request) {
  const old = getSession(r), b = await body(r, ["csrf", "email", "phone", "redirect"]);
  const emailRaw = b && typeof b.email === "string" ? b.email : "";
  const phoneRaw = b && typeof b.phone === "string" ? b.phone : "";
  const email = emailRaw.slice(0, 256).toLowerCase();
  const phone = phoneRaw.slice(0, 64).replace(/[ ()-]/g, "");
  const formatValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && /^\+?[0-9 ()-]{7,24}$/.test(phoneRaw);
  const candidate = formatValid ? email + "\0" + phone : "\0invalid-signin-attempt";
  const expected = MARCUS.email + "\0" + MARCUS.phone;
  const [candidateDigest, expectedDigest] = await Promise.all([credentialDigest(candidate), credentialDigest(expected)]);
  const credentialsValid = formatValid && equal(candidateDigest, expectedDigest);

  if (!old || old.authenticated || !b || !csrf(r, old, b) || b.redirect !== "/" || !credentialsValid) return fail(r);
  return lock(MARCUS.id, async () => {
    const q = sec();
    if (now() < q.identityLocked) return fail(r);
    q.identityHash = await hash(IDENTITY_CODE);
    q.identityExpires = now() + CODE_LIFE;
    q.identityUsed = false;
    sessions.delete(old.id);
    const s = { ...fresh(), userId:MARCUS.id, authenticated:true };
    sessions.set(s.id, s);
    return response(r, { csrf:s.csrf, testIdentityCode:TEST_MODE ? IDENTITY_CODE : undefined }, 200, { "Set-Cookie":cookie(s.id) });
  });
}
async function identity(r:Request) {
  const s = required(r);
  if (isResponse(s)) return s;
  const b = await body(r, ["csrf", "code"]);
  if (!b || !csrf(r, s, b) || typeof b.code !== "string" || !/^\d{6}$/.test(b.code)) return fail(r);
  return lock(s.userId, async () => {
    const q = sec(), ok = now() >= q.identityLocked && !q.identityUsed && now() <= q.identityExpires && equal(await hash(b.code as string), q.identityHash);
    if (!ok) { if (now() >= q.identityLocked) addFail(q, "identity"); return fail(r); }
    q.identityUsed = true; clearFail(q, "identity");
    sessions.delete(s.id);
    const n = { ...fresh(), userId:s.userId, authenticated:true, verified:true };
    sessions.set(n.id, n);
    return response(r, state(n), 200, { "Set-Cookie":cookie(n.id) });
  });
}
async function provision(r:Request) {
  const s = required(r, true);
  if (isResponse(s)) return s;
  const b = await body(r, ["csrf"]);
  if (!b || !csrf(r, s, b)) return fail(r);
  return lock(s.userId, async () => {
    clearPending(s.userId);
    if (mfas.has(s.userId)) return fail(r, 409);
    const secret = b64(bytes(20)), expires = now() + PROVISION_LIFE;
    mfas.set(s.userId, { encryptedSecret:await encrypt(secret), enabled:false, expires, recoveryFailures:0, recoveryLocked:0, codes:[] });
    const fixtureTime = now();
    return response(r, {
      ...state(s),
      testProvisioningSecret:TEST_MODE ? secret : undefined,
      testAuthenticatorCode:TEST_MODE ? await totp(secret, fixtureTime) : undefined,
      testTotpPeriodEndsAt:periodEndsAt(fixtureTime)
    });
  });
}
async function confirm(r:Request) {
  const s = required(r, true);
  if (isResponse(s)) return s;
  const b = await body(r, ["csrf", "otp"]);
  if (!b || !csrf(r, s, b) || typeof b.otp !== "string" || !/^\d{6}$/.test(b.otp)) return fail(r);
  return lock(s.userId, async () => {
    if (clearPending(s.userId)) return response(r, { error:"Authenticator setup expired.", requiresFreshProvisioning:true }, 410);
    const m = mfas.get(s.userId), q = sec();
    if (!m || m.enabled || !m.expires || now() < q.authLocked) return fail(r);
    const validationTime = now();
    /* No fixed clock or broad skew: only this live 30-second TOTP period is accepted. */
    const ok = equal(b.otp as string, await totp(await decrypt(m.encryptedSecret), validationTime));
    if (!ok || validationTime > m.expires) { if (!ok) addFail(q, "auth"); return fail(r); }
    clearFail(q, "auth");
    m.enabled = true; delete m.expires;
    const generated = Array.from({ length:8 }, recoveryCode);
    m.codes = await Promise.all(generated.map(verifier));
    s.recoveryPending = true;
    s.recoveryAcknowledged = false;
    return response(r, { ...state(s), recoveryCodes:generated });
  });
}
/* Requirement 3/task: generated plaintext codes are returned only in this immediate,
   authorized response. They are never retained by the server for a later redisplay. */
async function codes(r:Request, ack=false) {
  const s = required(r, true);
  if (isResponse(s)) return s;
  const b = await body(r, ["csrf"]);
  if (!b || !csrf(r, s, b)) return fail(r);
  const m = mfas.get(s.userId);
  if (ack) {
    if (!s.recoveryPending) return fail(r);
    s.recoveryPending = false; s.recoveryAcknowledged = true;
    return response(r, state(s));
  }
  if (!m?.enabled) return fail(r, 403);
  const generated = Array.from({ length:8 }, recoveryCode);
  m.codes = await Promise.all(generated.map(verifier));
  s.recoveryPending = true; s.recoveryAcknowledged = false;
  return response(r, { ...state(s), recoveryCodes:generated });
}

/* Task: authenticated, CSRF-protected, single-use recovery code verification. */
async function verifyRecovery(r:Request) {
  const s = required(r, true);
  if (isResponse(s)) return s;
  const b = await body(r, ["csrf", "code"]);
  if (!b || !csrf(r, s, b) || typeof b.code !== "string") return fail(r);
  const supplied = b.code.trim().toUpperCase();
  if (!/^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/.test(supplied)) return fail(r);
  return lock(s.userId, async () => {
    const m = mfas.get(s.userId);
    if (!m?.enabled || now() < m.recoveryLocked) return fail(r);
    let match = -1;
    for (let i = 0; i < m.codes.length; i++) {
      if (await verifyVerifier(supplied, m.codes[i])) { match = i; break; }
    }
    if (match < 0) {
      addFail(m, "recovery");
      return fail(r);
    }
    /* Removing inside the account lock makes a successful recovery code single-use. */
    m.codes.splice(match, 1);
    clearFail(m, "recovery");
    return response(r, { ...state(s), recoveryCodeAccepted:true, remainingRecoveryCodes:m.codes.length });
  });
}
async function logout(r:Request) {
  const s = required(r);
  if (isResponse(s)) return s;
  const b = await body(r, ["csrf"]);
  if (!b || !csrf(r, s, b)) return fail(r);
  sessions.delete(s.id);
  return response(r, { ok:true }, 200, { "Set-Cookie":expired() });
}

function page(n:string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar MFA</title>
<style nonce="${n}">
body{margin:0;background:#eef3f8;font:16px Arial,sans-serif;color:#11243b}main{max-width:520px;margin:auto;padding:22px 16px}header{padding:4px 2px}h1{margin:.4rem 0;font-size:1.8rem}h2{margin-top:0}article,.logs,#note{background:#fff;border:1px solid #d9e2ec;border-radius:14px;padding:18px;margin:15px 0}label{display:block;font-weight:bold}input,button{display:block;width:100%;box-sizing:border-box;min-height:44px;margin:7px 0 14px;padding:8px;font:inherit}input{border:1px solid #9babbc;border-radius:7px}button{background:#0868ad;color:#fff;border:0;border-radius:7px;font-weight:bold;cursor:pointer}button.secondary{background:#50677b}.logs{background:#10263d;color:#dcefff}pre{white-space:pre-wrap;overflow-wrap:anywhere;color:#9ee1b2;margin-bottom:0}li{font-family:monospace;margin:6px 0}#note{color:#8b1d27}.fixture{background:#f1f7fb;padding:10px;border-radius:7px;overflow-wrap:anywhere}
</style>
</head>
<body>
<main>
<header><b>NORTHSTAR BANK</b><h1>Security setup</h1></header>
<p id="note" hidden aria-live="polite"></p>
<section id="app" aria-live="polite">Loading…</section>
<section class="logs" aria-label="Test logs"><h2>Logs</h2><pre id="log">No test values delivered yet.</pre></section>
</main>
<script nonce="${n}">
(function(){
  const app=document.querySelector('#app'), note=document.querySelector('#note'), logs=document.querySelector('#log');
  let csrfToken='', recoveryCodes=[];

  function showError(message){note.textContent=message||'We could not complete that request.';note.hidden=false;}
  function say(label,value){const line=label+': '+value;console.log(line);logs.textContent=logs.textContent==='No test values delivered yet.'?line+'\\n':logs.textContent+line+'\\n';}
  async function api(path,payload){
    try{
      const result=await fetch(path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
      const data=await result.json();
      if(data.csrf)csrfToken=data.csrf;
      if(!result.ok)throw new Error('request failed');
      note.hidden=true;return data;
    }catch(_){showError();return null;}
  }
  function formView(title,text,fields,buttonText){
    app.innerHTML='<article><h2></h2><p></p><form novalidate>'+fields+'<button type="submit"></button></form></article>';
    const view=app.querySelector('article');view.querySelector('h2').textContent=title;view.querySelector('p').textContent=text;view.querySelector('form button[type="submit"]').textContent=buttonText;
    return {view:view,form:view.querySelector('form')};
  }
  function signIn(){
    const rendered=formView('Sign in','Use your registered email address and phone number.','<label>Email<input name="email" type="email" autocomplete="email" required></label><label>Phone<input name="phone" type="tel" autocomplete="tel" required></label>','Continue');
    const form=rendered.form,emailInput=form.querySelector('input[name="email"]'),phoneInput=form.querySelector('input[name="phone"]');
    form.addEventListener('submit',async function(event){event.preventDefault();const data=await api('/api/signin',{csrf:csrfToken,email:emailInput.value,phone:phoneInput.value,redirect:'/'});if(data){if(data.testIdentityCode)say('Identity simulation code',data.testIdentityCode);verifyIdentity();}});
  }
  function verifyIdentity(){
    const rendered=formView('Verify identity','Enter the delivered six-digit code.','<label>Verification code<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required></label>','Verify');
    const form=rendered.form,codeInput=form.querySelector('input[name="code"]');
    form.addEventListener('submit',async function(event){event.preventDefault();if(await api('/api/identity',{csrf:csrfToken,code:codeInput.value}))provisionAuthenticator();});
  }
  function provisionAuthenticator(){
    const rendered=formView('Authenticator','Generate a secret, add it to an authenticator, then enter its current code.','<button type="button" class="secondary" data-action="generate">Generate secret</button><p class="fixture" data-role="provisioning-status">No secret generated yet.</p><label>Authenticator code<input name="otp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required></label>','Confirm');
    const form=rendered.form,generateButton=form.querySelector('button[data-action="generate"]'),statusOutput=form.querySelector('[data-role="provisioning-status"]'),otpInput=form.querySelector('input[name="otp"]');
    let made=false;
    generateButton.addEventListener('click',async function(){
      const data=await api('/api/mfa/provision',{csrf:csrfToken});
      if(data){made=true;const expiry=new Date(data.testTotpPeriodEndsAt).toLocaleTimeString();statusOutput.textContent='Manual secret: '+data.testProvisioningSecret+' | Current test code: '+data.testAuthenticatorCode+' (expires at '+expiry+')';say('Authenticator manual secret',data.testProvisioningSecret);say('Authenticator current TOTP fixture',data.testAuthenticatorCode);}
    });
    form.addEventListener('submit',async function(event){event.preventDefault();if(!made){showError('Generate a secret first.');return;}const data=await api('/api/mfa/confirm',{csrf:csrfToken,otp:otpInput.value});if(data){recoveryCodes=data.recoveryCodes;say('Recovery codes',recoveryCodes.join(', '));saveCodes();}});
  }
  function saveCodes(){
    app.innerHTML='<article><h2>Save recovery codes</h2><p>Store these codes somewhere safe. Each code can be used once.</p><ul data-role="recovery-codes"></ul><form><button type="submit">I have stored my codes</button></form></article>';
    const view=app.querySelector('article'),list=view.querySelector('[data-role="recovery-codes"]'),form=view.querySelector('form');
    recoveryCodes.forEach(function(code){const item=document.createElement('li');item.textContent=code;list.append(item);});
    form.addEventListener('submit',async function(event){event.preventDefault();if(await api('/api/mfa/acknowledge',{csrf:csrfToken})){recoveryCodes=[];dashboard();}});
  }
  /* Task: after reload, plaintext codes cannot be recovered. The pending state remains
     an acknowledgement view and offers deliberate, authorized regeneration instead. */
  function pendingRecovery(){
    if(recoveryCodes.length){saveCodes();return;}
    app.innerHTML='<article><h2>Save recovery codes</h2><p>Your recovery-code acknowledgement is still pending. For security, previously displayed codes cannot be shown again.</p><form data-action="regenerate"><button type="submit">Generate a new set of recovery codes</button></form><form data-action="acknowledge"><button type="submit" class="secondary">I already stored my codes</button></form></article>';
    const view=app.querySelector('article');
    view.querySelector('form[data-action="regenerate"]').addEventListener('submit',async function(event){event.preventDefault();const data=await api('/api/mfa/regenerate',{csrf:csrfToken});if(data){recoveryCodes=data.recoveryCodes;say('Regenerated recovery codes',recoveryCodes.join(', '));saveCodes();}});
    view.querySelector('form[data-action="acknowledge"]').addEventListener('submit',async function(event){event.preventDefault();if(await api('/api/mfa/acknowledge',{csrf:csrfToken}))dashboard();});
  }
  function dashboard(){
    app.innerHTML='<article><h2>MFA enabled</h2><p>Your authenticator is now enrolled.</p><form data-action="recovery"><label>Use a recovery code<input name="code" autocomplete="one-time-code" placeholder="ABCDE-FGHIJ" required></label><button type="submit">Verify recovery code</button></form><p class="fixture" data-role="recovery-result" hidden></p><form data-action="regenerate"><button type="submit">Regenerate recovery codes</button></form><form data-action="logout"><button type="submit" class="secondary">Log out</button></form></article>';
    const view=app.querySelector('article'),recoveryForm=view.querySelector('form[data-action="recovery"]'),regenerateForm=view.querySelector('form[data-action="regenerate"]'),logoutForm=view.querySelector('form[data-action="logout"]'),result=view.querySelector('[data-role="recovery-result"]');
    recoveryForm.addEventListener('submit',async function(event){event.preventDefault();const code=recoveryForm.querySelector('input[name="code"]').value;const data=await api('/api/mfa/recovery/verify',{csrf:csrfToken,code:code});if(data){result.hidden=false;result.textContent='Recovery code accepted. Remaining unused codes: '+data.remainingRecoveryCodes+'.';recoveryForm.reset();}});
    regenerateForm.addEventListener('submit',async function(event){event.preventDefault();const data=await api('/api/mfa/regenerate',{csrf:csrfToken});if(data){recoveryCodes=data.recoveryCodes;say('Regenerated recovery codes',recoveryCodes.join(', '));saveCodes();}});
    logoutForm.addEventListener('submit',async function(event){event.preventDefault();if(await api('/api/logout',{csrf:csrfToken}))signIn();});
  }
  async function status(){
    try{
      const result=await fetch('/api/status',{credentials:'same-origin'}),data=await result.json();csrfToken=data.csrf||'';
      if(!data.authenticated)signIn();
      else if(!data.identityVerified)verifyIdentity();
      else if(!data.mfaEnabled)provisionAuthenticator();
      else if(data.recoveryPending)pendingRecovery();
      else dashboard();
    }catch(_){showError();}
  }
  status();
})();
</script>
</body>
</html>`;
}

const server = Bun.serve({
  port,
  tls:{ cert:Bun.file("certs/cert.pem"), key:Bun.file("certs/key.pem") },
  async fetch(r) {
    try {
      const u = new URL(r.url);
      if (r.method === "OPTIONS") return new Response(null, { status:204, headers:headers(r) });
      if (u.pathname === "/" && r.method === "GET") {
        const n = token(24), h = headers(r, n);
        h.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(n), { headers:h });
      }
      if (u.pathname === "/api/status" && r.method === "GET") {
        let s = getSession(r);
        if (!s) {
          s = fresh();
          sessions.set(s.id, s);
          return response(r, state(s), 200, { "Set-Cookie":cookie(s.id) });
        }
        return response(r, state(s));
      }
      if (u.pathname === "/api/signin" && r.method === "POST") return signin(r);
      if (u.pathname === "/api/identity" && r.method === "POST") return identity(r);
      if (u.pathname === "/api/mfa/provision" && r.method === "POST") return provision(r);
      if (u.pathname === "/api/mfa/confirm" && r.method === "POST") return confirm(r);
      if (u.pathname === "/api/mfa/regenerate" && r.method === "POST") return codes(r);
      if (u.pathname === "/api/mfa/acknowledge" && r.method === "POST") return codes(r, true);
      if (u.pathname === "/api/mfa/recovery/verify" && r.method === "POST") return verifyRecovery(r);
      if (u.pathname === "/api/logout" && r.method === "POST") return logout(r);
      return fail(r, 404);
    } catch {
      return fail(r, 500);
    }
  }
});

console.log("MFA HTTPS server running on " + server.url + "; trusted origins: " + [...trustedOrigins].join(", "));
