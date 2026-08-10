
import { readFileSync } from "node:fs";

/*
  MFA Enrolment System
  Single-file Bun HTTPS server + inline mobile SPA.
  Security requirement sections are marked throughout this file.
*/

type Stage = "anonymous" | "identity" | "mfa";
type Session = {
  id: string;
  csrf: string;
  stage: Stage;
  userId?: string;
  createdAt: number;
  lastSeen: number;
  identityCode?: string;
  identityExpiry?: number;
  identityUsed?: boolean;
  identityFails: number;
  identityLockedUntil?: number;
  pendingSecret?: string;
  encryptedSecret?: string;
  pendingOtp?: string;
  otpEnabled: boolean;
  backupHashes: string[];
  recoveryFails: number;
  recoveryLockedUntil?: number;
};

const sessions = new Map<string, Session>();
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 10 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const ACCOUNT = { id: "account-marcus", email: "marcus@example.com", password: "BankDemo!9" };
const encoder = new TextEncoder();
const masterKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
const recoveryPepper = randomText(32);

function randomText(length = 32) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, b => chars[b % chars.length]).join("");
}
function randomDigits(length = 6) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, b => String(b % 10)).join("");
}
function b64(bytes: Uint8Array) {
  return Buffer.from(bytes).toString("base64url");
}
async function digest(value: string) {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return b64(new Uint8Array(hash));
}
async function encryptAtRest(value: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(value));
  return `${b64(iv)}.${b64(new Uint8Array(ciphertext))}`;
}
function cookieHeader(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}
function expired(session: Session) {
  const now = Date.now();
  return now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS;
}
function newSession(stage: Stage = "anonymous", userId?: string): Session {
  const session: Session = {
    id: randomText(48), csrf: randomText(40), stage, userId,
    createdAt: Date.now(), lastSeen: Date.now(), identityFails: 0,
    otpEnabled: false, backupHashes: [], recoveryFails: 0
  };
  sessions.set(session.id, session);
  return session;
}
function parseCookies(request: Request) {
  const raw = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const item of raw.split(";")) {
    const index = item.indexOf("=");
    if (index > -1) result[item.slice(0, index).trim()] = item.slice(index + 1).trim();
  }
  return result;
}
function currentSession(request: Request) {
  const id = parseCookies(request).mfa_session;
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session || expired(session)) {
    if (id) sessions.delete(id);
    return undefined;
  }
  session.lastSeen = Date.now();
  return session;
}
/* Requirement 1: every protected MFA endpoint derives ownership from HttpOnly session only. */
function ownerSession(request: Request) {
  const session = currentSession(request);
  return session && session.stage === "mfa" && session.userId === ACCOUNT.id ? session : undefined;
}
function csrfOK(request: Request, session: Session | undefined) {
  return !!session && request.headers.get("x-csrf-token") === session.csrf;
}
function json(data: unknown, status = 200, extra: HeadersInit = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...securityHeaders(), ...extra }
  });
}
function fail(message = "We could not complete that step. Please try again.", status = 400) {
  return json({ ok: false, message }, status);
}
/* Requirement 2: restrictive browser security headers and same-origin policy. */
function securityHeaders(nonce?: string): Record<string, string> {
  const cspNonce = nonce ? `'nonce-${nonce}'` : "'none'";
  return {
    "content-security-policy": `default-src 'self'; script-src ${cspNonce}; style-src ${cspNonce}; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "access-control-allow-origin": "https://localhost",
    "access-control-allow-credentials": "true",
    "vary": "Origin"
  };
}
async function body(request: Request) {
  try {
    const value = await request.json();
    return value && typeof value === "object" ? value as Record<string, unknown> : {};
  } catch {
    return {};
  }
}
function validCode(value: unknown, length = 6) {
  return typeof value === "string" && new RegExp(`^\\d{${length}}$`).test(value);
}
function validRecovery(value: unknown) {
  return typeof value === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value);
}
function createRecoveryCodes() {
  return Array.from({ length: 8 }, () => `${randomText(4).toUpperCase()}-${randomText(4).toUpperCase()}`);
}
async function storeRecoveryCodes(session: Session, codes: string[]) {
  session.backupHashes = await Promise.all(codes.map(code => digest(`${recoveryPepper}:${code}`)));
}
function cleanInput(value: unknown, max: number) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

async function api(request: Request, path: string): Promise<Response> {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: { ...securityHeaders(), "access-control-allow-methods": "GET, POST", "access-control-allow-headers": "content-type, x-csrf-token" } });
  }
  if (request.method === "GET" && path === "/api/session") {
    let session = currentSession(request);
    const created = !session;
    if (!session) session = newSession();
    return json({
      ok: true, csrf: session.csrf, stage: session.stage,
      signedIn: session.stage !== "anonymous", verified: session.stage === "mfa",
      otpEnabled: session.otpEnabled, backupCount: session.backupHashes.length
    }, 200, created ? { "set-cookie": cookieHeader(session.id) } : {});
  }

  const session = currentSession(request);

  if (request.method === "POST" && path === "/api/sign-in") {
    if (!csrfOK(request, session)) return fail("Your secure page check expired. Refresh the page and try again.", 403);
    const data = await body(request);
    const email = cleanInput(data.email, 254).toLowerCase();
    const password = cleanInput(data.password, 256);
    /* Generic response avoids account enumeration. */
    if (email !== ACCOUNT.email || password !== ACCOUNT.password) return fail("We could not sign you in. Check your email and password, then try again.", 401);
    sessions.delete(session!.id); // Requirement 5: rotate ID after authentication.
    const fresh = newSession("identity", ACCOUNT.id);
    fresh.identityCode = randomDigits();
    fresh.identityExpiry = Date.now() + CODE_LIFETIME_MS;
    /* Mock delivery only: never server-log OTPs or secrets. */
    return json({ ok: true, csrf: fresh.csrf, mockCode: fresh.identityCode }, 200, { "set-cookie": cookieHeader(fresh.id) });
  }

  if (request.method === "POST" && path === "/api/identity/send") {
    if (!session || session.stage !== "identity" || session.userId !== ACCOUNT.id) return fail("Please sign in again to continue.", 401);
    if (!csrfOK(request, session)) return fail("Your secure page check expired. Refresh and try again.", 403);
    session.identityCode = randomDigits();
    session.identityExpiry = Date.now() + CODE_LIFETIME_MS;
    session.identityUsed = false;
    session.identityFails = 0;
    return json({ ok: true, csrf: session.csrf, mockCode: session.identityCode });
  }

  if (request.method === "POST" && path === "/api/identity/verify") {
    if (!session || session.stage !== "identity" || session.userId !== ACCOUNT.id) return fail("Please sign in again to continue.", 401);
    if (!csrfOK(request, session)) return fail("Your secure page check expired. Refresh and try again.", 403);
    if (session.identityLockedUntil && session.identityLockedUntil > Date.now()) return fail("Too many tries. Wait ten minutes, then request a new code.", 429);
    const code = cleanInput((await body(request)).code, 6);
    if (!validCode(code) || session.identityUsed || !session.identityExpiry || session.identityExpiry < Date.now() || code !== session.identityCode) {
      session.identityFails++;
      if (session.identityFails >= 5) session.identityLockedUntil = Date.now() + LOCK_MS;
      return fail("That code did not work. Check all 6 digits, or request a new code.", 400);
    }
    session.identityUsed = true; // Requirement 5: single use.
    session.stage = "mfa";
    session.csrf = randomText(40);
    return json({ ok: true, csrf: session.csrf });
  }

  /* All remaining MFA routes perform the owner check, never accept a user ID. */
  const owner = ownerSession(request);
  if (!owner) return fail("Please sign in again to manage MFA.", 401);

  if (request.method === "GET" && path === "/api/mfa/status") {
    return json({ ok: true, csrf: owner.csrf, otpEnabled: owner.otpEnabled, backupCount: owner.backupHashes.length });
  }
  if (request.method !== "POST") return fail("That page is not available.", 404);
  if (!csrfOK(request, owner)) return fail("Your secure page check expired. Refresh and try again.", 403);

  if (path === "/api/authenticator/start") {
    const secret = randomText(20).toUpperCase();
    owner.pendingSecret = secret;
    owner.encryptedSecret = await encryptAtRest(secret); // Requirement 3: AES-GCM protected at rest.
    owner.pendingOtp = randomDigits();
    return json({
      ok: true, csrf: owner.csrf, secret,
      provisioningUri: `otpauth://totp/Local%20Bank:marcus%40example.com?secret=${secret}&issuer=Local%20Bank`,
      mockOtp: owner.pendingOtp
    });
  }
  if (path === "/api/authenticator/verify") {
    const code = cleanInput((await body(request)).code, 6);
    if (!owner.pendingOtp || !validCode(code) || code !== owner.pendingOtp) return fail("That authenticator code did not work. Use the 6-digit code shown by your app, then try again.");
    owner.otpEnabled = true;
    owner.pendingOtp = undefined; // single-use mock OTP
    owner.pendingSecret = undefined;
    return json({ ok: true, csrf: owner.csrf });
  }
  if (path === "/api/backup/generate" || path === "/api/backup/regenerate") {
    if (!owner.otpEnabled) return fail("Set up your authenticator before making recovery codes.");
    const codes = createRecoveryCodes();
    await storeRecoveryCodes(owner, codes);
    return json({ ok: true, csrf: owner.csrf, codes });
  }
  if (path === "/api/recovery/verify") {
    if (owner.recoveryLockedUntil && owner.recoveryLockedUntil > Date.now()) return fail("Too many tries. Wait ten minutes before trying another recovery code.", 429);
    const code = cleanInput((await body(request)).code, 9).toUpperCase();
    if (!validRecovery(code)) return fail("Enter a recovery code like ABCD-1234.");
    const codeHash = await digest(`${recoveryPepper}:${code}`);
    const index = owner.backupHashes.indexOf(codeHash);
    if (index < 0) {
      owner.recoveryFails++;
      if (owner.recoveryFails >= 5) owner.recoveryLockedUntil = Date.now() + LOCK_MS;
      return fail("That recovery code was not available. Check it, or use a different unused code.");
    }
    owner.backupHashes.splice(index, 1); // Requirement 5: recovery codes are single-use.
    owner.recoveryFails = 0;
    return json({ ok: true, csrf: owner.csrf, remaining: owner.backupHashes.length });
  }
  if (path === "/api/logout") {
    sessions.delete(owner.id);
    return json({ ok: true }, 200, { "set-cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }
  return fail("That page is not available.", 404);
}

function page() {
  const nonce = randomText(24);
  return new Response(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#16253a;--muted:#526276;--blue:#075d9b;--pale:#eef7fc;--line:#c9d7e3;--good:#126b42;--error:#a22929}
*{box-sizing:border-box} body{margin:0;background:#f5f8fa;color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.035em}
main{max-width:600px;margin:auto;min-height:100vh;background:white;padding:20px 18px 34px}.brand{font-weight:700;color:var(--blue);font-size:1.05rem}.step{margin:18px 0;padding:10px 13px;border-left:5px solid var(--blue);background:var(--pale);font-size:.95rem}h1{font-size:1.65rem;line-height:1.3;margin:22px 0 10px}h2{font-size:1.18rem;line-height:1.35}p{margin:10px 0 17px}.card{border:1px solid var(--line);border-radius:12px;padding:17px;margin:18px 0;background:#fff}.hint{background:#fff8dc;border-left:4px solid #a77400;padding:11px 13px;font-size:.94rem}.message{padding:12px 14px;border-radius:8px;margin:14px 0}.error{background:#fff0f0;color:#762323}.success{background:#eaf8ef;color:#145b38}label{font-weight:700;display:block;margin-top:17px}input{width:100%;font:inherit;letter-spacing:.08em;border:2px solid #90a7b8;border-radius:8px;padding:12px;margin-top:5px;color:var(--ink)}input:focus{outline:3px solid #83c5ee;outline-offset:2px}button,.button{font:inherit;font-weight:700;letter-spacing:.025em;border-radius:8px;padding:12px 16px;cursor:pointer;margin-top:19px;width:100%;border:2px solid var(--blue);background:var(--blue);color:white}.secondary{background:white;color:var(--blue)}button:focus{outline:3px solid #f3bb45;outline-offset:3px}.row{display:grid;gap:9px}.code{font-family:monospace;letter-spacing:.12em;word-break:break-all;background:#f2f5f7;padding:12px;border-radius:7px}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px}.codes div{font-family:monospace;letter-spacing:.07em;padding:9px;background:#f2f5f7;border-radius:6px}.logs{margin-top:26px;border-top:2px solid var(--line);padding-top:12px}.logs pre{white-space:pre-wrap;word-break:break-word;max-height:180px;overflow:auto;background:#172435;color:#e8f3ff;padding:11px;border-radius:8px;font:12px/1.55 monospace;letter-spacing:0}.small{font-size:.9rem;color:var(--muted)}a{color:var(--blue);font-weight:700}@media(min-width:520px){main{margin-top:18px;border-radius:14px;box-shadow:0 3px 16px #ccd5dc}.row{grid-template-columns:1fr 1fr}.row button{margin-top:0}}
</style>
</head>
<body><main>
<header><div class="brand">🏦 Local Bank</div><div class="step" id="step">Step 1 of 4 · Sign in</div></header>
<section id="app" aria-live="polite">Loading secure setup…</section>
<section class="logs" aria-label="Mock delivery logs"><h2>🧾 Logs</h2><p class="small">Simulation messages are shown here too.</p><pre id="logs">Ready.</pre></section>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
let csrf="", state={}, shownCodes=[];
const app=document.getElementById("app"), step=document.getElementById("step"), logs=document.getElementById("logs");
function log(message){ console.log(message); logs.textContent += "\\n" + message; }
async function api(path, options={}){
  const response=await fetch(path,{method:options.method||"GET",credentials:"same-origin",headers:{"content-type":"application/json","x-csrf-token":csrf,...(options.headers||{})},body:options.body?JSON.stringify(options.body):undefined});
  const data=await response.json().catch(()=>({ok:false,message:"We could not complete that step. Please try again."}));
  if(data.csrf) csrf=data.csrf;
  return data;
}
function message(text, good=false){return '<div class="message '+(good?'success':'error')+'">'+text+'</div>'}
function setStep(text){step.textContent=text}
function bind(id, fn){const el=document.getElementById(id);if(el)el.addEventListener("click",fn)}
function signIn(){
 setStep("Step 1 of 4 · Sign in");
 app.innerHTML='<h1>Sign in</h1><p>Use your Local Bank email and password.</p><form id="signin"><label>Email address<input id="email" type="email" autocomplete="username" inputmode="email" placeholder="name@example.com" required></label><label>Password<input id="password" type="password" autocomplete="current-password" required></label><button>Continue →</button></form><p class="hint">💡 Example email: name@example.com. Need help? Check your saved password or try again.</p>';
 document.getElementById("signin").onsubmit=async e=>{e.preventDefault();const d=await api("/api/sign-in",{method:"POST",body:{email:document.getElementById("email").value,password:document.getElementById("password").value}});if(!d.ok){app.insertAdjacentHTML("afterbegin",message(d.message));return}log("Mock identity code delivered: "+d.mockCode);identity("A sign-in check was sent. Enter the 6 digits when ready.");};
}
function identity(note=""){
 setStep("Step 2 of 4 · Check your identity");
 app.innerHTML='<h1>Check your identity</h1>'+(note?message(note,true):'')+'<p>We sent a 6-digit check code. There is no reading timer.</p><form id="verify"><label>6-digit code<input id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" placeholder="Example: 123456" maxlength="6" required></label><button>Verify code →</button></form><button class="secondary" id="resend">↻ Send a new code</button><p class="hint">💡 The simulation code is in the Logs panel. You may request another code at any time.</p>';
 document.getElementById("verify").onsubmit=async e=>{e.preventDefault();const d=await api("/api/identity/verify",{method:"POST",body:{code:document.getElementById("code").value}});if(!d.ok){app.insertAdjacentHTML("afterbegin",message(d.message));return}authStart();};
 bind("resend",async()=>{const d=await api("/api/identity/send",{method:"POST"});if(d.ok){log("New mock identity code delivered: "+d.mockCode);identity("A new code was sent. The earlier code no longer works.")}else app.insertAdjacentHTML("afterbegin",message(d.message));});
}
function authStart(){
 setStep("Step 3 of 4 · Add authenticator");
 app.innerHTML='<h1>Add your authenticator</h1><p>An authenticator app makes a 6-digit code for you.</p><div class="card"><h2>📱 Set up your app</h2><p>Choose one simple option. You do not need to type the secret.</p><button id="start">Show setup details →</button></div><p class="hint">💡 You can copy the setup link or use a short manual secret. Take as long as you need.</p>';
 bind("start",async()=>{const d=await api("/api/authenticator/start",{method:"POST"});if(!d.ok){app.insertAdjacentHTML("afterbegin",message(d.message));return}log("Mock authenticator secret: "+d.secret);log("Mock authenticator confirmation code: "+d.mockOtp);authDetails(d);});
}
function authDetails(d){
 setStep("Step 3 of 4 · Add authenticator");
 app.innerHTML='<h1>Set up your authenticator</h1><p>In your authenticator app, choose <strong>add account</strong>, then use this setup link or secret.</p><div class="card"><h2>🔗 Setup link</h2><div class="code" id="uri"></div><button class="secondary" id="copyuri">Copy setup link</button><h2>⌨️ Manual secret</h2><div class="code" id="secret"></div><button class="secondary" id="copysecret">Copy secret</button></div><form id="otp"><label>Code from your authenticator<input id="otpcode" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6" required></label><button>Confirm authenticator →</button></form><button class="secondary" id="restart">↻ Show new setup details</button><p class="hint">💡 The test code is in Logs. In a normal bank app, your authenticator creates this code.</p>';
 document.getElementById("uri").textContent=d.provisioningUri; document.getElementById("secret").textContent=d.secret;
 function copy(text,label){navigator.clipboard?.writeText(text).then(()=>{log(label+" copied to clipboard.");}).catch(()=>log("Copy was unavailable. You can select the displayed text."));}
 bind("copyuri",()=>copy(d.provisioningUri,"Setup link")); bind("copysecret",()=>copy(d.secret,"Manual secret")); bind("restart",authStart);
 document.getElementById("otp").onsubmit=async e=>{e.preventDefault();const r=await api("/api/authenticator/verify",{method:"POST",body:{code:document.getElementById("otpcode").value}});if(!r.ok){app.insertAdjacentHTML("afterbegin",message(r.message));return}backup();};
}
function backup(){
 setStep("Step 4 of 4 · Save recovery codes");
 app.innerHTML='<h1>Save recovery codes</h1><p>Recovery codes help if you lose your phone. Each code works once.</p><button id="make">Create recovery codes →</button><p class="hint">💡 Keep them somewhere private. You can make a new set later.</p>';
 bind("make",async()=>{const d=await api("/api/backup/generate",{method:"POST"});if(!d.ok){app.insertAdjacentHTML("afterbegin",message(d.message));return}shownCodes=d.codes;log("Mock recovery codes: "+d.codes.join(", "));showCodes(d.codes);});
}
function showCodes(codes){
 setStep("Step 4 of 4 · Save recovery codes");
 app.innerHTML='<h1>Your recovery codes</h1>'+message("Your recovery codes are ready. Save them now, then continue.",true)+'<div class="codes" id="codes"></div><div class="row"><button class="secondary" id="copycodes">Copy codes</button><button class="secondary" id="download">Download text file</button></div><button id="finish">I saved my codes →</button><p class="hint">💡 You can hide this screen by moving on. Codes are not kept in your browser storage.</p>';
 const box=document.getElementById("codes");codes.forEach(code=>{const x=document.createElement("div");x.textContent=code;box.appendChild(x)});
 bind("copycodes",()=>navigator.clipboard?.writeText(codes.join("\\n")).then(()=>log("Recovery codes copied to clipboard.")));
 bind("download",()=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([codes.join("\\n")],{type:"text/plain"}));a.download="local-bank-recovery-codes.txt";a.click();URL.revokeObjectURL(a.href);log("Recovery code text file prepared for download.");});
 bind("finish",settings);
}
async function settings(){
 const d=await api("/api/mfa/status"); if(!d.ok){signIn();return}
 setStep("Complete · MFA settings");
 app.innerHTML='<h1>✅ MFA is ready</h1><p>Your authenticator is '+(d.otpEnabled?'on':'not set up')+'. You have '+d.backupCount+' unused recovery codes.</p><div class="card"><h2>🔐 Use a recovery code</h2><form id="recovery"><label>Recovery code<input id="recoverycode" autocomplete="one-time-code" placeholder="Example: ABCD-1234" maxlength="9" required></label><button class="secondary">Use recovery code</button></form></div><button class="secondary" id="regenerate">↻ Make new recovery codes</button><button class="secondary" id="again">↻ Set up authenticator again</button><button id="logout">Log out</button><p class="hint">💡 Making new recovery codes replaces every old recovery code.</p>';
 document.getElementById("recovery").onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery/verify",{method:"POST",body:{code:document.getElementById("recoverycode").value}});if(!r.ok){app.insertAdjacentHTML("afterbegin",message(r.message));return}settings();};
 bind("regenerate",async()=>{const r=await api("/api/backup/regenerate",{method:"POST"});if(!r.ok){app.insertAdjacentHTML("afterbegin",message(r.message));return}shownCodes=r.codes;log("Replacement mock recovery codes: "+r.codes.join(", "));showCodes(r.codes);});
 bind("again",authStart);
 bind("logout",async()=>{await api("/api/logout",{method:"POST"});csrf="";shownCodes=[];log("Signed out. Secure session invalidated.");signIn();});
}
async function boot(){const d=await api("/api/session");state=d;if(d.verified)settings();else if(d.signedIn)identity();else signIn();}
boot();
})();
</script></body></html>`, { headers: { "content-type": "text/html; charset=utf-8", ...securityHeaders(nonce), "set-cookie": cookieHeader(newSession().id) } });
}

const cert = readFileSync("certs/cert.pem");
const key = readFileSync("certs/key.pem");

Bun.serve({
  port: 3000,
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      /* Requirement 2: reject insecure proxied traffic; direct Bun listener is TLS-only. */
      if (request.headers.get("x-forwarded-proto") === "http") return new Response("Secure connection required.", { status: 400, headers: securityHeaders() });
      const origin = request.headers.get("origin");
      if (origin && origin !== "https://localhost") return new Response("Not allowed.", { status: 403, headers: securityHeaders() });
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      if (request.method === "GET" && url.pathname === "/") return page();
      return new Response("Page not found.", { status: 404, headers: securityHeaders() });
    } catch {
      /* Requirement 2: generic production error, no stack trace or sensitive detail. */
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: securityHeaders() });
    }
  }
});
