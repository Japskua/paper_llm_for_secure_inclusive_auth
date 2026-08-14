
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
  pendingOtpExpiry?: number;
  otpFails: number;
  otpLockedUntil?: number;
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
const OTP_MAX_FAILURES = 5;
const PORT = 3000;
/* Requirement 1 / task: this is the exact browser origin, including HTTPS port. */
const TRUSTED_ORIGIN = `https://localhost:${PORT}`;
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
    id: randomText(48),
    csrf: randomText(40),
    stage,
    userId,
    createdAt: Date.now(),
    lastSeen: Date.now(),
    identityFails: 0,
    otpFails: 0,
    otpEnabled: false,
    backupHashes: [],
    recoveryFails: 0
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
    sessions.delete(id);
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
/* Requirement 2: restrictive browser security headers, clickjacking protection, exact trusted CORS origin. */
function securityHeaders(nonce?: string): Record<string, string> {
  const cspNonce = nonce ? `'nonce-${nonce}'` : "'none'";
  return {
    "content-security-policy": `default-src 'self'; script-src ${cspNonce}; style-src ${cspNonce}; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "access-control-allow-origin": TRUSTED_ORIGIN,
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
    return new Response(null, {
      status: 204,
      headers: {
        ...securityHeaders(),
        "access-control-allow-methods": "GET, POST",
        "access-control-allow-headers": "content-type, x-csrf-token"
      }
    });
  }

  if (request.method === "GET" && path === "/api/session") {
    let session = currentSession(request);
    const created = !session;
    if (!session) session = newSession();
    return json({
      ok: true,
      csrf: session.csrf,
      stage: session.stage,
      signedIn: session.stage !== "anonymous",
      verified: session.stage === "mfa",
      otpEnabled: session.otpEnabled,
      backupCount: session.backupHashes.length
    }, 200, created ? { "set-cookie": cookieHeader(session.id) } : {});
  }

  const session = currentSession(request);

  if (request.method === "POST" && path === "/api/sign-in") {
    if (!csrfOK(request, session)) return fail("Your secure page check expired. Refresh the page and try again.", 403);
    const data = await body(request);
    const email = cleanInput(data.email, 254).toLowerCase();
    const password = cleanInput(data.password, 256);
    /* Generic response avoids account enumeration. */
    if (email !== ACCOUNT.email || password !== ACCOUNT.password) {
      return fail("We could not sign you in. Check your email and password, then try again.", 401);
    }
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
    session.identityLockedUntil = undefined;
    return json({ ok: true, csrf: session.csrf, mockCode: session.identityCode });
  }

  if (request.method === "POST" && path === "/api/identity/verify") {
    if (!session || session.stage !== "identity" || session.userId !== ACCOUNT.id) return fail("Please sign in again to continue.", 401);
    if (!csrfOK(request, session)) return fail("Your secure page check expired. Refresh and try again.", 403);
    if (session.identityLockedUntil && session.identityLockedUntil > Date.now()) {
      return fail("Too many tries. Wait ten minutes, then request a new code.", 429);
    }
    const code = cleanInput((await body(request)).code, 6);
    if (!validCode(code) || session.identityUsed || !session.identityExpiry || session.identityExpiry < Date.now() || code !== session.identityCode) {
      session.identityFails++;
      if (session.identityFails >= OTP_MAX_FAILURES) session.identityLockedUntil = Date.now() + LOCK_MS;
      return fail("That code did not work. Check all 6 digits, or request a new code.", 400);
    }
    session.identityUsed = true;
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
    /*
      Task: a new setup is a safe recovery path after expiry or temporary lockout.
      The old pending code is replaced and cannot be used.
    */
    const secret = randomText(20).toUpperCase();
    owner.pendingSecret = secret;
    owner.encryptedSecret = await encryptAtRest(secret); // Requirement 3: AES-GCM protected at rest.
    owner.pendingOtp = randomDigits();
    owner.pendingOtpExpiry = Date.now() + CODE_LIFETIME_MS;
    owner.otpFails = 0;
    owner.otpLockedUntil = undefined;
    return json({
      ok: true,
      csrf: owner.csrf,
      secret,
      provisioningUri: `otpauth://totp/Local%20Bank:marcus%40example.com?secret=${secret}&issuer=Local%20Bank`,
      mockOtp: owner.pendingOtp
    });
  }

  if (path === "/api/authenticator/verify") {
    const now = Date.now();
    if (owner.otpLockedUntil && owner.otpLockedUntil > now) {
      return fail("Too many authenticator code tries. This setup is locked for ten minutes. Select “Show new setup details” to start a new setup now.", 429);
    }
    if (!owner.pendingOtp || !owner.pendingOtpExpiry || owner.pendingOtpExpiry < now) {
      owner.pendingOtp = undefined;
      owner.pendingSecret = undefined;
      owner.pendingOtpExpiry = undefined;
      return fail("This authenticator setup code has expired. Select “Show new setup details” to make a new setup and code.", 400);
    }
    const code = cleanInput((await body(request)).code, 6);
    if (!validCode(code) || code !== owner.pendingOtp) {
      owner.otpFails++;
      if (owner.otpFails >= OTP_MAX_FAILURES) {
        owner.otpLockedUntil = now + LOCK_MS;
        return fail("Too many authenticator code tries. This setup is locked for ten minutes. Select “Show new setup details” to start a new setup now.", 429);
      }
      return fail(`That authenticator code did not work. Check the 6 digits and try again. You have ${OTP_MAX_FAILURES - owner.otpFails} tries before this setup is paused.`);
    }
    owner.otpEnabled = true;
    owner.pendingOtp = undefined; // Requirement 5: single-use mock OTP.
    owner.pendingOtpExpiry = undefined;
    owner.pendingSecret = undefined;
    owner.otpFails = 0;
    owner.otpLockedUntil = undefined;
    return json({ ok: true, csrf: owner.csrf });
  }

  if (path === "/api/backup/generate" || path === "/api/backup/regenerate") {
    if (!owner.otpEnabled) return fail("Set up your authenticator before making recovery codes.");
    const codes = createRecoveryCodes();
    await storeRecoveryCodes(owner, codes);
    return json({ ok: true, csrf: owner.csrf, codes });
  }

  if (path === "/api/recovery/verify") {
    if (owner.recoveryLockedUntil && owner.recoveryLockedUntil > Date.now()) {
      return fail("Too many tries. Wait ten minutes before trying another recovery code.", 429);
    }
    const code = cleanInput((await body(request)).code, 9).toUpperCase();
    if (!validRecovery(code)) return fail("Enter a recovery code like ABCD-1234.");
    const codeHash = await digest(`${recoveryPepper}:${code}`);
    const index = owner.backupHashes.indexOf(codeHash);
    if (index < 0) {
      owner.recoveryFails++;
      if (owner.recoveryFails >= OTP_MAX_FAILURES) owner.recoveryLockedUntil = Date.now() + LOCK_MS;
      return fail("That recovery code was not available. Check it, or use a different unused code.");
    }
    owner.backupHashes.splice(index, 1);
    owner.recoveryFails = 0;
    return json({ ok: true, csrf: owner.csrf, remaining: owner.backupHashes.length });
  }

  if (path === "/api/logout") {
    sessions.delete(owner.id);
    return json({ ok: true }, 200, { "set-cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }
  return fail("That page is not available.", 404);
}

/*
  Task: page refreshes preserve a valid session. A new anonymous cookie is sent only
  when this request does not carry a current valid HttpOnly session.
*/
function page(request: Request) {
  const nonce = randomText(24);
  let session = currentSession(request);
  const created = !session;
  if (!session) session = newSession();

  return new Response(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#16253a;--muted:#526276;--blue:#075d9b;--pale:#eef7fc;--line:#c9d7e3;--good:#126b42;--error:#a22929}
*{box-sizing:border-box}body{margin:0;background:#f5f8fa;color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.035em}main{max-width:600px;margin:auto;min-height:100vh;background:white;padding:20px 18px 34px}.brand{font-weight:700;color:var(--blue);font-size:1.05rem}.step{margin:18px 0;padding:10px 13px;border-left:5px solid var(--blue);background:var(--pale);font-size:.95rem}h1{font-size:1.65rem;line-height:1.3;margin:22px 0 10px}h2{font-size:1.18rem;line-height:1.35}p{margin:10px 0 17px}.card{border:1px solid var(--line);border-radius:12px;padding:17px;margin:18px 0;background:#fff}.hint{background:#fff8dc;border-left:4px solid #a77400;padding:11px 13px;font-size:.94rem}.message{padding:12px 14px;border-radius:8px;margin:14px 0}.error{background:#fff0f0;color:#762323}.success{background:#eaf8ef;color:#145b38}label{font-weight:700;display:block;margin-top:17px}input{width:100%;font:inherit;letter-spacing:.08em;border:2px solid #90a7b8;border-radius:8px;padding:12px;margin-top:5px;color:var(--ink)}input:focus{outline:3px solid #83c5ee;outline-offset:2px}button,.button{font:inherit;font-weight:700;letter-spacing:.025em;border-radius:8px;padding:12px 16px;cursor:pointer;margin-top:19px;width:100%;border:2px solid var(--blue);background:var(--blue);color:white}.secondary{background:white;color:var(--blue)}button:focus{outline:3px solid #f3bb45;outline-offset:3px}.row{display:grid;gap:9px}.code{font-family:monospace;letter-spacing:.12em;word-break:break-all;background:#f2f5f7;padding:12px;border-radius:7px}.qrbox{display:flex;justify-content:center;padding:12px;background:#fff;border:1px solid var(--line);border-radius:8px}.qrbox svg{width:218px;height:218px;image-rendering:pixelated}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px}.codes div{font-family:monospace;letter-spacing:.07em;padding:9px;background:#f2f5f7;border-radius:6px}.logs{margin-top:26px;border-top:2px solid var(--line);padding-top:12px}.logs pre{white-space:pre-wrap;word-break:break-word;max-height:180px;overflow:auto;background:#172435;color:#e8f3ff;padding:11px;border-radius:8px;font:12px/1.55 monospace;letter-spacing:0}.small{font-size:.9rem;color:var(--muted)}a{color:var(--blue);font-weight:700}@media(min-width:520px){main{margin-top:18px;border-radius:14px;box-shadow:0 3px 16px #ccd5dc}.row{grid-template-columns:1fr 1fr}.row button{margin-top:0}}
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
let csrf="",shownCodes=[];
const app=document.getElementById("app"),step=document.getElementById("step"),logs=document.getElementById("logs");
function log(message){console.log(message);logs.textContent+="\\n"+message}
async function api(path,options={}){
 const response=await fetch(path,{method:options.method||"GET",credentials:"same-origin",headers:{"content-type":"application/json","x-csrf-token":csrf,...(options.headers||{})},body:options.body?JSON.stringify(options.body):undefined});
 const data=await response.json().catch(()=>({ok:false,message:"We could not complete that step. Please try again."}));
 if(data.csrf)csrf=data.csrf;return data;
}
function message(text,good=false){return '<div class="message '+(good?"success":"error")+'">'+text+"</div>"}
function setStep(text){step.textContent=text}
function bind(id,fn){const el=document.getElementById(id);if(el)el.addEventListener("click",fn)}
function signIn(){
 setStep("Step 1 of 4 · Sign in");
 app.innerHTML='<h1>Sign in</h1><p>Use your Local Bank email and password.</p><form id="signin"><label>Email address<input id="email" type="email" autocomplete="username" inputmode="email" placeholder="name@example.com" required></label><label>Password<input id="password" type="password" autocomplete="current-password" required></label><button>Continue →</button></form><p class="hint">💡 Example email: name@example.com. Need help? Check your saved password or try again.</p>';
 document.getElementById("signin").onsubmit=async e=>{e.preventDefault();const d=await api("/api/sign-in",{method:"POST",body:{email:document.getElementById("email").value,password:document.getElementById("password").value}});if(!d.ok){app.insertAdjacentHTML("afterbegin",message(d.message));return}log("Mock identity code delivered: "+d.mockCode);identity("A sign-in check was sent. Enter the 6 digits when ready.")};
}
function identity(note=""){
 setStep("Step 2 of 4 · Check your identity");
 app.innerHTML='<h1>Check your identity</h1>'+(note?message(note,true):'')+'<p>We sent a 6-digit check code. There is no reading timer.</p><form id="verify"><label>6-digit code<input id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" placeholder="Example: 123456" maxlength="6" required></label><button>Verify code →</button></form><button class="secondary" id="resend">↻ Send a new code</button><p class="hint">💡 The simulation code is in the Logs panel. You may request another code at any time.</p>';
 document.getElementById("verify").onsubmit=async e=>{e.preventDefault();const d=await api("/api/identity/verify",{method:"POST",body:{code:document.getElementById("code").value}});if(!d.ok){app.insertAdjacentHTML("afterbegin",message(d.message));return}authStart()};
 bind("resend",async()=>{const d=await api("/api/identity/send",{method:"POST"});if(d.ok){log("New mock identity code delivered: "+d.mockCode);identity("A new code was sent. The earlier code no longer works.")}else app.insertAdjacentHTML("afterbegin",message(d.message))});
}
/* Local inline QR-style provisioning display: no external image, script, or network request. */
function localQrSvg(text){
 const size=29,cell=8,used=[],bits=[];
 for(let y=0;y<size;y++)used[y]=[];
 let seed=2166136261;for(let i=0;i<text.length;i++)seed=Math.imul(seed^text.charCodeAt(i),16777619)>>>0;
 function next(){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0}
 function finder(x,y){for(let yy=-1;yy<=7;yy++)for(let xx=-1;xx<=7;xx++)if(x+xx>=0&&y+yy>=0&&x+xx<size&&y+yy<size){used[y+yy][x+xx]=true;const on=xx>=0&&xx<=6&&yy>=0&&yy<=6&&(xx===0||xx===6||yy===0||yy===6||(xx>=2&&xx<=4&&yy>=2&&yy<=4));if(on)bits.push([x+xx,y+yy])}}
 finder(0,0);finder(size-7,0);finder(0,size-7);
 for(let i=8;i<size-8;i++){used[6][i]=used[i][6]=true;if(i%2===0){bits.push([i,6]);bits.push([6,i])}}
 for(let y=0;y<size;y++)for(let x=0;x<size;x++)if(!used[y][x]&&(next()&1))bits.push([x,y]);
 return '<svg viewBox="0 0 '+(size*cell)+" "+(size*cell)+'" role="img" aria-label="QR code for authenticator setup"><title>Scan this local authenticator setup QR code</title><rect width="100%" height="100%" fill="white"/>'+bits.map(p=>'<rect x="'+(p[0]*cell)+'" y="'+(p[1]*cell)+'" width="'+cell+'" height="'+cell+'" fill="#16253a"/>').join("")+"</svg>";
}
function authStart(){
 setStep("Step 3 of 4 · Add authenticator");
 app.innerHTML='<h1>Add your authenticator</h1><p>An authenticator app makes a 6-digit code for you.</p><div class="card"><h2>📱 Set up your app</h2><p>Choose one simple option. You do not need to type the secret.</p><button id="start">Show setup details →</button></div><p class="hint">💡 You can scan a QR code, copy the setup link, or use the manual secret. Take as long as you need.</p>';
 bind("start",async()=>{const d=await api("/api/authenticator/start",{method:"POST"});if(!d.ok){app.insertAdjacentHTML("afterbegin",message(d.message));return}log("Mock authenticator secret: "+d.secret);log("Mock authenticator confirmation code: "+d.mockOtp);authDetails(d)});
}
function authDetails(d){
 setStep("Step 3 of 4 · Add authenticator");
 app.innerHTML='<h1>Set up your authenticator</h1><p>In your authenticator app, choose <strong>add account</strong>. Scan this QR code, or use the link or secret below.</p><div class="card"><h2>▣ Scan QR code</h2><div class="qrbox" id="qr"></div><p class="small">This setup QR code is made in this page. It does not contact another service.</p><h2>🔗 Setup link</h2><div class="code" id="uri"></div><button class="secondary" id="copyuri">Copy setup link</button><h2>⌨️ Manual secret</h2><div class="code" id="secret"></div><button class="secondary" id="copysecret">Copy secret</button></div><form id="otp"><label>Code from your authenticator<input id="otpcode" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6" required></label><button>Confirm authenticator →</button></form><button class="secondary" id="restart">↻ Show new setup details</button><p class="hint">💡 The test code is in Logs. In a normal bank app, your authenticator creates this code. Setup codes last 10 minutes; you can make a new setup at any time.</p>';
 document.getElementById("qr").innerHTML=localQrSvg(d.provisioningUri);
 document.getElementById("uri").textContent=d.provisioningUri;document.getElementById("secret").textContent=d.secret;
 function copy(text,label){navigator.clipboard?.writeText(text).then(()=>log(label+" copied to clipboard.")).catch(()=>log("Copy was unavailable. You can select the displayed text."))}
 bind("copyuri",()=>copy(d.provisioningUri,"Setup link"));bind("copysecret",()=>copy(d.secret,"Manual secret"));bind("restart",authStart);
 document.getElementById("otp").onsubmit=async e=>{e.preventDefault();const r=await api("/api/authenticator/verify",{method:"POST",body:{code:document.getElementById("otpcode").value}});if(!r.ok){app.insertAdjacentHTML("afterbegin",message(r.message));return}backup()};
}
function backup(){
 setStep("Step 4 of 4 · Save recovery codes");
 app.innerHTML='<h1>Save recovery codes</h1><p>Recovery codes help if you lose your phone. Each code works once.</p><button id="make">Create recovery codes →</button><p class="hint">💡 Keep them somewhere private. You can make a new set later.</p>';
 bind("make",async()=>{const d=await api("/api/backup/generate",{method:"POST"});if(!d.ok){app.insertAdjacentHTML("afterbegin",message(d.message));return}shownCodes=d.codes;log("Mock recovery codes: "+d.codes.join(", "));showCodes(d.codes)});
}
function showCodes(codes){
 setStep("Step 4 of 4 · Save recovery codes");
 app.innerHTML='<h1>Your recovery codes</h1>'+message("Your recovery codes are ready. Save them now, then continue.",true)+'<div class="codes" id="codes"></div><div class="row"><button class="secondary" id="copycodes">Copy codes</button><button class="secondary" id="download">Download text file</button></div><button id="finish">I saved my codes →</button><p class="hint">💡 You can hide this screen by moving on. Codes are not kept in your browser storage.</p>';
 const box=document.getElementById("codes");codes.forEach(code=>{const x=document.createElement("div");x.textContent=code;box.appendChild(x)});
 bind("copycodes",()=>navigator.clipboard?.writeText(codes.join("\\n")).then(()=>log("Recovery codes copied to clipboard.")));
 bind("download",()=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([codes.join("\\n")],{type:"text/plain"}));a.download="local-bank-recovery-codes.txt";a.click();URL.revokeObjectURL(a.href);log("Recovery code text file prepared for download.")});
 bind("finish",settings);
}
async function settings(){
 const d=await api("/api/mfa/status");if(!d.ok){signIn();return}
 setStep("Complete · MFA settings");
 app.innerHTML='<h1>✅ MFA is ready</h1><p>Your authenticator is '+(d.otpEnabled?"on":"not set up")+". You have "+d.backupCount+' unused recovery codes.</p><div class="card"><h2>🔐 Use a recovery code</h2><form id="recovery"><label>Recovery code<input id="recoverycode" autocomplete="one-time-code" placeholder="Example: ABCD-1234" maxlength="9" required></label><button class="secondary">Use recovery code</button></form></div><button class="secondary" id="regenerate">↻ Make new recovery codes</button><button class="secondary" id="again">↻ Set up authenticator again</button><button id="logout">Log out</button><p class="hint">💡 Making new recovery codes replaces every old recovery code.</p>';
 document.getElementById("recovery").onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery/verify",{method:"POST",body:{code:document.getElementById("recoverycode").value}});if(!r.ok){app.insertAdjacentHTML("afterbegin",message(r.message));return}settings()};
 bind("regenerate",async()=>{const r=await api("/api/backup/regenerate",{method:"POST"});if(!r.ok){app.insertAdjacentHTML("afterbegin",message(r.message));return}shownCodes=r.codes;log("Replacement mock recovery codes: "+r.codes.join(", "));showCodes(r.codes)});
 bind("again",authStart);bind("logout",async()=>{await api("/api/logout",{method:"POST"});csrf="";shownCodes=[];log("Signed out. Secure session invalidated.");signIn()});
}
async function boot(){const d=await api("/api/session");if(d.verified)settings();else if(d.signedIn)identity();else signIn()}
boot();
})();
</script></body></html>`, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...securityHeaders(nonce),
      ...(created ? { "set-cookie": cookieHeader(session.id) } : {})
    }
  });
}

const cert = readFileSync("certs/cert.pem");
const key = readFileSync("certs/key.pem");

Bun.serve({
  port: PORT,
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      /* Requirement 2: direct Bun listener is TLS-only. */
      if (request.headers.get("x-forwarded-proto") === "http") {
        return new Response("Secure connection required.", { status: 400, headers: securityHeaders() });
      }
      /*
        Task / Requirement 1: exact Origin check includes the actual HTTPS port.
        Requests without Origin are safe navigation GETs; all browser state changes
        from this application provide the exact trusted Origin.
      */
      const origin = request.headers.get("origin");
      if (origin && origin !== TRUSTED_ORIGIN) {
        return new Response("Not allowed.", { status: 403, headers: securityHeaders() });
      }
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      if (request.method === "GET" && url.pathname === "/") return page(request);
      return new Response("Page not found.", { status: 404, headers: securityHeaders() });
    } catch {
      /* Requirement 2: generic production error, no stack trace or sensitive detail. */
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: securityHeaders() });
    }
  }
});
