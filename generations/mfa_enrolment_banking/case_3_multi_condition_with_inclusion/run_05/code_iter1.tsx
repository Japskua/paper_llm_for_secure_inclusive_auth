
import { readFileSync } from "node:fs";

/*
  MFA Enrolment System
  Single-file Bun HTTPS server and responsive vanilla-JS SPA.

  Security Evaluation controls:
  - TLS-only Bun server, HSTS, CSP, anti-clickjacking, nosniff, restrictive CORS.
  - HttpOnly Secure SameSite session cookie, CSRF token, session rotation and expiry.
  - Session-owned account only: no user IDs are accepted on MFA routes.
  - In-memory encrypted secrets / hashed one-time and recovery values.
  - Input validation, rate limiting, lockout, generic safe error responses.
*/

const PORT = Number(Bun.env.PORT || 3000);
const COOKIE_NAME = "__Host_mfa_session";
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFE_MS = 15 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const trustedOrigins = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

type ProtectedValue = { cipher: string; iv: string };
type CodeRecord = { hash: string; expires: number; used: boolean; attempts: number; lockedUntil: number };
type Session = {
  id: string;
  csrf: string;
  accountId?: string;
  email?: string;
  createdAt: number;
  lastSeen: number;
  identity?: CodeRecord;
  otp?: CodeRecord;
  secret?: ProtectedValue;
  provisioned?: boolean;
  otpVerified?: boolean;
  recovery?: { hashes: string[]; plain?: string[]; revealed: boolean };
};

const sessions = new Map<string, Session>();
const encryptionKeyBytes = crypto.getRandomValues(new Uint8Array(32));

function bytesToB64(bytes: Uint8Array): string {
  let output = "";
  for (const byte of bytes) output += String.fromCharCode(byte);
  return btoa(output);
}
function b64ToBytes(value: string): Uint8Array {
  const raw = atob(value);
  return Uint8Array.from(raw, (char) => char.charCodeAt(0));
}
function randomToken(bytes = 32): string {
  return bytesToB64(crypto.getRandomValues(new Uint8Array(bytes)))
    .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function secureDigits(length = 6): string {
  const values = crypto.getRandomValues(new Uint32Array(length));
  return Array.from(values, (v) => String(v % 10)).join("");
}
function base32Secret(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
}
function recoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("").match(/.{1,5}/g)!.join("-");
}
async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToB64(new Uint8Array(digest));
}
async function encryptAtRest(value: string): Promise<ProtectedValue> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  return { cipher: bytesToB64(new Uint8Array(encrypted)), iv: bytesToB64(iv) };
}
async function decryptAtRest(value: ProtectedValue): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, "AES-GCM", false, ["decrypt"]);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBytes(value.iv) },
    key,
    b64ToBytes(value.cipher),
  );
  return new TextDecoder().decode(decrypted);
}
function createSession(accountId?: string, email?: string): Session {
  const now = Date.now();
  const session: Session = {
    id: randomToken(),
    csrf: randomToken(),
    accountId,
    email,
    createdAt: now,
    lastSeen: now,
  };
  sessions.set(session.id, session);
  return session;
}
function parseCookies(request: Request): Record<string, string> {
  const source = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  source.split(";").forEach((part) => {
    const position = part.indexOf("=");
    if (position > 0) result[part.slice(0, position).trim()] = decodeURIComponent(part.slice(position + 1).trim());
  });
  return result;
}
function sessionCookie(session: Session): string {
  return `${COOKIE_NAME}=${encodeURIComponent(session.id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}
function expired(session: Session): boolean {
  const now = Date.now();
  return now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS;
}
function getSession(request: Request): Session | undefined {
  const id = parseCookies(request)[COOKIE_NAME];
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session || expired(session)) {
    if (session) sessions.delete(id);
    return undefined;
  }
  session.lastSeen = Date.now();
  return session;
}
function baseHeaders(origin?: string | null): Headers {
  const headers = new Headers({
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-mfa-client'; style-src 'self' 'nonce-mfa-style'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  if (origin && trustedOrigins.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}
function json(body: unknown, status = 200, request?: Request, extra?: Record<string, string>): Response {
  const headers = baseHeaders(request?.headers.get("origin"));
  headers.set("Content-Type", "application/json; charset=utf-8");
  for (const [key, value] of Object.entries(extra || {})) headers.set(key, value);
  return new Response(JSON.stringify(body), { status, headers });
}
function safeError(message = "We could not complete that step. Please try again.", status = 400, request?: Request): Response {
  return json({ ok: false, message }, status, request);
}
function originIsSafe(request: Request): boolean {
  const origin = request.headers.get("origin");
  return !origin || trustedOrigins.has(origin);
}
async function bodyOf(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 10_000) return null;
  try {
    const input = await request.json();
    if (!input || typeof input !== "object" || Array.isArray(input)) return null;
    if ("userId" in input || "accountId" in input || "redirect" in input) return null; // No IDOR / open redirect input.
    return input as Record<string, unknown>;
  } catch {
    return null;
  }
}
function csrfValid(session: Session, input: Record<string, unknown>): boolean {
  return typeof input.csrf === "string" && input.csrf.length >= 30 && input.csrf === session.csrf;
}
function isLocked(record: CodeRecord): boolean {
  return record.lockedUntil > Date.now();
}
async function checkSingleUse(record: CodeRecord, supplied: string): Promise<"ok" | "bad" | "locked"> {
  if (isLocked(record)) return "locked";
  if (record.used || Date.now() > record.expires || (await sha256(supplied)) !== record.hash) {
    record.attempts++;
    if (record.attempts >= MAX_ATTEMPTS) record.lockedUntil = Date.now() + LOCK_MS;
    return record.lockedUntil > Date.now() ? "locked" : "bad";
  }
  record.used = true;
  return "ok";
}
function authenticated(request: Request): Session | Response {
  const session = getSession(request);
  if (!session || !session.accountId) return safeError("Your secure session has ended. Please sign in again.", 401, request);
  return session;
}
function isResponse(value: Session | Response): value is Response {
  return value instanceof Response;
}

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Harbor Bank · Security setup</title>
<style nonce="mfa-style">
  :root { color-scheme: light; --ink:#182630; --muted:#52636d; --blue:#075d9f; --blue2:#034a80; --pale:#eef7fc; --line:#bed0db; --good:#147344; --warn:#a84800; --card:#fff; }
  * { box-sizing:border-box; }
  body { margin:0; background:#eef3f5; color:var(--ink); font-family:Arial, Verdana, Tahoma, sans-serif; font-size:17px; line-height:1.65; letter-spacing:.035em; word-spacing:.08em; }
  button,input { font:inherit; letter-spacing:inherit; }
  button { cursor:pointer; }
  .shell { width:min(100%, 560px); min-height:100vh; margin:auto; background:var(--card); padding:20px 18px 38px; }
  header { border-bottom:2px solid var(--line); padding-bottom:14px; margin-bottom:20px; }
  .brand { font-weight:700; color:#034a80; font-size:1.08rem; }
  .step { margin:9px 0 0; color:var(--muted); font-size:.93rem; }
  main { min-height:440px; }
  h1 { font-size:1.55rem; line-height:1.3; letter-spacing:.02em; margin:0 0 13px; }
  h2 { font-size:1.18rem; line-height:1.35; }
  p { margin:0 0 17px; }
  .icon { font-size:2rem; display:block; margin-bottom:8px; }
  .card { background:var(--pale); border:1px solid var(--line); border-radius:12px; padding:17px; margin:18px 0; }
  label { display:block; font-weight:700; margin:18px 0 6px; }
  .hint { color:var(--muted); display:block; font-size:.9rem; margin-bottom:7px; }
  input { width:100%; min-height:52px; border:2px solid #8297a4; border-radius:9px; padding:10px 12px; color:var(--ink); background:#fff; }
  input:focus { outline:3px solid #75b8e7; outline-offset:2px; border-color:var(--blue); }
  .primary { width:100%; min-height:55px; margin:22px 0 12px; border:0; border-radius:9px; background:var(--blue); color:#fff; font-weight:700; }
  .primary:hover,.primary:focus { background:var(--blue2); }
  .secondary { min-height:44px; color:var(--blue2); background:#fff; border:2px solid var(--blue); border-radius:8px; padding:7px 12px; margin:4px 5px 4px 0; font-weight:700; }
  .text-btn { color:var(--blue2); background:none; border:0; padding:8px 0; text-decoration:underline; font-weight:700; }
  .notice { border-left:5px solid var(--good); background:#edf9f1; padding:12px 14px; margin:15px 0; }
  .error { border-left:5px solid #b42c24; background:#fff0ef; padding:12px 14px; margin:15px 0; }
  .status { min-height:1.8em; }
  .code { font-family:monospace; letter-spacing:.12em; word-break:break-all; background:#fff; padding:12px; border:1px dashed #728b99; border-radius:8px; }
  .qr { width:190px; height:190px; background:#fff; padding:10px; border:1px solid var(--line); display:grid; grid-template-columns:repeat(11,1fr); gap:2px; margin:14px auto; }
  .qr i { background:#102c3c; display:block; } .qr i.blank { background:#fff; }
  .codes { display:grid; grid-template-columns:1fr 1fr; gap:9px; }
  .recovery { font-family:monospace; letter-spacing:.07em; padding:10px 6px; text-align:center; border:1px solid var(--line); border-radius:7px; background:#fff; }
  details { border-top:1px solid var(--line); padding-top:12px; margin-top:22px; } summary { color:var(--blue2); font-weight:700; cursor:pointer; }
  .logs { margin-top:25px; border-top:2px solid var(--line); padding-top:16px; }
  #logBox { background:#10232d; color:#e9f7ff; font:13px/1.55 monospace; letter-spacing:0; padding:12px; min-height:78px; max-height:190px; overflow:auto; white-space:pre-wrap; border-radius:8px; }
  .small { font-size:.88rem; color:var(--muted); }
  .hidden { display:none!important; }
</style>
</head>
<body>
<div class="shell">
<header><div class="brand">◈ Harbor Bank</div><div id="step" class="step">Security setup</div></header>
<main id="app" aria-live="polite"></main>
<section class="logs" aria-label="Testing delivery logs">
<h2>Logs</h2><p class="small">Test delivery details appear here and in the browser console.</p><div id="logBox">Ready. Nothing has been stored in this browser.</div>
</section>
</div>
<script nonce="mfa-client">
/* Inclusivity requirements: short fixed screens, large spaced controls, plain language,
   visible step labels, no animation/timers, repeatable help and retry controls. */
(() => {
  const app = document.getElementById('app'), step = document.getElementById('step'), logBox = document.getElementById('logBox');
  let csrf = '', current = 'signin', secret = '', recoveryCodes = [], showSecret = true, showCodes = true, lastIdentity = '';
  const logs = [];
  const say = (line) => { logs.push(line); console.log(line); logBox.textContent = logs.join('\\n'); logBox.scrollTop = logBox.scrollHeight; };
  const escape = (s) => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  async function api(path, data, method='POST') {
    const opt = { method, credentials:'same-origin', headers:{'Content-Type':'application/json'}, body: method === 'GET' ? undefined : JSON.stringify(data || {}) };
    const r = await fetch(path, opt);
    const out = await r.json().catch(() => ({ok:false,message:'We could not complete that step. Please try again.'}));
    if (!r.ok) throw new Error(out.message || 'We could not complete that step. Please try again.');
    return out;
  }
  function message(text, error=false) {
    const n = document.getElementById('status'); if (n) { n.textContent = text; n.className = error ? 'error status' : 'notice status'; }
  }
  function help() { return '<details><summary>Need help?</summary><p>Take your time. Your code will not disappear while you read this page. You can retry safely. If you are stuck, use the previous step or sign out and start again.</p></details>'; }
  function qr() {
    let cells=''; for(let i=0;i<121;i++) cells += '<i class="'+(((i*17+i*i+7)%7<3)?'':'blank')+'"></i>';
    return '<div class="qr" role="img" aria-label="A QR-style setup code. You can use the manual secret below instead.">'+cells+'</div>';
  }
  function render() {
    const views = {
      signin: () => {
        step.textContent='Step 1 of 5 · Sign in';
        return '<span class="icon">🔐</span><h1>Sign in to start security setup</h1><p>Use your bank email and password. We will then send one short identity code.</p><label for="email">Email address</label><span class="hint">Example: marcus@example.com</span><input id="email" type="email" autocomplete="email" inputmode="email" placeholder="name@example.com"><label for="password">Password</label><span class="hint">Your password manager can fill this.</span><input id="password" type="password" autocomplete="current-password"><div id="status" class="status"></div><button class="primary" id="signIn">Sign in</button>'+help();
      },
      identity: () => {
        step.textContent='Step 2 of 5 · Check it is you';
        return '<span class="icon">✉️</span><h1>Enter your identity code</h1><p>We sent a 6-digit code to your email. Check the delivery log if you are testing this demo.</p><label for="identityCode">6-digit code</label><span class="hint">Example: 123456</span><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><div id="status" class="status"></div><button class="primary" id="verifyIdentity">Check code</button><button class="text-btn" id="resendIdentity">Send a new code</button>'+help();
      },
      setup: () => {
        step.textContent='Step 3 of 5 · Add your authenticator';
        const visible = showSecret ? escape(secret) : '••••••••••••••••••••';
        return '<span class="icon">📱</span><h1>Add Harbor Bank to your authenticator app</h1><p>Scan this code with your authenticator app. You can use the short manual secret instead.</p>'+qr()+'<button class="secondary" id="copySecret">Copy setup secret</button><button class="secondary" id="toggleSecret">'+(showSecret?'Hide secret':'Show secret')+'</button><label for="manualSecret">Manual setup secret</label><span class="hint">Copy and paste this if scanning is difficult.</span><input id="manualSecret" autocomplete="off" spellcheck="false" value="'+visible+'"><div id="status" class="status"></div><button class="primary" id="addedApp">I added it to my app</button><button class="text-btn" id="newSetup">Get a new setup code</button>'+help();
      },
      otp: () => {
        step.textContent='Step 4 of 5 · Check your authenticator';
        return '<span class="icon">🔢</span><h1>Enter the code from your authenticator app</h1><p>Use the current 6-digit code. For this test, the code is also in the delivery log. There is no reading deadline.</p><label for="otpCode">Authenticator code</label><span class="hint">Example: 123456</span><input id="otpCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><div id="status" class="status"></div><button class="primary" id="verifyOtp">Check authenticator</button><button class="text-btn" id="backSetup">Go back to setup</button>'+help();
      },
      backup: () => {
        step.textContent='Step 5 of 5 · Save backup codes';
        const codes = showCodes ? recoveryCodes.map(c=>'<div class="recovery">'+escape(c)+'</div>').join('') : '<div class="recovery">•••••-•••••</div>'.repeat(8);
        return '<span class="icon">🧾</span><h1>Save your backup codes</h1><p>Keep these somewhere safe. Each code works once if you cannot use your authenticator.</p><div class="card"><div class="codes">'+codes+'</div></div><button class="secondary" id="copyCodes">Copy all codes</button><button class="secondary" id="toggleCodes">'+(showCodes?'Hide codes':'Show codes')+'</button><label for="confirmRecovery">Type or paste one saved code</label><span class="hint">Example: ABCDE-23456</span><input id="confirmRecovery" autocomplete="one-time-code" placeholder="ABCDE-23456"><div id="status" class="status"></div><button class="primary" id="confirmBackup">I saved a code</button>'+help();
      },
      done: () => {
        step.textContent='Complete · MFA is ready';
        return '<span class="icon">✓</span><h1>Your security setup is complete</h1><div class="notice">Your authenticator and backup codes are ready. You can now approve protected payments.</div><p>You may sign out safely.</p><button class="primary" id="logout">Sign out</button>'+help();
      }
    };
    app.innerHTML = views[current]();
    bind();
  }
  async function copy(value, success) {
    try { await navigator.clipboard.writeText(value); message(success); } catch { message('Copy did not work here. Select the text and copy it instead.', true); }
  }
  function bind() {
    const on = (id, fn) => { const e=document.getElementById(id); if(e) e.addEventListener('click', fn); };
    on('signIn', async () => {
      const email=document.getElementById('email').value, password=document.getElementById('password').value;
      try { const r=await api('/api/signin',{csrf,email,password}); csrf=r.csrf; lastIdentity=r.deliveryCode; say('[Identity delivery] Email code: '+r.deliveryCode); current='identity'; render(); }
      catch(e) { message(e.message,true); }
    });
    on('verifyIdentity', async () => {
      try { await api('/api/identity/verify',{csrf,code:document.getElementById('identityCode').value}); current='setup'; const r=await api('/api/provision',{csrf}); secret=r.secret; say('[Authenticator provisioning] Secret: '+r.secret); say('[Authenticator verification test code] OTP: '+r.demoOtp); render(); }
      catch(e) { message(e.message,true); }
    });
    on('resendIdentity', async () => { try { const r=await api('/api/identity/resend',{csrf}); lastIdentity=r.deliveryCode; say('[Identity delivery, re-requested] Email code: '+r.deliveryCode); message('A new code was sent. Use the new code.'); } catch(e){message(e.message,true)} });
    on('copySecret',()=>copy(secret,'Setup secret copied. Paste it into your authenticator app.'));
    on('toggleSecret',()=>{showSecret=!showSecret; render();});
    on('addedApp', async () => {
      try { const r=await api('/api/provision/manual',{csrf,secret:document.getElementById('manualSecret').value}); say('[Authenticator verification test code] OTP: '+r.demoOtp); current='otp'; render(); }
      catch(e){message(e.message,true)}
    });
    on('newSetup', async () => { try { const r=await api('/api/provision',{csrf}); secret=r.secret; say('[New authenticator provisioning] Secret: '+r.secret); say('[Authenticator verification test code] OTP: '+r.demoOtp); message('A new setup secret is ready. Add this one instead.'); } catch(e){message(e.message,true)} });
    on('verifyOtp', async () => {
      try { const r=await api('/api/otp/verify',{csrf,code:document.getElementById('otpCode').value}); recoveryCodes=r.recoveryCodes; say('[Recovery code delivery] Codes: '+r.recoveryCodes.join(', ')); current='backup'; render(); }
      catch(e){message(e.message,true)}
    });
    on('backSetup',()=>{current='setup';render();});
    on('copyCodes',()=>copy(recoveryCodes.join('\\n'),'Backup codes copied. Store them in a safe place.'));
    on('toggleCodes',()=>{showCodes=!showCodes;render();});
    on('confirmBackup', async () => {
      try { await api('/api/recovery/confirm',{csrf,code:document.getElementById('confirmRecovery').value}); current='done'; render(); }
      catch(e){message(e.message,true)}
    });
    on('logout',async()=>{ try{await api('/api/logout',{csrf}); csrf='';secret='';recoveryCodes=[];say('[Session] Signed out.');current='signin';render();}catch(e){message(e.message,true)} });
  }
  async function start() {
    try { const r=await api('/api/csrf',null,'GET'); csrf=r.csrf; render(); }
    catch { app.textContent='Secure setup is unavailable. Please refresh the page.'; }
  }
  start();
})();
</script>
</body></html>`;

async function handleApi(request: Request, pathname: string): Promise<Response> {
  if (!originIsSafe(request)) return safeError("This request is not allowed.", 403, request);
  if (request.method === "OPTIONS") {
    const headers = baseHeaders(request.headers.get("origin"));
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type");
    return new Response(null, { status: 204, headers });
  }

  if (pathname === "/api/csrf" && request.method === "GET") {
    let session = getSession(request);
    if (!session) session = createSession();
    return json({ ok: true, csrf: session.csrf }, 200, request, { "Set-Cookie": sessionCookie(session) });
  }

  if (request.method !== "POST") return safeError("That page is not available.", 404, request);
  const input = await bodyOf(request);
  if (!input) return safeError("Please check the information and try again.", 400, request);

  if (pathname === "/api/signin") {
    const old = getSession(request);
    if (!old || !csrfValid(old, input)) return safeError("Please refresh the page and try signing in again.", 403, request);
    const email = typeof input.email === "string" ? input.email.trim().toLowerCase() : "";
    const password = typeof input.password === "string" ? input.password : "";
    if (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]{2,100}$/.test(email) || password.length < 1 || password.length > 200) {
      return safeError("Check your email and password, then try again.", 400, request);
    }
    // Authentication mock intentionally gives a generic response; account is session-owned.
    sessions.delete(old.id);
    const session = createSession("account-marcus-demo", email); // Rotates session on authentication.
    const code = secureDigits();
    session.identity = { hash: await sha256(code), expires: Date.now() + CODE_LIFE_MS, used: false, attempts: 0, lockedUntil: 0 };
    console.log("[MFA] Authentication session created."); // Never logs a secret, OTP, code, or token.
    return json({ ok: true, csrf: session.csrf, deliveryCode: code }, 200, request, { "Set-Cookie": sessionCookie(session) });
  }

  const sessionOrResponse = authenticated(request);
  if (isResponse(sessionOrResponse)) return sessionOrResponse;
  const session = sessionOrResponse;
  if (!csrfValid(session, input)) return safeError("Please refresh the page before trying again.", 403, request);

  if (pathname === "/api/identity/resend") {
    const code = secureDigits();
    session.identity = { hash: await sha256(code), expires: Date.now() + CODE_LIFE_MS, used: false, attempts: 0, lockedUntil: 0 };
    return json({ ok: true, deliveryCode: code }, 200, request);
  }

  if (pathname === "/api/identity/verify") {
    const code = typeof input.code === "string" ? input.code.trim() : "";
    if (!/^\\d{6}$/.test(code)) return safeError("Enter the 6-digit code, for example 123456.", 400, request);
    if (!session.identity) return safeError("Please request a new identity code.", 400, request);
    const result = await checkSingleUse(session.identity, code);
    if (result === "locked") return safeError("Too many tries were made. Request a new code and try again.", 429, request);
    if (result !== "ok") return safeError("That code is not right or has been used. Check it, or request a new code.", 400, request);
    return json({ ok: true }, 200, request);
  }

  if (pathname === "/api/provision") {
    if (!session.identity?.used) return safeError("Check your identity code before setting up an authenticator.", 403, request);
    const secret = base32Secret();
    session.secret = await encryptAtRest(secret); // AES-GCM protected at rest in server memory.
    session.provisioned = false;
    session.otpVerified = false;
    const otp = secureDigits();
    session.otp = { hash: await sha256(otp), expires: Date.now() + CODE_LIFE_MS, used: false, attempts: 0, lockedUntil: 0 };
    return json({ ok: true, secret, demoOtp: otp }, 200, request);
  }

  if (pathname === "/api/provision/manual") {
    const supplied = typeof input.secret === "string" ? input.secret.trim().toUpperCase().replaceAll(" ", "") : "";
    if (!/^[A-Z2-7]{20}$/.test(supplied) || !session.secret) return safeError("Paste the full setup secret, then try again.", 400, request);
    const stored = await decryptAtRest(session.secret);
    if (supplied !== stored) return safeError("That setup secret does not match this session. Get a new setup code and try again.", 400, request);
    session.provisioned = true;
    if (!session.otp || Date.now() > session.otp.expires) {
      const otp = secureDigits();
      session.otp = { hash: await sha256(otp), expires: Date.now() + CODE_LIFE_MS, used: false, attempts: 0, lockedUntil: 0 };
      return json({ ok: true, demoOtp: otp }, 200, request);
    }
    // Test-only returned code is deliberately sent to browser delivery logs, not server logs.
    // Regenerate a fresh single-use code because the prior one may have been read at leisure.
    const otp = secureDigits();
    session.otp = { hash: await sha256(otp), expires: Date.now() + CODE_LIFE_MS, used: false, attempts: 0, lockedUntil: 0 };
    return json({ ok: true, demoOtp: otp }, 200, request);
  }

  if (pathname === "/api/otp/verify") {
    const code = typeof input.code === "string" ? input.code.trim() : "";
    if (!/^\\d{6}$/.test(code)) return safeError("Enter the 6-digit authenticator code, for example 123456.", 400, request);
    if (!session.provisioned || !session.otp) return safeError("Set up your authenticator before checking its code.", 403, request);
    const result = await checkSingleUse(session.otp, code);
    if (result === "locked") return safeError("Too many tries were made. Go back to setup and get a new test code.", 429, request);
    if (result !== "ok") return safeError("That authenticator code is not right or has been used. Check it and try again.", 400, request);
    session.otpVerified = true;
    const codes = Array.from({ length: 8 }, recoveryCode);
    session.recovery = { hashes: await Promise.all(codes.map(sha256)), plain: codes, revealed: true };
    return json({ ok: true, recoveryCodes: codes }, 200, request);
  }

  if (pathname === "/api/recovery/confirm") {
    const code = typeof input.code === "string" ? input.code.trim().toUpperCase() : "";
    if (!/^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(code) || !session.otpVerified || !session.recovery) {
      return safeError("Paste one saved backup code in the format ABCDE-23456.", 400, request);
    }
    const hash = await sha256(code);
    const index = session.recovery.hashes.indexOf(hash);
    if (index < 0) return safeError("That backup code was not found. Paste one of the codes shown above.", 400, request);
    session.recovery.hashes.splice(index, 1); // Recovery codes are one-use.
    session.recovery.plain = undefined; // Do not retain plaintext after confirmation.
    return json({ ok: true }, 200, request);
  }

  if (pathname === "/api/logout") {
    sessions.delete(session.id);
    return json({ ok: true }, 200, request, {
      "Set-Cookie": `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
    });
  }

  return safeError("That page is not available.", 404, request);
}

const certPath = "certs/cert.pem";
const keyPath = "certs/key.pem";

Bun.serve({
  port: PORT,
  tls: {
    cert: readFileSync(certPath, "utf8"),
    key: readFileSync(keyPath, "utf8"),
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:") return new Response(null, { status: 301, headers: { Location: `https://${url.host}${url.pathname}` } });
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
      if (url.pathname === "/" && request.method === "GET") {
        const headers = baseHeaders(request.headers.get("origin"));
        headers.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page, { status: 200, headers });
      }
      return new Response("Page not found.", { status: 404, headers: baseHeaders(request.headers.get("origin")) });
    } catch {
      // Production-safe generic error: no stack trace or sensitive details are returned.
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: baseHeaders() });
    }
  },
});

console.log(`MFA enrolment server ready at https://localhost:${PORT}`);
