
const encoder = new TextEncoder();
const PEPPER = bytesToBase64(randomBytes(32));
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt"]
);

type Session = {
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
};

type Verification = {
  hash: string;
  expiresAt: number;
  attempts: number;
  lockedUntil: number;
};

type StoredCipher = { iv: string; data: string };

type UserState = {
  email: string;
  identityVerified: boolean;
  mfaEnabled: boolean;
  encryptedSeed?: StoredCipher;
  identityCheck?: Verification;
  authenticatorCheck?: Verification;
  backupHashes: Set<string>;
};

const sessions = new Map<string, Session>();
const user: UserState = {
  email: "marcus@example.test",
  identityVerified: false,
  mfaEnabled: false,
  backupHashes: new Set(),
};

const IDLE_MS = 30 * 60 * 1000;
const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const VERIFY_MS = 30 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;

function randomBytes(length: number): Uint8Array {
  const values = new Uint8Array(length);
  crypto.getRandomValues(values);
  return values;
}

function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function randomToken(bytes = 32): string {
  return bytesToBase64(randomBytes(bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function randomDigits(): string {
  const value = new Uint32Array(1);
  crypto.getRandomValues(value);
  return String(100000 + (value[0] % 900000));
}

function randomBase32(length = 24): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const raw = randomBytes(length);
  let result = "";
  for (let i = 0; i < length; i++) result += alphabet[raw[i] % alphabet.length];
  return result;
}

function randomRecoveryCode(): string {
  const raw = randomBase32(10);
  return raw.slice(0, 5) + "-" + raw.slice(5);
}

async function digest(value: string): Promise<string> {
  const output = await crypto.subtle.digest("SHA-256", encoder.encode(value + ":" + PEPPER));
  return bytesToBase64(new Uint8Array(output));
}

async function encryptSecret(secret: string): Promise<StoredCipher> {
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encryptionKey,
    encoder.encode(secret)
  );
  return { iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(encrypted)) };
}

function cookieValue(request: Request, name: string): string | undefined {
  const source = request.headers.get("cookie") || "";
  for (const part of source.split(";")) {
    const item = part.trim();
    if (item.startsWith(name + "=")) return item.slice(name.length + 1);
  }
  return undefined;
}

function sessionCookie(id: string): string {
  return "mfa_session=" + id + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + Math.floor(ABSOLUTE_MS / 1000);
}

function expiredCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

function baseHeaders(): Headers {
  return new Headers({
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  });
}

function responseJson(data: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = baseHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((value, key) => headers.set(key, value));
  return new Response(JSON.stringify(data), { status, headers });
}

function genericError(status = 400, message = "We could not complete that request. Please try again."): Response {
  return responseJson({ ok: false, message }, status);
}

function trustedOrigin(origin: string | null): boolean {
  if (!origin) return false;
  try {
    const url = new URL(origin);
    return url.protocol === "https:" &&
      (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1");
  } catch {
    return false;
  }
}

function addCors(request: Request, response: Response): Response {
  const origin = request.headers.get("origin");
  if (trustedOrigin(origin)) response.headers.set("Access-Control-Allow-Origin", origin!);
  response.headers.set("Vary", "Origin");
  response.headers.set("Access-Control-Allow-Credentials", "true");
  response.headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
  response.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  return response;
}

function authenticated(request: Request): Session | undefined {
  const id = cookieValue(request, "mfa_session");
  if (!id) return undefined;
  const session = sessions.get(id);
  const now = Date.now();
  if (!session || session.userId !== "account-owner" || now - session.lastSeen > IDLE_MS || now - session.createdAt > ABSOLUTE_MS) {
    if (id) sessions.delete(id);
    return undefined;
  }
  session.lastSeen = now;
  return session;
}

function csrfOK(request: Request, session: Session): boolean {
  return trustedOrigin(request.headers.get("origin")) &&
    request.headers.get("x-csrf-token") === session.csrf;
}

async function bodyJSON(request: Request): Promise<Record<string, unknown> | undefined> {
  if (!(request.headers.get("content-type") || "").includes("application/json")) return undefined;
  const text = await request.text();
  if (text.length > 3000) return undefined;
  try {
    const value = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validCode(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function validRecovery(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(value);
}

async function newVerification(code: string): Promise<Verification> {
  return { hash: await digest(code), expiresAt: Date.now() + VERIFY_MS, attempts: 0, lockedUntil: 0 };
}

async function verifyCode(check: Verification | undefined, code: string): Promise<"ok" | "wrong" | "locked" | "expired"> {
  if (!check || Date.now() > check.expiresAt) return "expired";
  if (Date.now() < check.lockedUntil) return "locked";
  if ((await digest(code)) !== check.hash) {
    check.attempts++;
    if (check.attempts >= 5) check.lockedUntil = Date.now() + LOCK_MS;
    return check.attempts >= 5 ? "locked" : "wrong";
  }
  return "ok";
}

async function createRecoveryCodes(): Promise<string[]> {
  const codes = Array.from({ length: 8 }, randomRecoveryCode);
  user.backupHashes = new Set(await Promise.all(codes.map((code) => digest(code))));
  return codes;
}

/* Single-file/runtime requirement: all page markup, client code, and server routes remain in this file. */
const page = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Harbour Bank · Security setup</title>
<style>
:root { --ink:#17243a; --muted:#536276; --blue:#075fc8; --blue2:#064b9e; --pale:#eef6ff; --line:#cbd6e3; --good:#126b43; --bad:#b42318; --card:#fff; }
* { box-sizing:border-box; }
body { margin:0; background:#f3f7fb; color:var(--ink); font-family:Arial, Verdana, Tahoma, sans-serif; font-size:17px; line-height:1.65; letter-spacing:.025em; }
main { width:min(100%, 620px); margin:auto; padding:18px 15px 42px; }
header { padding:5px 5px 18px; }
.brand { font-weight:700; color:#064b9e; font-size:1.08rem; }
h1 { font-size:1.55rem; line-height:1.3; margin:0 0 9px; letter-spacing:.01em; }
h2 { font-size:1.17rem; line-height:1.35; margin:0 0 10px; }
p { margin:0 0 14px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:15px; padding:23px 19px; box-shadow:0 2px 8px #1935540d; }
.step { color:#075fc8; font-weight:700; font-size:.92rem; margin:0 0 12px; }
.icon { font-size:1.6rem; margin-right:8px; vertical-align:-3px; }
label { display:block; font-weight:700; margin:18px 0 6px; }
input { display:block; width:100%; border:2px solid #8ba0b8; border-radius:10px; padding:13px; min-height:52px; font:inherit; letter-spacing:.05em; color:var(--ink); background:white; }
input:focus { outline:3px solid #8bc5ff; outline-offset:2px; border-color:var(--blue); }
.hint { color:var(--muted); font-size:.94rem; }
button, .button { width:100%; min-height:53px; margin-top:20px; border:0; border-radius:10px; background:var(--blue); color:#fff; font:700 1rem Arial, sans-serif; letter-spacing:.02em; cursor:pointer; padding:12px 16px; text-align:center; text-decoration:none; display:block; }
button:hover { background:var(--blue2); }
button.secondary, .button.secondary { background:#fff; color:#064b9e; border:2px solid #1e70c7; }
button.small { width:auto; min-height:42px; margin:10px 8px 0 0; padding:7px 12px; font-size:.9rem; }
.notice { margin:16px 0 0; padding:12px 13px; border-radius:9px; font-weight:700; }
.notice.error { background:#fff0ef; color:var(--bad); border-left:5px solid var(--bad); }
.notice.ok { background:#eaf8f0; color:var(--good); border-left:5px solid var(--good); }
.secret { overflow-wrap:anywhere; background:#f5f8fc; border:1px dashed #7891ae; padding:12px; border-radius:8px; font-family:ui-monospace, monospace; font-weight:700; letter-spacing:.1em; }
.qr { width:174px; height:174px; display:grid; grid-template-columns:repeat(13,1fr); gap:1px; padding:8px; background:#fff; border:4px solid #17243a; margin:17px auto; }
.qr i { background:#fff; } .qr i.on { background:#17243a; }
.code-list { list-style:none; padding:0; margin:12px 0; } .code-list li { margin:8px 0; padding:8px 10px; background:#f5f8fc; font-family:ui-monospace, monospace; font-weight:700; border-radius:7px; letter-spacing:.08em; }
details { margin-top:18px; padding-top:12px; border-top:1px solid var(--line); color:var(--muted); } summary { color:#075fc8; font-weight:700; cursor:pointer; }
.log-panel { margin-top:22px; background:#14223a; color:#eaf4ff; border-radius:13px; padding:14px; } .log-panel h2 { font-size:1rem; margin:0 0 7px; } #logs { margin:0; white-space:pre-wrap; overflow-wrap:anywhere; font:13px/1.55 ui-monospace, monospace; max-height:180px; overflow:auto; }
.checkline { display:flex; gap:10px; align-items:flex-start; margin-top:17px; } .checkline input { width:23px; min-height:23px; margin-top:5px; flex:none; }
.status { display:flex; gap:9px; align-items:center; padding:10px; background:var(--pale); border-radius:9px; margin:14px 0; }
@media (max-width:370px) { body { font-size:16px; } .card { padding:18px 14px; } }
</style>
</head>
<body>
<main>
<header><div class="brand">◆ Harbour Bank</div></header>
<section id="app" aria-live="polite"></section>
<section class="log-panel" aria-label="Mock delivery logs"><h2>Logs</h2><pre id="logs">Ready. Mock delivery messages will appear here.</pre></section>
</main>
<script>
(() => {
"use strict";
/* Inclusivity requirements: short screens, large controls, plain wording, no timers or movement. */
const app = document.getElementById("app");
const logs = document.getElementById("logs");
const state = { csrf:"", screen:"signin", identityCode:"", otp:"", secret:"", codes:[], message:"", error:"" };

function log(message) {
  console.log(message); /* Mock delivery is deliberately browser-console only. */
  logs.textContent = message + "\\n" + logs.textContent;
}
function setMessage(message, error) { state.message=message||""; state.error=error||""; }
function note() {
  if (!state.message && !state.error) return "";
  return '<div class="notice ' + (state.error ? "error" : "ok") + '">' + escapeText(state.error || state.message) + "</div>";
}
function escapeText(value) {
  return String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
async function api(path, data) {
  const headers = {"Content-Type":"application/json"};
  if (state.csrf) headers["X-CSRF-Token"] = state.csrf;
  let response;
  try { response = await fetch(path, {method:"POST", credentials:"same-origin", headers, body:JSON.stringify(data || {})}); }
  catch { throw new Error("Connection problem. Please try again."); }
  const result = await response.json().catch(() => ({message:"We could not complete that request. Please try again."}));
  if (response.status === 401) { state.csrf=""; state.screen="signin"; render(); throw new Error("Please sign in again to continue."); }
  if (!response.ok) throw new Error(result.message || "We could not complete that request. Please try again.");
  return result;
}
function help(text) { return '<details><summary>Need help?</summary><p>' + escapeText(text) + "</p></details>"; }
function shell(step, title, icon, text, inner, helpText) {
 return '<article class="card"><p class="step">' + step + '</p><h1><span class="icon">' + icon + "</span>" + title + "</h1><p>" + text + "</p>" + inner + note() + help(helpText) + "</article>";
}
function render() {
  const screens = {
    signin() {
      return shell("Step 1 of 5", "Sign in to start", "👋", "Use the email for your bank account.", '<form id="signinForm"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="username email" inputmode="email" placeholder="name@example.com" required><p class="hint">Example: marcus@example.com</p><button>Continue</button></form>', "Use your own email address. This demo accepts any correctly written email.");
    },
    identity() {
      return shell("Step 2 of 5", "Check it is you", "✉️", "We sent a 6-digit check code in this safe demo.", '<form id="identityForm"><label for="identity">Check code</label><input id="identity" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="Example: 123456" required><p class="hint">Enter 6 numbers. There is plenty of time.</p><button>Check code</button></form><button class="secondary" id="fillIdentity">Use demo code</button><button class="secondary" id="resendIdentity">Send a new code</button>', "Choose “Use demo code” to avoid typing. You may request another code without penalty.");
    },
    setup() {
      const grid = Array.from({length:169}, (_,i) => '<i class="' + (((state.secret.charCodeAt(i % state.secret.length) + i*7) % 3 === 0) ? "on" : "") + '"></i>').join("");
      return shell("Step 3 of 5", "Add your authenticator", "📱", "Scan this QR-style setup image in your authenticator app. Or use the short secret below.", '<div class="qr" aria-label="QR-style authenticator setup image" role="img">' + grid + '</div><p class="hint">Manual secret</p><div class="secret" id="secretText"></div><button class="small secondary" id="copySecret" type="button">Copy secret</button><p class="hint">In your app, choose “enter a setup key” if scanning is difficult.</p><button id="toOtp">I added the authenticator</button>', "The image and secret both set up the same authenticator. Copying avoids transcription.");
    },
    otp() {
      return shell("Step 4 of 5", "Confirm your authenticator", "🔐", "Enter the 6-digit code from your authenticator app.", '<form id="otpForm"><label for="otp">Authenticator code</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="Example: 123456" required><p class="hint">Enter 6 numbers. You can retry if needed.</p><button>Confirm authenticator</button></form><button class="secondary" id="fillOtp">Use demo code</button><button class="secondary" id="restartSetup">Start setup again</button>', "For this demo, “Use demo code” fills the mock code. A wrong code can be retried.");
    },
    backup() {
      const list = state.codes.map(code => "<li>" + escapeText(code) + "</li>").join("");
      return shell("Step 5 of 5", "Save your recovery codes", "🧾", "Keep these codes somewhere safe. Each works once if you lose your phone.", '<ul class="code-list" id="backupList">' + list + '</ul><button class="small secondary" id="copyCodes">Copy all codes</button><button class="small secondary" id="downloadCodes">Download a text copy</button><label class="checkline"><input type="checkbox" id="savedCodes"><span>I have saved my recovery codes.</span></label><button id="finishBackup">Finish security setup</button>', "Copy or download the codes rather than typing them. You can make new codes later; old ones then stop working.");
    },
    settings() {
      return shell("Security settings", "MFA is ready", "✅", "Your authenticator and recovery codes are active.", '<div class="status"><span>🛡️</span><span><strong>Authenticator:</strong> active</span></div><label for="recovery">Test a recovery code</label><input id="recovery" autocomplete="off" autocapitalize="characters" placeholder="Example: ABCDE-FGHIJ"><p class="hint">This is optional. A recovery code can be used once.</p><button id="testRecovery">Test recovery code</button><button class="secondary" id="regenerate">Make new recovery codes</button><button class="secondary" id="logout">Sign out</button>', "Making new recovery codes replaces every old code. Sign out when you have finished.");
    }
  };
  app.innerHTML = screens[state.screen]();
  if (state.screen === "setup") document.getElementById("secretText").textContent = state.secret;
  bind();
}
async function copy(text, success) {
  try {
    await navigator.clipboard.writeText(text);
    setMessage(success, ""); render();
  } catch {
    setMessage("Copy was not available. You can select the text and copy it.", ""); render();
  }
}
function bind() {
  const byId = id => document.getElementById(id);
  if (state.screen === "signin") byId("signinForm").onsubmit = async e => {
    e.preventDefault(); setMessage("","");
    const email = byId("email").value;
    try { const r=await api("/api/signin",{email}); state.csrf=r.csrf; state.screen="identity"; state.identityCode=r.mockCode; log("[Mock delivery] Identity check code: " + r.mockCode); render(); }
    catch(err) { setMessage("",err.message); render(); }
  };
  if (state.screen === "identity") {
    byId("identityForm").onsubmit = async e => { e.preventDefault(); try { await api("/api/identity/verify",{code:byId("identity").value}); state.screen="setup"; await provision(); } catch(err) { setMessage("",err.message); render(); } };
    byId("fillIdentity").onclick=()=>{byId("identity").value=state.identityCode; byId("identity").focus();};
    byId("resendIdentity").onclick=async()=>{try {const r=await api("/api/identity/send");state.identityCode=r.mockCode;log("[Mock delivery] New identity check code: "+r.mockCode);setMessage("A new demo code is ready in Logs.","");render();}catch(err){setMessage("",err.message);render();}};
  }
  if (state.screen === "setup") {
    byId("copySecret").onclick=()=>copy(state.secret,"Secret copied. Paste it into your authenticator app.");
    byId("toOtp").onclick=()=>{state.screen="otp";setMessage("Your next step is to confirm the 6-digit code.","");render();};
  }
  if (state.screen === "otp") {
    byId("otpForm").onsubmit=async e=>{e.preventDefault();try {const r=await api("/api/authenticator/verify",{code:byId("otp").value});state.codes=r.codes;log("[Mock delivery] Recovery codes: "+r.codes.join(", "));state.screen="backup";setMessage("Authenticator confirmed. Now save your recovery codes.","");render();}catch(err){setMessage("",err.message);render();}};
    byId("fillOtp").onclick=()=>{byId("otp").value=state.otp;byId("otp").focus();};
    byId("restartSetup").onclick=async()=>{try {await provision();state.screen="setup";setMessage("A fresh setup secret is ready.","");render();}catch(err){setMessage("",err.message);render();}};
  }
  if (state.screen === "backup") {
    byId("copyCodes").onclick=()=>copy(state.codes.join("\\n"),"Recovery codes copied. Keep them somewhere safe.");
    byId("downloadCodes").onclick=()=>{const blob=new Blob([state.codes.join("\\n")+"\\n"],{type:"text/plain"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="harbour-bank-recovery-codes.txt";a.click();setTimeout(()=>URL.revokeObjectURL(a.href),500);setMessage("Your recovery-code text file was prepared.","");render();};
    byId("finishBackup").onclick=async()=>{if(!byId("savedCodes").checked){setMessage("Please tick the box after you have saved the codes.","");render();return;}try{await api("/api/backup/confirm");state.codes=[];state.screen="settings";setMessage("Security setup is complete.","");render();}catch(err){setMessage("",err.message);render();}};
  }
  if (state.screen === "settings") {
    byId("testRecovery").onclick=async()=>{try{await api("/api/recovery/verify",{code:byId("recovery").value.toUpperCase()});setMessage("That recovery code worked and is now used. Keep your remaining codes safe.","");render();}catch(err){setMessage("",err.message);render();}};
    byId("regenerate").onclick=async()=>{try{const r=await api("/api/recovery/regenerate");state.codes=r.codes;log("[Mock delivery] New recovery codes: "+r.codes.join(", "));state.screen="backup";setMessage("New codes have replaced the old ones. Save these new codes.","");render();}catch(err){setMessage("",err.message);render();}};
    byId("logout").onclick=async()=>{try{await api("/api/logout");state.csrf="";state.screen="signin";setMessage("You have signed out.","");render();}catch(err){setMessage("",err.message);render();}};
  }
}
async function provision() {
 const r=await api("/api/authenticator/provision");
 state.secret=r.secret; state.otp=r.mockCode;
 log("[Mock delivery] Authenticator test code: "+r.mockCode);
}
render();
})();
</script>
</body>
</html>`;

async function route(request: Request): Promise<Response> {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    if (!trustedOrigin(request.headers.get("origin"))) return genericError(403, "Request not allowed.");
    return addCors(request, new Response(null, { status: 204, headers: baseHeaders() }));
  }

  if (url.pathname === "/" && request.method === "GET") {
    const headers = baseHeaders();
    headers.set("Content-Type", "text/html; charset=utf-8");
    return new Response(page, { headers });
  }

  if (!url.pathname.startsWith("/api/")) return genericError(404, "Page not found.");

  /* Security sections 1 and 5: every MFA API route below obtains the owner session first. */
  if (url.pathname === "/api/signin" && request.method === "POST") {
    const data = await bodyJSON(request);
    if (!data || !validEmail(data.email) || !trustedOrigin(request.headers.get("origin"))) {
      return genericError(400, "Please enter an email address in the example format.");
    }
    // Mock authentication rotates to a new opaque session; no account lookup message is exposed.
    for (const [id, session] of sessions) if (session.userId === "account-owner") sessions.delete(id);
    const id = randomToken();
    const csrf = randomToken();
    sessions.set(id, { userId: "account-owner", csrf, createdAt: Date.now(), lastSeen: Date.now() });
    const mockCode = randomDigits();
    user.identityVerified = false;
    user.identityCheck = await newVerification(mockCode);
    const response = responseJson({ ok: true, csrf, mockCode });
    response.headers.set("Set-Cookie", sessionCookie(id));
    return addCors(request, response);
  }

  const session = authenticated(request);
  if (!session) {
    const response = genericError(401, "Please sign in again to continue.");
    response.headers.set("Set-Cookie", expiredCookie());
    return addCors(request, response);
  }

  if (request.method !== "GET" && !csrfOK(request, session)) {
    return addCors(request, genericError(403, "Your secure form check did not match. Refresh and try again."));
  }

  if (url.pathname === "/api/identity/send" && request.method === "POST") {
    const mockCode = randomDigits();
    user.identityCheck = await newVerification(mockCode);
    return addCors(request, responseJson({ ok: true, mockCode }));
  }

  if (url.pathname === "/api/identity/verify" && request.method === "POST") {
    const data = await bodyJSON(request);
    if (!data || !validCode(data.code)) return addCors(request, genericError(400, "Enter exactly 6 numbers, for example 123456."));
    const result = await verifyCode(user.identityCheck, data.code);
    if (result !== "ok") {
      const message = result === "locked" ? "Too many tries. Request a new code and try again." :
        result === "expired" ? "That code is no longer available. Request a new code and try again." :
        "That code does not match. Check the 6 numbers and try again.";
      return addCors(request, genericError(400, message));
    }
    user.identityCheck = undefined;
    user.identityVerified = true;
    return addCors(request, responseJson({ ok: true }));
  }

  if (url.pathname === "/api/authenticator/provision" && request.method === "POST") {
    if (!user.identityVerified) return addCors(request, genericError(403, "Complete the identity check before setting up an authenticator."));
    const secret = randomBase32(24);
    const mockCode = randomDigits();
    user.encryptedSeed = await encryptSecret(secret); // Cryptographic failures: encrypted at rest.
    user.authenticatorCheck = await newVerification(mockCode);
    return addCors(request, responseJson({ ok: true, secret, mockCode }));
  }

  if (url.pathname === "/api/authenticator/verify" && request.method === "POST") {
    const data = await bodyJSON(request);
    if (!data || !validCode(data.code)) return addCors(request, genericError(400, "Enter exactly 6 numbers, for example 123456."));
    const result = await verifyCode(user.authenticatorCheck, data.code);
    if (result !== "ok") {
      const message = result === "locked" ? "Too many tries. Start setup again to get a fresh code." :
        result === "expired" ? "That code is no longer available. Start setup again." :
        "That code does not match. Check the 6 numbers and try again.";
      return addCors(request, genericError(400, message));
    }
    user.authenticatorCheck = undefined; // Single-use verification value.
    user.mfaEnabled = true;
    const codes = await createRecoveryCodes();
    return addCors(request, responseJson({ ok: true, codes }));
  }

  if (url.pathname === "/api/backup/confirm" && request.method === "POST") {
    if (!user.mfaEnabled) return addCors(request, genericError(403, "Set up an authenticator first."));
    return addCors(request, responseJson({ ok: true }));
  }

  if (url.pathname === "/api/recovery/regenerate" && request.method === "POST") {
    if (!user.mfaEnabled) return addCors(request, genericError(403, "Set up an authenticator first."));
    const codes = await createRecoveryCodes(); // Old hashes are discarded; codes remain one-time.
    return addCors(request, responseJson({ ok: true, codes }));
  }

  if (url.pathname === "/api/recovery/verify" && request.method === "POST") {
    if (!user.mfaEnabled) return addCors(request, genericError(403, "Set up an authenticator first."));
    const data = await bodyJSON(request);
    if (!data || !validRecovery(data.code)) return addCors(request, genericError(400, "Enter a recovery code like ABCDE-FGHIJ."));
    const hashed = await digest(data.code);
    if (!user.backupHashes.has(hashed)) return addCors(request, genericError(400, "That recovery code is not available. Check it or use another saved code."));
    user.backupHashes.delete(hashed); // Recovery codes are single-use.
    return addCors(request, responseJson({ ok: true }));
  }

  if (url.pathname === "/api/logout" && request.method === "POST") {
    const id = cookieValue(request, "mfa_session");
    if (id) sessions.delete(id);
    const response = responseJson({ ok: true });
    response.headers.set("Set-Cookie", expiredCookie());
    return addCors(request, response);
  }

  return addCors(request, genericError(404, "Page not found."));
}

/* Security misconfiguration requirement: Bun serves TLS only using supplied mkcert files. */
Bun.serve({
  port: 3000,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      return await route(request);
    } catch {
      // No debug traces, secrets, or verbose server error output.
      return genericError(500, "We could not complete that request. Please try again.");
    }
  },
});

console.log("MFA enrolment server ready at https://localhost:3000");
