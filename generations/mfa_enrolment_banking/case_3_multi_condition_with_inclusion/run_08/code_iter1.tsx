
const encoder = new TextEncoder();
const sessions = new Map<string, Session>();
const allowedOrigins = new Set([
  "https://localhost",
  "https://127.0.0.1",
  "https://[::1]",
]);
const USER = { id: "acct_marcus_01", email: "marcus@example.test" };
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFE_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60 * 1000;

type Challenge = {
  value: string;
  expires: number;
  used: boolean;
  attempts: number;
  lockedUntil: number;
};

type Session = {
  id: string;
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
  identityVerified: boolean;
  mfaVerified: boolean;
  identityChallenge?: Challenge;
  authenticatorChallenge?: Challenge;
  encryptedSecret?: string;
  recoveryHashes: Set<string>;
};

function randomBytes(count: number) {
  const bytes = new Uint8Array(count);
  crypto.getRandomValues(bytes);
  return bytes;
}

function base64Url(bytes: Uint8Array) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function secureToken(bytes = 32) {
  return base64Url(randomBytes(bytes));
}

function randomDigits() {
  const value = new Uint32Array(1);
  crypto.getRandomValues(value);
  return String(value[0] % 1_000_000).padStart(6, "0");
}

const recoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function recoveryCode() {
  const bytes = randomBytes(8);
  let result = "";
  for (let i = 0; i < 8; i++) result += recoveryAlphabet[bytes[i] % recoveryAlphabet.length];
  return result.slice(0, 4) + "-" + result.slice(4);
}

function secretValue() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = randomBytes(20);
  let value = "";
  for (const byte of bytes) value += alphabet[byte % alphabet.length];
  return value;
}

const masterMaterial = randomBytes(32);
const masterKey = await crypto.subtle.importKey("raw", masterMaterial, "AES-GCM", false, ["encrypt", "decrypt"]);
const hashPepper = secureToken(24);

async function protectAtRest(value: string) {
  const iv = randomBytes(12);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(value));
  const output = new Uint8Array(iv.length + cipher.byteLength);
  output.set(iv);
  output.set(new Uint8Array(cipher), iv.length);
  return base64Url(output);
}

async function codeHash(value: string) {
  const bytes = await crypto.subtle.digest("SHA-256", encoder.encode(hashPepper + ":" + value));
  return base64Url(new Uint8Array(bytes));
}

function createChallenge(): Challenge {
  return {
    value: randomDigits(),
    expires: Date.now() + CODE_LIFE_MS,
    used: false,
    attempts: 0,
    lockedUntil: 0,
  };
}

function validOrigin(req: Request) {
  const origin = req.headers.get("origin");
  return !origin || allowedOrigins.has(origin);
}

/* Security requirements 2 and 4: strict headers, trusted-origin CORS, no verbose errors. */
function secureHeaders(nonce: string, origin?: string | null) {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  if (origin && allowedOrigins.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}

function json(data: unknown, status = 200, req?: Request) {
  const nonce = secureToken(16);
  return new Response(JSON.stringify(data), {
    status,
    headers: secureHeaders(nonce, req?.headers.get("origin")),
  });
}

function htmlResponse() {
  const nonce = secureToken(16);
  const headers = secureHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(page(nonce), { headers });
}

function getCookie(req: Request, key: string) {
  const raw = req.headers.get("cookie") || "";
  const item = raw.split(";").map(v => v.trim()).find(v => v.startsWith(key + "="));
  return item ? item.slice(key.length + 1) : "";
}

/* Security requirement 1 & 5: ownership, expiry and secure session enforcement on every protected API route. */
function authenticated(req: Request): { session?: Session; error?: Response } {
  const id = getCookie(req, "mfa_session");
  const session = sessions.get(id);
  const now = Date.now();
  if (!session) return { error: json({ error: "Please sign in again." }, 401, req) };
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return { error: json({ error: "Your session ended for safety. Please sign in again." }, 401, req) };
  }
  session.lastSeen = now;
  return { session };
}

async function requestBody(req: Request) {
  const type = req.headers.get("content-type") || "";
  if (!type.includes("application/json")) throw new Error("invalid");
  const body = await req.json();
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("invalid");
  return body as Record<string, unknown>;
}

/* Security requirement 1: CSRF plus explicit rejection of mismatched account identifiers. */
function stateAllowed(req: Request, session: Session, body: Record<string, unknown>) {
  if (req.headers.get("x-csrf-token") !== session.csrf) return "This request could not be confirmed. Refresh and try again.";
  if ("userId" in body && body.userId !== session.userId) return "This account request is not allowed.";
  return "";
}

function safeEmail(value: unknown) {
  return typeof value === "string" && value.length <= 120 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function safeCode(value: unknown, recovery = false) {
  const pattern = recovery ? /^[A-Z2-9]{4}-[A-Z2-9]{4}$/ : /^\d{6}$/;
  return typeof value === "string" && pattern.test(value);
}

async function verifyChallenge(challenge: Challenge | undefined, code: string) {
  if (!challenge) return { ok: false, message: "Request a new code, then try again." };
  if (challenge.lockedUntil > Date.now()) return { ok: false, message: "Too many tries. Please wait 15 minutes, then request a new code." };
  if (challenge.used) return { ok: false, message: "That code was already used. Request a new code." };
  if (challenge.expires < Date.now()) return { ok: false, message: "That code has expired. Request a new code." };
  if (challenge.value !== code) {
    challenge.attempts++;
    if (challenge.attempts >= MAX_FAILURES) {
      challenge.lockedUntil = Date.now() + LOCK_MS;
      return { ok: false, message: "Too many tries. Please wait 15 minutes, then request a new code." };
    }
    return { ok: false, message: `That code does not match. Check the six numbers and try again (${MAX_FAILURES - challenge.attempts} tries left).` };
  }
  challenge.used = true;
  return { ok: true, message: "" };
}

function createSession() {
  const now = Date.now();
  const session: Session = {
    id: secureToken(),
    userId: USER.id,
    csrf: secureToken(),
    createdAt: now,
    lastSeen: now,
    identityVerified: false,
    mfaVerified: false,
    recoveryHashes: new Set(),
  };
  session.identityChallenge = createChallenge();
  sessions.set(session.id, session);
  return session;
}

function sessionCookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}

function provisioningUri(secret: string) {
  return `otpauth://totp/Example%20Bank:${encodeURIComponent(USER.email)}?secret=${secret}&issuer=Example%20Bank&algorithm=SHA1&digits=6&period=30`;
}

async function generateRecovery(session: Session) {
  const codes = Array.from({ length: 8 }, recoveryCode);
  session.recoveryHashes = new Set(await Promise.all(codes.map(codeHash)));
  return codes;
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Example Bank — security set-up</title>
<style nonce="${nonce}">
:root { --ink:#172535; --muted:#526476; --blue:#075bb8; --blue-dark:#03448e; --pale:#edf6ff; --line:#c9d6e2; --good:#146c43; --bad:#ad2430; --focus:#f0a100; }
* { box-sizing:border-box; }
body { margin:0; background:#f3f7fa; color:var(--ink); font-family:Arial, Verdana, Tahoma, sans-serif; font-size:17px; line-height:1.65; letter-spacing:.025em; }
button,input { font:inherit; letter-spacing:.03em; }
button { cursor:pointer; }
.shell { width:min(100%, 520px); margin:auto; min-height:100vh; background:#fff; box-shadow:0 0 20px #b9c7d155; }
header { padding:20px 22px 14px; border-bottom:1px solid var(--line); }
.brand { margin:0; font-size:1.15rem; font-weight:700; }
.brand span { color:var(--blue); }
.progress { margin:14px 0 0; color:var(--muted); font-size:.91rem; }
main { padding:24px 22px 36px; }
h1 { font-size:1.65rem; line-height:1.25; margin:0 0 12px; letter-spacing:.01em; }
h2 { font-size:1.15rem; line-height:1.35; }
p { margin:0 0 17px; }
.lead { font-size:1.07rem; }
.card { border:1px solid var(--line); border-radius:12px; padding:17px; margin:18px 0; background:#fff; }
.note { background:var(--pale); border-left:5px solid var(--blue); }
label { display:block; font-weight:700; margin:15px 0 6px; }
input { width:100%; min-height:52px; padding:10px 13px; border:2px solid #8295a8; border-radius:8px; color:var(--ink); background:#fff; }
input:focus,button:focus { outline:3px solid var(--focus); outline-offset:2px; }
.hint { color:var(--muted); font-size:.92rem; margin-top:5px; }
.primary { width:100%; min-height:54px; margin:22px 0 10px; padding:10px; border:0; border-radius:9px; background:var(--blue); color:#fff; font-weight:700; }
.primary:hover { background:var(--blue-dark); }
.secondary, .linkbutton { min-height:42px; padding:7px 10px; border:1px solid var(--blue); border-radius:7px; background:#fff; color:var(--blue); font-weight:700; }
.linkbutton { border:0; padding:4px; text-decoration:underline; }
.actions { display:flex; flex-wrap:wrap; gap:10px; margin-top:10px; }
.error { background:#fff0f1; border-left:5px solid var(--bad); padding:10px 13px; margin:15px 0; font-weight:700; }
.success { background:#edf9f1; border-left:5px solid var(--good); padding:10px 13px; margin:15px 0; font-weight:700; }
.hidden { display:none !important; }
.code { font-family:ui-monospace, SFMono-Regular, Consolas, monospace; font-size:1.08rem; letter-spacing:.11em; word-break:break-all; background:#f4f7f9; border:1px solid var(--line); padding:12px; border-radius:8px; }
.qr { width:190px; height:190px; display:grid; grid-template-columns:repeat(13,1fr); gap:2px; padding:8px; background:#fff; border:1px solid var(--line); margin:12px auto; }
.qr i { background:#102a43; }
.qr i.blank { background:#fff; }
.codes { display:grid; grid-template-columns:1fr 1fr; gap:9px; list-style:none; padding:0; }
.codes li { font-family:ui-monospace, monospace; letter-spacing:.07em; padding:9px; background:#f4f7f9; border-radius:6px; text-align:center; }
.checkline { display:flex; gap:11px; align-items:flex-start; margin-top:20px; }
.checkline input { width:25px; min-height:25px; margin-top:4px; }
.help { margin-top:27px; border-top:1px solid var(--line); padding-top:15px; }
.logs { margin-top:24px; border-top:2px solid var(--line); padding-top:12px; }
.logs summary { font-weight:700; color:var(--blue); cursor:pointer; }
#logbox { max-height:170px; overflow:auto; white-space:pre-wrap; font-family:ui-monospace,monospace; font-size:.77rem; line-height:1.45; background:#152536; color:#e7f2ff; border-radius:8px; padding:10px; margin-top:9px; }
.small { font-size:.9rem; color:var(--muted); }
@media (max-width:360px) { main { padding:20px 16px 30px; } header { padding:18px 16px 12px; } body { font-size:16px; } }
</style>
</head>
<body>
<div class="shell">
<header><p class="brand">◈ <span>Example Bank</span> security set-up</p><p id="progress" class="progress">Step 1 of 6</p></header>
<main id="app" aria-live="polite"></main>
</div>
<script nonce="${nonce}">
(() => {
"use strict";
/* Inclusivity requirements: short, static screens, generous spacing, icons and plain wording. */
let csrf = "";
let recoveryCodes = [];
let current = "signin";
const app = document.getElementById("app");
const progress = document.getElementById("progress");
const logLines = [];

function visibleLog(message) {
  console.log(message); // Test mocks are deliberately browser-console only, never server logged.
  logLines.push(message);
  const box = document.getElementById("logbox");
  if (box) { box.textContent = logLines.join("\\n"); box.scrollTop = box.scrollHeight; }
}
function esc(value) {
  return String(value).replace(/[&<>"']/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" })[c]);
}
function logs() {
  return '<details class="logs"><summary>▣ Logs for this demo</summary><div id="logbox"></div><p class="small">Test values are shown here and in the browser console. In a real bank, they would not be shown.</p></details>';
}
function help() { return '<aside class="help"><strong>ⓘ Need help?</strong><br><span class="small">Take your time. You can retry or request a fresh code without penalty.</span></aside>'; }
function message(text, good=false) { return text ? '<div class="' + (good ? "success" : "error") + '" role="alert">' + esc(text) + "</div>" : ""; }
function render(screen, alertText="", good=false) {
  current = screen;
  const steps = {signin:"Step 1 of 6", identity:"Step 2 of 6", setup:"Step 3 of 6", confirm:"Step 4 of 6", recovery:"Step 5 of 6", done:"Step 6 of 6"};
  progress.textContent = steps[screen] || "";
  let body = "";
  if (screen === "signin") body = \`
    <h1>Sign in to set up extra protection</h1>
    <p class="lead">We will help you add a second step before high-value payments.</p>
    \${message(alertText,good)}
    <form id="signForm">
      <label for="email">✉ Email address</label>
      <input id="email" name="email" type="email" autocomplete="email" inputmode="email" placeholder="name@example.com" required maxlength="120">
      <p class="hint">Example: marcus@example.com</p>
      <button class="primary" type="submit">Continue</button>
    </form>\${help()}\`;
  if (screen === "identity") body = \`
    <h1>Check it is you</h1><p>We sent a six-number code to your email in this safe demo.</p>
    \${message(alertText,good)}
    <form id="identityForm"><label for="identityCode">🔐 Email code</label>
    <input id="identityCode" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="Example: 123456" required>
    <p class="hint">Enter six numbers. There is no reading timer.</p><button class="primary">Verify code</button></form>
    <div class="actions"><button class="secondary" id="resendIdentity">↻ Send a new code</button><button class="linkbutton" id="backSign">← Back</button></div>\${help()}\`;
  if (screen === "setup") body = \`
    <h1>Add your authenticator</h1><p>Use an authenticator app on your phone. Scanning is easier than typing.</p>
    \${message(alertText,good)}
    <section class="card note"><strong>▣ QR-style provisioning panel</strong><div class="qr" id="qr" aria-label="QR-style setup pattern"></div>
    <p class="small">Use your app’s scan option, or use the copy button below.</p></section>
    <button class="secondary" id="copyUri">⧉ Copy set-up link</button>
    <button class="linkbutton" id="showManual">Show manual secret instead</button>
    <div id="manual" class="hidden"><label>Manual secret</label><div class="code" id="secretText"></div><div class="actions"><button class="secondary" id="copySecret">⧉ Copy secret</button><button class="secondary" id="hideManual">Hide secret</button></div></div>
    <button class="primary" id="continueConfirm">I added it — continue</button><button class="linkbutton" id="backIdentity">← Back</button>\${help()}\`;
  if (screen === "confirm") body = \`
    <h1>Check your authenticator</h1><p>Open the app and enter the six-number code it shows.</p>
    \${message(alertText,good)}
    <form id="otpForm"><label for="otp">🔑 Authenticator code</label><input id="otp" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="Example: 123456" required>
    <p class="hint">You have plenty of time. If needed, go back and start again.</p><button class="primary">Verify authenticator</button></form>
    <div class="actions"><button class="secondary" id="newAuth">↻ Start with a new set-up code</button><button class="linkbutton" id="backSetup">← Back</button></div>\${help()}\`;
  if (screen === "recovery") body = \`
    <h1>Save recovery codes</h1><p>These one-use codes help if you lose your phone. Keep them somewhere private.</p>
    \${message(alertText,good)}
    <section id="codePanel" class="card hidden"><ul id="codeList" class="codes"></ul>
      <div class="actions"><button class="secondary" id="copyCodes">⧉ Copy codes</button><button class="secondary" id="printCodes">▤ Print or save</button></div>
      <button class="secondary" id="regenCodes">↻ Make new codes</button></section>
    <button class="primary" id="makeCodes">Show recovery codes</button>
    <div id="ackWrap" class="checkline hidden"><input id="ack" type="checkbox"><label for="ack">I saved my recovery codes in a private place.</label></div>
    <button class="primary hidden" id="finish">Finish set-up</button>\${help()}\`;
  if (screen === "done") body = \`
    <h1>✓ Extra protection is ready</h1><p class="lead">Your authenticator is set up. You can now approve protected payments.</p>
    \${message(alertText || "You have completed MFA enrolment.",true)}
    <section class="card note"><strong>What happens next</strong><br>You will use your authenticator when a payment needs extra protection.</section>
    <button class="primary" id="logout">Sign out safely</button>\${help()}\`;
  app.innerHTML = body + logs();
  const box = document.getElementById("logbox"); if (box) box.textContent = logLines.join("\\n");
  bind(screen);
}
async function api(path, body={}) {
  const response = await fetch(path, {method:"POST", credentials:"same-origin", headers:{"Content-Type":"application/json","X-CSRF-Token":csrf}, body:JSON.stringify(body)});
  const data = await response.json().catch(() => ({error:"Something went wrong. Please try again."}));
  if (!response.ok) throw new Error(data.error || "Something went wrong. Please try again.");
  return data;
}
function copy(text, ok) {
  navigator.clipboard.writeText(text).then(() => render(current, ok, true)).catch(() => render(current, "Copy did not work. Select the text and copy it another way."));
}
function fillCodes() {
  document.getElementById("codeList").innerHTML = recoveryCodes.map(c => "<li>"+esc(c)+"</li>").join("");
  document.getElementById("codePanel").classList.remove("hidden");
  document.getElementById("makeCodes").classList.add("hidden");
  document.getElementById("ackWrap").classList.remove("hidden");
  document.getElementById("finish").classList.remove("hidden");
}
function qrPattern(value) {
  const qr = document.getElementById("qr"); if (!qr) return;
  let html = ""; for (let i=0;i<169;i++) html += '<i class="'+(((value.charCodeAt(i%value.length)+i*7)%5===0) ? "blank" : "")+'"></i>';
  qr.innerHTML=html;
}
let provisioning = {secret:"", uri:""};
function bind(screen) {
  const on = (id, fn) => { const el=document.getElementById(id); if(el) el.addEventListener("click",fn); };
  if(screen==="signin") document.getElementById("signForm").addEventListener("submit", async e => {
    e.preventDefault(); const email=document.getElementById("email").value.trim();
    try { const d=await api("/api/auth/signin",{email}); csrf=d.csrf; visibleLog("[Demo] Identity verification code: "+d.testCode); render("identity","A code was sent. Enter the six numbers.",true); } catch(err) { render("signin",err.message); }
  });
  if(screen==="identity") {
    document.getElementById("identityForm").addEventListener("submit", async e => { e.preventDefault(); try { await api("/api/identity/verify",{code:document.getElementById("identityCode").value.trim()}); render("setup","Identity confirmed. Now add your authenticator.",true); } catch(err) { render("identity",err.message); } });
    on("resendIdentity",async()=>{try{const d=await api("/api/identity/resend",{});visibleLog("[Demo] New identity code: "+d.testCode);render("identity","A new code was sent.",true)}catch(err){render("identity",err.message)}});
    on("backSign",()=>render("signin"));
  }
  if(screen==="setup") {
    api("/api/mfa/provision",{}).then(d=>{ provisioning=d; visibleLog("[Demo] Authenticator secret: "+d.testSecret); visibleLog("[Demo] Authenticator verification code: "+d.testCode); qrPattern(d.uri); document.getElementById("secretText").textContent=d.secret; }).catch(err=>render("identity",err.message));
    on("copyUri",()=>copy(provisioning.uri,"Set-up link copied."));
    on("showManual",()=>document.getElementById("manual").classList.remove("hidden"));
    on("hideManual",()=>document.getElementById("manual").classList.add("hidden"));
    on("copySecret",()=>copy(provisioning.secret,"Manual secret copied."));
    on("continueConfirm",()=>render("confirm"));
    on("backIdentity",()=>render("identity"));
  }
  if(screen==="confirm") {
    document.getElementById("otpForm").addEventListener("submit",async e=>{e.preventDefault();try{await api("/api/mfa/verify",{code:document.getElementById("otp").value.trim()});render("recovery","Authenticator confirmed. Save recovery codes next.",true)}catch(err){render("confirm",err.message)}});
    on("newAuth",()=>render("setup","A fresh set-up code will be created.",true)); on("backSetup",()=>render("setup"));
  }
  if(screen==="recovery") {
    const make=async()=>{try{const d=await api("/api/mfa/recovery/generate",{});recoveryCodes=d.codes;visibleLog("[Demo] Recovery codes: "+d.codes.join(", "));fillCodes();}catch(err){render("recovery",err.message)}};
    on("makeCodes",make); on("regenCodes",make);
    on("copyCodes",()=>copy(recoveryCodes.join("\\n"),"Recovery codes copied."));
    on("printCodes",()=>{const w=window.open("","_blank");if(!w){render("recovery","Printing was blocked. Use Copy codes instead.");return;}w.document.write("<pre>Example Bank recovery codes\\n\\n"+recoveryCodes.join("\\n")+"</pre>");w.document.close();w.print();});
    on("finish",()=>{if(!document.getElementById("ack").checked){render("recovery","Please tick the box after you have saved the codes.");return;} recoveryCodes=[];render("done");});
  }
  if(screen==="done") on("logout",async()=>{try{await api("/api/auth/logout",{});}catch(_){} csrf=""; render("signin","You are signed out safely.",true);});
}
render("signin");
})();
</script>
</body></html>`;
}

async function handle(req: Request): Promise<Response> {
  try {
    const url = new URL(req.url);
    if (!validOrigin(req)) return json({ error: "Request not allowed." }, 403, req);
    if (req.method === "OPTIONS") {
      const headers = secureHeaders(secureToken(16), req.headers.get("origin"));
      headers.set("Access-Control-Allow-Methods", "POST");
      headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
      return new Response(null, { status: 204, headers });
    }
    if (req.method === "GET" && url.pathname === "/") return htmlResponse();
    if (req.method !== "POST") return json({ error: "Not found." }, 404, req);

    if (url.pathname === "/api/auth/signin") {
      const body = await requestBody(req);
      if (!safeEmail(body.email)) return json({ error: "Enter an email in the format name@example.com." }, 400, req);
      // Account-neutral response and a new opaque session prevent enumeration and fixation.
      const old = getCookie(req, "mfa_session");
      if (old) sessions.delete(old);
      const session = createSession();
      const response = json({ csrf: session.csrf, testCode: session.identityChallenge!.value }, 200, req);
      response.headers.set("Set-Cookie", sessionCookie(session.id));
      return response;
    }

    const auth = authenticated(req);
    if (auth.error) return auth.error;
    const session = auth.session!;
    const body = await requestBody(req);
    const csrfError = stateAllowed(req, session, body);
    if (csrfError) return json({ error: csrfError }, 403, req);

    if (url.pathname === "/api/auth/logout") {
      sessions.delete(session.id);
      const response = json({ ok: true }, 200, req);
      response.headers.set("Set-Cookie", "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
      return response;
    }
    if (url.pathname === "/api/identity/resend") {
      session.identityChallenge = createChallenge();
      return json({ testCode: session.identityChallenge.value }, 200, req);
    }
    if (url.pathname === "/api/identity/verify") {
      if (!safeCode(body.code)) return json({ error: "Enter the six numbers from the code." }, 400, req);
      const result = await verifyChallenge(session.identityChallenge, body.code as string);
      if (!result.ok) return json({ error: result.message }, 400, req);
      session.identityVerified = true;
      return json({ ok: true }, 200, req);
    }
    if (!session.identityVerified) return json({ error: "Complete the identity check before changing MFA settings." }, 403, req);

    if (url.pathname === "/api/mfa/provision") {
      const secret = secretValue();
      session.encryptedSecret = await protectAtRest(secret);
      session.authenticatorChallenge = createChallenge();
      session.mfaVerified = false;
      return json({
        secret,
        uri: provisioningUri(secret),
        testSecret: secret,
        testCode: session.authenticatorChallenge.value,
      }, 200, req);
    }
    if (url.pathname === "/api/mfa/verify") {
      if (!safeCode(body.code)) return json({ error: "Enter the six numbers from your authenticator app." }, 400, req);
      const result = await verifyChallenge(session.authenticatorChallenge, body.code as string);
      if (!result.ok) return json({ error: result.message }, 400, req);
      session.mfaVerified = true;
      return json({ ok: true }, 200, req);
    }
    if (url.pathname === "/api/mfa/recovery/generate") {
      if (!session.mfaVerified) return json({ error: "Confirm your authenticator before making recovery codes." }, 403, req);
      const codes = await generateRecovery(session);
      return json({ codes }, 200, req);
    }
    if (url.pathname === "/api/mfa/recovery/verify") {
      if (!session.mfaVerified) return json({ error: "MFA is not ready." }, 403, req);
      const code = typeof body.code === "string" ? body.code.toUpperCase() : "";
      if (!safeCode(code, true)) return json({ error: "Use the format ABCD-EFGH." }, 400, req);
      const hashed = await codeHash(code);
      if (!session.recoveryHashes.delete(hashed)) return json({ error: "That recovery code cannot be used. Try another saved code." }, 400, req);
      return json({ ok: true }, 200, req);
    }
    return json({ error: "Not found." }, 404, req);
  } catch {
    // Security requirement 2: production-safe, generic failure with no stack trace or sensitive output.
    return json({ error: "Something went wrong. Please try again." }, 500, req);
  }
}

/* TLS requirement: Bun serves HTTPS using the supplied local mkcert files. */
Bun.serve({
  port: 3000,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  fetch: handle,
});
