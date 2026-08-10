
import { serve, file } from "bun";

/*
  MFA Enrolment System
  - Security requirements: HTTPS, secure cookies, CSRF, server-side ownership,
    encrypted/hash-protected in-memory records, rate limits, safe headers.
  - Inclusivity requirements: the client provides plain language, short steps,
    visible help, generous spacing, copy controls, no timers or moving content.
*/

const PORT = 3000;
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 10 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;
const MAX_FAILURES = 5;
const trustedOrigins = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

type Challenge = {
  hash: string;
  expires: number;
  used: boolean;
  failures: number;
  lockedUntil: number;
};

type Session = {
  id: string;
  csrf: string;
  created: number;
  lastSeen: number;
  userId?: string;
  identityVerified: boolean;
  loginFailures: number;
  loginLockedUntil: number;
  identityChallenge?: Challenge;
  authenticatorChallenge?: Challenge;
};

type Account = {
  id: string;
  email: string;
  encryptedOtpSecret?: { iv: string; data: string };
  recoveryHashes: Set<string>;
  mfaEnabled: boolean;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  true,
  ["encrypt", "decrypt"],
);
const hashPepper = randomText(32);

/* A deliberately tiny in-memory account store. No client account ID is accepted. */
accounts.set("marcus-account", {
  id: "marcus-account",
  email: "marcus@example.com",
  recoveryHashes: new Set(),
  mfaEnabled: false,
});

function randomText(bytes = 24): string {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return Array.from(data, (x) => x.toString(16).padStart(2, "0")).join("");
}

function randomDigits(): string {
  const data = new Uint32Array(1);
  crypto.getRandomValues(data);
  return String((data[0] % 900000) + 100000);
}

function randomBase32(bytes = 20): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

function toBase64(data: Uint8Array): string {
  return Buffer.from(data).toString("base64");
}

function fromBase64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}

/* Cryptographic failures requirement: server-side OTP secret is AES-GCM encrypted. */
async function encryptSecret(secret: string) {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const encoded = new TextEncoder().encode(secret);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, encoded);
  return { iv: toBase64(iv), data: toBase64(new Uint8Array(ciphertext)) };
}

/* Recovery values and challenges are stored only as a keyed cryptographic hash. */
async function protectedHash(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(`${hashPepper}:${value}`);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return toBase64(new Uint8Array(digest));
}

function sameText(a: string, b: string): boolean {
  const aa = new TextEncoder().encode(a);
  const bb = new TextEncoder().encode(b);
  if (aa.length !== bb.length) return false;
  let result = 0;
  for (let i = 0; i < aa.length; i++) result |= aa[i] ^ bb[i];
  return result === 0;
}

function cookieValue(request: Request, name: string): string | undefined {
  const raw = request.headers.get("cookie") || "";
  for (const entry of raw.split(";")) {
    const [key, ...rest] = entry.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
}

function makeSession(): Session {
  const now = Date.now();
  return {
    id: randomText(32),
    csrf: randomText(32),
    created: now,
    lastSeen: now,
    identityVerified: false,
    loginFailures: 0,
    loginLockedUntil: 0,
  };
}

function sessionCookie(id: string): string {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}

function expired(session: Session): boolean {
  const now = Date.now();
  return now - session.lastSeen > SESSION_IDLE_MS || now - session.created > SESSION_ABSOLUTE_MS;
}

function currentSession(request: Request): Session | undefined {
  const id = cookieValue(request, "mfa_session");
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session || expired(session)) {
    if (session) sessions.delete(session.id);
    return undefined;
  }
  session.lastSeen = Date.now();
  return session;
}

function headers(nonce?: string): Headers {
  const h = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
  });
  h.set(
    "Content-Security-Policy",
    nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  );
  return h;
}

function json(body: unknown, status = 200, extra?: Headers): Response {
  const h = extra || headers();
  h.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers: h });
}

function reject(message = "We could not complete that step. Please try again.", status = 400): Response {
  return json({ ok: false, message }, status);
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(value) && value.length <= 254;
}

function validCode(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function validRecovery(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value);
}

/* Validation helper retained for any future phone verification endpoint. */
function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+?[0-9 ()-]{7,20}$/.test(value);
}

/* Open redirect protection: navigation is intentionally restricted to SPA paths. */
function validInternalPath(value: unknown): boolean {
  return typeof value === "string" && ["/", "/help", "/success"].includes(value);
}

async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const data = await request.json();
    return data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function checkOrigin(request: Request): Response | undefined {
  const origin = request.headers.get("origin");
  if (origin && !trustedOrigins.has(origin)) return reject("This request was not accepted. Please use this page directly.", 403);
}

function csrfOK(request: Request, session: Session): boolean {
  const token = request.headers.get("x-csrf-token");
  return typeof token === "string" && token.length === session.csrf.length && sameText(token, session.csrf);
}

function ownerSession(request: Request): { session: Session; account: Account } | Response {
  const session = currentSession(request);
  if (!session || !session.userId) return reject("Please sign in again to continue.", 401);
  const account = accounts.get(session.userId);
  if (!account) return reject("Please sign in again to continue.", 401);
  return { session, account };
}

function verifiedOwner(request: Request): { session: Session; account: Account } | Response {
  const result = ownerSession(request);
  if (result instanceof Response) return result;
  if (!result.session.identityVerified) return reject("Please finish identity check before changing MFA settings.", 403);
  return result;
}

async function challengeMatches(challenge: Challenge | undefined, code: string): Promise<"ok" | "expired" | "locked" | "wrong"> {
  if (!challenge || challenge.used || Date.now() > challenge.expires) return "expired";
  if (challenge.lockedUntil > Date.now()) return "locked";
  const enteredHash = await protectedHash(code);
  if (!sameText(enteredHash, challenge.hash)) {
    challenge.failures++;
    if (challenge.failures >= MAX_FAILURES) {
      challenge.lockedUntil = Date.now() + LOCKOUT_MS;
      challenge.failures = 0;
    }
    return "wrong";
  }
  challenge.used = true;
  return "ok";
}

function page(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Harbour Bank · MFA setup</title>
<style nonce="${nonce}">
:root { color-scheme: light; --ink:#172334; --muted:#526174; --blue:#075fc6; --blue2:#034d9f; --pale:#edf6ff; --line:#cbd6e2; --good:#146c43; --error:#a12828; --card:#fff; }
* { box-sizing:border-box; }
body { margin:0; background:#f2f5f8; color:var(--ink); font-family:Verdana, "Trebuchet MS", Arial, sans-serif; font-size:17px; line-height:1.65; letter-spacing:.025em; }
main { width:min(100%, 560px); margin:0 auto; min-height:100vh; padding:18px 16px 38px; }
header { display:flex; align-items:center; gap:11px; margin:5px 0 18px; }
.logo { display:grid; place-items:center; background:#075fc6; color:white; border-radius:50%; width:40px; height:40px; font-weight:bold; }
h1 { font-size:1.45rem; line-height:1.25; margin:0; letter-spacing:.015em; }
h2 { font-size:1.3rem; line-height:1.35; margin:0 0 9px; }
p { margin:8px 0 14px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:21px 18px; box-shadow:0 1px 2px #13223a10; }
.steps { font-size:.86rem; color:var(--muted); margin:0 2px 12px; }
.step-now { color:var(--blue2); font-weight:bold; }
.icon { font-size:1.65rem; margin-right:7px; vertical-align:middle; }
label { display:block; font-weight:bold; margin:17px 0 5px; }
input { width:100%; min-height:51px; border:2px solid #91a5b9; border-radius:9px; padding:10px 12px; color:var(--ink); background:white; font:inherit; letter-spacing:.045em; }
input:focus { outline:3px solid #8ac5ff; outline-offset:2px; border-color:var(--blue); }
.hint { color:var(--muted); font-size:.9rem; margin:4px 0 12px; }
button { font:inherit; letter-spacing:.02em; border-radius:9px; cursor:pointer; min-height:50px; padding:10px 16px; }
.primary { width:100%; border:2px solid var(--blue); background:var(--blue); color:white; font-weight:bold; margin-top:18px; }
.primary:hover, .primary:focus { background:var(--blue2); }
.secondary { border:1px solid #62768b; background:white; color:#163e68; min-height:43px; margin-top:10px; }
.action-row { display:flex; gap:9px; flex-wrap:wrap; margin-top:8px; }
.notice { border-left:5px solid var(--blue); background:var(--pale); padding:10px 12px; border-radius:5px; margin:15px 0; }
.error { border-left-color:var(--error); background:#fff0f0; color:#721b1b; }
.success { border-left-color:var(--good); background:#effaf3; color:#145535; }
details { margin-top:17px; border-top:1px solid var(--line); padding-top:11px; }
summary { cursor:pointer; color:#174f88; font-weight:bold; }
code, .secret { font-family:ui-monospace, "Courier New", monospace; word-break:break-all; font-size:.91rem; }
.secretbox { padding:10px; background:#f5f7f9; border:1px solid var(--line); border-radius:8px; }
.qr { width:190px; height:190px; display:grid; grid-template-columns:repeat(15,1fr); gap:1px; padding:8px; border:8px solid white; outline:1px solid var(--line); margin:15px auto; background:white; }
.qr span { background:white; } .qr span.on { background:#172334; }
.codes { list-style:none; padding:0; margin:10px 0; display:grid; grid-template-columns:1fr 1fr; gap:8px; }
.codes li { background:#f5f7f9; padding:8px; border:1px solid var(--line); border-radius:7px; font-family:ui-monospace,monospace; text-align:center; }
#logs { margin-top:18px; background:#152334; color:#e8f3ff; border-radius:10px; padding:12px; font-size:.78rem; line-height:1.5; }
#logs h2 { font-size:1rem; color:white; } #logLines { white-space:pre-wrap; overflow-wrap:anywhere; max-height:185px; overflow:auto; }
.footer { display:flex; justify-content:space-between; gap:12px; margin:17px 3px; font-size:.9rem; }
.link { color:#145897; text-decoration:underline; border:0; background:transparent; padding:3px; min-height:auto; }
[hidden] { display:none !important; }
@media (max-width:360px) { body { font-size:16px; } .card { padding:18px 14px; } .codes { grid-template-columns:1fr; } }
</style>
</head>
<body>
<main>
<header><div class="logo" aria-hidden="true">HB</div><div><h1>Harbour Bank</h1><div class="hint">MFA enrolment</div></div></header>
<div id="app" aria-live="polite">Loading your secure setup…</div>
<section id="logs" aria-label="Simulation logs"><h2>Logs</h2><div id="logLines">Ready.</div></section>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
let csrf = "";
let view = "signin";
let state = null;
let lastSetup = null;
let visibleSecret = true;
const app = document.getElementById("app");
const lines = document.getElementById("logLines");

function browserLog(message) {
  console.log(message);
  lines.textContent += "\\n" + message;
  lines.scrollTop = lines.scrollHeight;
}
function safeText(el, value) { el.textContent = value; }
function errorText(message) {
  const box = document.getElementById("message");
  if (box) { safeText(box, message); box.className = "notice error"; box.hidden = false; }
}
async function api(path, method = "GET", body) {
  const options = { method, headers: {} };
  if (method !== "GET") {
    options.headers["Content-Type"] = "application/json";
    options.headers["X-CSRF-Token"] = csrf;
    options.body = JSON.stringify(body || {});
  }
  let response;
  try { response = await fetch(path, options); }
  catch { throw new Error("Connection problem. Check the secure page and try again."); }
  let data;
  try { data = await response.json(); } catch { throw new Error("We could not complete that step. Please try again."); }
  if (data.csrf) csrf = data.csrf;
  if (!response.ok || !data.ok) throw new Error(data.message || "We could not complete that step. Please try again.");
  return data;
}
function shell(step, title, icon, text, content) {
  app.innerHTML = '<div class="steps">Step <span class="step-now">' + step + '</span> of 5</div><section class="card"><h2><span class="icon" aria-hidden="true">' + icon + '</span>' + title + '</h2><p>' + text + '</p><div id="message" class="notice error" hidden></div>' + content + '<details><summary>Need help?</summary><p>Take your time. You can retry a code or request a new one without penalty. This is a practice-style secure setup.</p></details></section><nav class="footer"><button class="link" id="helpLink">Help</button><button class="link" id="logoutLink">Log out</button></nav>';
  document.getElementById("helpLink").onclick = () => { view = "help"; render(); };
  document.getElementById("logoutLink").onclick = logout;
}
function render() {
  if (view === "signin") return signin();
  if (view === "identity") return identity();
  if (view === "setup") return setup();
  if (view === "confirm") return confirm();
  if (view === "backup") return backup();
  if (view === "recover") return recover();
  if (view === "success") return success();
  help();
}
function signin() {
  shell("1", "Sign in", "🔐", "Use the email for your new bank account.", '<form id="signForm"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="username" inputmode="email" placeholder="marcus@example.com" required><div class="hint">Example: name@example.com</div><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><div class="hint">Your normal bank password</div><button class="primary">Continue</button></form>');
  document.getElementById("signForm").onsubmit = async e => {
    e.preventDefault();
    try {
      const d = await api("/api/login", "POST", { email: document.getElementById("email").value, password: document.getElementById("password").value });
      csrf = d.csrf; state = d; browserLog("Sign-in accepted. Identity check is ready."); view = "identity"; render();
    } catch (x) { errorText(x.message); }
  };
}
function identity() {
  shell("2", "Check it is you", "✉️", "We will send a short practice code to your account email.", '<div class="notice">There is no rush. The code has 6 numbers, like <code>123456</code>.</div><button class="primary" id="sendCode">Send my code</button><button class="secondary" id="backSign">Use a different sign-in</button>');
  document.getElementById("sendCode").onclick = async () => {
    try {
      const d = await api("/api/identity/send", "POST");
      browserLog("SIMULATION — identity code: " + d.testCode);
      identityEntry(d.testCode);
    } catch (x) { errorText(x.message); }
  };
  document.getElementById("backSign").onclick = () => { view = "signin"; render(); };
}
function identityEntry(code) {
  shell("2", "Enter the email code", "✉️", "Enter the 6-number code. It is shown in Logs for this simulation.", '<form id="identityForm"><label for="identityCode">Email code</label><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required><div class="hint">Example: 123456</div><button class="primary">Check code</button></form><button class="secondary" id="again">Send a new code</button>');
  document.getElementById("identityForm").onsubmit = async e => {
    e.preventDefault();
    try { await api("/api/identity/verify", "POST", { code: document.getElementById("identityCode").value }); browserLog("Identity check completed."); view = "setup"; render(); }
    catch (x) { errorText(x.message); }
  };
  document.getElementById("again").onclick = () => identity();
}
function qrMarkup(value) {
  let n = 0; for (let i = 0; i < value.length; i++) n = (n * 31 + value.charCodeAt(i)) >>> 0;
  let out = '<div class="qr" role="img" aria-label="QR-style setup code">';
  for (let i = 0; i < 225; i++) { n = (n * 1664525 + 1013904223) >>> 0; out += '<span class="' + ((n >>> 30) ? "on" : "") + '"></span>'; }
  return out + "</div>";
}
function setup() {
  shell("3", "Set up your authenticator", "📱", "Use an authenticator app on this phone. We will show a QR-style code and a copyable setup key.", '<div class="notice">Choose one easy way: scan the code, or copy the setup key into your app.</div><button class="primary" id="makeSetup">Show setup options</button>');
  document.getElementById("makeSetup").onclick = async () => {
    try {
      lastSetup = await api("/api/authenticator/setup", "POST");
      browserLog("SIMULATION — authenticator secret: " + lastSetup.secret);
      browserLog("SIMULATION — confirmation code: " + lastSetup.testCode);
      setupOptions();
    } catch (x) { errorText(x.message); }
  };
}
function setupOptions() {
  shell("3", "Add this to your app", "📱", "Scan the square in your authenticator app. Or copy the short setup key below.", qrMarkup(lastSetup.uri) + '<label>Setup key</label><div class="secretbox"><span class="secret" id="secretValue"></span></div><div class="action-row"><button class="secondary" id="copySecret">Copy setup key</button><button class="secondary" id="toggleSecret">Hide key</button></div><div class="hint">Manual option: in your app choose “enter setup key”, then paste it.</div><button class="primary" id="ready">I added it to my app</button>');
  safeText(document.getElementById("secretValue"), visibleSecret ? lastSetup.secret : "••••••••••••••••");
  document.getElementById("copySecret").onclick = async () => {
    try { await navigator.clipboard.writeText(lastSetup.secret); browserLog("Setup key copied to clipboard."); } catch { errorText("Copy did not work. Select the setup key and copy it."); }
  };
  document.getElementById("toggleSecret").onclick = () => { visibleSecret = !visibleSecret; setupOptions(); };
  document.getElementById("ready").onclick = () => { view = "confirm"; render(); };
}
function confirm() {
  shell("4", "Check your authenticator", "✅", "Open your authenticator app and enter its 6-number code. The simulation code is in Logs.", '<form id="otpForm"><label for="otp">Authenticator code</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required><div class="hint">Example: 123456</div><button class="primary">Check authenticator</button></form><button class="secondary" id="restartSetup">Show setup key again</button>');
  document.getElementById("otpForm").onsubmit = async e => {
    e.preventDefault();
    try { await api("/api/authenticator/confirm", "POST", { code: document.getElementById("otp").value }); browserLog("Authenticator confirmed."); view = "backup"; render(); }
    catch (x) { errorText(x.message); }
  };
  document.getElementById("restartSetup").onclick = () => setupOptions();
}
function backup() {
  shell("5", "Save backup codes", "🧾", "Keep these codes somewhere safe. Each one works once if you cannot use your authenticator.", '<div class="notice">You can copy all codes. You will next check one code, so you know where they are.</div><button class="primary" id="createCodes">Show my backup codes</button>');
  document.getElementById("createCodes").onclick = async () => {
    try { const d = await api("/api/recovery/generate", "POST"); browserLog("SIMULATION — backup codes: " + d.codes.join(", ")); backupList(d.codes); }
    catch (x) { errorText(x.message); }
  };
}
function backupList(codes) {
  shell("5", "Your backup codes", "🧾", "Copy or write down these short codes. Each code can be used once.", '<ul class="codes" id="codes"></ul><button class="secondary" id="copyCodes">Copy all codes</button><button class="primary" id="checkCode">I saved them — check one code</button>');
  const list = document.getElementById("codes"); codes.forEach(c => { const li = document.createElement("li"); safeText(li, c); list.appendChild(li); });
  document.getElementById("copyCodes").onclick = async () => {
    try { await navigator.clipboard.writeText(codes.join("\\n")); browserLog("Backup codes copied to clipboard."); } catch { errorText("Copy did not work. Select the codes and copy them."); }
  };
  document.getElementById("checkCode").onclick = () => { view = "recover"; render(); };
}
function recover() {
  shell("5", "Check one backup code", "🔎", "Enter one unused backup code. This confirms you can recover your account later.", '<form id="recoveryForm"><label for="recovery">Backup code</label><input id="recovery" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" maxlength="9" placeholder="AB12-CD34" required><div class="hint">Example: AB12-CD34</div><button class="primary">Check backup code</button></form><button class="secondary" id="backCodes">Show my codes again</button>');
  document.getElementById("recoveryForm").onsubmit = async e => {
    e.preventDefault();
    try { await api("/api/recovery/verify", "POST", { code: document.getElementById("recovery").value.toUpperCase() }); browserLog("A backup code was checked and used once."); view = "success"; render(); }
    catch (x) { errorText(x.message); }
  };
  document.getElementById("backCodes").onclick = () => backup();
}
function success() {
  shell("5", "MFA is ready", "🎉", "Your authenticator is connected and your backup codes are saved. You can now use MFA for protected payments.", '<div class="notice success">Setup complete. You are in control of your account security.</div><button class="primary" id="finish">Finish securely</button>');
  document.getElementById("finish").onclick = logout;
}
function help() {
  shell("Help", "Help with MFA", "💡", "Use one step at a time. Nothing on this page moves or times your reading.", '<div class="notice">If a code does not work, request a new one or try again. A temporary pause after several incorrect entries protects your account.</div><button class="primary" id="return">Return to my current step</button>');
  document.getElementById("return").onclick = () => { view = state && state.loggedIn ? (state.identityVerified ? "setup" : "identity") : "signin"; render(); };
}
async function logout() {
  try { await api("/api/logout", "POST"); } catch (_) {}
  csrf = ""; state = null; lastSetup = null; visibleSecret = true;
  browserLog("You have been logged out securely.");
  await boot();
}
async function boot() {
  try {
    state = await api("/api/state");
    if (!state.loggedIn) view = "signin";
    else if (!state.identityVerified) view = "identity";
    else if (!state.mfaEnabled) view = "setup";
    else view = "success";
    render();
  } catch (x) { app.textContent = "We could not open secure setup. Please refresh this page."; }
}
boot();
})();
</script>
</body></html>`;
}

async function handleApi(request: Request, path: string): Promise<Response> {
  const originIssue = checkOrigin(request);
  if (originIssue) return originIssue;

  if (path === "/api/state" && request.method === "GET") {
    let session = currentSession(request);
    let setCookie: string | undefined;
    if (!session) {
      session = makeSession();
      sessions.set(session.id, session);
      setCookie = sessionCookie(session.id);
    }
    const account = session.userId ? accounts.get(session.userId) : undefined;
    const h = headers();
    if (setCookie) h.set("Set-Cookie", setCookie);
    return json({
      ok: true,
      csrf: session.csrf,
      loggedIn: Boolean(session.userId),
      identityVerified: session.identityVerified,
      mfaEnabled: Boolean(account?.mfaEnabled),
    }, 200, h);
  }

  if (path === "/api/login" && request.method === "POST") {
    const oldSession = currentSession(request);
    if (!oldSession || !csrfOK(request, oldSession)) return reject("Please refresh the page and try again.", 403);
    const body = await readBody(request);
    if (!body || !validEmail(body.email) || typeof body.password !== "string" || body.password.length > 256) {
      return reject("We could not sign you in. Check your email and password, then try again.", 401);
    }
    if (oldSession.loginLockedUntil > Date.now()) {
      return reject("Too many sign-in attempts. Please wait a few minutes, then try again.", 429);
    }
    /* Generic response avoids account enumeration. The mock account credential is fixed. */
    const correct = body.email.toLowerCase() === "marcus@example.com" && body.password === "bank-demo";
    if (!correct) {
      oldSession.loginFailures++;
      if (oldSession.loginFailures >= MAX_FAILURES) {
        oldSession.loginFailures = 0;
        oldSession.loginLockedUntil = Date.now() + LOCKOUT_MS;
      }
      return reject("We could not sign you in. Check your email and password, then try again.", 401);
    }
    /* Authentication requirement: rotate session ID after successful authentication. */
    sessions.delete(oldSession.id);
    const session = makeSession();
    session.userId = "marcus-account";
    sessions.set(session.id, session);
    const h = headers();
    h.set("Set-Cookie", sessionCookie(session.id));
    return json({ ok: true, csrf: session.csrf, loggedIn: true, identityVerified: false, mfaEnabled: false }, 200, h);
  }

  if (path === "/api/logout" && request.method === "POST") {
    const session = currentSession(request);
    if (!session || !csrfOK(request, session)) return reject("Please refresh the page and try again.", 403);
    sessions.delete(session.id);
    const h = headers();
    h.set("Set-Cookie", "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
    return json({ ok: true }, 200, h);
  }

  if (path === "/api/identity/send" && request.method === "POST") {
    const result = ownerSession(request);
    if (result instanceof Response) return result;
    if (!csrfOK(request, result.session)) return reject("Please refresh the page and try again.", 403);
    const testCode = randomDigits();
    result.session.identityChallenge = {
      hash: await protectedHash(testCode),
      expires: Date.now() + CODE_LIFETIME_MS,
      used: false,
      failures: 0,
      lockedUntil: 0,
    };
    /* Test code is returned only through the authenticated HTTPS response, never server logged. */
    return json({ ok: true, testCode, csrf: result.session.csrf });
  }

  if (path === "/api/identity/verify" && request.method === "POST") {
    const result = ownerSession(request);
    if (result instanceof Response) return result;
    if (!csrfOK(request, result.session)) return reject("Please refresh the page and try again.", 403);
    const body = await readBody(request);
    if (!body || !validCode(body.code)) return reject("Enter all 6 numbers from the email code.");
    const outcome = await challengeMatches(result.session.identityChallenge, body.code);
    if (outcome === "ok") {
      result.session.identityVerified = true;
      return json({ ok: true, csrf: result.session.csrf });
    }
    if (outcome === "locked") return reject("Too many incorrect codes. Please wait a few minutes, then request a new code.", 429);
    if (outcome === "expired") return reject("That code is no longer available. Send a new code and try again.");
    return reject("That code does not match. Check the 6 numbers or send a new code.");
  }

  if (path === "/api/authenticator/setup" && request.method === "POST") {
    const result = verifiedOwner(request);
    if (result instanceof Response) return result;
    if (!csrfOK(request, result.session)) return reject("Please refresh the page and try again.", 403);
    const secret = randomBase32();
    result.account.encryptedOtpSecret = await encryptSecret(secret);
    const testCode = randomDigits();
    result.session.authenticatorChallenge = {
      hash: await protectedHash(testCode),
      expires: Date.now() + CODE_LIFETIME_MS,
      used: false,
      failures: 0,
      lockedUntil: 0,
    };
    const uri = `otpauth://totp/Harbour%20Bank:marcus%40example.com?secret=${secret}&issuer=Harbour%20Bank`;
    return json({ ok: true, csrf: result.session.csrf, secret, uri, testCode });
  }

  if (path === "/api/authenticator/confirm" && request.method === "POST") {
    const result = verifiedOwner(request);
    if (result instanceof Response) return result;
    if (!csrfOK(request, result.session)) return reject("Please refresh the page and try again.", 403);
    const body = await readBody(request);
    if (!body || !validCode(body.code)) return reject("Enter the 6-number authenticator code.");
    const outcome = await challengeMatches(result.session.authenticatorChallenge, body.code);
    if (outcome === "ok") {
      result.account.mfaEnabled = true;
      return json({ ok: true, csrf: result.session.csrf });
    }
    if (outcome === "locked") return reject("Too many incorrect codes. Please wait a few minutes, then show setup options again.", 429);
    if (outcome === "expired") return reject("That code is no longer available. Show setup options again to get a new code.");
    return reject("That code does not match. Check your authenticator app and try again.");
  }

  if (path === "/api/recovery/generate" && request.method === "POST") {
    const result = verifiedOwner(request);
    if (result instanceof Response) return result;
    if (!csrfOK(request, result.session)) return reject("Please refresh the page and try again.", 403);
    if (!result.account.mfaEnabled) return reject("Finish authenticator setup before creating backup codes.", 403);
    const codes: string[] = [];
    for (let i = 0; i < 8; i++) {
      const raw = randomText(4).toUpperCase().replace(/[^A-F0-9]/g, "A").slice(0, 8);
      codes.push(`${raw.slice(0, 4)}-${raw.slice(4, 8)}`);
    }
    result.account.recoveryHashes = new Set(await Promise.all(codes.map(protectedHash)));
    return json({ ok: true, csrf: result.session.csrf, codes });
  }

  if (path === "/api/recovery/verify" && request.method === "POST") {
    const result = verifiedOwner(request);
    if (result instanceof Response) return result;
    if (!csrfOK(request, result.session)) return reject("Please refresh the page and try again.", 403);
    const body = await readBody(request);
    if (!body || !validRecovery(body.code)) return reject("Enter a backup code in this format: AB12-CD34.");
    const codeHash = await protectedHash(body.code);
    let match: string | undefined;
    for (const saved of result.account.recoveryHashes) {
      if (sameText(saved, codeHash)) {
        match = saved;
        break;
      }
    }
    if (!match) return reject("That backup code is not available. Check the code and try another saved code.");
    result.account.recoveryHashes.delete(match);
    return json({ ok: true, csrf: result.session.csrf });
  }

  return reject("This secure page is not available.", 404);
}

serve({
  port: PORT,
  tls: {
    cert: file("certs/cert.pem"),
    key: file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:") return reject("Please use the secure HTTPS address.", 403);
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = randomText(18);
        const h = headers(nonce);
        h.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { status: 200, headers: h });
      }
      return reject("This secure page is not available.", 404);
    } catch {
      /* Production-safe generic error: no stack trace, secrets, or request values. */
      return reject("We could not complete that request. Please try again.", 500);
    }
  },
});
