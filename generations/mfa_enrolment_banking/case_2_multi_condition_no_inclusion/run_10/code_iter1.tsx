
import { timingSafeEqual } from "node:crypto";

/*
  MFA Enrolment System, one-file architecture.
  Bun serves this HTML, its inline client application, and all in-memory API routes.
  Start with: bun app.ts
*/

const PORT = 3000;
const CERT_FILE = "certs/cert.pem";
const KEY_FILE = "certs/key.pem";

// Requirement 2/3: TLS is mandatory; do not silently downgrade this application to HTTP.
if (!(await Bun.file(CERT_FILE).exists()) || !(await Bun.file(KEY_FILE).exists())) {
  console.error("TLS certificate files are required at certs/cert.pem and certs/key.pem.");
  process.exit(1);
}

const encoder = new TextEncoder();
const ACCOUNT = {
  id: "acct_marcus_001",
  email: "marcus@example.com",
  phone: "+15551234567",
  displayName: "Marcus",
};

const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const PREAUTH_MAX_MS = 10 * 60 * 1000;
const VERIFY_WINDOW_MS = 10 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;

type Session = {
  id: string;
  userId?: string;
  authenticated: boolean;
  createdAt: number;
  lastSeen: number;
  expiresAt: number;
  csrf: string;
  identityCode?: string;
  identityExpiresAt?: number;
  identityAttempts: number;
  identityLockedUntil?: number;
};

type Enrollment = {
  encryptedSecret: string;
  expiresAt: number;
  attempts: number;
  lockedUntil?: number;
  usedCounters: Set<number>;
};

type MfaRecord = {
  encryptedSecret: string;
  enabledAt: number;
  usedCounters: Set<number>;
  backupHashes: Set<string>;
  recoveryAttempts: number;
  recoveryLockedUntil?: number;
};

const sessions = new Map<string, Session>();
const pendingEnrollments = new Map<string, Enrollment>();
const mfaRecords = new Map<string, MfaRecord>();

// Requirement 3: process-local cryptographic keys encrypt OTP seeds and HMAC backup values at rest.
const encryptionKeyBytes = crypto.getRandomValues(new Uint8Array(32));
const hmacKeyBytes = crypto.getRandomValues(new Uint8Array(32));
const aesKeyPromise = crypto.subtle.importKey("raw", encryptionKeyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
const hmacKeyPromise = crypto.subtle.importKey("raw", hmacKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);

function bytesToB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}
function b64ToBytes(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64url"));
}
function secureToken(bytes = 32): string {
  return bytesToB64(crypto.getRandomValues(new Uint8Array(bytes)));
}
function secureDigits(): string {
  const bytes = crypto.getRandomValues(new Uint32Array(1));
  return String(100000 + (bytes[0] % 900000));
}
function secureEquals(a: string, b: string): boolean {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function base32Encode(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) result += alphabet[(buffer << (5 - bits)) & 31];
  return result;
}
function base32Decode(text: string): Uint8Array | null {
  const clean = text.toUpperCase().replace(/[\s-]/g, "");
  if (!/^[A-Z2-7]{16,128}$/.test(clean)) return null;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let buffer = 0;
  let bits = 0;
  const output: number[] = [];
  for (const char of clean) {
    const value = alphabet.indexOf(char);
    if (value < 0) return null;
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}
async function encryptSecret(secret: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await aesKeyPromise;
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret));
  return `${bytesToB64(iv)}.${bytesToB64(new Uint8Array(cipher))}`;
}
async function decryptSecret(payload: string): Promise<string> {
  const [ivText, cipherText] = payload.split(".");
  if (!ivText || !cipherText) throw new Error("Invalid encrypted record");
  const key = await aesKeyPromise;
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBytes(ivText) },
    key,
    b64ToBytes(cipherText),
  );
  return new TextDecoder().decode(plain);
}
async function protectedBackupValue(code: string): Promise<string> {
  const key = await hmacKeyPromise;
  const signed = await crypto.subtle.sign("HMAC", key, encoder.encode(`backup-code-v1:${code}`));
  return bytesToB64(new Uint8Array(signed));
}
async function totpFor(secret: string, counter: number): Promise<string> {
  const raw = base32Decode(secret);
  if (!raw) throw new Error("Invalid OTP secret");
  const counterBytes = new Uint8Array(8);
  let value = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = Number(value & 255n);
    value >>= 8n;
  }
  const key = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = digest[digest.length - 1] & 15;
  const number = ((digest[offset] & 127) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(number % 1000000).padStart(6, "0");
}
async function verifyTotp(secret: string, otp: string, usedCounters: Set<number>): Promise<boolean> {
  const nowCounter = Math.floor(Date.now() / 30000);
  for (const counter of [nowCounter, nowCounter - 1]) {
    if (usedCounters.has(counter)) continue;
    if (secureEquals(await totpFor(secret, counter), otp)) {
      usedCounters.add(counter);
      return true;
    }
  }
  return false;
}
function makeBackupCodes(): string[] {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const codes: string[] = [];
  for (let i = 0; i < 8; i++) {
    const random = crypto.getRandomValues(new Uint8Array(10));
    let raw = "";
    for (const byte of random) raw += alphabet[byte % alphabet.length];
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5, 10)}`);
  }
  return codes;
}
function parseCookies(request: Request): Record<string, string> {
  const source = request.headers.get("cookie") || "";
  const values: Record<string, string> = {};
  for (const part of source.split(";")) {
    const at = part.indexOf("=");
    if (at > 0) values[part.slice(0, at).trim()] = decodeURIComponent(part.slice(at + 1).trim());
  }
  return values;
}
function sessionCookie(id: string): string {
  return `__Host-mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}
function expiredSessionCookie(): string {
  return "__Host-mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}
function newSession(authenticated = false): Session {
  const now = Date.now();
  return {
    id: secureToken(),
    authenticated,
    createdAt: now,
    lastSeen: now,
    expiresAt: now + (authenticated ? SESSION_ABSOLUTE_MS : PREAUTH_MAX_MS),
    csrf: secureToken(),
    identityAttempts: 0,
  };
}
function currentSession(request: Request): Session | null {
  const id = parseCookies(request).__Host-mfa_session;
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  const now = Date.now();
  if (now > session.expiresAt || (session.authenticated && now - session.lastSeen > SESSION_IDLE_MS)) {
    sessions.delete(id);
    return null;
  }
  session.lastSeen = now;
  return session;
}
// Requirement 1: each MFA route derives ownership solely from the HttpOnly session.
function authenticatedOwner(request: Request): Session | null {
  const session = currentSession(request);
  if (!session || !session.authenticated || session.userId !== ACCOUNT.id) return null;
  return session;
}
function hasCsrf(request: Request, session: Session): boolean {
  const token = request.headers.get("x-csrf-token") || "";
  return token.length > 20 && secureEquals(token, session.csrf);
}
function isValidEmail(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]{2,100}$/.test(value) && value.length <= 254;
}
function isValidPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+[1-9][0-9]{7,14}$/.test(value);
}
function isValidOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function isValidBackupCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/.test(value);
}
function containsManipulatedIdentifier(body: Record<string, unknown>): boolean {
  return ["userId", "accountId", "ownerId", "email"].some((key) => key in body);
}
async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  if (!request.headers.get("content-type")?.includes("application/json")) return null;
  const text = await request.text();
  if (text.length > 4096) return null;
  try {
    const body = JSON.parse(text);
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function trustedOrigin(request: Request): string | null {
  const origin = request.headers.get("origin");
  if (!origin) return null;
  try {
    const url = new URL(origin);
    const trustedHost = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1";
    return url.protocol === "https:" && trustedHost && url.port === String(PORT) ? origin : null;
  } catch {
    return null;
  }
}
function securityHeaders(request: Request, nonce: string): Headers {
  const headers = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  });
  const origin = trustedOrigin(request);
  if (origin) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}
function json(request: Request, data: unknown, status = 200, setCookie?: string): Response {
  const headers = securityHeaders(request, secureToken(16));
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (setCookie) headers.append("Set-Cookie", setCookie);
  return new Response(JSON.stringify(data), { status, headers });
}
function genericError(request: Request, status = 400, setCookie?: string): Response {
  return json(request, { ok: false, message: "We could not complete that request. Please try again." }, status, setCookie);
}

function page(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light">
<title>Northstar Bank · Security</title>
<style nonce="${nonce}">
:root { --ink:#12213a; --muted:#536278; --blue:#0759c7; --blue-dark:#034494; --pale:#eef5ff; --line:#cad5e4; --good:#087443; --danger:#a91d35; --focus:#f1a500; }
* { box-sizing:border-box; }
body { margin:0; background:#f4f7fb; color:var(--ink); font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
.shell { width:min(100%, 520px); min-height:100vh; margin:auto; background:white; box-shadow:0 0 24px #11224412; }
header { padding:20px 20px 16px; border-bottom:1px solid var(--line); }
.brand { display:flex; gap:10px; align-items:center; font-weight:800; letter-spacing:.01em; }
.mark { display:grid; place-items:center; width:31px; height:31px; border-radius:9px; background:var(--blue); color:white; font-size:18px; }
header p { color:var(--muted); margin:4px 0 0 41px; font-size:.9rem; }
main { padding:22px 20px 32px; }
h1 { font-size:1.5rem; line-height:1.2; margin:0 0 10px; }
h2 { font-size:1.15rem; margin:0 0 8px; }
p { margin:0 0 16px; }
.muted { color:var(--muted); }
.card { border:1px solid var(--line); border-radius:13px; padding:16px; margin:16px 0; background:#fff; }
.notice { background:var(--pale); border-left:4px solid var(--blue); border-radius:7px; padding:12px; margin:15px 0; }
.success { background:#edf9f2; border-left-color:var(--good); }
.error { background:#fff0f2; border-left-color:var(--danger); }
label { display:block; font-weight:700; margin:15px 0 6px; }
input { width:100%; min-height:48px; padding:11px 12px; border:1px solid #8998ac; border-radius:8px; color:var(--ink); font:inherit; }
input:focus, button:focus, a:focus { outline:3px solid var(--focus); outline-offset:2px; }
.otp { letter-spacing:.22em; font-size:1.2rem; text-align:center; }
button, .button-link { display:inline-flex; justify-content:center; align-items:center; min-height:48px; border:0; border-radius:8px; padding:10px 16px; background:var(--blue); color:white; font:700 1rem system-ui,sans-serif; cursor:pointer; text-decoration:none; width:100%; }
button:hover, .button-link:hover { background:var(--blue-dark); }
button.secondary { background:white; color:var(--blue); border:1px solid var(--blue); margin-top:10px; }
button.danger { background:var(--danger); }
button:disabled { opacity:.55; cursor:not-allowed; }
.actions { margin-top:22px; }
.text-link { color:var(--blue); font-weight:700; border:0; background:transparent; padding:8px 0; width:auto; min-height:auto; text-decoration:underline; }
.setup-code { word-break:break-all; letter-spacing:.1em; font:700 1.05rem ui-monospace,SFMono-Regular,monospace; color:#072b62; background:#f5f8fc; padding:13px; border-radius:8px; }
.codes { list-style:none; margin:12px 0 0; padding:0; display:grid; grid-template-columns:1fr 1fr; gap:8px; }
.codes li { padding:10px 8px; background:#f5f8fc; border-radius:6px; text-align:center; font:700 .88rem ui-monospace,SFMono-Regular,monospace; }
.log-panel { margin:24px -20px -32px; padding:16px 20px max(18px, env(safe-area-inset-bottom)); background:#13243e; color:#ecf5ff; }
.log-panel h2 { font-size:1rem; }
#logs { max-height:150px; overflow:auto; margin:0; white-space:pre-wrap; font: .78rem/1.45 ui-monospace,SFMono-Regular,monospace; }
hr { border:0; border-top:1px solid var(--line); margin:22px 0; }
.small { font-size:.88rem; }
@media (max-width:360px) { main { padding-left:16px; padding-right:16px; } .codes { grid-template-columns:1fr; } .log-panel { margin-left:-16px; margin-right:-16px; } }
</style>
</head>
<body>
<div class="shell">
<header><div class="brand"><span class="mark" aria-hidden="true">N</span><span>Northstar Bank</span></div><p>Security centre · MFA enrolment</p></header>
<main id="app" aria-live="polite"><p>Loading secure session…</p></main>
<section class="log-panel" aria-label="Browser simulation logs"><h2>Logs</h2><pre id="logs">No simulated delivery yet.</pre></section>
</div>
<script nonce="${nonce}">
(() => {
  "use strict";
  const app = document.getElementById("app");
  const logs = document.getElementById("logs");
  let csrf = "";
  let me = null;
  let setupSecret = "";
  let backupCodes = [];

  // Requirement delivery: test-only values are logged in the browser, never by the Bun server.
  function mockLog(label, value) {
    console.log("[MFA simulation] " + label, value);
    logs.textContent = "[" + new Date().toLocaleTimeString() + "] " + label + ": " +
      (Array.isArray(value) ? value.join(", ") : String(value)) + "\\n" + logs.textContent;
  }
  function message(text, type = "notice") {
    const node = document.createElement("div");
    node.className = "notice " + type;
    node.textContent = text;
    return node;
  }
  async function api(path, options = {}) {
    const headers = Object.assign({ "Content-Type": "application/json", "X-CSRF-Token": csrf }, options.headers || {});
    const response = await fetch(path, Object.assign({ credentials:"same-origin", headers }, options));
    let data;
    try { data = await response.json(); } catch { data = { ok:false, message:"We could not complete that request." }; }
    if (!response.ok || !data.ok) throw new Error(data.message || "We could not complete that request.");
    return data;
  }
  function errorHere(text) {
    const old = document.getElementById("form-message");
    if (old) old.remove();
    const node = message(text, "error"); node.id = "form-message"; app.prepend(node);
  }
  function renderSignIn() {
    app.innerHTML = \`
      <section aria-labelledby="signin-title">
        <h1 id="signin-title">Sign in to continue</h1>
        <p class="muted">Confirm your account details before setting up payment security.</p>
        <form id="signin-form" novalidate>
          <label for="email">Email address</label>
          <input id="email" name="email" type="email" autocomplete="email" inputmode="email" placeholder="marcus@example.com" required>
          <label for="phone">Mobile number</label>
          <input id="phone" name="phone" type="tel" autocomplete="tel" inputmode="tel" placeholder="+15551234567" required>
          <div class="actions"><button type="submit">Continue</button></div>
        </form>
        <p class="small muted">For this secure demo, use the account details shown in the placeholders.</p>
      </section>\`;
    document.getElementById("signin-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = new FormData(event.currentTarget);
      try {
        const data = await api("/api/auth/start", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ email:form.get("email"), phone:form.get("phone") }) });
        csrf = data.csrf;
        mockLog("Simulated identity verification code", data.testCode);
        renderIdentity();
      } catch (err) { errorHere(err.message); }
    });
  }
  function renderIdentity() {
    app.innerHTML = \`
      <section aria-labelledby="identity-title">
        <h1 id="identity-title">Verify your identity</h1>
        <p>We sent a six-digit verification code to your verified mobile number.</p>
        <div class="notice">Demo delivery is shown in the visible Logs panel and browser console.</div>
        <form id="identity-form" novalidate>
          <label for="identity-code">Verification code</label>
          <input class="otp" id="identity-code" name="code" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required>
          <div class="actions"><button type="submit">Verify identity</button></div>
        </form>
        <button class="text-link" id="back-signin" type="button">Use different details</button>
      </section>\`;
    document.getElementById("back-signin").onclick = renderSignIn;
    document.getElementById("identity-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const code = new FormData(event.currentTarget).get("code");
      try {
        const data = await api("/api/auth/verify", { method:"POST", body:JSON.stringify({ code }) });
        csrf = data.csrf; me = data.user; renderEnroll();
      } catch (err) { errorHere(err.message); }
    });
  }
  function renderEnroll() {
    app.innerHTML = \`
      <section aria-labelledby="enrol-title">
        <h1 id="enrol-title">Set up an authenticator</h1>
        <p>Use an authenticator app for an extra check before high-value payments.</p>
        <div class="card"><h2>What you need</h2><p class="muted">An authenticator app on your phone. It works even when you have no signal.</p></div>
        <form id="begin-setup"><div class="actions"><button type="submit">Set up authenticator</button></div></form>
        <button class="text-link" type="button" id="settings-link">Go to security settings</button>
      </section>\`;
    document.getElementById("settings-link").onclick = renderSettings;
    document.getElementById("begin-setup").addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        const data = await api("/api/mfa/setup", { method:"POST", body:"{}" });
        setupSecret = data.manualSecret;
        mockLog("Simulated authenticator setup secret", data.manualSecret);
        mockLog("Simulated current authenticator code", data.testOtp);
        renderProvision(data.testOtp);
      } catch (err) { errorHere(err.message); }
    });
  }
  function renderProvision(testOtp) {
    app.innerHTML = \`
      <section aria-labelledby="provision-title">
        <h1 id="provision-title">Add this account to your app</h1>
        <p>In your authenticator app, choose <strong>add account</strong> then enter this setup code manually.</p>
        <div class="card" aria-label="Authenticator provisioning representation">
          <h2>Northstar Bank · Marcus</h2>
          <p class="small muted">Setup code</p><div class="setup-code" id="manual-secret"></div>
        </div>
        <div class="notice">A test code was delivered to the Logs panel. In a real app, use the changing code from your authenticator.</div>
        <form id="otp-form" novalidate>
          <label for="otp">Six-digit authenticator code</label>
          <input class="otp" id="otp" name="otp" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required>
          <div class="actions"><button type="submit">Confirm authenticator</button></div>
        </form>
        <button class="text-link" type="button" id="cancel-setup">Cancel setup</button>
      </section>\`;
    document.getElementById("manual-secret").textContent = setupSecret;
    document.getElementById("cancel-setup").onclick = renderEnroll;
    document.getElementById("otp-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const otp = new FormData(event.currentTarget).get("otp");
      try {
        const data = await api("/api/mfa/confirm", { method:"POST", body:JSON.stringify({ otp }) });
        backupCodes = data.backupCodes;
        mockLog("Simulated backup recovery codes", backupCodes);
        renderBackupCodes();
      } catch (err) { errorHere(err.message); }
    });
  }
  function renderBackupCodes() {
    app.innerHTML = \`
      <section aria-labelledby="backup-title">
        <h1 id="backup-title">Save your recovery codes</h1>
        <div class="notice success">Your authenticator is now active.</div>
        <p>Each code works once if you lose access to your authenticator. Store them somewhere safe and private.</p>
        <ul class="codes" id="backup-list" aria-label="Recovery codes"></ul>
        <div class="actions"><button id="saved-codes" type="button">I have saved these codes</button></div>
      </section>\`;
    const list = document.getElementById("backup-list");
    backupCodes.forEach((code) => { const li = document.createElement("li"); li.textContent = code; list.appendChild(li); });
    document.getElementById("saved-codes").onclick = renderConfirmation;
  }
  function renderConfirmation() {
    backupCodes = []; setupSecret = "";
    app.innerHTML = \`
      <section aria-labelledby="complete-title">
        <h1 id="complete-title">MFA enrolment complete</h1>
        <div class="notice success">Your account is protected with an authenticator and recovery codes.</div>
        <p class="muted">You can review your security settings at any time.</p>
        <div class="actions"><button id="complete-settings" type="button">View security settings</button></div>
      </section>\`;
    document.getElementById("complete-settings").onclick = renderSettings;
  }
  async function renderSettings() {
    try {
      const data = await api("/api/mfa/settings", { method:"GET", headers:{} });
      me = data.user;
      app.innerHTML = \`
        <section aria-labelledby="settings-title">
          <h1 id="settings-title">Security settings</h1>
          <p>Signed in as <strong id="account-name"></strong></p>
          <div class="card"><h2>Authenticator</h2><p id="mfa-state" class="muted"></p></div>
          <div class="card"><h2>Recovery codes</h2><p class="muted">Use a recovery code once if you cannot use your authenticator.</p>
            <button class="secondary" id="try-recovery" type="button">Verify a recovery code</button>
            <button class="secondary" id="regenerate" type="button">Generate new recovery codes</button>
          </div>
          <button class="danger" id="logout" type="button">Sign out</button>
        </section>\`;
      document.getElementById("account-name").textContent = me.displayName;
      document.getElementById("mfa-state").textContent = data.mfaEnabled ? "Active — authenticator confirmation is required." : "Not active.";
      document.getElementById("try-recovery").onclick = renderRecovery;
      document.getElementById("regenerate").onclick = regenerate;
      document.getElementById("logout").onclick = logout;
    } catch (_) { renderSignIn(); }
  }
  function renderRecovery() {
    app.innerHTML = \`
      <section aria-labelledby="recovery-title">
        <h1 id="recovery-title">Use a recovery code</h1>
        <p>Enter one unused recovery code. It will be permanently consumed after verification.</p>
        <form id="recovery-form" novalidate>
          <label for="recovery-code">Recovery code</label>
          <input id="recovery-code" name="code" autocomplete="off" autocapitalize="characters" placeholder="ABCDE-FGHIJ" maxlength="11" required>
          <div class="actions"><button type="submit">Verify recovery code</button></div>
        </form>
        <button class="text-link" id="back-settings" type="button">Back to settings</button>
      </section>\`;
    document.getElementById("back-settings").onclick = renderSettings;
    document.getElementById("recovery-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const code = String(new FormData(event.currentTarget).get("code") || "").toUpperCase().trim();
      try {
        await api("/api/mfa/recovery/verify", { method:"POST", body:JSON.stringify({ code }) });
        app.innerHTML = \`<section><h1>Recovery code accepted</h1><div class="notice success">That recovery code has been used and cannot be used again.</div><button id="return-settings" type="button">Return to settings</button></section>\`;
        document.getElementById("return-settings").onclick = renderSettings;
      } catch (err) { errorHere(err.message); }
    });
  }
  async function regenerate() {
    if (!confirm("Generate new recovery codes? Your previous unused codes will stop working.")) return;
    try {
      const data = await api("/api/mfa/backup/regenerate", { method:"POST", body:"{}" });
      backupCodes = data.backupCodes;
      mockLog("Simulated regenerated backup recovery codes", backupCodes);
      renderBackupCodes();
    } catch (err) { errorHere(err.message); }
  }
  async function logout() {
    try { await api("/api/auth/logout", { method:"POST", body:"{}" }); } catch (_) {}
    csrf = ""; me = null; setupSecret = ""; backupCodes = []; renderSignIn();
  }
  async function boot() {
    try {
      const data = await api("/api/me", { method:"GET", headers:{} });
      csrf = data.csrf; me = data.user;
      if (data.authenticated) renderSettings(); else renderSignIn();
    } catch (_) { renderSignIn(); }
  }
  boot();
})();
</script>
</body></html>`;
}

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "OPTIONS") {
    const headers = securityHeaders(request, secureToken(16));
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return new Response(null, { status: 204, headers });
  }

  if (request.method === "GET" && path === "/") {
    const nonce = secureToken(16);
    const headers = securityHeaders(request, nonce);
    headers.set("Content-Type", "text/html; charset=utf-8");
    return new Response(page(nonce), { headers });
  }

  if (request.method === "GET" && path === "/api/me") {
    const session = authenticatedOwner(request);
    if (!session) return json(request, { ok: true, authenticated: false });
    return json(request, { ok: true, authenticated: true, csrf: session.csrf, user: { displayName: ACCOUNT.displayName } });
  }

  if (request.method === "POST" && path === "/api/auth/start") {
    const body = await readBody(request);
    if (!body || !isValidEmail(body.email) || !isValidPhone(body.phone)) return genericError(request);
    const prior = currentSession(request);
    if (prior) sessions.delete(prior.id);

    // Same generic response shape reduces account enumeration. A non-matching entry receives a non-authenticatable challenge.
    const session = newSession(false);
    session.identityCode = secureDigits();
    session.identityExpiresAt = Date.now() + VERIFY_WINDOW_MS;
    session.userId = secureEquals(String(body.email).toLowerCase(), ACCOUNT.email) && secureEquals(String(body.phone), ACCOUNT.phone)
      ? ACCOUNT.id : "unverified";
    sessions.set(session.id, session);
    return json(request, { ok: true, csrf: session.csrf, testCode: session.identityCode }, 200, sessionCookie(session.id));
  }

  if (request.method === "POST" && path === "/api/auth/verify") {
    const session = currentSession(request);
    const body = await readBody(request);
    if (!session || !body || !isValidOtp(body.code) || !hasCsrf(request, session)) return genericError(request, 400);
    const now = Date.now();
    if (session.identityLockedUntil && now < session.identityLockedUntil) return genericError(request, 429);
    const valid = !!session.identityCode && !!session.identityExpiresAt && now <= session.identityExpiresAt &&
      session.userId === ACCOUNT.id && secureEquals(String(body.code), session.identityCode);
    if (!valid) {
      session.identityAttempts++;
      if (session.identityAttempts >= MAX_FAILURES) session.identityLockedUntil = now + LOCK_MS;
      return genericError(request, session.identityLockedUntil ? 429 : 400);
    }
    // Requirement 5: rotate session ID after authentication and invalidate the pre-auth ID.
    sessions.delete(session.id);
    const authenticated = newSession(true);
    authenticated.userId = ACCOUNT.id;
    sessions.set(authenticated.id, authenticated);
    return json(request, { ok: true, csrf: authenticated.csrf, user: { displayName: ACCOUNT.displayName } }, 200, sessionCookie(authenticated.id));
  }

  if (request.method === "POST" && path === "/api/auth/logout") {
    const session = authenticatedOwner(request);
    const body = await readBody(request);
    if (!session || !body || !hasCsrf(request, session)) return genericError(request, 403);
    sessions.delete(session.id);
    pendingEnrollments.delete(ACCOUNT.id);
    return json(request, { ok: true }, 200, expiredSessionCookie());
  }

  if (request.method === "GET" && path === "/api/mfa/settings") {
    const session = authenticatedOwner(request);
    if (!session) return genericError(request, 401);
    return json(request, { ok: true, user: { displayName: ACCOUNT.displayName }, mfaEnabled: mfaRecords.has(ACCOUNT.id) });
  }

  if (request.method === "POST" && path === "/api/mfa/setup") {
    const session = authenticatedOwner(request);
    const body = await readBody(request);
    if (!session || !body || containsManipulatedIdentifier(body) || !hasCsrf(request, session)) return genericError(request, 403);
    const secret = base32Encode(crypto.getRandomValues(new Uint8Array(20)));
    pendingEnrollments.set(ACCOUNT.id, {
      encryptedSecret: await encryptSecret(secret),
      expiresAt: Date.now() + VERIFY_WINDOW_MS,
      attempts: 0,
      usedCounters: new Set(),
    });
    // Test delivery is returned only over TLS to the authenticated owner; server never logs it.
    return json(request, { ok: true, manualSecret: secret, testOtp: await totpFor(secret, Math.floor(Date.now() / 30000)) });
  }

  if (request.method === "POST" && path === "/api/mfa/confirm") {
    const session = authenticatedOwner(request);
    const body = await readBody(request);
    if (!session || !body || containsManipulatedIdentifier(body) || !isValidOtp(body.otp) || !hasCsrf(request, session)) return genericError(request, 403);
    const enrollment = pendingEnrollments.get(ACCOUNT.id);
    const now = Date.now();
    if (!enrollment || now > enrollment.expiresAt) return genericError(request, 400);
    if (enrollment.lockedUntil && now < enrollment.lockedUntil) return genericError(request, 429);
    const secret = await decryptSecret(enrollment.encryptedSecret);
    if (!(await verifyTotp(secret, String(body.otp), enrollment.usedCounters))) {
      enrollment.attempts++;
      if (enrollment.attempts >= MAX_FAILURES) enrollment.lockedUntil = now + LOCK_MS;
      return genericError(request, enrollment.lockedUntil ? 429 : 400);
    }
    const backupCodes = makeBackupCodes();
    const hashes = new Set<string>();
    for (const code of backupCodes) hashes.add(await protectedBackupValue(code));
    mfaRecords.set(ACCOUNT.id, {
      encryptedSecret: enrollment.encryptedSecret,
      enabledAt: now,
      usedCounters: enrollment.usedCounters,
      backupHashes: hashes,
      recoveryAttempts: 0,
    });
    pendingEnrollments.delete(ACCOUNT.id);
    return json(request, { ok: true, backupCodes });
  }

  if (request.method === "POST" && path === "/api/mfa/recovery/verify") {
    const session = authenticatedOwner(request);
    const body = await readBody(request);
    if (!session || !body || containsManipulatedIdentifier(body) || !isValidBackupCode(body.code) || !hasCsrf(request, session)) return genericError(request, 403);
    const record = mfaRecords.get(ACCOUNT.id);
    const now = Date.now();
    if (!record) return genericError(request, 400);
    if (record.recoveryLockedUntil && now < record.recoveryLockedUntil) return genericError(request, 429);
    const hash = await protectedBackupValue(String(body.code));
    if (!record.backupHashes.has(hash)) {
      record.recoveryAttempts++;
      if (record.recoveryAttempts >= MAX_FAILURES) record.recoveryLockedUntil = now + LOCK_MS;
      return genericError(request, record.recoveryLockedUntil ? 429 : 400);
    }
    // Requirement 5: recovery codes are single-use.
    record.backupHashes.delete(hash);
    record.recoveryAttempts = 0;
    return json(request, { ok: true });
  }

  if (request.method === "POST" && path === "/api/mfa/backup/regenerate") {
    const session = authenticatedOwner(request);
    const body = await readBody(request);
    if (!session || !body || containsManipulatedIdentifier(body) || !hasCsrf(request, session)) return genericError(request, 403);
    const record = mfaRecords.get(ACCOUNT.id);
    if (!record) return genericError(request, 400);
    const backupCodes = makeBackupCodes();
    const hashes = new Set<string>();
    for (const code of backupCodes) hashes.add(await protectedBackupValue(code));
    record.backupHashes = hashes;
    record.recoveryAttempts = 0;
    record.recoveryLockedUntil = undefined;
    return json(request, { ok: true, backupCodes });
  }

  return genericError(request, 404);
}

Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file(CERT_FILE),
    key: Bun.file(KEY_FILE),
  },
  async fetch(request) {
    try {
      return await handle(request);
    } catch {
      // Requirement 2: production error handling intentionally reveals no stack trace or secrets.
      return genericError(request, 500);
    }
  },
});

console.log(`Northstar MFA HTTPS server listening on https://localhost:${PORT}`);
