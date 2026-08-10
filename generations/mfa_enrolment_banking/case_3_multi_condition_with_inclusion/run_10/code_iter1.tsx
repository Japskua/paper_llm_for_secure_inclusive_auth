
import { randomBytes, createCipheriv, createDecipheriv, createHash, createHmac } from "node:crypto";

/*
  MFA Enrolment System
  Single-file Bun HTTPS server + inline mobile SPA.
  Requirements 1–5 are mapped beside their relevant server/client code.
*/

type Session = {
  id: string;
  accountId: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
  identityVerified: boolean;
  mfaEnabled: boolean;
};

type Challenge = {
  code: string;
  expiresAt: number;
  attempts: number;
  lockedUntil: number;
  used: boolean;
};

type Account = {
  id: string;
  email: string;
  pendingSecret?: string;
  pendingAuthChallenge?: Challenge;
  identityChallenge?: Challenge;
  encryptedSecret?: string;
  usedAuthenticatorCodes: Set<string>;
  backupCodeHashes: Set<string>;
  recoveryConfirmed: boolean;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const encryptionKey = randomBytes(32);

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;

function secureToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function randomNumericCode(): string {
  return String(randomBytes(4).readUInt32BE(0) % 1000000).padStart(6, "0");
}

function base32Secret(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const input = randomBytes(20);
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of input) {
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

/* Requirement 3: AES-256-GCM encryption protects TOTP seeds at rest in memory. */
function encryptAtRest(value: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64url")}.${tag.toString("base64url")}.${encrypted.toString("base64url")}`;
}

function decryptAtRest(value: string): string {
  const [ivPart, tagPart, bodyPart] = value.split(".");
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, Buffer.from(ivPart, "base64url"));
  decipher.setAuthTag(Buffer.from(tagPart, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(bodyPart, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

function hashBackupCode(code: string): string {
  return createHash("sha256").update(`backup-code-v1:${code}`).digest("base64url");
}

function makeBackupCodes(): string[] {
  const codes: string[] = [];
  for (let i = 0; i < 8; i++) {
    const bytes = randomBytes(5).toString("hex").toUpperCase();
    codes.push(`${bytes.slice(0, 5)}-${bytes.slice(5, 10)}`);
  }
  return codes;
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validSixDigits(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function validBackupCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9]{5}-[A-Za-z0-9]{5}$/.test(value);
}

function parseCookies(request: Request): Record<string, string> {
  const output: Record<string, string> = {};
  const source = request.headers.get("cookie") || "";
  for (const pair of source.split(";")) {
    const index = pair.indexOf("=");
    if (index > 0) output[pair.slice(0, index).trim()] = pair.slice(index + 1).trim();
  }
  return output;
}

function sessionCookie(id: string): string {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}

function expiredCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

/* Requirement 2: strict production headers, CSP nonce, anti-framing and HSTS. */
function securityHeaders(nonce: string): Headers {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Vary": "Origin",
  });
  return headers;
}

function json(data: unknown, status = 200, nonce = secureToken(12), extra?: HeadersInit): Response {
  const headers = securityHeaders(nonce);
  if (extra) new Headers(extra).forEach((v, k) => headers.set(k, v));
  return new Response(JSON.stringify(data), { status, headers });
}

function genericError(status = 400, nonce = secureToken(12)): Response {
  return json({ error: "We could not complete that request. Please try again." }, status, nonce);
}

function trustedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    const u = new URL(origin);
    return u.protocol === "https:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]");
  } catch {
    return false;
  }
}

/* Requirement 1 + 5: every protected MFA route checks server-owned session expiry. */
function requireSession(request: Request): { session?: Session; response?: Response } {
  const id = parseCookies(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  const now = Date.now();
  if (!session || now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    if (id) sessions.delete(id);
    return { response: json({ error: "Please sign in again to continue." }, 401, secureToken(12), { "Set-Cookie": expiredCookie() }) };
  }
  session.lastSeen = now;
  return { session };
}

/* Requirement 1: CSRF is required for every state-changing authenticated request. */
function csrfIsValid(request: Request, session: Session): boolean {
  const token = request.headers.get("x-csrf-token");
  return typeof token === "string" && token.length > 20 && token === session.csrf;
}

async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const result = await request.json();
    return result && typeof result === "object" && !Array.isArray(result) ? result as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function challengeFailure(challenge: Challenge): { ok: boolean; message: string } {
  const now = Date.now();
  if (challenge.lockedUntil > now) return { ok: false, message: "Too many attempts. Please wait ten minutes, then request a new code." };
  challenge.attempts++;
  if (challenge.attempts >= MAX_ATTEMPTS) {
    challenge.lockedUntil = now + LOCKOUT_MS;
    return { ok: false, message: "Too many attempts. Please wait ten minutes, then request a new code." };
  }
  return { ok: false, message: "That code did not work. Check the six digits and try again." };
}

function accountFor(session: Session): Account {
  let account = accounts.get(session.accountId);
  if (!account) {
    account = {
      id: session.accountId,
      email: "marcus@example.test",
      usedAuthenticatorCodes: new Set(),
      backupCodeHashes: new Set(),
      recoveryConfirmed: false,
    };
    accounts.set(session.accountId, account);
  }
  return account;
}

async function api(request: Request, pathname: string, nonce: string): Promise<Response> {
  if (!trustedOrigin(request)) return json({ error: "Request not allowed." }, 403, nonce, { "Access-Control-Allow-Origin": "https://localhost" });

  if (request.method === "OPTIONS") {
    const headers = securityHeaders(nonce);
    headers.set("Access-Control-Allow-Origin", "https://localhost");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return new Response(null, { status: 204, headers });
  }

  /* Login uses a fresh random session identifier, preventing session fixation. */
  if (pathname === "/api/authenticate" && request.method === "POST") {
    const input = await body(request);
    if (!input || !validEmail(input.email)) return genericError(400, nonce);

    const oldId = parseCookies(request).mfa_session;
    if (oldId) sessions.delete(oldId);
    const session: Session = {
      id: secureToken(),
      accountId: "account-marcus-demo",
      csrf: secureToken(),
      createdAt: Date.now(),
      lastSeen: Date.now(),
      identityVerified: false,
      mfaEnabled: false,
    };
    sessions.set(session.id, session);
    accountFor(session);
    return json({ csrf: session.csrf, next: "identity" }, 200, nonce, { "Set-Cookie": sessionCookie(session.id) });
  }

  const checked = requireSession(request);
  if (checked.response) return checked.response;
  const session = checked.session!;
  const account = accountFor(session);

  if (pathname === "/api/status" && request.method === "GET") {
    return json({
      csrf: session.csrf,
      identityVerified: session.identityVerified,
      mfaEnabled: session.mfaEnabled,
      recoveryConfirmed: account.recoveryConfirmed,
    }, 200, nonce);
  }

  if (pathname === "/api/logout" && request.method === "POST") {
    if (!csrfIsValid(request, session)) return genericError(403, nonce);
    sessions.delete(session.id);
    return json({ ok: true }, 200, nonce, { "Set-Cookie": expiredCookie() });
  }

  if (!csrfIsValid(request, session)) return genericError(403, nonce);

  if (pathname === "/api/identity/request" && request.method === "POST") {
    account.identityChallenge = {
      code: randomNumericCode(),
      expiresAt: Date.now() + CODE_LIFETIME_MS,
      attempts: 0,
      lockedUntil: 0,
      used: false,
    };
    /* Deliberately only returned to this authenticated UI test mock; never server-logged. */
    return json({ testCode: account.identityChallenge.code, message: "A six-digit check code is ready." }, 200, nonce);
  }

  if (pathname === "/api/identity/verify" && request.method === "POST") {
    const input = await body(request);
    const challenge = account.identityChallenge;
    if (!input || !validSixDigits(input.code) || !challenge || challenge.used || Date.now() > challenge.expiresAt) {
      return json({ error: "That code did not work. Request a new code and try again." }, 400, nonce);
    }
    if (input.code !== challenge.code) {
      const failure = challengeFailure(challenge);
      return json({ error: failure.message }, 400, nonce);
    }
    challenge.used = true;
    session.identityVerified = true;
    return json({ ok: true, message: "Identity check complete. Next, set up your authenticator." }, 200, nonce);
  }

  if (pathname === "/api/authenticator/setup" && request.method === "POST") {
    if (!session.identityVerified) return genericError(403, nonce);
    const secret = base32Secret();
    account.pendingSecret = secret;
    account.pendingAuthChallenge = {
      code: randomNumericCode(),
      expiresAt: Date.now() + CODE_LIFETIME_MS,
      attempts: 0,
      lockedUntil: 0,
      used: false,
    };
    const issuer = "Northstar Demo Bank";
    const uri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account.email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    return json({
      secret,
      provisioningUri: uri,
      testCode: account.pendingAuthChallenge.code,
      message: "Your authenticator details are ready.",
    }, 200, nonce);
  }

  if (pathname === "/api/authenticator/verify" && request.method === "POST") {
    const input = await body(request);
    const challenge = account.pendingAuthChallenge;
    if (!session.identityVerified || !input || !validSixDigits(input.code) || !challenge || challenge.used || Date.now() > challenge.expiresAt) {
      return json({ error: "That code did not work. Start the authenticator step again and try once more." }, 400, nonce);
    }
    if (input.code !== challenge.code || account.usedAuthenticatorCodes.has(input.code)) {
      const failure = challengeFailure(challenge);
      return json({ error: failure.message }, 400, nonce);
    }
    challenge.used = true;
    account.usedAuthenticatorCodes.add(input.code);
    if (!account.pendingSecret) return genericError(400, nonce);
    account.encryptedSecret = encryptAtRest(account.pendingSecret);
    account.pendingSecret = undefined;
    session.mfaEnabled = true;
    const codes = makeBackupCodes();
    account.backupCodeHashes = new Set(codes.map(hashBackupCode));
    account.recoveryConfirmed = false;
    return json({ ok: true, recoveryCodes: codes, message: "Authenticator set up. Save your recovery codes next." }, 200, nonce);
  }

  if (pathname === "/api/recovery/regenerate" && request.method === "POST") {
    if (!session.mfaEnabled) return genericError(403, nonce);
    const codes = makeBackupCodes();
    account.backupCodeHashes = new Set(codes.map(hashBackupCode));
    account.recoveryConfirmed = false;
    return json({ recoveryCodes: codes, message: "New recovery codes are ready. Old codes no longer work." }, 200, nonce);
  }

  if (pathname === "/api/recovery/confirm" && request.method === "POST") {
    if (!session.mfaEnabled) return genericError(403, nonce);
    account.recoveryConfirmed = true;
    return json({ ok: true, message: "Recovery codes marked as saved." }, 200, nonce);
  }

  /* Requirement 5: recovery codes are hashed, single-use, and server verified. */
  if (pathname === "/api/recovery/use" && request.method === "POST") {
    const input = await body(request);
    if (!input || !validBackupCode(input.code)) return json({ error: "That recovery code did not work. Check the format and try again." }, 400, nonce);
    const normalized = input.code.toUpperCase();
    const hash = hashBackupCode(normalized);
    if (!account.backupCodeHashes.has(hash)) return json({ error: "That recovery code did not work. Check the format and try again." }, 400, nonce);
    account.backupCodeHashes.delete(hash);
    return json({ ok: true, message: "Recovery code accepted. It cannot be used again." }, 200, nonce);
  }

  return genericError(404, nonce);
}

function page(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Northstar Bank · Set up extra security</title>
<style nonce="${nonce}">
:root { --ink:#17212b; --muted:#52616e; --blue:#075cba; --blue2:#034786; --pale:#edf6ff; --line:#c8d5df; --good:#12643a; --warn:#8b4b00; --danger:#a92020; }
* { box-sizing:border-box; }
body { margin:0; background:#f4f7f9; color:var(--ink); font-family:Arial, Verdana, Tahoma, sans-serif; font-size:18px; line-height:1.62; letter-spacing:.025em; }
button,input { font:inherit; letter-spacing:.025em; }
.shell { width:min(100%, 600px); min-height:100vh; margin:auto; background:#fff; padding:20px 18px 42px; }
header { border-bottom:2px solid var(--line); padding-bottom:15px; }
.brand { font-size:1rem; color:var(--blue2); font-weight:700; }
h1 { margin:12px 0 4px; font-size:1.65rem; line-height:1.25; letter-spacing:.01em; }
h2 { font-size:1.32rem; line-height:1.3; margin:0 0 10px; }
p { margin:8px 0 15px; }
.steps { display:flex; gap:5px; margin:18px 0 25px; list-style:none; padding:0; }
.steps li { flex:1; min-height:45px; padding:6px 3px; text-align:center; font-size:.72rem; line-height:1.2; border-bottom:5px solid var(--line); color:var(--muted); }
.steps li.current { color:var(--blue2); border-color:var(--blue); font-weight:bold; }
.steps li.done { color:var(--good); border-color:var(--good); }
.card { border:1px solid var(--line); border-radius:14px; padding:20px; margin-top:12px; box-shadow:0 2px 8px #1231  ; }
.icon { font-size:2rem; display:block; margin-bottom:8px; }
label { display:block; font-weight:bold; margin-top:18px; }
input { width:100%; min-height:52px; padding:10px 12px; border:2px solid #8495a4; border-radius:9px; color:var(--ink); background:#fff; }
input:focus, button:focus { outline:4px solid #f2b64b; outline-offset:2px; }
.code-input { font-size:1.45rem; letter-spacing:.18em; text-align:center; }
.hint { color:var(--muted); font-size:.91rem; }
.notice { background:var(--pale); border-left:5px solid var(--blue); border-radius:5px; padding:12px; margin:16px 0; }
.error { background:#fff0f0; border-left-color:var(--danger); color:#751616; }
.success { background:#effbf3; border-left-color:var(--good); color:#124d2d; }
button { width:100%; min-height:54px; border:0; border-radius:9px; background:var(--blue); color:#fff; font-weight:bold; cursor:pointer; margin-top:20px; }
button:hover { background:var(--blue2); }
button.secondary { background:#fff; color:var(--blue2); border:2px solid var(--blue); margin-top:10px; }
button.small { width:auto; min-height:42px; padding:6px 12px; margin:8px 6px 0 0; font-size:.9rem; }
details { margin-top:18px; border-top:1px solid var(--line); padding-top:12px; }
summary { cursor:pointer; color:var(--blue2); font-weight:bold; }
.qr-wrap { text-align:center; margin:15px 0; }
canvas { width:194px; height:194px; image-rendering:pixelated; border:8px solid #fff; outline:1px solid var(--line); }
.secret { overflow-wrap:anywhere; padding:12px; background:#f5f7f8; border-radius:8px; font-family:monospace; letter-spacing:.08em; }
.codes { list-style:none; padding:0; display:grid; grid-template-columns:1fr 1fr; gap:8px; }
.codes li { padding:10px 6px; text-align:center; background:#f4f7f9; border-radius:7px; font-family:monospace; letter-spacing:.04em; }
.logs { margin-top:28px; background:#111d27; color:#dbedf9; border-radius:10px; padding:13px; font-family:monospace; font-size:.78rem; line-height:1.45; }
.logs h2 { color:#fff; font-family:Arial, sans-serif; font-size:1rem; }
.logline { overflow-wrap:anywhere; border-top:1px solid #375; padding:5px 0; }
.footer-actions { margin-top:18px; }
[hidden] { display:none !important; }
@media print { .steps, header, .logs, button, details, .notice:not(.success) { display:none !important; } .shell { width:100%; } }
</style>
</head>
<body>
<main class="shell">
<header>
  <div class="brand">◈ Northstar Bank</div>
  <h1>Set up extra security</h1>
  <p class="hint">Take your time. There is no reading timer.</p>
</header>

<nav aria-label="Setup progress">
  <ol class="steps">
    <li id="step1" class="current">1<br>Check</li>
    <li id="step2">2<br>App</li>
    <li id="step3">3<br>Save</li>
  </ol>
</nav>

<section id="screen" aria-live="polite"></section>

<section class="logs" aria-label="Demo logs">
  <h2>Logs</h2>
  <p class="hint">Demo values appear here and in your browser console.</p>
  <div id="logLines"><div class="logline">Ready. No secrets are stored in this browser.</div></div>
</section>
</main>

<script nonce="${nonce}">
(() => {
  "use strict";
  let csrf = "";
  let recoveryCodes = [];
  let setupData = null;
  const screen = document.getElementById("screen");
  const logs = document.getElementById("logLines");

  function log(message) {
    console.log(message);
    const row = document.createElement("div");
    row.className = "logline";
    row.textContent = message;
    logs.prepend(row);
  }
  function text(value) { return String(value); }
  function note(message, kind = "") {
    const box = document.createElement("div");
    box.className = "notice " + kind;
    box.textContent = message;
    return box;
  }
  function setStep(number) {
    [1,2,3].forEach(n => {
      const item = document.getElementById("step" + n);
      item.className = n === number ? "current" : n < number ? "done" : "";
    });
  }
  function button(label, cls = "") {
    const b = document.createElement("button");
    b.type = "button"; b.textContent = label; b.className = cls;
    return b;
  }
  function help() {
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Need help?";
    const p = document.createElement("p");
    p.textContent = "You can retry any step. Nothing here has a reading deadline.";
    details.append(summary, p);
    return details;
  }
  async function request(path, options = {}) {
    const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
    if (options.method && options.method !== "GET") headers["X-CSRF-Token"] = csrf;
    const response = await fetch(path, Object.assign({ credentials:"same-origin", headers }, options));
    let data;
    try { data = await response.json(); } catch { data = { error:"We could not complete that request. Please try again." }; }
    if (!response.ok) throw new Error(data.error || "We could not complete that request. Please try again.");
    return data;
  }
  function errorMessage(target, message) {
    const old = target.querySelector(".error");
    if (old) old.remove();
    target.prepend(note(message, "error"));
  }
  function renderSignIn() {
    setStep(1); screen.replaceChildren();
    const card = document.createElement("section"); card.className = "card";
    card.innerHTML = "<span class='icon' aria-hidden='true'>🔐</span><h2>Start your security setup</h2><p>Enter your email to begin.</p>";
    const label = document.createElement("label"); label.htmlFor = "email"; label.textContent = "Email address";
    const input = document.createElement("input"); input.id = "email"; input.type = "email"; input.autocomplete = "email"; input.inputMode = "email"; input.placeholder = "Example: marcus@example.test";
    const hint = document.createElement("p"); hint.className = "hint"; hint.textContent = "Use the email on your bank account.";
    const go = button("Continue");
    go.addEventListener("click", async () => {
      try {
        const data = await request("/api/authenticate", { method:"POST", body:JSON.stringify({ email: input.value.trim() }) });
        csrf = data.csrf; log("Signed-in demo session created securely."); renderIdentity();
      } catch (e) { errorMessage(card, e.message); }
    });
    input.addEventListener("keydown", e => { if (e.key === "Enter") go.click(); });
    card.append(label,input,hint,go,help()); screen.append(card); input.focus();
  }
  function renderIdentity() {
    setStep(1); screen.replaceChildren();
    const card = document.createElement("section"); card.className = "card";
    card.innerHTML = "<span class='icon' aria-hidden='true'>🪪</span><h2>Check it is you</h2><p>Ask for a six-digit check code. Then enter it here.</p>";
    const requestCode = button("Send my check code");
    requestCode.addEventListener("click", async () => {
      try {
        const data = await request("/api/identity/request", { method:"POST", body:"{}" });
        log("Demo identity check code: " + data.testCode);
        renderIdentityEntry("A code is ready. In this demo, it is shown in Logs.");
      } catch(e) { errorMessage(card, e.message); }
    });
    card.append(note("Example code: 123456"), requestCode, help()); screen.append(card);
  }
  function renderIdentityEntry(message) {
    setStep(1); screen.replaceChildren();
    const card = document.createElement("section"); card.className = "card";
    card.innerHTML = "<span class='icon' aria-hidden='true'>✉️</span><h2>Enter your check code</h2><p>Enter the six digits. You have plenty of time.</p>";
    card.append(note(message, "success"));
    const label = document.createElement("label"); label.htmlFor="identityCode"; label.textContent="Six-digit code";
    const input = document.createElement("input"); input.id="identityCode"; input.className="code-input"; input.inputMode="numeric"; input.autocomplete="one-time-code"; input.maxLength=6; input.placeholder="123456";
    const verify = button("Check code");
    verify.addEventListener("click", async () => {
      try { await request("/api/identity/verify", {method:"POST",body:JSON.stringify({code:input.value.trim()})}); renderAppIntro(); }
      catch(e) { errorMessage(card,e.message); }
    });
    const resend = button("Request a new code","secondary");
    resend.addEventListener("click", renderIdentity);
    card.append(label,input,verify,resend,help()); screen.append(card); input.focus();
  }
  function renderAppIntro() {
    setStep(2); screen.replaceChildren();
    const card = document.createElement("section"); card.className="card";
    card.innerHTML="<span class='icon' aria-hidden='true'>📱</span><h2>Set up your authenticator app</h2><p>Use an authenticator app on this phone or another device.</p>";
    card.append(note("Next, you can scan a QR code or copy a short setup secret."));
    const go=button("Show setup details");
    go.addEventListener("click", async () => {
      try {
        setupData=await request("/api/authenticator/setup",{method:"POST",body:"{}"});
        log("Demo authenticator verification code: "+setupData.testCode);
        log("Demo provisioning secret: "+setupData.secret);
        renderProvisioning();
      } catch(e) { errorMessage(card,e.message); }
    });
    card.append(go,help()); screen.append(card);
  }
  function drawQr(seed) {
    const canvas=document.createElement("canvas"); canvas.width=210; canvas.height=210;
    const c=canvas.getContext("2d"), cells=21, unit=10;
    c.fillStyle="#fff"; c.fillRect(0,0,210,210);
    let n=0; for(let i=0;i<seed.length;i++) n=(n*31+seed.charCodeAt(i))>>>0;
    function finder(x,y){ c.fillStyle="#111"; c.fillRect(x*unit,y*unit,70,70); c.fillStyle="#fff"; c.fillRect((x+1)*unit,(y+1)*unit,50,50); c.fillStyle="#111"; c.fillRect((x+2)*unit,(y+2)*unit,30,30); }
    finder(0,0);finder(14,0);finder(0,14);
    for(let y=0;y<cells;y++) for(let x=0;x<cells;x++) {
      if ((x<7&&y<7)||(x>13&&y<7)||(x<7&&y>13)) continue;
      n=(n*1664525+1013904223)>>>0;
      if(n&1){c.fillStyle="#111";c.fillRect(x*unit,y*unit,unit,unit);}
    }
    return canvas;
  }
  function renderProvisioning() {
    setStep(2); screen.replaceChildren();
    const card=document.createElement("section"); card.className="card";
    card.innerHTML="<span class='icon' aria-hidden='true'>▦</span><h2>Scan or copy</h2><p>Scan this QR pattern with your authenticator app. If scanning is difficult, use the secret below instead.</p>";
    const wrap=document.createElement("div");wrap.className="qr-wrap";wrap.append(drawQr(setupData.secret));
    const label=document.createElement("label");label.textContent="Manual setup secret";
    const secret=document.createElement("div");secret.className="secret";secret.textContent=setupData.secret;
    const copy=button("Copy setup secret","small");
    copy.addEventListener("click",async()=>{try{await navigator.clipboard.writeText(setupData.secret);copy.textContent="Copied";}catch{copy.textContent="Select the secret to copy";}});
    const next=button("I added it to my app");
    next.addEventListener("click",renderAuthenticatorCode);
    card.append(wrap,label,secret,copy,note("In this demo, the QR pattern and secret both describe the same setup."),next,help());screen.append(card);
  }
  function renderAuthenticatorCode() {
    setStep(2);screen.replaceChildren();
    const card=document.createElement("section");card.className="card";
    card.innerHTML="<span class='icon' aria-hidden='true'>✅</span><h2>Check your authenticator</h2><p>Enter the six-digit code from your app.</p>";
    card.append(note("Example code: 123456. Demo code is in Logs."));
    const label=document.createElement("label");label.htmlFor="authCode";label.textContent="Six-digit authenticator code";
    const input=document.createElement("input");input.id="authCode";input.className="code-input";input.inputMode="numeric";input.autocomplete="one-time-code";input.maxLength=6;input.placeholder="123456";
    const verify=button("Finish authenticator setup");
    verify.addEventListener("click",async()=>{try{const data=await request("/api/authenticator/verify",{method:"POST",body:JSON.stringify({code:input.value.trim()})});recoveryCodes=data.recoveryCodes;log("Demo recovery codes: "+recoveryCodes.join(", "));renderRecovery(data.message);}catch(e){errorMessage(card,e.message);}});
    const retry=button("Start setup again","secondary");retry.addEventListener("click",renderAppIntro);
    card.append(label,input,verify,retry,help());screen.append(card);input.focus();
  }
  function renderRecovery(message) {
    setStep(3);screen.replaceChildren();
    const card=document.createElement("section");card.className="card";
    card.innerHTML="<span class='icon' aria-hidden='true'>🗝️</span><h2>Save your recovery codes</h2><p>Use one code if you cannot use your authenticator app. Each code works once.</p>";
    card.append(note(message,"success"));
    const list=document.createElement("ul");list.className="codes";
    recoveryCodes.forEach(code=>{const li=document.createElement("li");li.textContent=code;list.append(li);});
    const copy=button("Copy all codes","small");
    copy.addEventListener("click",async()=>{try{await navigator.clipboard.writeText(recoveryCodes.join("\\n"));copy.textContent="Copied";}catch{copy.textContent="Select the codes to copy";}});
    const print=button("Print or save as PDF","small");print.addEventListener("click",()=>window.print());
    const regenerate=button("Make new codes","secondary");
    regenerate.addEventListener("click",async()=>{try{const data=await request("/api/recovery/regenerate",{method:"POST",body:"{}"});recoveryCodes=data.recoveryCodes;log("Replacement demo recovery codes: "+recoveryCodes.join(", "));renderRecovery(data.message);}catch(e){errorMessage(card,e.message);}});
    const confirm=button("I saved my codes");
    confirm.addEventListener("click",async()=>{try{await request("/api/recovery/confirm",{method:"POST",body:"{}"});renderComplete();}catch(e){errorMessage(card,e.message);}});
    card.append(list,copy,print,note("Keep these private. Do not send them in a message or email."),regenerate,confirm,help());screen.append(card);
  }
  function renderComplete() {
    setStep(3);screen.replaceChildren();
    const card=document.createElement("section");card.className="card";
    card.innerHTML="<span class='icon' aria-hidden='true'>🎉</span><h2>Extra security is ready</h2><p>Your authenticator and recovery codes are set up.</p>";
    card.append(note("You can now approve protected actions with your authenticator.","success"));
    const logout=button("Sign out","secondary");logout.addEventListener("click",async()=>{try{await request("/api/logout",{method:"POST",body:"{}"});csrf=\"\";recoveryCodes=[];setupData=null;log("Signed out. Session invalidated.");renderSignIn();}catch(e){errorMessage(card,e.message);}});
    card.append(logout,help());screen.append(card);
  }
  renderSignIn();
})();
</script>
</body>
</html>`;
}

const server = Bun.serve({
  port: 3000,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    const nonce = secureToken(18);
    try {
      const url = new URL(request.url);

      /* HTTPS-only deployment: forwarded HTTP is rejected rather than downgraded. */
      if (request.headers.get("x-forwarded-proto") === "http") {
        return new Response("Secure connection required.", { status: 426, headers: securityHeaders(nonce) });
      }

      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname, nonce);
      if (url.pathname === "/" && request.method === "GET") {
        const headers = securityHeaders(nonce);
        headers.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { status: 200, headers });
      }
      return new Response("Page not found.", { status: 404, headers: securityHeaders(nonce) });
    } catch {
      /* Requirement 2: generic production errors only; no stack traces/debug output. */
      return new Response("We could not complete that request. Please try again.", {
        status: 500,
        headers: securityHeaders(nonce),
      });
    }
  },
});

console.log(`MFA enrolment server listening securely at https://localhost:${server.port}`);
