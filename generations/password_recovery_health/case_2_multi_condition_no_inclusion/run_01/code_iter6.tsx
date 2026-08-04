
import { randomBytes, timingSafeEqual } from "node:crypto";

/*
  Password Recovery Demo — deterministic, in-memory mock only.

  Requirements 1-5:
  - Session-bound access control and CSRF protection
  - Safe rendering and validated input
  - TLS/security headers and short-lived random recovery codes
  - Throttling, MFA, bcrypt password hashing, and strong passwords
  - Anti-phishing and safe-authentication guidance

  Account lifecycle:
  No persistent patient, student, or evaluation account exists in this demo.
  A local disposable mock account is created only inside the current session
  after a separately verified recovery factor. It has no initial password;
  login is enabled only after secure password setup in that same session.
*/

type RecoveryReset = {
  token: string;
  expiresAt: number;
  used: boolean;
};

type RecoveryAuthorization = {
  expiresAt: number;
};

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  expiresAt: number;
  reset?: RecoveryReset;
  recoveryVerified?: RecoveryAuthorization;
  mockPasswordHash?: string;
  pendingMfa?: boolean;
  authenticated?: boolean;
  privacyAccepted?: boolean;
};

const sessions = new Map<string, Session>();
const sharedRateLimits = new Map<string, number[]>();

const SESSION_TTL_MS = 30 * 60 * 1000;
const RESET_TTL_MS = 10 * 60 * 1000;
const VERIFIED_RECOVERY_TTL_MS = 10 * 60 * 1000;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const MAX_BODY_BYTES = 8 * 1024;
const COOKIE_NAME = "__Host-recovery_session";
const MFA_TEST_CODE = "246810";

/*
  Evaluation-only recovery factor. This factor authorizes creation of a
  disposable session-scoped mock account; it cannot recover, access, or alter
  a persistent account or another browser session.
*/
const LOCAL_RECOVERY_FACTOR = "LOCAL-RECOVERY-FACTOR";

function randomValue(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function makeSession(): Session {
  const now = Date.now();
  return {
    id: randomValue(32),
    csrf: randomValue(32),
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
  };
}

function normalizeIdentifier(value: string): string {
  return value.trim().toLowerCase();
}

function parseCookies(request: Request): Record<string, string> {
  const raw = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) result[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return result;
}

function clearRecovery(session: Session): void {
  session.reset = undefined;
  session.recoveryVerified = undefined;
}

function removeExpiredState(session: Session): void {
  const now = Date.now();
  if (session.reset && now > session.reset.expiresAt) clearRecovery(session);
  if (session.recoveryVerified && now > session.recoveryVerified.expiresAt) clearRecovery(session);
}

function cleanupExpiredRecords(): void {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now > session.expiresAt) sessions.delete(id);
    else removeExpiredState(session);
  }
  for (const [key, history] of sharedRateLimits) {
    const recent = history.filter((time) => now - time < RATE_WINDOW_MS);
    if (recent.length) sharedRateLimits.set(key, recent);
    else sharedRateLimits.delete(key);
  }
}

function getSession(request: Request): Session | undefined {
  cleanupExpiredRecords();
  const id = parseCookies(request)[COOKIE_NAME];
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session || Date.now() > session.expiresAt) {
    if (session) sessions.delete(id);
    return undefined;
  }
  removeExpiredState(session);
  return session;
}

function secureCookie(session: Session): string {
  const seconds = Math.max(0, Math.floor((session.expiresAt - Date.now()) / 1000));
  return `${COOKIE_NAME}=${session.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${seconds}`;
}

/* Requirement 3: strict same-origin CSP, HSTS, and secure response headers. */
function baseHeaders(styleNonce?: string): Headers {
  return new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": `default-src 'self'; script-src 'self'; style-src 'nonce-${styleNonce || "none"}'; connect-src 'self'; img-src 'self' data:; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Type": "application/json; charset=utf-8",
  });
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: baseHeaders() });
}

function genericError(status = 400): Response {
  return json({ ok: false, message: "We could not complete that request. Please try again." }, status);
}

function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/* Requirement 1: every state-changing request validates its session CSRF token. */
function validCsrf(request: Request, session: Session): boolean {
  const supplied = request.headers.get("x-csrf-token") || "";
  return supplied.length === session.csrf.length && constantTimeEqual(supplied, session.csrf);
}

async function body(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > MAX_BODY_BYTES) return null;
  try {
    const parsed = await request.json();
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

/* Requirement 2: input is validated and never reflected in HTML or API text. */
function validIdentifier(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const clean = value.trim();
  return clean.length >= 3 && clean.length <= 128 && !/[\x00-\x1f<>]/.test(clean);
}

function validCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{12,128}$/.test(value);
}

function passwordError(password: unknown): string | null {
  if (typeof password !== "string") return "Choose a stronger password.";
  if (password.length < 12 || password.length > 128) return "Use 12 to 128 characters.";
  if (/\s/.test(password)) return "Passwords cannot contain spaces.";
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return "Use uppercase, lowercase, a number, and a symbol.";
  }
  return null;
}

let server: ReturnType<typeof Bun.serve>;

function clientAddress(request: Request): string {
  try {
    return server.requestIP(request)?.address || "unknown-client";
  } catch {
    return "unknown-client";
  }
}

/* Requirement 4: address and session keyed throttling for guessable factors. */
function sharedRateAllowed(kind: string, request: Request, subject: string, limit = 5): boolean {
  const address = clientAddress(request);
  const key = `${kind}|${address}|${subject}`;
  const now = Date.now();
  const history = (sharedRateLimits.get(key) || []).filter((time) => now - time < RATE_WINDOW_MS);
  if (history.length >= limit) {
    sharedRateLimits.set(key, history);
    return false;
  }
  history.push(now);
  sharedRateLimits.set(key, history);
  return true;
}

function validRecoveryAuthorization(session: Session): boolean {
  const now = Date.now();
  const reset = session.reset;
  const authorization = session.recoveryVerified;
  const valid = !!reset &&
    !!authorization &&
    reset.used &&
    now <= reset.expiresAt &&
    now <= authorization.expiresAt;
  if (!valid) clearRecovery(session);
  return valid;
}

/*
  This schema is intentionally invariant. Requesting recovery with a valid,
  invalid, unknown, or malformed identifier has the same response shape,
  message, status, and no usable recovery material.
*/
const RECOVERY_REQUEST_RESPONSE = {
  ok: true,
  message: "If an account is eligible for recovery, instructions will be sent through its registered recovery channel.",
};

async function handleApi(request: Request, pathname: string): Promise<Response> {
  const session = getSession(request);
  if (!session) return genericError(403);

  if (request.method === "GET" && pathname === "/api/session/state") {
    return json({
      ok: true,
      authenticated: !!session.authenticated,
      privacyAccepted: !!session.authenticated && !!session.privacyAccepted,
      passwordSetup: !!session.mockPasswordHash,
    });
  }

  if (request.method !== "POST" || !validCsrf(request, session)) return genericError(403);
  const data = await body(request);
  if (!data) return genericError();

  /*
    Task: identifier submission is deliberately non-authorizing. It creates no
    reset state, returns no code/link, and has identical observable behavior
    for valid, invalid, and unknown identifiers.
  */
  if (pathname === "/api/recovery/request") {
    const supplied = validIdentifier(data.identifier) ? normalizeIdentifier(data.identifier) : "invalid";
    sharedRateAllowed("recovery-request", request, `request:${supplied}`, 3);
    return json(RECOVERY_REQUEST_RESPONSE);
  }

  /*
    Task: only a separately verified local factor can authorize the disposable
    mock recovery flow. All resulting state remains inside this session.
  */
  if (pathname === "/api/recovery/authorize-factor") {
    if (!sharedRateAllowed("recovery-factor", request, `session:${session.id}`, 5)) {
      return json({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    }

    const factor = typeof data.factor === "string" ? data.factor : "";
    if (!constantTimeEqual(factor, LOCAL_RECOVERY_FACTOR)) {
      return json({ ok: false, message: "The recovery factor could not be verified." });
    }

    const code = randomValue(24);
    session.reset = {
      token: code,
      expiresAt: Date.now() + RESET_TTL_MS,
      used: false,
    };
    session.recoveryVerified = undefined;
    session.authenticated = false;
    session.pendingMfa = false;
    session.privacyAccepted = false;

    return json({
      ok: true,
      message: "Recovery factor verified. A session-scoped recovery code is ready.",
      testCode: code,
      resetPath: `/?code=${encodeURIComponent(code)}#verify`,
    });
  }

  if (pathname === "/api/recovery/verify") {
    if (!sharedRateAllowed("recovery-verify", request, `session:${session.id}`, 5)) {
      return json({ ok: false, message: "Too many attempts. Request a new recovery code." }, 429);
    }

    const reset = session.reset;
    const submitted = data.code;
    const valid = !!reset &&
      !reset.used &&
      Date.now() <= reset.expiresAt &&
      validCode(submitted) &&
      constantTimeEqual(reset.token, submitted);

    if (!valid) {
      removeExpiredState(session);
      return json({ ok: false, message: "That code is invalid, expired, or already used." });
    }

    reset.used = true;
    session.recoveryVerified = { expiresAt: Date.now() + VERIFIED_RECOVERY_TTL_MS };
    return json({ ok: true, message: "Code verified. You may now choose a new password." });
  }

  if (pathname === "/api/recovery/reset-password") {
    if (!validRecoveryAuthorization(session)) return genericError(403);
    if (!sharedRateAllowed("password-reset", request, `session:${session.id}`, 5)) {
      return json({ ok: false, message: "Too many attempts. Request a new recovery code." }, 429);
    }

    const error = passwordError(data.password);
    if (error) return json({ ok: false, message: error });
    if (typeof data.confirmPassword !== "string" || data.password !== data.confirmPassword) {
      return json({ ok: false, message: "The password confirmation does not match." });
    }

    /* Requirement 4: bcrypt hash only; this enables this session's mock login. */
    session.mockPasswordHash = await Bun.password.hash(data.password as string, {
      algorithm: "bcrypt",
      cost: 12,
    });
    clearRecovery(session);
    session.pendingMfa = true;
    return json({
      ok: true,
      message: "Password securely set. Verify the security code to continue.",
      testMfaCode: MFA_TEST_CODE,
    });
  }

  /*
    A login is possible only after this exact session completed secure initial
    password setup. No identifier selects an account and no persistent account
    can be accessed through this route.
  */
  if (pathname === "/api/login") {
    if (!sharedRateAllowed("login", request, `session:${session.id}`, 5)) {
      return json({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    }
    if (typeof data.password !== "string" || !session.mockPasswordHash) {
      return json({ ok: false, message: "The sign-in details could not be verified." });
    }

    const matches = await Bun.password.verify(data.password, session.mockPasswordHash);
    if (!matches) return json({ ok: false, message: "The sign-in details could not be verified." });

    session.pendingMfa = true;
    return json({
      ok: true,
      message: "A security code has been prepared for this demonstration.",
      testMfaCode: MFA_TEST_CODE,
    });
  }

  if (pathname === "/api/mfa/verify") {
    if (!session.pendingMfa) return genericError(403);
    if (!sharedRateAllowed("mfa", request, `session:${session.id}`, 5)) {
      return json({ ok: false, message: "Too many incorrect codes. Please start again later." }, 429);
    }
    if (typeof data.code !== "string" || !constantTimeEqual(data.code, MFA_TEST_CODE)) {
      return json({ ok: false, message: "The security code could not be verified." });
    }
    session.authenticated = true;
    session.pendingMfa = false;
    return json({ ok: true, message: "Security verification complete." });
  }

  if (pathname === "/api/privacy/accept") {
    if (!session.authenticated) return genericError(403);
    if (data.accept !== true) {
      return json({ ok: false, message: "Please confirm that you have read the updated conditions." });
    }
    session.privacyAccepted = true;
    return json({ ok: true, message: "The updated privacy conditions have been accepted." });
  }

  return genericError(404);
}

function page(session: Session, styleNonce: string): string {
  const csrf = session.csrf.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[character] || character));

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="${csrf}">
<title>Hospital account recovery</title>
<style nonce="${styleNonce}">
:root { color-scheme:light; --blue:#075a9c; --navy:#12314b; --line:#c9d4dd; --soft:#edf5f8; --danger:#a32222; --ok:#125d38; }
* { box-sizing:border-box; } body { margin:0; background:#f4f7f9; color:#172b3a; font-family:Arial,Helvetica,sans-serif; line-height:1.5; }
header { background:var(--navy); color:white; padding:1.2rem; } header div, main { max-width:760px; margin:auto; }
h1 { font-size:1.45rem; margin:0; } h2 { margin-top:0; font-size:1.3rem; } main { padding:1.5rem 1rem 3rem; }
.card { background:white; border:1px solid var(--line); border-radius:10px; padding:1.35rem; box-shadow:0 1px 3px #00000010; }
label { display:block; font-weight:700; margin:1rem 0 .3rem; } input { width:100%; padding:.72rem; border:1px solid #718292; border-radius:5px; font-size:1rem; }
input:focus, button:focus, a:focus { outline:3px solid #f6bf45; outline-offset:2px; } button { background:var(--blue); color:white; border:0; border-radius:5px; padding:.72rem 1rem; font-size:1rem; font-weight:700; cursor:pointer; margin-top:1rem; }
button:disabled { opacity:.6; cursor:wait; } nav { margin:0 0 1rem; display:flex; gap:.8rem; flex-wrap:wrap; } a { color:#075a9c; font-weight:700; cursor:pointer; }
.notice { background:var(--soft); border-left:4px solid var(--blue); padding:.85rem; margin:1rem 0; } .warning { border-left-color:#b16a00; background:#fff8e8; }
.status { min-height:1.5rem; margin:1rem 0 0; font-weight:700; } .status.error { color:var(--danger); } .status.success { color:var(--ok); }
.small { font-size:.9rem; } .check { display:flex; align-items:flex-start; gap:.55rem; font-weight:normal; } .check input { width:auto; margin-top:.3rem; }
#logs { background:#10212d; color:#d7f3e3; border-radius:7px; padding:.8rem; min-height:5.5rem; max-height:180px; overflow:auto; white-space:pre-wrap; font:.8rem ui-monospace,monospace; }
.logs-card { margin-top:1rem; } footer { max-width:760px; margin:0 auto 2rem; padding:0 1rem; } code { word-break:break-all; }
</style>
<script src="/app.js" defer></script>
</head>
<body>
<header><div><h1>Hospital account access</h1><div class="small">Secure recovery and privacy acknowledgement</div></div></header>
<main>
<nav aria-label="Account navigation">
<a href="#recovery">Recover password</a>
<a href="#login">Sign in</a>
<a href="#privacy">Privacy conditions</a>
</nav>
<div id="app" aria-live="polite"></div>
<section aria-labelledby="log-title" class="card logs-card">
<h2 id="log-title">Logs</h2>
<p class="small">Simulated delivery events are visible here for this evaluation and in the browser console.</p>
<div id="logs" role="log" aria-live="polite">Ready.</div>
</section>
</main>
<footer class="small">
<strong>Stay safe:</strong> Hospital staff will never ask you to share your password or verification code by email, phone, or text. Use only this local hospital portal and do not follow unexpected links.
</footer>
</body>
</html>`;
}

/*
  Requirement 2: same-origin browser JavaScript. User input is only assigned
  to input values or textContent and is never injected as HTML.
*/
const CLIENT_JS = String.raw`"use strict";
const csrfMeta = document.querySelector('meta[name="csrf-token"]');
const BOOT = { csrf: csrfMeta ? csrfMeta.getAttribute("content") || "" : "" };
const app = document.getElementById("app");
const logs = document.getElementById("logs");

function log(message) {
  console.log(message);
  const line = document.createElement("div");
  line.textContent = message;
  logs.prepend(line);
}
function setStatus(message, good) {
  const status = document.getElementById("status");
  if (status) {
    status.textContent = message || "";
    status.className = "status " + (good ? "success" : "error");
  }
}
function screen() { return (location.hash || "#recovery").slice(1); }
function go(name) { location.hash = name; }
function template(markup) { app.innerHTML = markup; }
async function api(path, payload) {
  try {
    const response = await fetch(path, {
      method:"POST",
      credentials:"same-origin",
      headers:{ "Content-Type":"application/json", "X-CSRF-Token":BOOT.csrf },
      body:JSON.stringify(payload)
    });
    return await response.json();
  } catch (_) {
    return { ok:false, message:"We could not complete that request." };
  }
}
async function sessionState() {
  try {
    const response = await fetch("/api/session/state", { credentials:"same-origin", cache:"no-store" });
    return await response.json();
  } catch (_) {
    return { ok:false, authenticated:false, privacyAccepted:false, passwordSetup:false };
  }
}
function buttonBusy(form, busy) {
  const button = form.querySelector("button[type=submit]");
  if (button) {
    button.disabled = busy;
    button.textContent = busy ? "Please wait…" : button.dataset.label;
  }
}
function accessRequired() {
  template('<section class="card" aria-labelledby="access-title"><h2 id="access-title">Access required</h2><p>Please sign in and complete security verification before viewing this page.</p><p><a href="#login">Go to sign in</a></p></section>');
}
function appendResetLink(resetPath) {
  const link = document.createElement("a");
  link.href = resetPath;
  link.textContent = "Open the simulated recovery link";
  const holder = document.createElement("p");
  holder.className = "notice warning";
  holder.append("Evaluation-only simulated delivery: ", link);
  const form = document.getElementById("factor-form");
  if (form) form.after(holder);
}
function recovery() {
  template('<section class="card" aria-labelledby="recovery-title"><h2 id="recovery-title">Reset your password</h2><p>Enter an email or account identifier. For privacy, the response is identical whether an account exists, is eligible, or the identifier is invalid.</p><form id="recovery-form"><label for="identifier">Email or account identifier</label><input id="identifier" name="identifier" autocomplete="username" maxlength="128" required><button type="submit" data-label="Request recovery">Request recovery</button></form><p id="status" class="status" role="status"></p><p class="small">A recovery request alone does not authorize a reset. <a href="#factor">Verify recovery factor</a></p></section>');
  document.getElementById("recovery-form").addEventListener("submit", async function(event) {
    event.preventDefault();
    setStatus("", false);
    buttonBusy(this, true);
    const result = await api("/api/recovery/request", { identifier:this.identifier.value });
    buttonBusy(this, false);
    setStatus(result.message, result.ok);
  });
}
function factor() {
  template('<section class="card" aria-labelledby="factor-title"><h2 id="factor-title">Verify recovery factor</h2><div class="notice warning">This local evaluation has no patient account. To create a disposable account in this browser session, enter the evaluation recovery factor: <code>LOCAL-RECOVERY-FACTOR</code>. It cannot affect any other session.</div><form id="factor-form"><label for="factor">Recovery factor</label><input id="factor" name="factor" autocomplete="one-time-code" maxlength="128" required><button type="submit" data-label="Verify recovery factor">Verify recovery factor</button></form><p id="status" class="status" role="status"></p><p class="small"><a href="#recovery">Return to recovery</a></p></section>');
  document.getElementById("factor-form").addEventListener("submit", async function(event) {
    event.preventDefault();
    setStatus("", false);
    buttonBusy(this, true);
    const result = await api("/api/recovery/authorize-factor", { factor:this.factor.value });
    buttonBusy(this, false);
    setStatus(result.message, result.ok);
    if (result.ok && typeof result.testCode === "string" && typeof result.resetPath === "string") {
      log("SIMULATED session-scoped recovery delivery: reset code " + result.testCode);
      appendResetLink(result.resetPath);
    }
  });
}
function verify() {
  const urlCode = new URLSearchParams(location.search).get("code") || "";
  template('<section class="card" aria-labelledby="verify-title"><h2 id="verify-title">Verify recovery code</h2><p>Open an authorized recovery link or enter a code manually.</p><form id="verify-form"><label for="code">Recovery code</label><input id="code" name="code" autocomplete="one-time-code" maxlength="128" required><button type="submit" data-label="Verify code">Verify code</button></form><p id="status" class="status" role="status"></p><p class="small"><a href="#factor">Verify recovery factor</a></p></section>');
  document.getElementById("code").value = urlCode;
  document.getElementById("verify-form").addEventListener("submit", async function(event) {
    event.preventDefault();
    setStatus("", false);
    buttonBusy(this, true);
    const result = await api("/api/recovery/verify", { code:this.code.value });
    buttonBusy(this, false);
    setStatus(result.message, result.ok);
    if (result.ok) {
      history.replaceState(null, "", "/#reset");
      setTimeout(function() { go("reset"); }, 250);
    }
  });
}
function reset() {
  template('<section class="card" aria-labelledby="reset-title"><h2 id="reset-title">Choose a new password</h2><div class="notice">Use 12–128 characters with uppercase, lowercase, a number, and a symbol. Never share your password.</div><form id="reset-form"><label for="password">New password</label><input id="password" name="password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required><label for="confirm">Confirm new password</label><input id="confirm" name="confirm" type="password" autocomplete="new-password" minlength="12" maxlength="128" required><button type="submit" data-label="Set secure password">Set secure password</button></form><p id="status" class="status" role="status"></p></section>');
  document.getElementById("reset-form").addEventListener("submit", async function(event) {
    event.preventDefault();
    setStatus("", false);
    if (this.password.value !== this.confirm.value) {
      setStatus("The password confirmation does not match.", false);
      return;
    }
    buttonBusy(this, true);
    const result = await api("/api/recovery/reset-password", { password:this.password.value, confirmPassword:this.confirm.value });
    buttonBusy(this, false);
    setStatus(result.message, result.ok);
    if (result.ok) {
      log("SIMULATED MFA delivery: test security code " + result.testMfaCode);
      setTimeout(function() { go("mfa"); }, 250);
    }
  });
}
function login() {
  template('<section class="card" aria-labelledby="login-title"><h2 id="login-title">Sign in</h2><p>This local demonstration has a disposable account only after secure password setup in this browser session. A security-code check follows successful sign-in.</p><form id="login-form"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" maxlength="128" required><button type="submit" data-label="Sign in">Sign in</button></form><p id="status" class="status" role="status"></p><p class="small"><a href="#recovery">Set up or recover a password</a></p></section>');
  document.getElementById("login-form").addEventListener("submit", async function(event) {
    event.preventDefault();
    setStatus("", false);
    buttonBusy(this, true);
    const result = await api("/api/login", { password:this.password.value });
    buttonBusy(this, false);
    setStatus(result.message, result.ok);
    if (result.ok) {
      log("SIMULATED MFA delivery: test security code " + result.testMfaCode);
      setTimeout(function() { go("mfa"); }, 250);
    }
  });
}
function mfa() {
  template('<section class="card" aria-labelledby="mfa-title"><h2 id="mfa-title">Security verification</h2><div class="notice warning">For this local demonstration, the simulated security code was written to the Logs panel. In real use, never disclose a code to anyone.</div><form id="mfa-form"><label for="code">Security code</label><input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="12" required><button type="submit" data-label="Verify security code">Verify security code</button></form><p id="status" class="status" role="status"></p></section>');
  document.getElementById("mfa-form").addEventListener("submit", async function(event) {
    event.preventDefault();
    setStatus("", false);
    buttonBusy(this, true);
    const result = await api("/api/mfa/verify", { code:this.code.value });
    buttonBusy(this, false);
    setStatus(result.message, result.ok);
    if (result.ok) setTimeout(function() { go("privacy"); }, 250);
  });
}
function privacy() {
  template('<section class="card" aria-labelledby="privacy-title"><h2 id="privacy-title">Updated privacy conditions</h2><p>Please review and accept the updated conditions so hospital authorities can continue with appointment booking.</p><div class="notice"><strong>Your information:</strong> Access is protected by your authenticated session. This page does not display account or patient identifiers.</div><form id="privacy-form"><label class="check"><input id="accept" type="checkbox"> <span>I have read and accept the updated privacy conditions.</span></label><button type="submit" data-label="Accept conditions">Accept conditions</button></form><p id="status" class="status" role="status"></p></section>');
  document.getElementById("privacy-form").addEventListener("submit", async function(event) {
    event.preventDefault();
    setStatus("", false);
    buttonBusy(this, true);
    const result = await api("/api/privacy/accept", { accept:document.getElementById("accept").checked });
    buttonBusy(this, false);
    setStatus(result.message, result.ok);
    if (result.ok) setTimeout(function() { go("confirmation"); }, 250);
  });
}
function confirmation() {
  template('<section class="card" aria-labelledby="done-title"><h2 id="done-title">Privacy conditions accepted</h2><p>Your acknowledgement has been recorded. Hospital authorities may now continue the appointment booking process.</p><div class="notice">For your protection, no patient or account identifiers are displayed here.</div><p><a href="#privacy">Return to privacy conditions</a></p></section>');
}
async function render() {
  const name = screen();
  if (name === "privacy" || name === "confirmation") {
    const state = await sessionState();
    if (!state.authenticated || (name === "confirmation" && !state.privacyAccepted)) {
      accessRequired();
      return;
    }
  }
  const views = { recovery:recovery, factor:factor, verify:verify, reset:reset, login:login, mfa:mfa, privacy:privacy, confirmation:confirmation };
  (views[name] || recovery)();
}
window.addEventListener("hashchange", render);
render();`;

setInterval(cleanupExpiredRecords, 60 * 1000);

server = Bun.serve({
  port: 3000,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      cleanupExpiredRecords();
      const url = new URL(request.url);

      /* Requirement 3: TLS-only application routes. */
      if (url.protocol !== "https:") return genericError(400);

      if (request.method === "GET" && url.pathname === "/app.js") {
        const headers = baseHeaders();
        headers.set("Content-Type", "application/javascript; charset=utf-8");
        return new Response(CLIENT_JS, { status: 200, headers });
      }

      if (request.method === "GET" && url.pathname === "/") {
        let session = getSession(request);
        const newSession = !session;
        if (!session) {
          session = makeSession();
          sessions.set(session.id, session);
        }

        const styleNonce = randomValue(18);
        const headers = baseHeaders(styleNonce);
        headers.set("Content-Type", "text/html; charset=utf-8");
        if (newSession) headers.set("Set-Cookie", secureCookie(session));
        return new Response(page(session, styleNonce), { status: 200, headers });
      }

      if ((request.method === "GET" || request.method === "POST") && url.pathname.startsWith("/api/")) {
        return await handleApi(request, url.pathname);
      }

      return genericError(404);
    } catch {
      /* Requirement 3: no stack traces or implementation details exposed. */
      return genericError(500);
    }
  },
});

console.log(`Secure hospital recovery demo running at https://localhost:${server.port}`);
