
import { randomBytes, timingSafeEqual } from "node:crypto";

/*
  Password Recovery Demo — all data below is an internal, deterministic in-memory mock.
  Security requirements:
  1) session-bound access control + CSRF
  2) validation and safe client-side text rendering
  3) TLS, headers, random short-lived reset tokens
  4) strong passwords, throttling, mocked MFA
  5) internal-only navigation and anti-phishing guidance
*/

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  recoveryRequests: number[];
  resetAttempts: number[];
  mfaAttempts: number[];
  loginAttempts: number[];
  reset?: { token: string; expiresAt: number; used: boolean; accountId: string };
  recoveryVerified?: boolean;
  pendingMfaAccount?: string;
  authenticatedAccount?: string;
  privacyAccepted?: boolean;
};

type Account = {
  id: string;
  passwordHash: string;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();

// Requirement 4: password storage uses bcrypt, never plaintext.
accounts.set("internal-demo-account", {
  id: "internal-demo-account",
  passwordHash: await Bun.password.hash("Initial!Secure2025", { algorithm: "bcrypt" }),
});

const COOKIE_NAME = "__Host-recovery_session";
const MFA_TEST_CODE = "246810";
const RESET_TTL_MS = 10 * 60 * 1000;
const MAX_BODY_BYTES = 8 * 1024;

function randomValue(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function makeSession(): Session {
  return {
    id: randomValue(32),
    csrf: randomValue(32),
    createdAt: Date.now(),
    recoveryRequests: [],
    resetAttempts: [],
    mfaAttempts: [],
    loginAttempts: [],
  };
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

function getSession(request: Request): Session | undefined {
  const id = parseCookies(request)[COOKIE_NAME];
  return id ? sessions.get(id) : undefined;
}

function secureCookie(session: Session): string {
  return `${COOKIE_NAME}=${session.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=1800`;
}

function baseHeaders(nonce?: string): Headers {
  const headers = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce || "none"}'; style-src 'nonce-${nonce || "none"}'; connect-src 'self'; img-src 'self' data:; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Type": "application/json; charset=utf-8",
  });
  return headers;
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

function validCsrf(request: Request, session: Session): boolean {
  const supplied = request.headers.get("x-csrf-token") || "";
  return supplied.length === session.csrf.length && constantTimeEqual(supplied, session.csrf);
}

function withinLimit(history: number[], limit: number, windowMs: number): boolean {
  const now = Date.now();
  const recent = history.filter((time) => now - time < windowMs);
  history.splice(0, history.length, ...recent);
  if (history.length >= limit) return false;
  history.push(now);
  return true;
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

// Requirement 2: validate input without reflecting it back to any response.
function validIdentifier(value: unknown): boolean {
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

async function handleApi(request: Request, pathname: string): Promise<Response> {
  const session = getSession(request);
  if (!session) return genericError(403);
  if (!validCsrf(request, session)) return genericError(403);

  const data = await body(request);
  if (!data) return genericError();

  if (pathname === "/api/recovery/request") {
    // Requirements 1, 3, 4: generic outcome, rate limiting, random session-bound token.
    if (!validIdentifier(data.identifier)) return json({ ok: false, message: "Enter a valid email or account identifier." });
    if (!withinLimit(session.recoveryRequests, 3, 15 * 60 * 1000)) {
      return json({ ok: false, message: "Please wait before requesting another recovery message." }, 429);
    }

    const code = randomValue(24);
    session.reset = {
      token: code,
      expiresAt: Date.now() + RESET_TTL_MS,
      used: false,
      accountId: "internal-demo-account",
    };
    session.recoveryVerified = false;

    // Delivery is intentionally NOT logged on the server. Browser logs the test-only mock.
    return json({
      ok: true,
      message: "If the account can be recovered, recovery instructions have been prepared.",
      testCode: code,
      resetPath: `/?code=${encodeURIComponent(code)}#verify`,
    });
  }

  if (pathname === "/api/recovery/verify") {
    // Requirements 1, 3, 4: token is session-bound, expires, is one-use, and attempts are limited.
    if (!withinLimit(session.resetAttempts, 5, 15 * 60 * 1000)) {
      return json({ ok: false, message: "Too many attempts. Request a new recovery code." }, 429);
    }
    const reset = session.reset;
    const submitted = data.code;
    const valid = reset &&
      !reset.used &&
      Date.now() <= reset.expiresAt &&
      validCode(submitted) &&
      constantTimeEqual(reset.token, submitted);

    if (!valid) return json({ ok: false, message: "That code is invalid, expired, or already used." });

    reset.used = true;
    session.recoveryVerified = true;
    return json({ ok: true, message: "Code verified. You may now choose a new password." });
  }

  if (pathname === "/api/recovery/reset-password") {
    if (!session.recoveryVerified || !session.reset) return genericError(403);
    const error = passwordError(data.password);
    if (error) return json({ ok: false, message: error });
    if (typeof data.confirmPassword !== "string" || data.password !== data.confirmPassword) {
      return json({ ok: false, message: "The password confirmation does not match." });
    }

    const account = accounts.get(session.reset.accountId);
    if (!account) return genericError();
    account.passwordHash = await Bun.password.hash(data.password as string, { algorithm: "bcrypt" });
    session.recoveryVerified = false;
    session.pendingMfaAccount = account.id;
    return json({
      ok: true,
      message: "Password updated. Verify the security code to continue.",
      testMfaCode: MFA_TEST_CODE,
    });
  }

  if (pathname === "/api/login") {
    // Requirement 4: login throttle. Identifier is deliberately never used in response text.
    if (!withinLimit(session.loginAttempts, 5, 15 * 60 * 1000)) {
      return json({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    }
    if (!validIdentifier(data.identifier) || typeof data.password !== "string") {
      return json({ ok: false, message: "The sign-in details could not be verified." });
    }
    const account = accounts.get("internal-demo-account")!;
    const matches = await Bun.password.verify(data.password, account.passwordHash);
    if (!matches) return json({ ok: false, message: "The sign-in details could not be verified." });

    session.pendingMfaAccount = account.id;
    return json({
      ok: true,
      message: "A security code has been prepared for this demonstration.",
      testMfaCode: MFA_TEST_CODE,
    });
  }

  if (pathname === "/api/mfa/verify") {
    if (!session.pendingMfaAccount) return genericError(403);
    if (!withinLimit(session.mfaAttempts, 5, 15 * 60 * 1000)) {
      return json({ ok: false, message: "Too many incorrect codes. Please start again later." }, 429);
    }
    if (typeof data.code !== "string" || !constantTimeEqual(data.code, MFA_TEST_CODE)) {
      return json({ ok: false, message: "The security code could not be verified." });
    }
    session.authenticatedAccount = session.pendingMfaAccount;
    session.pendingMfaAccount = undefined;
    return json({ ok: true, message: "Security verification complete." });
  }

  if (pathname === "/api/privacy/accept") {
    // Requirement 1: account is derived exclusively from authenticated session, never a request ID.
    if (!session.authenticatedAccount || !accounts.has(session.authenticatedAccount)) return genericError(403);
    if (data.accept !== true) return json({ ok: false, message: "Please confirm that you have read the updated conditions." });
    session.privacyAccepted = true;
    return json({ ok: true, message: "The updated privacy conditions have been accepted." });
  }

  return genericError(404);
}

function page(session: Session, nonce: string): string {
  const boot = JSON.stringify({ csrf: session.csrf }).replace(/</g, "\\u003c");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
:root { color-scheme: light; --blue:#075a9c; --navy:#12314b; --line:#c9d4dd; --soft:#edf5f8; --danger:#a32222; --ok:#125d38; }
* { box-sizing:border-box; } body { margin:0; background:#f4f7f9; color:#172b3a; font-family:Arial,Helvetica,sans-serif; line-height:1.5; }
header { background:var(--navy); color:white; padding:1.2rem; } header div, main { max-width:760px; margin:auto; }
h1 { font-size:1.45rem; margin:0; } h2 { margin-top:0; font-size:1.3rem; } main { padding:1.5rem 1rem 3rem; }
.card { background:white; border:1px solid var(--line); border-radius:10px; padding:1.35rem; box-shadow:0 1px 3px #00000010; }
label { display:block; font-weight:700; margin:1rem 0 .3rem; } input { width:100%; padding:.72rem; border:1px solid #718292; border-radius:5px; font-size:1rem; }
input:focus, button:focus, a:focus { outline:3px solid #f6bf45; outline-offset:2px; } button { background:var(--blue); color:white; border:0; border-radius:5px; padding:.72rem 1rem; font-size:1rem; font-weight:700; cursor:pointer; margin-top:1rem; }
button.secondary { background:#e7eef2; color:#17354d; } button:disabled { opacity:.6; cursor:wait; }
nav { margin:0 0 1rem; display:flex; gap:.8rem; flex-wrap:wrap; } a { color:#075a9c; font-weight:700; cursor:pointer; }
.notice { background:var(--soft); border-left:4px solid var(--blue); padding:.85rem; margin:1rem 0; } .warning { border-left-color:#b16a00; background:#fff8e8; }
.status { min-height:1.5rem; margin:1rem 0 0; font-weight:700; } .status.error { color:var(--danger); } .status.success { color:var(--ok); }
.small { font-size:.9rem; } .hidden { display:none; } .check { display:flex; align-items:flex-start; gap:.55rem; font-weight:normal; } .check input { width:auto; margin-top:.3rem; }
#logs { background:#10212d; color:#d7f3e3; border-radius:7px; padding:.8rem; min-height:5.5rem; max-height:180px; overflow:auto; white-space:pre-wrap; font: .8rem ui-monospace,monospace; }
footer { max-width:760px; margin:0 auto 2rem; padding:0 1rem; } code { word-break:break-all; }
</style>
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
<section aria-labelledby="log-title" class="card" style="margin-top:1rem">
<h2 id="log-title">Logs</h2>
<p class="small">Simulated delivery events are visible here for this evaluation and in the browser console.</p>
<div id="logs" role="log" aria-live="polite">Ready.</div>
</section>
</main>
<footer class="small">
<strong>Stay safe:</strong> Hospital staff will never ask you to share your password or verification code by email, phone, or text. Use only this local hospital portal and do not follow unexpected links.
</footer>
<script nonce="${nonce}">
"use strict";
/* Client controls for requirements 2 and 5: static templates only; user values are never injected as HTML. */
const BOOT = ${boot};
const app = document.getElementById("app");
const logs = document.getElementById("logs");
let pendingResetPath = "";

function log(message) {
  console.log(message);
  const line = document.createElement("div");
  line.textContent = message;
  logs.prepend(line);
}
function setStatus(message, good) {
  const status = document.getElementById("status");
  if (status) { status.textContent = message || ""; status.className = "status " + (good ? "success" : "error"); }
}
function screen() { return (location.hash || "#recovery").slice(1); }
function go(name) { location.hash = name; }
function template(markup) { app.innerHTML = markup; }
async function api(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type":"application/json", "X-CSRF-Token": BOOT.csrf },
    body: JSON.stringify(payload)
  });
  try { return await response.json(); } catch (_) { return { ok:false, message:"We could not complete that request." }; }
}
function buttonBusy(form, busy) {
  const button = form.querySelector("button[type=submit]");
  if (button) { button.disabled = busy; button.textContent = busy ? "Please wait…" : button.dataset.label; }
}
function recovery() {
  template('<section class="card" aria-labelledby="recovery-title"><h2 id="recovery-title">Reset your password</h2><p>Enter your email or account identifier. For privacy, we give the same response whether or not an account is available.</p><form id="recovery-form"><label for="identifier">Email or account identifier</label><input id="identifier" name="identifier" autocomplete="username" maxlength="128" required><button type="submit" data-label="Prepare recovery">Prepare recovery</button></form><p id="status" class="status" role="status"></p><p class="small"><a href="#verify">I already have a recovery code</a></p></section>');
  document.getElementById("recovery-form").addEventListener("submit", async function(event) {
    event.preventDefault(); setStatus("", false); buttonBusy(this, true);
    const result = await api("/api/recovery/request", { identifier: this.identifier.value });
    buttonBusy(this, false); setStatus(result.message, result.ok);
    if (result.ok) {
      pendingResetPath = result.resetPath;
      log("SIMULATED recovery delivery: test reset code " + result.testCode);
      const link = document.createElement("a");
      link.href = result.resetPath;
      link.textContent = "Open the simulated recovery link";
      const holder = document.createElement("p");
      holder.append("Evaluation-only test link: ", link);
      document.getElementById("recovery-form").after(holder);
    }
  });
}
function verify() {
  const urlCode = new URLSearchParams(location.search).get("code") || "";
  template('<section class="card" aria-labelledby="verify-title"><h2 id="verify-title">Verify recovery code</h2><p>Open your recovery link or enter the code manually.</p><form id="verify-form"><label for="code">Recovery code</label><input id="code" name="code" autocomplete="one-time-code" maxlength="128" required><button type="submit" data-label="Verify code">Verify code</button></form><p id="status" class="status" role="status"></p><p class="small"><a href="#recovery">Request a new code</a></p></section>');
  document.getElementById("code").value = urlCode;
  document.getElementById("verify-form").addEventListener("submit", async function(event) {
    event.preventDefault(); setStatus("", false); buttonBusy(this, true);
    const result = await api("/api/recovery/verify", { code: this.code.value });
    buttonBusy(this, false); setStatus(result.message, result.ok);
    if (result.ok) { history.replaceState(null, "", "/#reset"); setTimeout(function(){ go("reset"); }, 250); }
  });
}
function reset() {
  template('<section class="card" aria-labelledby="reset-title"><h2 id="reset-title">Choose a new password</h2><div class="notice">Use 12–128 characters with uppercase, lowercase, a number, and a symbol. Never share your password.</div><form id="reset-form"><label for="password">New password</label><input id="password" name="password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required><label for="confirm">Confirm new password</label><input id="confirm" name="confirm" type="password" autocomplete="new-password" minlength="12" maxlength="128" required><button type="submit" data-label="Update password">Update password</button></form><p id="status" class="status" role="status"></p></section>');
  document.getElementById("reset-form").addEventListener("submit", async function(event) {
    event.preventDefault(); setStatus("", false);
    if (this.password.value !== this.confirm.value) { setStatus("The password confirmation does not match.", false); return; }
    buttonBusy(this, true);
    const result = await api("/api/recovery/reset-password", { password:this.password.value, confirmPassword:this.confirm.value });
    buttonBusy(this, false); setStatus(result.message, result.ok);
    if (result.ok) { log("SIMULATED MFA delivery: test security code " + result.testMfaCode); setTimeout(function(){ go("mfa"); }, 250); }
  });
}
function login() {
  template('<section class="card" aria-labelledby="login-title"><h2 id="login-title">Sign in</h2><p>Use your account identifier and password. A security-code check follows successful sign-in.</p><form id="login-form"><label for="identifier">Email or account identifier</label><input id="identifier" name="identifier" autocomplete="username" maxlength="128" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" maxlength="128" required><button type="submit" data-label="Sign in">Sign in</button></form><p id="status" class="status" role="status"></p><p class="small"><a href="#recovery">Forgot your password?</a></p></section>');
  document.getElementById("login-form").addEventListener("submit", async function(event) {
    event.preventDefault(); setStatus("", false); buttonBusy(this, true);
    const result = await api("/api/login", { identifier:this.identifier.value, password:this.password.value });
    buttonBusy(this, false); setStatus(result.message, result.ok);
    if (result.ok) { log("SIMULATED MFA delivery: test security code " + result.testMfaCode); setTimeout(function(){ go("mfa"); }, 250); }
  });
}
function mfa() {
  template('<section class="card" aria-labelledby="mfa-title"><h2 id="mfa-title">Security verification</h2><div class="notice warning">For this local demonstration, the simulated security code was written to the Logs panel. In real use, never disclose a code to anyone.</div><form id="mfa-form"><label for="code">Security code</label><input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="12" required><button type="submit" data-label="Verify security code">Verify security code</button></form><p id="status" class="status" role="status"></p></section>');
  document.getElementById("mfa-form").addEventListener("submit", async function(event) {
    event.preventDefault(); setStatus("", false); buttonBusy(this, true);
    const result = await api("/api/mfa/verify", { code:this.code.value });
    buttonBusy(this, false); setStatus(result.message, result.ok);
    if (result.ok) setTimeout(function(){ go("privacy"); }, 250);
  });
}
function privacy() {
  template('<section class="card" aria-labelledby="privacy-title"><h2 id="privacy-title">Updated privacy conditions</h2><p>Please review and accept the updated conditions so hospital authorities can continue with appointment booking.</p><div class="notice"><strong>Your information:</strong> Access is protected by your authenticated session. This page does not display account or patient identifiers.</div><form id="privacy-form"><label class="check"><input id="accept" type="checkbox"> <span>I have read and accept the updated privacy conditions.</span></label><button type="submit" data-label="Accept conditions">Accept conditions</button></form><p id="status" class="status" role="status"></p></section>');
  document.getElementById("privacy-form").addEventListener("submit", async function(event) {
    event.preventDefault(); setStatus("", false); buttonBusy(this, true);
    const result = await api("/api/privacy/accept", { accept:document.getElementById("accept").checked });
    buttonBusy(this, false); setStatus(result.message, result.ok);
    if (result.ok) setTimeout(function(){ go("confirmation"); }, 250);
  });
}
function confirmation() {
  template('<section class="card" aria-labelledby="done-title"><h2 id="done-title">Privacy conditions accepted</h2><p>Your acknowledgement has been recorded. Hospital authorities may now continue the appointment booking process.</p><div class="notice">For your protection, no patient or account identifiers are displayed here.</div><p><a href="#privacy">Return to privacy conditions</a></p></section>');
}
function render() {
  const views = { recovery:recovery, verify:verify, reset:reset, login:login, mfa:mfa, privacy:privacy, confirmation:confirmation };
  (views[screen()] || recovery)();
}
window.addEventListener("hashchange", render);
render();
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
    try {
      const url = new URL(request.url);

      // Requirement 3: this listener is TLS-only; non-HTTPS traffic cannot reach application routes.
      if (url.protocol !== "https:") return genericError(400);

      if (request.method === "GET" && url.pathname === "/") {
        let session = getSession(request);
        const newSession = !session;
        if (!session) {
          session = makeSession();
          sessions.set(session.id, session);
        }

        const nonce = randomValue(18);
        const headers = baseHeaders(nonce);
        headers.set("Content-Type", "text/html; charset=utf-8");
        if (newSession) headers.set("Set-Cookie", secureCookie(session));
        return new Response(page(session, nonce), { status: 200, headers });
      }

      if (request.method === "POST" && url.pathname.startsWith("/api/")) {
        return await handleApi(request, url.pathname);
      }

      return genericError(404);
    } catch {
      // Requirement 3: no debug data, stack traces, listings, or implementation details.
      return genericError(500);
    }
  },
});

console.log(`Secure hospital recovery demo running at https://localhost:${server.port}`);
