
import { readFileSync } from "node:fs";
import { randomBytes, randomUUID } from "node:crypto";

/*
  Password Recovery System
  - HTTPS / secure headers: Security Misconfiguration requirements
  - Sessions, CSRF, ownership: Broken Access Control requirements
  - Escaped client rendering/CSP: Injection (XSS) requirements
  - Random reset records: reset-token requirements
  - MFA, password hashing, throttling: Authentication requirements
  - Fixed same-origin navigation only: SSRF/open-redirect requirements
  - Focused progress, pause/resume, help: ADHD inclusivity requirements
*/

type ResetRecord = {
  token: string;
  expiresAt: number;
  used: boolean;
};

type AttemptState = {
  attempts: number;
  windowStart: number;
  lockedUntil: number;
};

type Session = {
  id: string;
  csrf: string;
  reset?: ResetRecord;
  verifiedToken?: string;
  mfaSent?: boolean;
  mfaVerified?: boolean;
  attempts: Record<string, AttemptState>;
};

const sessions = new Map<string, Session>();
let storedPasswordHash = "";
const HTTPS_PORT = 3443;
const HTTP_PORT = 3000;
const RESET_LIFETIME_MS = 15 * 60 * 1000;
const LOCK_MS = 15 * 60 * 1000;
const MFA_CODE = "246810";

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function parseCookies(request: Request): Record<string, string> {
  const cookie = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const piece of cookie.split(";")) {
    const index = piece.indexOf("=");
    if (index > -1) {
      result[piece.slice(0, index).trim()] = decodeURIComponent(piece.slice(index + 1).trim());
    }
  }
  return result;
}

function newSession(): Session {
  const session: Session = {
    id: randomToken(32),
    csrf: randomToken(32),
    attempts: {},
  };
  sessions.set(session.id, session);
  return session;
}

function sessionFor(request: Request, create = false): Session | undefined {
  const sid = parseCookies(request).recovery_session;
  const existing = sid ? sessions.get(sid) : undefined;
  return existing || (create ? newSession() : undefined);
}

function secureCookie(session: Session): string {
  return `recovery_session=${encodeURIComponent(session.id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`;
}

function securityHeaders(nonce: string): Headers {
  return new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; ` +
      "connect-src 'self'; img-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; " +
      "frame-ancestors 'none'; form-action 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
  });
}

function json(data: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = securityHeaders(randomToken(16));
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) {
    for (const [key, value] of new Headers(extra)) headers.set(key, value);
  }
  return new Response(JSON.stringify(data), { status, headers });
}

function genericFailure(status = 400): Response {
  return json({ ok: false, message: "We could not complete that step. Please check the code and try again." }, status);
}

async function bodyOf(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

/* CSRF/access-control guard used by every state-changing route. */
async function protectedRequest(request: Request): Promise<{ session: Session; body: Record<string, unknown> } | Response> {
  const session = sessionFor(request);
  if (!session) return genericFailure(403);
  const csrf = request.headers.get("x-csrf-token");
  if (!csrf || csrf.length !== session.csrf.length || csrf !== session.csrf) return genericFailure(403);
  const body = await bodyOf(request);
  if (!body) return genericFailure();
  return { session, body };
}

/* Authentication rate limiting, deliberately generic and session-scoped. */
function permitted(session: Session, name: string, maxAttempts: number): boolean {
  const now = Date.now();
  let entry = session.attempts[name];
  if (!entry || now - entry.windowStart > 10 * 60 * 1000) {
    entry = { attempts: 0, windowStart: now, lockedUntil: 0 };
    session.attempts[name] = entry;
  }
  if (entry.lockedUntil > now) return false;
  return true;
}

function failedAttempt(session: Session, name: string, maxAttempts: number): void {
  const entry = session.attempts[name] || { attempts: 0, windowStart: Date.now(), lockedUntil: 0 };
  entry.attempts++;
  if (entry.attempts >= maxAttempts) {
    entry.lockedUntil = Date.now() + LOCK_MS;
    entry.attempts = 0;
  }
  session.attempts[name] = entry;
  console.log(`[security] ${name} attempt recorded; no account information logged`);
}

function clearAttempts(session: Session, name: string): void {
  delete session.attempts[name];
}

function resetIsValid(session: Session): boolean {
  const reset = session.reset;
  return !!reset &&
    !reset.used &&
    reset.expiresAt > Date.now() &&
    session.verifiedToken === reset.token;
}

function validPassword(password: string): boolean {
  return password.length >= 12 &&
    password.length <= 128 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9\s]/.test(password) &&
    !/\s/.test(password);
}

async function api(request: Request, pathname: string): Promise<Response> {
  if (pathname === "/api/session" && request.method === "GET") {
    const existing = sessionFor(request);
    const session = existing || newSession();
    const headers = new Headers();
    if (!existing) headers.set("Set-Cookie", secureCookie(session));
    return json({ ok: true, csrf: session.csrf }, 200, headers);
  }

  if (pathname === "/api/recovery/request" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session, body } = guarded;
    if (!permitted(session, "recovery-request", 5)) return genericFailure(429);

    // Contact input is intentionally discarded: no account enumeration or identifier storage.
    const contact = typeof body.contact === "string" ? body.contact.trim() : "";
    if (contact.length < 3 || contact.length > 254) return genericFailure();
    const token = randomToken(32);
    session.reset = { token, expiresAt: Date.now() + RESET_LIFETIME_MS, used: false };
    session.verifiedToken = undefined;
    session.mfaSent = false;
    session.mfaVerified = false;
    console.log("[security] simulated password-reset delivery created without logging recipient details");

    // Testing-only simulated delivery. The HTML itself never contains a reset token.
    return json({
      ok: true,
      message: "If an eligible account matches those details, a recovery message has been prepared.",
      mockDeliveryToken: token,
    });
  }

  if (pathname === "/api/reset/verify" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session, body } = guarded;
    if (!permitted(session, "reset-verify", 5)) return genericFailure(429);
    const token = typeof body.token === "string" ? body.token : "";
    const reset = session.reset;

    // Ownership is checked by requiring the token to belong to this Secure cookie session.
    if (!/^[A-Za-z0-9_-]{43}$/.test(token) || !reset || reset.used ||
      reset.expiresAt <= Date.now() || token !== reset.token) {
      failedAttempt(session, "reset-verify", 5);
      return genericFailure();
    }
    session.verifiedToken = token;
    clearAttempts(session, "reset-verify");
    console.log("[security] reset token verified for its owning session");
    return json({ ok: true, message: "Code confirmed. Next, confirm your security code." });
  }

  if (pathname === "/api/mfa/send" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session } = guarded;
    if (!resetIsValid(session)) return genericFailure(403);
    session.mfaSent = true;
    session.mfaVerified = false;
    console.log("[security] simulated MFA code delivery prepared");
    return json({
      ok: true,
      message: "A security code has been prepared for this practice session.",
      mockMfaCode: MFA_CODE,
    });
  }

  if (pathname === "/api/mfa/verify" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session, body } = guarded;
    if (!permitted(session, "mfa-verify", 5)) return genericFailure(429);
    const code = typeof body.code === "string" ? body.code : "";
    if (!resetIsValid(session) || !session.mfaSent || code !== MFA_CODE) {
      failedAttempt(session, "mfa-verify", 5);
      return genericFailure();
    }
    session.mfaVerified = true;
    clearAttempts(session, "mfa-verify");
    console.log("[security] MFA confirmed for reset-owning session");
    return json({ ok: true, message: "Security code confirmed. You can now choose a new password." });
  }

  if (pathname === "/api/password/change" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session, body } = guarded;
    const password = typeof body.password === "string" ? body.password : "";
    if (!resetIsValid(session) || !session.mfaVerified) return genericFailure(403);
    if (!validPassword(password)) {
      return json({ ok: false, message: "Use 12 or more characters with upper and lower case letters, a number, and a symbol." });
    }

    // Authentication requirement: bcrypt hash only; plaintext is never logged or retained.
    storedPasswordHash = await (Bun.password as any).hash(password, {
      algorithm: "bcrypt",
      cost: 10,
    });
    session.reset!.used = true;
    session.verifiedToken = undefined;
    session.mfaVerified = false;
    console.log("[security] password reset completed; bcrypt hash stored, no password logged");
    return json({ ok: true, message: "Your password has been changed." });
  }

  // Present for login-throttling verification; it never reveals account existence.
  if (pathname === "/api/login" && request.method === "POST") {
    const guarded = await protectedRequest(request);
    if (guarded instanceof Response) return guarded;
    const { session, body } = guarded;
    if (!permitted(session, "login", 5)) return genericFailure(429);
    const password = typeof body.password === "string" ? body.password : "";
    const valid = !!storedPasswordHash && await (Bun.password as any).verify(password, storedPasswordHash);
    if (!valid) {
      failedAttempt(session, "login", 5);
      return json({ ok: false, message: "The sign-in details could not be confirmed." }, 401);
    }
    clearAttempts(session, "login");
    console.log("[security] generic login success");
    return json({ ok: true, message: "Sign-in confirmed." });
  }

  return json({ ok: false, message: "Not found." }, 404);
}

function page(): Response {
  const nonce = randomToken(16);
  const headers = securityHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
:root { color-scheme: light; --blue:#075a9c; --ink:#172331; --soft:#eef5fa; --line:#b9cad7; --good:#086d42; --warn:#934100; }
* { box-sizing:border-box; }
body { margin:0; font:18px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; color:var(--ink); background:#f6f9fb; }
header { background:#fff; border-bottom:4px solid var(--blue); }
.wrap { width:min(760px, calc(100% - 32px)); margin:auto; }
header .wrap { padding:22px 0 18px; }
h1 { font-size:1.65rem; margin:0; } h2 { font-size:1.28rem; margin-top:0; }
.subtitle { margin:4px 0 0; color:#405367; }
main { padding:28px 0 40px; }
.progress { display:flex; list-style:none; padding:0; margin:0 0 24px; gap:6px; flex-wrap:wrap; }
.progress li { border:1px solid var(--line); border-radius:20px; padding:5px 10px; font-size:.83rem; background:#fff; }
.progress li.active { background:var(--blue); color:#fff; border-color:var(--blue); font-weight:700; }
.progress li.done { border-color:var(--good); color:var(--good); }
.card, details, .logs { background:#fff; border:1px solid var(--line); border-radius:10px; padding:22px; box-shadow:0 1px 2px #1224; }
.step[hidden] { display:none; }
p { max-width:65ch; } label { display:block; font-weight:700; margin:16px 0 5px; }
input { display:block; width:100%; max-width:520px; padding:12px; border:2px solid #71889b; border-radius:6px; font:inherit; }
input:focus, button:focus, summary:focus { outline:3px solid #f3b83f; outline-offset:3px; }
button { margin-top:18px; padding:11px 17px; border:0; border-radius:6px; background:var(--blue); color:#fff; font:inherit; font-weight:700; cursor:pointer; }
button.secondary { background:#e4edf3; color:#152a3a; margin-left:8px; } button:disabled { opacity:.6; cursor:not-allowed; }
.notice { padding:12px 14px; background:var(--soft); border-left:5px solid var(--blue); }
.status { min-height:28px; font-weight:700; color:var(--good); } .error { color:#9b250d; }
small { color:#405367; } details { margin-top:18px; } summary { font-weight:700; cursor:pointer; }
.logs { margin-top:18px; } #logList { margin:8px 0 0; padding-left:22px; font:14px/1.4 ui-monospace,monospace; max-height:150px; overflow:auto; }
footer { color:#405367; font-size:.9rem; margin-top:20px; }
@media (max-width:520px) { body { font-size:17px; } .card { padding:17px; } button.secondary { margin-left:0; } }
</style>
</head>
<body>
<header><div class="wrap"><h1>Hospital account recovery</h1><p class="subtitle">A calm, guided way to reset your password</p></div></header>
<main class="wrap">
<nav aria-label="Recovery progress"><ol class="progress" id="progress">
<li data-n="1">1. Request</li><li data-n="2">2. Recovery code</li><li data-n="3">3. Security code</li><li data-n="4">4. New password</li><li data-n="5">5. Finished</li>
</ol></nav>
<div class="notice" id="orientation">You are on step 1 of 5. You can pause at any time; your place is saved on this device.</div>

<section class="card step" data-step="1">
<h2>Request a recovery code</h2>
<p>Enter the email address or phone number you use for your hospital account. We will give the same response whether or not an account is found, to protect your privacy.</p>
<form id="requestForm" novalidate>
<label for="contact">Email address or phone number</label>
<input id="contact" name="contact" autocomplete="email" inputmode="email" maxlength="254" required>
<small>Use your own contact detail. Never enter a password here.</small><br>
<button type="submit">Request recovery code</button>
</form>
<p class="status" id="requestStatus" aria-live="polite"></p>
<button id="openLink" class="secondary" type="button" hidden>Open simulated recovery link</button>
</section>

<section class="card step" data-step="2" hidden>
<h2>Confirm your recovery code</h2>
<p>Use the recovery link from the practice delivery, or enter the code manually. The code is shown only in the browser console and the activity log for this demonstration.</p>
<form id="verifyForm" novalidate>
<label for="token">Recovery code</label>
<input id="token" name="token" autocomplete="one-time-code" spellcheck="false" maxlength="80" required>
<button type="submit">Confirm recovery code</button>
</form>
<p class="status" id="verifyStatus" aria-live="polite"></p>
</section>

<section class="card step" data-step="3" hidden>
<h2>Confirm your security code</h2>
<p>One more short check keeps your account safe. Select “Send security code”, then use the practice code from the activity log.</p>
<button id="sendMfa" type="button">Send security code</button>
<form id="mfaForm" novalidate>
<label for="mfa">Security code</label>
<input id="mfa" name="mfa" autocomplete="one-time-code" inputmode="numeric" maxlength="6" required>
<button type="submit">Confirm security code</button>
</form>
<p class="status" id="mfaStatus" aria-live="polite"></p>
</section>

<section class="card step" data-step="4" hidden>
<h2>Choose a new password</h2>
<p>Create a password with at least 12 characters, an uppercase letter, lowercase letter, number, and symbol. It is not shown or saved in this page.</p>
<form id="passwordForm" novalidate>
<label for="password">New password</label>
<input id="password" type="password" autocomplete="new-password" maxlength="128" required>
<label for="confirmPassword">Confirm new password</label>
<input id="confirmPassword" type="password" autocomplete="new-password" maxlength="128" required>
<button type="submit">Change password safely</button>
</form>
<p class="status" id="passwordStatus" aria-live="polite"></p>
</section>

<section class="card step" data-step="5" hidden>
<h2>Password changed</h2>
<p>Your recovery task is complete. You can now return to the hospital sign-in page and accept the updated privacy conditions.</p>
<button id="restart" type="button">Start another recovery</button>
</section>

<details open>
<summary>Help and safe sign-in reminders</summary>
<p>Take one step at a time. There is no countdown. If you pause, return here on this device and select the step where you stopped.</p>
<ul><li>Hospital staff will never ask you to share a password or security code.</li><li>Check that the address begins with <strong>https://localhost</strong> before entering a code.</li><li>If something does not look right, stop and contact your hospital through its known phone number.</li></ul>
</details>
<section class="logs" aria-label="Activity logs"><h2>Logs</h2><p><small>Practice delivery and security events appear here without private account details.</small></p><ul id="logList" aria-live="polite"></ul></section>
<footer>Recovery progress is saved only in this browser. There are no automatic timeouts on this page.</footer>
</main>
<script nonce="${nonce}">
(() => {
  "use strict";
  let csrf = "";
  let currentStep = Number(localStorage.getItem("recovery-step") || "1");
  let lastToken = "";
  const $ = (id) => document.getElementById(id);
  const steps = Array.from(document.querySelectorAll(".step"));
  const logList = $("logList");

  // XSS requirement: dynamic strings always use textContent, never innerHTML.
  function audit(message) {
    console.log(message);
    const li = document.createElement("li");
    li.textContent = message;
    logList.appendChild(li);
    logList.scrollTop = logList.scrollHeight;
  }
  function status(id, message, bad) {
    const element = $(id);
    element.textContent = message;
    element.className = "status" + (bad ? " error" : "");
  }
  function showStep(number) {
    currentStep = Math.max(1, Math.min(5, number));
    localStorage.setItem("recovery-step", String(currentStep));
    steps.forEach((section) => { section.hidden = Number(section.dataset.step) !== currentStep; });
    document.querySelectorAll("#progress li").forEach((item) => {
      const n = Number(item.dataset.n);
      item.classList.toggle("active", n === currentStep);
      item.classList.toggle("done", n < currentStep);
    });
    $("orientation").textContent = currentStep === 5
      ? "You have finished the recovery steps. Your new password is ready to use."
      : "You are on step " + currentStep + " of 5. You can pause at any time; your place is saved on this device.";
    const focus = document.querySelector('.step[data-step="' + currentStep + '"] h2');
    if (focus) focus.setAttribute("tabindex", "-1");
  }
  async function call(path, payload) {
    const response = await fetch(path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify(payload)
    });
    return response.json();
  }
  function passwordLooksStrong(value) {
    return value.length >= 12 && value.length <= 128 && /[a-z]/.test(value) &&
      /[A-Z]/.test(value) && /\\d/.test(value) && /[^A-Za-z0-9\\s]/.test(value) && !/\\s/.test(value);
  }

  $("requestForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const contact = $("contact").value.trim();
    if (contact.length < 3) return status("requestStatus", "Please enter an email address or phone number.", true);
    const result = await call("/api/recovery/request", { contact });
    status("requestStatus", result.message, !result.ok);
    if (result.ok) {
      lastToken = result.mockDeliveryToken;
      audit("Simulated reset delivery token (testing only): " + lastToken);
      $("openLink").hidden = false;
      showStep(2);
    }
  });
  $("openLink").addEventListener("click", () => {
    if (!lastToken) return;
    // Same-origin fixed route only; no arbitrary outgoing redirect is possible.
    location.assign("/recovery?reset=" + encodeURIComponent(lastToken));
  });
  $("verifyForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const token = $("token").value.trim();
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return status("verifyStatus", "Please enter the complete recovery code.", true);
    const result = await call("/api/reset/verify", { token });
    status("verifyStatus", result.message, !result.ok);
    if (result.ok) showStep(3);
  });
  $("sendMfa").addEventListener("click", async () => {
    const result = await call("/api/mfa/send", {});
    status("mfaStatus", result.message, !result.ok);
    if (result.ok) audit("Simulated MFA code (testing only): " + result.mockMfaCode);
  });
  $("mfaForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const code = $("mfa").value.trim();
    if (!/^\\d{6}$/.test(code)) return status("mfaStatus", "Please enter the six-digit security code.", true);
    const result = await call("/api/mfa/verify", { code });
    status("mfaStatus", result.message, !result.ok);
    if (result.ok) showStep(4);
  });
  $("passwordForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = $("password").value;
    const confirmation = $("confirmPassword").value;
    if (!passwordLooksStrong(password)) return status("passwordStatus", "Use 12 or more characters with upper and lower case letters, a number, and a symbol.", true);
    if (password !== confirmation) return status("passwordStatus", "The two passwords do not match. Please try again.", true);
    const result = await call("/api/password/change", { password });
    // Clear sensitive browser fields immediately after submission.
    $("password").value = ""; $("confirmPassword").value = "";
    status("passwordStatus", result.message, !result.ok);
    if (result.ok) { audit("Password reset completed safely."); showStep(5); }
  });
  $("restart").addEventListener("click", () => {
    localStorage.removeItem("recovery-step");
    location.assign("/");
  });

  async function start() {
    const sessionResponse = await fetch("/api/session", { credentials: "same-origin", cache: "no-store" });
    const session = await sessionResponse.json();
    csrf = session.csrf;
    const fromLink = new URLSearchParams(location.search).get("reset");
    showStep(currentStep);
    if (fromLink) {
      $("token").value = fromLink;
      showStep(2);
      audit("Recovery link opened. Confirming its code for this browser session.");
      const result = await call("/api/reset/verify", { token: fromLink });
      status("verifyStatus", result.message, !result.ok);
      if (result.ok) showStep(3);
      history.replaceState({}, "", "/recovery");
    }
  }
  start().catch(() => audit("The secure recovery service is temporarily unavailable. Please try again."));
})();
</script>
</body></html>`, { headers });
}

async function handleHttps(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/recovery")) return page();
    return json({ ok: false, message: "Not found." }, 404);
  } catch {
    // No debugging details or stack traces are exposed to clients.
    return json({ ok: false, message: "The service could not complete that request." }, 500);
  }
}

// HTTPS requirement: mkcert files are deliberately loaded from the prescribed paths.
const cert = readFileSync("certs/cert.pem", "utf8");
const key = readFileSync("certs/key.pem", "utf8");

Bun.serve({
  port: HTTPS_PORT,
  tls: { cert, key },
  fetch: handleHttps,
});

// Plain HTTP has no application routes and always performs a fixed HTTPS redirect.
Bun.serve({
  port: HTTP_PORT,
  fetch(request) {
    const incoming = new URL(request.url);
    const location = `https://localhost:${HTTPS_PORT}${incoming.pathname}${incoming.search}`;
    return new Response(null, {
      status: 308,
      headers: {
        Location: location,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  },
});

console.log(`Secure recovery service running at https://localhost:${HTTPS_PORT}`);
console.log(`HTTP redirects to HTTPS at http://localhost:${HTTP_PORT}`);
