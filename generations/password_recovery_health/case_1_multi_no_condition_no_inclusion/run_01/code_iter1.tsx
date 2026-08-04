
import { existsSync } from "node:fs";

// Security Requirements 3: HTTPS-only server configuration, HSTS, restrictive CSP, and secure headers.
const HTTPS_PORT = Number(Bun.env.HTTPS_PORT || 3000);
const HTTP_PORT = Number(Bun.env.HTTP_PORT || 3001);
const CERT_FILE = "certs/cert.pem";
const KEY_FILE = "certs/key.pem";

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  authenticated: boolean;
  mfaPending: boolean;
  mfaVerified: boolean;
  privacyAccepted: boolean;
  loginFailures: number[];
  resetFailures: number[];
  lockedUntil: number;
};

type ResetRecord = {
  sessionId: string;
  token: string;
  code: string;
  expiresAt: number;
  used: boolean;
};

const sessions = new Map<string, Session>();
const resetRecords = new Map<string, ResetRecord>();
const RESET_TTL_MS = 10 * 60 * 1000;
const SESSION_TTL_SECONDS = 60 * 30;
const LOCK_MS = 10 * 60 * 1000;
const RATE_WINDOW_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const MFA_TEST_CODE = "246810";

// Security Requirement 4: Password is stored only as a Bun bcrypt hash, never plaintext.
const account = {
  passwordHash: "",
};

const passwordReady = Bun.password.hash("Helena!Secure2025", {
  algorithm: "bcrypt",
  cost: 10,
}).then((hash) => {
  account.passwordHash = hash;
});

function randomSecret(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
}

function randomCode(): string {
  const values = new Uint32Array(1);
  crypto.getRandomValues(values);
  return String(100000 + (values[0] % 900000));
}

function parseCookies(request: Request): Record<string, string> {
  const cookie = request.headers.get("cookie") || "";
  const output: Record<string, string> = {};
  for (const part of cookie.split(";")) {
    const divider = part.indexOf("=");
    if (divider > 0) {
      const key = part.slice(0, divider).trim();
      const value = part.slice(divider + 1).trim();
      if (/^[A-Za-z0-9_-]{1,128}$/.test(key) && /^[A-Za-z0-9_-]{1,256}$/.test(value)) {
        output[key] = value;
      }
    }
  }
  return output;
}

function getSession(request: Request): Session | undefined {
  const id = parseCookies(request).sid;
  if (!id) return undefined;
  return sessions.get(id);
}

function sessionCookie(session: Session): string {
  return `sid=${session.id}; Path=/; Max-Age=${SESSION_TTL_SECONDS}; Secure; HttpOnly; SameSite=Strict`;
}

function createSession(): Session {
  const session: Session = {
    id: randomSecret(32),
    csrf: randomSecret(32),
    createdAt: Date.now(),
    authenticated: false,
    mfaPending: false,
    mfaVerified: false,
    privacyAccepted: false,
    loginFailures: [],
    resetFailures: [],
    lockedUntil: 0,
  };
  sessions.set(session.id, session);
  return session;
}

function baseHeaders(nonce?: string): Headers {
  const headers = new Headers();
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  headers.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  headers.set("Pragma", "no-cache");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set(
    "Content-Security-Policy",
    nonce
      ? `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  );
  return headers;
}

function json(data: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = baseHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) {
    for (const [key, value] of new Headers(extra)) headers.set(key, value);
  }
  return new Response(JSON.stringify(data), { status, headers });
}

function errorResponse(message = "Request could not be completed.", status = 400): Response {
  return json({ ok: false, message }, status);
}

function originIsAllowed(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    const url = new URL(origin);
    if (url.protocol !== "https:") return false;
    const allowedHost = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
    return allowedHost && (url.port === String(HTTPS_PORT) || (HTTPS_PORT === 443 && url.port === ""));
  } catch {
    return false;
  }
}

// Security Requirement 1: every state-changing API call must have a same-origin request and per-session CSRF token.
function requireCsrf(request: Request): { session?: Session; response?: Response } {
  const session = getSession(request);
  const token = request.headers.get("x-csrf-token") || "";
  if (!session || !originIsAllowed(request) || token.length !== session.csrf.length || token !== session.csrf) {
    return { response: errorResponse("Your secure session could not be verified. Refresh and try again.", 403) };
  }
  return { session };
}

async function readObject(request: Request): Promise<Record<string, unknown> | undefined> {
  const type = request.headers.get("content-type") || "";
  if (!type.toLowerCase().startsWith("application/json")) return undefined;
  const body = await request.text();
  if (body.length > 2048) return undefined;
  try {
    const value = JSON.parse(body);
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" &&
    value.length <= 254 &&
    /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(value);
}

function validSecret(value: unknown, max = 128): value is string {
  return typeof value === "string" && value.length >= 6 && value.length <= max && /^[A-Za-z0-9]+$/.test(value);
}

function recordFailure(session: Session, kind: "loginFailures" | "resetFailures"): boolean {
  const now = Date.now();
  session[kind] = session[kind].filter((time) => now - time < RATE_WINDOW_MS);
  session[kind].push(now);
  if (session[kind].length >= MAX_ATTEMPTS) {
    session.lockedUntil = now + LOCK_MS;
    return true;
  }
  return false;
}

function isLocked(session: Session): boolean {
  return session.lockedUntil > Date.now();
}

function validStrongPassword(password: unknown): password is string {
  return typeof password === "string" &&
    password.length >= 12 &&
    password.length <= 128 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9]/.test(password);
}

async function api(request: Request, pathname: string): Promise<Response> {
  if (request.method === "GET" && pathname === "/api/session") {
    let session = getSession(request);
    let newSession = false;
    if (!session) {
      session = createSession();
      newSession = true;
    }
    const headers = new Headers();
    if (newSession) headers.set("Set-Cookie", sessionCookie(session));
    return json({ ok: true, csrf: session.csrf }, 200, headers);
  }

  if (request.method !== "POST") return errorResponse("Not found.", 404);
  const protectedRequest = requireCsrf(request);
  if (protectedRequest.response) return protectedRequest.response;
  const session = protectedRequest.session!;
  const body = await readObject(request);
  if (!body) return errorResponse("Invalid request format.");

  if (pathname === "/api/recovery") {
    // Security Requirements 1 and 4: no account lookup result is disclosed (anti-enumeration).
    if (isLocked(session)) return errorResponse("Too many attempts. Please wait before trying again.", 429);
    const contactIsValid = validEmail(body.contact);
    if (!contactIsValid) {
      recordFailure(session, "resetFailures");
      return json({ ok: true, message: "If an eligible account exists, recovery instructions have been prepared." });
    }

    const token = randomSecret(32);
    const code = randomCode();
    resetRecords.set(token, {
      sessionId: session.id,
      token,
      code,
      expiresAt: Date.now() + RESET_TTL_MS,
      used: false,
    });

    // Required mock delivery value: returned only to the requesting browser; never server logged or rendered.
    return json({
      ok: true,
      message: "If an eligible account exists, recovery instructions have been prepared.",
      mockRecoveryToken: token,
      mockRecoveryCode: code,
    });
  }

  if (pathname === "/api/reset/verify") {
    if (isLocked(session)) return errorResponse("Too many attempts. Please wait before trying again.", 429);
    const token = validSecret(body.token, 128) ? body.token : "";
    const code = validSecret(body.code, 12) ? body.code : "";
    let record: ResetRecord | undefined;

    if (token) record = resetRecords.get(token);
    if (!record && code) {
      record = Array.from(resetRecords.values()).find((candidate) =>
        candidate.sessionId === session.id && candidate.code === code && !candidate.used && candidate.expiresAt > Date.now()
      );
    }

    if (!record || record.sessionId !== session.id || record.used || record.expiresAt <= Date.now()) {
      recordFailure(session, "resetFailures");
      return errorResponse("That recovery code or link is invalid, expired, or has already been used.", 400);
    }

    session.resetFailures = [];
    session.mfaPending = false;
    // Short-lived authorization remains server-side and is tied to this session only.
    (session as Session & { resetAuthorizedUntil?: number; resetToken?: string }).resetAuthorizedUntil = Date.now() + 5 * 60 * 1000;
    (session as Session & { resetAuthorizedUntil?: number; resetToken?: string }).resetToken = record.token;
    return json({ ok: true, message: "Recovery code verified. Choose a new password." });
  }

  if (pathname === "/api/password") {
    const resetSession = session as Session & { resetAuthorizedUntil?: number; resetToken?: string };
    const record = resetSession.resetToken ? resetRecords.get(resetSession.resetToken) : undefined;
    if (!resetSession.resetAuthorizedUntil || resetSession.resetAuthorizedUntil <= Date.now() || !record ||
      record.sessionId !== session.id || record.used || record.expiresAt <= Date.now()) {
      return errorResponse("Your password reset authorization has expired. Start recovery again.", 403);
    }
    if (!validStrongPassword(body.password)) {
      return errorResponse("Use 12–128 characters with uppercase, lowercase, a number, and a symbol.");
    }

    await passwordReady;
    account.passwordHash = await Bun.password.hash(body.password, { algorithm: "bcrypt", cost: 10 });
    record.used = true;
    resetSession.resetAuthorizedUntil = 0;
    resetSession.resetToken = undefined;

    // Security Requirement 4: invalidate all authentication state after credential change.
    for (const existing of sessions.values()) {
      existing.authenticated = false;
      existing.mfaPending = false;
      existing.mfaVerified = false;
      existing.privacyAccepted = false;
    }
    return json({ ok: true, message: "Password updated. Sign in with your new password." });
  }

  if (pathname === "/api/login") {
    if (isLocked(session)) return errorResponse("Too many attempts. Please wait before trying again.", 429);
    const password = typeof body.password === "string" && body.password.length <= 128 ? body.password : "";
    await passwordReady;
    const accepted = password.length > 0 && await Bun.password.verify(password, account.passwordHash);
    if (!accepted) {
      recordFailure(session, "loginFailures");
      return errorResponse("Sign-in could not be completed. Check your credentials and try again.", 401);
    }
    session.loginFailures = [];
    session.authenticated = true;
    session.mfaPending = true;
    session.mfaVerified = false;
    session.privacyAccepted = false;
    return json({ ok: true, message: "A second verification step is required.", mockMfaCode: MFA_TEST_CODE });
  }

  if (pathname === "/api/mfa") {
    if (isLocked(session)) return errorResponse("Too many attempts. Please wait before trying again.", 429);
    if (!session.authenticated || !session.mfaPending) return errorResponse("Sign in is required before verification.", 403);
    const code = typeof body.code === "string" ? body.code : "";
    if (!/^\d{6}$/.test(code) || code !== MFA_TEST_CODE) {
      recordFailure(session, "loginFailures");
      return errorResponse("Verification could not be completed. Try again.", 401);
    }
    session.loginFailures = [];
    session.mfaPending = false;
    session.mfaVerified = true;
    return json({ ok: true, message: "Second verification completed." });
  }

  if (pathname === "/api/privacy") {
    // Security Requirement 1: server authorization, not client-side state, protects acceptance.
    if (!session.authenticated || !session.mfaVerified) {
      return errorResponse("Sign in and second verification are required.", 403);
    }
    if (body.accept !== true) return errorResponse("Please explicitly accept the privacy conditions.");
    session.privacyAccepted = true;
    return json({ ok: true, message: "Privacy conditions accepted." });
  }

  return errorResponse("Not found.", 404);
}

function page(): Response {
  const nonce = randomSecret(18);
  const headers = baseHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital Account Recovery</title>
<style nonce="${nonce}">
:root{color-scheme:light;--navy:#14365d;--blue:#075ea8;--soft:#eef5fa;--line:#c9d7e3;--danger:#a32121;--ok:#12663b}
*{box-sizing:border-box}body{margin:0;background:#f4f7fa;color:#17212b;font:17px/1.5 Arial,sans-serif}
header{background:var(--navy);color:#fff;padding:1.1rem 1.4rem}header h1{font-size:1.35rem;margin:0}header p{margin:.15rem 0 0;font-size:.94rem}
main{max-width:760px;margin:2rem auto;padding:0 1rem}.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:1.5rem;box-shadow:0 1px 3px #0001}
h2{margin-top:0;color:var(--navy)}label{font-weight:bold;display:block;margin-top:1rem}input{width:100%;padding:.7rem;border:1px solid #8295a5;border-radius:5px;font:inherit}button{margin:.9rem .5rem 0 0;background:var(--blue);color:#fff;border:0;border-radius:5px;padding:.7rem 1rem;font-weight:bold;font:inherit;cursor:pointer}button.secondary{background:#526877}button:focus,input:focus{outline:3px solid #f3be55;outline-offset:2px}.message{min-height:1.5rem;margin:1rem 0;padding:.65rem;border-radius:5px;background:var(--soft)}.message.error{background:#fdeeee;color:var(--danger)}.message.success{background:#eaf8ef;color:var(--ok)}.notice{margin-top:1.3rem;padding:1rem;background:#fff8df;border-left:4px solid #d28b00}.small{font-size:.91rem}.hidden{display:none!important}fieldset{border:0;padding:0;margin:0}#logs{margin-top:1.5rem;background:#101b26;color:#e3f2ff;border-radius:8px;padding:1rem;min-height:100px;max-height:220px;overflow:auto}#logs h2{color:#fff;font-size:1rem}.logline{font:13px/1.4 monospace;white-space:pre-wrap;margin:.35rem 0}.privacy{padding:1rem;background:var(--soft);border-radius:6px}
footer{text-align:center;padding:1rem;color:#526877;font-size:.85rem}
</style>
</head>
<body>
<header><h1>Hospital Account Portal</h1><p>Secure account recovery and privacy confirmation</p></header>
<main>
<section class="card" aria-live="polite">
<div id="message" class="message">Loading secure recovery service…</div>

<section id="recover-view">
<h2>Recover your account</h2>
<p>Enter the email address associated with your account. For privacy, we always show the same response.</p>
<form id="recover-form" novalidate>
<label for="contact">Email address</label>
<input id="contact" name="contact" type="email" autocomplete="email" maxlength="254" required>
<button type="submit">Prepare recovery instructions</button>
</form>
<p class="small">Already have a password? <button type="button" class="secondary" data-view="login">Sign in</button></p>
</section>

<section id="verify-view" class="hidden">
<h2>Verify recovery</h2>
<p>Use the code sent through the approved recovery channel, or continue using the simulated recovery link.</p>
<form id="verify-form" novalidate>
<label for="recovery-code">Recovery code</label>
<input id="recovery-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}">
<button type="submit">Verify code</button>
<button type="button" id="link-verify" class="secondary">Use recovery link</button>
</form>
<button type="button" class="secondary" data-view="recover">Start over</button>
</section>

<section id="password-view" class="hidden">
<h2>Create a new password</h2>
<p>Use 12–128 characters, including uppercase and lowercase letters, a number, and a symbol.</p>
<form id="password-form" novalidate>
<label for="new-password">New password</label>
<input id="new-password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required>
<label for="confirm-password">Confirm new password</label>
<input id="confirm-password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required>
<button type="submit">Update password</button>
</form>
</section>

<section id="login-view" class="hidden">
<h2>Sign in</h2>
<p>Enter your account password. Account identifiers are not displayed in this portal.</p>
<form id="login-form" novalidate>
<label for="login-password">Password</label>
<input id="login-password" type="password" autocomplete="current-password" maxlength="128" required>
<button type="submit">Sign in securely</button>
</form>
<button type="button" class="secondary" data-view="recover">Forgot password?</button>
</section>

<section id="mfa-view" class="hidden">
<h2>Second verification</h2>
<p>Enter the six-digit verification code from your approved authenticator.</p>
<form id="mfa-form" novalidate>
<label for="mfa-code">Verification code</label>
<input id="mfa-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required>
<button type="submit">Verify and continue</button>
</form>
</section>

<section id="privacy-view" class="hidden">
<h2>Updated privacy conditions</h2>
<div class="privacy"><p>Your account information is used only to manage your healthcare services and required hospital administration. Please review and explicitly accept these updated conditions.</p></div>
<form id="privacy-form">
<label><input id="privacy-check" type="checkbox"> I have reviewed and accept the updated privacy conditions.</label>
<button type="submit">Accept conditions</button>
</form>
</section>

<section id="confirmation-view" class="hidden">
<h2>Confirmation</h2>
<p>Your privacy-condition acceptance has been recorded. You may now continue with hospital appointment arrangements.</p>
<button type="button" class="secondary" data-view="login">Return to sign in</button>
</section>

<aside class="notice" aria-labelledby="safety-title">
<h2 id="safety-title">Stay safe</h2>
<p>Hospital staff will never ask for your password or verification code by email, text message, or phone call. Do not share recovery codes with callers. Use this verified portal directly rather than links from unexpected messages.</p>
</aside>
</section>
<section id="logs" aria-live="polite" aria-label="Simulated delivery and verification logs"><h2>Logs</h2><p class="logline">Secure client log ready.</p></section>
</main>
<footer>Secure hospital portal — no patient details are displayed here.</footer>

<script nonce="${nonce}">
(() => {
  "use strict";
  // Security Requirements 2 and 5: static code only; user data is never inserted as HTML or used for navigation.
  let csrf = "";
  let recoveryToken = "";
  const views = ["recover", "verify", "password", "login", "mfa", "privacy", "confirmation"];
  const message = document.getElementById("message");
  const logs = document.getElementById("logs");

  function log(text) {
    console.log(text);
    const line = document.createElement("p");
    line.className = "logline";
    line.textContent = text;
    logs.appendChild(line);
    logs.scrollTop = logs.scrollHeight;
  }

  function showMessage(text, kind) {
    message.textContent = text;
    message.className = "message" + (kind ? " " + kind : "");
  }

  function show(view) {
    views.forEach((name) => document.getElementById(name + "-view").classList.toggle("hidden", name !== view));
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function request(path, data) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify(data)
    });
    const result = await response.json().catch(() => ({ ok: false, message: "Secure service response was invalid." }));
    if (!response.ok || !result.ok) throw new Error(typeof result.message === "string" ? result.message : "Request could not be completed.");
    return result;
  }

  document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => {
      const view = button.getAttribute("data-view");
      if (views.includes(view)) {
        show(view);
        showMessage("", "");
      }
    });
  });

  document.getElementById("recover-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const contact = document.getElementById("contact").value.trim();
    try {
      const result = await request("/api/recovery", { contact });
      recoveryToken = result.mockRecoveryToken;
      // Required test mock: delivery is simulated in the browser console and mirrored in Logs.
      log("SIMULATED RECOVERY DELIVERY — code: " + result.mockRecoveryCode + " | recovery token: " + result.mockRecoveryToken);
      showMessage(result.message, "success");
      show("verify");
    } catch (error) {
      showMessage(error.message, "error");
    }
  });

  document.getElementById("verify-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const code = document.getElementById("recovery-code").value.trim();
    try {
      await request("/api/reset/verify", { code });
      log("Recovery code verification succeeded.");
      showMessage("Recovery verified. Choose a new password.", "success");
      show("password");
    } catch (error) {
      showMessage(error.message, "error");
    }
  });

  document.getElementById("link-verify").addEventListener("click", async () => {
    if (!recoveryToken) {
      showMessage("Start recovery first to use the simulated recovery link.", "error");
      return;
    }
    try {
      await request("/api/reset/verify", { token: recoveryToken });
      recoveryToken = "";
      log("Simulated recovery link verification succeeded.");
      showMessage("Recovery link verified. Choose a new password.", "success");
      show("password");
    } catch (error) {
      showMessage(error.message, "error");
    }
  });

  document.getElementById("password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = document.getElementById("new-password").value;
    const confirmation = document.getElementById("confirm-password").value;
    if (password !== confirmation) {
      showMessage("The passwords do not match.", "error");
      return;
    }
    try {
      const result = await request("/api/password", { password });
      document.getElementById("new-password").value = "";
      document.getElementById("confirm-password").value = "";
      log("Password reset completed; existing sign-in states were invalidated.");
      showMessage(result.message, "success");
      show("login");
    } catch (error) {
      showMessage(error.message, "error");
    }
  });

  document.getElementById("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = document.getElementById("login-password").value;
    try {
      const result = await request("/api/login", { password });
      document.getElementById("login-password").value = "";
      // Required deterministic MFA test mock, logged in browser only.
      log("SIMULATED MFA DELIVERY — verification code: " + result.mockMfaCode);
      showMessage(result.message, "success");
      show("mfa");
    } catch (error) {
      showMessage(error.message, "error");
    }
  });

  document.getElementById("mfa-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const code = document.getElementById("mfa-code").value.trim();
    try {
      const result = await request("/api/mfa", { code });
      document.getElementById("mfa-code").value = "";
      log("MFA verification succeeded.");
      showMessage(result.message, "success");
      show("privacy");
    } catch (error) {
      showMessage(error.message, "error");
    }
  });

  document.getElementById("privacy-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const accept = document.getElementById("privacy-check").checked;
    try {
      const result = await request("/api/privacy", { accept });
      log("Privacy conditions acceptance recorded.");
      showMessage(result.message, "success");
      show("confirmation");
    } catch (error) {
      showMessage(error.message, "error");
    }
  });

  fetch("/api/session", { credentials: "same-origin", cache: "no-store" })
    .then((response) => response.json())
    .then((result) => {
      if (!result.ok || typeof result.csrf !== "string") throw new Error("Session setup failed.");
      csrf = result.csrf;
      showMessage("Use account recovery or sign in to continue.", "");
      log("Secure session established.");
    })
    .catch(() => showMessage("Secure session setup failed. Refresh this page and try again.", "error"));
})();
</script>
</body>
</html>`;
  return new Response(html, { status: 200, headers });
}

if (!existsSync(CERT_FILE) || !existsSync(KEY_FILE)) {
  throw new Error("HTTPS certificate files are required at certs/cert.pem and certs/key.pem.");
}

Bun.serve({
  port: HTTPS_PORT,
  tls: {
    cert: Bun.file(CERT_FILE),
    key: Bun.file(KEY_FILE),
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/") return page();
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      return errorResponse("Not found.", 404);
    } catch {
      return errorResponse("Request could not be completed.", 400);
    }
  },
});

// Security Requirement 3: plaintext HTTP has no application routes and redirects only to a fixed local HTTPS origin.
Bun.serve({
  port: HTTP_PORT,
  fetch(request) {
    const url = new URL(request.url);
    const destination = `https://localhost:${HTTPS_PORT}${url.pathname}${url.search}`;
    return new Response(null, {
      status: 308,
      headers: {
        Location: destination,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  },
});
