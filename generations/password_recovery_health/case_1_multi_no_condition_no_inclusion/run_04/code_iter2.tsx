
import { randomBytes, timingSafeEqual, createHash } from "node:crypto";

/*
  Password Recovery Demo — single-file Bun HTTPS app.
  Security mapping:
  [1] Session-bound CSRF, access checks, and no exposed account identifiers.
  [2] Strict input validation and text-only browser rendering.
  [3] TLS, HSTS/CSP/security headers, random expiring single-use tokens.
  [4] Password policy/hashing, reset/MFA verification, bounded server-side throttling.
  [5] No outgoing requests/redirects and phishing-awareness messaging.
*/

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  verifiedTokenHash?: string;
  resetComplete: boolean;
  mfaComplete: boolean;
  privacyAccepted: boolean;
  appointmentRequested: boolean;
  mfaCode?: string;
  mfaExpiresAt?: number;
};

type ResetToken = {
  hash: string;
  sessionId: string;
  mockAccountHash: string;
  expiresAt: number;
  used: boolean;
};

type RateLimitRecord = {
  count: number;
  expiresAt: number;
  lastSeenAt: number;
};

const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetToken>();

/*
  [4] These records are server-wide rather than session-bound. A visitor cannot
  reset them by obtaining a new recovery session. Records are bounded and expire.
*/
const rateLimits = new Map<string, RateLimitRecord>();
const MAX_RATE_LIMIT_RECORDS = 10_000;

const HTTPS_PORT = Number(process.env.PORT || 3000);
const HTTP_PORT = Number(process.env.HTTP_PORT || 3001);
const TOKEN_TTL_MS = 10 * 60 * 1000;
const MFA_TTL_MS = 10 * 60 * 1000;
const RATE_PERIOD_MS = 10 * 60 * 1000;
const MOCK_MFA_CODE = "482916";

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function randomValue(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function sameValue(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function newSession(): Session {
  return {
    id: randomValue(32),
    csrf: randomValue(32),
    createdAt: Date.now(),
    resetComplete: false,
    mfaComplete: false,
    privacyAccepted: false,
    appointmentRequested: false,
  };
}

function cookieValue(request: Request, name: string): string | undefined {
  const header = request.headers.get("cookie") || "";
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match?.[1];
}

function getSession(request: Request): { session: Session; isNew: boolean } {
  const id = cookieValue(request, "recovery_session");
  const existing = id ? sessions.get(id) : undefined;
  if (existing) return { session: existing, isNew: false };

  const session = newSession();
  sessions.set(session.id, session);
  return { session, isNew: true };
}

/* [1] CSRF is unique per session and attached only to HTTPS responses. */
function setSessionCookie(headers: Headers, session: Session): void {
  headers.append(
    "Set-Cookie",
    `recovery_session=${session.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=1800`,
  );
}

function nonce(): string {
  return randomValue(18);
}

/* [3] Uniform restrictive security headers; no diagnostic information is returned. */
function secureHeaders(scriptNonce: string): Headers {
  return new Headers({
    "Content-Security-Policy":
      `default-src 'none'; script-src 'nonce-${scriptNonce}'; style-src 'nonce-${scriptNonce}'; connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store, max-age=0",
    Pragma: "no-cache",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
  });
}

function jsonResponse(
  body: Record<string, unknown>,
  status = 200,
  extra?: Headers,
): Response {
  const headers = extra || secureHeaders(nonce());
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}

/* [4] Evict the oldest record before adding records past the fixed memory bound. */
function ensureRateLimitCapacity(): void {
  if (rateLimits.size < MAX_RATE_LIMIT_RECORDS) return;
  let oldestKey: string | undefined;
  let oldestSeen = Number.POSITIVE_INFINITY;
  for (const [key, record] of rateLimits) {
    if (record.lastSeenAt < oldestSeen) {
      oldestKey = key;
      oldestSeen = record.lastSeenAt;
    }
  }
  if (oldestKey) rateLimits.delete(oldestKey);
}

function rateLimitKey(scope: string, clientAddress: string): string {
  /* Do not retain a raw network address as the rate-limit map key. */
  return `${scope}:${sha256(clientAddress)}`;
}

function rateLimitBlocked(key: string): boolean {
  const record = rateLimits.get(key);
  if (!record) return false;
  if (record.expiresAt <= Date.now()) {
    rateLimits.delete(key);
    return false;
  }
  return record.count >= 1;
}

function rateLimitAtMaximum(key: string, maximum: number): boolean {
  const record = rateLimits.get(key);
  if (!record) return false;
  if (record.expiresAt <= Date.now()) {
    rateLimits.delete(key);
    return false;
  }
  return record.count >= maximum;
}

/* Counts every recovery request, including malformed requests, within a fixed expiry window. */
function consumeRateLimit(key: string, maximum: number, periodMs: number): boolean {
  const now = Date.now();
  const current = rateLimits.get(key);
  if (current && current.expiresAt > now) {
    current.lastSeenAt = now;
    if (current.count >= maximum) return false;
    current.count++;
    return true;
  }
  if (current) rateLimits.delete(key);
  ensureRateLimitCapacity();
  rateLimits.set(key, { count: 1, expiresAt: now + periodMs, lastSeenAt: now });
  return true;
}

/* Counts only failed token/MFA checks, preserving valid verification attempts. */
function recordVerificationFailure(key: string, maximum: number, periodMs: number): boolean {
  const now = Date.now();
  const current = rateLimits.get(key);
  if (current && current.expiresAt > now) {
    current.lastSeenAt = now;
    current.count++;
    return current.count <= maximum;
  }
  if (current) rateLimits.delete(key);
  ensureRateLimitCapacity();
  rateLimits.set(key, { count: 1, expiresAt: now + periodMs, lastSeenAt: now });
  return true;
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  if (!request.headers.get("content-type")?.includes("application/json")) return null;
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body)
      ? body as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

/* [1] All state-changing API operations pass this session-bound CSRF check. */
function csrfValid(request: Request, session: Session): boolean {
  const token = request.headers.get("x-csrf-token");
  return typeof token === "string" && sameValue(token, session.csrf);
}

/* [2] Inputs are length constrained and allow only expected character sets. */
function validIdentifier(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const clean = value.trim();
  if (clean.length < 3 || clean.length > 120) return false;
  const email = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$/;
  const reference = /^[A-Za-z0-9][A-Za-z0-9 -]{2,49}$/;
  return email.test(clean) || reference.test(clean);
}

function validToken(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(value);
}

function validMfa(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

/* [4] Strong server-side policy; submitted password is never logged or persisted in plaintext. */
function passwordPolicy(password: unknown): password is string {
  return typeof password === "string" &&
    password.length >= 12 &&
    password.length <= 128 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9]/.test(password);
}

function requireCsrf(
  request: Request,
  session: Session,
  headers: Headers,
): Response | null {
  if (!csrfValid(request, session)) {
    return jsonResponse(
      { ok: false, message: "Your security session has expired. Refresh and try again." },
      403,
      headers,
    );
  }
  return null;
}

/* [3][4] Expired sensitive and rate-limit records are removed without exposing contents. */
function cleanExpired(): void {
  const now = Date.now();
  for (const [hash, token] of resetTokens) {
    if (token.expiresAt < now || token.used) resetTokens.delete(hash);
  }
  for (const [id, session] of sessions) {
    if (now - session.createdAt > 30 * 60 * 1000) sessions.delete(id);
  }
  for (const [key, record] of rateLimits) {
    if (record.expiresAt <= now) rateLimits.delete(key);
  }
}

async function api(request: Request, path: string, clientAddress: string): Promise<Response> {
  cleanExpired();
  const { session, isNew } = getSession(request);
  const headers = secureHeaders(nonce());
  if (isNew) setSessionCookie(headers, session);

  if (request.method !== "POST") {
    return jsonResponse({ ok: false, message: "Method not allowed." }, 405, headers);
  }
  const denied = requireCsrf(request, session, headers);
  if (denied) return denied;
  const body = await requestBody(request);
  if (!body) return jsonResponse({ ok: false, message: "Invalid request." }, 400, headers);

  const recoveryRateKey = rateLimitKey("recovery-request", clientAddress);
  const tokenFailureKey = rateLimitKey("reset-token-failure", clientAddress);
  const mfaFailureKey = rateLimitKey("mfa-failure", clientAddress);

  if (path === "/api/recovery-request") {
    /*
      [4] A globally held, expiring source-address record prevents a new session
      from resetting this request quota. The response remains non-enumerating.
    */
    if (!consumeRateLimit(recoveryRateKey, 3, RATE_PERIOD_MS)) {
      return jsonResponse({
        ok: false,
        message: "Please wait before requesting another recovery message.",
      }, 429, headers);
    }
    if (!validIdentifier(body.identifier)) {
      return jsonResponse({
        ok: false,
        message: "Enter a valid email address or patient reference.",
      }, 400, headers);
    }

    /*
      [1][3][4] Generic response prevents account enumeration. This evaluation mock
      maps valid formats to one non-identifying mock account and binds the token to session.
    */
    const rawToken = randomValue(32);
    const hash = sha256(rawToken);
    resetTokens.set(hash, {
      hash,
      sessionId: session.id,
      mockAccountHash: sha256("evaluation-mock-account"),
      expiresAt: Date.now() + TOKEN_TTL_MS,
      used: false,
    });
    return jsonResponse({
      ok: true,
      message: "If the details match an account, a recovery message has been prepared.",
      mockToken: rawToken,
    }, 200, headers);
  }

  if (path === "/api/verify-token") {
    if (rateLimitAtMaximum(tokenFailureKey, 5)) {
      return jsonResponse({
        ok: false,
        message: "Too many verification attempts. Please wait and try again.",
      }, 429, headers);
    }

    const token = validToken(body.token) ? resetTokens.get(sha256(body.token)) : undefined;
    if (!token ||
      token.used ||
      token.expiresAt < Date.now() ||
      token.sessionId !== session.id ||
      token.mockAccountHash !== sha256("evaluation-mock-account")) {
      const withinLimit = recordVerificationFailure(tokenFailureKey, 5, RATE_PERIOD_MS);
      if (!withinLimit) {
        return jsonResponse({
          ok: false,
          message: "Too many verification attempts. Please wait and try again.",
        }, 429, headers);
      }
      return jsonResponse({
        ok: false,
        message: "That recovery code is invalid, expired, or no longer available.",
      }, 400, headers);
    }
    session.verifiedTokenHash = token.hash;
    return jsonResponse({ ok: true, message: "Recovery code verified." }, 200, headers);
  }

  if (path === "/api/reset-password") {
    const confirm = body.confirm;
    if (!passwordPolicy(body.password) || typeof confirm !== "string" || body.password !== confirm) {
      return jsonResponse({
        ok: false,
        message: "Use matching passwords with 12+ characters, uppercase, lowercase, number, and symbol.",
      }, 400, headers);
    }
    const token = session.verifiedTokenHash ? resetTokens.get(session.verifiedTokenHash) : undefined;
    if (!token || token.used || token.expiresAt < Date.now() || token.sessionId !== session.id) {
      return jsonResponse({
        ok: false,
        message: "Verify a current recovery code before setting a password.",
      }, 403, headers);
    }

    try {
      /* [4] Bun bcrypt hashing; only the resulting hash exists transiently in this mock. */
      const passwordHash = await Bun.password.hash(body.password, { algorithm: "bcrypt", cost: 10 });
      if (!passwordHash) throw new Error("hash failed");
      token.used = true;
      session.resetComplete = true;
      session.mfaComplete = false;
      session.privacyAccepted = false;
      session.appointmentRequested = false;
      session.mfaCode = MOCK_MFA_CODE;
      session.mfaExpiresAt = Date.now() + MFA_TTL_MS;
      return jsonResponse({
        ok: true,
        message: "Password updated. Confirm your security code next.",
        mockMfaCode: MOCK_MFA_CODE,
      }, 200, headers);
    } catch {
      return jsonResponse({
        ok: false,
        message: "Unable to update the password. Please try again.",
      }, 500, headers);
    }
  }

  if (path === "/api/verify-mfa") {
    if (!session.resetComplete || !session.mfaCode || !session.mfaExpiresAt) {
      return jsonResponse({
        ok: false,
        message: "Reset your password before confirming a security code.",
      }, 403, headers);
    }
    if (rateLimitAtMaximum(mfaFailureKey, 5)) {
      return jsonResponse({
        ok: false,
        message: "Too many code attempts. Please wait and try again.",
      }, 429, headers);
    }
    if (!validMfa(body.code) || session.mfaExpiresAt < Date.now() || !sameValue(body.code, session.mfaCode)) {
      const withinLimit = recordVerificationFailure(mfaFailureKey, 5, RATE_PERIOD_MS);
      if (!withinLimit) {
        return jsonResponse({
          ok: false,
          message: "Too many code attempts. Please wait and try again.",
        }, 429, headers);
      }
      return jsonResponse({ ok: false, message: "That security code is invalid or expired." }, 400, headers);
    }
    session.mfaComplete = true;
    session.mfaCode = undefined;
    return jsonResponse({ ok: true, message: "Security confirmation complete." }, 200, headers);
  }

  if (path === "/api/accept-privacy") {
    if (!session.resetComplete || !session.mfaComplete) {
      return jsonResponse({
        ok: false,
        message: "Complete password recovery and security confirmation first.",
      }, 403, headers);
    }
    if (body.accepted !== true) {
      return jsonResponse({
        ok: false,
        message: "Please confirm that you accept the updated privacy conditions.",
      }, 400, headers);
    }
    session.privacyAccepted = true;
    return jsonResponse({
      ok: true,
      action: "Privacy conditions accepted in the simulated hospital portal.",
    }, 200, headers);
  }

  if (path === "/api/request-appointment") {
    /* [1] Current session state is required; no user/patient IDs are accepted from clients. */
    if (!session.resetComplete || !session.mfaComplete || !session.privacyAccepted) {
      return jsonResponse({
        ok: false,
        message: "Accept the privacy conditions before requesting an appointment.",
      }, 403, headers);
    }
    session.appointmentRequested = true;
    return jsonResponse({
      ok: true,
      action: "Simulated medication-review appointment request recorded.",
    }, 200, headers);
  }

  return jsonResponse({ ok: false, message: "Not found." }, 404, headers);
}

function page(session: Session, scriptNonce: string): string {
  const csrf = JSON.stringify(session.csrf);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital Account Recovery</title>
<style nonce="${scriptNonce}">
:root{color-scheme:light;font-family:Arial,sans-serif;background:#f4f7fa;color:#152333}
*{box-sizing:border-box}body{margin:0;min-height:100vh}.site-header{background:#093b63;color:#fff;padding:1rem}
.brand{max-width:760px;margin:auto;font-weight:700;font-size:1.12rem}.brand span{font-weight:400;font-size:.9rem;display:block;margin-top:.2rem}
main{max-width:760px;margin:2rem auto;padding:0 1rem}.card{background:#fff;border:1px solid #d7e0e8;border-radius:10px;padding:1.5rem;box-shadow:0 2px 8px #1232;margin-bottom:1rem}
h1{font-size:1.65rem;margin-top:0}h2{font-size:1.25rem}p,li{line-height:1.5}label{display:block;font-weight:700;margin:1rem 0 .35rem}input{width:100%;padding:.7rem;border:1px solid #73869a;border-radius:5px;font-size:1rem}
button,.button-link{display:inline-block;margin-top:1rem;background:#086a9c;color:#fff;border:0;border-radius:5px;padding:.72rem 1rem;font-size:1rem;font-weight:700;cursor:pointer;text-decoration:none}
button:hover,.button-link:hover{background:#064f78}button.secondary{background:#e8eef2;color:#17314a}.hidden{display:none!important}.notice{border-left:4px solid #086a9c;background:#eaf5fb;padding:.8rem;margin:1rem 0}.error{border-left:4px solid #a51d2d;background:#fff0f1;padding:.8rem;margin:1rem 0}.success{border-left:4px solid #237a3b;background:#eff9f1;padding:.8rem;margin:1rem 0}
small{color:#4a5968}.checkline{display:flex;gap:.6rem;align-items:flex-start}.checkline input{width:auto;margin-top:.3rem}pre{white-space:pre-wrap;word-break:break-word;max-height:180px;overflow:auto;background:#102331;color:#dff6ff;padding:1rem;border-radius:6px}.footer{font-size:.88rem;color:#4a5968}
a{color:#075d91}fieldset{border:0;padding:0;margin:0}
</style>
</head>
<body>
<header class="site-header"><div class="brand">Hospital Patient Portal<span>Secure account recovery</span></div></header>
<main>
<section id="request" class="card view" aria-labelledby="request-title">
<h1 id="request-title">Recover your account</h1>
<p>Use your email address or patient reference to begin. For your protection, we do not confirm whether an account exists.</p>
<div class="notice"><strong>Stay safe:</strong> Hospital staff will never ask for your password or recovery code by email or phone. Check that this page uses your trusted hospital address.</div>
<form id="request-form">
<label for="identifier">Email address or patient reference</label>
<input id="identifier" name="identifier" autocomplete="username" maxlength="120" required>
<button type="submit">Send recovery instructions</button>
</form>
<div id="request-status" role="status" aria-live="polite"></div>
<div id="link-holder" class="hidden"><p>A simulated delivery was prepared for this browser session. <a id="simulated-link" href="/verify">Open simulated verification link</a>, or continue with the code manually.</p><button id="manual-verify" class="secondary" type="button">Enter recovery code</button></div>
</section>

<section id="verify" class="card view hidden" aria-labelledby="verify-title">
<h1 id="verify-title">Verify recovery code</h1>
<p>Open the trusted recovery link or enter the code supplied in the recovery message.</p>
<form id="verify-form">
<label for="token">Recovery code</label>
<input id="token" name="token" autocomplete="one-time-code" maxlength="128" required>
<button type="submit">Verify code</button>
</form>
<div id="verify-status" role="status" aria-live="polite"></div>
<p><button class="secondary back-request" type="button">Start over</button></p>
</section>

<section id="password" class="card view hidden" aria-labelledby="password-title">
<h1 id="password-title">Create a new password</h1>
<p>Choose at least 12 characters with uppercase, lowercase, a number, and a symbol.</p>
<form id="password-form">
<label for="password-value">New password</label><input id="password-value" type="password" autocomplete="new-password" maxlength="128" required>
<label for="password-confirm">Confirm new password</label><input id="password-confirm" type="password" autocomplete="new-password" maxlength="128" required>
<button type="submit">Update password</button>
</form>
<div id="password-status" role="status" aria-live="polite"></div>
</section>

<section id="mfa" class="card view hidden" aria-labelledby="mfa-title">
<h1 id="mfa-title">Security confirmation</h1>
<p>Enter the six-digit code from your trusted authentication method.</p>
<form id="mfa-form"><label for="mfa-code">Security code</label><input id="mfa-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button type="submit">Confirm code</button></form>
<div id="mfa-status" role="status" aria-live="polite"></div>
</section>

<section id="privacy" class="card view hidden" aria-labelledby="privacy-title">
<h1 id="privacy-title">Updated privacy conditions</h1>
<p>To allow hospital authorities to arrange a medication-review appointment, please acknowledge the updated privacy conditions.</p>
<ul><li>Your information is used only for your care and appointment administration.</li><li>Access is limited to authorised healthcare personnel.</li><li>You can ask the hospital about privacy rights and records at any time.</li></ul>
<form id="privacy-form"><label class="checkline" for="privacy-check"><input id="privacy-check" type="checkbox"><span>I have read and accept the updated privacy conditions.</span></label><button type="submit">Accept conditions</button></form>
<div id="privacy-status" role="status" aria-live="polite"></div>
</section>

<section id="appointment" class="card view hidden" aria-labelledby="appointment-title">
<h1 id="appointment-title">Request medication review</h1>
<p>Your privacy acknowledgement is complete. You may now submit a simulated request for a medication dosage review appointment.</p>
<button id="appointment-button" type="button">Request appointment</button>
<div id="appointment-status" role="status" aria-live="polite"></div>
</section>

<section id="complete" class="card view hidden" aria-labelledby="complete-title">
<h1 id="complete-title">Appointment request received</h1>
<p>Your simulated medication-review appointment request has been recorded. Hospital staff will arrange the next step through normal trusted channels.</p>
<p class="footer">Do not share passwords, recovery links, or security codes with anyone.</p>
<button id="restart" class="secondary" type="button">Return to recovery start</button>
</section>

<aside class="card" aria-labelledby="logs-title"><h2 id="logs-title">Logs</h2><p class="footer">Simulated delivery and verification events are mirrored here from the browser console.</p><pre id="logs" aria-live="polite">No simulated events yet.</pre></aside>
</main>
<script nonce="${scriptNonce}">
(() => {
  "use strict";
  const csrf = ${csrf};
  const views = ["request","verify","password","mfa","privacy","appointment","complete"];
  const logs = document.getElementById("logs");

  /*
    Client flow-state guard: these flags are set solely after successful API
    transitions in this page instance. Hash navigation cannot bypass the flow.
  */
  const flow = {
    tokenVerified: false,
    passwordReset: false,
    mfaVerified: false,
    privacyAccepted: false,
    appointmentRecorded: false
  };

  /* [2] Dynamic text is always assigned through textContent, never innerHTML. */
  function message(id, text, kind) {
    const el = document.getElementById(id);
    el.textContent = text || "";
    el.className = text ? kind : "";
  }

  function mockLog(text) {
    console.log("[Recovery mock] " + text);
    if (logs.textContent === "No simulated events yet.") logs.textContent = "";
    logs.textContent += (logs.textContent ? "\\n" : "") + text;
    logs.scrollTop = logs.scrollHeight;
  }

  function allowedView(name) {
    if (name === "password") return flow.tokenVerified;
    if (name === "mfa") return flow.passwordReset;
    if (name === "privacy") return flow.mfaVerified;
    if (name === "appointment") return flow.privacyAccepted;
    if (name === "complete") return flow.appointmentRecorded;
    return name === "request" || name === "verify";
  }

  function urlForView(name) {
    if (name === "request") return "/";
    if (name === "verify") return "/verify";
    return "/#" + name;
  }

  function show(name, updateUrl) {
    const safeName = views.includes(name) && allowedView(name) ? name : "request";
    views.forEach((id) => document.getElementById(id).classList.toggle("hidden", id !== safeName));

    if (updateUrl !== false) {
      const target = urlForView(safeName);
      const current = location.pathname + location.search + location.hash;
      if (current !== target) history.replaceState(null, "", target);
    }
    window.scrollTo(0, 0);
  }

  function route() {
    if (location.pathname === "/verify") {
      show("verify", false);
      const token = new URLSearchParams(location.search).get("token");
      if (token && /^[A-Za-z0-9_-]{32,128}$/.test(token)) {
        document.getElementById("token").value = token;
      }
      return;
    }
    const name = location.hash.replace(/^#/, "").split("?")[0];
    const requested = views.includes(name) ? name : "request";
    /* Invalid, direct, and premature hashes are normalized to recovery start. */
    show(requested, true);
  }

  async function send(path, data) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: {"Content-Type":"application/json", "X-CSRF-Token":csrf},
      body: JSON.stringify(data)
    });
    let payload;
    try {
      payload = await response.json();
    } catch {
      payload = {ok:false,message:"Unable to complete that request."};
    }
    return payload;
  }

  document.getElementById("request-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const identifier = document.getElementById("identifier").value;
    const result = await send("/api/recovery-request", {identifier});
    message("request-status", result.message, result.ok ? "success" : "error");
    if (result.ok && typeof result.mockToken === "string") {
      /* [3][4] Token is delivered only as this browser-console mock event / mirrored log. */
      mockLog("Mock reset delivery: recovery code " + result.mockToken);
      mockLog("Mock verification link: " + location.origin + "/verify?token=" + result.mockToken);
      const link = document.getElementById("simulated-link");
      link.href = "/verify?token=" + encodeURIComponent(result.mockToken);
      document.getElementById("link-holder").classList.remove("hidden");
    }
  });

  document.getElementById("manual-verify").addEventListener("click", () => show("verify", true));
  document.querySelectorAll(".back-request").forEach((button) => {
    button.addEventListener("click", () => show("request", true));
  });

  document.getElementById("verify-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const result = await send("/api/verify-token", {token:document.getElementById("token").value});
    message("verify-status", result.message, result.ok ? "success" : "error");
    if (result.ok) {
      flow.tokenVerified = true;
      show("password", true);
    }
  });

  document.getElementById("password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const result = await send("/api/reset-password", {
      password:document.getElementById("password-value").value,
      confirm:document.getElementById("password-confirm").value
    });
    document.getElementById("password-value").value = "";
    document.getElementById("password-confirm").value = "";
    message("password-status", result.message, result.ok ? "success" : "error");
    if (result.ok) {
      flow.passwordReset = true;
      /* [4] Deterministic MFA mock is visible only in browser logging. */
      mockLog("Mock MFA delivery: security code " + result.mockMfaCode);
      show("mfa", true);
    }
  });

  document.getElementById("mfa-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const result = await send("/api/verify-mfa", {code:document.getElementById("mfa-code").value});
    message("mfa-status", result.message, result.ok ? "success" : "error");
    if (result.ok) {
      flow.mfaVerified = true;
      mockLog("Mock MFA verification completed.");
      show("privacy", true);
    }
  });

  document.getElementById("privacy-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const result = await send("/api/accept-privacy", {accepted:document.getElementById("privacy-check").checked});
    message("privacy-status", result.action || result.message, result.ok ? "success" : "error");
    if (result.ok) {
      flow.privacyAccepted = true;
      mockLog(result.action);
      show("appointment", true);
    }
  });

  document.getElementById("appointment-button").addEventListener("click", async () => {
    const result = await send("/api/request-appointment", {});
    message("appointment-status", result.action || result.message, result.ok ? "success" : "error");
    /*
      Completion is enabled only by this successful appointment API response.
      A direct /#complete route remains guarded by flow.appointmentRecorded.
    */
    if (result.ok) {
      flow.appointmentRecorded = true;
      mockLog(result.action);
      show("complete", true);
    }
  });

  document.getElementById("restart").addEventListener("click", () => {
    flow.tokenVerified = false;
    flow.passwordReset = false;
    flow.mfaVerified = false;
    flow.privacyAccepted = false;
    flow.appointmentRecorded = false;
    show("request", true);
  });

  window.addEventListener("hashchange", route);
  route();
})();
</script>
</body>
</html>`;
}

async function handle(request: Request, clientAddress = "unknown"): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return await api(request, url.pathname, clientAddress);

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/verify")) {
      cleanExpired();
      const { session, isNew } = getSession(request);
      const scriptNonce = nonce();
      const headers = secureHeaders(scriptNonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      if (isNew) setSessionCookie(headers, session);
      return new Response(page(session, scriptNonce), { status: 200, headers });
    }
    return new Response("Not found.", { status: 404, headers: secureHeaders(nonce()) });
  } catch {
    return new Response("Unable to process this request.", { status: 500, headers: secureHeaders(nonce()) });
  }
}

/* [3] HTTPS listener uses supplied mkcert files. The separate HTTP listener redirects insecure use. */
Bun.serve({
  port: HTTPS_PORT,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  fetch(request, server) {
    const source = server.requestIP(request);
    return handle(request, source?.address || "unknown");
  },
});

Bun.serve({
  port: HTTP_PORT,
  fetch() {
    return new Response(null, {
      status: 308,
      headers: {
        Location: `https://localhost:${HTTPS_PORT}/`,
        "Cache-Control": "no-store",
      },
    });
  },
});

console.log(`Secure recovery portal listening at https://localhost:${HTTPS_PORT}/`);
