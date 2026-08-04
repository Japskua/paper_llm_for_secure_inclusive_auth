
import { serve, file } from "bun";

/*
  Security requirements mapping:
  1: Per-session CSRF, SameSite cookies, server-side authorization, no IDOR.
  2: The client writes variable messages using textContent; input is never HTML-interpolated.
  3: HTTPS, HSTS, CSP nonce, secure headers, random short-lived single-use reset tokens.
  4: bcrypt password storage, strong policy, MFA, and server-side account/scope throttling.
  5: Fixed internal routes only; supplied redirect targets and external URLs are never used.
*/

const HTTPS_PORT = Number(Bun.env.HTTPS_PORT || 3000);
const HTTP_PORT = Number(Bun.env.HTTP_PORT || 3001);
const SESSION_TTL = 60 * 60 * 1000;
const RESET_TTL = 10 * 60 * 1000;
const THROTTLE_WINDOW = 10 * 60 * 1000;
const LOCKOUT_WINDOW = 5 * 60 * 1000;

/*
  Deterministic mock recovery identity. It is intentionally only compared server-side
  and is never rendered in the portal or included in a response.
*/
const VALID_RECOVERY_IDENTITY = "helena.recovery@localhost";
const ACCOUNT_SCOPE = "mock-care-account";

const sessions = new Map<string, any>();
const resetRecords = new Map<string, any>();
const activeResetByIdentity = new Map<string, string>();
const recoveryThrottle = new Map<string, number[]>();
const resetVerificationThrottle = new Map<string, number[]>();
const loginProtection = new Map<string, { failures: number[]; lockedUntil: number }>();
const mfaProtection = new Map<string, { failures: number[]; lockedUntil: number }>();

const account = {
  passwordHash: await Bun.password.hash("Initial!DemoPassword2025", {
    algorithm: "bcrypt",
    cost: 10,
  }),
};

function randomValue(bytes = 32) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return Buffer.from(data).toString("base64url");
}

function tokenHash(value: string) {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

function normalizeIdentity(value: string) {
  return value.trim().toLowerCase();
}

/*
  A privacy-preserving, stable server request scope. It is not exposed to the client.
  Identity scopes are preferred for recovery; this fallback ensures malformed-code
  attempts cannot be reset simply by creating a new portal session.
*/
function stableRequestScope(request: Request) {
  const userAgent = request.headers.get("user-agent") || "unknown-browser";
  const language = request.headers.get("accept-language") || "";
  return "scope:" + tokenHash(userAgent + "|" + language);
}

function createSession() {
  const id = randomValue(32);
  const session = {
    id,
    csrf: randomValue(24),
    createdAt: Date.now(),
    recoveryIdentity: null as string | null,
    resetVerified: false,
    pendingMfa: false,
    authenticated: false,
    privacyAccepted: false,
    appointmentBooked: false,
  };
  sessions.set(id, session);
  return session;
}

function cookieSession(request: Request) {
  const raw = request.headers.get("cookie") || "";
  const value = raw.match(/(?:^|;\s*)portal_session=([^;]+)/)?.[1];
  if (!value) return null;
  const session = sessions.get(value);
  if (!session || Date.now() - session.createdAt > SESSION_TTL) {
    sessions.delete(value);
    return null;
  }
  return session;
}

function sessionCookie(session: any) {
  return `portal_session=${session.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600`;
}

function headers(nonce: string, extra: Record<string, string> = {}) {
  return new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      `default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; ` +
      `form-action 'self'; connect-src 'self'; img-src 'self'; font-src 'none'; ` +
      `script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'`,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    "Cache-Control": "no-store",
    ...extra,
  });
}

function json(data: any, status = 200, cookie?: string) {
  const nonce = randomValue(16);
  const resultHeaders = headers(nonce, { "Content-Type": "application/json; charset=utf-8" });
  if (cookie) resultHeaders.set("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers: resultHeaders });
}

function genericError(status = 400) {
  return json({ ok: false, message: "The request could not be completed. Please try again." }, status);
}

function validCsrf(request: Request, session: any, body: any) {
  return Boolean(
    session &&
      typeof body?.csrf === "string" &&
      body.csrf.length >= 20 &&
      body.csrf === session.csrf,
  );
}

/* Requirement 4: all rate-limit state below is server-global, never session-local. */
function consumeAttempt(store: Map<string, number[]>, key: string, limit: number, windowMs: number) {
  const now = Date.now();
  const attempts = (store.get(key) || []).filter((time) => now - time < windowMs);
  attempts.push(now);
  store.set(key, attempts);
  return attempts.length <= limit;
}

function protectionFor(
  store: Map<string, { failures: number[]; lockedUntil: number }>,
  key: string,
) {
  let protection = store.get(key);
  if (!protection) {
    protection = { failures: [], lockedUntil: 0 };
    store.set(key, protection);
  }
  return protection;
}

function failedProtectedAttempt(
  store: Map<string, { failures: number[]; lockedUntil: number }>,
  key: string,
  limit: number,
) {
  const protection = protectionFor(store, key);
  const now = Date.now();
  protection.failures = protection.failures.filter((time) => now - time < LOCKOUT_WINDOW);
  protection.failures.push(now);
  if (protection.failures.length >= limit) protection.lockedUntil = now + LOCKOUT_WINDOW;
  return protection;
}

async function readBody(request: Request) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.startsWith("application/json")) return null;
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function isStrongPassword(password: string) {
  return (
    typeof password === "string" &&
    password.length >= 12 &&
    password.length <= 128 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}

function appHtml(session: any) {
  const nonce = randomValue(16);
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="${session.csrf}">
<title>Care Portal – Secure access</title>
<style nonce="${nonce}">
:root{color-scheme:light;font-family:Arial,Helvetica,sans-serif;background:#f4f7f9;color:#172535}
*{box-sizing:border-box}body{margin:0}.shell{max-width:760px;margin:0 auto;padding:28px 18px 42px}
header{border-bottom:4px solid #176b80;margin-bottom:22px;padding-bottom:16px}h1{font-size:1.7rem;margin:0 0 7px}
h2{font-size:1.35rem;margin-top:0}p,li{line-height:1.5}.card{background:#fff;border:1px solid #d5e0e5;border-radius:10px;padding:23px;box-shadow:0 2px 6px #17253512}
label{font-weight:bold;display:block;margin:15px 0 6px}input{width:100%;font:inherit;padding:11px;border:1px solid #80909b;border-radius:5px}
button,.button{font:inherit;font-weight:bold;background:#176b80;color:white;border:0;border-radius:5px;padding:11px 16px;margin-top:18px;cursor:pointer;text-decoration:none;display:inline-block}
button.secondary,.button.secondary{background:#e5eef1;color:#17313b;margin-left:7px}.notice{background:#edf7fa;border-left:4px solid #176b80;padding:12px;margin:16px 0}
.warning{background:#fff8e9;border-left:4px solid #a76a00;padding:12px;margin:16px 0}.message{min-height:24px;font-weight:bold;margin-top:14px}
nav{margin-top:18px}nav a{color:#075b73;margin-right:15px}.hidden{display:none}code{word-break:break-all}
.logs{margin-top:23px;background:#10212a;color:#d8f2f5;border-radius:8px;padding:14px}.logs h2{font-size:1rem;margin:0 0 8px}.logs pre{margin:0;white-space:pre-wrap;font-size:.82rem;min-height:22px}
footer{font-size:.88rem;color:#4d5d65;margin-top:24px}
</style>
</head>
<body>
<div class="shell">
<header><h1>Care Portal secure access</h1><p>Recovery and sign-in for privacy statement acceptance.</p></header>
<main id="app" aria-live="polite"></main>
<section class="logs" aria-label="Simulated delivery logs"><h2>Logs</h2><pre id="logs">No simulated events yet.</pre></section>
<footer>Check that the address begins with <strong>https://localhost</strong>. Hospital staff never request passwords, reset codes, or MFA codes by email or telephone.</footer>
</div>
<script nonce="${nonce}">
(() => {
"use strict";
/* Requirement 2: all variable UI text is inserted with textContent, never innerHTML. */
const app = document.getElementById("app");
const logs = document.getElementById("logs");
let csrf = document.querySelector('meta[name="csrf-token"]').content;

function eventLog(message) {
  console.log(message);
  logs.textContent = logs.textContent === "No simulated events yet." ? message : logs.textContent + "\\n" + message;
}
function el(tag, text) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; return node; }
function button(text, handler, secondary) {
  const b = el("button", text); if (secondary) b.className = "secondary"; b.type = "button"; b.addEventListener("click", handler); return b;
}
function link(text, href, secondary) {
  const a = el("a", text); a.href = href; a.className = secondary ? "button secondary" : "button"; return a;
}
function clear() { app.replaceChildren(); }
function card(title) { const c = el("section"); c.className = "card"; c.append(el("h2", title)); app.append(c); return c; }
function message(parent) { const m = el("p"); m.className = "message"; parent.append(m); return m; }
function guidance(parent) {
  const n = el("aside"); n.className = "notice";
  n.textContent = "Safe sign-in reminder: use only this localhost HTTPS portal. Staff never ask for your password or security codes by phone, email, or message.";
  parent.append(n);
}
async function api(path, payload) {
  const response = await fetch(path, {method:"POST", credentials:"same-origin", headers:{"Content-Type":"application/json"}, body:JSON.stringify({...payload, csrf})});
  const data = await response.json().catch(() => ({ok:false,message:"Service unavailable."}));
  if (data.csrf) csrf = data.csrf;
  return data;
}
function go(path) { history.pushState({}, "", path); render(); }
window.addEventListener("popstate", render);

function recovery() {
  const c = card("Reset your password");
  c.append(el("p", "Enter your recovery identifier. For privacy, we show the same result whether or not an account is found."));
  guidance(c);
  const label = el("label", "Recovery identifier"); label.htmlFor = "identifier"; c.append(label);
  const input = el("input"); input.id = "identifier"; input.autocomplete = "username"; input.maxLength = 160; c.append(input);
  const m = message(c);
  const submit = button("Send recovery instructions", async () => {
    submit.disabled = true;
    const data = await api("/api/recovery-request", {identifier: input.value});
    submit.disabled = false;
    m.textContent = data.message || "If an account can be recovered, instructions have been prepared.";
    if (data.ok && typeof data.code === "string") {
      eventLog("Simulated recovery delivery prepared. Test reset code: " + data.code);
      c.append(link("Open secure verification link", "/reset?code=" + encodeURIComponent(data.code)));
    }
  });
  c.append(submit);
  const nav = el("nav"); nav.append(link("Return to sign in", "/login", true)); c.append(nav);
}
function verify() {
  const c = card("Verify recovery code");
  c.append(el("p", "Use the secure link you received or enter the delivered recovery code manually."));
  guidance(c);
  const label = el("label", "Recovery code"); label.htmlFor = "code"; c.append(label);
  const input = el("input"); input.id = "code"; input.autocomplete = "one-time-code"; input.maxLength = 128;
  const supplied = new URL(location.href).searchParams.get("code") || "";
  if (/^[A-Za-z0-9_-]{32,128}$/.test(supplied)) input.value = supplied;
  c.append(input);
  const m = message(c);
  c.append(button("Verify code", async () => {
    const data = await api("/api/verify-reset", {code: input.value});
    m.textContent = data.message || "Unable to verify this code.";
    if (data.ok) { eventLog("Simulated recovery code verification completed."); go("/new-password"); }
  }));
  c.append(link("Start over", "/", true));
}
function passwordScreen() {
  const c = card("Choose a new password");
  c.append(el("p", "Use at least 12 characters, including uppercase and lowercase letters, a number, and a symbol."));
  const warning = el("aside"); warning.className = "warning"; warning.textContent = "Do not share this password or any code. Passwords are never displayed after submission."; c.append(warning);
  const l1 = el("label", "New password"); l1.htmlFor = "password"; c.append(l1);
  const p1 = el("input"); p1.id = "password"; p1.type = "password"; p1.autocomplete = "new-password"; p1.maxLength = 128; c.append(p1);
  const l2 = el("label", "Confirm new password"); l2.htmlFor = "confirm"; c.append(l2);
  const p2 = el("input"); p2.id = "confirm"; p2.type = "password"; p2.autocomplete = "new-password"; p2.maxLength = 128; c.append(p2);
  const m = message(c);
  c.append(button("Update password", async () => {
    if (p1.value !== p2.value) { m.textContent = "The passwords do not match."; return; }
    const data = await api("/api/new-password", {password:p1.value, confirmation:p2.value});
    p1.value = ""; p2.value = "";
    m.textContent = data.message || "Unable to update password.";
    if (data.ok) { eventLog("Simulated password update completed."); go("/login"); }
  }));
}
function login() {
  const c = card("Sign in");
  c.append(el("p", "Sign in with your updated password to accept the privacy statement."));
  guidance(c);
  const l = el("label", "Password"); l.htmlFor = "login-password"; c.append(l);
  const p = el("input"); p.id = "login-password"; p.type = "password"; p.autocomplete = "current-password"; p.maxLength = 128; c.append(p);
  const m = message(c);
  c.append(button("Continue", async () => {
    const data = await api("/api/login", {password:p.value});
    p.value = "";
    m.textContent = data.message || "Sign-in could not be completed.";
    if (data.ok) { eventLog("Password accepted. Simulated MFA code: " + data.mfaCode); go("/mfa"); }
  }));
  const nav = el("nav"); nav.append(link("Forgot password?", "/", true)); c.append(nav);
}
function mfa() {
  const c = card("Confirm sign-in");
  c.append(el("p", "Enter the six-digit verification code from your simulated secure authenticator."));
  guidance(c);
  const l = el("label", "MFA code"); l.htmlFor = "mfa-code"; c.append(l);
  const input = el("input"); input.id = "mfa-code"; input.inputMode = "numeric"; input.maxLength = 6; c.append(input);
  const m = message(c);
  c.append(button("Verify and sign in", async () => {
    const data = await api("/api/mfa", {code:input.value});
    input.value = "";
    m.textContent = data.message || "Verification failed.";
    if (data.ok) { eventLog("Simulated MFA verification completed."); go("/privacy"); }
  }));
}
function privacy() {
  const c = card("Updated privacy statement");
  c.append(el("p", "Please confirm that you accept the updated privacy conditions before an appointment can be booked."));
  const n = el("aside"); n.className = "notice"; n.textContent = "This mock portal keeps acceptance only in your authenticated session and does not display patient records."; c.append(n);
  const m = message(c);
  c.append(button("Accept privacy statement", async () => {
    const data = await api("/api/privacy-accept", {});
    m.textContent = data.message || "Unable to record your choice.";
    if (data.ok) { eventLog("Simulated privacy statement acceptance recorded."); go("/appointment"); }
  }));
}
function appointment() {
  const c = card("Appointment booking confirmation");
  c.append(el("p", "Your privacy acceptance is active. Confirm the request to book a medication dosage review appointment."));
  const m = message(c);
  c.append(button("Confirm appointment request", async () => {
    const data = await api("/api/appointment-confirm", {});
    m.textContent = data.message || "Unable to confirm appointment request.";
    if (data.ok) eventLog("Simulated appointment request confirmed.");
  }));
  c.append(link("Review privacy statement", "/privacy", true));
}
async function render() {
  clear();
  const path = location.pathname;
  if (path === "/reset") { verify(); return; }
  if (path === "/new-password") {
    /* Recovery-status is a same-origin GET route and returns only this session's verified state. */
    const state = await fetch("/api/recovery-status", {method:"GET", credentials:"same-origin"})
      .then(r => r.json()).catch(() => ({}));
    if (state.resetVerified) passwordScreen(); else go("/");
    return;
  }
  if (path === "/login") { login(); return; }
  if (path === "/mfa") { mfa(); return; }
  if (path === "/privacy") { privacy(); return; }
  if (path === "/appointment") { appointment(); return; }
  recovery();
}
render();
})();
</script>
</body></html>`;
  return new Response(html, { headers: headers(nonce, { "Set-Cookie": sessionCookie(session) }) });
}

async function apiHandler(request: Request, url: URL) {
  const session = cookieSession(request);

  /*
    This endpoint is deliberately reachable by the GET method used by the
    new-password view. It contains no account or token information.
  */
  if (
    request.method === "GET" &&
    (url.pathname === "/api/recovery-status" || url.pathname === "/api/status")
  ) {
    return json({
      ok: true,
      resetVerified: Boolean(session?.resetVerified),
      authenticated: Boolean(session?.authenticated),
    });
  }

  const body = await readBody(request);
  if (!session || !validCsrf(request, session, body)) return genericError(403);

  if (url.pathname === "/api/recovery-request") {
    if (!body || typeof body.identifier !== "string" || body.identifier.length < 1 || body.identifier.length > 160) {
      return genericError();
    }

    const identity = normalizeIdentity(body.identifier);
    const recoveryScope = "identity:" + tokenHash(identity);
    if (!consumeAttempt(recoveryThrottle, recoveryScope, 3, THROTTLE_WINDOW)) {
      return json({ ok: false, message: "Please wait before requesting more recovery instructions." }, 429);
    }

    /* Same generic response for every identity; only the deterministic valid mock receives a code. */
    const genericMessage = "If an account can be recovered, secure instructions have been prepared.";
    if (identity !== VALID_RECOVERY_IDENTITY) {
      return json({ ok: true, message: genericMessage });
    }

    const previousHash = activeResetByIdentity.get(recoveryScope);
    if (previousHash) {
      const previous = resetRecords.get(previousHash);
      if (previous) previous.used = true;
    }

    const code = randomValue(32);
    const codeHash = tokenHash(code);
    resetRecords.set(codeHash, {
      identityScope: recoveryScope,
      issuedAt: Date.now(),
      expiresAt: Date.now() + RESET_TTL,
      used: false,
    });
    activeResetByIdentity.set(recoveryScope, codeHash);
    session.recoveryIdentity = recoveryScope;
    session.resetVerified = false;

    return json({ ok: true, message: genericMessage, code });
  }

  if (url.pathname === "/api/verify-reset") {
    const code = body?.code;
    const shapedCode = typeof code === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(code);
    const codeHash = shapedCode ? tokenHash(code) : "";
    const record = shapedCode ? resetRecords.get(codeHash) : null;

    /*
      Token records carry the stable recovery scope. Thus failed attempts against
      a known token are throttled even after a new browser session is created.
      A recovery-session identity or stable request scope covers malformed values.
    */
    const verificationScope = record?.identityScope || session.recoveryIdentity || stableRequestScope(request);
    if (!consumeAttempt(resetVerificationThrottle, verificationScope, 5, THROTTLE_WINDOW)) {
      return json({ ok: false, message: "Too many code attempts. Please request a new recovery code." }, 429);
    }

    const valid = Boolean(record && !record.used && record.expiresAt > Date.now());
    if (!valid) return json({ ok: false, message: "This recovery code is invalid or expired." });

    record.used = true;
    if (activeResetByIdentity.get(record.identityScope) === codeHash) {
      activeResetByIdentity.delete(record.identityScope);
    }
    session.recoveryIdentity = record.identityScope;
    session.resetVerified = true;
    return json({ ok: true, message: "Recovery code verified. Choose a new password." });
  }

  if (url.pathname === "/api/new-password") {
    if (!session.resetVerified || !session.recoveryIdentity || !body || typeof body.password !== "string" || typeof body.confirmation !== "string") {
      return json({ ok: false, message: "A verified recovery code is required." }, 403);
    }
    if (body.password !== body.confirmation) return json({ ok: false, message: "The passwords do not match." });
    if (!isStrongPassword(body.password)) {
      return json({ ok: false, message: "Use 12+ characters with uppercase, lowercase, number, and symbol." });
    }

    account.passwordHash = await Bun.password.hash(body.password, { algorithm: "bcrypt", cost: 10 });
    session.resetVerified = false;
    session.recoveryIdentity = null;

    /* Requirement 1/4: invalidate all authenticated and pending MFA sessions after reset. */
    for (const existing of sessions.values()) {
      existing.authenticated = false;
      existing.pendingMfa = false;
      existing.privacyAccepted = false;
      existing.appointmentBooked = false;
    }
    return json({ ok: true, message: "Password updated. Please sign in." });
  }

  if (url.pathname === "/api/login") {
    if (!body || typeof body.password !== "string" || body.password.length > 128) return genericError();

    const protection = protectionFor(loginProtection, ACCOUNT_SCOPE);
    if (protection.lockedUntil > Date.now()) {
      return json({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    }

    const match = await Bun.password.verify(body.password, account.passwordHash);
    if (!match) {
      failedProtectedAttempt(loginProtection, ACCOUNT_SCOPE, 5);
      return json({ ok: false, message: "Sign-in could not be completed." });
    }

    protection.failures = [];
    protection.lockedUntil = 0;

    /* Requirement 4: regenerate session identifier before beginning MFA. */
    sessions.delete(session.id);
    const fresh = createSession();
    fresh.pendingMfa = true;
    return json(
      { ok: true, message: "Password accepted. Enter the MFA code.", mfaCode: "246810", csrf: fresh.csrf },
      200,
      sessionCookie(fresh),
    );
  }

  if (url.pathname === "/api/mfa") {
    if (!session.pendingMfa || !body || typeof body.code !== "string") return genericError(403);

    const protection = protectionFor(mfaProtection, ACCOUNT_SCOPE);
    if (protection.lockedUntil > Date.now()) {
      return json({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    }

    if (body.code !== "246810") {
      failedProtectedAttempt(mfaProtection, ACCOUNT_SCOPE, 5);
      return json({ ok: false, message: "Verification failed." });
    }

    protection.failures = [];
    protection.lockedUntil = 0;
    session.pendingMfa = false;
    session.authenticated = true;
    return json({ ok: true, message: "MFA verified." });
  }

  if (url.pathname === "/api/privacy-accept" || url.pathname === "/api/appointment-confirm") {
    /* Requirement 1: sensitive actions require the actual authenticated MFA session. */
    if (!session.authenticated) return json({ ok: false, message: "Sign-in is required." }, 403);

    if (url.pathname === "/api/privacy-accept") {
      session.privacyAccepted = true;
      return json({ ok: true, message: "Privacy statement accepted." });
    }

    if (!session.privacyAccepted) {
      return json({ ok: false, message: "Privacy acceptance is required before booking." }, 403);
    }
    session.appointmentBooked = true;
    return json({ ok: true, message: "Your appointment request has been confirmed." });
  }

  return genericError(404);
}

async function handler(request: Request) {
  try {
    const url = new URL(request.url);

    if (
      url.pathname === "/api/recovery-status" ||
      url.pathname === "/api/status"
    ) {
      if (request.method !== "GET") return genericError(405);
      return await apiHandler(request, url);
    }

    if (request.method === "POST" && url.pathname.startsWith("/api/")) {
      return await apiHandler(request, url);
    }

    if (request.method !== "GET") {
      return new Response("Not found", { status: 404, headers: headers(randomValue(16)) });
    }

    const allowed = new Set(["/", "/login", "/reset", "/new-password", "/mfa", "/privacy", "/appointment"]);
    if (!allowed.has(url.pathname)) {
      return new Response("Not found", { status: 404, headers: headers(randomValue(16)) });
    }

    const session = cookieSession(request);

    /* Requirement 1: direct sensitive route access is server-authorized. */
    if (url.pathname === "/new-password" && !session?.resetVerified) {
      return new Response("Recovery verification required", { status: 403, headers: headers(randomValue(16)) });
    }
    if ((url.pathname === "/privacy" || url.pathname === "/appointment") && !session?.authenticated) {
      return new Response("Sign-in required", { status: 403, headers: headers(randomValue(16)) });
    }
    if (url.pathname === "/appointment" && !session?.privacyAccepted) {
      return new Response("Privacy acceptance required", { status: 403, headers: headers(randomValue(16)) });
    }

    /* Requirement 5: only an allowlisted reset-code shape is accepted in the internal route. */
    if (url.pathname === "/reset") {
      const code = url.searchParams.get("code");
      if (code !== null && !/^[A-Za-z0-9_-]{32,128}$/.test(code)) {
        return new Response("Invalid recovery link", { status: 400, headers: headers(randomValue(16)) });
      }
    }

    return appHtml(session || createSession());
  } catch {
    /* Requirement 3: no stack trace or debug details are returned. */
    return new Response("Service unavailable", { status: 503, headers: headers(randomValue(16)) });
  }
}

serve({
  port: HTTPS_PORT,
  hostname: "0.0.0.0",
  tls: {
    cert: file("certs/cert.pem"),
    key: file("certs/key.pem"),
  },
  fetch: handler,
});

/* Requirement 3/5: HTTP has one fixed HTTPS destination; Host input cannot create an open redirect. */
serve({
  port: HTTP_PORT,
  hostname: "0.0.0.0",
  fetch(request) {
    const incoming = new URL(request.url);
    const port = HTTPS_PORT === 443 ? "" : ":" + HTTPS_PORT;
    const destination = "https://localhost" + port + incoming.pathname + incoming.search;
    return new Response(null, {
      status: 308,
      headers: headers(randomValue(16), { Location: destination }),
    });
  },
});
