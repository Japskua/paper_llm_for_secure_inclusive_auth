
const encoder = new TextEncoder();

type Phase = "start" | "token" | "mfa" | "password" | "signin" | "privacy" | "appointment" | "done";
type Limit = { failures: number; blockedUntil: number };

type RecoverySession = {
  id: string;
  csrf: string;
  phase: Phase;
  expiresAt: number;
  resetToken?: string;
  resetExpires?: number;
  resetUsed?: boolean;
  mfaCode?: string;
  passwordHash?: string;
  authenticated: boolean;
  privacyAccepted: boolean;
  appointmentConfirmed: boolean;
  limits: Record<string, Limit>;
};

const sessions = new Map<string, RecoverySession>();
const SESSION_COOKIE = "__Host-hospital-recovery";
const HTTPS_PORT = 3000;
const HTTP_REDIRECT_PORT = 8080;
const RESET_TTL_MS = 10 * 60 * 1000;
const RECOVERY_SESSION_TTL_MS = 15 * 60 * 1000;
const SESSION_CLEANUP_MS = 60 * 1000;
const BLOCK_MS = 60 * 1000;
const MAX_FAILURES = 5;

/* Security Requirement 3: cryptographically strong, opaque values. */
function randomValue(bytes = 32): string {
  const values = new Uint8Array(bytes);
  crypto.getRandomValues(values);
  return Buffer.from(values).toString("base64url");
}

/* Task: recovery sessions have a short, server-enforced lifetime. */
function createSession(): RecoverySession {
  return {
    id: randomValue(),
    csrf: randomValue(),
    phase: "start",
    expiresAt: Date.now() + RECOVERY_SESSION_TTL_MS,
    authenticated: false,
    privacyAccepted: false,
    appointmentConfirmed: false,
    limits: {},
  };
}

/* Task: expiry is refreshed only after verified/sensitive recovery progress. */
function refreshSession(session: RecoverySession): void {
  session.expiresAt = Date.now() + RECOVERY_SESSION_TTL_MS;
}

function removeExpiredSessions(): void {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (session.expiresAt <= now) sessions.delete(id);
  }
}

function cookieValue(request: Request, name: string): string | undefined {
  const cookie = request.headers.get("cookie") || "";
  const item = cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return item ? item.slice(name.length + 1) : undefined;
}

/* Task: session lookup rejects and deletes expired records regardless of cookie lifetime. */
function sessionFor(request: Request): { session: RecoverySession; isNew: boolean } {
  const sessionId = cookieValue(request, SESSION_COOKIE);
  const existing = sessionId ? sessions.get(sessionId) : undefined;

  if (existing && existing.expiresAt <= Date.now()) {
    sessions.delete(existing.id);
  } else if (existing) {
    return { session: existing, isNew: false };
  }

  const session = createSession();
  sessions.set(session.id, session);
  return { session, isNew: true };
}

/* Security Requirements 1 and 4: per-session throttling and CSRF checking. */
function isBlocked(session: RecoverySession, name: string): boolean {
  const limit = session.limits[name];
  return Boolean(limit && limit.blockedUntil > Date.now());
}

function failedAttempt(session: RecoverySession, name: string): void {
  const limit = session.limits[name] || { failures: 0, blockedUntil: 0 };
  limit.failures += 1;
  if (limit.failures >= MAX_FAILURES) {
    limit.failures = 0;
    limit.blockedUntil = Date.now() + BLOCK_MS;
  }
  session.limits[name] = limit;
}

function successfulAttempt(session: RecoverySession, name: string): void {
  delete session.limits[name];
}

function genericBlockedResponse(): Response {
  return json({ ok: false, message: "Please wait a moment before trying again." }, 429);
}

function csrfValid(session: RecoverySession, body: Record<string, unknown>): boolean {
  const supplied = typeof body.csrf === "string" ? body.csrf : "";
  return supplied.length === session.csrf.length &&
    supplied.length > 0 &&
    crypto.timingSafeEqual(encoder.encode(supplied), encoder.encode(session.csrf));
}

/* Security Requirement 2: strict input validation; output is never inserted as HTML. */
function validAccountInput(value: unknown): boolean {
  if (typeof value !== "string" || value.length < 3 || value.length > 254) return false;
  return /^[A-Za-z0-9@._+\- ]+$/.test(value);
}

function validToken(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(value);
}

function validMfa(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}

function passwordProblem(password: unknown, confirmation: unknown): string | null {
  if (typeof password !== "string" || typeof confirmation !== "string") return "Use a strong password.";
  if (password.length < 12 || password.length > 128) return "Use at least 12 characters.";
  if (password !== confirmation) return "The password confirmation does not match.";
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return "Use upper and lowercase letters, a number, and a symbol.";
  }
  const common = ["password", "password123", "welcome123", "qwerty123", "letmein123", "hospital123"];
  if (common.includes(password.toLowerCase()) || /^(.)\1{11,}$/.test(password)) {
    return "Choose a password that is not common or repetitive.";
  }
  return null;
}

function json(data: unknown, status = 200, extraHeaders: HeadersInit = {}): Response {
  const headers = new Headers(extraHeaders);
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers });
}

/* Security Requirement 3: restrictive transport, browser, and caching headers. */
function secureHeaders(nonce: string): Headers {
  const headers = new Headers();
  headers.set("strict-transport-security", "max-age=31536000; includeSubDomains");
  headers.set("content-security-policy",
    `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'none'; connect-src 'self'; font-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests`);
  headers.set("x-frame-options", "DENY");
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=()");
  headers.set("cache-control", "no-store, max-age=0");
  headers.set("pragma", "no-cache");
  return headers;
}

function htmlPage(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Hospital | Secure account recovery</title>
<style nonce="${nonce}">
:root{color-scheme:light;font-family:Arial,Helvetica,sans-serif;color:#152433;background:#eef4f6}
*{box-sizing:border-box} body{margin:0;min-height:100vh} header{background:#073b4c;color:white;padding:1.2rem}
.header-inner,main,footer{max-width:820px;margin:auto}.brand{font-size:1.2rem;font-weight:700}.sub{font-size:.9rem;opacity:.9;margin-top:.3rem}
main{padding:1.5rem 1rem 2rem}.card{background:#fff;border:1px solid #c8d8dc;border-radius:10px;padding:1.5rem;box-shadow:0 2px 8px #102a3020}
h1{font-size:1.55rem;margin-top:0;color:#073b4c}h2{font-size:1.1rem;color:#073b4c}p,li{line-height:1.5}
label{display:block;font-weight:700;margin:.9rem 0 .35rem}input{display:block;width:100%;max-width:540px;padding:.72rem;border:1px solid #71858a;border-radius:5px;font:inherit}
button{margin-top:1.1rem;background:#075d70;color:#fff;border:0;border-radius:5px;padding:.75rem 1.05rem;font:inherit;font-weight:700;cursor:pointer}
button:hover{background:#064b5a}button:focus,input:focus{outline:3px solid #f6bb42;outline-offset:2px}.notice{border-left:5px solid #d38b00;background:#fff7df;padding:.8rem 1rem;margin:1rem 0}.success{border-left:5px solid #16803b;background:#e9f8ed;padding:.8rem 1rem;margin:1rem 0}.message{min-height:1.5rem;color:#8b1e25;font-weight:700;margin:.75rem 0}.hint{font-size:.9rem;color:#43565c}.steps{font-size:.9rem;color:#43565c;margin-bottom:1.25rem}code{word-break:break-all;background:#edf3f4;padding:.12rem .28rem}
.logs{margin-top:1.2rem;background:#10252c;color:#d9f0e8;border-radius:8px;padding:1rem}.logs h2{color:#d9f0e8;margin-top:0}.logs pre{white-space:pre-wrap;word-break:break-word;margin:0;min-height:2em;font-size:.82rem}
footer{padding:0 1rem 2rem;color:#43565c;font-size:.84rem} .check{display:flex;gap:.55rem;align-items:flex-start;font-weight:normal}.check input{width:auto;margin-top:.2rem}
</style>
</head>
<body>
<header><div class="header-inner"><div class="brand">Local Hospital Patient Portal</div><div class="sub">Secure recovery and privacy confirmation</div></div></header>
<main>
<section class="card" aria-live="polite">
<div class="steps" id="steps">Secure account recovery</div>
<div id="app">Loading secure recovery…</div>
</section>
<section class="logs" aria-label="Simulated delivery logs"><h2>Logs</h2><pre id="logs">Waiting for secure session…</pre></section>
</main>
<footer>For your safety, use only this local hospital address. This training portal uses simulated delivery and contains no patient records.</footer>
<script nonce="${nonce}">
"use strict";
/* Deliverable: single-page client routes; all dynamic content uses textContent/value, never innerHTML. */
(function () {
  const app = document.getElementById("app");
  const logs = document.getElementById("logs");
  const steps = document.getElementById("steps");
  let csrf = "";
  let phase = "start";

  function log(message) {
    const line = "[SIMULATION] " + message;
    console.log(line);
    logs.textContent += (logs.textContent ? "\\n" : "") + line;
  }
  function element(tag, text) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function field(labelText, type, name, autocomplete) {
    const label = element("label", labelText);
    const input = document.createElement("input");
    input.type = type; input.name = name; input.id = name; input.autocomplete = autocomplete || "off";
    label.htmlFor = name;
    return { label, input };
  }
  function messageBox() { const box = element("div"); box.className = "message"; box.setAttribute("role","alert"); return box; }
  function button(text) { const b = element("button", text); b.type = "submit"; return b; }
  function clear(title, step) { app.replaceChildren(); steps.textContent = step; const h = element("h1", title); app.append(h); return h; }
  function notice() {
    const n = element("aside"); n.className = "notice";
    n.append(element("strong", "Avoid phishing. "));
    n.append(document.createTextNode("The hospital never asks for your password by email or through support contact. Verify the localhost hospital address before entering credentials."));
    app.append(n);
  }
  async function api(action, values) {
    const payload = Object.assign({}, values, { csrf: csrf });
    let response, data;
    try {
      response = await fetch("/api/" + action, {
        method: "POST", credentials: "same-origin",
        headers: {"content-type":"application/json", "accept":"application/json"},
        body: JSON.stringify(payload)
      });
      data = await response.json();
    } catch (_) {
      return {ok:false, message:"The secure service is unavailable. Please try again."};
    }
    if (data && typeof data.csrf === "string") csrf = data.csrf;
    if (data && typeof data.phase === "string") phase = data.phase;
    return data || {ok:false, message:"Please try again."};
  }
  function renderStart() {
    clear("Recover your account", "Step 1 of 6 — Start recovery");
    app.append(element("p", "Enter an account contact value to request a recovery code. For privacy, this portal gives the same response for every request."));
    notice();
    const form = document.createElement("form");
    const f = field("Account email or contact value", "text", "account", "username");
    f.input.maxLength = 254; f.input.required = true; f.input.setAttribute("pattern", "[A-Za-z0-9@._+\\\\- ]+");
    const msg = messageBox();
    form.append(f.label, f.input, msg, button("Send recovery code"));
    form.addEventListener("submit", async function(e) {
      e.preventDefault(); msg.textContent = "";
      const result = await api("recover", {account:f.input.value});
      msg.textContent = result.message || "";
      if (result.ok) {
        log("Recovery delivery simulated for this browser session. Test reset token: " + result.testToken);
        renderToken();
      }
    });
    app.append(form);
  }
  function renderToken() {
    clear("Verify recovery code", "Step 2 of 6 — Verify code");
    app.append(element("p", "Enter the recovery token delivered to this secure browser session. Tokens expire quickly and can only be used once."));
    const form = document.createElement("form");
    const f = field("Recovery token", "text", "token", "one-time-code");
    f.input.maxLength = 128; f.input.required = true;
    const msg = messageBox();
    form.append(f.label, f.input, msg, button("Verify code"));
    form.addEventListener("submit", async function(e) {
      e.preventDefault(); msg.textContent = "";
      const result = await api("verify-token", {token:f.input.value});
      if (!result.ok) { msg.textContent = result.message || "Unable to verify that code."; return; }
      log("MFA delivery simulated for this browser session. Test MFA code: " + result.testMfaCode);
      renderMfa(result.testMfaCode);
    });
    app.append(form);
  }
  function renderMfa(testCode) {
    clear("Confirm a second factor", "Step 3 of 6 — Security confirmation");
    app.append(element("p", "A second-factor code was sent through the simulated local delivery channel."));
    const hint = element("p", "Testing code displayed for this simulated exercise: " + testCode);
    hint.className = "hint"; app.append(hint);
    const form = document.createElement("form");
    const f = field("Six-digit code", "text", "mfa", "one-time-code");
    f.input.inputMode = "numeric"; f.input.maxLength = 6; f.input.required = true; f.input.pattern = "[0-9]{6}";
    const msg = messageBox();
    form.append(f.label, f.input, msg, button("Confirm code"));
    form.addEventListener("submit", async function(e) {
      e.preventDefault(); const result = await api("verify-mfa", {code:f.input.value});
      if (!result.ok) { msg.textContent = result.message || "Unable to verify that code."; return; }
      renderPassword();
    });
    app.append(form);
  }
  function renderPassword() {
    clear("Create a new password", "Step 4 of 6 — Reset password");
    app.append(element("p", "Use 12 or more characters with uppercase, lowercase, a number, and a symbol. Do not reuse a common password."));
    notice();
    const form = document.createElement("form");
    const a = field("New password", "password", "password", "new-password");
    const b = field("Confirm new password", "password", "confirmation", "new-password");
    a.input.minLength = 12; a.input.maxLength = 128; b.input.maxLength = 128;
    const msg = messageBox();
    form.append(a.label,a.input,b.label,b.input,msg,button("Save secure password"));
    form.addEventListener("submit", async function(e) {
      e.preventDefault(); const result = await api("reset-password", {password:a.input.value, confirmation:b.input.value});
      a.input.value = ""; b.input.value = "";
      if (!result.ok) { msg.textContent = result.message || "Unable to save password."; return; }
      log("Password reset completed. Password content was never logged or displayed.");
      renderSignin();
    });
    app.append(form);
  }
  function renderSignin() {
    clear("Sign in confirmation", "Step 5 of 6 — Confirm new password");
    app.append(element("p", "Confirm your new password to complete the secure sign-in. This verification is limited after repeated failures."));
    const form = document.createElement("form");
    const f = field("New password", "password", "password", "current-password");
    f.input.maxLength = 128; f.input.required = true;
    const msg = messageBox();
    form.append(f.label,f.input,msg,button("Confirm and sign in"));
    form.addEventListener("submit", async function(e) {
      e.preventDefault(); const result = await api("sign-in", {password:f.input.value}); f.input.value = "";
      if (!result.ok) { msg.textContent = result.message || "Unable to sign in."; return; }
      renderPrivacy();
    });
    app.append(form);
  }
  function renderPrivacy() {
    clear("Updated privacy conditions", "Step 6 of 6 — Privacy acceptance");
    app.append(element("p", "Please acknowledge the updated privacy conditions so hospital authorities can proceed with your appointment request."));
    const form = document.createElement("form");
    const label = element("label"); label.className = "check";
    const check = document.createElement("input"); check.type = "checkbox"; check.required = true;
    label.append(check, document.createTextNode(" I have reviewed and accept the updated privacy conditions."));
    const msg = messageBox(); form.append(label,msg,button("Accept conditions and continue"));
    form.addEventListener("submit", async function(e) {
      e.preventDefault(); const result = await api("accept-privacy", {accepted:check.checked});
      if (!result.ok) { msg.textContent = result.message || "Unable to record acceptance."; return; }
      renderAppointment();
    });
    app.append(form);
  }
  function renderAppointment() {
    clear("Book medication review", "Appointment request");
    app.append(element("p", "Your privacy conditions are accepted. Confirm a medication dosage review appointment request."));
    const form = document.createElement("form"); const msg = messageBox();
    form.append(msg,button("Confirm appointment request"));
    form.addEventListener("submit", async function(e) {
      e.preventDefault(); const result = await api("book-appointment", {});
      if (!result.ok) { msg.textContent = result.message || "Unable to confirm request."; return; }
      renderDone();
    });
    app.append(form);
  }
  function renderDone() {
    clear("Appointment request confirmed", "Complete");
    const box = element("div"); box.className = "success";
    box.textContent = "Your medication dosage review appointment request has been confirmed. No patient or appointment identifier is displayed in this portal.";
    app.append(box);
    log("Appointment request confirmation simulated securely for the authenticated browser session.");
  }
  function render() {
    const routes = {start:renderStart, token:renderToken, mfa:function(){renderMfa("Check the Logs panel");}, password:renderPassword, signin:renderSignin, privacy:renderPrivacy, appointment:renderAppointment, done:renderDone};
    (routes[phase] || renderStart)();
  }
  fetch("/api/bootstrap", {credentials:"same-origin", headers:{"accept":"application/json"}})
    .then(function(r){return r.json()}).then(function(data) {
      csrf = data.csrf; phase = data.phase || "start";
      logs.textContent = "Secure browser session established.";
      render();
    }).catch(function(){ app.textContent = "Unable to establish a secure session."; });
}());
</script>
</body></html>`;
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

async function apiHandler(request: Request, session: RecoverySession, action: string): Promise<Response> {
  if (request.method !== "POST") return json({ ok: false, message: "Request not allowed." }, 405);

  const origin = request.headers.get("origin");
  const expectedOrigin = new URL(request.url).origin;
  if (origin !== expectedOrigin) return json({ ok: false, message: "Request not allowed." }, 403);

  const body = await requestBody(request);
  if (!body || !csrfValid(session, body)) return json({ ok: false, message: "Request could not be verified." }, 403);

  if (action === "recover") {
    if (isBlocked(session, "recover")) return genericBlockedResponse();
    if (!validAccountInput(body.account)) {
      failedAttempt(session, "recover");
      return json({ ok: false, message: "If the account can be recovered, instructions will be available shortly." });
    }

    successfulAttempt(session, "recover");
    session.resetToken = randomValue(32);
    session.resetExpires = Date.now() + RESET_TTL_MS;
    session.resetUsed = false;
    session.mfaCode = undefined;
    session.phase = "token";
    refreshSession(session);

    return json({
      ok: true,
      phase: session.phase,
      testToken: session.resetToken,
      message: "If the account can be recovered, instructions are available in this secure browser session."
    });
  }

  if (action === "verify-token") {
    if (isBlocked(session, "token")) return genericBlockedResponse();

    const valid = session.phase === "token" && validToken(body.token) && session.resetToken &&
      !session.resetUsed && session.resetExpires && Date.now() <= session.resetExpires &&
      crypto.timingSafeEqual(encoder.encode(body.token), encoder.encode(session.resetToken));

    if (!valid) {
      failedAttempt(session, "token");
      return json({ ok: false, message: "That recovery code cannot be verified." });
    }

    successfulAttempt(session, "token");
    session.resetUsed = true;
    session.resetToken = undefined;
    session.resetExpires = undefined;
    session.mfaCode = "482913";
    session.phase = "mfa";
    refreshSession(session);
    return json({ ok: true, phase: session.phase, testMfaCode: session.mfaCode });
  }

  if (action === "verify-mfa") {
    if (isBlocked(session, "mfa")) return genericBlockedResponse();
    const valid = session.phase === "mfa" && validMfa(body.code) && body.code === session.mfaCode;

    if (!valid) {
      failedAttempt(session, "mfa");
      return json({ ok: false, message: "That security code cannot be verified." });
    }

    successfulAttempt(session, "mfa");
    session.mfaCode = undefined;
    session.phase = "password";
    refreshSession(session);
    return json({ ok: true, phase: session.phase });
  }

  if (action === "reset-password") {
    if (isBlocked(session, "password")) return genericBlockedResponse();
    if (session.phase !== "password") return json({ ok: false, message: "This action is not available." }, 403);

    const problem = passwordProblem(body.password, body.confirmation);
    if (problem) {
      failedAttempt(session, "password");
      return json({ ok: false, message: problem });
    }

    successfulAttempt(session, "password");
    // Security Requirement 4: bcrypt hash only; plaintext is never retained.
    session.passwordHash = await Bun.password.hash(body.password as string, { algorithm: "bcrypt", cost: 10 });
    session.phase = "signin";
    refreshSession(session);
    return json({ ok: true, phase: session.phase });
  }

  if (action === "sign-in") {
    if (isBlocked(session, "signin")) return genericBlockedResponse();

    if (session.phase !== "signin" || typeof body.password !== "string" || !session.passwordHash) {
      failedAttempt(session, "signin");
      return json({ ok: false, message: "Sign-in could not be verified." });
    }

    const verified = await Bun.password.verify(body.password, session.passwordHash);
    if (!verified) {
      failedAttempt(session, "signin");
      return json({ ok: false, message: "Sign-in could not be verified." });
    }

    successfulAttempt(session, "signin");
    session.authenticated = true;
    session.phase = "privacy";
    refreshSession(session);
    return json({ ok: true, phase: session.phase });
  }

  /* Security Requirement 1: sensitive actions use only server-owned session state. */
  if (action === "accept-privacy") {
    if (!session.authenticated || session.phase !== "privacy" || body.accepted !== true) {
      return json({ ok: false, message: "This action is not available." }, 403);
    }

    session.privacyAccepted = true;
    session.phase = "appointment";
    refreshSession(session);
    return json({ ok: true, phase: session.phase });
  }

  if (action === "book-appointment") {
    if (!session.authenticated || !session.privacyAccepted || session.phase !== "appointment") {
      return json({ ok: false, message: "This action is not available." }, 403);
    }

    session.appointmentConfirmed = true;
    session.phase = "done";
    refreshSession(session);
    return json({ ok: true, phase: session.phase });
  }

  return json({ ok: false, message: "Request not allowed." }, 404);
}

async function handler(request: Request): Promise<Response> {
  const nonce = randomValue(18);
  const headers = secureHeaders(nonce);

  try {
    const { session, isNew } = sessionFor(request);
    if (isNew) {
      headers.append(
        "set-cookie",
        `${SESSION_COOKIE}=${session.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(RECOVERY_SESSION_TTL_MS / 1000)}`
      );
    }

    const url = new URL(request.url);
    if (url.pathname === "/api/bootstrap" && request.method === "GET") {
      return json({ csrf: session.csrf, phase: session.phase }, 200, headers);
    }

    if (url.pathname.startsWith("/api/")) {
      const response = await apiHandler(request, session, url.pathname.slice(5));
      response.headers.forEach((value, name) => headers.set(name, value));
      return new Response(response.body, { status: response.status, headers });
    }

    if (url.pathname === "/" && request.method === "GET") {
      headers.set("content-type", "text/html; charset=utf-8");
      return new Response(htmlPage(nonce), { headers });
    }

    headers.set("content-type", "text/plain; charset=utf-8");
    return new Response("Not found", { status: 404, headers });
  } catch {
    /* Task: global errors receive the full no-store and browser security header set. */
    headers.set("content-type", "text/plain; charset=utf-8");
    return new Response("Service unavailable", { status: 503, headers });
  }
}

/* Task: periodically purge expired, server-side recovery records. */
setInterval(removeExpiredSessions, SESSION_CLEANUP_MS);

/* Deliverable / Security Requirement 3: TLS is mandatory. No plaintext portal starts without certificates.
   The optional HTTP listener only redirects to the fixed local HTTPS origin. */
const certFile = Bun.file("certs/cert.pem");
const keyFile = Bun.file("certs/key.pem");
const tlsAvailable = await certFile.exists() && await keyFile.exists();

if (!tlsAvailable) {
  console.error("SECURE PORTAL NOT STARTED: TLS certificates certs/cert.pem and certs/key.pem are required. Plaintext HTTP is disabled.");
  process.exitCode = 1;
} else {
  Bun.serve({
    port: HTTPS_PORT,
    hostname: "localhost",
    tls: { cert: certFile, key: keyFile },
    fetch: handler,
  });

  Bun.serve({
    port: HTTP_REDIRECT_PORT,
    hostname: "localhost",
    fetch() {
      return new Response(null, {
        status: 308,
        headers: {
          "location": `https://localhost:${HTTPS_PORT}/`,
          "cache-control": "no-store, max-age=0",
          "pragma": "no-cache",
          "x-content-type-options": "nosniff",
          "referrer-policy": "no-referrer",
        },
      });
    },
  });

  console.log(`Secure Local Hospital portal running at https://localhost:${HTTPS_PORT}/`);
}
