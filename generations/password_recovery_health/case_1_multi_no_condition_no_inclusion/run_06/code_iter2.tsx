
const HTTPS_PORT = Number(Bun.env.HTTPS_PORT || 3000);
const HTTP_PORT = Number(Bun.env.HTTP_PORT || 3001);
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";

type RateRecord = { count: number; resetAt: number };
type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  resetVerified: boolean;
  passwordReplaced: boolean;
  mfaComplete: boolean;
  privacyAccepted: boolean;
  credentialHash?: string;
};

type ResetToken = {
  sessionId: string;
  expiresAt: number;
  used: boolean;
  attempts: number;
};

const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetToken>();
const rateLimits = new Map<string, RateRecord>();

const encoder = new TextEncoder();

/* Requirements 1, 3, 4: cryptographically random server-side session, CSRF, and token values. */
function secureToken(bytes = 32): string {
  return crypto.getRandomValues(new Uint8Array(bytes)).toBase64({ alphabet: "base64url", omitPadding: true });
}

function json(data: unknown, status = 200, extraHeaders: HeadersInit = {}): Response {
  const headers = new Headers(extraHeaders);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(data), { status, headers });
}

/* Requirement 3: defensive HTTPS/browser security headers on every application response. */
function secureHeaders(nonce?: string): Headers {
  const csp = [
    "default-src 'self'",
    `script-src 'nonce-${nonce || "none"}'`,
    `style-src 'nonce-${nonce || "none"}'`,
    "img-src 'self' data:",
    "connect-src 'self'",
    "font-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");

  return new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": csp,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store, max-age=0",
  });
}

function parseCookies(request: Request): Record<string, string> {
  const raw = request.headers.get("cookie") || "";
  const output: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) {
      output[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
    }
  }
  return output;
}

function sessionFor(request: Request): Session | undefined {
  const id = parseCookies(request).recovery_session;
  return id ? sessions.get(id) : undefined;
}

function createSession(): Session {
  const session: Session = {
    id: secureToken(32),
    csrf: secureToken(32),
    createdAt: Date.now(),
    resetVerified: false,
    passwordReplaced: false,
    mfaComplete: false,
    privacyAccepted: false,
  };
  sessions.set(session.id, session);
  return session;
}

function sessionCookie(session: Session): string {
  /* Requirement 1, 3: HttpOnly prevents JavaScript session theft; CSRF is separately bootstrapped. */
  return `recovery_session=${encodeURIComponent(session.id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`;
}

function validCsrf(request: Request, session: Session | undefined): boolean {
  const received = request.headers.get("x-csrf-token") || "";
  if (!session || received.length !== session.csrf.length) return false;
  return timingSafeEqual(received, session.csrf);
}

function timingSafeEqual(a: string, b: string): boolean {
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);
  if (aa.length !== bb.length) return false;
  let difference = 0;
  for (let i = 0; i < aa.length; i++) difference |= aa[i] ^ bb[i];
  return difference === 0;
}

/* Requirement 4: server-side in-memory throttling, keyed by opaque session/token values only. */
function consumeRateLimit(key: string, maximum: number, windowMs: number): boolean {
  const now = Date.now();
  const old = rateLimits.get(key);
  if (!old || old.resetAt <= now) {
    rateLimits.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  old.count++;
  return old.count <= maximum;
}

function parseJsonObject(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    return parseJsonObject(await request.json());
  } catch {
    return null;
  }
}

function textField(value: unknown, max: number): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > max) return null;
  return value;
}

function validRecoveryIdentifier(value: string): boolean {
  return /^[A-Za-z0-9@._ -]{3,160}$/.test(value);
}

function validResetToken(value: string): boolean {
  return /^[A-Za-z0-9_-]{40,100}$/.test(value);
}

function strongPassword(value: string): boolean {
  return value.length >= 12 &&
    value.length <= 128 &&
    !/\s/.test(value) &&
    /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /\d/.test(value) &&
    /[^A-Za-z0-9]/.test(value);
}

function cleanExpiredState(): void {
  const now = Date.now();
  for (const [token, state] of resetTokens) {
    if (state.expiresAt < now) resetTokens.delete(token);
  }
  for (const [id, session] of sessions) {
    if (session.createdAt + 30 * 60 * 1000 < now) sessions.delete(id);
  }
}

/* Requirements 1, 4: all state-changing API operations require the session's CSRF token. */
function requireSessionAndCsrf(request: Request): { session?: Session; failure?: Response } {
  const session = sessionFor(request);
  if (!session) {
    return { failure: json({ message: "Your secure session has ended. Please restart recovery." }, 401) };
  }
  if (!validCsrf(request, session)) {
    return { failure: json({ message: "This request could not be verified. Refresh the page and try again." }, 403) };
  }
  return { session };
}

async function apiRecovery(request: Request): Promise<Response> {
  const auth = requireSessionAndCsrf(request);
  if (auth.failure) return auth.failure;
  const body = await requestBody(request);
  const identifier = textField(body?.identifier, 160);

  if (!identifier || !validRecoveryIdentifier(identifier)) {
    return json({ message: "Enter a valid email address or recovery reference." }, 400);
  }

  if (!consumeRateLimit(`recovery:${auth.session!.id}`, 3, 15 * 60 * 1000)) {
    return json({ message: "Please wait before requesting another recovery message." }, 429);
  }

  /* Requirement 4: intentionally identical behavior for all identifiers prevents account enumeration. */
  const token = secureToken(32);
  resetTokens.set(token, {
    sessionId: auth.session!.id,
    expiresAt: Date.now() + 10 * 60 * 1000,
    used: false,
    attempts: 0,
  });

  return json({
    message: "If the account can be recovered, a secure recovery message has been prepared.",
    testToken: token,
  });
}

async function apiVerifyToken(request: Request): Promise<Response> {
  const auth = requireSessionAndCsrf(request);
  if (auth.failure) return auth.failure;
  const body = await requestBody(request);
  const token = textField(body?.token, 100);

  if (!token || !validResetToken(token)) {
    return json({ message: "That recovery code is not valid. Check the code and try again." }, 400);
  }

  const state = resetTokens.get(token);
  if (!state || state.sessionId !== auth.session!.id) {
    return json({ message: "That recovery code is not valid or has expired." }, 400);
  }

  if (!consumeRateLimit(`verify:${auth.session!.id}`, 6, 10 * 60 * 1000)) {
    return json({ message: "Too many code attempts. Request a new recovery message later." }, 429);
  }

  state.attempts++;
  if (state.attempts > 5 || state.used || state.expiresAt < Date.now()) {
    resetTokens.delete(token);
    return json({ message: "That recovery code has expired or can no longer be used. Request a new one." }, 400);
  }

  /* Requirement 3, 4: the opaque token is consumed once, then server session authorizes password entry. */
  state.used = true;
  auth.session!.resetVerified = true;
  return json({ message: "Recovery code confirmed." });
}

async function apiPassword(request: Request): Promise<Response> {
  const auth = requireSessionAndCsrf(request);
  if (auth.failure) return auth.failure;
  if (!auth.session!.resetVerified) {
    return json({ message: "Confirm a recovery code before creating a password." }, 403);
  }

  const body = await requestBody(request);
  const password = textField(body?.password, 128);
  const confirmation = textField(body?.confirmation, 128);

  if (!password || !confirmation || password !== confirmation) {
    return json({ message: "The password entries must match." }, 400);
  }
  if (!strongPassword(password)) {
    return json({ message: "Use 12 or more characters with uppercase, lowercase, a number, and a symbol. Do not use spaces." }, 400);
  }

  /* Requirement 4: bcrypt hash only; no plaintext credential is retained in server state. */
  auth.session!.credentialHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 10 });
  auth.session!.passwordReplaced = true;
  return json({ message: "Password updated.", demoMfaCode: "246810" });
}

async function apiMfa(request: Request): Promise<Response> {
  const auth = requireSessionAndCsrf(request);
  if (auth.failure) return auth.failure;
  if (!auth.session!.passwordReplaced) {
    return json({ message: "Create a new password before confirming the security code." }, 403);
  }

  const body = await requestBody(request);
  const code = textField(body?.code, 12);
  if (!code || !/^\d{6}$/.test(code)) {
    return json({ message: "Enter the six-digit security code." }, 400);
  }

  if (!consumeRateLimit(`mfa:${auth.session!.id}`, 5, 10 * 60 * 1000)) {
    return json({ message: "Too many incorrect attempts. Restart recovery later." }, 429);
  }

  /* Deterministic mock MFA code required by the exercise. */
  if (code !== "246810") {
    return json({ message: "That security code was not accepted." }, 400);
  }

  auth.session!.mfaComplete = true;
  return json({ message: "Security code confirmed." });
}

async function apiPrivacy(request: Request): Promise<Response> {
  const auth = requireSessionAndCsrf(request);
  if (auth.failure) return auth.failure;
  const body = await requestBody(request);

  /* Requirement 1: authorization derives exclusively from server-side session state, never request IDs. */
  if (!auth.session!.mfaComplete || body?.accepted !== true) {
    return json({ message: "Sign-in verification is required before accepting the privacy conditions." }, 403);
  }

  auth.session!.privacyAccepted = true;
  return json({ message: "Privacy conditions accepted." });
}

/* Requirement 4: a protected, throttled placeholder also covers login-attempt control without exposing login data. */
async function apiLogin(request: Request): Promise<Response> {
  const auth = requireSessionAndCsrf(request);
  if (auth.failure) return auth.failure;
  if (!consumeRateLimit(`login:${auth.session!.id}`, 5, 15 * 60 * 1000)) {
    return json({ message: "Too many sign-in attempts. Please wait before trying again." }, 429);
  }
  return json({ message: "Direct sign-in is unavailable during this recovery demonstration." }, 403);
}

function page(session: Session): Response {
  const nonce = secureToken(18);
  const headers = secureHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Set-Cookie", sessionCookie(session));

  /* Requirement 2: bootstrap contains only generated CSRF data; all browser dynamic content uses textContent. */
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
:root { color-scheme: light; --blue:#084d89; --blue-dark:#063962; --ink:#17212b; --muted:#53616e; --line:#c9d3dc; --soft:#eff6fa; --danger:#9a260f; --ok:#155b37; }
* { box-sizing:border-box; }
body { margin:0; font-family:Arial,Helvetica,sans-serif; color:var(--ink); background:#f4f7f9; line-height:1.5; }
header { background:var(--blue); color:#fff; border-bottom:5px solid #77bce8; }
.header-inner, main, footer { max-width:760px; margin:auto; padding-left:24px; padding-right:24px; }
.header-inner { padding-top:22px; padding-bottom:20px; }
.brand { margin:0; font-size:1.35rem; font-weight:700; }
.brand span { display:block; font-size:.91rem; font-weight:400; margin-top:2px; }
main { padding-top:28px; padding-bottom:30px; }
.card { background:#fff; border:1px solid var(--line); border-radius:8px; padding:28px; box-shadow:0 2px 7px #17212b12; }
h1 { font-size:1.65rem; line-height:1.22; margin:0 0 12px; }
h2 { font-size:1.06rem; margin:22px 0 7px; }
p { margin:0 0 14px; }
label { display:block; font-weight:bold; margin:18px 0 6px; }
input { width:100%; padding:12px; font:inherit; border:2px solid #8092a1; border-radius:4px; }
input:focus { outline:3px solid #a9d9f5; outline-offset:1px; border-color:var(--blue); }
button { margin-top:20px; padding:12px 18px; color:#fff; background:var(--blue); border:0; border-radius:4px; cursor:pointer; font:inherit; font-weight:bold; }
button:hover { background:var(--blue-dark); } button:disabled { opacity:.6; cursor:wait; }
.notice { padding:14px; margin:18px 0; background:var(--soft); border-left:5px solid var(--blue); }
.warning { padding:14px; margin:20px 0 0; background:#fff8e9; border-left:5px solid #b56d00; }
.status { min-height:24px; margin-top:14px; font-weight:bold; } .status.error { color:var(--danger); } .status.ok { color:var(--ok); }
.check-row { display:flex; gap:10px; align-items:flex-start; margin-top:18px; } .check-row input { width:auto; margin-top:5px; }
.logs { margin-top:24px; background:#13202b; color:#d8f0ff; border-radius:6px; padding:15px; }
.logs h2 { margin:0 0 8px; color:#fff; } #log-output { margin:0; white-space:pre-wrap; overflow-wrap:anywhere; font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace; max-height:150px; overflow:auto; }
footer { color:var(--muted); font-size:.88rem; padding-bottom:28px; }
.hidden { display:none; }
@media (max-width:550px) { .card { padding:21px; } .header-inner, main, footer { padding-left:16px; padding-right:16px; } }
</style>
</head>
<body>
<header><div class="header-inner"><p class="brand">Hospital patient portal <span>Secure account recovery</span></p></div></header>
<main>
<section class="card" aria-labelledby="screen-title">
<div id="app" aria-live="polite"></div>
</section>
<section class="logs" aria-labelledby="logs-title">
<h2 id="logs-title">Logs</h2><pre id="log-output">Ready. Simulated delivery events appear here.</pre>
</section>
</main>
<footer>Use only the verified <strong>https://localhost</strong> address. This demonstration does not contact external services.</footer>
<script nonce="${nonce}">
"use strict";
const BOOT = { csrf: "${session.csrf}" };
const app = document.getElementById("app");
const logOutput = document.getElementById("log-output");
let currentScreen = "request";
let deliveredToken = "";

function log(message) {
  console.log(message);
  logOutput.textContent += "\\n" + message;
  logOutput.scrollTop = logOutput.scrollHeight;
}
function element(tag, text, attrs) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (attrs) Object.entries(attrs).forEach(function(entry) {
    if (entry[0] === "className") node.className = entry[1];
    else node.setAttribute(entry[0], entry[1]);
  });
  return node;
}
function title(text) { return element("h1", text, { id:"screen-title" }); }
function paragraph(text) { return element("p", text); }
function statusBox() { const n = element("p", "", { className:"status", role:"alert" }); return n; }
function setStatus(node, message, bad) { node.textContent = message; node.className = "status " + (bad ? "error" : "ok"); }
function button(text) { return element("button", text, { type:"submit" }); }
function safetyGuidance() {
  const aside = element("aside", undefined, { className:"warning", "aria-label":"Account safety guidance" });
  aside.append(element("strong", "Stay safe: "), document.createTextNode("Hospital staff will never ask for your password or security code by email, phone, or text. Check that the address begins with https://localhost before continuing."));
  return aside;
}
async function api(path, payload) {
  const response = await fetch(path, {
    method:"POST",
    headers: { "Content-Type":"application/json", "X-CSRF-Token":BOOT.csrf },
    credentials:"same-origin",
    body:JSON.stringify(payload)
  });
  const data = await response.json().catch(function(){ return { message:"A secure response could not be read." }; });
  return { ok:response.ok, data:data };
}
function clearAndShow(nodes) { app.replaceChildren.apply(app, nodes); }
function formInput(labelText, type, name, autocomplete, maxLength) {
  const label = element("label", labelText, { for:name });
  const input = element("input", undefined, { id:name, name:name, type:type, autocomplete:autocomplete, maxlength:String(maxLength), required:"" });
  return { label:label, input:input };
}
function showRequest() {
  currentScreen = "request";
  const form = element("form");
  const field = formInput("Email address or recovery reference", "text", "identifier", "username", 160);
  field.input.setAttribute("pattern", "[A-Za-z0-9@._ -]{3,160}");
  field.input.setAttribute("aria-describedby", "identifier-help");
  const help = element("p", "Enter the email address or recovery reference associated with your account.", { id:"identifier-help" });
  const status = statusBox();
  form.append(field.label, field.input, help, button("Send recovery message"), status);
  form.addEventListener("submit", async function(event) {
    event.preventDefault();
    const value = field.input.value.trim();
    if (!/^[A-Za-z0-9@._ -]{3,160}$/.test(value)) {
      setStatus(status, "Enter a valid email address or recovery reference.", true); return;
    }
    const submit = form.querySelector("button"); submit.disabled = true;
    const result = await api("/api/recovery", { identifier:value });
    submit.disabled = false;
    if (!result.ok) { setStatus(status, result.data.message, true); return; }
    deliveredToken = result.data.testToken;
    const recoveryLink = location.origin + location.pathname + "?token=" + encodeURIComponent(deliveredToken);
    /* Required simulated delivery is visible only in browser console/log panel, not rendered as page content. */
    log("SIMULATED RECOVERY DELIVERY: secure code " + deliveredToken + " (valid for 10 minutes; test use only).");
    log("SIMULATED RECOVERY LINK: " + recoveryLink);
    showDelivery();
  });
  clearAndShow([title("Recover your account"), paragraph("Start a secure password recovery request. For privacy, the same confirmation is shown for every request."), form, safetyGuidance()]);
}
function showDelivery() {
  currentScreen = "delivery";
  const next = element("button", "Enter recovery code");
  next.type = "button"; next.addEventListener("click", showVerify);
  clearAndShow([title("Check your recovery message"), paragraph("If your account can be recovered, a secure message has been prepared. It contains a short-lived recovery link and code."), element("div", "For this local demonstration, the simulated delivery is printed only in the browser Logs panel and browser console.", { className:"notice" }), next, safetyGuidance()]);
}
function showVerify() {
  currentScreen = "verify";
  const form = element("form");
  const field = formInput("Recovery code", "text", "recovery-code", "one-time-code", 100);
  field.input.setAttribute("spellcheck", "false");
  field.input.value = deliveredToken || new URLSearchParams(location.search).get("token") || "";
  const status = statusBox();
  form.append(field.label, field.input, paragraph("You may use the recovery link or manually enter its code. Codes expire after 10 minutes and work once."), button("Confirm recovery code"), status);
  form.addEventListener("submit", async function(event) {
    event.preventDefault();
    const token = field.input.value.trim();
    if (!/^[A-Za-z0-9_-]{40,100}$/.test(token)) { setStatus(status, "Enter a valid recovery code.", true); return; }
    const submit = form.querySelector("button"); submit.disabled = true;
    const result = await api("/api/verify-token", { token:token });
    submit.disabled = false;
    if (!result.ok) { setStatus(status, result.data.message, true); return; }
    history.replaceState({}, "", location.pathname);
    log("Recovery code verified in this secure session.");
    showPassword();
  });
  clearAndShow([title("Confirm recovery code"), form, safetyGuidance()]);
}
function showPassword() {
  currentScreen = "password";
  const form = element("form");
  const first = formInput("New password", "password", "new-password", "new-password", 128);
  const second = formInput("Confirm new password", "password", "confirm-password", "new-password", 128);
  const status = statusBox();
  form.append(first.label, first.input, second.label, second.input, paragraph("Use at least 12 characters with uppercase and lowercase letters, a number, and a symbol. Do not use spaces."), button("Update password"), status);
  form.addEventListener("submit", async function(event) {
    event.preventDefault();
    if (first.input.value !== second.input.value) { setStatus(status, "The password entries must match.", true); return; }
    const result = await api("/api/password", { password:first.input.value, confirmation:second.input.value });
    if (!result.ok) { setStatus(status, result.data.message, true); return; }
    log("SIMULATED MFA DELIVERY: security code " + result.data.demoMfaCode + " (test code only).");
    first.input.value = ""; second.input.value = "";
    showMfa();
  });
  clearAndShow([title("Create a strong password"), form, safetyGuidance()]);
}
function showMfa() {
  currentScreen = "mfa";
  const form = element("form");
  const field = formInput("Six-digit security code", "text", "mfa-code", "one-time-code", 6);
  field.input.setAttribute("inputmode", "numeric"); field.input.setAttribute("pattern", "\\\\d{6}");
  const status = statusBox();
  form.append(field.label, field.input, paragraph("A second check protects your account. In this local demonstration, the code is in the Logs panel."), button("Verify security code"), status);
  form.addEventListener("submit", async function(event) {
    event.preventDefault();
    const code = field.input.value.trim();
    if (!/^\\d{6}$/.test(code)) { setStatus(status, "Enter the six-digit security code.", true); return; }
    const result = await api("/api/mfa", { code:code });
    if (!result.ok) { setStatus(status, result.data.message, true); return; }
    log("MFA verification completed.");
    showPrivacy();
  });
  clearAndShow([title("Verify your identity"), form, safetyGuidance()]);
}
function showPrivacy() {
  currentScreen = "privacy";
  const form = element("form");
  const check = element("input", undefined, { type:"checkbox", id:"privacy-check", required:"" });
  const checkLabel = element("label", "I have read and accept the updated privacy conditions.", { for:"privacy-check" });
  checkLabel.style.margin = "0";
  const row = element("div", undefined, { className:"check-row" });
  row.append(check, checkLabel);
  const status = statusBox();
  form.append(paragraph("Updated privacy conditions allow hospital authorities to process the appointment request after your verified sign-in."), element("div", "Your acceptance is protected by your authenticated recovery session. No patient or account identifier is shown on this page.", { className:"notice" }), row, button("Accept privacy conditions"), status);
  form.addEventListener("submit", async function(event) {
    event.preventDefault();
    if (!check.checked) { setStatus(status, "Please confirm that you accept the privacy conditions.", true); return; }
    const result = await api("/api/privacy", { accepted:true });
    if (!result.ok) { setStatus(status, result.data.message, true); return; }
    log("Privacy conditions accepted in authenticated session.");
    showComplete();
  });
  clearAndShow([title("Updated privacy conditions"), form, safetyGuidance()]);
}
function showComplete() {
  currentScreen = "complete";
  const restart = element("button", "Start over");
  restart.type = "button"; restart.addEventListener("click", function() { location.href = location.pathname; });
  clearAndShow([title("Recovery complete"), paragraph("Your password has been updated, identity verification is complete, and the updated privacy conditions have been accepted."), element("div", "You may now return to the hospital appointment process. This recovery demonstration does not make an appointment.", { className:"notice" }), restart, safetyGuidance()]);
}
if (new URLSearchParams(location.search).get("token")) showVerify(); else showRequest();
</script>
</body></html>`;
  return new Response(html, { headers });
}

async function handle(request: Request): Promise<Response> {
  cleanExpiredState();
  const url = new URL(request.url);

  if (request.method === "GET" && url.pathname === "/") {
    return page(sessionFor(request) || createSession());
  }

  if (request.method === "POST") {
    let result: Response | undefined;
    if (url.pathname === "/api/recovery") result = await apiRecovery(request);
    else if (url.pathname === "/api/verify-token") result = await apiVerifyToken(request);
    else if (url.pathname === "/api/password") result = await apiPassword(request);
    else if (url.pathname === "/api/mfa") result = await apiMfa(request);
    else if (url.pathname === "/api/privacy") result = await apiPrivacy(request);
    else if (url.pathname === "/api/login") result = await apiLogin(request);
    if (result) {
      const secured = secureHeaders();
      result.headers.forEach((value, key) => secured.set(key, value));
      return new Response(result.body, { status: result.status, headers: secured });
    }
  }

  const headers = secureHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify({ message: "Not found." }), { status: 404, headers });
}

const certificatesPresent = await Bun.file(CERT_PATH).exists() && await Bun.file(KEY_PATH).exists();

if (!certificatesPresent) {
  /* Requirement 3: fail closed; never serve the portal over unsecured HTTP. */
  console.error("TLS certificate files are unavailable. Secure portal not started.");
  process.exit(1);
}

/* Requirement 3: TLS server uses the supplied mkcert material. */
Bun.serve({
  port: HTTPS_PORT,
  tls: { cert: Bun.file(CERT_PATH), key: Bun.file(KEY_PATH) },
  fetch: handle,
});

/* Requirement 3: separate HTTP listener allows only a safe fixed-host HTTPS redirect. */
Bun.serve({
  port: HTTP_PORT,
  fetch(request) {
    const incoming = new URL(request.url);
    const target = `https://localhost:${HTTPS_PORT}${incoming.pathname}${incoming.search}`;
    const headers = secureHeaders();
    headers.set("Location", target);
    return new Response(null, { status: 308, headers });
  },
});

console.log(`Secure recovery portal: https://localhost:${HTTPS_PORT} (HTTP redirect: ${HTTP_PORT})`);
