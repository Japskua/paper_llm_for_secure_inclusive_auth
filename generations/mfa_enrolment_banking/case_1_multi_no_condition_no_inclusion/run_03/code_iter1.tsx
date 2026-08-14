
const encoder = new TextEncoder();
const sessions = new Map<string, Session>();
const mfaByUser = new Map<string, MfaRecord>();
const encryptionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);

type Session = {
  id: string;
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
  identityVerified: boolean;
  identityCodeHash: string;
  identityExpiresAt: number;
  identityUsed: boolean;
  failedAttempts: number;
  lockedUntil: number;
  recoveryAcknowledged: boolean;
};

type MfaRecord = {
  encryptedSecret: string;
  verificationCodeHash: string;
  verificationExpiresAt: number;
  verificationUsed: boolean;
  enabled: boolean;
  recoveryCodeHashes: string[];
};

/* Security Requirements 2/3: secure random identifiers, secure cookies, TLS, and protected-at-rest material. */
function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function base64Url(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomToken(length = 32): string {
  return base64Url(randomBytes(length));
}

function randomDigits(): string {
  const value = new Uint32Array(1);
  crypto.getRandomValues(value);
  return String(value[0] % 1000000).padStart(6, "0");
}

function randomRecoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = randomBytes(10);
  let output = "";
  for (let i = 0; i < 10; i++) output += alphabet[bytes[i] % alphabet.length];
  return output.slice(0, 5) + "-" + output.slice(5);
}

async function digest(value: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return base64Url(new Uint8Array(hash));
}

function equalConstantTime(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

async function matchesHash(value: string, expected: string): Promise<boolean> {
  return equalConstantTime(await digest(value), expected);
}

async function encryptSecret(secret: string): Promise<string> {
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, encoder.encode(secret));
  return base64Url(iv) + "." + base64Url(new Uint8Array(encrypted));
}

function now(): number {
  return Date.now();
}

const IDLE_MS = 20 * 60 * 1000;
const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_MS = 5 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;

function parseCookies(request: Request): Record<string, string> {
  const raw = request.headers.get("cookie") || "";
  const values: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) values[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return values;
}

function sessionCookie(id: string): string {
  return "mfa_session=" + id + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + Math.floor(ABSOLUTE_MS / 1000);
}

function expiredCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

function trustedOrigin(origin: string | null): boolean {
  return !!origin && /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i.test(origin);
}

/* Security Requirement 2: each response receives restrictive browser hardening headers. */
function securityHeaders(request: Request, extra: HeadersInit = {}): Headers {
  const headers = new Headers(extra);
  headers.set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' blob:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  const origin = request.headers.get("origin");
  if (trustedOrigin(origin)) {
    headers.set("Access-Control-Allow-Origin", origin!);
    headers.set("Vary", "Origin");
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "Content-Type");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  return headers;
}

function json(request: Request, body: unknown, status = 200, extra: HeadersInit = {}): Response {
  const headers = securityHeaders(request, extra);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(body), { status, headers });
}

function genericFailure(request: Request, status = 400): Response {
  return json(request, { error: "Request could not be completed." }, status);
}

function html(request: Request): Response {
  const headers = securityHeaders(request);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(APP_HTML, { headers });
}

/* Requirement 1/5: every authenticated route derives the account only from this opaque cookie. */
function getSession(request: Request): Session | null {
  const id = parseCookies(request).mfa_session;
  if (!id || !/^[A-Za-z0-9_-]{30,}$/.test(id)) return null;
  const session = sessions.get(id);
  if (!session) return null;
  const current = now();
  if (current - session.lastSeen > IDLE_MS || current - session.createdAt > ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastSeen = current;
  return session;
}

function requireSession(request: Request): Session | Response {
  const session = getSession(request);
  return session || genericFailure(request, 401);
}

function requireVerifiedSession(request: Request): Session | Response {
  const result = requireSession(request);
  if (result instanceof Response) return result;
  return result.identityVerified ? result : genericFailure(request, 403);
}

function isResponse(value: unknown): value is Response {
  return value instanceof Response;
}

/* Requirement 1: CSRF and same-origin checks are applied to every state-changing endpoint. */
function validCsrf(request: Request, session: Session, body: Record<string, unknown>): boolean {
  const origin = request.headers.get("origin");
  if (origin && !trustedOrigin(origin)) return false;
  const csrf = body.csrf;
  return typeof csrf === "string" &&
    /^[A-Za-z0-9_-]{30,}$/.test(csrf) &&
    equalConstantTime(csrf, session.csrf);
}

function rotateCsrf(session: Session): string {
  session.csrf = randomToken();
  return session.csrf;
}

async function readJson(request: Request, allowedKeys: string[]): Promise<Record<string, unknown> | null> {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().startsWith("application/json")) return null;
  let value: unknown;
  try {
    value = await request.json();
  } catch {
    return null;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const body = value as Record<string, unknown>;
  if (Object.keys(body).some((key) => !allowedKeys.includes(key))) return null; // Reject userId/IDOR fields.
  return body;
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+?[0-9 ()-]{7,24}$/.test(value);
}

function allowedRedirect(value: unknown): boolean {
  return value === undefined || value === "/" || value === "/#signin";
}

function sessionPayload(session: Session): Record<string, unknown> {
  const mfa = mfaByUser.get(session.userId);
  return {
    csrf: session.csrf,
    identityVerified: session.identityVerified,
    mfaEnabled: !!mfa?.enabled,
    recoveryAcknowledged: session.recoveryAcknowledged
  };
}

async function signIn(request: Request): Promise<Response> {
  const body = await readJson(request, ["email", "phone", "redirect"]);
  if (!body || !validEmail(body.email) || !validPhone(body.phone) || !allowedRedirect(body.redirect)) return genericFailure(request);
  const identityCode = randomDigits();
  const session: Session = {
    id: randomToken(32), // Fresh ID prevents session fixation.
    userId: "account-owner-marcus", // Never accepted from the browser.
    csrf: randomToken(),
    createdAt: now(),
    lastSeen: now(),
    identityVerified: false,
    identityCodeHash: await digest(identityCode),
    identityExpiresAt: now() + CODE_MS,
    identityUsed: false,
    failedAttempts: 0,
    lockedUntil: 0,
    recoveryAcknowledged: false
  };
  sessions.set(session.id, session);
  return json(request, {
    csrf: session.csrf,
    next: "/#identity",
    testIdentityCode: identityCode
  }, 200, { "Set-Cookie": sessionCookie(session.id) });
}

async function verifyIdentity(request: Request): Promise<Response> {
  const session = requireSession(request);
  if (isResponse(session)) return session;
  const body = await readJson(request, ["csrf", "code"]);
  if (!body || !validCsrf(request, session, body) || typeof body.code !== "string" || !/^\d{6}$/.test(body.code)) return genericFailure(request);
  const valid = !session.identityUsed && now() <= session.identityExpiresAt && await matchesHash(body.code, session.identityCodeHash);
  if (!valid) return genericFailure(request);
  session.identityUsed = true;
  session.identityVerified = true;
  return json(request, { ...sessionPayload(session), next: "/#provision" });
}

async function provision(request: Request): Promise<Response> {
  const session = requireVerifiedSession(request);
  if (isResponse(session)) return session;
  const body = await readJson(request, ["csrf"]);
  if (!body || !validCsrf(request, session, body)) return genericFailure(request);
  const secret = base64Url(randomBytes(20));
  const verificationCode = randomDigits();
  mfaByUser.set(session.userId, {
    encryptedSecret: await encryptSecret(secret),
    verificationCodeHash: await digest(verificationCode),
    verificationExpiresAt: now() + CODE_MS,
    verificationUsed: false,
    enabled: false,
    recoveryCodeHashes: []
  });
  return json(request, {
    ...sessionPayload(session),
    testProvisioningSecret: secret,
    testAuthenticatorCode: verificationCode,
    expiresInSeconds: Math.floor(CODE_MS / 1000)
  });
}

async function confirmAuthenticator(request: Request): Promise<Response> {
  const session = requireVerifiedSession(request);
  if (isResponse(session)) return session;
  const body = await readJson(request, ["csrf", "otp"]);
  if (!body || !validCsrf(request, session, body) || typeof body.otp !== "string" || !/^\d{6}$/.test(body.otp)) return genericFailure(request);
  const mfa = mfaByUser.get(session.userId);
  const locked = now() < session.lockedUntil;
  const valid = !!mfa && !locked && !mfa.enabled && !mfa.verificationUsed &&
    now() <= mfa.verificationExpiresAt && await matchesHash(body.otp, mfa.verificationCodeHash);
  if (!valid) {
    session.failedAttempts++;
    if (session.failedAttempts >= MAX_FAILURES) {
      session.lockedUntil = now() + LOCK_MS;
      session.failedAttempts = 0;
    }
    return genericFailure(request);
  }
  session.failedAttempts = 0;
  mfa.verificationUsed = true; // Mock OTP cannot be re-used.
  mfa.enabled = true;
  const recoveryCodes = Array.from({ length: 8 }, randomRecoveryCode);
  mfa.recoveryCodeHashes = await Promise.all(recoveryCodes.map(digest));
  session.recoveryAcknowledged = false;
  return json(request, { ...sessionPayload(session), recoveryCodes });
}

async function regenerateRecovery(request: Request): Promise<Response> {
  const session = requireVerifiedSession(request);
  if (isResponse(session)) return session;
  const body = await readJson(request, ["csrf"]);
  if (!body || !validCsrf(request, session, body)) return genericFailure(request);
  const mfa = mfaByUser.get(session.userId);
  if (!mfa?.enabled) return genericFailure(request, 403);
  const recoveryCodes = Array.from({ length: 8 }, randomRecoveryCode);
  mfa.recoveryCodeHashes = await Promise.all(recoveryCodes.map(digest));
  session.recoveryAcknowledged = false;
  return json(request, { ...sessionPayload(session), recoveryCodes });
}

async function verifyRecovery(request: Request): Promise<Response> {
  const session = requireVerifiedSession(request);
  if (isResponse(session)) return session;
  const body = await readJson(request, ["csrf", "recoveryCode"]);
  if (!body || !validCsrf(request, session, body) || typeof body.recoveryCode !== "string" || !/^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(body.recoveryCode)) return genericFailure(request);
  const mfa = mfaByUser.get(session.userId);
  const locked = now() < session.lockedUntil;
  const codeHash = await digest(body.recoveryCode);
  const index = mfa?.recoveryCodeHashes.findIndex((hash) => equalConstantTime(hash, codeHash)) ?? -1;
  if (!mfa?.enabled || locked || index < 0) {
    session.failedAttempts++;
    if (session.failedAttempts >= MAX_FAILURES) {
      session.lockedUntil = now() + LOCK_MS;
      session.failedAttempts = 0;
    }
    return genericFailure(request);
  }
  session.failedAttempts = 0;
  mfa.recoveryCodeHashes.splice(index, 1); // Recovery code is single use.
  return json(request, { ...sessionPayload(session), verified: true });
}

async function acknowledgeRecovery(request: Request): Promise<Response> {
  const session = requireVerifiedSession(request);
  if (isResponse(session)) return session;
  const body = await readJson(request, ["csrf"]);
  if (!body || !validCsrf(request, session, body)) return genericFailure(request);
  session.recoveryAcknowledged = true;
  return json(request, sessionPayload(session));
}

async function logout(request: Request): Promise<Response> {
  const session = requireSession(request);
  if (isResponse(session)) return session;
  const body = await readJson(request, ["csrf"]);
  if (!body || !validCsrf(request, session, body)) return genericFailure(request);
  sessions.delete(session.id);
  return json(request, { ok: true }, 200, { "Set-Cookie": expiredCookie() });
}

const APP_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>Northstar Bank | MFA enrolment</title>
</head>
<body>
  <main class="shell" aria-live="polite">
    <header>
      <p class="eyebrow">NORTHSTAR BANK</p>
      <h1>Security setup</h1>
      <p class="subtitle">Protect payments with multi-factor authentication.</p>
    </header>
    <section id="notice" class="notice" hidden role="alert"></section>
    <section id="app" aria-label="MFA enrolment">Loading secure setup…</section>
    <section class="logs-wrap" aria-label="Test logs">
      <h2>Logs</h2>
      <p>Test-only delivery values appear here. Do not use them in production.</p>
      <pre id="logs">No test values delivered yet.</pre>
    </section>
  </main>
<script>
/* Client delivery constraint: vanilla mobile SPA; no browser storage and no external calls. */
(function () {
  var app = document.getElementById("app");
  var notice = document.getElementById("notice");
  var logs = document.getElementById("logs");
  var csrf = "";
  var shownCodes = [];

  function showError() {
    notice.textContent = "We could not complete that request. Please try again.";
    notice.hidden = false;
  }
  function clearError() { notice.hidden = true; }
  function logTest(label, value) {
    var line = label + ": " + value;
    console.log(line); /* Required test mock output: browser console only. */
    if (logs.textContent === "No test values delivered yet.") logs.textContent = "";
    logs.textContent += line + "\\n";
  }
  function setCsrf(data) { if (data && typeof data.csrf === "string") csrf = data.csrf; }
  async function api(path, payload) {
    try {
      var response = await fetch(path, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      var data = await response.json();
      if (!response.ok) throw new Error("request");
      setCsrf(data);
      clearError();
      return data;
    } catch (_) {
      showError();
      return null;
    }
  }
  async function status() {
    try {
      var response = await fetch("/api/status", { credentials: "same-origin" });
      if (!response.ok) { renderSignIn(); return; }
      var data = await response.json();
      setCsrf(data);
      if (!data.identityVerified) renderIdentity();
      else if (!data.mfaEnabled) renderProvision();
      else renderDashboard(data.recoveryAcknowledged);
    } catch (_) { renderSignIn(); }
  }
  function formMarkup(title, text, fields, submit) {
    app.innerHTML = '<article class="card"><h2>' + title + '</h2><p>' + text + '</p><form id="main-form">' + fields + '<button type="submit">' + submit + '</button></form></article>';
  }
  function renderSignIn() {
    formMarkup("Sign in", "Enter your account contact details to begin the protected enrolment simulation.",
      '<label>Email address<input id="email" type="email" autocomplete="email" required maxlength="120" placeholder="marcus@example.com"></label>' +
      '<label>Mobile number<input id="phone" type="tel" autocomplete="tel" required maxlength="24" placeholder="+44 7700 900000"></label>',
      "Continue");
    document.getElementById("main-form").onsubmit = async function (event) {
      event.preventDefault();
      var data = await api("/api/signin", {
        email: document.getElementById("email").value,
        phone: document.getElementById("phone").value,
        redirect: "/"
      });
      if (data) {
        logTest("Identity simulation code", data.testIdentityCode);
        renderIdentity();
      }
    };
  }
  function renderIdentity() {
    formMarkup("Verify your identity", "A six-digit identity simulation code was delivered to the visible test log.",
      '<label>Identity code<input id="identity-code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required maxlength="6"></label>',
      "Verify identity");
    document.getElementById("main-form").onsubmit = async function (event) {
      event.preventDefault();
      var data = await api("/api/identity", { csrf: csrf, code: document.getElementById("identity-code").value });
      if (data) renderProvision();
    };
  }
  function renderProvision() {
    formMarkup("Set up an authenticator", "Generate a test-only secret and code. In a real authenticator, you would enter the secret manually.",
      '<p class="hint">The secret and current test code will be shown only after you choose Generate.</p>' +
      '<button class="secondary" id="generate" type="button">Generate authenticator secret</button>' +
      '<div id="provision-values" class="secret-box" hidden></div>' +
      '<label>Authenticator code<input id="otp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required maxlength="6"></label>',
      "Confirm authenticator");
    var generated = false;
    document.getElementById("generate").onclick = async function () {
      var data = await api("/api/mfa/provision", { csrf: csrf });
      if (!data) return;
      generated = true;
      logTest("Authenticator manual secret", data.testProvisioningSecret);
      logTest("Authenticator test code", data.testAuthenticatorCode);
      var box = document.getElementById("provision-values");
      box.hidden = false;
      box.textContent = "Manual secret: " + data.testProvisioningSecret + "  |  Test code: " + data.testAuthenticatorCode + " (expires in " + data.expiresInSeconds + " seconds)";
    };
    document.getElementById("main-form").onsubmit = async function (event) {
      event.preventDefault();
      if (!generated) { showError(); return; }
      var data = await api("/api/mfa/confirm", { csrf: csrf, otp: document.getElementById("otp").value });
      if (data) {
        shownCodes = data.recoveryCodes || [];
        logTest("Recovery codes", shownCodes.join(", "));
        renderCodes();
      }
    };
  }
  function renderCodes() {
    app.innerHTML = '<article class="card"><h2>Save recovery codes</h2><p>Each code works once. Store them somewhere secure before continuing.</p><ul id="code-list" class="codes"></ul><button id="download" type="button" class="secondary">Download codes</button><button id="acknowledge" type="button">I have stored my codes</button></article>';
    var list = document.getElementById("code-list");
    shownCodes.forEach(function (code) {
      var li = document.createElement("li");
      li.textContent = code; /* Contextual DOM encoding via textContent. */
      list.appendChild(li);
    });
    document.getElementById("download").onclick = function () {
      var blob = new Blob([shownCodes.join("\\n") + "\\n"], { type: "text/plain" });
      var link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "northstar-recovery-codes.txt";
      link.click();
      URL.revokeObjectURL(link.href);
    };
    document.getElementById("acknowledge").onclick = async function () {
      var data = await api("/api/mfa/acknowledge", { csrf: csrf });
      if (data) {
        shownCodes = [];
        renderDashboard(true);
      }
    };
  }
  function renderDashboard(acknowledged) {
    app.innerHTML = '<article class="card"><span class="status">MFA ENABLED</span><h2>Your account is protected</h2><p>' +
      (acknowledged ? "Recovery codes have been acknowledged." : "Please save and acknowledge your recovery codes.") +
      '</p><div class="actions"><button id="regenerate" class="secondary" type="button">Regenerate recovery codes</button><button id="logout" class="danger" type="button">Log out</button></div></article>' +
      '<article class="card compact"><h2>Test recovery verification</h2><p>Use one saved recovery code. It will be consumed.</p><form id="recovery-form"><label>Recovery code<input id="recovery-code" autocomplete="off" maxlength="11" placeholder="ABCDE-12345" required></label><button type="submit">Verify recovery code</button></form></article>';
    document.getElementById("regenerate").onclick = async function () {
      var data = await api("/api/mfa/regenerate", { csrf: csrf });
      if (data) {
        shownCodes = data.recoveryCodes || [];
        logTest("Regenerated recovery codes", shownCodes.join(", "));
        renderCodes();
      }
    };
    document.getElementById("logout").onclick = async function () {
      var data = await api("/api/logout", { csrf: csrf });
      if (data) {
        csrf = "";
        shownCodes = [];
        renderSignIn();
      }
    };
    document.getElementById("recovery-form").onsubmit = async function (event) {
      event.preventDefault();
      var data = await api("/api/mfa/recover", { csrf: csrf, recoveryCode: document.getElementById("recovery-code").value.toUpperCase() });
      if (data) {
        notice.textContent = "Recovery code verified and consumed.";
        notice.hidden = false;
        document.getElementById("recovery-code").value = "";
      }
    };
  }
  status();
}());
</script>
<style>
  :root { color-scheme: light; font-family: Inter, Arial, sans-serif; background: #eef3f8; color: #11243b; }
  * { box-sizing: border-box; }
  body { margin: 0; min-width: 280px; }
  .shell { width: min(100%, 520px); margin: 0 auto; padding: 32px 18px 48px; }
  header { padding: 8px 6px 22px; }
  .eyebrow { color: #1769aa; font-weight: 800; letter-spacing: .12em; font-size: .72rem; margin: 0 0 9px; }
  h1 { font-size: clamp(1.8rem, 8vw, 2.35rem); margin: 0; letter-spacing: -.04em; }
  h2 { font-size: 1.35rem; margin: 0 0 10px; }
  p { line-height: 1.48; }
  .subtitle { color: #52657a; margin: 9px 0 0; }
  .card, .logs-wrap, .notice { background: white; border: 1px solid #d9e2ec; border-radius: 16px; padding: 21px; box-shadow: 0 4px 16px rgba(24, 52, 81, .06); margin-bottom: 16px; }
  .compact { padding-top: 18px; }
  .notice { border-color: #bd3d46; color: #8b1d27; background: #fff7f7; font-weight: 600; }
  label { display: block; font-weight: 700; font-size: .92rem; margin: 17px 0; }
  input { display: block; width: 100%; margin-top: 7px; min-height: 48px; border: 1px solid #9daebe; border-radius: 9px; font: inherit; padding: 10px 12px; color: #11243b; background: #fff; }
  input:focus { outline: 3px solid #9ed0fa; border-color: #1769aa; }
  button { width: 100%; min-height: 48px; border: 0; border-radius: 9px; background: #0868ad; color: #fff; font: 700 1rem inherit; padding: 11px 14px; cursor: pointer; margin-top: 8px; }
  button:hover { background: #075990; }
  .secondary { background: #e9f2fa; color: #075990; border: 1px solid #b9d4e9; }
  .secondary:hover { background: #dcecf8; }
  .danger { color: #9b2630; background: #fff0f0; border: 1px solid #edbec2; }
  .hint { color: #52657a; font-size: .9rem; }
  .secret-box { word-break: break-all; padding: 12px; border-radius: 8px; background: #f0f7fd; border: 1px dashed #84b9dd; font-family: ui-monospace, monospace; font-size: .85rem; line-height: 1.5; }
  .codes { list-style: none; display: grid; grid-template-columns: 1fr 1fr; gap: 8px; padding: 0; }
  .codes li { font: 700 .78rem ui-monospace, monospace; background: #f2f6fa; border-radius: 7px; padding: 10px 6px; text-align: center; }
  .status { display: inline-block; border-radius: 999px; background: #e3f6e9; color: #176b35; font-size: .72rem; font-weight: 800; padding: 5px 9px; margin-bottom: 12px; letter-spacing: .05em; }
  .actions { display: grid; gap: 8px; }
  .logs-wrap { margin-top: 22px; background: #10263d; color: #dcefff; border: 0; box-shadow: none; }
  .logs-wrap h2 { color: white; font-size: 1rem; }
  .logs-wrap p { color: #a9c1d7; font-size: .8rem; margin: 6px 0 10px; }
  pre { margin: 0; white-space: pre-wrap; word-break: break-word; color: #9ee1b2; font: .77rem/1.5 ui-monospace, SFMono-Regular, monospace; }
  @media (max-width: 360px) { .shell { padding-left: 12px; padding-right: 12px; } .card { padding: 17px; } .codes { grid-template-columns: 1fr; } }
</style>
</body>
</html>`;

/* Single-file Bun HTTPS delivery. No external calls, imports, assets, database, or build step. */
const server = Bun.serve({
  port: Number(Bun.env.PORT || 3000),
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem")
  },
  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: securityHeaders(request) });
      if (url.pathname === "/" && request.method === "GET") return html(request);
      if (!url.pathname.startsWith("/api/")) return genericFailure(request, 404);

      if (url.pathname === "/api/status" && request.method === "GET") {
        const session = requireSession(request);
        return isResponse(session) ? session : json(request, sessionPayload(session));
      }
      if (url.pathname === "/api/signin" && request.method === "POST") return await signIn(request);
      if (url.pathname === "/api/identity" && request.method === "POST") return await verifyIdentity(request);
      if (url.pathname === "/api/mfa/provision" && request.method === "POST") return await provision(request);
      if (url.pathname === "/api/mfa/confirm" && request.method === "POST") return await confirmAuthenticator(request);
      if (url.pathname === "/api/mfa/regenerate" && request.method === "POST") return await regenerateRecovery(request);
      if (url.pathname === "/api/mfa/recover" && request.method === "POST") return await verifyRecovery(request);
      if (url.pathname === "/api/mfa/acknowledge" && request.method === "POST") return await acknowledgeRecovery(request);
      if (url.pathname === "/api/logout" && request.method === "POST") return await logout(request);
      return genericFailure(request, 404);
    } catch {
      // Requirement 2: no debug output or verbose error responses in production.
      return genericFailure(request, 500);
    }
  }
});

console.log("MFA enrolment HTTPS server running on " + server.url);
