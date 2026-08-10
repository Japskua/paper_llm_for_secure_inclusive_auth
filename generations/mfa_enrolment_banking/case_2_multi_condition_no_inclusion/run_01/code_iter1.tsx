
import { readFileSync } from "fs";

/*
  MFA Enrolment System
  Single-file Bun HTTPS server + mobile SPA.
  Run: bun app.ts
*/

const PORT = 3000;
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";

/* Requirement 3: startup-only cryptographic keys; no secrets are persisted. */
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  true,
  ["encrypt", "decrypt"],
);
const recoveryPepper = crypto.getRandomValues(new Uint8Array(32));

type Session = {
  accountId: string;
  createdAt: number;
  lastSeen: number;
  csrf: string;
};

type PreAuth = {
  accountId: string;
  expiresAt: number;
  attempts: number;
  lockedUntil: number;
};

type EncryptedSecret = {
  iv: string;
  ciphertext: string;
};

type MfaRecord = {
  active: boolean;
  secret?: EncryptedSecret;
  setupOtp?: string;
  setupOtpExpiresAt?: number;
  setupOtpUsed?: boolean;
  failedAttempts: number;
  lockedUntil: number;
  recoveryCodes: Map<string, boolean>;
};

const sessions = new Map<string, Session>();
const preAuthSessions = new Map<string, PreAuth>();
const mfaByAccount = new Map<string, MfaRecord>();

const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
const ABSOLUTE_TIMEOUT_MS = 8 * 60 * 60 * 1000;
const PREAUTH_TIMEOUT_MS = 10 * 60 * 1000;
const OTP_TIMEOUT_MS = 5 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;

const trustedOrigins = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function bytesToBase32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const byte of bytes) bits += byte.toString(2).padStart(8, "0");
  let output = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    output += alphabet[parseInt(bits.slice(i, i + 5), 2)];
  }
  return output;
}

function secureSecret(): string {
  return bytesToBase32(crypto.getRandomValues(new Uint8Array(20)));
}

function secureRecoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  let code = "";
  for (let i = 0; i < 10; i++) code += alphabet[bytes[i] % alphabet.length];
  return `${code.slice(0, 5)}-${code.slice(5)}`;
}

function parseCookies(request: Request): Record<string, string> {
  const source = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const item of source.split(";")) {
    const index = item.indexOf("=");
    if (index > 0) result[item.slice(0, index).trim()] = item.slice(index + 1).trim();
  }
  return result;
}

function secureCookie(name: string, value: string, maxAge: number): string {
  return `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

function expiredCookie(name: string): string {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

/* Requirement 2: common production-safe security headers on every response. */
function securityHeaders(request: Request): Headers {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy":
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store, max-age=0",
  });
  const origin = request.headers.get("origin");
  if (origin && trustedOrigins.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  return headers;
}

function json(request: Request, body: unknown, status = 200, cookies: string[] = []): Response {
  const headers = securityHeaders(request);
  for (const cookie of cookies) headers.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(body), { status, headers });
}

function genericError(request: Request, status = 400): Response {
  return json(request, { ok: false, message: "We could not complete that request. Please try again." }, status);
}

function allowedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return !origin || trustedOrigins.has(origin);
}

/* Requirement 5: authenticated session ownership, idle and absolute expiry. */
function authenticated(request: Request): { token: string; session: Session } | null {
  const token = parseCookies(request)["__Host-session"];
  if (!token) return null;
  const session = sessions.get(token);
  const now = Date.now();
  if (!session || now - session.lastSeen > IDLE_TIMEOUT_MS || now - session.createdAt > ABSOLUTE_TIMEOUT_MS) {
    if (token) sessions.delete(token);
    return null;
  }
  session.lastSeen = now;
  return { token, session };
}

/* Requirement 1: per-session CSRF validation for every MFA state change. */
function csrfValid(request: Request, session: Session): boolean {
  const supplied = request.headers.get("x-csrf-token") || "";
  if (supplied.length !== session.csrf.length) return false;
  let value = 0;
  for (let i = 0; i < supplied.length; i++) value |= supplied.charCodeAt(i) ^ session.csrf.charCodeAt(i);
  return value === 0;
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,120}\.[A-Za-z]{2,24}$/.test(value);
}

function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+?[0-9]{8,15}$/.test(value);
}

function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function normaliseRecovery(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const clean = value.trim().toUpperCase();
  return /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{5}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{5}$/.test(clean)
    ? clean
    : null;
}

async function sha256Text(value: string): Promise<string> {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Buffer.from(hash).toString("base64url");
}

async function recoveryHash(code: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    recoveryPepper,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(code));
  return Buffer.from(signature).toString("base64url");
}

/* Requirement 3: AES-GCM encryption protects the TOTP provisioning secret at rest. */
async function encryptSecret(secret: string): Promise<EncryptedSecret> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encryptionKey,
    new TextEncoder().encode(secret),
  );
  return {
    iv: Buffer.from(iv).toString("base64url"),
    ciphertext: Buffer.from(encrypted).toString("base64url"),
  };
}

async function issueRecoveryCodes(record: MfaRecord): Promise<string[]> {
  const codes = Array.from({ length: 8 }, secureRecoveryCode);
  const protectedCodes = new Map<string, boolean>();
  for (const code of codes) protectedCodes.set(await recoveryHash(code), false);
  record.recoveryCodes = protectedCodes;
  return codes;
}

function recordFor(accountId: string): MfaRecord {
  let record = mfaByAccount.get(accountId);
  if (!record) {
    record = {
      active: false,
      failedAttempts: 0,
      lockedUntil: 0,
      recoveryCodes: new Map(),
    };
    mfaByAccount.set(accountId, record);
  }
  return record;
}

function locked(record: MfaRecord): boolean {
  return record.lockedUntil > Date.now();
}

function failAttempt(record: MfaRecord): void {
  record.failedAttempts++;
  if (record.failedAttempts >= MAX_FAILURES) {
    record.failedAttempts = 0;
    record.lockedUntil = Date.now() + LOCK_MS;
  }
}

function apiBody(request: Request): Promise<Record<string, unknown> | null> {
  return request.json()
    .then((body) => body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null)
    .catch(() => null);
}

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Northstar Bank | Security setup</title>
</head>
<body>
<main class="shell">
  <header>
    <div class="mark" aria-hidden="true">N</div>
    <div><p class="eyebrow">NORTHSTAR BANK</p><h1>Account security</h1></div>
  </header>

  <section id="notice" class="notice" aria-live="polite" hidden></section>

  <section id="signinView" class="card view" aria-labelledby="signinTitle">
    <p class="step">Step 1 of 3</p>
    <h2 id="signinTitle">Sign in securely</h2>
    <p>Enter your registered details. We will send an identity check to your phone.</p>
    <form id="signinForm" novalidate>
      <label for="email">Email address</label>
      <input id="email" name="email" type="email" autocomplete="email" inputmode="email" maxlength="184" required>
      <label for="phone">Mobile phone number</label>
      <input id="phone" name="phone" type="tel" autocomplete="tel" inputmode="tel" placeholder="+44 7700 900000" maxlength="16" required>
      <button type="submit">Continue</button>
    </form>
    <p class="small">For this secure demo, a mock identity code is sent only to your browser console.</p>
  </section>

  <section id="identityView" class="card view" aria-labelledby="identityTitle" hidden>
    <p class="step">Step 2 of 3</p>
    <h2 id="identityTitle">Verify your identity</h2>
    <p>Enter the six-digit code sent to your phone. The code expires in 10 minutes.</p>
    <form id="identityForm" novalidate>
      <label for="identityCode">Identity verification code</label>
      <input id="identityCode" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required>
      <button type="submit">Verify and continue</button>
    </form>
    <button class="linkButton" id="backToSignIn" type="button">Use different details</button>
  </section>

  <section id="homeView" class="card view" aria-labelledby="homeTitle" hidden>
    <p class="step">Step 3 of 3</p>
    <h2 id="homeTitle">Multi-factor authentication</h2>
    <p id="mfaStatus">Checking your security status…</p>
    <div id="homeActions"></div>
    <button class="linkButton danger" id="logoutButton" type="button">Sign out</button>
  </section>

  <section id="setupView" class="card view" aria-labelledby="setupTitle" hidden>
    <p class="step">Authenticator setup</p>
    <h2 id="setupTitle">Add your authenticator</h2>
    <p>Open an authenticator app, add an account manually, then enter this setup key.</p>
    <div class="secretBox">
      <span class="small">Manual setup key</span>
      <code id="setupSecret"></code>
    </div>
    <p class="small">Account name: Northstar Bank. Type: time-based code. The setup key is shown only during this enrolment.</p>
    <form id="setupForm" novalidate>
      <label for="setupOtp">Six-digit authenticator code</label>
      <input id="setupOtp" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required>
      <button type="submit">Confirm authenticator</button>
    </form>
    <button class="linkButton" id="cancelSetup" type="button">Cancel setup</button>
  </section>

  <section id="codesView" class="card view" aria-labelledby="codesTitle" hidden>
    <p class="step">Important</p>
    <h2 id="codesTitle">Save your recovery codes</h2>
    <p>Keep these somewhere safe. Each code works once. They will not be shown again.</p>
    <ul id="codesList" class="codes" aria-label="Recovery codes"></ul>
    <button id="savedCodes" type="button">I have saved these codes</button>
  </section>

  <section id="recoveryView" class="card view" aria-labelledby="recoveryTitle" hidden>
    <p class="step">Recovery</p>
    <h2 id="recoveryTitle">Use a recovery code</h2>
    <p>Use one of your saved recovery codes if your authenticator is unavailable.</p>
    <form id="recoveryForm" novalidate>
      <label for="recoveryCode">Recovery code</label>
      <input id="recoveryCode" type="text" autocomplete="off" maxlength="11" placeholder="ABCDE-23456" required>
      <button type="submit">Verify recovery code</button>
    </form>
    <button class="linkButton" id="backHome" type="button">Back to security settings</button>
  </section>

  <section class="logsPanel" aria-labelledby="logsTitle">
    <h2 id="logsTitle">Logs</h2>
    <p class="small">Mock delivery and verification messages appear here and in the browser console.</p>
    <output id="logs" aria-live="polite"></output>
  </section>
</main>

<style>
:root { color-scheme: light; font-family: Arial, sans-serif; background:#eef3f8; color:#13263b; }
* { box-sizing:border-box; }
body { margin:0; min-height:100vh; }
.shell { width:min(100%, 500px); margin:auto; padding:22px 16px 36px; }
header { display:flex; align-items:center; gap:12px; margin:4px 2px 22px; }
.mark { background:#075d85; color:white; border-radius:50%; width:42px; height:42px; display:grid; place-items:center; font-size:22px; font-weight:700; }
.eyebrow,.step { color:#28627d; font-size:.76rem; font-weight:700; letter-spacing:.08em; margin:0 0 4px; }
h1 { font-size:1.2rem; margin:0; } h2 { margin:0 0 12px; font-size:1.42rem; } p { line-height:1.5; }
.card,.logsPanel { background:white; border-radius:14px; padding:22px; box-shadow:0 3px 14px #18344c19; }
label { display:block; margin:18px 0 6px; font-weight:700; }
input { width:100%; min-height:48px; border:2px solid #8ca2b3; border-radius:8px; padding:10px 12px; font-size:1rem; color:#13263b; }
input:focus { outline:3px solid #86c8e8; border-color:#075d85; }
button { width:100%; min-height:48px; margin-top:20px; border:0; border-radius:8px; background:#075d85; color:white; padding:10px 14px; font-size:1rem; font-weight:700; cursor:pointer; }
button:hover { background:#034867; } button:focus-visible { outline:3px solid #ee9d37; outline-offset:2px; }
.linkButton { background:transparent; color:#075d85; text-decoration:underline; } .linkButton:hover { background:#eaf5fa; color:#034867; }
.danger { color:#a32323; } .small { font-size:.88rem; color:#496170; }
.notice { margin-bottom:14px; padding:12px 14px; border-radius:8px; background:#fff3d9; border-left:5px solid #b86b00; line-height:1.4; }
.secretBox { border:2px dashed #28627d; background:#edf8fc; border-radius:8px; padding:14px; margin:16px 0; overflow-wrap:anywhere; }
.secretBox code { display:block; font-size:1.1rem; font-weight:700; letter-spacing:.08em; margin-top:6px; }
.codes { list-style:none; padding:0; display:grid; grid-template-columns:1fr 1fr; gap:8px; }
.codes li { background:#edf8fc; border-radius:6px; padding:10px 6px; font-family:monospace; text-align:center; font-weight:700; }
.logsPanel { margin-top:18px; } output { display:block; min-height:35px; max-height:180px; overflow:auto; white-space:pre-wrap; word-break:break-word; background:#10212c; color:#d8f4ff; padding:10px; border-radius:7px; font:12px/1.45 monospace; }
@media (max-width:360px) { .shell { padding:14px 10px 25px; } .card,.logsPanel { padding:17px; } .codes { grid-template-columns:1fr; } }
</style>

<script>
(() => {
  "use strict";
  let csrf = "";
  const views = ["signinView", "identityView", "homeView", "setupView", "codesView", "recoveryView"];
  const logs = document.getElementById("logs");
  const notice = document.getElementById("notice");

  /* Requirement 2/3: all client-only sensitive state stays in JavaScript memory, never browser storage. */
  function log(message) {
    console.log(message);
    logs.textContent += "[" + new Date().toLocaleTimeString() + "] " + message + "\\n";
    logs.scrollTop = logs.scrollHeight;
  }
  function show(id) {
    views.forEach((view) => document.getElementById(view).hidden = view !== id);
    notice.hidden = true;
    window.scrollTo(0, 0);
  }
  function message(text) {
    notice.textContent = text;
    notice.hidden = false;
    window.scrollTo(0, 0);
  }
  function digits(value) { return /^[0-9]{6}$/.test(value); }
  function recovery(value) { return /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{5}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{5}$/.test(value); }

  async function api(path, method, data, protectedAction) {
    const headers = { "Content-Type": "application/json" };
    if (protectedAction) headers["X-CSRF-Token"] = csrf;
    try {
      const response = await fetch(path, {
        method,
        headers,
        credentials: "same-origin",
        body: data === undefined ? undefined : JSON.stringify(data)
      });
      const result = await response.json();
      if (!response.ok || !result.ok) throw new Error(result.message || "Request could not be completed.");
      return result;
    } catch (error) {
      message(error instanceof Error ? error.message : "Request could not be completed.");
      return null;
    }
  }

  async function loadHome() {
    const result = await api("/api/mfa", "GET");
    if (!result) { show("signinView"); return; }
    csrf = result.csrf;
    const status = document.getElementById("mfaStatus");
    const actions = document.getElementById("homeActions");
    actions.replaceChildren();
    if (result.active) {
      status.textContent = "Your authenticator is active. Recovery codes are available for emergency access.";
      const recoveryButton = document.createElement("button");
      recoveryButton.type = "button"; recoveryButton.textContent = "Use a recovery code";
      recoveryButton.addEventListener("click", () => show("recoveryView"));
      const regenerateButton = document.createElement("button");
      regenerateButton.type = "button"; regenerateButton.className = "linkButton";
      regenerateButton.textContent = "Regenerate recovery codes";
      regenerateButton.addEventListener("click", regenerateCodes);
      actions.append(recoveryButton, regenerateButton);
    } else {
      status.textContent = "Set up an authenticator before authorising protected payments.";
      const begin = document.createElement("button");
      begin.type = "button"; begin.textContent = "Set up authenticator";
      begin.addEventListener("click", beginSetup);
      actions.append(begin);
    }
    show("homeView");
  }

  async function beginSetup() {
    const result = await api("/api/mfa/enrol", "POST", {}, true);
    if (!result) return;
    document.getElementById("setupSecret").textContent = result.secret;
    /* Requirement: mock provisioning information goes to browser console and visible Logs panel only. */
    log("Mock authenticator provisioning secret: " + result.secret);
    log("Mock authenticator verification code (valid for 5 minutes): " + result.mockOtp);
    show("setupView");
  }

  function displayCodes(codes, action) {
    const list = document.getElementById("codesList");
    list.replaceChildren();
    codes.forEach((code) => {
      const item = document.createElement("li");
      item.textContent = code;
      list.appendChild(item);
    });
    log(action + ": " + codes.join(", "));
    show("codesView");
  }

  async function regenerateCodes() {
    const result = await api("/api/mfa/recovery/regenerate", "POST", {}, true);
    if (result) displayCodes(result.codes, "New mock recovery codes issued");
  }

  document.getElementById("signinForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const email = document.getElementById("email").value.trim();
    const phone = document.getElementById("phone").value.trim();
    if (!/^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,120}\\.[A-Za-z]{2,24}$/.test(email) || !/^\\+?[0-9]{8,15}$/.test(phone)) {
      message("Enter a valid email address and mobile phone number.");
      return;
    }
    const result = await api("/api/signin", "POST", { email, phone });
    if (result) {
      log("Mock identity verification code delivered to browser console: " + result.mockCode);
      show("identityView");
      document.getElementById("identityCode").focus();
    }
  });

  document.getElementById("identityForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const code = document.getElementById("identityCode").value.trim();
    if (!digits(code)) { message("Enter the six-digit verification code."); return; }
    const result = await api("/api/identity/verify", "POST", { code });
    if (result) {
      csrf = result.csrf;
      log("Identity verification succeeded.");
      await loadHome();
    }
  });

  document.getElementById("setupForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const otp = document.getElementById("setupOtp").value.trim();
    if (!digits(otp)) { message("Enter the six-digit authenticator code."); return; }
    const result = await api("/api/mfa/confirm", "POST", { otp }, true);
    if (result) {
      log("Authenticator verification succeeded. Recovery codes were generated.");
      displayCodes(result.codes, "Mock recovery codes issued");
    }
  });

  document.getElementById("recoveryForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const code = document.getElementById("recoveryCode").value.trim().toUpperCase();
    if (!recovery(code)) { message("Enter a recovery code in the format ABCDE-23456."); return; }
    const result = await api("/api/mfa/recovery/use", "POST", { code }, true);
    if (result) {
      log("Recovery code verification succeeded. That code is now invalid.");
      message("Recovery code accepted. Your account remains protected.");
      document.getElementById("recoveryCode").value = "";
    }
  });

  document.getElementById("backToSignIn").addEventListener("click", () => show("signinView"));
  document.getElementById("cancelSetup").addEventListener("click", loadHome);
  document.getElementById("backHome").addEventListener("click", loadHome);
  document.getElementById("savedCodes").addEventListener("click", loadHome);
  document.getElementById("logoutButton").addEventListener("click", async () => {
    await api("/api/logout", "POST", {}, true);
    csrf = "";
    log("Secure session signed out.");
    show("signinView");
  });

  loadHome();
})();
</script>
</body>
</html>`;

async function handle(request: Request): Promise<Response> {
  try {
    if (!allowedOrigin(request)) return genericError(request, 403);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: securityHeaders(request) });
    }

    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/") {
      const headers = securityHeaders(request);
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page, { headers });
    }

    if (request.method === "POST" && url.pathname === "/api/signin") {
      const body = await apiBody(request);
      if (!body || !validEmail(body.email) || !validPhone(body.phone)) return genericError(request);
      const accountId = await sha256Text(body.email.trim().toLowerCase());
      const preToken = randomToken();
      preAuthSessions.set(preToken, {
        accountId,
        expiresAt: Date.now() + PREAUTH_TIMEOUT_MS,
        attempts: 0,
        lockedUntil: 0,
      });
      /* Mock only; never emitted to server logs. Client intentionally logs its returned test value. */
      return json(request, { ok: true, mockCode: "135790" }, 200, [
        secureCookie("__Host-preauth", preToken, PREAUTH_TIMEOUT_MS / 1000),
      ]);
    }

    if (request.method === "POST" && url.pathname === "/api/identity/verify") {
      const body = await apiBody(request);
      const preToken = parseCookies(request)["__Host-preauth"];
      const pending = preToken ? preAuthSessions.get(preToken) : undefined;
      if (!body || !validOtp(body.code) || !pending || pending.expiresAt < Date.now() || pending.lockedUntil > Date.now()) {
        return genericError(request, 401);
      }
      if (body.code !== "135790") {
        pending.attempts++;
        if (pending.attempts >= MAX_FAILURES) {
          pending.attempts = 0;
          pending.lockedUntil = Date.now() + LOCK_MS;
        }
        return genericError(request, 401);
      }

      /* Requirement 5: session identifier is newly generated after authentication. */
      preAuthSessions.delete(preToken);
      const sessionToken = randomToken();
      const session: Session = {
        accountId: pending.accountId,
        createdAt: Date.now(),
        lastSeen: Date.now(),
        csrf: randomToken(),
      };
      sessions.set(sessionToken, session);
      return json(request, { ok: true, csrf: session.csrf }, 200, [
        secureCookie("__Host-session", sessionToken, ABSOLUTE_TIMEOUT_MS / 1000),
        expiredCookie("__Host-preauth"),
      ]);
    }

    if (url.pathname.startsWith("/api/")) {
      const auth = authenticated(request);
      if (!auth) return genericError(request, 401);
      const { token, session } = auth;
      const record = recordFor(session.accountId);

      if (request.method === "GET" && url.pathname === "/api/mfa") {
        return json(request, { ok: true, csrf: session.csrf, active: record.active });
      }

      if (request.method !== "POST" || !csrfValid(request, session)) return genericError(request, 403);

      if (url.pathname === "/api/logout") {
        sessions.delete(token);
        return json(request, { ok: true }, 200, [expiredCookie("__Host-session")]);
      }

      if (url.pathname === "/api/mfa/enrol") {
        if (record.active || locked(record)) return genericError(request, 429);
        const secret = secureSecret();
        record.secret = await encryptSecret(secret);
        record.setupOtp = "654321";
        record.setupOtpExpiresAt = Date.now() + OTP_TIMEOUT_MS;
        record.setupOtpUsed = false;
        return json(request, { ok: true, secret, mockOtp: "654321" });
      }

      if (url.pathname === "/api/mfa/confirm") {
        const body = await apiBody(request);
        if (!body || !validOtp(body.otp) || locked(record) || !record.secret || !record.setupOtp ||
          record.setupOtpUsed || !record.setupOtpExpiresAt || record.setupOtpExpiresAt < Date.now() ||
          body.otp !== record.setupOtp) {
          failAttempt(record);
          return genericError(request, 401);
        }
        /* Requirement 5: setup OTP is time-bound and single-use. */
        record.setupOtpUsed = true;
        record.setupOtp = undefined;
        record.active = true;
        record.failedAttempts = 0;
        const codes = await issueRecoveryCodes(record);
        return json(request, { ok: true, codes });
      }

      if (url.pathname === "/api/mfa/recovery/use") {
        const body = await apiBody(request);
        const code = body ? normaliseRecovery(body.code) : null;
        if (!record.active || !code || locked(record)) {
          failAttempt(record);
          return genericError(request, 401);
        }
        const protectedCode = await recoveryHash(code);
        const alreadyUsed = record.recoveryCodes.get(protectedCode);
        if (alreadyUsed === undefined || alreadyUsed) {
          failAttempt(record);
          return genericError(request, 401);
        }
        /* Requirement 3/5: individual server-side hashes, consumed after one valid use. */
        record.recoveryCodes.set(protectedCode, true);
        record.failedAttempts = 0;
        return json(request, { ok: true });
      }

      if (url.pathname === "/api/mfa/recovery/regenerate") {
        if (!record.active || locked(record)) return genericError(request, 401);
        /* Requirement 1/3: owner-only, CSRF-protected replacement invalidates all prior hashes. */
        const codes = await issueRecoveryCodes(record);
        return json(request, { ok: true, codes });
      }

      return genericError(request, 404);
    }

    return genericError(request, 404);
  } catch {
    /* Requirement 2: intentionally generic production error; no stacks or sensitive values. */
    return genericError(request, 500);
  }
}

/* Requirement 3: HTTPS-only Bun server using the provided localhost mkcert files. */
const cert = readFileSync(CERT_PATH);
const key = readFileSync(KEY_PATH);

Bun.serve({
  port: PORT,
  tls: { cert, key },
  fetch: handle,
});

console.log(`MFA enrolment server listening securely at https://localhost:${PORT}`);
