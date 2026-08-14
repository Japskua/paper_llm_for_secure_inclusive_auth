
import { readFileSync } from "fs";

/*
  MFA Enrolment System
  Single-file Bun HTTPS server + mobile SPA.
  Run: bun app.ts

  Test-only mock disclosure is enabled unless NODE_ENV=production.
  Production mode never returns/logs identity codes, provisioning secrets, or TOTP values.
*/

const PORT = 3000;
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const TEST_MODE = process.env.NODE_ENV !== "production";

/* Requirement 3: startup-only cryptographic keys; no secrets are persisted. */
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt", "decrypt"],
);
const recoveryPepper = crypto.getRandomValues(new Uint8Array(32));

type Account = {
  id: string;
  email: string;
  phone: string;
};

type Session = {
  accountId: string;
  createdAt: number;
  lastSeen: number;
  csrf: string;
};

type PreAuth = {
  accountId: string;
  identityCode: string;
  expiresAt: number;
  used: boolean;
};

type IdentityFailures = {
  failedAttempts: number;
  lockedUntil: number;
};

type EncryptedSecret = {
  iv: string;
  ciphertext: string;
};

type MfaRecord = {
  active: boolean;
  secret?: EncryptedSecret;
  usedSetupCounters: Set<number>;
  failedAttempts: number;
  lockedUntil: number;
  recoveryCodes: Map<string, boolean>;
};

/*
  Requirement task: stable server-side registry. Only an exact registered
  email-and-phone pair is eligible to begin authentication.
*/
const accountRegistry = new Map<string, Account>([
  ["marcus@example.com", {
    id: "acct_4f90e2bd8bb1499ab7c5",
    email: "marcus@example.com",
    phone: "+447700900000",
  }],
  ["marcus.contractor@example.com", {
    id: "acct_b183c75bd3244014a6f9",
    email: "marcus.contractor@example.com",
    phone: "+447700900001",
  }],
]);

const sessions = new Map<string, Session>();
const preAuthSessions = new Map<string, PreAuth>();
const identityFailuresByAccount = new Map<string, IdentityFailures>();
const mfaByAccount = new Map<string, MfaRecord>();

const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
const ABSOLUTE_TIMEOUT_MS = 8 * 60 * 60 * 1000;
const PREAUTH_TIMEOUT_MS = 10 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const TOTP_STEP_MS = 30 * 1000;
const SIGNIN_MIN_RESPONSE_MS = 260;

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function secureSixDigitCode(): string {
  const values = new Uint32Array(1);
  crypto.getRandomValues(values);
  return String(values[0] % 1_000_000).padStart(6, "0");
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

function base32ToBytes(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const character of value.replace(/=+$/g, "").toUpperCase()) {
    const position = alphabet.indexOf(character);
    if (position < 0) throw new Error("Invalid base32 value");
    bits += position.toString(2).padStart(5, "0");
  }
  const output: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    output.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(output);
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
const trustedOrigins = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

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
  return json(request, {
    ok: false,
    message: "We could not complete that request. Please try again.",
  }, status);
}

function allowedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return !origin || trustedOrigins.has(origin);
}

function timingSafeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let result = 0;
  for (let i = 0; i < left.length; i++) result |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return result === 0;
}

async function waitAtLeast(startedAt: number, duration: number): Promise<void> {
  const remaining = duration - (Date.now() - startedAt);
  if (remaining > 0) await Bun.sleep(remaining);
}

/* Requirement 5: authenticated session ownership, idle and absolute expiry. */
function authenticated(request: Request): { token: string; session: Session } | null {
  const token = parseCookies(request)["__Host-session"];
  if (!token) return null;
  const session = sessions.get(token);
  const now = Date.now();
  if (!session || now - session.lastSeen > IDLE_TIMEOUT_MS || now - session.createdAt > ABSOLUTE_TIMEOUT_MS) {
    sessions.delete(token);
    return null;
  }
  session.lastSeen = now;
  return { token, session };
}

/* Requirement 1: per-session CSRF validation for every authenticated state change. */
function csrfValid(request: Request, session: Session): boolean {
  const supplied = request.headers.get("x-csrf-token") || "";
  return timingSafeEqual(supplied, session.csrf);
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" &&
    /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,120}\.[A-Za-z]{2,24}$/.test(value);
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
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
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

async function decryptSecret(encrypted: EncryptedSecret): Promise<string> {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(encrypted.iv, "base64url") },
    encryptionKey,
    Buffer.from(encrypted.ciphertext, "base64url"),
  );
  return new TextDecoder().decode(plain);
}

/*
  Requirement task: standards-compatible RFC 6238-style TOTP, generated from
  the decrypted per-account provisioning secret. There are no fixed OTP values.
*/
async function totpForCounter(secret: string, counter: number): Promise<string> {
  const counterBytes = new Uint8Array(8);
  let current = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = Number(current & 0xffn);
    current >>= 8n;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    base32ToBytes(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = signature[signature.length - 1] & 0x0f;
  const binary = (
    ((signature[offset] & 0x7f) << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3]
  ) >>> 0;
  return String(binary % 1_000_000).padStart(6, "0");
}

async function validTotpCounter(secret: string, supplied: string): Promise<number | null> {
  const currentCounter = Math.floor(Date.now() / TOTP_STEP_MS);
  for (const counter of [currentCounter - 1, currentCounter, currentCounter + 1]) {
    if (timingSafeEqual(await totpForCounter(secret, counter), supplied)) return counter;
  }
  return null;
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
      usedSetupCounters: new Set(),
      failedAttempts: 0,
      lockedUntil: 0,
      recoveryCodes: new Map(),
    };
    mfaByAccount.set(accountId, record);
  }
  return record;
}

function identityStatus(accountId: string): IdentityFailures {
  let status = identityFailuresByAccount.get(accountId);
  if (!status) {
    status = { failedAttempts: 0, lockedUntil: 0 };
    identityFailuresByAccount.set(accountId, status);
  }
  return status;
}

function locked(record: { lockedUntil: number }): boolean {
  return record.lockedUntil > Date.now();
}

function failAttempt(record: { failedAttempts: number; lockedUntil: number }): void {
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
      <input id="phone" name="phone" type="tel" autocomplete="tel" inputmode="tel" placeholder="+447700900000" maxlength="16" required>
      <button type="submit">Continue</button>
    </form>
    <p class="small testOnly">Test mode only: mock identity codes are disclosed in Logs and the browser console.</p>
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
    <p id="setupInstructions">Open an authenticator app, add an account manually, then enter this setup key.</p>
    <div id="secretBox" class="secretBox">
      <span class="small">Manual setup key</span>
      <code id="setupSecret"></code>
    </div>
    <p id="setupDetail" class="small">Account name: Northstar Bank. Type: time-based code. The setup key is shown only during this enrolment.</p>
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
    <p class="small">Mock delivery and verification messages appear here and in the browser console during test mode.</p>
    <output id="logs" aria-live="polite"></output>
  </section>
</main>

<style>
:root { color-scheme:light; font-family:Arial,sans-serif; background:#eef3f8; color:#13263b; }
* { box-sizing:border-box; } body { margin:0; min-height:100vh; }
.shell { width:min(100%,500px); margin:auto; padding:22px 16px 36px; }
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
  const TEST_MODE = ${JSON.stringify(TEST_MODE)};
  let csrf = "";
  const views = ["signinView", "identityView", "homeView", "setupView", "codesView", "recoveryView"];
  const logs = document.getElementById("logs");
  const notice = document.getElementById("notice");

  /* Requirement 2/3: sensitive state is only in JavaScript memory, never browser storage. */
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
        method, headers, credentials: "same-origin",
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
    const secretBox = document.getElementById("secretBox");
    if (TEST_MODE && result.secret) {
      secretBox.hidden = false;
      document.getElementById("setupSecret").textContent = result.secret;
      /* Test-only disclosure: no provisioning material is logged/rendered in production mode. */
      log("TEST ONLY — mock authenticator provisioning secret: " + result.secret);
      if (result.mockOtp) log("TEST ONLY — current mock authenticator code: " + result.mockOtp);
    } else {
      secretBox.hidden = true;
      document.getElementById("setupInstructions").textContent =
        "Follow the secure authenticator provisioning instructions supplied by your bank, then enter its six-digit code.";
      document.getElementById("setupDetail").textContent = "Authenticator codes change regularly.";
    }
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
    /* Recovery-code display is the intentional one-time user disclosure. */
    if (TEST_MODE) log("TEST ONLY — " + action + ": " + codes.join(", "));
    show("codesView");
  }

  async function regenerateCodes() {
    const result = await api("/api/mfa/recovery/regenerate", "POST", {}, true);
    if (result) displayCodes(result.codes, "new recovery codes issued");
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
      if (TEST_MODE && result.mockCode) log("TEST ONLY — mock identity verification code: " + result.mockCode);
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
      displayCodes(result.codes, "mock recovery codes issued");
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

  if (!TEST_MODE) document.querySelectorAll(".testOnly").forEach((node) => node.remove());
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

    /*
      Requirement task: paired registry lookup with generic, minimum-duration
      response. Invalid/unknown details never create a usable pre-auth record.
    */
    if (request.method === "POST" && url.pathname === "/api/signin") {
      const startedAt = Date.now();
      const body = await apiBody(request);
      const email = body && validEmail(body.email) ? body.email.trim().toLowerCase() : "";
      const phone = body && validPhone(body.phone) ? body.phone.trim() : "";
      const account = accountRegistry.get(email);
      const matches = !!account && timingSafeEqual(account.phone, phone);

      /* Equal-cost digest prevents a cheap valid/invalid timing distinction. */
      await sha256Text(`${email}\\u0000${phone}`);

      if (!matches || !account) {
        await waitAtLeast(startedAt, SIGNIN_MIN_RESPONSE_MS);
        return genericError(request, 401);
      }

      const preToken = randomToken();
      const identityCode = secureSixDigitCode();
      preAuthSessions.set(preToken, {
        accountId: account.id,
        identityCode,
        expiresAt: Date.now() + PREAUTH_TIMEOUT_MS,
        used: false,
      });

      await waitAtLeast(startedAt, SIGNIN_MIN_RESPONSE_MS);
      const response: Record<string, unknown> = { ok: true };
      /*
        Test-only mock delivery: server does not console.log this value. It is
        returned only to the browser's intentionally visible mock-delivery flow.
      */
      if (TEST_MODE) response.mockCode = identityCode;
      return json(request, response, 200, [
        secureCookie("__Host-preauth", preToken, PREAUTH_TIMEOUT_MS / 1000),
      ]);
    }

    /*
      Requirement task: account-level identity failures survive new sign-in
      attempts, so a fresh pre-auth cookie cannot reset a lockout.
    */
    if (request.method === "POST" && url.pathname === "/api/identity/verify") {
      const body = await apiBody(request);
      const preToken = parseCookies(request)["__Host-preauth"];
      const pending = preToken ? preAuthSessions.get(preToken) : undefined;
      if (!body || !validOtp(body.code) || !pending || pending.expiresAt < Date.now() || pending.used) {
        return genericError(request, 401);
      }

      const identityStatusForAccount = identityStatus(pending.accountId);
      if (locked(identityStatusForAccount)) return genericError(request, 429);

      if (!timingSafeEqual(body.code, pending.identityCode)) {
        failAttempt(identityStatusForAccount);
        return genericError(request, 401);
      }

      pending.used = true;
      identityStatusForAccount.failedAttempts = 0;
      preAuthSessions.delete(preToken);

      /* Requirement 5: rotate to a newly generated authenticated session identifier. */
      const sessionToken = randomToken();
      const now = Date.now();
      const session: Session = {
        accountId: pending.accountId,
        createdAt: now,
        lastSeen: now,
        csrf: randomToken(),
      };
      sessions.set(sessionToken, session);
      return json(request, { ok: true, csrf: session.csrf }, 200, [
        secureCookie("__Host-session", sessionToken, ABSOLUTE_TIMEOUT_MS / 1000),
        expiredCookie("__Host-preauth"),
      ]);
    }

    if (url.pathname.startsWith("/api/")) {
      /* Requirement 1: every MFA endpoint derives account ownership only from HttpOnly session. */
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
        record.usedSetupCounters.clear();

        const response: Record<string, unknown> = { ok: true };
        /*
          Test-only provisioning disclosure. The encrypted secret remains
          server-side; production responses deliberately contain no secret.
        */
        if (TEST_MODE) {
          response.secret = secret;
          response.mockOtp = await totpForCounter(secret, Math.floor(Date.now() / TOTP_STEP_MS));
        }
        return json(request, response);
      }

      if (url.pathname === "/api/mfa/confirm") {
        const body = await apiBody(request);
        if (!body || !validOtp(body.otp) || locked(record) || !record.secret) {
          failAttempt(record);
          return genericError(request, 401);
        }

        const secret = await decryptSecret(record.secret);
        const counter = await validTotpCounter(secret, body.otp);
        /*
          TOTP derives from the encrypted secret. A counter accepted during setup
          is consumed, preventing reuse of that verification value.
        */
        if (counter === null || record.usedSetupCounters.has(counter)) {
          failAttempt(record);
          return genericError(request, 401);
        }

        record.usedSetupCounters.add(counter);
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
        /* Requirement 3/5: individual HMAC hashes are consumed after one valid use. */
        record.recoveryCodes.set(protectedCode, true);
        record.failedAttempts = 0;
        return json(request, { ok: true });
      }

      if (url.pathname === "/api/mfa/recovery/regenerate") {
        if (!record.active || locked(record)) return genericError(request, 401);
        /* Requirement 1/3: owner-only CSRF-protected replacement invalidates all prior hashes. */
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
