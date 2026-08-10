
import { readFileSync } from "node:fs";

/*
  MFA Enrolment System
  Security control references:
  [1] Access control / CSRF
  [2] Secure headers / TLS / CORS
  [3] Cryptographic storage and secure generation
  [4] Server-side validation and safe output
  [5] Session lifecycle, expiry, rate limiting, lockouts
*/

const cert = readFileSync("certs/cert.pem", "utf8");
const key = readFileSync("certs/key.pem", "utf8");

const encoder = new TextEncoder();
const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_LIFETIME_MS = 5 * 60 * 1000;
const LOCK_WINDOW_MS = 10 * 60 * 1000;
const LOCK_DURATION_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const COOKIE_NAME = "__Host-mfa_session";
const INTERNAL_ROUTES = new Set(["signin", "setup", "verify", "backup", "confirmed", "settings"]);

type AttemptState = {
  count: number;
  windowStart: number;
  lockedUntil: number;
};

type ProtectedRecoveryCode = {
  salt: string;
  hash: string;
  used: boolean;
};

type MfaRecord = {
  protectedSecret?: { iv: string; ciphertext: string };
  provisioning?: {
    otpHash: string;
    expiresAt: number;
    used: boolean;
  };
  enabled: boolean;
  recoveryCodes: ProtectedRecoveryCode[];
  otpAttempts: AttemptState;
  recoveryAttempts: AttemptState;
};

type Session = {
  id: string;
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
};

const sessions = new Map<string, Session>();
const mfaRecords = new Map<string, MfaRecord>();
const masterKeyBytes = crypto.getRandomValues(new Uint8Array(32));
const encryptionKey = await crypto.subtle.importKey(
  "raw",
  masterKeyBytes,
  { name: "AES-GCM" },
  false,
  ["encrypt"],
);

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function randomToken(length = 32): string {
  return base64Url(randomBytes(length));
}

function secureDigits(length: number): string {
  let result = "";
  while (result.length < length) {
    const values = randomBytes(24);
    for (const value of values) {
      if (value < 250) result += String(value % 10);
      if (result.length === length) break;
    }
  }
  return result;
}

function randomBase32(length: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "";
  while (result.length < length) {
    const values = randomBytes(32);
    for (const value of values) {
      if (value < 224) result += alphabet[value % 32];
      if (result.length === length) break;
    }
  }
  return result;
}

function createRecoveryCode(): string {
  const raw = randomBase32(12);
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
}

async function sha256(value: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Buffer.from(hash).toString("hex");
}

/* [3] PBKDF2-protected recovery-code storage; raw values are never retained server-side. */
async function hashRecoveryCode(rawCode: string, salt = base64Url(randomBytes(16))): Promise<ProtectedRecoveryCode> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(rawCode),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: encoder.encode(salt),
      iterations: 210000,
      hash: "SHA-256",
    },
    keyMaterial,
    256,
  );
  return { salt, hash: Buffer.from(bits).toString("hex"), used: false };
}

async function matchesRecoveryCode(rawCode: string, protectedCode: ProtectedRecoveryCode): Promise<boolean> {
  const calculated = await hashRecoveryCode(rawCode, protectedCode.salt);
  const a = Buffer.from(calculated.hash, "hex");
  const b = Buffer.from(protectedCode.hash, "hex");
  if (a.length !== b.length) return false;
  let different = 0;
  for (let i = 0; i < a.length; i++) different |= a[i] ^ b[i];
  return different === 0;
}

async function encryptSecret(secret: string): Promise<{ iv: string; ciphertext: string }> {
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encryptionKey,
    encoder.encode(secret),
  );
  return { iv: base64Url(iv), ciphertext: base64Url(new Uint8Array(encrypted)) };
}

function initialAttempts(): AttemptState {
  return { count: 0, windowStart: Date.now(), lockedUntil: 0 };
}

function getMfaRecord(userId: string): MfaRecord {
  let record = mfaRecords.get(userId);
  if (!record) {
    record = {
      enabled: false,
      recoveryCodes: [],
      otpAttempts: initialAttempts(),
      recoveryAttempts: initialAttempts(),
    };
    mfaRecords.set(userId, record);
  }
  return record;
}

function cookieValue(request: Request, name: string): string | undefined {
  const raw = request.headers.get("cookie") || "";
  const pair = raw.split(";").map((item) => item.trim()).find((item) => item.startsWith(`${name}=`));
  return pair ? pair.slice(name.length + 1) : undefined;
}

/* [5] Session expiry is checked server-side on every protected request. */
function getSession(request: Request): Session | null {
  const id = cookieValue(request, COOKIE_NAME);
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;

  const now = Date.now();
  if (now > session.expiresAt || now - session.lastSeenAt > SESSION_IDLE_MS) {
    sessions.delete(id);
    return null;
  }

  session.lastSeenAt = now;
  return session;
}

function sessionCookie(id: string): string {
  return `${COOKIE_NAME}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}

function expiredCookie(): string {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

function trustedOrigin(origin: string | null): boolean {
  if (!origin) return true;
  return /^https:\/\/localhost(?::\d+)?$/.test(origin);
}

/* [2] Shared hardened response headers and localhost-only CORS policy. */
function secureHeaders(request: Request, contentType: string): Headers {
  const headers = new Headers({
    "Content-Type": contentType,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });

  const origin = request.headers.get("origin");
  if (origin && trustedOrigin(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}

function json(request: Request, status: number, value: unknown, extra?: HeadersInit): Response {
  const headers = secureHeaders(request, "application/json; charset=utf-8");
  if (extra) {
    for (const [key, value] of new Headers(extra)) headers.set(key, value);
  }
  return new Response(JSON.stringify(value), { status, headers });
}

function genericError(request: Request, status = 400): Response {
  return json(request, status, { ok: false, message: "The request could not be completed." });
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+[1-9]\d{7,14}$/.test(value);
}

function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function canonicalRecoveryCode(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toUpperCase();
  return /^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$/.test(normalized) ? normalized : null;
}

function validRedirect(value: unknown): boolean {
  return value === undefined || value === null || (typeof value === "string" && INTERNAL_ROUTES.has(value));
}

async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

/* [1] All MFA routes obtain account identity only from authenticated HttpOnly session. */
function authorized(request: Request): Session | null {
  return getSession(request);
}

/* [1] State-changing routes require matching per-session CSRF header and trusted origin. */
function csrfValid(request: Request, session: Session): boolean {
  const token = request.headers.get("x-csrf-token");
  return Boolean(token && token === session.csrf && trustedOrigin(request.headers.get("origin")));
}

function lockStatus(attempts: AttemptState): boolean {
  return Date.now() < attempts.lockedUntil;
}

function recordFailure(attempts: AttemptState): void {
  const now = Date.now();
  if (now - attempts.windowStart > LOCK_WINDOW_MS) {
    attempts.count = 0;
    attempts.windowStart = now;
  }
  attempts.count += 1;
  if (attempts.count >= MAX_FAILURES) {
    attempts.lockedUntil = now + LOCK_DURATION_MS;
    attempts.count = 0;
    attempts.windowStart = now;
  }
}

function resetAttempts(attempts: AttemptState): void {
  attempts.count = 0;
  attempts.windowStart = Date.now();
  attempts.lockedUntil = 0;
}

async function createBackupCodes(record: MfaRecord): Promise<string[]> {
  const codes = Array.from({ length: 8 }, createRecoveryCode);
  record.recoveryCodes = await Promise.all(codes.map((code) => hashRecoveryCode(code)));
  return codes;
}

function publicState(session: Session): object {
  const record = getMfaRecord(session.userId);
  return {
    ok: true,
    user: { displayName: "Marcus" },
    csrf: session.csrf,
    mfa: {
      enabled: record.enabled,
      hasRecoveryCodes: record.recoveryCodes.length > 0,
      provisioningPending: Boolean(record.provisioning),
    },
  };
}

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Northstar Bank — MFA enrolment</title>
<style>
:root { color-scheme: light; --navy:#11284a; --blue:#1769d1; --pale:#eef5ff; --line:#d8e1ee; --text:#172033; --muted:#5b6880; --danger:#a52626; --ok:#17653a; }
* { box-sizing:border-box; }
body { margin:0; background:#f4f7fb; color:var(--text); font-family:Arial,sans-serif; font-size:16px; line-height:1.45; }
main { max-width:560px; min-height:100vh; margin:auto; background:white; padding:20px 18px 34px; }
header { border-bottom:1px solid var(--line); padding-bottom:16px; margin-bottom:22px; }
.brand { color:var(--navy); font-weight:800; font-size:1.15rem; letter-spacing:.02em; }
.eyebrow { color:var(--blue); font-size:.82rem; font-weight:700; text-transform:uppercase; letter-spacing:.08em; margin:16px 0 4px; }
h1 { color:var(--navy); font-size:1.65rem; line-height:1.18; margin:0; }
h2 { color:var(--navy); font-size:1.15rem; margin:0 0 10px; }
p { margin:8px 0; } .muted { color:var(--muted); }
.card { background:#fff; border:1px solid var(--line); border-radius:12px; padding:16px; margin:14px 0; }
.notice { background:var(--pale); border-left:4px solid var(--blue); padding:12px; border-radius:5px; margin:14px 0; }
.success { background:#effaf3; border-left:4px solid var(--ok); padding:12px; border-radius:5px; }
.error { color:var(--danger); font-weight:700; min-height:1.4em; }
label { font-weight:700; display:block; margin:13px 0 5px; }
input { font:inherit; width:100%; border:1px solid #9ba9bc; border-radius:8px; padding:12px; background:#fff; }
button, .button { font:inherit; font-weight:700; cursor:pointer; border-radius:8px; padding:12px 15px; margin-top:14px; border:1px solid var(--blue); background:var(--blue); color:#fff; width:100%; text-align:center; display:block; text-decoration:none; }
button.secondary, .button.secondary { background:#fff; color:var(--blue); }
button.danger { background:#a52626; border-color:#a52626; }
button:focus, input:focus, a:focus { outline:3px solid #f1b94d; outline-offset:2px; }
code.secret { overflow-wrap:anywhere; display:block; padding:10px; margin-top:8px; border-radius:7px; background:#f2f5f8; font-size:.9rem; }
ul.codes { list-style:none; padding:0; margin:10px 0; columns:2; }
ul.codes li { font-family:monospace; font-weight:bold; padding:6px 2px; }
.logs { margin-top:25px; padding-top:14px; border-top:1px solid var(--line); }
.logs pre { white-space:pre-wrap; word-break:break-word; background:#101c2e; color:#dce9ff; border-radius:8px; padding:10px; min-height:42px; font-size:.78rem; }
.navlink { color:var(--blue); font-weight:700; display:inline-block; margin-top:14px; }
.small { font-size:.88rem; }
@media (max-width:380px) { main { padding:16px 14px 28px; } ul.codes { columns:1; } h1 { font-size:1.45rem; } }
</style>
</head>
<body>
<main id="app" aria-live="polite">Loading secure enrolment…</main>
<script>
(() => {
  "use strict";
  let csrf = "";
  let accountState = null;
  let backupCodes = null;
  let provision = null;
  let visibleLogs = [];
  const app = document.getElementById("app");

  function log(message) {
    console.log(message);
    visibleLogs.push(message);
    const panel = document.getElementById("log-output");
    if (panel) panel.textContent = visibleLogs.join("\\n");
  }

  async function api(path, method = "GET", data) {
    const headers = { "Accept": "application/json" };
    if (method !== "GET") {
      headers["Content-Type"] = "application/json";
      headers["X-CSRF-Token"] = csrf;
    }
    const response = await fetch(path, {
      method, headers, credentials:"same-origin",
      body: data === undefined ? undefined : JSON.stringify(data)
    });
    let result;
    try { result = await response.json(); } catch { result = { ok:false, message:"The request could not be completed." }; }
    if (response.status === 401) {
      csrf = ""; accountState = null;
      location.hash = "#/signin";
    }
    return { response, result };
  }

  function route() {
    const value = location.hash.replace(/^#\\/?/, "");
    return ["signin","setup","verify","backup","confirmed","settings"].includes(value) ? value : (accountState ? "settings" : "signin");
  }

  function setError(text) {
    const el = document.getElementById("form-error");
    if (el) el.textContent = text || "";
  }

  function shell(title, subtitle) {
    app.innerHTML =
      '<header><div class="brand">NORTHSTAR BANK</div><div class="eyebrow">Security centre</div><h1></h1><p class="muted"></p></header>' +
      '<section id="screen"></section>' +
      '<section class="logs" aria-label="Simulation logs"><h2>Logs</h2><p class="small muted">Authorized simulation output is mirrored here.</p><pre id="log-output"></pre></section>';
    app.querySelector("h1").textContent = title;
    app.querySelector("header p").textContent = subtitle;
    document.getElementById("log-output").textContent = visibleLogs.join("\\n");
    return document.getElementById("screen");
  }

  function signinView() {
    const screen = shell("Sign in and verify identity", "Enrol MFA before approving higher-value payments.");
    screen.innerHTML =
      '<div class="notice"><strong>Demo identity check:</strong> use any valid email, an international phone number, and identity code <strong>654321</strong>.</div>' +
      '<form id="signin-form" novalidate><label for="email">Email address</label><input id="email" type="email" autocomplete="email" maxlength="254" required>' +
      '<label for="phone">Mobile number</label><input id="phone" type="tel" inputmode="tel" placeholder="+15551234567" autocomplete="tel" required>' +
      '<label for="identity">Identity verification code</label><input id="identity" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required>' +
      '<p id="form-error" class="error" role="alert"></p><button type="submit">Verify and continue</button></form>';
    document.getElementById("signin-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      setError("");
      const data = {
        email: document.getElementById("email").value.trim(),
        phone: document.getElementById("phone").value.trim(),
        identityCode: document.getElementById("identity").value.trim(),
        redirect: "setup"
      };
      const { response, result } = await api("/api/signin", "POST", data);
      if (!response.ok || !result.ok) return setError("We could not verify those details.");
      csrf = result.csrf;
      accountState = result;
      log("Identity verification simulation completed for the authenticated account.");
      location.hash = "#/setup";
    });
  }

  function setupView() {
    if (!accountState) return signinView();
    const screen = shell("Set up your authenticator", "Use an authenticator app to generate time-based verification codes.");
    if (!provision) {
      screen.innerHTML =
        '<div class="card"><h2>Authenticator app</h2><p>Generate a protected setup secret, then add it manually to your preferred authenticator app.</p>' +
        '<p class="small muted">This demonstration supplies a temporary mock verification code after setup. It expires in five minutes and can be used once.</p>' +
        '<p id="form-error" class="error" role="alert"></p><button id="provision-button">Generate setup secret</button></div>' +
        '<a class="navlink" href="#/settings">Back to MFA settings</a>';
      document.getElementById("provision-button").addEventListener("click", async () => {
        const { response, result } = await api("/api/mfa/provision", "POST", {});
        if (!response.ok || !result.ok) return setError("The setup request could not be completed.");
        provision = result;
        log("Authenticator provisioning simulation — manual secret: " + result.manualSecret);
        log("Authenticator provisioning simulation — temporary OTP: " + result.verificationCode);
        render();
      });
      return;
    }
    screen.innerHTML =
      '<div class="success"><strong>Setup secret generated.</strong> Enter this secret manually in an authenticator app. Keep it private.</div>' +
      '<div class="card"><h2>Manual setup secret</h2><code class="secret" id="manual-secret"></code><p class="small muted">For this simulation, the temporary verification code is available in the Logs panel and browser console.</p>' +
      '<a class="button" href="#/verify">I have added the secret</a></div>' +
      '<a class="navlink" href="#/settings">Cancel and return to settings</a>';
    document.getElementById("manual-secret").textContent = provision.manualSecret;
  }

  function verifyView() {
    if (!accountState) return signinView();
    const screen = shell("Confirm your authenticator", "Enter the six-digit code generated during setup.");
    screen.innerHTML =
      '<form id="otp-form" novalidate><label for="otp">Authenticator code</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required>' +
      '<p class="small muted">The demonstration code expires after five minutes and cannot be reused.</p><p id="form-error" class="error" role="alert"></p>' +
      '<button type="submit">Verify authenticator</button></form><a class="navlink" href="#/setup">Back to setup</a>';
    document.getElementById("otp-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      setError("");
      const { response, result } = await api("/api/mfa/verify-otp", "POST", { otp: document.getElementById("otp").value.trim() });
      if (!response.ok || !result.ok) return setError("Verification could not be completed.");
      accountState.mfa = result.mfa;
      backupCodes = result.backupCodes;
      log("MFA authenticator verification simulation succeeded.");
      for (const code of backupCodes) log("New backup recovery code: " + code);
      location.hash = "#/backup";
    });
  }

  function backupView() {
    if (!accountState) return signinView();
    const screen = shell("Save your backup codes", "These codes can help you recover access if you lose your authenticator.");
    if (!backupCodes) {
      screen.innerHTML = '<div class="notice">Backup codes are only displayed immediately after enrolment or regeneration. You can create a new set in MFA settings.</div><a class="button" href="#/settings">Go to MFA settings</a>';
      return;
    }
    screen.innerHTML =
      '<div class="notice"><strong>Store these securely.</strong> Copy them to a password manager or write them down. Each code works once. Do not save them in an email or shared note.</div>' +
      '<div class="card"><h2>Your new recovery codes</h2><ul class="codes" id="codes"></ul></div>' +
      '<a class="button" href="#/confirmed">I have stored my codes</a>';
    const list = document.getElementById("codes");
    backupCodes.forEach((code) => { const item = document.createElement("li"); item.textContent = code; list.appendChild(item); });
  }

  function confirmedView() {
    if (!accountState) return signinView();
    const screen = shell("MFA is active", "Your account is ready for secure payment approval.");
    screen.innerHTML =
      '<div class="success"><strong>Enrolment confirmed.</strong><p>Your authenticator and recovery codes are now active.</p></div>' +
      '<a class="button" href="#/settings">View MFA settings</a>';
  }

  function settingsView() {
    if (!accountState) return signinView();
    const screen = shell("MFA settings", "Manage the security methods for Marcus’s authenticated account.");
    const enabled = accountState.mfa && accountState.mfa.enabled;
    screen.innerHTML =
      '<div class="card"><h2>Authenticator</h2><p id="auth-status"></p>' +
      (enabled ? '<p class="small muted">Your authenticator is enrolled.</p>' : '<a class="button" href="#/setup">Set up authenticator</a>') +
      '</div>' +
      (enabled ? '<div class="card"><h2>Backup recovery codes</h2><p>Generate a replacement set if your current codes are unavailable. Existing codes will stop working immediately.</p><p id="form-error" class="error" role="alert"></p><button id="regenerate" class="secondary">Generate replacement codes</button></div>' +
      '<div class="card"><h2>Test a recovery code</h2><form id="recovery-form"><label for="recovery">Recovery code</label><input id="recovery" autocomplete="one-time-code" placeholder="ABCD-EFGH-JKLM" required><button type="submit" class="secondary">Verify recovery code</button></form></div>' : '') +
      '<button id="logout" class="danger">Log out</button>';
    document.getElementById("auth-status").textContent = enabled ? "Status: Active" : "Status: Not enrolled";
    const regen = document.getElementById("regenerate");
    if (regen) regen.addEventListener("click", async () => {
      setError("");
      const { response, result } = await api("/api/mfa/regenerate-backup", "POST", {});
      if (!response.ok || !result.ok) return setError("The request could not be completed.");
      backupCodes = result.backupCodes;
      log("Replacement backup recovery codes generated.");
      result.backupCodes.forEach((code) => log("New backup recovery code: " + code));
      location.hash = "#/backup";
    });
    const recoveryForm = document.getElementById("recovery-form");
    if (recoveryForm) recoveryForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const { response, result } = await api("/api/mfa/recover", "POST", { recoveryCode: document.getElementById("recovery").value.trim() });
      if (!response.ok || !result.ok) return setError("Verification could not be completed.");
      log("Backup recovery-code verification simulation succeeded; the code is now invalid.");
      setError("");
      alert("Recovery code accepted and invalidated.");
    });
    document.getElementById("logout").addEventListener("click", async () => {
      await api("/api/logout", "POST", {});
      csrf = ""; accountState = null; backupCodes = null; provision = null; visibleLogs = [];
      location.hash = "#/signin";
    });
  }

  function render() {
    switch (route()) {
      case "setup": return setupView();
      case "verify": return verifyView();
      case "backup": return backupView();
      case "confirmed": return confirmedView();
      case "settings": return settingsView();
      default: return signinView();
    }
  }

  async function load() {
    const { response, result } = await api("/api/state");
    if (response.ok && result.ok) {
      csrf = result.csrf;
      accountState = result;
      if (!location.hash || route() === "signin") location.hash = result.mfa.enabled ? "#/settings" : "#/setup";
    }
    render();
  }

  window.addEventListener("hashchange", () => {
    if (route() !== "backup") backupCodes = null;
    if (route() !== "setup") provision = null;
    visibleLogs = [];
    render();
  });
  load();
})();
</script>
</body>
</html>`;

async function handleApi(request: Request, pathname: string): Promise<Response> {
  if (pathname === "/api/signin" && request.method === "POST") {
    const input = await body(request);
    if (!input || !validEmail(input.email) || !validPhone(input.phone) || !validOtp(input.identityCode) || !validRedirect(input.redirect)) {
      return genericError(request);
    }

    /* [5] Generic result and a fresh session ID prevent account enumeration and fixation. */
    if (input.identityCode !== "654321") return genericError(request, 401);

    const oldId = cookieValue(request, COOKIE_NAME);
    if (oldId) sessions.delete(oldId);

    const id = randomToken(32);
    const now = Date.now();
    const session: Session = {
      id,
      userId: "account_marcus_001",
      csrf: randomToken(24),
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + SESSION_ABSOLUTE_MS,
    };
    sessions.set(id, session);
    return json(request, 200, publicState(session), { "Set-Cookie": sessionCookie(id) });
  }

  if (pathname === "/api/state" && request.method === "GET") {
    const session = authorized(request);
    if (!session) return genericError(request, 401);
    return json(request, 200, publicState(session));
  }

  if (pathname === "/api/logout" && request.method === "POST") {
    const session = authorized(request);
    if (!session || !csrfValid(request, session)) return genericError(request, 403);
    sessions.delete(session.id);
    return json(request, 200, { ok: true }, { "Set-Cookie": expiredCookie() });
  }

  if (pathname === "/api/mfa/provision" && request.method === "POST") {
    const session = authorized(request);
    if (!session || !csrfValid(request, session)) return genericError(request, 403);
    const input = await body(request);
    if (!input) return genericError(request);

    const record = getMfaRecord(session.userId);
    if (record.enabled) return genericError(request, 409);

    /* [3] Secret and temporary OTP are cryptographically generated; only encrypted/hash forms persist. */
    const manualSecret = randomBase32(32);
    const verificationCode = secureDigits(6);
    record.protectedSecret = await encryptSecret(manualSecret);
    record.provisioning = {
      otpHash: await sha256(verificationCode),
      expiresAt: Date.now() + OTP_LIFETIME_MS,
      used: false,
    };
    resetAttempts(record.otpAttempts);

    return json(request, 200, { ok: true, manualSecret, verificationCode });
  }

  if (pathname === "/api/mfa/verify-otp" && request.method === "POST") {
    const session = authorized(request);
    if (!session || !csrfValid(request, session)) return genericError(request, 403);
    const input = await body(request);
    if (!input || !validOtp(input.otp)) return genericError(request);

    const record = getMfaRecord(session.userId);
    if (lockStatus(record.otpAttempts)) return genericError(request, 429);

    const pending = record.provisioning;
    const valid = Boolean(
      pending &&
      !pending.used &&
      pending.expiresAt >= Date.now() &&
      pending.otpHash === await sha256(input.otp),
    );

    if (!valid) {
      recordFailure(record.otpAttempts);
      return genericError(request, 401);
    }

    pending!.used = true;
    record.enabled = true;
    record.provisioning = undefined;
    resetAttempts(record.otpAttempts);
    const backupCodes = await createBackupCodes(record);
    return json(request, 200, {
      ok: true,
      mfa: { enabled: true, hasRecoveryCodes: true, provisioningPending: false },
      backupCodes,
    });
  }

  if (pathname === "/api/mfa/regenerate-backup" && request.method === "POST") {
    const session = authorized(request);
    if (!session || !csrfValid(request, session)) return genericError(request, 403);
    const input = await body(request);
    if (!input) return genericError(request);

    const record = getMfaRecord(session.userId);
    if (!record.enabled) return genericError(request, 409);
    /* [3] Assignment replaces every former protected hash, invalidating the old set. */
    const backupCodes = await createBackupCodes(record);
    return json(request, 200, { ok: true, backupCodes });
  }

  if (pathname === "/api/mfa/recover" && request.method === "POST") {
    const session = authorized(request);
    if (!session || !csrfValid(request, session)) return genericError(request, 403);
    const input = await body(request);
    const code = input ? canonicalRecoveryCode(input.recoveryCode) : null;
    if (!code) return genericError(request);

    const record = getMfaRecord(session.userId);
    if (!record.enabled || lockStatus(record.recoveryAttempts)) return genericError(request, 429);

    let matched: ProtectedRecoveryCode | undefined;
    for (const stored of record.recoveryCodes) {
      if (!stored.used && await matchesRecoveryCode(code, stored)) {
        matched = stored;
        break;
      }
    }

    if (!matched) {
      recordFailure(record.recoveryAttempts);
      return genericError(request, 401);
    }

    matched.used = true;
    resetAttempts(record.recoveryAttempts);
    return json(request, 200, { ok: true });
  }

  return genericError(request, 404);
}

Bun.serve({
  port: 3000,
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);

      /* [2][3] This listener is TLS-only. Reject malformed/non-secure request URLs defensively. */
      if (url.protocol !== "https:") return genericError(request, 400);

      if (request.method === "OPTIONS") {
        if (!trustedOrigin(request.headers.get("origin"))) return genericError(request, 403);
        const headers = secureHeaders(request, "text/plain; charset=utf-8");
        headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
        headers.set("Access-Control-Max-Age", "600");
        return new Response(null, { status: 204, headers });
      }

      if (request.headers.get("origin") && !trustedOrigin(request.headers.get("origin"))) {
        return genericError(request, 403);
      }

      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
      if (url.pathname === "/" && request.method === "GET") {
        return new Response(html, { status: 200, headers: secureHeaders(request, "text/html; charset=utf-8") });
      }

      return genericError(request, 404);
    } catch {
      /* [2] Production-safe generic failure: no debug data or stack traces. */
      return genericError(request, 500);
    }
  },
});
