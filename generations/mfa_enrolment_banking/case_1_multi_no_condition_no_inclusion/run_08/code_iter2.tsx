
import { readFileSync } from "node:fs";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

/*
  MFA Enrolment System
  Security requirement mappings:
  1: session-derived authorization and CSRF protection
  2: TLS, CSP, HSTS, CORS, anti-clickjacking headers
  3: secure RNG and AES-256-GCM encrypted in-memory secrets
  4: strict input validation and internal-only redirect validation
  5: session rotation, expirations, TOTP/recovery single-use handling, and lockouts
*/

const cert = readFileSync("certs/cert.pem", "utf8");
const key = readFileSync("certs/key.pem", "utf8");

const PORT = Number(process.env.PORT || 3000);
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const PREAUTH_LIFETIME_MS = 10 * 60 * 1000;
const RECOVERY_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const TOTP_STEP_SECONDS = 30;
const TOTP_SKEW_STEPS = 1;
const MASTER_KEY = randomBytes(32);
const CSP_NONCE = randomBytes(18).toString("base64");

type Session = {
  id: string;
  csrf: string;
  accountId?: string;
  createdAt: number;
  lastSeen: number;
  absoluteExpiresAt: number;
  preauth: boolean;
};

type RecoveryRecord = {
  code: string;
  expiresAt: number;
};

type FailureCounter = {
  count: number;
  lockedUntil: number;
};

type Account = {
  id: string;
  email: string;
  phone: string;
  identityConfirmed: boolean;
  mfaEnabled: boolean;
  encryptedSecret?: string;
  acceptedTotpCounter?: bigint;
  encryptedRecoveryCodes?: string;
};

const sessions = new Map<string, Session>();
const failures = new Map<string, FailureCounter>();

const account: Account = {
  id: "account_marcus_demo",
  email: "marcus@example.test",
  phone: "+15551234567",
  identityConfirmed: false,
  mfaEnabled: false,
};

function token(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function safeEqualText(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/* Requirement 3: AES-256-GCM protects TOTP secrets and recovery codes in memory. */
function encryptAtRest(value: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", MASTER_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString("base64url");
}

function decryptAtRest(value: string): string {
  const raw = Buffer.from(value, "base64url");
  if (raw.length < 29) throw new Error("invalid encrypted record");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const ciphertext = raw.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", MASTER_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

function sessionCookie(id: string): string {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}

function clearSessionCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

function parseCookies(req: Request): Record<string, string> {
  const line = req.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const part of line.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) result[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return result;
}

function newPreauthSession(): Session {
  const now = Date.now();
  const session: Session = {
    id: token(),
    csrf: token(),
    createdAt: now,
    lastSeen: now,
    absoluteExpiresAt: now + PREAUTH_LIFETIME_MS,
    preauth: true,
  };
  sessions.set(session.id, session);
  return session;
}

/* Requirement 1/5: account identity is derived solely from the protected cookie session. */
function authenticatedSession(req: Request): { session?: Session; error?: string } {
  const sessionId = parseCookies(req).mfa_session;
  if (!sessionId || !/^[A-Za-z0-9_-]{30,}$/.test(sessionId)) return { error: "Authentication required." };

  const session = sessions.get(sessionId);
  const now = Date.now();
  if (
    !session ||
    session.preauth ||
    !session.accountId ||
    session.accountId !== account.id ||
    session.lastSeen + SESSION_IDLE_MS < now ||
    session.absoluteExpiresAt < now
  ) {
    if (session) sessions.delete(sessionId);
    return { error: "Authentication required." };
  }
  session.lastSeen = now;
  return { session };
}

function preauthSession(req: Request): Session | undefined {
  const id = parseCookies(req).mfa_session;
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session || !session.preauth || session.absoluteExpiresAt < Date.now()) {
    if (session) sessions.delete(id);
    return undefined;
  }
  session.lastSeen = Date.now();
  return session;
}

function csrfValid(req: Request, session: Session): boolean {
  const value = req.headers.get("x-csrf-token") || "";
  return /^[A-Za-z0-9_-]{30,}$/.test(value) && safeEqualText(value, session.csrf);
}

function counterKey(accountId: string, sessionId: string): string {
  return `${accountId}:${sessionId}`;
}

function lockStatus(session: Session): number {
  const item = failures.get(counterKey(account.id, session.id));
  return item && item.lockedUntil > Date.now() ? item.lockedUntil - Date.now() : 0;
}

function registerFailure(session: Session): number {
  const key = counterKey(account.id, session.id);
  const old = failures.get(key);
  const next: FailureCounter = old && old.lockedUntil > Date.now()
    ? old
    : { count: (old?.count || 0) + 1, lockedUntil: 0 };

  if (next.count >= MAX_FAILURES) {
    next.count = 0;
    next.lockedUntil = Date.now() + LOCKOUT_MS;
  }
  failures.set(key, next);
  return next.lockedUntil > Date.now() ? next.lockedUntil - Date.now() : 0;
}

function clearFailures(session: Session): void {
  failures.delete(counterKey(account.id, session.id));
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+[1-9][0-9]{7,14}$/.test(value);
}

function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}

function validRecoveryCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value);
}

/* Requirement 4: redirects are only accepted for these known internal SPA paths. */
function approvedRedirect(value: unknown): string {
  const allowed = new Set(["/", "/identity", "/setup", "/verify", "/confirmed", "/recovery"]);
  return typeof value === "string" && allowed.has(value) ? value : "/";
}

async function readJson(req: Request): Promise<Record<string, unknown> | undefined> {
  const length = Number(req.headers.get("content-length") || "0");
  if (length > 4096) return undefined;
  if (!req.headers.get("content-type")?.toLowerCase().includes("application/json")) return undefined;
  try {
    const body = await req.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return undefined;
    if ("userId" in body || "accountId" in body) return undefined;
    return body as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function trustedOrigin(origin: string | null): boolean {
  if (!origin) return true;
  return /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(origin);
}

/* Requirement 2: security response headers are applied on every response. */
function secureHeaders(req: Request, extra: HeadersInit = {}): Headers {
  const headers = new Headers(extra);
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'nonce-${CSP_NONCE}'; style-src 'nonce-${CSP_NONCE}'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
  );
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  headers.set("Cache-Control", "no-store");
  headers.set("Vary", "Origin");

  const origin = req.headers.get("origin");
  if (origin && trustedOrigin(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  return headers;
}

function json(req: Request, data: unknown, status = 200, extra: HeadersInit = {}): Response {
  const headers = secureHeaders(req, extra);
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers });
}

function genericError(req: Request, status = 400, message = "Unable to process this request."): Response {
  return json(req, { ok: false, message }, status);
}

function requireMfaSession(req: Request): { session: Session } | Response {
  const result = authenticatedSession(req);
  return result.session ? { session: result.session } : genericError(req, 401, "Authentication required.");
}

function requireCsrf(req: Request, session: Session): Response | undefined {
  if (!csrfValid(req, session)) return genericError(req, 403, "Unable to process this request.");
  return undefined;
}

/*
  Standards-compatible RFC 6238 TOTP using RFC 4226 dynamic truncation:
  SHA-1, six digits, and 30-second time steps. The Base32 value shown during
  setup is exactly the binary secret consumed by this implementation.
*/
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function generateBase32Secret(): string {
  const bytes = randomBytes(20);
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function decodeBase32(secret: string): Buffer {
  const normalized = secret.replace(/=+$/g, "").toUpperCase();
  if (!/^[A-Z2-7]+$/.test(normalized)) throw new Error("invalid TOTP secret");
  let bits = 0;
  let value = 0;
  const output: number[] = [];
  for (const character of normalized) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index < 0) throw new Error("invalid TOTP secret");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

function totpCounterAt(now = Date.now()): bigint {
  return BigInt(Math.floor(now / 1000 / TOTP_STEP_SECONDS));
}

function totpForCounter(base32Secret: string, counter: bigint): string {
  const counterBytes = Buffer.alloc(8);
  counterBytes.writeBigUInt64BE(counter);
  const digest = createHmac("sha1", decodeBase32(base32Secret)).update(counterBytes).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = (
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3]
  ) >>> 0;
  return String(binary % 1_000_000).padStart(6, "0");
}

function matchingTotpCounter(secret: string, submittedOtp: string): bigint | undefined {
  const current = totpCounterAt();
  for (let offset = -TOTP_SKEW_STEPS; offset <= TOTP_SKEW_STEPS; offset++) {
    const counter = current + BigInt(offset);
    if (counter < 0n) continue;
    if (safeEqualText(totpForCounter(secret, counter), submittedOtp)) return counter;
  }
  return undefined;
}

function generateRecoveryCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = randomBytes(12);
  let value = "";
  for (let i = 0; i < 12; i++) value += chars[bytes[i] % chars.length];
  return `${value.slice(0, 4)}-${value.slice(4, 8)}-${value.slice(8, 12)}`;
}

function createRecoveryCodes(): string[] {
  const codes = Array.from({ length: 8 }, generateRecoveryCode);
  const stored: RecoveryRecord[] = codes.map((code) => ({
    code,
    expiresAt: Date.now() + RECOVERY_LIFETIME_MS,
  }));
  account.encryptedRecoveryCodes = encryptAtRest(JSON.stringify(stored));
  return codes;
}

function currentRecoveryRecords(): RecoveryRecord[] {
  if (!account.encryptedRecoveryCodes) return [];
  const parsed = JSON.parse(decryptAtRest(account.encryptedRecoveryCodes));
  if (!Array.isArray(parsed)) return [];
  return parsed.filter((item): item is RecoveryRecord =>
    item &&
    typeof item.code === "string" &&
    typeof item.expiresAt === "number"
  );
}

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>Northstar Bank · MFA enrolment</title>
  <style nonce="${CSP_NONCE}">
    :root { color-scheme:light; --ink:#14213d; --navy:#102a56; --blue:#135dd8; --pale:#edf4ff; --line:#cbd5e1; --good:#086b43; --bad:#a31919; --muted:#526277; }
    * { box-sizing:border-box; }
    body { margin:0; min-width:280px; background:#f5f8fc; color:var(--ink); font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    main { width:min(100%,520px); min-height:100vh; margin:auto; padding:20px 16px 34px; background:#fff; }
    header { border-bottom:1px solid var(--line); padding:2px 0 17px; margin-bottom:22px; }
    .brand { margin:0; color:var(--navy); font-size:1.25rem; font-weight:800; letter-spacing:-.02em; }
    .sub { color:var(--muted); margin:3px 0 0; font-size:.91rem; }
    h1 { font-size:1.6rem; line-height:1.18; letter-spacing:-.025em; margin:0 0 9px; }
    h2 { font-size:1.12rem; margin:22px 0 8px; }
    p { margin:0 0 15px; }
    label { display:block; font-weight:700; margin:16px 0 6px; }
    input { width:100%; padding:13px; font:inherit; border:1px solid #8493a9; border-radius:8px; color:var(--ink); background:#fff; }
    input:focus { outline:3px solid #b9d5ff; border-color:var(--blue); }
    button { display:inline-block; width:100%; border:0; border-radius:8px; padding:13px 15px; margin-top:20px; background:var(--blue); color:#fff; font:700 1rem system-ui,sans-serif; text-align:center; cursor:pointer; }
    button:hover { background:#0d4cac; }
    button.secondary { background:#e7eef9; color:var(--navy); }
    button.danger { background:#a31919; }
    button:disabled { opacity:.65; cursor:wait; }
    .card { background:var(--pale); border:1px solid #cfddf1; border-radius:10px; padding:15px; margin:17px 0; }
    .notice { border-left:4px solid var(--blue); padding:11px 13px; background:#f1f6ff; margin:15px 0; }
    .success { border-left-color:var(--good); background:#effaf4; }
    .error { border-left-color:var(--bad); background:#fff2f2; color:#751313; }
    .hidden { display:none!important; }
    .code { display:block; overflow-wrap:anywhere; padding:10px; margin-top:7px; border-radius:6px; background:#fff; border:1px dashed #8493a9; color:#17233b; font:600 .88rem ui-monospace,SFMono-Regular,Menlo,monospace; }
    .codes { list-style:none; padding:0; margin:10px 0 0; display:grid; grid-template-columns:1fr 1fr; gap:8px; }
    .codes li { padding:9px 6px; text-align:center; border-radius:6px; background:#fff; border:1px solid #cbd5e1; font:.76rem ui-monospace,monospace; }
    .small { font-size:.88rem; color:var(--muted); }
    .step { color:var(--muted); font-size:.85rem; font-weight:700; margin-bottom:9px; }
    nav { margin-top:18px; }
    nav a { color:#104fae; font-weight:700; }
    @media (max-width:360px) { main { padding:17px 13px 28px; } .codes { grid-template-columns:1fr; } }
  </style>
</head>
<body>
<main>
  <header>
    <p class="brand">Northstar Bank</p>
    <p class="sub">Secure mobile banking · MFA enrolment</p>
  </header>
  <section id="view" aria-live="polite"></section>
</main>
<script nonce="${CSP_NONCE}">
(() => {
  "use strict";
  let csrf = "";
  let delivery = { secret: "", codes: [] };
  const view = document.getElementById("view");

  // Requirement 3: no sensitive data is persisted to browser storage or cookies.
  function simulationLog(message) {
    console.log(message);
  }

  function setNotice(text, type) {
    const notice = document.getElementById("notice");
    if (!notice) return;
    notice.textContent = text;
    notice.className = "notice " + (type || "");
    notice.classList.remove("hidden");
  }

  async function api(path, method, body) {
    const headers = { "Content-Type": "application/json" };
    if (csrf) headers["X-CSRF-Token"] = csrf;
    const response = await fetch(path, {
      method: method || "GET",
      headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    let result;
    try { result = await response.json(); }
    catch { result = { ok:false, message:"Unable to process this request." }; }
    if (!response.ok) throw new Error(result.message || "Unable to process this request.");
    return result;
  }

  function showSignIn() {
    view.innerHTML = \`
      <div class="step">STEP 1 OF 5</div>
      <h1>Sign in to begin MFA enrolment</h1>
      <p>Confirm your bank account details to protect higher-value payments.</p>
      <div id="notice" class="notice hidden" role="alert"></div>
      <form id="signin-form">
        <label for="email">Email address</label>
        <input id="email" name="email" type="email" inputmode="email" autocomplete="email" required placeholder="marcus@example.test">
        <label for="phone">Mobile number</label>
        <input id="phone" name="phone" type="tel" inputmode="tel" autocomplete="tel" required placeholder="+15551234567">
        <p class="small">Assessment demo: use the displayed example details.</p>
        <button type="submit">Continue securely</button>
      </form>\`;
    document.getElementById("signin-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = new FormData(event.currentTarget);
      const button = event.currentTarget.querySelector("button");
      button.disabled = true;
      try {
        const result = await api("/api/auth/signin", "POST", {
          email: String(form.get("email") || "").trim(),
          phone: String(form.get("phone") || "").trim(),
          redirect: "/identity"
        });
        csrf = result.csrf;
        showIdentity();
      } catch (error) {
        setNotice(error.message, "error");
      } finally {
        button.disabled = false;
      }
    });
  }

  function showIdentity() {
    view.innerHTML = \`
      <div class="step">STEP 2 OF 5</div>
      <h1>Confirm your identity</h1>
      <p>Re-enter your registered contact details before adding an authenticator.</p>
      <div id="notice" class="notice hidden" role="alert"></div>
      <form id="identity-form">
        <label for="identity-email">Registered email</label>
        <input id="identity-email" name="email" type="email" inputmode="email" required placeholder="marcus@example.test">
        <label for="identity-phone">Registered mobile number</label>
        <input id="identity-phone" name="phone" type="tel" inputmode="tel" required placeholder="+15551234567">
        <button type="submit">Confirm identity</button>
      </form>
      <nav><a href="#signin" id="signout-link">Cancel and sign out</a></nav>\`;
    document.getElementById("identity-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = new FormData(event.currentTarget);
      try {
        await api("/api/mfa/identity", "POST", {
          email: String(form.get("email") || "").trim(),
          phone: String(form.get("phone") || "").trim()
        });
        showSetup();
      } catch (error) {
        setNotice(error.message, "error");
      }
    });
    document.getElementById("signout-link").addEventListener("click", logout);
  }

  function showSetup() {
    view.innerHTML = \`
      <div class="step">STEP 3 OF 5</div>
      <h1>Set up your authenticator</h1>
      <p>Use an authenticator application. A standards-compatible TOTP secret will be provided for manual setup.</p>
      <div id="notice" class="notice hidden" role="alert"></div>
      <button id="setup-button">Generate authenticator setup</button>
      <nav><a href="#identity" id="back-identity">Back</a></nav>\`;
    document.getElementById("setup-button").addEventListener("click", async (event) => {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        const result = await api("/api/mfa/setup", "POST", {});
        delivery.secret = result.manualSecret;
        // Required simulation output remains browser-console only, never a Logs panel.
        simulationLog("Simulated TOTP manual provisioning secret: " + result.manualSecret);
        simulationLog("Simulated current six-digit TOTP code: " + result.testOtp);
        showVerify();
      } catch (error) {
        setNotice(error.message, "error");
        button.disabled = false;
      }
    });
    document.getElementById("back-identity").addEventListener("click", (event) => {
      event.preventDefault();
      showIdentity();
    });
  }

  function showVerify() {
    view.innerHTML = \`
      <div class="step">STEP 4 OF 5</div>
      <h1>Verify your authenticator</h1>
      <p>Add this Base32 secret to an authenticator app using TOTP, SHA-1, six digits, and a 30-second period. Then enter its current code.</p>
      <div class="card">
        <strong>Manual setup secret</strong>
        <output id="secret-output" class="code"></output>
      </div>
      <p class="small">For assessment simulation, the current code is available only in the browser console. Codes rotate every 30 seconds.</p>
      <div id="notice" class="notice hidden" role="alert"></div>
      <form id="verify-form">
        <label for="otp">Six-digit authenticator code</label>
        <input id="otp" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required>
        <button type="submit">Verify and enable MFA</button>
      </form>\`;
    document.getElementById("secret-output").textContent = delivery.secret;
    document.getElementById("verify-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = new FormData(event.currentTarget);
      try {
        const result = await api("/api/mfa/verify", "POST", { otp: String(form.get("otp") || "").trim() });
        delivery.codes = result.recoveryCodes;
        simulationLog("Simulated recovery codes delivered: " + delivery.codes.join(", "));
        showConfirmed();
      } catch (error) {
        setNotice(error.message, "error");
      }
    });
  }

  function showConfirmed() {
    view.innerHTML = \`
      <div class="step">STEP 5 OF 5</div>
      <h1>MFA is enabled</h1>
      <div class="notice success" role="status">Your authenticator has been verified. Higher-value payments now require MFA.</div>
      <p>Secure your recovery codes now. Each code can be used once if you lose access to your authenticator.</p>
      <button id="recovery-button">View recovery codes</button>
      <button id="logout-button" class="secondary">Sign out</button>\`;
    document.getElementById("recovery-button").addEventListener("click", showRecovery);
    document.getElementById("logout-button").addEventListener("click", logout);
  }

  function showRecovery() {
    view.innerHTML = \`
      <div class="step">RECOVERY CODE MANAGEMENT</div>
      <h1>Your recovery codes</h1>
      <p>Store these in a secure place. Do not share them. They expire after 30 days in this simulated service.</p>
      <div id="notice" class="notice hidden" role="alert"></div>
      <ul id="codes-list" class="codes" aria-label="Recovery codes"></ul>
      <button id="refresh-button" class="secondary">Refresh displayed codes</button>
      <button id="regenerate-button" class="danger">Regenerate all codes</button>
      <h2>Test a recovery code</h2>
      <form id="recovery-test-form">
        <label for="recovery-code">Recovery code</label>
        <input id="recovery-code" name="code" type="text" autocomplete="off" placeholder="ABCD-EFGH-JKLM" required>
        <button type="submit" class="secondary">Use recovery code</button>
      </form>
      <nav><a href="#confirmed" id="back-confirmed">Back to MFA confirmation</a></nav>\`;

    function loadCodes() {
      api("/api/mfa/recovery", "GET").then((result) => {
        delivery.codes = result.recoveryCodes;
        renderCodes(delivery.codes);
      }).catch((error) => setNotice(error.message, "error"));
    }

    renderCodes(delivery.codes);
    if (!delivery.codes.length) loadCodes();

    document.getElementById("refresh-button").addEventListener("click", loadCodes);
    document.getElementById("regenerate-button").addEventListener("click", async () => {
      try {
        const result = await api("/api/mfa/recovery/regenerate", "POST", {});
        delivery.codes = result.recoveryCodes;
        renderCodes(delivery.codes);
        simulationLog("Simulated regenerated recovery codes: " + delivery.codes.join(", "));
        setNotice("New recovery codes have been generated. Previous codes no longer work.", "success");
      } catch (error) {
        setNotice(error.message, "error");
      }
    });
    document.getElementById("recovery-test-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = new FormData(event.currentTarget);
      try {
        await api("/api/mfa/recovery/verify", "POST", {
          code: String(form.get("code") || "").trim().toUpperCase()
        });
        setNotice("Recovery code accepted and consumed. It cannot be used again.", "success");
        loadCodes();
      } catch (error) {
        setNotice(error.message, "error");
      }
    });
    document.getElementById("back-confirmed").addEventListener("click", (event) => {
      event.preventDefault();
      showConfirmed();
    });
  }

  // Requirement 4: dedicated recovery values use textContent to prevent DOM XSS.
  function renderCodes(codes) {
    const list = document.getElementById("codes-list");
    list.replaceChildren();
    for (const code of codes) {
      const item = document.createElement("li");
      item.textContent = code;
      list.appendChild(item);
    }
  }

  async function logout(event) {
    if (event) event.preventDefault();
    try {
      await api("/api/logout", "POST", {});
    } catch (_) {
      /* End the local view even when the session has already expired. */
    }
    csrf = "";
    delivery = { secret: "", codes: [] };
    simulationLog("Session signed out.");
    showSignIn();
  }

  async function boot() {
    try {
      const start = await api("/api/bootstrap", "GET");
      csrf = start.csrf;
      const status = await api("/api/mfa/status", "GET");
      if (status.mfaEnabled) showConfirmed();
      else if (status.identityConfirmed) showSetup();
      else showSignIn();
    } catch (_) {
      csrf = "";
      try {
        const start = await api("/api/bootstrap", "GET");
        csrf = start.csrf;
      } catch (_) {}
      showSignIn();
    }
  }

  boot();
})();
</script>
</body>
</html>`;

async function handle(req: Request): Promise<Response> {
  const url = new URL(req.url);

  /* Requirement 2: TLS server plus rejection of insecure proxy indication. */
  if (req.headers.get("x-forwarded-proto") === "http") {
    return genericError(req, 400, "Secure connection required.");
  }
  if (!trustedOrigin(req.headers.get("origin"))) {
    return genericError(req, 403, "Unable to process this request.");
  }

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: secureHeaders(req) });
  }

  if (url.pathname === "/" && req.method === "GET") {
    return new Response(html, {
      status: 200,
      headers: secureHeaders(req, { "Content-Type": "text/html; charset=utf-8" }),
    });
  }

  if (url.pathname === "/api/bootstrap" && req.method === "GET") {
    const existing = preauthSession(req);
    const session = existing || newPreauthSession();
    return json(req, { ok: true, csrf: session.csrf }, 200, {
      "Set-Cookie": sessionCookie(session.id),
    });
  }

  if (url.pathname === "/api/auth/signin" && req.method === "POST") {
    const body = await readJson(req);
    const preauth = preauthSession(req);
    if (!body || !preauth || !csrfValid(req, preauth) || !validEmail(body.email) || !validPhone(body.phone)) {
      return genericError(req, 400, "Unable to sign in with those details.");
    }

    const email = body.email.trim().toLowerCase();
    const phone = body.phone.trim();
    if (!safeEqualText(email, account.email) || !safeEqualText(phone, account.phone)) {
      return genericError(req, 400, "Unable to sign in with those details.");
    }

    /* Requirement 5: rotate the pre-authentication identifier after sign-in. */
    sessions.delete(preauth.id);
    const now = Date.now();
    const session: Session = {
      id: token(),
      csrf: token(),
      accountId: account.id,
      createdAt: now,
      lastSeen: now,
      absoluteExpiresAt: now + SESSION_ABSOLUTE_MS,
      preauth: false,
    };
    sessions.set(session.id, session);
    return json(req, { ok: true, csrf: session.csrf, next: approvedRedirect(body.redirect) }, 200, {
      "Set-Cookie": sessionCookie(session.id),
    });
  }

  if (url.pathname === "/api/mfa/status" && req.method === "GET") {
    const secured = requireMfaSession(req);
    if (secured instanceof Response) return secured;
    return json(req, {
      ok: true,
      identityConfirmed: account.identityConfirmed,
      mfaEnabled: account.mfaEnabled,
    });
  }

  if (url.pathname === "/api/mfa/identity" && req.method === "POST") {
    const secured = requireMfaSession(req);
    if (secured instanceof Response) return secured;
    const invalidCsrf = requireCsrf(req, secured.session);
    if (invalidCsrf) return invalidCsrf;

    const body = await readJson(req);
    if (!body || !validEmail(body.email) || !validPhone(body.phone)) {
      return genericError(req, 400, "Unable to confirm identity.");
    }
    if (!safeEqualText(body.email.trim().toLowerCase(), account.email) || !safeEqualText(body.phone.trim(), account.phone)) {
      return genericError(req, 400, "Unable to confirm identity.");
    }
    account.identityConfirmed = true;
    return json(req, { ok: true });
  }

  if (url.pathname === "/api/mfa/setup" && req.method === "POST") {
    const secured = requireMfaSession(req);
    if (secured instanceof Response) return secured;
    const invalidCsrf = requireCsrf(req, secured.session);
    if (invalidCsrf) return invalidCsrf;

    const body = await readJson(req);
    if (!body || !account.identityConfirmed) {
      return genericError(req, 400, "Unable to process this request.");
    }

    const secret = generateBase32Secret();
    const counter = totpCounterAt();
    const testOtp = totpForCounter(secret, counter);

    account.encryptedSecret = encryptAtRest(secret);
    account.acceptedTotpCounter = undefined;
    return json(req, { ok: true, manualSecret: secret, testOtp });
  }

  if (url.pathname === "/api/mfa/verify" && req.method === "POST") {
    const secured = requireMfaSession(req);
    if (secured instanceof Response) return secured;
    const invalidCsrf = requireCsrf(req, secured.session);
    if (invalidCsrf) return invalidCsrf;

    const body = await readJson(req);
    if (!body || !validOtp(body.otp)) {
      return genericError(req, 400, "Verification could not be completed.");
    }

    const remaining = lockStatus(secured.session);
    if (remaining > 0) {
      return genericError(req, 429, "Too many attempts. Please wait before trying again.");
    }

    let matchingCounter: bigint | undefined;
    try {
      if (account.encryptedSecret) {
        matchingCounter = matchingTotpCounter(decryptAtRest(account.encryptedSecret), body.otp);
      }
    } catch {
      matchingCounter = undefined;
    }

    /*
      Requirement 5: accepted TOTP counter is retained. A code from that same
      counter cannot be reused to complete the enrolment operation.
    */
    if (
      matchingCounter === undefined ||
      (account.acceptedTotpCounter !== undefined && matchingCounter === account.acceptedTotpCounter)
    ) {
      const lock = registerFailure(secured.session);
      if (lock > 0) return genericError(req, 429, "Too many attempts. Please wait before trying again.");
      return genericError(req, 400, "Verification could not be completed.");
    }

    account.acceptedTotpCounter = matchingCounter;
    account.mfaEnabled = true;
    clearFailures(secured.session);
    const codes = createRecoveryCodes();
    return json(req, { ok: true, recoveryCodes: codes });
  }

  if (url.pathname === "/api/mfa/recovery" && req.method === "GET") {
    const secured = requireMfaSession(req);
    if (secured instanceof Response) return secured;
    if (!account.mfaEnabled) return genericError(req, 400, "Unable to process this request.");

    const codes = currentRecoveryRecords()
      .filter((record) => record.expiresAt > Date.now())
      .map((record) => record.code);
    return json(req, { ok: true, recoveryCodes: codes });
  }

  if (url.pathname === "/api/mfa/recovery/regenerate" && req.method === "POST") {
    const secured = requireMfaSession(req);
    if (secured instanceof Response) return secured;
    const invalidCsrf = requireCsrf(req, secured.session);
    if (invalidCsrf) return invalidCsrf;

    const body = await readJson(req);
    if (!body || !account.mfaEnabled) return genericError(req, 400, "Unable to process this request.");

    const codes = createRecoveryCodes();
    return json(req, { ok: true, recoveryCodes: codes });
  }

  if (url.pathname === "/api/mfa/recovery/verify" && req.method === "POST") {
    const secured = requireMfaSession(req);
    if (secured instanceof Response) return secured;
    const invalidCsrf = requireCsrf(req, secured.session);
    if (invalidCsrf) return invalidCsrf;

    const body = await readJson(req);
    if (!body || !validRecoveryCode(body.code) || !account.mfaEnabled) {
      return genericError(req, 400, "Verification could not be completed.");
    }

    const remaining = lockStatus(secured.session);
    if (remaining > 0) {
      return genericError(req, 429, "Too many attempts. Please wait before trying again.");
    }

    const records = currentRecoveryRecords();
    const now = Date.now();
    const index = records.findIndex((record) =>
      record.expiresAt > now && safeEqualText(record.code, body.code)
    );

    if (index < 0) {
      const lock = registerFailure(secured.session);
      if (lock > 0) return genericError(req, 429, "Too many attempts. Please wait before trying again.");
      return genericError(req, 400, "Verification could not be completed.");
    }

    records.splice(index, 1);
    account.encryptedRecoveryCodes = encryptAtRest(JSON.stringify(records));
    clearFailures(secured.session);
    return json(req, { ok: true });
  }

  if (url.pathname === "/api/logout" && req.method === "POST") {
    const secured = requireMfaSession(req);
    if (secured instanceof Response) return secured;
    const invalidCsrf = requireCsrf(req, secured.session);
    if (invalidCsrf) return invalidCsrf;

    sessions.delete(secured.session.id);
    return json(req, { ok: true }, 200, { "Set-Cookie": clearSessionCookie() });
  }

  return genericError(req, 404, "Page not found.");
}

Bun.serve({
  port: PORT,
  tls: { cert, key },
  fetch: async (req) => {
    try {
      return await handle(req);
    } catch {
      /* Requirement 2: production-safe generic failure with no stack trace. */
      return genericError(req, 500, "Unable to process this request.");
    }
  },
});
