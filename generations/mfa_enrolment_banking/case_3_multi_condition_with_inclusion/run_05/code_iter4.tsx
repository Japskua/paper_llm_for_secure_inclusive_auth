
import { serve } from "bun";

/*
 Requirements 2 & 3: TLS uses supplied local certificates. Sensitive server
 state is in-memory only; no secrets are written to logs or browser storage.
*/
const cert = await Bun.file("certs/cert.pem").text();
const key = await Bun.file("certs/key.pem").text();

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const SIGNIN_LOCKOUT_MS = 10 * 60 * 1000;
const TOTP_PERIOD_SECONDS = 30;
const TOTP_SKEW_WINDOWS = 1;
const TRUSTED_ORIGIN = /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/;

type Verification = { code: string; expiresAt: number; used: boolean; attempts: number; lockedUntil: number };
type Session = { id: string; accountId: string; csrf: string; createdAt: number; lastSeen: number };
type EncryptedSecret = { iv: string; cipher: string };
type SigninFailure = { attempts: number; lockedUntil: number };
type Account = {
  id: string; email: string; identityVerified: boolean; mfaEnabled: boolean;
  encryptedSecret?: EncryptedSecret; pendingEncryptedSecret?: EncryptedSecret;
  identity?: Verification; authenticator?: Verification; pendingUsedTotpSteps: number[];
  backupCodes: Array<{ salt: string; hash: string; used: boolean }>;
  recoveryAttempts: number; recoveryLockedUntil: number;
};

const sessions = new Map<string, Session>();
const csrfTickets = new Map<string, number>();
const signinFailures = new Map<string, SigninFailure>();
const accounts = new Map<string, Account>();
const encryptionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);

accounts.set("acct-marcus", {
  id: "acct-marcus", email: "marcus@example.com", identityVerified: false, mfaEnabled: false,
  pendingUsedTotpSteps: [], backupCodes: [], recoveryAttempts: 0, recoveryLockedUntil: 0,
});

function randomToken(bytes = 32) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return Buffer.from(data).toString("base64url");
}
function randomSixDigitCode() {
  const data = new Uint32Array(1); crypto.getRandomValues(data);
  return String((data[0] % 900000) + 100000);
}
function randomSecret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", data = new Uint8Array(20);
  crypto.getRandomValues(data);
  return Array.from(data, v => alphabet[v % alphabet.length]).join("");
}
function randomRecoveryCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", data = new Uint8Array(10);
  crypto.getRandomValues(data);
  return Array.from(data, v => alphabet[v % alphabet.length]).join("");
}
function b64(data: Uint8Array | ArrayBuffer) { return Buffer.from(data).toString("base64url"); }
function fromB64(value: string) { return new Uint8Array(Buffer.from(value, "base64url")); }
async function sha256(value: string) { return b64(await crypto.subtle.digest("SHA-256", encoder.encode(value))); }

async function encryptSecret(secret: string): Promise<EncryptedSecret> {
  const iv = new Uint8Array(12); crypto.getRandomValues(iv);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, encoder.encode(secret));
  return { iv: b64(iv), cipher: b64(cipher) };
}
async function decryptSecret(stored: EncryptedSecret) {
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(stored.iv) }, encryptionKey, fromB64(stored.cipher));
  return decoder.decode(plain);
}
function base32Decode(secret: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", clean = secret.replace(/[\s=]/g, "").toUpperCase();
  let buffer = 0, bits = 0; const bytes: number[] = [];
  for (const char of clean) {
    const value = alphabet.indexOf(char);
    if (value < 0) throw new Error("Invalid setup key");
    buffer = (buffer << 5) | value; bits += 5;
    while (bits >= 8) { bits -= 8; bytes.push((buffer >> bits) & 255); }
  }
  return new Uint8Array(bytes);
}
async function totpForCounter(secret: string, counter: number) {
  const message = new Uint8Array(8); let value = BigInt(counter);
  for (let i = 7; i >= 0; i--) { message[i] = Number(value & 255n); value >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = mac[mac.length - 1] & 15;
  const binary = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(binary % 1000000).padStart(6, "0");
}
async function currentTotp(secret: string) {
  return totpForCounter(secret, Math.floor(Date.now() / 1000 / TOTP_PERIOD_SECONDS));
}
async function makeBackupCodes() {
  const plain = Array.from({ length: 8 }, randomRecoveryCode);
  const stored = [];
  for (const code of plain) {
    const salt = randomToken(16);
    stored.push({ salt, hash: await sha256(salt + ":" + code), used: false });
  }
  return { plain, stored };
}

/* Requirement 1/5: ownership is derived only from a secure session cookie. */
function sessionFrom(request: Request): Session | null {
  const match = (request.headers.get("cookie") || "").match(/(?:^|;\s*)mfa_session=([^;]+)/);
  if (!match) return null;
  const session = sessions.get(match[1]);
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(session.id); return null;
  }
  session.lastSeen = now;
  return session;
}
function authorized(request: Request) {
  const session = sessionFrom(request);
  if (!session) return null;
  const account = accounts.get(session.accountId);
  if (!account) { sessions.delete(session.id); return null; }
  return { session, account };
}
function sessionCookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}
function cleanCookie() { return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }

/* Requirement 2: nonce-based CSP, production headers, restrictive CORS, no cache. */
function securityHeaders(request: Request, nonce?: string) {
  const headers = new Headers({
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  const origin = request.headers.get("origin");
  if (origin && TRUSTED_ORIGIN.test(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Vary", "Origin");
  }
  return headers;
}
function json(request: Request, data: unknown, status = 200, extra?: HeadersInit) {
  const headers = securityHeaders(request);
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((v, k) => headers.set(k, v));
  return new Response(JSON.stringify(data), { status, headers });
}
function page(request: Request) {
  /* Per-response cryptographically random nonce; no unsafe-inline CSP directives. */
  const nonce = randomToken(24);
  const headers = securityHeaders(request, nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(HTML.replaceAll("__CSP_NONCE__", nonce), { headers });
}
async function readBody(request: Request) {
  if (!(request.headers.get("content-type") || "").includes("application/json")) return null;
  const raw = await request.text();
  if (raw.length > 4000) return null;
  try {
    const body = JSON.parse(raw);
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch { return null; }
}
function stringField(body: Record<string, unknown> | null, field: string, max = 200) {
  const value = body?.[field];
  return typeof value === "string" && value.length <= max ? value.trim() : "";
}
function validEmail(value: string) { return /^[^\s@]+@[^\s@]+\.[^\s@]{2,80}$/.test(value) && value.length <= 120; }
function validOtp(value: string) { return /^\d{6}$/.test(value); }
function validRecovery(value: string) { return /^[A-Z2-9]{10}$/.test(value); }
function csrfOK(request: Request, session: Session, body: Record<string, unknown> | null) {
  const token = request.headers.get("x-csrf-token") || stringField(body, "csrf", 200);
  return token.length >= 32 && token === session.csrf;
}
function csrfError(request: Request) { return json(request, { error: "Your page check expired. Refresh the page, then try again." }, 403); }
function safeOrigin(request: Request) { const origin = request.headers.get("origin"); return !origin || TRUSTED_ORIGIN.test(origin); }
function lockMessage() { return "Too many tries were made. Please wait 10 minutes, then try again."; }
function newVerificationPreservingState(previous?: Verification): Verification {
  return { code: randomSixDigitCode(), expiresAt: Date.now() + CODE_LIFETIME_MS, used: false, attempts: previous?.attempts || 0, lockedUntil: previous?.lockedUntil || 0 };
}
function checkIdentity(record: Verification | undefined, code: string) {
  const now = Date.now();
  if (!record) return { ok: false, message: "Request a new code, then try again." };
  if (record.lockedUntil > now) return { ok: false, message: lockMessage() };
  if (record.used || now > record.expiresAt) return { ok: false, message: "This code is no longer available. Request a new code and try again." };
  if (code !== record.code) {
    record.attempts++;
    if (record.attempts >= MAX_ATTEMPTS) record.lockedUntil = now + LOCKOUT_MS;
    return { ok: false, message: record.lockedUntil > now ? lockMessage() : "That code does not match. Check the six digits and try again." };
  }
  record.used = true; return { ok: true, message: "" };
}
function incrementAuthenticatorFailure(account: Account) {
  if (!account.authenticator) account.authenticator = newVerificationPreservingState();
  account.authenticator.attempts++;
  if (account.authenticator.attempts >= MAX_ATTEMPTS) {
    account.authenticator.lockedUntil = Date.now() + LOCKOUT_MS; return lockMessage();
  }
  return "That code does not match your authenticator. Check the six digits and try again.";
}
function recoveryLockMessage(until: number) {
  const minutes = Math.max(1, Math.ceil((until - Date.now()) / 60000));
  return `Too many recovery-code attempts were made. You may retry in about ${minutes} minute${minutes === 1 ? "" : "s"}.`;
}
function failedRecovery(account: Account) {
  account.recoveryAttempts++;
  if (account.recoveryAttempts >= MAX_ATTEMPTS) {
    account.recoveryLockedUntil = Date.now() + LOCKOUT_MS; account.recoveryAttempts = 0;
    return recoveryLockMessage(account.recoveryLockedUntil);
  }
  return "That recovery code cannot be used. Check it, or use another unused code.";
}

/* Requirement task: server-side normalized-email sign-in failure protection. */
function normalizedEmail(value: string) { return value.trim().toLowerCase(); }
function signinLocked(email: string) {
  const state = signinFailures.get(email);
  if (!state) return false;
  if (state.lockedUntil > Date.now()) return true;
  if (state.lockedUntil) { state.lockedUntil = 0; state.attempts = 0; }
  return false;
}
function recordSigninFailure(email: string) {
  const state = signinFailures.get(email) || { attempts: 0, lockedUntil: 0 };
  state.attempts++;
  if (state.attempts >= MAX_ATTEMPTS) { state.lockedUntil = Date.now() + SIGNIN_LOCKOUT_MS; state.attempts = 0; }
  signinFailures.set(email, state);
}
function clearSigninFailure(email: string) { signinFailures.delete(email); }

async function api(request: Request, pathname: string) {
  if (!safeOrigin(request)) return json(request, { error: "Request not allowed." }, 403);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: securityHeaders(request) });

  if (pathname === "/api/bootstrap" && request.method === "GET") {
    const token = randomToken(); csrfTickets.set(token, Date.now() + 10 * 60 * 1000);
    return json(request, { csrf: token });
  }

  if (pathname === "/api/signin" && request.method === "POST") {
    const body = await readBody(request);
    const ticket = stringField(body, "csrf", 200), expires = csrfTickets.get(ticket);
    csrfTickets.delete(ticket);
    if (!expires || expires < Date.now()) return csrfError(request);

    const email = normalizedEmail(stringField(body, "email", 120));
    const password = stringField(body, "password", 200);
    const account = accounts.get("acct-marcus");

    if (signinLocked(email)) {
      return json(request, { error: "We could not sign you in with those details. Check them and try again." }, 401);
    }
    if (!account || !validEmail(email) || password.length < 8 || email !== account.email || password !== "BankPass1!") {
      recordSigninFailure(email);
      return json(request, { error: "We could not sign you in with those details. Check them and try again." }, 401);
    }
    clearSigninFailure(email);

    const id = randomToken();
    const session: Session = { id, accountId: account.id, csrf: randomToken(), createdAt: Date.now(), lastSeen: Date.now() };
    sessions.set(id, session);
    return json(request, { csrf: session.csrf, step: account.identityVerified ? (account.mfaEnabled ? "settings" : "provision") : "identity" }, 200, { "Set-Cookie": sessionCookie(id) });
  }

  const auth = authorized(request);
  if (!auth) return json(request, { error: "Your signed-in session ended. Please sign in again." }, 401);
  const { session, account } = auth;

  if (pathname === "/api/me" && request.method === "GET") {
    return json(request, { email: account.email, identityVerified: account.identityVerified, mfaEnabled: account.mfaEnabled, csrf: session.csrf });
  }
  const body = request.method === "POST" ? await readBody(request) : null;

  if (pathname === "/api/identity/request" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    if (account.identity?.lockedUntil && account.identity.lockedUntil > Date.now()) return json(request, { error: lockMessage() }, 429);
    account.identity = newVerificationPreservingState(account.identity);
    return json(request, { message: "A new verification code was sent.", testCode: account.identity.code });
  }
  if (pathname === "/api/identity/verify" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    if (account.identity?.lockedUntil && account.identity.lockedUntil > Date.now()) return json(request, { error: lockMessage() }, 429);
    const code = stringField(body, "code", 6);
    if (!validOtp(code)) return json(request, { error: "Enter six digits, for example 123456." }, 400);
    const result = checkIdentity(account.identity, code);
    if (!result.ok) return json(request, { error: result.message }, 400);
    account.identityVerified = true;
    return json(request, { message: "Identity confirmed.", next: "provision" });
  }
  if (pathname === "/api/provision" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    if (!account.identityVerified) return json(request, { error: "Please confirm your identity before setting up an authenticator." }, 403);
    if (account.authenticator?.lockedUntil && account.authenticator.lockedUntil > Date.now()) return json(request, { error: lockMessage() }, 429);
    const secret = randomSecret();
    account.pendingEncryptedSecret = await encryptSecret(secret);
    account.pendingUsedTotpSteps = [];
    account.authenticator = newVerificationPreservingState(account.authenticator);
    return json(request, { secret, testOtp: await currentTotp(secret), issuer: "Harbour Bank", email: account.email, period: TOTP_PERIOD_SECONDS });
  }
  if (pathname === "/api/authenticator/activate" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    if (account.authenticator?.lockedUntil && account.authenticator.lockedUntil > Date.now()) return json(request, { error: lockMessage() }, 429);
    if (!account.identityVerified || !account.pendingEncryptedSecret) return json(request, { error: "Start the authenticator setup again, then enter the new code." }, 400);
    const otp = stringField(body, "otp", 6);
    const manualSecret = stringField(body, "manualSecret", 64).replace(/\s/g, "").toUpperCase();
    if (!validOtp(otp)) return json(request, { error: "Enter the six digits from your authenticator, for example 123456." }, 400);
    let pendingSecret = "";
    try { pendingSecret = await decryptSecret(account.pendingEncryptedSecret); }
    catch { account.pendingEncryptedSecret = undefined; return json(request, { error: "Start the authenticator setup again, then enter the new code." }, 400); }
    if (manualSecret && manualSecret !== pendingSecret) return json(request, { error: "The setup key does not match this page. Copy the key again, then try." }, 400);

    const currentCounter = Math.floor(Date.now() / 1000 / TOTP_PERIOD_SECONDS);
    let acceptedCounter: number | null = null;
    for (let offset = -TOTP_SKEW_WINDOWS; offset <= TOTP_SKEW_WINDOWS; offset++) {
      const counter = currentCounter + offset;
      if (!account.pendingUsedTotpSteps.includes(counter) && (await totpForCounter(pendingSecret, counter)) === otp) { acceptedCounter = counter; break; }
    }
    if (acceptedCounter === null) return json(request, { error: incrementAuthenticatorFailure(account) }, 400);
    account.pendingUsedTotpSteps.push(acceptedCounter);
    account.encryptedSecret = account.pendingEncryptedSecret; account.pendingEncryptedSecret = undefined;
    account.authenticator = undefined; account.mfaEnabled = true;
    const codes = await makeBackupCodes(); account.backupCodes = codes.stored; account.recoveryAttempts = 0; account.recoveryLockedUntil = 0;
    return json(request, { message: "Authenticator confirmed.", recoveryCodes: codes.plain });
  }
  if (pathname === "/api/recovery/confirm" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    if (!account.mfaEnabled) return json(request, { error: "Set up your authenticator before completing enrolment." }, 400);
    return json(request, { message: "MFA enrolment is complete." });
  }
  if (pathname === "/api/recovery/regenerate" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    if (!account.mfaEnabled) return json(request, { error: "MFA is not active on this account." }, 400);
    const codes = await makeBackupCodes(); account.backupCodes = codes.stored; account.recoveryAttempts = 0; account.recoveryLockedUntil = 0;
    return json(request, { message: "New recovery codes are ready. Older codes no longer work.", recoveryCodes: codes.plain });
  }
  if (pathname === "/api/recovery/use" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    if (account.recoveryLockedUntil > Date.now()) return json(request, { error: recoveryLockMessage(account.recoveryLockedUntil) }, 429);
    if (account.recoveryLockedUntil) { account.recoveryLockedUntil = 0; account.recoveryAttempts = 0; }
    const code = stringField(body, "code", 20).replace(/[-\s]/g, "").toUpperCase();
    if (!validRecovery(code)) return json(request, { error: failedRecovery(account) }, 400);
    let found = false;
    for (const saved of account.backupCodes) {
      const possible = await sha256(saved.salt + ":" + code);
      if (!saved.used && possible === saved.hash) { saved.used = true; found = true; }
    }
    if (!found) return json(request, { error: failedRecovery(account) }, 400);
    account.recoveryAttempts = 0;
    return json(request, { message: "Recovery code accepted. That code has now been used." });
  }
  if (pathname === "/api/logout" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    sessions.delete(session.id);
    return json(request, { message: "Signed out." }, 200, { "Set-Cookie": cleanCookie() });
  }
  return json(request, { error: "That service is not available." }, 404);
}

const HTML = String.raw`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank – MFA setup</title>
<style nonce="__CSP_NONCE__">
:root{--ink:#162235;--muted:#536174;--paper:#f5f8fc;--card:#fff;--blue:#0759bd;--dark:#063f8a;--line:#d4ddea;--good:#12623c;--bad:#a22929;--focus:#ee9b00}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font-family:Arial,"Atkinson Hyperlegible","Segoe UI",sans-serif;font-size:17px;line-height:1.65;letter-spacing:.025em}button,input{font:inherit;letter-spacing:.025em}button{cursor:pointer}.shell{max-width:630px;margin:auto;padding:17px 15px 42px}header{display:flex;gap:11px;align-items:center;margin:4px 0 20px}.mark{width:44px;height:44px;border-radius:14px;display:grid;place-items:center;background:var(--blue);color:#fff;font-size:23px}h1{font-size:1.35rem;line-height:1.2;margin:0}h2{font-size:1.36rem;line-height:1.3;margin:0 0 10px}p{margin:0 0 14px}.small,.hint{color:var(--muted);font-size:.9rem}.steps{display:flex;gap:5px;margin-bottom:18px}.step{flex:1;padding:6px 3px;border-radius:8px;background:#e5eaf2;color:var(--muted);font-size:.7rem;text-align:center;line-height:1.3}.step.current{background:#dceaff;color:var(--dark);font-weight:bold}.card{padding:22px;background:var(--card);border:1px solid var(--line);border-radius:17px;box-shadow:0 2px 8px #18385a0b}.cue{display:flex;gap:10px;align-items:center;color:var(--dark);font-weight:bold;margin-bottom:10px;font-size:1.05rem}label{display:block;font-weight:bold;margin:15px 0 5px}input{width:100%;min-height:50px;padding:11px 13px;border:2px solid #adbacd;border-radius:10px;color:var(--ink);background:#fff}input:focus,button:focus{outline:3px solid var(--focus);outline-offset:2px}.code{font-size:1.18rem;letter-spacing:.14em}.primary,.secondary{width:100%;min-height:52px;padding:10px 14px;border-radius:11px;font-weight:bold;margin-top:18px}.primary{border:0;background:var(--blue);color:#fff}.primary:hover{background:var(--dark)}.secondary{border:2px solid var(--blue);background:#fff;color:var(--blue);margin-top:10px}.notice{padding:11px 13px;border-radius:10px;background:#e7f5ec;color:var(--good);font-weight:bold;margin:12px 0}.error{background:#fff0f0;color:var(--bad)}.noticebox:empty{display:none}details{border-top:1px solid var(--line);margin-top:19px;padding-top:12px;color:var(--muted)}summary{color:var(--blue);font-weight:bold;cursor:pointer}.secret{padding:10px;border-radius:10px;background:#f0f4f9;word-break:break-all;font-family:monospace;letter-spacing:.1em}.qr{width:250px;height:250px;max-width:100%;display:block;margin:15px auto;background:#fff;image-rendering:pixelated;box-shadow:0 0 0 1px var(--line)}.codes{list-style:none;padding:0;margin:13px 0}.codes li{font-family:monospace;font-weight:bold;letter-spacing:.1em;padding:7px;border-bottom:1px solid var(--line)}.top{display:flex;justify-content:space-between;align-items:center}.link{border:0;background:transparent;color:var(--blue);text-decoration:underline;font-weight:bold;padding:5px}.logs{margin-top:18px;border:1px solid var(--line);border-radius:13px;background:#fff;padding:13px}.logs h2{font-size:1rem}.logline{font-family:monospace;font-size:.78rem;overflow-wrap:anywhere;padding:5px 0;border-bottom:1px solid #edf0f5}.logline:last-child{border:0}@media print{header,.steps,button,details,.logs,.noticebox{display:none!important}.card{box-shadow:none;border:0}}
</style></head><body>
<main class="shell"><header><div class="mark" aria-hidden="true">⚓</div><div><h1>Harbour Bank</h1><div class="small">MFA enrolment</div></div></header>
<nav class="steps" id="steps" aria-label="Setup progress"></nav><section id="app" aria-live="polite"><div class="card">Loading your secure page…</div></section>
<section class="logs" aria-label="Browser simulation logs"><h2>Logs</h2><div id="logs">No simulation messages yet.</div></section></main>
<script nonce="__CSP_NONCE__">
(function(){
"use strict";
var app=document.getElementById("app"),steps=document.getElementById("steps"),logs=document.getElementById("logs"),csrf="",setupSecret="",currentCodes=[];

function log(message){console.log(message);if(logs.textContent==="No simulation messages yet.")logs.replaceChildren();var row=document.createElement("div");row.className="logline";row.textContent=message;logs.appendChild(row)}
function el(tag,text,cls){var node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(cls)node.className=cls;return node}
function clear(){app.replaceChildren()}function button(text,cls){var b=el("button",text,cls||"primary");b.type="button";return b}
function input(type,name,placeholder){var i=document.createElement("input");i.type=type;i.name=name;i.placeholder=placeholder||"";return i}
function box(){var x=el("div",undefined,"noticebox");x.setAttribute("role","status");return x}
function show(target,text,bad){target.replaceChildren(el("div",text,"notice"+(bad?" error":"")))}
function help(text){var d=document.createElement("details"),s=el("summary","Help");d.append(s,el("p",text));return d}
function drawSteps(active){steps.replaceChildren();[["signin","1 · Sign in"],["identity","2 · Confirm"],["provision","3 · App"],["recovery","4 · Codes"]].forEach(function(item){steps.appendChild(el("div",item[1],"step"+(item[0]===active?" current":"")))})}
async function request(path,data,method){var options={method:method||"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},credentials:"same-origin"};if(options.method!=="GET")options.body=JSON.stringify(data||{});var response=await fetch(path,options),body;try{body=await response.json()}catch(e){throw new Error("Something went wrong. Please try again.")}if(!response.ok)throw new Error(body.error||"Something went wrong. Please try again.");if(body.csrf)csrf=body.csrf;return body}
function action(form,label,target,callback){var b=button(label);form.appendChild(b);form.addEventListener("submit",function(e){e.preventDefault();b.disabled=true;show(target,"",false);callback().catch(function(err){show(target,err.message||"Something went wrong. Please try again.",true)}).finally(function(){b.disabled=false})})}
function copy(value,label){navigator.clipboard.writeText(value).then(function(){log(label+" copied to clipboard.")}).catch(function(){log("Copy was not available. Select the text and copy it instead.")})}

/* Real QR encoder: byte-mode QR version 10-L, Reed-Solomon ECC, SVG-free canvas output. */
function qrCanvas(text){
 var n=57,cap=274,bytes=new TextEncoder().encode(text),bits=[];
 function put(v,l){for(var i=l-1;i>=0;i--)bits.push((v>>>i)&1)}put(4,4);put(bytes.length,16);for(var z=0;z<bytes.length;z++)put(bytes[z],8);for(var t=0;t<Math.min(4,cap*8-bits.length);t++)bits.push(0);while(bits.length%8)bits.push(0);
 var data=[];for(var p=0;p<bits.length;p+=8){var q=0;for(var k=0;k<8;k++)q=(q<<1)|bits[p+k];data.push(q)}for(var pad=0;data.length<cap;pad++)data.push(pad%2?17:236);
 var exp=[],logt=[];var x=1;for(var i=0;i<255;i++){exp[i]=x;logt[x]=i;x<<=1;if(x&256)x^=285}for(i=255;i<512;i++)exp[i]=exp[i-255];
 function mul(a,b){return!a||!b?0:exp[logt[a]+logt[b]]}function poly(deg){var r=[1];for(var j=0;j<deg;j++){var a=exp[j],next=[];for(var h=0;h<r.length+1;h++)next[h]=(h<r.length? r[h]:0)^(h?r[h-1]&&mul(r[h-1],a):0);r=next}return r}
 function ecc(block){var gen=poly(18),r=new Array(18).fill(0);for(var j=0;j<block.length;j++){var f=block[j]^r.shift();r.push(0);for(var h=0;h<18;h++)r[h]^=mul(gen[h+1],f)}return r}
 var blocks=[],offset=0;for(i=0;i<4;i++){var len=i<2?68:69;blocks.push(data.slice(offset,offset+len));offset+=len}var ec=blocks.map(ecc),stream=[];for(i=0;i<69;i++)for(var j=0;j<4;j++)if(i<blocks[j].length)stream.push(blocks[j][i]);for(i=0;i<18;i++)for(j=0;j<4;j++)stream.push(ec[j][i]);
 var m=Array.from({length:n},function(){return Array(n).fill(null)}),reserved=Array.from({length:n},function(){return Array(n).fill(false)});
 function set(r,c,v){if(r>=0&&c>=0&&r<n&&c<n){m[r][c]=v;reserved[r][c]=true}}function finder(r,c){for(var y=-1;y<=7;y++)for(var xx=-1;xx<=7;xx++)set(r+y,c+xx,y>=0&&y<=6&&xx>=0&&xx<=6&&(y===0||y===6||xx===0||xx===6||(y>=2&&y<=4&&xx>=2&&xx<=4)))}
 finder(0,0);finder(0,n-7);finder(n-7,0);
 for(i=8;i<n-8;i++){set(6,i,i%2===0);set(i,6,i%2===0)}var centers=[6,28,50];for(var a=0;a<centers.length;a++)for(var b=0;b<centers.length;b++){var rr=centers[a],cc=centers[b];if((rr<9&&cc<9)||(rr<9&&cc>n-9)||(rr>n-9&&cc<9))continue;for(var yy=-2;yy<=2;yy++)for(var xx=-2;xx<=2;xx++)set(rr+yy,cc+xx,Math.max(Math.abs(yy),Math.abs(xx))!==1)}
 for(i=0;i<9;i++){if(!reserved[i][8])set(i,8,false);if(!reserved[8][i])set(8,i,false);if(!reserved[i][n-8])set(i,n-8,false);if(!reserved[n-8][i])set(n-8,i,false)}set(n-8,8,true);
 function bch(v,polyv){var d=0;for(var u=polyv;u;u>>=1)d++;v<<=d-1;while(v.toString(2).length>=d){var shift=v.toString(2).length-d;v^=polyv<<shift}return v}
 var fmt=((1<<3)|0);fmt=(fmt<<10|bch(fmt,1335))^21522;for(i=0;i<15;i++){var bit=((fmt>>i)&1)===1;if(i<6)set(i,8,bit);else if(i<8)set(i+1,8,bit);else set(n-15+i,8,bit);if(i<8)set(8,n-i-1,bit);else if(i<9)set(8,15-i,bit);else set(8,14-i-1,bit)}
 var bi=0,up=true;for(var col=n-1;col>0;col-=2){if(col===6)col--;for(var rowi=0;rowi<n;rowi++){var row=up?n-1-rowi:rowi;for(var side=0;side<2;side++){var c=col-side;if(!reserved[row][c]){var bit=bi<stream.length?((stream[bi>>3]>>(7-(bi&7)))&1):0;bi++;if((row+c)%2===0)bit^=1;m[row][c]=!!bit}}up=!up}
 var canvas=document.createElement("canvas");canvas.width=canvas.height=n*4;canvas.className="qr";canvas.setAttribute("role","img");canvas.setAttribute("aria-label","Scannable QR code for Harbour Bank authenticator setup");var ctx=canvas.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle="#000";for(var r=0;r<n;r++)for(var c=0;c<n;c++)if(m[r][c])ctx.fillRect(c*4,r*4,4,4);return canvas
}

function signIn(){drawSteps("signin");clear();var c=el("section",undefined,"card"),n=box(),f=document.createElement("form");c.append(el("div","🔐 Sign in","cue"),el("h2","Set up extra payment protection"),el("p","Sign in first. You will take this one step at a time."),n);var email=input("email","email","name@example.com"),password=input("password","password","Your password");email.autocomplete="email";password.autocomplete="current-password";f.append(el("label","Email address"),email,el("p","Example: marcus@example.com","hint"),el("label","Password"),password,el("p","Demo: marcus@example.com / BankPass1!","hint"));action(f,"Sign in securely",n,async function(){var j=await request("/api/signin",{email:email.value,password:password.value,csrf:csrf});csrf=j.csrf;log("Sign-in simulation complete.");if(j.step==="settings")settings();else if(j.step==="provision")provisionStart();else identity()});c.append(f,help("Use the demo details shown above. No information is saved in your browser."));app.appendChild(c)}
function identity(){drawSteps("identity");clear();var c=el("section",undefined,"card"),n=box(),f=document.createElement("form");c.append(el("div","🪪 Confirm your identity","cue"),el("h2","Get a short verification code"),el("p","Select send. You can request another code whenever you need."),n);var send=button("Send verification code"),code=input("text","code","123456");code.inputMode="numeric";code.maxLength=6;code.autocomplete="one-time-code";code.className="code";send.onclick=async function(){send.disabled=true;try{var j=await request("/api/identity/request",{});log("Identity verification test code: "+j.testCode);show(n,j.message,false);send.textContent="Send another code"}catch(e){show(n,e.message,true)}finally{send.disabled=false}};f.append(el("label","Six-digit code"),code,el("p","Example: 123456","hint"));action(f,"Confirm identity",n,async function(){await request("/api/identity/verify",{code:code.value});log("Identity verification completed.");provisionStart()});c.append(send,f,help("The test code appears in the browser console and the Logs panel after you select Send. There is no reading countdown."));app.appendChild(c)}
function provisionStart(){drawSteps("provision");clear();var c=el("section",undefined,"card"),n=box(),b=button("Create my setup key");c.append(el("div","📱 Authenticator app","cue"),el("h2","Make your setup key"),el("p","Use an authenticator app. You can scan a QR option or copy the setup key."),n);b.onclick=async function(){b.disabled=true;try{var j=await request("/api/provision",{});setupSecret=j.secret;log("Current authenticator test OTP: "+j.testOtp+" (changes with its 30-second TOTP window).");provisionScreen(j.email)}catch(e){show(n,e.message,true)}finally{b.disabled=false}};c.append(b,help("Choose this when you are ready. Starting again creates a different setup key without removing any safety lockout."));app.appendChild(c)}
function provisionScreen(email){drawSteps("provision");clear();var c=el("section",undefined,"card"),n=box(),f=document.createElement("form");c.append(el("div","📷 Scan or copy","cue"),el("h2","Add this to your authenticator app"),el("p","Scan the QR code first. If scanning is difficult, copy the setup key below instead."),n);var uri="otpauth://totp/"+encodeURIComponent("Harbour Bank:"+email)+"?secret="+encodeURIComponent(setupSecret)+"&issuer="+encodeURIComponent("Harbour Bank")+"&algorithm=SHA1&digits=6&period=30";c.append(qrCanvas(uri),el("p","Setup key","hint"));var secret=el("div",setupSecret,"secret");secret.setAttribute("aria-label","Setup key "+setupSecret.split("").join(" "));c.append(secret);var copyKey=button("Copy setup key","secondary");copyKey.onclick=function(){copy(setupSecret,"Setup key")};c.append(copyKey);var copyUri=button("Copy authenticator QR link","secondary");copyUri.onclick=function(){copy(uri,"Authenticator setup link")};c.append(copyUri);var manual=input("text","manual","Paste setup key here if needed"),otp=input("text","otp","123456");otp.inputMode="numeric";otp.maxLength=6;otp.autocomplete="one-time-code";otp.className="code";f.append(el("label","Manual setup key (optional)"),manual,el("p","Paste it only if your app asks you to confirm it.","hint"),el("label","Six-digit code from your app"),otp,el("p","Example: 123456. The current test value is in Logs.","hint"));action(f,"Confirm authenticator",n,async function(){var j=await request("/api/authenticator/activate",{manualSecret:manual.value,otp:otp.value});setupSecret="";currentCodes=j.recoveryCodes||[];log("Authenticator verification completed. Recovery codes: "+currentCodes.join(", "));recovery(false)});var restart=button("Start setup again","secondary");restart.onclick=provisionStart;c.append(f,restart,help("There is no time limit for reading. A TOTP is valid for its short authenticator window, and a fresh current test value is shown whenever setup is created."));app.appendChild(c)}
function recovery(regenerated){drawSteps("recovery");clear();var c=el("section",undefined,"card"),n=box(),list=el("ul",undefined,"codes"),f=document.createElement("form");c.append(el("div","🧾 Recovery codes","cue"),el("h2",regenerated?"Your new recovery codes":"Save these recovery codes"),el("p","Each code works once if you cannot use your authenticator. Keep them somewhere private."),n);currentCodes.forEach(function(code){list.appendChild(el("li",code))});c.append(list);var cp=button("Copy all recovery codes","secondary");cp.onclick=function(){copy(currentCodes.join("\n"),"Recovery codes")};c.append(cp);var tick=document.createElement("input");tick.type="checkbox";tick.id="saved";f.append(tick);var label=el("label"," I have saved these codes somewhere private.");label.htmlFor="saved";label.style.display="inline";f.append(label);action(f,regenerated?"Return to settings":"Finish MFA setup",n,async function(){if(!tick.checked)throw new Error("Please tick the box after you have saved the codes.");await request("/api/recovery/confirm",{});log("MFA enrolment completed.");settings()});c.append(f,help("You may copy before continuing. Do not share these codes."));app.appendChild(c)}
function settings(){drawSteps("recovery");clear();var c=el("section",undefined,"card"),n=box(),top=el("div",undefined,"top");top.appendChild(el("strong","🔐 MFA settings"));var out=button("Sign out","link");out.onclick=async function(){out.disabled=true;try{await request("/api/logout",{});csrf="";setupSecret="";currentCodes=[];log("Signed out. Secure session invalidated.");boot()}catch(e){show(n,e.message,true)}finally{out.disabled=false}};top.appendChild(out);c.append(top,el("h2","Your authenticator is active"),el("p","Your account has extra protection for higher-value payments."),n);var regenerate=button("Make new recovery codes");regenerate.onclick=async function(){regenerate.disabled=true;try{var j=await request("/api/recovery/regenerate",{});currentCodes=j.recoveryCodes||[];log("Recovery codes regenerated: "+currentCodes.join(", "));recovery(true)}catch(e){show(n,e.message,true)}finally{regenerate.disabled=false}};c.append(regenerate,help("New recovery codes replace older ones. You can sign out whenever you are finished."));app.appendChild(c)}
async function boot(){try{var j=await request("/api/bootstrap",null,"GET");csrf=j.csrf;signIn()}catch(e){clear();app.appendChild(el("div","This secure page could not start. Refresh and try again.","notice error"))}}boot()
})();
</script></body></html>`;

serve({
  port: Number(process.env.PORT || 3000),
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      if (url.pathname === "/" && request.method === "GET") return page(request);
      return new Response("Not found.", { status: 404, headers: securityHeaders(request) });
    } catch {
      return new Response("Something went wrong. Please try again.", { status: 500, headers: securityHeaders(request) });
    }
  },
});
