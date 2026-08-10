
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHmac,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

/*
 MFA Enrolment System
 Single-file Bun HTTPS server and mobile HTML application.

 Requirement 1: all account state is server-owned and accessed only through
 the authenticated session's account identity. No submitted account identifiers
 are accepted by MFA endpoints.
*/

type Session = {
  id: string;
  accountId: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
  identityVerified: boolean;
  mfaEnabled: boolean;
};

type Challenge = {
  code: string;
  expiresAt: number;
  attempts: number;
  lockedUntil: number;
  used: boolean;
};

type RecoveryVerifier = {
  salt: string;
  verifier: string;
};

type Account = {
  id: string;
  email: string;
  mfaEnabled: boolean;
  pendingEncryptedSecret?: string;
  encryptedSecret?: string;
  identityChallenge?: Challenge;
  usedTotpCounters: Set<string>;
  authenticatorAttempts: number;
  authenticatorLockedUntil: number;
  recoveryVerifiers: RecoveryVerifier[];
  recoveryAttempts: number;
  recoveryLockedUntil: number;
  recoveryConfirmed: boolean;
};

const sessions = new Map<string, Session>();
const accountsById = new Map<string, Account>();
const accountIdByEmail = new Map<string, string>();
const loginCsrfTokens = new Map<string, number>();
const encryptionKey = randomBytes(32);

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const RECOVERY_KDF_N = 16384;

function secureToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function randomNumericCode(): string {
  return String(randomBytes(4).readUInt32BE(0) % 1000000).padStart(6, "0");
}

function base32Secret(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const input = randomBytes(20);
  let bits = 0;
  let value = 0;
  let result = "";
  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) result += alphabet[(value << (5 - bits)) & 31];
  return result;
}

/* Requirement 3: AES-256-GCM protects TOTP material while held at rest. */
function encryptAtRest(value: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return [
    iv.toString("base64url"),
    cipher.getAuthTag().toString("base64url"),
    encrypted.toString("base64url"),
  ].join(".");
}

function decryptAtRest(value: string): string {
  const [iv, tag, encrypted] = value.split(".");
  if (!iv || !tag || !encrypted) throw new Error("Invalid protected value");
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(encrypted, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

function base32Decode(value: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const input = value.replace(/=+$/g, "").toUpperCase();
  let bits = 0;
  let current = 0;
  const output: number[] = [];
  for (const character of input) {
    const position = alphabet.indexOf(character);
    if (position < 0) throw new Error("Invalid base32");
    current = (current << 5) | position;
    bits += 5;
    if (bits >= 8) {
      output.push((current >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

/* Requirement task: RFC 6238-compatible HMAC-SHA1 TOTP, 30 seconds, six digits. */
function totpForCounter(secret: string, counter: number): string {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", base32Decode(secret)).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 15;
  const value = (
    ((digest[offset] & 127) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3]
  ) % 1000000;
  return String(value).padStart(6, "0");
}

function matchingTotpCounter(secret: string, code: string): number | null {
  const current = Math.floor(Date.now() / 30000);
  for (const offset of [-1, 0, 1]) {
    const counter = current + offset;
    if (counter >= 0 && totpForCounter(secret, counter) === code) return counter;
  }
  return null;
}

/* Requirement task: high entropy codes with an individual random salt and scrypt verifier. */
function makeBackupCodes(): string[] {
  const codes: string[] = [];
  for (let index = 0; index < 8; index++) {
    const value = randomBytes(10).toString("hex").toUpperCase();
    codes.push(`${value.slice(0, 10)}-${value.slice(10, 20)}`);
  }
  return codes;
}

function makeRecoveryVerifiers(codes: string[]): RecoveryVerifier[] {
  return codes.map((code) => {
    const salt = randomBytes(16);
    const verifier = scryptSync(code, salt, 32, { N: RECOVERY_KDF_N, r: 8, p: 1 });
    return { salt: salt.toString("base64url"), verifier: verifier.toString("base64url") };
  });
}

function recoveryCodeMatches(code: string, stored: RecoveryVerifier): boolean {
  const salt = Buffer.from(stored.salt, "base64url");
  const expected = Buffer.from(stored.verifier, "base64url");
  const actual = scryptSync(code, salt, 32, { N: RECOVERY_KDF_N, r: 8, p: 1 });
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validSixDigits(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function validBackupCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9]{10}-[A-Za-z0-9]{10}$/.test(value);
}

function parseCookies(request: Request): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const item of (request.headers.get("cookie") || "").split(";")) {
    const separator = item.indexOf("=");
    if (separator > 0) cookies[item.slice(0, separator).trim()] = item.slice(separator + 1).trim();
  }
  return cookies;
}

function sessionCookie(id: string): string {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}

function loginCsrfCookie(token: string): string {
  return `mfa_login_csrf=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=600`;
}

function expiredCookie(name: string): string {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

/* Requirement 2: production-safe response headers and no permissive CORS. */
function securityHeaders(nonce: string): Headers {
  return new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
}

function json(data: unknown, status = 200, nonce = secureToken(12), extra?: HeadersInit): Response {
  const headers = securityHeaders(nonce);
  if (extra) new Headers(extra).forEach((value, key) => headers.set(key, value));
  return new Response(JSON.stringify(data), { status, headers });
}

function genericError(status: number, nonce: string): Response {
  return json({ error: "We could not complete that request. Please try again." }, status, nonce);
}

/* Requirement task: every state change requires the exact same trusted HTTPS origin. */
function trustedSameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    const expected = new URL(request.url);
    const supplied = new URL(origin);
    if (supplied.origin !== expected.origin || supplied.protocol !== "https:") return false;
    return ["localhost", "127.0.0.1", "[::1]"].includes(supplied.hostname);
  } catch {
    return false;
  }
}

function accountForSession(session: Session): Account | null {
  return accountsById.get(session.accountId) || null;
}

function accountForAuthenticatedIdentity(email: string): Account {
  const normalized = email.trim().toLowerCase();
  const existingId = accountIdByEmail.get(normalized);
  if (existingId) return accountsById.get(existingId)!;

  const account: Account = {
    id: secureToken(18),
    email: normalized,
    mfaEnabled: false,
    usedTotpCounters: new Set(),
    authenticatorAttempts: 0,
    authenticatorLockedUntil: 0,
    recoveryVerifiers: [],
    recoveryAttempts: 0,
    recoveryLockedUntil: 0,
    recoveryConfirmed: false,
  };
  accountIdByEmail.set(normalized, account.id);
  accountsById.set(account.id, account);
  return account;
}

function requireSession(request: Request, nonce: string): { session?: Session; account?: Account; response?: Response } {
  const id = parseCookies(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  const now = Date.now();
  if (!session || now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    if (id) sessions.delete(id);
    return {
      response: json(
        { error: "Please sign in again to continue." },
        401,
        nonce,
        { "Set-Cookie": expiredCookie("mfa_session") },
      ),
    };
  }
  const account = accountForSession(session);
  if (!account) {
    sessions.delete(session.id);
    return { response: genericError(401, nonce) };
  }
  session.lastSeen = now;
  session.mfaEnabled = account.mfaEnabled;
  return { session, account };
}

function csrfIsValid(request: Request, session: Session): boolean {
  const token = request.headers.get("x-csrf-token");
  return !!token && token.length > 20 && token === session.csrf;
}

async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function challengeFailure(challenge: Challenge): string {
  const now = Date.now();
  if (challenge.lockedUntil > now) return "Too many attempts. Wait ten minutes, then request a new code.";
  challenge.attempts++;
  if (challenge.attempts >= MAX_ATTEMPTS) {
    challenge.lockedUntil = now + LOCKOUT_MS;
    return "Too many attempts. Wait ten minutes, then request a new code.";
  }
  return "That code did not work. Check the six digits and try again.";
}

function accountLockFailure(account: Account, type: "authenticator" | "recovery"): string {
  const now = Date.now();
  const attemptKey = type === "authenticator" ? "authenticatorAttempts" : "recoveryAttempts";
  const lockKey = type === "authenticator" ? "authenticatorLockedUntil" : "recoveryLockedUntil";
  if (account[lockKey] > now) {
    return "Too many attempts. Wait ten minutes before trying again. Starting over will not remove this wait.";
  }
  account[attemptKey]++;
  if (account[attemptKey] >= MAX_ATTEMPTS) {
    account[lockKey] = now + LOCKOUT_MS;
    return "Too many attempts. Wait ten minutes before trying again. Starting over will not remove this wait.";
  }
  if (type === "recovery") {
    return `That recovery code did not work. Check all 20 characters and try again. ${MAX_ATTEMPTS - account[attemptKey]} tries remain before a ten-minute wait.`;
  }
  return `That authenticator code did not work. Check the current six digits and try again. ${MAX_ATTEMPTS - account[attemptKey]} tries remain before a ten-minute wait.`;
}

async function api(request: Request, pathname: string, nonce: string): Promise<Response> {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: securityHeaders(nonce) });

  /* Pre-login same-origin CSRF protection for authentication. */
  if (pathname === "/api/login-csrf" && request.method === "GET") {
    const token = secureToken();
    loginCsrfTokens.set(token, Date.now() + 10 * 60 * 1000);
    return json({ token }, 200, nonce, { "Set-Cookie": loginCsrfCookie(token) });
  }

  if (pathname === "/api/authenticate" && request.method === "POST") {
    if (!trustedSameOrigin(request)) return genericError(403, nonce);
    const cookies = parseCookies(request);
    const token = request.headers.get("x-login-csrf-token");
    const expiresAt = token ? loginCsrfTokens.get(token) : undefined;
    if (!token || cookies.mfa_login_csrf !== token || !expiresAt || expiresAt < Date.now()) {
      return genericError(403, nonce);
    }
    loginCsrfTokens.delete(token);
    const input = await body(request);
    if (!input || !validEmail(input.email)) return genericError(400, nonce);

    const oldId = cookies.mfa_session;
    if (oldId) sessions.delete(oldId);

    /* The mock authenticated identity selects one server-owned account record. */
    const account = accountForAuthenticatedIdentity(input.email);
    const session: Session = {
      id: secureToken(),
      accountId: account.id,
      csrf: secureToken(),
      createdAt: Date.now(),
      lastSeen: Date.now(),
      identityVerified: false,
      mfaEnabled: account.mfaEnabled,
    };
    sessions.set(session.id, session);
    return json(
      { csrf: session.csrf, next: account.mfaEnabled ? "complete" : "identity" },
      200,
      nonce,
      {
        "Set-Cookie": `${sessionCookie(session.id)}, ${expiredCookie("mfa_login_csrf")}`,
      },
    );
  }

  const checked = requireSession(request, nonce);
  if (checked.response) return checked.response;
  const session = checked.session!;
  const account = checked.account!;

  if (pathname === "/api/status" && request.method === "GET") {
    return json({
      csrf: session.csrf,
      identityVerified: session.identityVerified,
      mfaEnabled: account.mfaEnabled,
      recoveryConfirmed: account.recoveryConfirmed,
    }, 200, nonce);
  }

  if (request.method === "POST" && (!trustedSameOrigin(request) || !csrfIsValid(request, session))) {
    return genericError(403, nonce);
  }

  if (pathname === "/api/logout" && request.method === "POST") {
    sessions.delete(session.id);
    return json({ ok: true }, 200, nonce, { "Set-Cookie": expiredCookie("mfa_session") });
  }

  if (pathname === "/api/identity/request" && request.method === "POST") {
    account.identityChallenge = {
      code: randomNumericCode(),
      expiresAt: Date.now() + CODE_LIFETIME_MS,
      attempts: 0,
      lockedUntil: 0,
      used: false,
    };
    /*
      Simulated delivery is provided to the authenticated page only. It is not
      logged by browser or server and is not included in a URL.
    */
    return json({
      deliveredCode: account.identityChallenge.code,
      message: "Your six-digit check code is ready.",
    }, 200, nonce);
  }

  if (pathname === "/api/identity/verify" && request.method === "POST") {
    const input = await body(request);
    const challenge = account.identityChallenge;
    if (!input || !validSixDigits(input.code) || !challenge || challenge.used || Date.now() > challenge.expiresAt) {
      return json({ error: "That code did not work. Request a new code and try again." }, 400, nonce);
    }
    if (input.code !== challenge.code) return json({ error: challengeFailure(challenge) }, 400, nonce);
    challenge.used = true;
    session.identityVerified = true;
    return json({ ok: true, message: "Identity check complete. Next, set up your authenticator." }, 200, nonce);
  }

  if (pathname === "/api/authenticator/setup" && request.method === "POST") {
    if (!session.identityVerified) return genericError(403, nonce);
    if (account.authenticatorLockedUntil > Date.now()) {
      return json({
        error: "Too many attempts. Wait ten minutes before trying again. Starting over will not remove this wait.",
      }, 429, nonce);
    }

    const secret = base32Secret();
    account.pendingEncryptedSecret = encryptAtRest(secret);
    const issuer = "Northstar Demo Bank";
    const provisioningUri =
      `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account.email)}` +
      `?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

    return json({
      secret,
      provisioningUri,
      message: "Your authenticator details are ready.",
    }, 200, nonce);
  }

  if (pathname === "/api/authenticator/verify" && request.method === "POST") {
    const input = await body(request);
    if (!session.identityVerified || !input || !validSixDigits(input.code) || !account.pendingEncryptedSecret) {
      return json({ error: "Set up your authenticator first, then enter its current six-digit code." }, 400, nonce);
    }
    if (account.authenticatorLockedUntil > Date.now()) {
      return json({
        error: "Too many attempts. Wait ten minutes before trying again. Starting over will not remove this wait.",
      }, 429, nonce);
    }

    let secret = "";
    try {
      secret = decryptAtRest(account.pendingEncryptedSecret);
    } catch {
      return genericError(400, nonce);
    }
    const counter = matchingTotpCounter(secret, input.code);
    if (counter === null || account.usedTotpCounters.has(String(counter))) {
      return json({ error: accountLockFailure(account, "authenticator") }, 400, nonce);
    }

    account.usedTotpCounters.add(String(counter));
    account.authenticatorAttempts = 0;
    account.authenticatorLockedUntil = 0;
    account.encryptedSecret = account.pendingEncryptedSecret;
    account.pendingEncryptedSecret = undefined;
    account.mfaEnabled = true;
    session.mfaEnabled = true;

    const codes = makeBackupCodes();
    account.recoveryVerifiers = makeRecoveryVerifiers(codes);
    account.recoveryAttempts = 0;
    account.recoveryLockedUntil = 0;
    account.recoveryConfirmed = false;
    return json({
      ok: true,
      recoveryCodes: codes,
      message: "Authenticator set up. Save your recovery codes next.",
    }, 200, nonce);
  }

  if (pathname === "/api/recovery/regenerate" && request.method === "POST") {
    if (!account.mfaEnabled) return genericError(403, nonce);
    const codes = makeBackupCodes();
    account.recoveryVerifiers = makeRecoveryVerifiers(codes);
    account.recoveryAttempts = 0;
    account.recoveryLockedUntil = 0;
    account.recoveryConfirmed = false;
    return json({
      recoveryCodes: codes,
      message: "New recovery codes are ready. Old codes no longer work.",
    }, 200, nonce);
  }

  if (pathname === "/api/recovery/confirm" && request.method === "POST") {
    if (!account.mfaEnabled) return genericError(403, nonce);
    account.recoveryConfirmed = true;
    return json({ ok: true, message: "Recovery codes marked as saved." }, 200, nonce);
  }

  /* Requirement 5 + task: account-scoped recovery rate limiting and one-time use. */
  if (pathname === "/api/recovery/use" && request.method === "POST") {
    const input = await body(request);
    if (account.recoveryLockedUntil > Date.now()) {
      return json({
        error: "Too many attempts. Wait ten minutes before trying again. Starting over will not remove this wait.",
      }, 429, nonce);
    }
    if (!input || !validBackupCode(input.code)) {
      return json({ error: accountLockFailure(account, "recovery") }, 400, nonce);
    }
    const normalized = input.code.toUpperCase();
    let matchingIndex = -1;
    for (let index = 0; index < account.recoveryVerifiers.length; index++) {
      if (recoveryCodeMatches(normalized, account.recoveryVerifiers[index])) {
        matchingIndex = index;
        break;
      }
    }
    if (matchingIndex < 0) return json({ error: accountLockFailure(account, "recovery") }, 400, nonce);

    account.recoveryVerifiers.splice(matchingIndex, 1);
    account.recoveryAttempts = 0;
    account.recoveryLockedUntil = 0;
    return json({ ok: true, message: "Recovery code accepted. It cannot be used again." }, 200, nonce);
  }

  return genericError(404, nonce);
}

function page(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Northstar Bank · Set up extra security</title>
<style nonce="${nonce}">
:root{--ink:#17212b;--muted:#52616e;--blue:#075cba;--blue2:#034786;--pale:#edf6ff;--line:#c8d5df;--good:#12643a;--danger:#a92020}
*{box-sizing:border-box}body{margin:0;background:#f4f7f9;color:var(--ink);font-family:Arial,Verdana,Tahoma,sans-serif;font-size:18px;line-height:1.62;letter-spacing:.025em}
button,input{font:inherit;letter-spacing:.025em}.shell{width:min(100%,600px);min-height:100vh;margin:auto;background:#fff;padding:20px 18px 42px}
header{border-bottom:2px solid var(--line);padding-bottom:15px}.brand{font-size:1rem;color:var(--blue2);font-weight:700}h1{margin:12px 0 4px;font-size:1.65rem;line-height:1.25;letter-spacing:.01em}h2{font-size:1.32rem;line-height:1.3;margin:0 0 10px}p{margin:8px 0 15px}
.steps{display:flex;gap:5px;margin:18px 0 25px;list-style:none;padding:0}.steps li{flex:1;min-height:45px;padding:6px 3px;text-align:center;font-size:.72rem;line-height:1.2;border-bottom:5px solid var(--line);color:var(--muted)}.steps li.current{color:var(--blue2);border-color:var(--blue);font-weight:bold}.steps li.done{color:var(--good);border-color:var(--good)}
.card{border:1px solid var(--line);border-radius:14px;padding:20px;margin-top:12px;box-shadow:0 2px 8px #1231}.icon{font-size:2rem;display:block;margin-bottom:8px}label{display:block;font-weight:bold;margin-top:18px}
input{width:100%;min-height:52px;padding:10px 12px;border:2px solid #8495a4;border-radius:9px;color:var(--ink);background:#fff}input:focus,button:focus{outline:4px solid #f2b64b;outline-offset:2px}.code-input{font-size:1.45rem;letter-spacing:.18em;text-align:center}.hint{color:var(--muted);font-size:.91rem}
.notice{background:var(--pale);border-left:5px solid var(--blue);border-radius:5px;padding:12px;margin:16px 0}.error{background:#fff0f0;border-left-color:var(--danger);color:#751616}.success{background:#effbf3;border-left-color:var(--good);color:#124d2d}
button{width:100%;min-height:54px;border:0;border-radius:9px;background:var(--blue);color:#fff;font-weight:bold;cursor:pointer;margin-top:20px}button:hover{background:var(--blue2)}button.secondary{background:#fff;color:var(--blue2);border:2px solid var(--blue);margin-top:10px}button.small{width:auto;min-height:42px;padding:6px 12px;margin:8px 6px 0 0;font-size:.9rem}
details{margin-top:18px;border-top:1px solid var(--line);padding-top:12px}summary{cursor:pointer;color:var(--blue2);font-weight:bold}.qr-wrap{text-align:center;margin:16px 0}.qr-wrap canvas{width:250px;height:250px;max-width:100%;image-rendering:pixelated;border:8px solid #fff;outline:1px solid var(--line)}.secret{overflow-wrap:anywhere;padding:12px;background:#f5f7f8;border-radius:8px;font-family:monospace;letter-spacing:.08em}.codes{list-style:none;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:8px}.codes li{padding:10px 6px;text-align:center;background:#f4f7f9;border-radius:7px;font-family:monospace;letter-spacing:.04em}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media print{.steps,header,button,details,.notice:not(.success){display:none!important}.shell{width:100%}}
</style>
</head>
<body>
<main class="shell">
<header><div class="brand">◈ Northstar Bank</div><h1>Set up extra security</h1><p class="hint">Take your time. There is no reading timer.</p></header>
<nav aria-label="Setup progress"><ol class="steps"><li id="step1" class="current">1<br>Check</li><li id="step2">2<br>App</li><li id="step3">3<br>Save</li></ol></nav>
<section id="screen" aria-live="polite"></section>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
let csrf="", loginCsrf="", recoveryCodes=[], setupData=null;
const screen=document.getElementById("screen");

function note(message,kind=""){const box=document.createElement("div");box.className="notice "+kind;box.textContent=message;return box}
function setStep(number){[1,2,3].forEach(n=>{const el=document.getElementById("step"+n);el.className=n===number?"current":n<number?"done":""})}
function button(label,cls=""){const b=document.createElement("button");b.type="button";b.textContent=label;b.className=cls;return b}
function help(){const d=document.createElement("details"),s=document.createElement("summary"),p=document.createElement("p");s.textContent="Need help?";p.textContent="You can retry any step. Nothing here has a reading deadline.";d.append(s,p);return d}
function errorMessage(target,message){const old=target.querySelector(".error");if(old)old.remove();target.prepend(note(message,"error"))}
async function request(path,options={}){
 const headers=Object.assign({"Content-Type":"application/json"},options.headers||{});
 if(options.method&&options.method!=="GET")headers["X-CSRF-Token"]=csrf;
 const response=await fetch(path,Object.assign({credentials:"same-origin",headers},options));
 let data;try{data=await response.json()}catch{data={error:"We could not complete that request. Please try again."}}
 if(!response.ok)throw new Error(data.error||"We could not complete that request. Please try again.");
 return data;
}
async function getLoginCsrf(){
 const response=await fetch("/api/login-csrf",{credentials:"same-origin"});
 const data=await response.json();if(!response.ok||!data.token)throw new Error("Please refresh the page and try again.");loginCsrf=data.token;
}
function renderSignIn(){
 setStep(1);screen.replaceChildren();
 const card=document.createElement("section");card.className="card";
 card.innerHTML="<span class='icon' aria-hidden='true'>🔐</span><h2>Start your security setup</h2><p>Enter your email to begin.</p>";
 const label=document.createElement("label"),input=document.createElement("input"),hint=document.createElement("p"),go=button("Continue");
 label.htmlFor="email";label.textContent="Email address";input.id="email";input.type="email";input.autocomplete="email";input.inputMode="email";input.placeholder="Example: marcus@example.test";
 hint.className="hint";hint.textContent="Use the email on your bank account.";
 go.addEventListener("click",async()=>{try{
   if(!loginCsrf)await getLoginCsrf();
   const response=await fetch("/api/authenticate",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-Login-CSRF-Token":loginCsrf},body:JSON.stringify({email:input.value.trim()})});
   const data=await response.json();if(!response.ok)throw new Error(data.error||"We could not complete that request. Please try again.");
   csrf=data.csrf; loginCsrf=""; data.next==="complete"?renderComplete():renderIdentity();
 }catch(e){errorMessage(card,e.message)}});
 input.addEventListener("keydown",e=>{if(e.key==="Enter")go.click()});
 card.append(label,input,hint,go,help());screen.append(card);input.focus();
}
function renderIdentity(){
 setStep(1);screen.replaceChildren();const card=document.createElement("section");card.className="card";
 card.innerHTML="<span class='icon' aria-hidden='true'>🪪</span><h2>Check it is you</h2><p>Ask for a six-digit check code. Then enter it here.</p>";
 const send=button("Send my check code");
 send.addEventListener("click",async()=>{try{const data=await request("/api/identity/request",{method:"POST",body:"{}"});renderIdentityEntry(data.deliveredCode)}catch(e){errorMessage(card,e.message)}});
 card.append(note("Example code: 123456"),send,help());screen.append(card);
}
function renderIdentityEntry(deliveredCode){
 setStep(1);screen.replaceChildren();const card=document.createElement("section");card.className="card";
 card.innerHTML="<span class='icon' aria-hidden='true'>✉️</span><h2>Enter your check code</h2><p>Enter the six digits. You have plenty of time.</p>";
 card.append(note("Demo delivery code: "+deliveredCode+". Enter it below.","success"));
 const label=document.createElement("label"),input=document.createElement("input"),verify=button("Check code"),resend=button("Request a new code","secondary");
 label.htmlFor="identityCode";label.textContent="Six-digit code";input.id="identityCode";input.className="code-input";input.inputMode="numeric";input.autocomplete="one-time-code";input.maxLength=6;input.placeholder="123456";
 verify.addEventListener("click",async()=>{try{await request("/api/identity/verify",{method:"POST",body:JSON.stringify({code:input.value.trim()})});renderAppIntro()}catch(e){errorMessage(card,e.message)}});
 resend.addEventListener("click",renderIdentity);card.append(label,input,verify,resend,help());screen.append(card);input.focus();
}
function renderAppIntro(){
 setStep(2);screen.replaceChildren();const card=document.createElement("section");card.className="card";
 card.innerHTML="<span class='icon' aria-hidden='true'>📱</span><h2>Set up your authenticator app</h2><p>Use an authenticator app on this phone or another device.</p>";
 const go=button("Show setup details");go.addEventListener("click",async()=>{try{setupData=await request("/api/authenticator/setup",{method:"POST",body:"{}"});renderProvisioning()}catch(e){errorMessage(card,e.message)}});
 card.append(note("Next, scan a QR code or copy the setup secret."),go,help());screen.append(card);
}

/* Standards-compliant QR Code Model 2 encoder: Version 10-L, byte mode,
   Reed-Solomon error correction, format/version information and best mask.
   Its only encoded payload is the pending provisioning URI passed below. */
const QR_EXP=new Array(512),QR_LOG=new Array(256);(()=>{let x=1;for(let i=0;i<255;i++){QR_EXP[i]=x;QR_LOG[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)QR_EXP[i]=QR_EXP[i-255]})();
function qrMul(a,b){return!a||!b?0:QR_EXP[QR_LOG[a]+QR_LOG[b]]}
function qrPolyMultiply(a,b){const out=Array(a.length+b.length-1).fill(0);for(let i=0;i<a.length;i++)for(let j=0;j<b.length;j++)out[i+j]^=qrMul(a[i],b[j]);return out}
function qrGenerator(degree){let p=[1];for(let i=0;i<degree;i++)p=qrPolyMultiply(p,[1,QR_EXP[i]]);return p}
function qrEc(data,count){const gen=qrGenerator(count),work=data.concat(Array(count).fill(0));for(let i=0;i<data.length;i++){const factor=work[i];if(factor)for(let j=0;j<gen.length;j++)work[i+j]^=qrMul(gen[j],factor)}return work.slice(-count)}
function qrBch(value,poly){let d=0;for(let x=poly;x;x>>>=1)d++;let v=value<<(d-1);while(true){let vd=0;for(let x=v;x;x>>>=1)vd++;if(vd<d)return v;v^=poly<<(vd-d)}}
function qrBytes(text){
 const raw=[];for(let i=0;i<text.length;i++){const c=text.charCodeAt(i);if(c>127)throw new Error("QR payload must be ASCII");raw.push(c)}
 const bits=[0,1,0,0];for(let i=15;i>=0;i--)bits.push((raw.length>>>i)&1);raw.forEach(v=>{for(let i=7;i>=0;i--)bits.push((v>>>i)&1)});
 const capacity=274*8;for(let i=0;i<Math.min(4,capacity-bits.length);i++)bits.push(0);while(bits.length%8)bits.push(0);
 const bytes=[];for(let i=0;i<bits.length;i+=8){let value=0;for(let j=0;j<8;j++)value=(value<<1)|bits[i+j];bytes.push(value)}
 let pad=0;while(bytes.length<274)bytes.push((pad++%2)?17:236);return bytes;
}
function qrData(text){
 const bytes=qrBytes(text),blocks=[],defs=[[2,86,68],[2,87,69]];let offset=0;
 defs.forEach(([n,total,data])=>{for(let z=0;z<n;z++){const part=bytes.slice(offset,offset+data);offset+=data;blocks.push({data:part,ec:qrEc(part,total-data)})}});
 const out=[];for(let i=0;i<69;i++)blocks.forEach(b=>{if(i<b.data.length)out.push(b.data[i])});for(let i=0;i<18;i++)blocks.forEach(b=>out.push(b.ec[i]));return out;
}
function qrFinder(m,row,col){for(let r=-1;r<=7;r++)for(let c=-1;c<=7;c++){if(row+r<0||col+c<0||row+r>=57||col+c>=57)continue;m[row+r][col+c]=r>=0&&r<=6&&c>=0&&c<=6&&(r===0||r===6||c===0||c===6||(r>=2&&r<=4&&c>=2&&c<=4))}}
function qrBase(){
 const n=57,m=Array.from({length:n},()=>Array(n).fill(null));qrFinder(m,0,0);qrFinder(m,n-7,0);qrFinder(m,0,n-7);
 [6,28,50].forEach(r=>[6,28,50].forEach(c=>{if(m[r][c]!==null) return;for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)m[r+y][c+x]=Math.max(Math.abs(x),Math.abs(y))!==1}));
 for(let i=8;i<n-8;i++){if(m[i][6]===null)m[i][6]=i%2===0;if(m[6][i]===null)m[6][i]=i%2===0}
 const version=10,versionBits=(version<<12)|qrBch(version,0x1f25);for(let i=0;i<18;i++){const bit=((versionBits>>>i)&1)===1;m[Math.floor(i/3)][n-11+i%3]=bit;m[n-11+i%3][Math.floor(i/3)]=bit}
 return m;
}
function qrMask(mask,row,col){if(mask===0)return(row+col)%2===0;if(mask===1)return row%2===0;if(mask===2)return col%3===0;if(mask===3)return(row+col)%3===0;if(mask===4)return(Math.floor(row/2)+Math.floor(col/3))%2===0;if(mask===5)return(row*col)%2+(row*col)%3===0;if(mask===6)return((row*col)%2+(row*col)%3)%2===0;return((row*col)%3+(row+col)%2)%2===0}
function qrBuilt(data,mask){
 const m=qrBase(),n=57,format=((1<<3)|mask),bits=(format<<10|qrBch(format,0x537))^0x5412;
 for(let i=0;i<15;i++){const bit=((bits>>>i)&1)===1;if(i<6)m[i][8]=bit;else if(i<8)m[i+1][8]=bit;else m[n-15+i][8]=bit;if(i<8)m[8][n-i-1]=bit;else if(i<9)m[8][15-i]=bit;else m[8][15-i-1]=bit}m[n-8][8]=true;
 let bitIndex=0,up=true;for(let col=n-1;col>0;col-=2){if(col===6)col--;for(let z=0;z<n;z++){const row=up?n-1-z:z;for(let c=0;c<2;c++){const x=col-c;if(m[row][x]===null){const value=bitIndex<data.length*8?((data[Math.floor(bitIndex/8)]>>>(7-bitIndex%8))&1)===1:false;m[row][x]=value!==qrMask(mask,row,x);bitIndex++}}}up=!up}return m;
}
function qrPenalty(m){const n=m.length;let score=0;for(let r=0;r<n;r++)for(let c=0;c<n;c++){let same=0;for(let y=-1;y<=1;y++)for(let x=-1;x<=1;x++){if(!x&&!y)continue;if(r+y>=0&&r+y<n&&c+x>=0&&c+x<n&&m[r][c]===m[r+y][c+x])same++}if(same>5)score+=3+same-5}for(let r=0;r<n-1;r++)for(let c=0;c<n-1;c++)if(m[r][c]===m[r+1][c]&&m[r][c]===m[r+1][c+1]&&m[r][c]===m[r+1][c+1])score+=3;for(let r=0;r<n;r++)for(let c=0;c<n-6;c++)if(m[r][c]&&!m[r][c+1]&&m[r][c+2]&&m[r][c+3]&&m[r][c+4]&&!m[r][c+5]&&m[r][c+6])score+=40;for(let c=0;c<n;c++)for(let r=0;r<n-6;r++)if(m[r][c]&&!m[r+1][c]&&m[r+2][c]&&m[r+3][c]&&m[r+4][c]&&!m[r+5][c]&&m[r+6][c])score+=40;let dark=0;m.forEach(row=>row.forEach(v=>{if(v)dark++}));score+=Math.floor(Math.abs(100*dark/(n*n)-50)/5)*10;return score}
function standardQrCanvas(payload){
 const data=qrData(payload);let best=null,bestScore=Infinity;for(let mask=0;mask<8;mask++){const candidate=qrBuilt(data,mask),score=qrPenalty(candidate);if(score<bestScore){best=candidate;bestScore=score}}
 const canvas=document.createElement("canvas"),scale=5;canvas.width=canvas.height=57*scale;canvas.setAttribute("role","img");canvas.setAttribute("aria-label","QR code that configures an authenticator app with this pending Northstar Bank account.");const ctx=canvas.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle="#000";best.forEach((row,y)=>row.forEach((on,x)=>{if(on)ctx.fillRect(x*scale,y*scale,scale,scale)}));return canvas;
}
function renderProvisioning(){
 setStep(2);screen.replaceChildren();const card=document.createElement("section");card.className="card";
 card.innerHTML="<span class='icon' aria-hidden='true'>▦</span><h2>Scan or copy</h2><p>Scan this QR code with your authenticator app. It configures the app for your pending Northstar Bank account.</p>";
 const wrap=document.createElement("div");wrap.className="qr-wrap";wrap.append(standardQrCanvas(setupData.provisioningUri));
 const label=document.createElement("label"),secret=document.createElement("div"),copy=button("Copy setup secret","small"),copyUri=button("Copy setup link","small"),next=button("I added it to my app");
 label.textContent="Manual setup secret";secret.className="secret";secret.textContent=setupData.secret;
 copy.addEventListener("click",async()=>{try{await navigator.clipboard.writeText(setupData.secret);copy.textContent="Copied"}catch{copy.textContent="Select the secret to copy"}});
 copyUri.addEventListener("click",async()=>{try{await navigator.clipboard.writeText(setupData.provisioningUri);copyUri.textContent="Copied"}catch{copyUri.textContent="Copy is not available"}});
 next.addEventListener("click",renderAuthenticatorCode);card.append(wrap,label,secret,copy,copyUri,note("The QR code, setup link, and secret all describe the same authenticator setup."),next,help());screen.append(card);
}
function renderAuthenticatorCode(){
 setStep(2);screen.replaceChildren();const card=document.createElement("section");card.className="card";
 card.innerHTML="<span class='icon' aria-hidden='true'>✅</span><h2>Check your authenticator</h2><p>Enter the current six-digit code from your app.</p>";
 const label=document.createElement("label"),input=document.createElement("input"),verify=button("Finish authenticator setup"),retry=button("Start setup again","secondary");
 label.htmlFor="authCode";label.textContent="Six-digit authenticator code";input.id="authCode";input.className="code-input";input.inputMode="numeric";input.autocomplete="one-time-code";input.maxLength=6;input.placeholder="123456";
 verify.addEventListener("click",async()=>{try{const data=await request("/api/authenticator/verify",{method:"POST",body:JSON.stringify({code:input.value.trim()})});recoveryCodes=data.recoveryCodes;setupData=null;renderRecovery(data.message)}catch(e){errorMessage(card,e.message)}});
 retry.addEventListener("click",renderAppIntro);card.append(note("Example code: 123456. Use the code currently shown by your authenticator app."),label,input,verify,retry,help());screen.append(card);input.focus();
}
function renderRecovery(message){
 setStep(3);screen.replaceChildren();const card=document.createElement("section");card.className="card";
 card.innerHTML="<span class='icon' aria-hidden='true'>🗝️</span><h2>Save your recovery codes</h2><p>Use one code if you cannot use your authenticator app. Each code works once.</p>";card.append(note(message,"success"));
 const list=document.createElement("ul");list.className="codes";recoveryCodes.forEach(code=>{const li=document.createElement("li");li.textContent=code;list.append(li)});
 const copy=button("Copy all codes","small"),print=button("Print or save as PDF","small"),regenerate=button("Make new codes","secondary"),confirm=button("I saved my codes");
 copy.addEventListener("click",async()=>{try{await navigator.clipboard.writeText(recoveryCodes.join("\\n"));copy.textContent="Copied"}catch{copy.textContent="Select the codes to copy"}});
 print.addEventListener("click",()=>window.print());regenerate.addEventListener("click",async()=>{try{const data=await request("/api/recovery/regenerate",{method:"POST",body:"{}"});recoveryCodes=data.recoveryCodes;renderRecovery(data.message)}catch(e){errorMessage(card,e.message)}});
 confirm.addEventListener("click",async()=>{try{await request("/api/recovery/confirm",{method:"POST",body:"{}"});recoveryCodes=[];renderComplete()}catch(e){errorMessage(card,e.message)}});
 card.append(list,copy,print,note("Keep these private. Do not send them in a message or email."),regenerate,confirm,help());screen.append(card);
}
function renderComplete(){
 setStep(3);screen.replaceChildren();const card=document.createElement("section");card.className="card";
 card.innerHTML="<span class='icon' aria-hidden='true'>🎉</span><h2>Extra security is ready</h2><p>Your authenticator and recovery codes are set up.</p>";card.append(note("You can now approve protected actions with your authenticator.","success"));
 const logout=button("Sign out","secondary");logout.addEventListener("click",async()=>{try{await request("/api/logout",{method:"POST",body:"{}"});csrf="";recoveryCodes=[];setupData=null;await getLoginCsrf();renderSignIn()}catch(e){errorMessage(card,e.message)}});
 card.append(logout,help());screen.append(card);
}
getLoginCsrf().catch(()=>{}).finally(renderSignIn);
})();
</script>
</body>
</html>`;
}

const server = Bun.serve({
  port: 3000,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    const nonce = secureToken(18);
    try {
      const url = new URL(request.url);
      if (request.headers.get("x-forwarded-proto") === "http") {
        return new Response("Secure connection required.", { status: 426, headers: securityHeaders(nonce) });
      }
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname, nonce);
      if (url.pathname === "/" && request.method === "GET") {
        const headers = securityHeaders(nonce);
        headers.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { status: 200, headers });
      }
      return new Response("Page not found.", { status: 404, headers: securityHeaders(nonce) });
    } catch {
      return new Response("We could not complete that request. Please try again.", {
        status: 500,
        headers: securityHeaders(nonce),
      });
    }
  },
});

console.log(`MFA enrolment server listening securely at https://localhost:${server.port}`);
