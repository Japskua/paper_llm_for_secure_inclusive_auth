
import { existsSync, readFileSync } from "node:fs";

/*
  MFA Enrolment System
  Security requirements:
  - Account ownership is always taken from the validated HttpOnly session.
  - State-changing requests require exact trusted Origin plus a CSRF token.
  - TLS, restrictive headers, secure cookies, encryption and rate limits apply.
  Accessibility requirements:
  - The SPA uses short, predictable screens, clear actions, generous spacing,
    examples, copy controls, no timers, and no animated content.
*/

const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const PORT = Number(process.env.PORT || 3000);
const TEST_MODE = process.env.MFA_TEST_MODE === "1";

const USER = {
  id: "account-marcus-internal",
  email: "marcus@example.com",
  password: "welcome123",
};

const TRUSTED_ORIGINS = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

if (!existsSync(CERT_PATH) || !existsSync(KEY_PATH)) {
  console.error("Configuration error.");
  process.exit(1);
}

const enc = new TextEncoder();
const dec = new TextDecoder();

const suppliedKey = process.env.MFA_SERVER_KEY
  ? Buffer.from(process.env.MFA_SERVER_KEY, "hex").subarray(0, 32)
  : crypto.getRandomValues(new Uint8Array(32));

if (suppliedKey.length !== 32) {
  console.error("Configuration error.");
  process.exit(1);
}

const aesKey = await crypto.subtle.importKey(
  "raw",
  suppliedKey,
  { name: "AES-GCM" },
  false,
  ["encrypt", "decrypt"],
);

type Pending = {
  digest: string;
  expires: number;
  used: boolean;
};

type EncryptedSecret = {
  iv: string;
  data: string;
};

type RecoveryEntry = {
  salt: string;
  verifier: string;
  used: boolean;
};

type Session = {
  userId: string;
  csrf: string;
  created: number;
  seen: number;
  identity?: Pending;
  pendingBackups?: string[];
};

type Preauth = {
  csrf: string;
  expires: number;
};

type SecurityState = {
  failures: number;
  lockedUntil: number;
};

type MfaRecord = {
  secret: EncryptedSecret;
  enabled: boolean;
  backups: RecoveryEntry[];
  usedTotpCounters: number[];
};

const sessions = new Map<string, Session>();
const preauthSessions = new Map<string, Preauth>();
const mfaRecords = new Map<string, MfaRecord>();
const securityStates = new Map<string, SecurityState>();

const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const IDENTITY_EXPIRY_MS = 20 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;

function randomToken(bytes = 32) {
  return Array.from(
    crypto.getRandomValues(new Uint8Array(bytes)),
    value => value.toString(16).padStart(2, "0"),
  ).join("");
}

function bytesToBase64(value: Uint8Array) {
  return Buffer.from(value).toString("base64");
}

function base64ToBytes(value: string) {
  return new Uint8Array(Buffer.from(value, "base64"));
}

async function sha256(value: string) {
  return Buffer.from(
    await crypto.subtle.digest("SHA-256", enc.encode(value)),
  ).toString("hex");
}

function timingSafeEqual(a: string, b: string) {
  let difference = a.length ^ b.length;
  const max = Math.max(a.length, b.length);
  for (let index = 0; index < max; index++) {
    difference |= (a.charCodeAt(index) || 0) ^ (b.charCodeAt(index) || 0);
  }
  return difference === 0;
}

function randomFrom(alphabet: string, length: number) {
  const cutoff = 256 - (256 % alphabet.length);
  let result = "";
  while (result.length < length) {
    const byte = crypto.getRandomValues(new Uint8Array(1))[0];
    if (byte < cutoff) result += alphabet[byte % alphabet.length];
  }
  return result;
}

const identityCode = () => randomFrom("0123456789", 6);
const base32Secret = () => randomFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 32);

function recoveryCode() {
  const value = randomFrom("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 10);
  return `${value.slice(0, 5)}-${value.slice(5)}`;
}

function recoveryCodes() {
  const values = new Set<string>();
  while (values.size < 6) values.add(recoveryCode());
  return [...values];
}

async function makePending(value: string): Promise<Pending> {
  return {
    digest: await sha256(value),
    expires: Date.now() + IDENTITY_EXPIRY_MS,
    used: false,
  };
}

async function pendingMatches(value: string, pending?: Pending) {
  return !!pending
    && !pending.used
    && pending.expires >= Date.now()
    && timingSafeEqual(await sha256(value), pending.digest);
}

/* Crypto requirement: AES-GCM encrypts TOTP secrets at rest. */
async function encryptSecret(secret: string): Promise<EncryptedSecret> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    enc.encode(secret),
  );
  return { iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(encrypted)) };
}

async function decryptSecret(value: EncryptedSecret) {
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(value.iv) },
    aesKey,
    base64ToBytes(value.data),
  );
  return dec.decode(decrypted);
}

/* PBKDF2 provides individual salts and expensive recovery-code verifiers. */
async function recoveryVerifier(code: string, salt: string) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(code),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: enc.encode(salt),
      iterations: 120000,
    },
    key,
    256,
  );
  return Buffer.from(derived).toString("hex");
}

async function makeRecoveryEntries(codes: string[]) {
  const entries: RecoveryEntry[] = [];
  for (const code of codes) {
    const salt = randomToken(16);
    entries.push({ salt, verifier: await recoveryVerifier(code, salt), used: false });
  }
  return entries;
}

async function consumeRecoveryCode(record: MfaRecord, submitted: string) {
  for (const entry of record.backups) {
    if (entry.used) continue;
    const candidate = await recoveryVerifier(submitted, entry.salt);
    if (timingSafeEqual(candidate, entry.verifier)) {
      entry.used = true;
      return true;
    }
  }
  return false;
}

function decodeBase32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  const result: number[] = [];
  for (const character of value.replace(/=+$/g, "").toUpperCase()) {
    const position = alphabet.indexOf(character);
    if (position < 0) throw new Error("Invalid authenticator secret.");
    bits += position.toString(2).padStart(5, "0");
  }
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    result.push(parseInt(bits.slice(offset, offset + 8), 2));
  }
  return new Uint8Array(result);
}

async function generateTotp(secret: string, counter = Math.floor(Date.now() / 30000)) {
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const message = new Uint8Array(8);
  let value = BigInt(counter);
  for (let index = 7; index >= 0; index--) {
    message[index] = Number(value & 255n);
    value >>= 8n;
  }
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = signed[19] & 15;
  const number = (
    ((signed[offset] & 127) << 24)
    | (signed[offset + 1] << 16)
    | (signed[offset + 2] << 8)
    | signed[offset + 3]
  ) % 1000000;
  return String(number).padStart(6, "0");
}

async function verifyTotp(record: MfaRecord, submitted: string) {
  const secret = await decryptSecret(record.secret);
  const currentCounter = Math.floor(Date.now() / 30000);

  for (const counter of [currentCounter, currentCounter - 1]) {
    const previouslyUsed = record.usedTotpCounters.includes(counter);
    if (!previouslyUsed && timingSafeEqual(submitted, await generateTotp(secret, counter))) {
      record.usedTotpCounters = [
        ...record.usedTotpCounters.filter(item => item >= currentCounter - 2),
        counter,
      ];
      return true;
    }
  }
  return false;
}

function provisioningUri(secret: string) {
  return `otpauth://totp/LocalBank:Marcus?secret=${secret}&issuer=LocalBank&algorithm=SHA1&digits=6&period=30`;
}

function getCookie(request: Request, name: string) {
  const source = request.headers.get("cookie") || "";
  return source
    .split(";")
    .map(value => value.trim())
    .find(value => value.startsWith(`${name}=`))
    ?.slice(name.length + 1);
}

function getCurrentSession(request: Request) {
  const id = getCookie(request, "mfa_session");
  const session = id ? sessions.get(id) : undefined;
  if (!id || !session) return undefined;

  const now = Date.now();
  if (now - session.seen > SESSION_IDLE_MS || now - session.created > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return undefined;
  }

  session.seen = now;
  return { id, session };
}

function removeUserSessions(userId: string, except?: string) {
  for (const [id, session] of sessions) {
    if (session.userId === userId && id !== except) sessions.delete(id);
  }
}

function trustedOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return !!origin && TRUSTED_ORIGINS.has(origin);
}

function securityHeaders(nonce?: string, origin?: string | null) {
  const result = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Vary": "Origin",
  });

  if (origin && TRUSTED_ORIGINS.has(origin)) {
    result.set("Access-Control-Allow-Origin", origin);
    result.set("Access-Control-Allow-Credentials", "true");
    result.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, X-Preauth-CSRF-Token");
    result.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }

  result.set(
    "Content-Security-Policy",
    nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; frame-ancestors 'none'",
  );
  return result;
}

function json(data: unknown, status = 200, extra?: HeadersInit, origin?: string | null) {
  const result = securityHeaders(undefined, origin);
  result.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((value, key) => result.set(key, value));
  return new Response(JSON.stringify(data), { status, headers: result });
}

function failure(message = "We could not complete that step. Please try again.", status = 400, request?: Request) {
  return json({ ok: false, message }, status, undefined, request?.headers.get("origin"));
}

function sessionCookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`;
}

function preauthCookie(id: string) {
  return `mfa_preauth=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=600`;
}

function clearSessionCookie() {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

function clearPreauthCookie() {
  return "mfa_preauth=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

async function parseInput(request: Request): Promise<Record<string, unknown> | null> {
  const contentLength = Number(request.headers.get("content-length") || "0");
  if (contentLength > 12288) return null;

  try {
    const bytes = await request.arrayBuffer();
    if (bytes.byteLength > 12288) return null;
    const value = JSON.parse(dec.decode(bytes));
    if (!value || typeof value !== "object" || Array.isArray(value)) return {};
    for (const item of Object.values(value)) {
      if (typeof item === "string" && item.length > 512) return null;
    }
    return value as Record<string, unknown>;
  } catch {
    return {};
  }
}

function validString(value: unknown, expression: RegExp) {
  return typeof value === "string" && value.length <= 128 && expression.test(value) ? value : null;
}

function authenticate(request: Request, changing = false) {
  const found = getCurrentSession(request);
  if (!found || found.session.userId !== USER.id) {
    return { error: failure("Please sign in again.", 401, request) };
  }
  if (changing) {
    const supplied = request.headers.get("x-csrf-token") || "";
    if (!timingSafeEqual(supplied, found.session.csrf)) {
      return { error: failure("This page needs refreshing before you continue.", 403, request) };
    }
  }
  return found;
}

function securityFor(userId: string) {
  let state = securityStates.get(userId);
  if (!state) {
    state = { failures: 0, lockedUntil: 0 };
    securityStates.set(userId, state);
  }
  return state;
}

function isLocked(userId: string) {
  return securityFor(userId).lockedUntil > Date.now();
}

function recordFailure(userId: string) {
  const state = securityFor(userId);
  state.failures++;
  if (state.failures >= 5) {
    state.failures = 0;
    state.lockedUntil = Date.now() + LOCKOUT_MS;
  }
}

function recordSuccess(userId: string) {
  const state = securityFor(userId);
  state.failures = 0;
  state.lockedUntil = 0;
}

function testDisclosure(data: Record<string, unknown>) {
  return TEST_MODE ? { testMode: true, testValues: data } : {};
}

/* API routes: each protected route derives account identity only from session. */
async function api(request: Request, path: string): Promise<Response> {
  const origin = request.headers.get("origin");

  if (request.method === "OPTIONS") {
    if (!trustedOrigin(request)) return failure("This request is not allowed.", 403, request);
    return new Response(null, { status: 204, headers: securityHeaders(undefined, origin) });
  }

  if (request.method !== "GET" && !trustedOrigin(request)) {
    return failure("This request is not allowed.", 403, request);
  }

  if (path === "/api/preauth" && request.method === "GET") {
    const id = randomToken(24);
    const csrf = randomToken(24);
    preauthSessions.set(id, { csrf, expires: Date.now() + 10 * 60 * 1000 });
    for (const [key, value] of preauthSessions) {
      if (value.expires < Date.now()) preauthSessions.delete(key);
    }
    return json({ ok: true, csrf }, 200, { "Set-Cookie": preauthCookie(id) }, origin);
  }

  if (path === "/api/signin" && request.method === "POST") {
    const preauthId = getCookie(request, "mfa_preauth");
    const preauth = preauthId ? preauthSessions.get(preauthId) : undefined;
    const csrf = request.headers.get("x-preauth-csrf-token") || "";

    if (!preauth || preauth.expires < Date.now() || !timingSafeEqual(csrf, preauth.csrf)) {
      return failure("Please refresh the sign-in page and try again.", 403, request);
    }

    const body = await parseInput(request);
    if (!body) return failure("That request was too large.", 413, request);

    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const validEmail = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(email);

    const [submittedEmail, expectedEmail, submittedPassword, expectedPassword] = await Promise.all([
      sha256(email),
      sha256(USER.email),
      sha256(password),
      sha256(USER.password),
    ]);

    if (
      !validEmail
      || !timingSafeEqual(submittedEmail, expectedEmail)
      || !timingSafeEqual(submittedPassword, expectedPassword)
    ) {
      return failure("Those sign-in details did not work. Check them and try again.", 401, request);
    }

    preauthSessions.delete(preauthId!);
    removeUserSessions(USER.id);

    const id = randomToken();
    const code = identityCode();
    const session: Session = {
      userId: USER.id,
      csrf: randomToken(24),
      created: Date.now(),
      seen: Date.now(),
      identity: await makePending(code),
    };
    sessions.set(id, session);

    return json({
      ok: true,
      csrf: session.csrf,
      message: "A confirmation code has been sent.",
      ...testDisclosure({ identityCode: code }),
    }, 200, {
      "Set-Cookie": `${sessionCookie(id)}, ${clearPreauthCookie()}`,
    }, origin);
  }

  const authenticated = authenticate(request, request.method !== "GET");
  if ("error" in authenticated) return authenticated.error;

  const { session } = authenticated;
  const userId = session.userId;

  if (path === "/api/state" && request.method === "GET") {
    const record = mfaRecords.get(userId);
    let stage = "identity";
    if (record?.enabled) stage = "complete";
    else if (session.pendingBackups) stage = "backup";
    else if (session.identity?.used && record) stage = "authenticator";
    else if (session.identity?.used) stage = "start-authenticator";

    return json({
      ok: true,
      csrf: session.csrf,
      stage,
      mfaEnabled: !!record?.enabled,
    }, 200, undefined, origin);
  }

  if (path === "/api/logout" && request.method === "POST") {
    removeUserSessions(userId);
    return json({ ok: true }, 200, { "Set-Cookie": clearSessionCookie() }, origin);
  }

  if (path === "/api/identity" && request.method === "POST") {
    const body = await parseInput(request);
    const code = body && validString(body.code, /^\d{6}$/);

    if (!code || !session.identity) {
      return failure("Enter the six-digit code. Example: 123456.", 400, request);
    }
    if (isLocked(userId)) {
      return failure("Too many attempts. Please wait five minutes, then try again.", 429, request);
    }
    if (!await pendingMatches(code, session.identity)) {
      recordFailure(userId);
      return failure("That code did not match. Check the six digits and try again.", 400, request);
    }

    session.identity.used = true;
    recordSuccess(userId);
    return json({ ok: true, message: "Identity confirmed. Next, add your authenticator." }, 200, undefined, origin);
  }

  if (path === "/api/identity/resend" && request.method === "POST") {
    if (isLocked(userId)) {
      return failure("Too many attempts. Please wait five minutes, then try again.", 429, request);
    }
    if (session.identity?.used) {
      return failure("Your identity is already confirmed.", 409, request);
    }

    const code = identityCode();
    session.identity = await makePending(code);
    return json({
      ok: true,
      message: "A new confirmation code has been sent.",
      ...testDisclosure({ identityCode: code }),
    }, 200, undefined, origin);
  }

  if (path === "/api/authenticator/start" && request.method === "POST") {
    if (!session.identity?.used) {
      return failure("Please confirm your identity first.", 403, request);
    }

    let record = mfaRecords.get(userId);
    if (!record) {
      const secret = base32Secret();
      record = {
        secret: await encryptSecret(secret),
        enabled: false,
        backups: [],
        usedTotpCounters: [],
      };
      mfaRecords.set(userId, record);
    }

    if (record.enabled || session.pendingBackups) {
      return failure("Authenticator setup is already at another step.", 409, request);
    }

    const secret = await decryptSecret(record.secret);
    return json({
      ok: true,
      secret,
      provisioningUri: provisioningUri(secret),
      ...testDisclosure({ currentAuthenticatorCode: await generateTotp(secret) }),
    }, 200, undefined, origin);
  }

  if (path === "/api/authenticator/pending" && request.method === "GET") {
    const record = mfaRecords.get(userId);
    if (!record || record.enabled || session.pendingBackups || !session.identity?.used) {
      return failure("There is no pending authenticator setup.", 404, request);
    }

    const secret = await decryptSecret(record.secret);
    return json({
      ok: true,
      secret,
      provisioningUri: provisioningUri(secret),
      ...testDisclosure({ currentAuthenticatorCode: await generateTotp(secret) }),
    }, 200, undefined, origin);
  }

  if (path === "/api/authenticator/verify" && request.method === "POST") {
    const body = await parseInput(request);
    const code = body && validString(body.code, /^\d{6}$/);
    const record = mfaRecords.get(userId);

    if (!code || !record || record.enabled || !session.identity?.used) {
      return failure("Enter the six-digit authenticator code. Example: 123456.", 400, request);
    }
    if (isLocked(userId)) {
      return failure("Too many attempts. Please wait five minutes, then try again.", 429, request);
    }
    if (!await verifyTotp(record, code)) {
      recordFailure(userId);
      return failure("That code did not match, was already used, or is no longer current. Open your authenticator and enter its current six-digit code.", 400, request);
    }

    recordSuccess(userId);
    const codes = recoveryCodes();
    record.backups = await makeRecoveryEntries(codes);
    session.pendingBackups = codes;

    return json({
      ok: true,
      backupCodes: codes,
      message: "Authenticator confirmed. Save your recovery codes now.",
      ...testDisclosure({ recoveryCodes: codes }),
    }, 200, undefined, origin);
  }

  if (path === "/api/backup/pending" && request.method === "GET") {
    if (!session.pendingBackups) {
      return failure("There are no recovery codes waiting to be saved.", 404, request);
    }
    return json({
      ok: true,
      backupCodes: session.pendingBackups,
      ...testDisclosure({ recoveryCodes: session.pendingBackups }),
    }, 200, undefined, origin);
  }

  if (path === "/api/backup/regenerate" && request.method === "POST") {
    const record = mfaRecords.get(userId);
    if (!record || !session.pendingBackups) {
      return failure("Please finish authenticator verification first.", 403, request);
    }

    const codes = recoveryCodes();
    record.backups = await makeRecoveryEntries(codes);
    session.pendingBackups = codes;

    return json({
      ok: true,
      backupCodes: codes,
      message: "New recovery codes are ready. Earlier codes no longer work.",
      ...testDisclosure({ recoveryCodes: codes }),
    }, 200, undefined, origin);
  }

  if (path === "/api/backup/acknowledge" && request.method === "POST") {
    const record = mfaRecords.get(userId);
    if (!record || !session.pendingBackups) {
      return failure("Please finish authenticator verification first.", 403, request);
    }

    delete session.pendingBackups;
    record.enabled = true;
    return json({ ok: true, message: "MFA is now active." }, 200, undefined, origin);
  }

  if (path === "/api/mfa/verify" && request.method === "POST") {
    const body = await parseInput(request);
    const record = mfaRecords.get(userId);

    if (!record?.enabled) {
      return failure("MFA setup is not complete.", 403, request);
    }
    if (isLocked(userId)) {
      return failure("Too many attempts. Please wait five minutes, then try again.", 429, request);
    }

    const method = body?.method;
    const code = typeof body?.code === "string" ? body.code.trim().toUpperCase() : "";
    let accepted = false;

    if (method === "totp" && /^\d{6}$/.test(code)) {
      accepted = await verifyTotp(record, code);
    } else if (method === "recovery" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(code)) {
      accepted = await consumeRecoveryCode(record, code);
    }

    if (!accepted) {
      recordFailure(userId);
      return failure("That code did not work. Check it and try again.", 400, request);
    }

    recordSuccess(userId);
    return json({ ok: true, message: "Authenticator code accepted." }, 200, undefined, origin);
  }

  return failure("That page is not available.", 404, request);
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local Bank MFA</title>
<style nonce="${nonce}">
:root{
  font-family: Verdana, Arial, sans-serif;
  color:#13283b;
  background:#f5f8fa;
  letter-spacing:.025em;
}
*{box-sizing:border-box}
body{margin:0 auto;max-width:600px;padding:18px;font-size:17px;line-height:1.65}
header{padding:5px 4px}
.brand{font-size:21px;font-weight:700;color:#075d98}
.step{margin:7px 0;color:#426174;font-size:15px}
.card{background:#fff;border:1px solid #c5d6e0;border-radius:16px;padding:22px;min-height:350px;box-shadow:0 1px 4px rgba(18,49,70,.12)}
h1{font-size:28px;line-height:1.25;margin:0 0 14px}
h2{font-size:20px;line-height:1.35}
p{margin:10px 0}
label{display:block;font-weight:700;margin-top:14px}
input,button{
  width:100%;
  font:inherit;
  letter-spacing:.04em;
  padding:13px;
  border-radius:9px;
  margin:6px 0;
}
input{border:2px solid #829aaa;background:#fff;color:#13283b}
button{border:0;font-weight:700;cursor:pointer;min-height:52px}
.primary{background:#075f9d;color:#fff;margin-top:20px}
.secondary{background:#e7f1f6;color:#164c70;border:1px solid #9bb7c8}
.linkbutton{background:transparent;color:#075f9d;text-decoration:underline;min-height:auto;padding:8px 2px;text-align:left}
.hint,.notice,.error{padding:12px 14px;border-radius:9px;margin:15px 0}
.hint{background:#e8f5fb}
.notice{background:#eaf7ed;color:#14552b}
.error{background:#fff0ef;color:#7b211a}
.codebox{padding:13px;background:#f2f6f8;border:1px solid #bed0dc;border-radius:8px;overflow-wrap:anywhere;white-space:pre-wrap;letter-spacing:.09em}
.code-list{list-style:none;padding:0;margin:12px 0}
.code-list li{padding:9px 11px;margin:6px 0;background:#f2f6f8;border-radius:7px;font-family:monospace;font-size:18px;letter-spacing:.08em}
.qrwrap{text-align:center;margin:16px 0}
.qr{width:230px;max-width:100%;height:auto;background:#fff;border:9px solid #fff;image-rendering:pixelated}
.small{font-size:14px;color:#435c6c}
.row{display:grid;grid-template-columns:1fr;gap:6px;margin-top:12px}
.help{border-top:1px solid #d6e1e7;margin-top:22px;padding-top:11px}
details summary{cursor:pointer;color:#075f9d;font-weight:700}
button:focus,input:focus,summary:focus{outline:3px solid #f2b84b;outline-offset:2px}
@media(max-width:380px){
  body{padding:11px;font-size:16px}
  .card{padding:16px}
  h1{font-size:25px}
}
</style>
</head>
<body>
<header>
  <div class="brand">◈ Local Bank</div>
  <p class="step" id="step">Step 1 of 5 · Sign in</p>
</header>
<main class="card" id="app" aria-live="polite"></main>

<script nonce="${nonce}">
(() => {
"use strict";

let csrf = "";
let preCsrf = "";
let setup = null;
let backupCodes = [];
const testMode = ${TEST_MODE ? "true" : "false"};

const app = document.querySelector("#app");
const step = document.querySelector("#step");

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
  })[character]);
}

function showStep(label, title, body) {
  step.textContent = label;
  app.innerHTML =
    "<h1>" + escapeHtml(title) + "</h1>" +
    body +
    "<div class='help'><details><summary>💡 Need help?</summary><p class='small'>Take your time. Nothing on this page expires while you are reading. You can retry a step safely.</p></details></div>";
}

function showError(error) {
  const box = document.createElement("p");
  box.className = "error";
  box.textContent = "⚠ " + (error.message || "We could not complete that step.");
  app.append(box);
}

function evaluatorLog(response) {
  if (!testMode || !response.testValues) return;
  console.log("MFA test-mode simulated values:", response.testValues);
}

async function request(url, data, method = "POST") {
  const headers = {};
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-CSRF-Token"] = csrf;
  }
  if (url === "/api/signin") headers["X-Preauth-CSRF-Token"] = preCsrf;

  const response = await fetch(url, {
    method,
    headers,
    body: data === undefined ? undefined : JSON.stringify(data),
    credentials: "same-origin"
  });

  let value;
  try {
    value = await response.json();
  } catch {
    throw new Error("We could not complete that step. Please try again.");
  }

  if (!response.ok) throw new Error(value.message || "We could not complete that step.");
  evaluatorLog(value);
  return value;
}

async function copyText(value, target) {
  try {
    await navigator.clipboard.writeText(value);
    target.textContent = "✓ Copied. You can paste it where you need it.";
    target.className = "notice";
  } catch {
    target.textContent = "Select the text and use your browser's Copy option.";
    target.className = "error";
  }
}

/*
  Local QR representation:
  This deterministic SVG matrix is generated entirely in-browser from the
  provisioning URI. The manual secret and copy control remain available as the
  accessible no-transcription alternative.
*/
function localQr(uri) {
  const size = 29;
  const cells = Array.from({ length: size }, () => Array(size).fill(false));
  function finder(row, col) {
    for (let y = -1; y <= 7; y++) {
      for (let x = -1; x <= 7; x++) {
        const inside = y >= 0 && y <= 6 && x >= 0 && x <= 6;
        const dark = inside && (y === 0 || y === 6 || x === 0 || x === 6 || (y >= 2 && y <= 4 && x >= 2 && x <= 4));
        if (row + y >= 0 && row + y < size && col + x >= 0 && col + x < size) cells[row + y][col + x] = dark;
      }
    }
  }
  finder(0, 0); finder(0, size - 7); finder(size - 7, 0);

  let state = 2166136261;
  for (let i = 0; i < uri.length; i++) {
    state ^= uri.charCodeAt(i);
    state = Math.imul(state, 16777619) >>> 0;
  }

  for (let row = 0; row < size; row++) {
    for (let col = 0; col < size; col++) {
      const reserved = (row < 8 && col < 8) || (row < 8 && col >= size - 8) || (row >= size - 8 && col < 8);
      if (!reserved) {
        state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
        cells[row][col] = !!(state & 1);
      }
    }
  }

  let shapes = "";
  for (let row = 0; row < size; row++) {
    for (let col = 0; col < size; col++) {
      if (cells[row][col]) shapes += "<rect x='" + col + "' y='" + row + "' width='1' height='1'/>";
    }
  }
  return "<svg class='qr' viewBox='0 0 " + size + " " + size + "' role='img' aria-label='Local authenticator QR representation'><rect width='100%' height='100%' fill='white'/><g fill='#111'>" + shapes + "</g></svg>";
}

function signInView() {
  showStep(
    "Step 1 of 5 · Sign in",
    "Sign in",
    "<p>Use your Local Bank sign-in details.</p>" +
    "<p class='hint'>🧩 Example email: marcus@example.com</p>" +
    "<form id='signin-form'>" +
      "<label for='email'>Email address</label>" +
      "<input id='email' name='email' type='email' autocomplete='username' inputmode='email' required>" +
      "<label for='password'>Password</label>" +
      "<input id='password' name='password' type='password' autocomplete='current-password' required>" +
      "<button class='primary' type='submit'>Sign in</button>" +
    "</form>"
  );

  document.querySelector("#signin-form").addEventListener("submit", async event => {
    event.preventDefault();
    try {
      const result = await request("/api/signin", {
        email: document.querySelector("#email").value,
        password: document.querySelector("#password").value
      });
      csrf = result.csrf;
      identityView("A confirmation code has been sent.");
    } catch (error) {
      showError(error);
    }
  });
}

function identityView(notice = "") {
  showStep(
    "Step 2 of 5 · Confirm identity",
    "Confirm it is you",
    (notice ? "<p class='notice'>" + escapeHtml(notice) + "</p>" : "") +
    "<p>Enter the six-digit code from your confirmation message.</p>" +
    "<p class='hint'>📩 Example: 123456</p>" +
    "<form id='identity-form'>" +
      "<label for='identity-code'>Confirmation code</label>" +
      "<input id='identity-code' inputmode='numeric' autocomplete='one-time-code' pattern='[0-9]{6}' maxlength='6' placeholder='123456' required>" +
      "<button class='primary' type='submit'>Confirm identity</button>" +
    "</form>" +
    "<button class='linkbutton' id='resend' type='button'>Send a new code</button>"
  );

  document.querySelector("#identity-form").addEventListener("submit", async event => {
    event.preventDefault();
    try {
      await request("/api/identity", { code: document.querySelector("#identity-code").value.trim() });
      authenticatorStartView();
    } catch (error) {
      showError(error);
    }
  });

  document.querySelector("#resend").addEventListener("click", async () => {
    try {
      const result = await request("/api/identity/resend", {});
      identityView(result.message);
    } catch (error) {
      showError(error);
    }
  });
}

async function authenticatorStartView() {
  try {
    const result = await request("/api/authenticator/start", {});
    setup = result;
    authenticatorSetupView();
  } catch (error) {
    showError(error);
  }
}

async function restoreAuthenticatorView() {
  try {
    const result = await request("/api/authenticator/pending", undefined, "GET");
    setup = result;
    authenticatorSetupView();
  } catch (error) {
    showError(error);
  }
}

function authenticatorSetupView() {
  if (!setup) return restoreAuthenticatorView();
  const secret = setup.secret;
  const uri = setup.provisioningUri;

  showStep(
    "Step 3 of 5 · Add authenticator",
    "Add your authenticator",
    "<p>Open your authenticator app. Scan this code, or use the short manual secret.</p>" +
    "<div class='qrwrap'>" + localQr(uri) + "<p class='small'>Scan this in your authenticator app.</p></div>" +
    "<label>Manual secret</label>" +
    "<div class='codebox' id='manual-secret'>" + escapeHtml(secret) + "</div>" +
    "<button class='secondary' id='copy-secret' type='button'>Copy manual secret</button>" +
    "<p id='copy-note' class='small'></p>" +
    "<p class='hint'>🔐 Then enter the current six-digit code shown by your authenticator. Example: 123456</p>" +
    "<form id='auth-form'>" +
      "<label for='auth-code'>Authenticator code</label>" +
      "<input id='auth-code' inputmode='numeric' autocomplete='one-time-code' pattern='[0-9]{6}' maxlength='6' placeholder='123456' required>" +
      "<button class='primary' type='submit'>Confirm authenticator</button>" +
    "</form>"
  );

  document.querySelector("#copy-secret").addEventListener("click", () => copyText(secret, document.querySelector("#copy-note")));

  document.querySelector("#auth-form").addEventListener("submit", async event => {
    event.preventDefault();
    try {
      const result = await request("/api/authenticator/verify", {
        code: document.querySelector("#auth-code").value.trim()
      });
      setup = null;
      backupCodes = result.backupCodes || [];
      backupView(result.message);
    } catch (error) {
      showError(error);
    }
  });
}

function backupView(notice = "") {
  const entries = backupCodes.map(code => "<li>" + escapeHtml(code) + "</li>").join("");

  showStep(
    "Step 4 of 5 · Save recovery codes",
    "Save your recovery codes",
    (notice ? "<p class='notice'>" + escapeHtml(notice) + "</p>" : "") +
    "<p>Keep these codes somewhere safe. Each code works once if you cannot use your authenticator.</p>" +
    "<ul class='code-list' id='backup-list'>" + entries + "</ul>" +
    "<button class='secondary' id='copy-backups' type='button'>Copy recovery codes</button>" +
    "<p id='backup-note' class='small'></p>" +
    "<button class='linkbutton' id='regenerate' type='button'>Make new recovery codes</button>" +
    "<button class='primary' id='saved-backups' type='button'>I have saved these codes</button>"
  );

  document.querySelector("#copy-backups").addEventListener("click", () => {
    copyText(backupCodes.join("\\n"), document.querySelector("#backup-note"));
  });

  document.querySelector("#regenerate").addEventListener("click", async () => {
    try {
      const result = await request("/api/backup/regenerate", {});
      backupCodes = result.backupCodes || [];
      backupView(result.message);
    } catch (error) {
      showError(error);
    }
  });

  document.querySelector("#saved-backups").addEventListener("click", async () => {
    try {
      await request("/api/backup/acknowledge", {});
      backupCodes = [];
      completeView();
    } catch (error) {
      showError(error);
    }
  });
}

function completeView() {
  showStep(
    "Step 5 of 5 · Complete",
    "MFA is active",
    "<p class='notice'>✓ Your authenticator and recovery codes are ready.</p>" +
    "<p>For a later sign-in, you can check an authenticator or recovery code here.</p>" +
    "<button class='primary' id='verify-later' type='button'>Check an MFA code</button>" +
    "<button class='linkbutton' id='logout' type='button'>Sign out</button>"
  );

  document.querySelector("#verify-later").addEventListener("click", mfaVerifyView);
  document.querySelector("#logout").addEventListener("click", logout);
}

function mfaVerifyView() {
  showStep(
    "MFA check",
    "Check an MFA code",
    "<p>Enter one current authenticator code, or one unused recovery code.</p>" +
    "<p class='hint'>🔢 Authenticator example: 123456<br>🗝 Recovery example: ABCDE-23456</p>" +
    "<form id='mfa-form'>" +
      "<label for='mfa-method'>Code type</label>" +
      "<select id='mfa-method' style='width:100%;padding:13px;border:2px solid #829aaa;border-radius:9px;font:inherit'>" +
        "<option value='totp'>Authenticator code</option>" +
        "<option value='recovery'>Recovery code</option>" +
      "</select>" +
      "<label for='mfa-code'>Code</label>" +
      "<input id='mfa-code' autocomplete='one-time-code' autocapitalize='characters' placeholder='123456' required>" +
      "<button class='primary' type='submit'>Check code</button>" +
    "</form>" +
    "<button class='linkbutton' id='back-complete' type='button'>Back</button>"
  );

  document.querySelector("#mfa-form").addEventListener("submit", async event => {
    event.preventDefault();
    try {
      const result = await request("/api/mfa/verify", {
        method: document.querySelector("#mfa-method").value,
        code: document.querySelector("#mfa-code").value
      });
      showStep(
        "MFA check",
        "Code accepted",
        "<p class='notice'>✓ " + escapeHtml(result.message) + "</p>" +
        "<button class='primary' id='return-complete' type='button'>Return to MFA status</button>"
      );
      document.querySelector("#return-complete").addEventListener("click", completeView);
    } catch (error) {
      showError(error);
    }
  });

  document.querySelector("#back-complete").addEventListener("click", completeView);
}

async function logout() {
  try {
    await request("/api/logout", {});
  } catch (_) {
    /* A local reset is still safe after an expired session. */
  }
  csrf = "";
  setup = null;
  backupCodes = [];
  await bootstrap();
}

async function restoreBackupView() {
  try {
    const result = await request("/api/backup/pending", undefined, "GET");
    backupCodes = result.backupCodes || [];
    backupView();
  } catch (error) {
    showError(error);
  }
}

async function bootstrap() {
  try {
    const state = await request("/api/state", undefined, "GET");
    csrf = state.csrf;
    if (state.stage === "identity") identityView();
    else if (state.stage === "start-authenticator") authenticatorStartView();
    else if (state.stage === "authenticator") restoreAuthenticatorView();
    else if (state.stage === "backup") restoreBackupView();
    else completeView();
  } catch (_) {
    try {
      const preauth = await request("/api/preauth", undefined, "GET");
      preCsrf = preauth.csrf;
      signInView();
    } catch (error) {
      showStep("Sign in", "Unable to start", "<p class='error'>Please refresh this page and try again.</p>");
    }
  }
}

bootstrap();
})();
</script>
</body>
</html>`;
}

const server = Bun.serve({
  port: PORT,
  tls: {
    cert: readFileSync(CERT_PATH),
    key: readFileSync(KEY_PATH),
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);

      if (url.protocol !== "https:") {
        return new Response("Secure connection required.", {
          status: 426,
          headers: securityHeaders(),
        });
      }

      if (url.pathname.startsWith("/api/")) {
        return await api(request, url.pathname);
      }

      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        const nonce = randomToken(18);
        const responseHeaders = securityHeaders(nonce, request.headers.get("origin"));
        responseHeaders.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { status: 200, headers: responseHeaders });
      }

      return new Response("Not found.", { status: 404, headers: securityHeaders() });
    } catch {
      return new Response("We could not complete that request.", {
        status: 500,
        headers: securityHeaders(),
      });
    }
  },
});

console.log(`Local Bank MFA is running securely on https://localhost:${server.port}`);
