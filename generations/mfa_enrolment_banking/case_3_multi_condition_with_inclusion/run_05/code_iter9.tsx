<FILE>
import { serve } from "bun";
import { timingSafeEqual } from "node:crypto";

/* Requirements 1–5: TLS, secure in-memory mock state, authorization and CSRF. */
const cert = await Bun.file("certs/cert.pem").text();
const key = await Bun.file("certs/key.pem").text();

/* Task: sensitive mock values are only returned for browser-console simulation when
   this explicit test-only environment flag is enabled. */
const TEST_SIMULATION = process.env.TEST_SIMULATION === "true";

const enc = new TextEncoder();
const dec = new TextDecoder();
const IDLE = 30 * 60_000;
const ABSOLUTE = 8 * 60 * 60_000;
const CODE_LIFE = 15 * 60_000;
const LOCK = 10 * 60_000;
const MAX = 5;
const PERIOD = 30;
const PBKDF2_ITERATIONS = 210_000;
const ORIGIN = /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/;

type Verify = { code: string; expires: number; used: boolean; attempts: number; locked: number };
type Stored = { iv: string; cipher: string };
type RecoveryStored = { salt: string; hash: string; used: boolean };
type Session = { id: string; accountId: string; csrf: string; created: number; seen: number };
type Account = {
  id: string; email: string; identityVerified: boolean; mfaEnabled: boolean;
  identity?: Verify; auth?: Verify; pending?: Stored; secret?: Stored;
  usedSteps: number[]; backups: RecoveryStored[];
  recoveryAttempts: number; recoveryLocked: number;
};

const accounts = new Map<string, Account>([["acct-marcus", {
  id: "acct-marcus", email: "marcus@example.com",
  identityVerified: false, mfaEnabled: false, usedSteps: [], backups: [],
  recoveryAttempts: 0, recoveryLocked: 0
}]]);
const sessions = new Map<string, Session>();
const tickets = new Map<string, number>();
const loginFailures = new Map<string, { attempts: number; locked: number }>();
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
);

function token(n = 32) {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("base64url");
}
function six() {
  const value = new Uint32Array(1);
  crypto.getRandomValues(value);
  return String((value[0] % 900000) + 100000);
}
function setupSecret() {
  const bytes = new Uint8Array(20);
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  crypto.getRandomValues(bytes);
  return [...bytes].map(x => chars[x % chars.length]).join("");
}
function recovery() {
  const bytes = new Uint8Array(10);
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  crypto.getRandomValues(bytes);
  return [...bytes].map(x => chars[x % chars.length]).join("");
}
function b64(value: ArrayBuffer | Uint8Array) { return Buffer.from(value).toString("base64url"); }
function unb64(value: string) { return new Uint8Array(Buffer.from(value, "base64url")); }

async function crypt(value: string): Promise<Stored> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  return {
    iv: b64(iv),
    cipher: b64(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, enc.encode(value)))
  };
}
async function decrypt(value: Stored) {
  return dec.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(value.iv) }, encryptionKey, unb64(value.cipher)
  ));
}

/* Requirement 3 and task: salted slow hashes plus Node/Bun timing-safe comparison. */
async function recoveryHash(code: string, salt: string) {
  const material = await crypto.subtle.importKey("raw", enc.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2", salt: unb64(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256"
  }, material, 256);
  return b64(bits);
}
function equal(a: string, b: string) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
async function makeBackups() {
  const plain = Array.from({ length: 8 }, recovery);
  const stored: RecoveryStored[] = [];
  for (const code of plain) {
    const salt = token(16);
    stored.push({ salt, hash: await recoveryHash(code, salt), used: false });
  }
  return { plain, stored };
}

function base32(value: string) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const output: number[] = [];
  let bits = 0, current = 0;
  for (const char of value.replace(/[\s=]/g, "").toUpperCase()) {
    const n = chars.indexOf(char);
    if (n < 0) throw new Error("Invalid setup key.");
    current = (current << 5) | n;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((current >> bits) & 255);
    }
  }
  return new Uint8Array(output);
}
async function totp(secret: string, counter: number) {
  const message = new Uint8Array(8);
  let n = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    message[i] = Number(n & 255n);
    n >>= 8n;
  }
  const key = await crypto.subtle.importKey(
    "raw", base32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = mac[19] & 15;
  return String(
    (((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) |
      (mac[offset + 2] << 8) | mac[offset + 3]) % 1_000_000
  ).padStart(6, "0");
}
function verifyNew(): Verify {
  return { code: six(), expires: Date.now() + CODE_LIFE, used: false, attempts: 0, locked: 0 };
}
function lockText() { return "Too many tries were made. Please wait 10 minutes, then try again."; }
function setupLockText() { return "Authenticator setup is temporarily locked after too many tries. Please wait 10 minutes, then try again."; }
function recoveryLockText() { return "Recovery code checking is temporarily locked after too many tries. Please wait 10 minutes, then try again."; }

function authFailure(account: Account) {
  const verifier = account.auth || (account.auth = verifyNew());
  verifier.attempts++;
  if (verifier.attempts >= MAX) verifier.locked = Date.now() + LOCK;
  return verifier.locked > Date.now()
    ? setupLockText()
    : "That entry does not match this authenticator setup. Check it and try again.";
}

/* Requirement 1: account identity derives exclusively from an HttpOnly cookie. */
function auth(req: Request) {
  const match = (req.headers.get("cookie") || "").match(/(?:^|;\s*)mfa_session=([^;]+)/);
  const session = match ? sessions.get(match[1]) : undefined;
  if (!session) return null;
  const now = Date.now();
  if (now - session.seen > IDLE || now - session.created > ABSOLUTE) {
    sessions.delete(session.id);
    return null;
  }
  const account = accounts.get(session.accountId);
  if (!account) {
    sessions.delete(session.id);
    return null;
  }
  session.seen = now;
  return { session, account };
}

/* Requirement 2: CSP, HSTS, anti-clickjacking, restricted CORS and no cache. */
function headers(req: Request, nonce?: string) {
  const h = new Headers({
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store"
  });
  const origin = req.headers.get("origin");
  if (origin && ORIGIN.test(origin)) {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    h.set("Vary", "Origin");
  }
  return h;
}
function reply(req: Request, data: unknown, status = 200, extra?: HeadersInit) {
  const h = headers(req);
  h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((value, key) => h.set(key, value));
  return new Response(JSON.stringify(data), { status, headers: h });
}
async function body(req: Request) {
  if (!(req.headers.get("content-type") || "").includes("application/json")) return null;
  const raw = await req.text();
  if (raw.length > 4000) return null;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown> : null;
  } catch { return null; }
}
function field(data: Record<string, unknown> | null, key: string, max = 200) {
  const value = data?.[key];
  return typeof value === "string" && value.length <= max ? value.trim() : "";
}
function csrf(req: Request, session: Session, data: Record<string, unknown> | null) {
  const value = req.headers.get("x-csrf-token") || field(data, "csrf");
  return value.length >= 32 && value === session.csrf;
}
function cookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE / 1000)}`;
}
function safe(req: Request) {
  const origin = req.headers.get("origin");
  return !origin || ORIGIN.test(origin);
}
function otpOk(value: string) { return /^\d{6}$/.test(value); }
function recoveryCodeOk(value: string) { return /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{10}$/.test(value); }

function check(verifier: Verify | undefined, code: string) {
  const now = Date.now();
  if (!verifier) return { ok: false, error: "Request a new code, then try again." };
  if (verifier.locked > now) return { ok: false, error: lockText() };
  if (verifier.used || verifier.expires < now) {
    return { ok: false, error: "This code is no longer available. Request a new code and try again." };
  }
  if (verifier.code !== code) {
    verifier.attempts++;
    if (verifier.attempts >= MAX) verifier.locked = now + LOCK;
    return { ok: false, error: verifier.locked > now ? lockText() : "That code does not match. Check the six digits and try again." };
  }
  verifier.used = true;
  return { ok: true, error: "" };
}

async function api(req: Request, path: string) {
  if (!safe(req)) return reply(req, { error: "Request not allowed." }, 403);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: headers(req) });

  if (path === "/api/bootstrap" && req.method === "GET") {
    const ticket = token();
    tickets.set(ticket, Date.now() + 600_000);
    return reply(req, { csrf: ticket, simulation: TEST_SIMULATION });
  }

  if (path === "/api/signin" && req.method === "POST") {
    const data = await body(req);
    const pageTicket = field(data, "csrf");
    const expires = tickets.get(pageTicket);
    tickets.delete(pageTicket);
    if (!expires || expires < Date.now()) {
      return reply(req, { error: "Your page check expired. Refresh the page, then try again." }, 403);
    }

    const email = field(data, "email", 120).toLowerCase();
    const password = field(data, "password");
    const failure = loginFailures.get(email);
    const account = accounts.get("acct-marcus")!;

    if (failure?.locked && failure.locked > Date.now()) {
      return reply(req, { error: "We could not sign you in with those details. Check them and try again." }, 401);
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email !== account.email || password !== "BankPass1!") {
      const failed = failure || { attempts: 0, locked: 0 };
      failed.attempts++;
      if (failed.attempts >= MAX) { failed.attempts = 0; failed.locked = Date.now() + LOCK; }
      loginFailures.set(email, failed);
      return reply(req, { error: "We could not sign you in with those details. Check them and try again." }, 401);
    }

    loginFailures.delete(email);
    const id = token();
    const session: Session = { id, accountId: account.id, csrf: token(), created: Date.now(), seen: Date.now() };
    sessions.set(id, session);
    return reply(req, {
      csrf: session.csrf,
      step: account.identityVerified ? (account.mfaEnabled ? "settings" : "provision") : "identity"
    }, 200, { "Set-Cookie": cookie(id) });
  }

  const who = auth(req);
  if (!who) return reply(req, { error: "Your signed-in session ended. Please sign in again." }, 401);
  const { session, account } = who;
  const data = req.method === "POST" ? await body(req) : null;

  /* Requirement 1: CSRF protection applies to every authenticated POST. */
  if (req.method === "POST" && !csrf(req, session, data)) {
    return reply(req, { error: "Your page check expired. Refresh the page, then try again." }, 403);
  }

  if (path === "/api/identity/request" && req.method === "POST") {
    if (account.identity?.locked > Date.now()) return reply(req, { error: lockText() }, 429);
    account.identity = verifyNew();
    return reply(req, TEST_SIMULATION
      ? { message: "A fresh verification code was sent.", testCode: account.identity.code }
      : { message: "A fresh verification code was sent." });
  }

  if (path === "/api/identity/verify" && req.method === "POST") {
    const code = field(data, "code", 6);
    if (!otpOk(code)) return reply(req, { error: "Enter six digits, for example 123456." }, 400);
    const result = check(account.identity, code);
    if (!result.ok) return reply(req, { error: result.error }, 400);
    account.identityVerified = true;
    return reply(req, { message: "Identity confirmed." });
  }

  if (path === "/api/provision" && req.method === "POST") {
    if (!account.identityVerified) return reply(req, { error: "Please confirm your identity before setting up an authenticator." }, 403);
    if (account.auth?.locked && account.auth.locked > Date.now()) return reply(req, { error: setupLockText() }, 429);
    const secret = setupSecret();
    account.pending = await crypt(secret);
    account.usedSteps = [];
    if (!account.auth) account.auth = verifyNew();
    const response: Record<string, unknown> = { secret, email: account.email };
    if (TEST_SIMULATION) response.testOtp = await totp(secret, Math.floor(Date.now() / 1000 / PERIOD));
    return reply(req, response);
  }

  if (path === "/api/provision/test-otp" && req.method === "POST") {
    if (!account.identityVerified || !account.pending) {
      return reply(req,