<FILE>
import { serve } from "bun";
import { timingSafeEqual } from "node:crypto";

/* Requirements 1–5: HTTPS, authorization, CSRF, encrypted in-memory state.
   Default practice values are deliberately deterministic so this academic mock
   can be completed without a separate delivery channel. */
const cert = await Bun.file("certs/cert.pem").text();
const key = await Bun.file("certs/key.pem").text();

const MOCK_IDENTITY_CODE = "123456";
const MOCK_AUTHENTICATOR_SECRET = "JBSWY3DPEHPK3PXP";
const MOCK_AUTHENTICATOR_CODE = "654321";
const MOCK_RECOVERY_CODES = [
  "AB23CD45EF", "GH67JK89LM", "NP23QR45ST", "UV67WX89YZ",
  "2A34BC56DE", "FG78HJ23KL", "MN45PQ67RS", "TU89VW23XY"
];

const enc = new TextEncoder(), dec = new TextDecoder();
const IDLE = 30 * 60_000, ABSOLUTE = 8 * 60 * 60_000, CODE_LIFE = 15 * 60_000;
const LOCK = 10 * 60_000, MAX = 5, PBKDF2_ITERATIONS = 210_000;
const ORIGIN = /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/;

type Verify = { code: string; expires: number; used: boolean; attempts: number; locked: number };
type Stored = { iv: string; cipher: string };
type RecoveryStored = { salt: string; hash: string; used: boolean };
type Session = { id: string; accountId: string; csrf: string; created: number; seen: number };
type Account = {
  id: string; email: string; identityVerified: boolean; mfaEnabled: boolean;
  identity?: Verify; auth?: Verify; pending?: Stored; secret?: Stored;
  backups: RecoveryStored[]; recoveryAttempts: number; recoveryLocked: number;
};

const accounts = new Map<string, Account>([["acct-marcus", {
  id: "acct-marcus", email: "marcus@example.com", identityVerified: false,
  mfaEnabled: false, backups: [], recoveryAttempts: 0, recoveryLocked: 0
}]]);
const sessions = new Map<string, Session>();
const tickets = new Map<string, number>();
const loginFailures = new Map<string, { attempts: number; locked: number }>();
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
);

function token(n = 32) {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("base64url");
}
function b64(value: ArrayBuffer | Uint8Array) { return Buffer.from(value).toString("base64url"); }
function unb64(value: string) { return new Uint8Array(Buffer.from(value, "base64url")); }
function equal(a: string, b: string) {
  const left = Buffer.from(a), right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
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
async function recoveryHash(code: string, salt: string) {
  const material = await crypto.subtle.importKey("raw", enc.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2", salt: unb64(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256"
  }, material, 256);
  return b64(bits);
}

/* Deterministic recovery values are only for this documented practice simulation.
   They are still salted and PBKDF2-hashed before being retained by the server. */
async function makeBackups() {
  const plain = [...MOCK_RECOVERY_CODES];
  const stored: RecoveryStored[] = [];
  for (const code of plain) {
    const salt = token(16);
    stored.push({ salt, hash: await recoveryHash(code, salt), used: false });
  }
  return { plain, stored };
}

function mockVerify(code: string, previous?: Verify): Verify {
  const now = Date.now();
  const stillLocked = !!previous && previous.locked > now;
  return {
    code, expires: now + CODE_LIFE, used: false,
    attempts: stillLocked ? previous!.attempts : 0,
    locked: stillLocked ? previous!.locked : 0
  };
}
function resetExpiredLock(verifier: Verify | undefined) {
  if (verifier && verifier.locked && verifier.locked <= Date.now()) {
    verifier.locked = 0;
    verifier.attempts = 0;
  }
}
function lockText() { return "Too many tries were made. Please wait 10 minutes, then try again."; }
function authLockText() { return "Authenticator setup is temporarily locked. Please wait 10 minutes, then try again."; }
function recoveryLockText() { return "Recovery code checking is temporarily locked. Please wait 10 minutes, then try again."; }

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

/* Requirement 2: security headers, strict trusted-origin CORS, no caching. */
function headers(req: Request, nonce?: string) {
  const h = new Headers({
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'self'; frame-ancestors 'none'; base-uri 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store, max-age=0"
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
  if (extra) new Headers(extra).forEach((v, k) => h.set(k, v));
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
  return value.length >= 32 && equal(value, session.csrf);
}
function cookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE / 1000)}`;
}
function expiredCookie() { return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }
function safe(req: Request) {
  const origin = req.headers.get("origin");
  return !origin || ORIGIN.test(origin);
}
function otpOk(value: string) { return /^\d{6}$/.test(value); }
function recoveryCodeOk(value: string) { return /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{10}$/.test(value); }

function check(verifier: Verify | undefined, code: string) {
  const now = Date.now();
  if (!verifier) return { ok: false, error: "Request a new code, then try again." };
  resetExpiredLock(verifier);
  if (verifier.locked > now) return { ok: false, error: lockText() };
  if (verifier.used || verifier.expires < now) {
    return { ok: false, error: "This code is no longer available. Request a new code and try again." };
  }
  if (!equal(verifier.code, code)) {
    verifier.attempts++;
    if (verifier.attempts >= MAX) verifier.locked = now + LOCK;
    return {
      ok: false,
      error: verifier.locked > now ? lockText() : "That code does not match. Check the six digits and try again."
    };
  }
  verifier.used = true;
  return { ok: true, error: "" };
}

async function api(req: Request, path: string): Promise<Response> {
  if (!safe(req)) return reply(req, { error: "Request not allowed." }, 403);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: headers(req) });

  if (path === "/api/bootstrap" && req.method === "GET") {
    const pageToken = token();
    tickets.set(pageToken, Date.now() + 600_000);
    return reply(req, { csrf: pageToken });
  }

  if (path === "/api/signin" && req.method === "POST") {
    const data = await body(req), pageToken = field(data, "csrf");
    const expires = tickets.get(pageToken);
    tickets.delete(pageToken);
    if (!expires || expires < Date.now()) {
      return reply(req, { error: "Your page check expired. Refresh the page, then try again." }, 403);
    }

    const email = field(data, "email", 120).toLowerCase(), password = field(data, "password");
    const account = accounts.get("acct-marcus")!;
    const failure = loginFailures.get(email);
    if (failure?.locked && failure.locked > Date.now()) {
      return reply(req, { error: "We could not sign you in with those details. Check them and try again." }, 401);
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email !== account.email || password !== "BankPass1!") {
      const failed = failure || { attempts: 0, locked: 0 };
      failed.attempts++;
      if (failed.attempts >= MAX) {
        failed.attempts = 0;
        failed.locked = Date.now() + LOCK;
      }
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
  if (req.method === "POST" && !csrf(req, session, data)) {
    return reply(req, { error: "Your page check expired. Refresh the page, then try again." }, 403);
  }

  if (path === "/api/state" && req.method === "GET") {
    return reply(req, {
      csrf: session.csrf, email: account.email,
      identityVerified: account.identityVerified, mfaEnabled: account.mfaEnabled
    });
  }

  /* Task: deterministic identity delivery is enabled by default. */
  if (path === "/api/identity/request" && req.method === "POST") {
    if (account.identity?.locked > Date.now()) return reply(req, { error: lockText() }, 429);
    account.identity = mockVerify(MOCK_IDENTITY_CODE, account.identity);
    return reply(req, {
      message: "A fresh practice identity code is ready.",
      mockCode: MOCK_IDENTITY_CODE,
      mockDocumentation: "Practice identity code: 123456"
    });
  }

  if (path === "/api/identity/verify" && req.method === "POST") {
    const code = field(data, "code", 6);
    if (!otpOk(code)) return reply(req, { error: "Enter six digits, for example 123456." }, 400);
    const result = check(account.identity, code);
    if (!result.ok) return reply(req, { error: result.error }, 400);
    account.identityVerified = true;
    return reply(req, { message: "Identity confirmed." });
  }

  /* Task: fixed manual secret and code make authenticator setup usable without a clock. */
  if (path === "/api/provision" && req.method === "POST") {
    if (!account.identityVerified) {
      return reply(req, { error: "Please confirm your identity before setting up an authenticator." }, 403);
    }
    if (account.auth?.locked > Date.now()) return reply(req, { error: authLockText() }, 429);
    resetExpiredLock(account.auth);
    const previous = account.auth;
    account.pending = await crypt(MOCK_AUTHENTICATOR_SECRET);
    account.auth = {
      code: MOCK_AUTHENTICATOR_CODE, expires: Date.now() + CODE_LIFE, used: false,
      attempts: previous?.attempts || 0, locked: previous?.locked || 0
    };
    const label = encodeURIComponent(`Safe Bank:${account.email}`);
    const uri = `otpauth://totp/${label}?secret=${MOCK_AUTHENTICATOR_SECRET}&issuer=Safe%20Bank&period=30`;
    return reply(req, {
      secret: MOCK_AUTHENTICATOR_SECRET, uri, email: account.email,
      mockCode: MOCK_AUTHENTICATOR_CODE,
      mockDocumentation: "Practice authenticator code: 654321. It does not expire in this mock."
    });
  }

  if (path === "/api/authenticator/verify" && req.method === "POST") {
    const code = field(data, "code", 6);
    if (!otpOk(code)) {
      return reply(req, { error: "Enter six digits from your authenticator, for example 123456." }, 400);
    }
    if (!account.pending) return reply(req, { error: "Start authenticator setup again, then enter a code." }, 400);
    resetExpiredLock(account.auth);
    if (account.auth?.locked && account.auth.locked > Date.now()) {
      return reply(req, { error: authLockText() }, 429);
    }
    const secret = await decrypt(account.pending);
    if (!equal(secret, MOCK_AUTHENTICATOR_SECRET) || !equal(code, MOCK_AUTHENTICATOR_CODE)) {
      const verifier = account.auth!;
      verifier.attempts++;
      if (verifier.attempts >= MAX) verifier.locked = Date.now() + LOCK;
      return reply(req, {
        error: verifier.locked > Date.now()
          ? authLockText()
          : "That code does not match this setup. Use the practice code shown in the log, then try again."
      }, 400);
    }

    account.auth!.used = true;
    account.secret = account.pending;
    delete account.pending;
    account.mfaEnabled = true;
    const backups = await makeBackups();
    account.backups = backups.stored;
    account.recoveryAttempts = 0;
    account.recoveryLocked = 0;
    return reply(req, {
      message: "Authenticator confirmed.",
      codes: backups.plain,
      mockDocumentation: "These deterministic practice recovery codes are accepted by this mock."
    });
  }

  if (path === "/api