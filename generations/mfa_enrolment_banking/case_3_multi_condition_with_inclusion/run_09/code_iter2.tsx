
import { timingSafeEqual } from "node:crypto";

/*
  MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.
  Accessibility requirements: plain language, spacing, predictable steps, no timers/motion.
  Security requirements 1–5: session ownership, CSRF, TLS headers, protected mock secrets,
  validation, rate limiting, and secure session lifecycle are implemented below.
*/

type Stage = "signed-in" | "identity" | "setup" | "otp" | "recovery" | "complete";

type Session = {
  id: string;
  csrf: string;
  authenticated: boolean;
  userId?: string;
  email?: string;
  stage: Stage;
  createdAt: number;
  lastSeen: number;
  identityCodeHash?: string;
  identityExpiresAt?: number;
  identityUsed?: boolean;
  identityFailures: number;
  otpHash?: string;
  otpExpiresAt?: number;
  otpUsed?: boolean;
  otpFailures: number;
  recoveryFailures: number;
  lockedUntil?: number;
  encryptedOtpSecret?: { iv: string; ciphertext: string };
  recoveryCodes: Array<{ salt: string; hash: string; used: boolean; expiresAt: number }>;
};

const sessions = new Map<string, Session>();
const MASTER_KEY = crypto.getRandomValues(new Uint8Array(32));
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 15 * 60 * 1000;
const RECOVERY_LIFETIME_MS = 365 * 24 * 60 * 60 * 1000;
const LOCK_MS = 5 * 60 * 1000;
const TEST_IDENTITY_CODE = "246810";
const TEST_AUTHENTICATOR_OTP = "123456";
const encoder = new TextEncoder();

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function now(): number {
  return Date.now();
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Buffer.from(digest).toString("base64url");
}

async function encryptAtRest(value: string): Promise<{ iv: string; ciphertext: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", MASTER_KEY, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return {
    iv: Buffer.from(iv).toString("base64url"),
    ciphertext: Buffer.from(encrypted).toString("base64url"),
  };
}

function secureEqual(a: string, b: string): boolean {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}

function cookieValue(request: Request, name: string): string | undefined {
  const header = request.headers.get("cookie") || "";
  return header.split(";").map((item) => item.trim()).find((item) => item.startsWith(name + "="))?.slice(name.length + 1);
}

function cookieFor(sessionId: string, maxAge = SESSION_ABSOLUTE_MS / 1000): string {
  return `mfa_session=${sessionId}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

function expiredCookie(): string {
  return "mfa_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict";
}

function makeSession(): Session {
  const session: Session = {
    id: randomToken(),
    csrf: randomToken(),
    authenticated: false,
    stage: "signed-in",
    createdAt: now(),
    lastSeen: now(),
    identityFailures: 0,
    otpFailures: 0,
    recoveryFailures: 0,
    recoveryCodes: [],
  };
  sessions.set(session.id, session);
  return session;
}

/* Security requirement 5: idle and absolute session expiry on every protected request. */
function currentSession(request: Request, requireAuth = false): Session | null {
  const id = cookieValue(request, "mfa_session");
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  if (now() - session.lastSeen > SESSION_IDLE_MS || now() - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  if (requireAuth && !session.authenticated) return null;
  session.lastSeen = now();
  return session;
}

function baseHeaders(nonce?: string): Headers {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  if (nonce) {
    headers.set(
      "Content-Security-Policy",
      `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    );
  } else {
    headers.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  }
  return headers;
}

function json(data: unknown, status = 200, extra?: Record<string, string>): Response {
  const headers = baseHeaders();
  if (extra) for (const [key, value] of Object.entries(extra)) headers.set(key, value);
  return new Response(JSON.stringify(data), { status, headers });
}

function safeError(message = "Something went wrong. Please try again.", status = 400): Response {
  return json({ ok: false, error: message }, status);
}

function trustedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  return /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(origin);
}

/* Security requirements 1 and 4: mutation requests need same trusted origin and a CSRF token. */
function csrfValid(request: Request, session: Session): boolean {
  if (!trustedOrigin(request)) return false;
  const token = request.headers.get("x-csrf-token") || "";
  return /^[A-Za-z0-9_-]{40,60}$/.test(token) && secureEqual(token, session.csrf);
}

async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 4096) return null;
  try {
    const value = await request.json();
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const body = value as Record<string, unknown>;
    if ("userId" in body || "accountId" in body || "redirect" in body) return null;
    return body;
  } catch {
    return null;
  }
}

function stringField(body: Record<string, unknown>, field: string, max: number): string | null {
  const value = body[field];
  if (typeof value !== "string" || value.length > max) return null;
  return value.trim();
}

function validEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 120;
}

function validPhone(phone: string): boolean {
  return /^\+?[0-9 ()-]{7,24}$/.test(phone);
}

function validCode(code: string): boolean {
  return /^\d{6}$/.test(code);
}

function validRecoveryCode(code: string): boolean {
  return /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code);
}

function locked(session: Session): boolean {
  return !!session.lockedUntil && session.lockedUntil > now();
}

function failAndMaybeLock(session: Session, kind: "identityFailures" | "otpFailures" | "recoveryFailures"): void {
  session[kind]++;
  if (session[kind] >= 5) {
    session.lockedUntil = now() + LOCK_MS;
    session[kind] = 0;
  }
}

function requireOwner(request: Request): Session | Response {
  const session = currentSession(request, true);
  if (!session) return safeError("Your secure session has ended. Please sign in again.", 401);
  return session;
}

function stateView(session: Session) {
  return {
    ok: true,
    stage: session.stage,
    email: session.email || "",
    csrf: session.csrf,
    locked: locked(session),
  };
}

function recoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  const chars = Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
  return `${chars.slice(0, 4)}-${chars.slice(4)}`;
}

/* Requirement 3: Base32 encodes cryptographically random authenticator key bytes. */
function base32Secret(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function authenticatorDetails(session: Session, secret: string) {
  const issuer = "Northstar Bank";
  const label = `${issuer}:${session.email || "marcus@example.com"}`;
  const provisioningUri =
    `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}` +
    `&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  return { secret, provisioningUri, testOtp: TEST_AUTHENTICATOR_OTP };
}

async function createAuthenticatorDetails(session: Session) {
  const secret = base32Secret();
  session.encryptedOtpSecret = await encryptAtRest(secret);
  session.otpHash = await sha256(TEST_AUTHENTICATOR_OTP);
  session.otpExpiresAt = now() + CODE_LIFETIME_MS;
  session.otpUsed = false;
  session.otpFailures = 0;
  return authenticatorDetails(session, secret);
}

async function createRecoveryCodes(session: Session): Promise<string[]> {
  const codes = Array.from({ length: 6 }, recoveryCode);
  session.recoveryCodes = await Promise.all(codes.map(async (code) => {
    const salt = randomToken(16);
    return { salt, hash: await sha256(`${salt}:${code}`), used: false, expiresAt: now() + RECOVERY_LIFETIME_MS };
  }));
  return codes;
}

async function api(request: Request, pathname: string): Promise<Response> {
  if (!trustedOrigin(request)) return safeError("This request is not allowed.", 403);

  if (pathname === "/api/bootstrap" && request.method === "GET") {
    let session = currentSession(request);
    let setCookie: string | undefined;
    if (!session) {
      session = makeSession();
      setCookie = cookieFor(session.id);
    }
    return json({ ok: true, csrf: session.csrf, authenticated: session.authenticated, stage: session.stage }, 200, setCookie ? { "Set-Cookie": setCookie } : undefined);
  }

  if (pathname === "/api/sign-in" && request.method === "POST") {
    const old = currentSession(request);
    if (!old || !csrfValid(request, old)) return safeError("Please refresh the page and try signing in again.", 403);
    const body = await readBody(request);
    if (!body) return safeError("Please enter your email and password in the expected format.");
    const email = stringField(body, "email", 120);
    const password = stringField(body, "password", 200);
    if (!email || !validEmail(email) || !password) return safeError("Enter an email like name@example.com and your password.");
    if (email.toLowerCase() !== "marcus@example.com" || password !== "bank-demo") {
      return safeError("We could not sign you in. Check your email and password, then try again.", 401);
    }

    sessions.delete(old.id);
    const session = makeSession();
    session.authenticated = true;
    session.userId = "account-owner-marcus";
    session.email = "marcus@example.com";
    session.stage = "identity";
    session.identityCodeHash = await sha256(TEST_IDENTITY_CODE);
    session.identityExpiresAt = now() + CODE_LIFETIME_MS;

    return json({
      ok: true,
      csrf: session.csrf,
      stage: session.stage,
      testIdentityCode: TEST_IDENTITY_CODE,
      message: "We sent a six-digit check code.",
    }, 200, { "Set-Cookie": cookieFor(session.id) });
  }

  if (pathname === "/api/state" && request.method === "GET") {
    const session = requireOwner(request);
    return session instanceof Response ? session : json(stateView(session));
  }

  if (pathname === "/api/identity/verify" && request.method === "POST") {
    const session = requireOwner(request);
    if (session instanceof Response) return session;
    if (!csrfValid(request, session)) return safeError("Please refresh the page and try again.", 403);
    /* Identity stage is required; lockout is enforced before checking any submitted value. */
    if (session.stage !== "identity") return safeError("Please complete the earlier step first.", 409);
    if (locked(session)) return safeError("Too many tries. Please wait five minutes, then try again.", 429);
    const body = await readBody(request);
    const code = body ? stringField(body, "code", 6) : null;
    const phone = body ? stringField(body, "phone", 24) : null;
    if (!code || !validCode(code) || !phone || !validPhone(phone)) {
      return safeError("Enter a six-digit code like 246810 and a phone number like +1 555 010 0200.");
    }
    if (session.identityUsed || !session.identityCodeHash || !session.identityExpiresAt || now() > session.identityExpiresAt) {
      return safeError("That check code is no longer active. Choose “send a new code” and try again.");
    }
    if (!secureEqual(await sha256(code), session.identityCodeHash)) {
      failAndMaybeLock(session, "identityFailures");
      return safeError(locked(session) ? "Too many tries. Please wait five minutes, then try again." : "That code does not match. Check the six digits and try again.");
    }
    session.identityUsed = true;
    session.stage = "setup";
    return json({ ok: true, stage: session.stage, message: "Identity check complete. Next, add your authenticator." });
  }

  if (pathname === "/api/identity/resend" && request.method === "POST") {
    const session = requireOwner(request);
    if (session instanceof Response) return session;
    if (!csrfValid(request, session)) return safeError("Please refresh the page and try again.", 403);
    /* Resend cannot be used to reset counters or bypass the active five-minute lockout. */
    if (session.stage !== "identity") return safeError("Please complete the earlier step first.", 409);
    if (locked(session)) return safeError("Too many tries. Please wait five minutes, then try again.", 429);
    session.identityCodeHash = await sha256(TEST_IDENTITY_CODE);
    session.identityExpiresAt = now() + CODE_LIFETIME_MS;
    session.identityUsed = false;
    return json({ ok: true, testIdentityCode: TEST_IDENTITY_CODE, message: "A new check code is ready. Your previous tries are still counted." });
  }

  if (pathname === "/api/authenticator/setup" && request.method === "POST") {
    const session = requireOwner(request);
    if (session instanceof Response) return session;
    if (!csrfValid(request, session)) return safeError("Please refresh the page and try again.", 403);
    if (session.stage !== "setup") return safeError("Please complete the earlier step first.", 409);
    const details = await createAuthenticatorDetails(session);
    session.stage = "otp";
    return json({
      ok: true,
      stage: session.stage,
      ...details,
      message: "Authenticator details are ready. Add them, then enter its six-digit code.",
    });
  }

  /*
    Requirement task: authenticated, owner-scoped and CSRF-protected fresh provisioning
    details during the OTP stage. A fresh secret invalidates the previous setup details.
  */
  if (pathname === "/api/authenticator/refresh" && request.method === "POST") {
    const session = requireOwner(request);
    if (session instanceof Response) return session;
    if (!csrfValid(request, session)) return safeError("Please refresh the page and try again.", 403);
    if (session.stage !== "otp") return safeError("Please complete the earlier step first.", 409);
    if (locked(session)) return safeError("Too many tries. Please wait five minutes, then try again.", 429);
    const details = await createAuthenticatorDetails(session);
    return json({
      ok: true,
      stage: session.stage,
      ...details,
      message: "Fresh authenticator setup details are ready. The previous setup details no longer work.",
    });
  }

  if (pathname === "/api/otp/verify" && request.method === "POST") {
    const session = requireOwner(request);
    if (session instanceof Response) return session;
    if (!csrfValid(request, session)) return safeError("Please refresh the page and try again.", 403);
    if (session.stage !== "otp") return safeError("Please complete the earlier step first.", 409);
    if (locked(session)) return safeError("Too many tries. Please wait five minutes, then try again.", 429);
    const body = await readBody(request);
    const code = body ? stringField(body, "code", 6) : null;
    if (!code || !validCode(code)) return safeError("Enter six numbers, for example 123456.");
    if (session.otpUsed || !session.otpHash || !session.otpExpiresAt || now() > session.otpExpiresAt) {
      return safeError("That authenticator code is no longer active. Choose “get fresh setup details” and try again.");
    }
    if (!secureEqual(await sha256(code), session.otpHash)) {
      failAndMaybeLock(session, "otpFailures");
      return safeError(locked(session) ? "Too many tries. Please wait five minutes, then try again." : "That code does not match. Check the six numbers in your authenticator and try again.");
    }
    session.otpUsed = true;
    session.stage = "recovery";
    const codes = await createRecoveryCodes(session);
    return json({ ok: true, stage: session.stage, recoveryCodes: codes, message: "Authenticator confirmed. Your recovery codes are ready." });
  }

  if (pathname === "/api/recovery/generate" && request.method === "POST") {
    const session = requireOwner(request);
    if (session instanceof Response) return session;
    if (!csrfValid(request, session)) return safeError("Please refresh the page and try again.", 403);
    if (session.stage !== "recovery" && session.stage !== "complete") return safeError("Please complete the earlier step first.", 409);
    const codes = await createRecoveryCodes(session);
    return json({ ok: true, recoveryCodes: codes, message: "New recovery codes are ready. The old ones no longer work." });
  }

  if (pathname === "/api/recovery/verify" && request.method === "POST") {
    const session = requireOwner(request);
    if (session instanceof Response) return session;
    if (!csrfValid(request, session)) return safeError("Please refresh the page and try again.", 403);
    if (locked(session)) return safeError("Too many tries. Please wait five minutes, then try again.", 429);
    const body = await readBody(request);
    const code = body ? stringField(body, "recoveryCode", 9)?.toUpperCase() : null;
    if (!code || !validRecoveryCode(code)) return safeError("Enter a recovery code like ABCD-EFGH.");
    let matched: { salt: string; hash: string; used: boolean; expiresAt: number } | undefined;
    for (const entry of session.recoveryCodes) {
      const candidate = await sha256(`${entry.salt}:${code}`);
      if (!entry.used && entry.expiresAt > now() && secureEqual(candidate, entry.hash)) matched = entry;
    }
    if (!matched) {
      failAndMaybeLock(session, "recoveryFailures");
      return safeError(locked(session) ? "Too many tries. Please wait five minutes, then try again." : "That recovery code does not match an unused code. Check it and try again.");
    }
    matched.used = true;
    return json({ ok: true, message: "That recovery code worked and is now used. Your other codes still work." });
  }

  if (pathname === "/api/recovery/complete" && request.method === "POST") {
    const session = requireOwner(request);
    if (session instanceof Response) return session;
    if (!csrfValid(request, session)) return safeError("Please refresh the page and try again.", 403);
    if (session.stage !== "recovery") return safeError("Please complete the earlier step first.", 409);
    session.stage = "complete";
    return json({ ok: true, stage: session.stage, message: "MFA enrolment is complete." });
  }

  if (pathname === "/api/logout" && request.method === "POST") {
    const session = currentSession(request);
    if (!session || !csrfValid(request, session)) return safeError("Please refresh the page and try again.", 403);
    sessions.delete(session.id);
    return json({ ok: true, message: "You have signed out." }, 200, { "Set-Cookie": expiredCookie() });
  }

  return safeError("That page is not available.", 404);
}

function htmlPage(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Northstar Bank — MFA setup</title>
<style nonce="${nonce}">
:root { --ink:#172033; --muted:#536074; --blue:#0759b8; --dark:#063a78; --soft:#eef6ff; --line:#cad5e2; --card:#fff; }
* { box-sizing:border-box; }
body { margin:0; background:#f3f6fa; color:var(--ink); font-family:Arial, Verdana, Tahoma, sans-serif; font-size:17px; line-height:1.65; letter-spacing:.035em; }
button,input { font:inherit; letter-spacing:.035em; }
button { cursor:pointer; }
.shell { width:min(100%, 540px); min-height:100vh; margin:auto; background:var(--card); padding:20px 18px 38px; }
.brand { display:flex; align-items:center; gap:10px; font-size:18px; font-weight:700; color:var(--dark); padding-bottom:18px; border-bottom:1px solid var(--line); }
.brand-mark { width:34px; height:34px; border-radius:9px; background:var(--blue); color:white; display:grid; place-items:center; font-size:20px; }
.progress { margin:20px 0 26px; }
.progress-label { display:flex; justify-content:space-between; font-size:14px; color:var(--muted); font-weight:700; }
.bar { height:9px; border-radius:9px; background:#dce5ef; overflow:hidden; margin-top:7px; }
.progress-fill { display:block; height:100%; border-radius:9px; background:var(--blue); }
.progress-1 { width:16%; } .progress-2 { width:33%; } .progress-3 { width:50%; }
.progress-4 { width:66%; } .progress-5 { width:83%; } .progress-6 { width:100%; }
.card { border:1px solid var(--line); border-radius:16px; padding:24px 20px; box-shadow:0 2px 10px #1720330b; }
.step-icon { width:48px; height:48px; border-radius:14px; display:grid; place-items:center; background:var(--soft); font-size:27px; margin-bottom:14px; }
h1 { font-size:27px; line-height:1.25; letter-spacing:.02em; margin:0 0 11px; }
h2 { font-size:20px; line-height:1.35; margin:21px 0 9px; }
p { margin:0 0 16px; }
.hint, details { color:var(--muted); font-size:15px; }
.example { background:#f5f8fc; border-left:4px solid #79a8dd; padding:10px 12px; border-radius:4px; font-size:15px; margin:14px 0 19px; }
label { display:block; font-weight:700; margin:17px 0 6px; }
input { width:100%; border:2px solid #9eacbd; border-radius:10px; padding:13px; min-height:51px; color:var(--ink); background:#fff; }
input:focus { outline:3px solid #8bbdf3; outline-offset:2px; border-color:var(--blue); }
.code-input { font-size:23px; font-weight:700; letter-spacing:.19em; text-align:center; }
.primary { width:100%; min-height:54px; border:0; border-radius:10px; background:var(--blue); color:#fff; font-weight:700; margin-top:23px; }
.primary:hover,.primary:focus { background:var(--dark); }
.secondary { border:0; background:none; color:var(--blue); text-decoration:underline; font-weight:700; padding:10px 1px; margin-top:9px; }
.notice { padding:12px 13px; border-radius:10px; margin:0 0 17px; font-size:15px; }
.notice.good { background:#e8f7ef; color:#075d36; border:1px solid #98d7b4; }
.notice.bad { background:#fff0ef; color:#8b1d16; border:1px solid #efb7b2; }
.secret { display:flex; gap:8px; align-items:center; background:#f5f8fc; border:1px solid var(--line); border-radius:10px; padding:10px; }
.secret code { flex:1; overflow-wrap:anywhere; font-size:14px; letter-spacing:.07em; }
.copy { border:1px solid var(--blue); border-radius:8px; color:var(--blue); background:#fff; padding:7px 9px; font-weight:700; white-space:nowrap; }
.qr-wrap { text-align:center; margin:18px 0; }
canvas { width:220px; height:220px; image-rendering:pixelated; border:9px solid white; outline:1px solid var(--line); border-radius:4px; }
.codes { list-style:none; padding:0; display:grid; gap:8px; }
.codes li { display:flex; align-items:center; justify-content:space-between; gap:8px; border:1px solid var(--line); border-radius:9px; padding:8px 9px; }
.codes code { font-size:18px; font-weight:700; letter-spacing:.09em; }
.logs { margin-top:22px; border-top:1px solid var(--line); padding-top:16px; }
.logs h2 { margin:0 0 5px; }
.logbox { background:#101b2d; color:#dff1ff; border-radius:10px; min-height:72px; max-height:190px; overflow:auto; padding:11px; font-family:ui-monospace, monospace; font-size:12px; line-height:1.55; letter-spacing:0; white-space:pre-wrap; }
footer { color:var(--muted); font-size:13px; margin-top:19px; text-align:center; }
[hidden] { display:none !important; }
@media (max-width:380px) { .shell { padding:15px 13px 28px; } .card { padding:20px 15px; } h1 { font-size:24px; } canvas { width:190px; height:190px; } }
</style>
</head>
<body>
<main class="shell">
<header class="brand"><span class="brand-mark" aria-hidden="true">✦</span><span>Northstar Bank</span></header>
<section class="progress" aria-label="Setup progress"><div class="progress-label"><span id="stepText">Getting started</span><span id="stepCount">Step 1 of 6</span></div><div class="bar"><span id="bar" class="progress-fill progress-1"></span></div></section>
<section id="app" aria-live="polite"><p>Loading your secure setup…</p></section>
<section class="logs" aria-label="Test delivery logs"><h2>Logs</h2><p class="hint">Test delivery details appear here and in your browser console.</p><div id="logs" class="logbox">Ready.</div></section>
<footer>Take your time. There is no reading timer.</footer>
</main>
<script nonce="${nonce}">
(() => {
  "use strict";
  const app = document.getElementById("app");
  const logs = document.getElementById("logs");
  const stepText = document.getElementById("stepText");
  const stepCount = document.getElementById("stepCount");
  const bar = document.getElementById("bar");
  let csrf = "";
  let state = { stage:"signed-in", email:"" };
  let setupSecret = "";
  let provisioningUri = "";
  let recoveryCodes = [];

  function testLog(message) {
    console.log(message);
    logs.textContent += "\\n" + message;
    logs.scrollTop = logs.scrollHeight;
  }

  function setNotice(text, bad) {
    const node = document.getElementById("notice");
    if (node) {
      node.textContent = text;
      node.className = "notice " + (bad ? "bad" : "good");
      node.hidden = false;
    }
  }

  async function request(path, method = "GET", body) {
    const options = { method, credentials:"same-origin", headers:{} };
    if (method !== "GET") {
      options.headers["Content-Type"] = "application/json";
      options.headers["X-CSRF-Token"] = csrf;
      options.body = JSON.stringify(body || {});
    }
    let response;
    try {
      response = await fetch(path, options);
    } catch {
      throw new Error("Cannot reach the secure service. Check that you opened the HTTPS address.");
    }
    const data = await response.json().catch(() => ({ ok:false, error:"Please try again." }));
    if (!response.ok || !data.ok) throw new Error(data.error || "Please try again.");
    if (data.csrf) csrf = data.csrf;
    return data;
  }

  /* CSP-safe progress rendering: only predefined nonce-authorized CSS classes are used. */
  function progress(stage) {
    const map = {
      "signed-in":[1,"Sign in"], "identity":[2,"Identity check"], "setup":[3,"Authenticator setup"],
      "otp":[4,"Confirm code"], "recovery":[5,"Save recovery codes"], "complete":[6,"Finished"]
    };
    const item = map[stage] || map["signed-in"];
    stepText.textContent = item[1];
    stepCount.textContent = "Step " + item[0] + " of 6";
    bar.className = "progress-fill progress-" + item[0];
  }

  function bind(id, event, handler) {
    const el = document.getElementById(id);
    if (el) el.addEventListener(event, handler);
  }

  function copy(value, label) {
    navigator.clipboard?.writeText(value).then(
      () => setNotice(label + " copied.", false),
      () => setNotice("Select the text and copy it using your browser.", true)
    );
  }

  /*
    Standards-compliant QR Code Model 2 encoder:
    Version 10, error correction level L, byte mode, mask 0.
    This capacity safely holds the complete otpauth:// URI. The generated canvas is
    scannable by normal authenticator applications and includes QR-required metadata.
  */
  function drawQr(text) {
    const canvas = document.getElementById("qr");
    if (!canvas || !text) return;
    const size = 57;
    const dataCodewords = 274;
    const eccPerBlock = 18;
    const blocks = 4;
    const bytes = Array.from(new TextEncoder().encode(text));
    if (bytes.length > 255 || bytes.length + 2 > dataCodewords) return;

    const bits = [];
    const putBits = (value, count) => {
      for (let i = count - 1; i >= 0; i--) bits.push((value >>> i) & 1);
    };
    putBits(4, 4);
    putBits(bytes.length, 8);
    bytes.forEach(byte => putBits(byte, 8));
    putBits(0, Math.min(4, dataCodewords * 8 - bits.length));
    while (bits.length % 8) bits.push(0);
    const data = [];
    for (let i = 0; i < bits.length; i += 8) {
      let value = 0;
      for (let j = 0; j < 8; j++) value = (value << 1) | bits[i + j];
      data.push(value);
    }
    let pad = 0;
    while (data.length < dataCodewords) data.push((pad++ % 2) ? 0x11 : 0xec);

    const gfMultiply = (a, b) => {
      let result = 0;
      while (b) {
        if (b & 1) result ^= a;
        a = (a << 1) ^ (a & 0x80 ? 0x11d : 0);
        b >>>= 1;
      }
      return result;
    };
    const generator = [1];
    let root = 1;
    for (let i = 0; i < eccPerBlock; i++) {
      generator.push(0);
      for (let j = generator.length - 1; j > 0; j--) generator[j] = generator[j - 1] ^ gfMultiply(generator[j], root);
      generator[0] = gfMultiply(generator[0], root);
      root = gfMultiply(root, 2);
    }
    const ecc = (block) => {
      const rem = Array(eccPerBlock).fill(0);
      for (const value of block) {
        const factor = value ^ rem.shift();
        rem.push(0);
        for (let i = 0; i < eccPerBlock; i++) rem[i] ^= gfMultiply(generator[i + 1], factor);
      }
      return rem;
    };
    const blockLength = dataCodewords / blocks;
    const dataBlocks = Array.from({length:blocks}, (_, i) => data.slice(i * blockLength, (i + 1) * blockLength));
    const eccBlocks = dataBlocks.map(ecc);
    const words = [];
    for (let i = 0; i < blockLength; i++) dataBlocks.forEach(block => words.push(block[i]));
    for (let i = 0; i < eccPerBlock; i++) eccBlocks.forEach(block => words.push(block[i]));
    const stream = [];
    words.forEach(word => putWord(stream, word));
    function putWord(target, word) {
      for (let bit = 7; bit >= 0; bit--) target.push((word >>> bit) & 1);
    }

    const matrix = Array.from({length:size}, () => Array(size).fill(null));
    const set = (x, y, value) => { if (x >= 0 && y >= 0 && x < size && y < size) matrix[y][x] = value; };
    const finder = (x, y) => {
      for (let dy = -1; dy <= 7; dy++) for (let dx = -1; dx <= 7; dx++) {
        const on = dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6 &&
          (dx === 0 || dx === 6 || dy === 0 || dy === 6 || (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4));
        set(x + dx, y + dy, on);
      }
    };
    finder(0, 0); finder(size - 7, 0); finder(0, size - 7);
    const alignment = (x, y) => {
      if (matrix[y][x] !== null) return;
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) {
        set(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    };
    [6, 28, 50].forEach(y => [6, 28, 50].forEach(x => alignment(x, y)));
    for (let i = 8; i < size - 8; i++) {
      if (matrix[6][i] === null) set(i, 6, i % 2 === 0);
      if (matrix[i][6] === null) set(6, i, i % 2 === 0);
    }

    const versionBits = 0x07c94;
    for (let i = 0; i < 18; i++) {
      const bit = ((versionBits >>> i) & 1) === 1;
      set(size - 11 + (i % 3), Math.floor(i / 3), bit);
      set(Math.floor(i / 3), size - 11 + (i % 3), bit);
    }

    const formatBits = 0x77c4;
    for (let i = 0; i < 15; i++) {
      const bit = ((formatBits >>> i) & 1) === 1;
      if (i < 6) set(8, i, bit);
      else if (i < 8) set(8, i + 1, bit);
      else set(8, size - 15 + i, bit);
      if (i < 8) set(size - i - 1, 8, bit);
      else if (i < 9) set(15 - i, 8, bit);
      else set(14 - i, 8, bit);
    }
    set(8, size - 8, true);

    let index = 0;
    let upward = true;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right--;
      for (let step = 0; step < size; step++) {
        const y = upward ? size - 1 - step : step;
        for (let dx = 0; dx < 2; dx++) {
          const x = right - dx;
          if (matrix[y][x] === null) {
            const raw = index < stream.length ? stream[index++] : 0;
            const masked = raw ^ (((y + x) % 2) === 0 ? 1 : 0);
            set(x, y, !!masked);
          }
        }
      }
      upward = !upward;
    }

    const scale = 5;
    canvas.width = canvas.height = size * scale;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#111111";
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
      if (matrix[y][x]) ctx.fillRect(x * scale, y * scale, scale, scale);
    }
  }

  function setupFrom(data, prefix) {
    setupSecret = data.secret;
    provisioningUri = data.provisioningUri;
    testLog(prefix + " secret: " + data.secret);
    testLog(prefix + " provisioning URI: " + data.provisioningUri);
    testLog("Mock authenticator OTP: " + data.testOtp);
  }

  function render(notice, bad) {
    progress(state.stage);
    const messages = notice ? '<div id="notice" class="notice ' + (bad ? "bad" : "good") + '">' + notice + '</div>' : '<div id="notice" hidden></div>';

    if (state.stage === "signed-in") {
      app.innerHTML = '<article class="card"><div class="step-icon" aria-hidden="true">🔐</div><h1>Sign in to start MFA setup</h1><p>Use the demo account to begin. We will guide you one step at a time.</p>' + messages + '<form id="signForm"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="username" inputmode="email" placeholder="marcus@example.com" required><div class="example">Example: marcus@example.com</div><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" placeholder="bank-demo" required><div class="example">Demo password: bank-demo</div><button class="primary" type="submit">Sign in</button></form><details><summary>Need help?</summary><p class="hint">This is a safe demo. Use the email and password shown above.</p></details></article>';
      bind("signForm", "submit", async (event) => {
        event.preventDefault();
        try {
          const data = await request("/api/sign-in","POST",{email:email.value,password:password.value});
          csrf = data.csrf;
          state.stage = data.stage;
          testLog("Mock identity check code: " + data.testIdentityCode);
          render(data.message,false);
        } catch(e) { setNotice(e.message,true); }
      });

    } else if (state.stage === "identity") {
      app.innerHTML = '<article class="card"><div class="step-icon" aria-hidden="true">🪪</div><h1>Check it is you</h1><p>Enter your phone number and the six-digit code we sent.</p>' + messages + '<form id="identityForm"><label for="phone">Phone number</label><input id="phone" type="tel" autocomplete="tel" inputmode="tel" placeholder="+1 555 010 0200" required><div class="example">Example: +1 555 010 0200</div><label for="identityCode">Six-digit check code</label><input id="identityCode" class="code-input" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="246810" required><button class="primary" type="submit">Check my identity</button></form><button id="resend" class="secondary" type="button">Send a new code</button><details><summary>Need help?</summary><p class="hint">You can retry when the lock is not active. The test code is shown in Logs.</p></details></article>';
      bind("identityForm","submit",async(e) => {
        e.preventDefault();
        try {
          const data = await request("/api/identity/verify","POST",{phone:phone.value,code:identityCode.value});
          state.stage = data.stage;
          render(data.message,false);
        } catch(err) { setNotice(err.message,true); }
      });
      bind("resend","click",async() => {
        try {
          const data = await request("/api/identity/resend","POST",{});
          testLog("Mock identity check code: " + data.testIdentityCode);
          setNotice(data.message,false);
        } catch(err) { setNotice(err.message,true); }
      });

    } else if (state.stage === "setup") {
      app.innerHTML = '<article class="card"><div class="step-icon" aria-hidden="true">📱</div><h1>Add your authenticator</h1><p>Use an authenticator app on this phone or another device. We will show a scannable QR code and copyable setup details.</p>' + messages + '<button id="makeSetup" class="primary" type="button">Show authenticator setup</button><details><summary>Need help?</summary><p class="hint">An authenticator app creates a new six-digit code. You can scan the code, copy the Base32 secret, or copy the full setup link.</p></details></article>';
      bind("makeSetup","click",async() => {
        try {
          const data = await request("/api/authenticator/setup","POST",{});
          state.stage = data.stage;
          setupFrom(data, "Mock authenticator");
          render(data.message,false);
        } catch(err) { setNotice(err.message,true); }
      });

    } else if (state.stage === "otp") {
      app.innerHTML = '<article class="card"><div class="step-icon" aria-hidden="true">▦</div><h1>Scan or copy the setup details</h1><p>In your authenticator app, scan this QR code. You can also copy the Base32 secret or the full setup link.</p>' + messages + '<div class="qr-wrap"><canvas id="qr" aria-label="Scannable QR code for authenticator setup" role="img"></canvas></div><label for="secretView">Manual Base32 secret</label><div class="secret"><code id="secretView"></code><button id="copySecret" class="copy" type="button">Copy</button></div><label for="uriView">Authenticator setup link</label><div class="secret"><code id="uriView"></code><button id="copyUri" class="copy" type="button">Copy</button></div><button id="refreshSetup" class="secondary" type="button">Get fresh setup details</button><form id="otpForm"><label for="otp">Six-digit authenticator code</label><input id="otp" class="code-input" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required><div class="example">Example: 123456</div><button class="primary" type="submit">Confirm authenticator</button></form><details><summary>Need help?</summary><p class="hint">The test code is in Logs. There is no rush. If the page was refreshed or a code expired, choose “Get fresh setup details”.</p></details></article>';
      document.getElementById("secretView").textContent = setupSecret || "Choose fresh setup details to show a new secret.";
      document.getElementById("uriView").textContent = provisioningUri || "Choose fresh setup details to show a new setup link.";
      drawQr(provisioningUri);
      bind("copySecret","click",() => copy(setupSecret,"Base32 secret"));
      bind("copyUri","click",() => copy(provisioningUri,"Authenticator setup link"));
      bind("refreshSetup","click",async() => {
        try {
          const data = await request("/api/authenticator/refresh","POST",{});
          setupFrom(data, "Fresh mock authenticator");
          render(data.message,false);
        } catch(err) { setNotice(err.message,true); }
      });
      bind("otpForm","submit",async(e) => {
        e.preventDefault();
        try {
          const data = await request("/api/otp/verify","POST",{code:otp.value});
          state.stage = data.stage;
          recoveryCodes = data.recoveryCodes;
          testLog("Mock recovery codes: " + recoveryCodes.join(", "));
          render(data.message,false);
        } catch(err) { setNotice(err.message,true); }
      });

    } else if (state.stage === "recovery") {
      const list = recoveryCodes.length
        ? recoveryCodes.map((code,i) => '<li><code>' + code + '</code><button class="copy codeCopy" type="button" data-index="' + i + '">Copy</button></li>').join("")
        : '<li><span>Codes are not shown after a page refresh.</span></li>';
      app.innerHTML = '<article class="card"><div class="step-icon" aria-hidden="true">🗝️</div><h1>Save your recovery codes</h1><p>Keep these codes somewhere safe. Each code works once if you cannot use your authenticator.</p>' + messages + '<ul class="codes" aria-label="Recovery codes">' + list + '</ul><button id="copyAll" class="secondary" type="button">Copy all codes</button><button id="newCodes" class="secondary" type="button">Make new codes</button><button id="finish" class="primary" type="button">I have saved my codes</button><details><summary>Need help?</summary><p class="hint">Copying avoids typing long codes. New codes replace the old set. Codes also appear in Logs for this demo.</p></details></article>';
      document.querySelectorAll(".codeCopy").forEach(button => button.addEventListener("click",() => copy(recoveryCodes[Number(button.dataset.index)],"Recovery code")));
      bind("copyAll","click",() => copy(recoveryCodes.join("\\n"),"Recovery codes"));
      bind("newCodes","click",async() => {
        try {
          const data = await request("/api/recovery/generate","POST",{});
          recoveryCodes = data.recoveryCodes;
          testLog("Mock replacement recovery codes: " + recoveryCodes.join(", "));
          render(data.message,false);
        } catch(err) { setNotice(err.message,true); }
      });
      bind("finish","click",async() => {
        try {
          const data = await request("/api/recovery/complete","POST",{});
          state.stage = data.stage;
          render(data.message,false);
        } catch(err) { setNotice(err.message,true); }
      });

    } else {
      app.innerHTML = '<article class="card"><div class="step-icon" aria-hidden="true">✓</div><h1>MFA is ready</h1><p>Your authenticator is connected and your recovery codes have been created.</p>' + messages + '<details><summary>Test a recovery code</summary><p class="hint">This marks one saved code as used. Format: ABCD-EFGH.</p><form id="recoveryForm"><label for="recoveryCode">Recovery code</label><input id="recoveryCode" type="text" autocomplete="one-time-code" placeholder="ABCD-EFGH" maxlength="9"><button class="secondary" type="submit">Check this recovery code</button></form></details><button id="logout" class="primary" type="button">Sign out safely</button><details><summary>Need help?</summary><p class="hint">You can sign in again whenever you need to manage MFA.</p></details></article>';
      bind("recoveryForm","submit",async(e) => {
        e.preventDefault();
        try {
          const data = await request("/api/recovery/verify","POST",{recoveryCode:recoveryCode.value});
          setNotice(data.message,false);
        } catch(err) { setNotice(err.message,true); }
      });
      bind("logout","click",async() => {
        try {
          const data = await request("/api/logout","POST",{});
          csrf = "";
          state.stage = "signed-in";
          setupSecret = "";
          provisioningUri = "";
          recoveryCodes = [];
          render(data.message,false);
        } catch(err) { setNotice(err.message,true); }
      });
    }
  }

  async function start() {
    try {
      const data = await request("/api/bootstrap");
      csrf = data.csrf;
      state.stage = data.authenticated ? data.stage : "signed-in";
      if (data.authenticated) {
        const current = await request("/api/state");
        state = current;
        csrf = current.csrf;
      }
      render();
    } catch {
      app.textContent = "We could not start secure setup. Please refresh the page.";
    }
  }
  start();
})();
</script>
</body>
</html>`;
}

const server = Bun.serve({
  port: 3000,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.method === "OPTIONS") {
        if (!trustedOrigin(request)) return safeError("This request is not allowed.", 403);
        const headers = baseHeaders();
        headers.set("Access-Control-Allow-Origin", url.origin);
        headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
        return new Response(null, { status: 204, headers });
      }
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = randomToken(18);
        const headers = baseHeaders(nonce);
        headers.set("Content-Type", "text/html; charset=utf-8");
        return new Response(htmlPage(nonce), { status: 200, headers });
      }
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      return safeError("That page is not available.", 404);
    } catch {
      return safeError("Something went wrong. Please try again.", 500);
    }
  },
});

console.log(`MFA demo HTTPS server running at https://localhost:${server.port}`);
