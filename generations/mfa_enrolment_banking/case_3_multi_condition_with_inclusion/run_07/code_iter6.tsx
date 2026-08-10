
/**
 * MFA Enrolment System
 * Single-file Bun HTTPS server and responsive vanilla-JS mobile SPA.
 * Run with: bun app.ts
 *
 * Academic mode is the default. Set MFA_PRODUCTION_MODE=true to suppress
 * simulated raw codes from API responses.
 */
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 10 * 60 * 1000;
const LOCKOUT_MS = 15 * 60 * 1000;
const RESEND_INTERVAL_MS = 60 * 1000;
const MAX_FAILURES = 5;
const TRUSTED_ORIGIN = "https://localhost:3000";
const ACADEMIC_MODE = Bun.env.MFA_PRODUCTION_MODE !== "true";

const TEST_SECRET = "JBSWY3DPEHPK3PXPX";
const TEST_IDENTITY_CODE = "123456";
const TEST_RECOVERY_CODES = [
  "DEMO0001-CODE0001", "DEMO0002-CODE0002", "DEMO0003-CODE0003", "DEMO0004-CODE0004",
  "DEMO0005-CODE0005", "DEMO0006-CODE0006", "DEMO0007-CODE0007", "DEMO0008-CODE0008",
];

const encryptionKey = await crypto.subtle.importKey(
  "raw", crypto.getRandomValues(new Uint8Array(32)),
  { name: "AES-GCM" }, false, ["encrypt", "decrypt"],
);

type Stage = "identity" | "setup" | "confirm" | "recovery" | "complete";
type Session = {
  id: string; owner: "marcus@example.com"; csrf: string;
  createdAt: number; lastSeen: number; stage: Stage;
};
type ExpiringCode = {
  hash: string; expiresAt: number; used: boolean; failures: number;
  lockedUntil: number; nextSendAt: number;
};
type Protection = { failures: number; lockedUntil: number };
type TotpProtection = Protection & { acceptedCounters: Set<number> };

const sessions = new Map<string, Session>();

const account = {
  email: "marcus@example.com" as const,
  password: "BankPass!42",
  identity: null as ExpiringCode | null,
  encryptedSecret: "",
  backupHashes: [] as string[],
  recovery: { failures: 0, lockedUntil: 0 } as Protection,
  totp: { failures: 0, lockedUntil: 0, acceptedCounters: new Set<number>() } as TotpProtection,
  signIn: { failures: 0, lockedUntil: 0 } as Protection,
  mfaEnabled: false,
};

function now() { return Date.now(); }
function bytes(length: number) { return crypto.getRandomValues(new Uint8Array(length)); }
function token(length = 32) { return Buffer.from(bytes(length)).toString("base64url"); }

function randomRecoveryCode() {
  const part = () => Buffer.from(bytes(4)).toString("hex").toUpperCase();
  return `${part()}-${part()}`;
}
function identityCode() {
  if (ACADEMIC_MODE) return TEST_IDENTITY_CODE;
  const value = new Uint32Array(1);
  crypto.getRandomValues(value);
  return String(value[0] % 1_000_000).padStart(6, "0");
}
function base32(value: Uint8Array) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let output = "", buffer = 0, bits = 0;
  for (const byte of value) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(buffer << (5 - bits)) & 31];
  return output;
}
function fromBase32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = value.toUpperCase().replace(/[\s=]/g, "");
  if (!/^[A-Z2-7]+$/.test(clean)) throw new Error("bad secret");
  let buffer = 0, bits = 0;
  const output: number[] = [];
  for (const char of clean) {
    buffer = (buffer << 5) | alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}
async function hash(value: string) {
  return Buffer.from(await crypto.subtle.digest("SHA-256", encoder.encode(value))).toString("base64url");
}
async function encrypt(value: string) {
  const iv = bytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, encoder.encode(value));
  return `${Buffer.from(iv).toString("base64url")}.${Buffer.from(ciphertext).toString("base64url")}`;
}
async function decrypt(value: string) {
  const [iv, ciphertext] = value.split(".");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(iv, "base64url") },
    encryptionKey, Buffer.from(ciphertext, "base64url"),
  );
  return decoder.decode(plain);
}

/* Security §3: RFC 6238 TOTP with HMAC-SHA-1 and 30-second steps. */
async function totpForCounter(secret: string, counter: number) {
  const key = await crypto.subtle.importKey(
    "raw", fromBase32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"],
  );
  const data = new Uint8Array(8);
  let count = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    data[i] = Number(count & 255n);
    count >>= 8n;
  }
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  const offset = digest[digest.length - 1] & 15;
  const number = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) | digest[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}
async function verifyTotp(code: string): Promise<"ok" | "invalid" | "locked"> {
  const state = account.totp;
  const current = now();
  if (state.lockedUntil > current) return "locked";
  if (!account.encryptedSecret) return "invalid";
  const secret = await decrypt(account.encryptedSecret);
  const center = Math.floor(current / 30_000);
  for (const counter of [center - 1, center, center + 1]) {
    if (code === await totpForCounter(secret, counter)) {
      if (state.acceptedCounters.has(counter)) return "invalid";
      state.acceptedCounters.add(counter);
      for (const used of state.acceptedCounters) if (used < center - 2) state.acceptedCounters.delete(used);
      state.failures = 0;
      return "ok";
    }
  }
  state.failures++;
  if (state.failures >= MAX_FAILURES) state.lockedUntil = current + LOCKOUT_MS;
  return state.lockedUntil > current ? "locked" : "invalid";
}

function cookieMap(request: Request) {
  const values: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const at = part.indexOf("=");
    if (at > 0) values[part.slice(0, at).trim()] = decodeURIComponent(part.slice(at + 1).trim());
  }
  return values;
}
function sessionCookie(id: string) {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}
function csrfCookie(value: string) {
  return `mfa_csrf=${encodeURIComponent(value)}; Path=/; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}
function clearCookies() {
  return [
    "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
    "mfa_csrf=; Path=/; Secure; SameSite=Strict; Max-Age=0",
  ];
}

/* Security §2: restrictive headers, TLS/HSTS and no permissive CORS. */
const baseHeaders = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};
function json(data: unknown, status = 200, cookies: string[] = []) {
  const headers = new Headers(baseHeaders);
  for (const item of cookies) headers.append("Set-Cookie", item);
  return new Response(JSON.stringify(data), { status, headers });
}
function page() {
  return new Response(HTML, { headers: { ...baseHeaders, "Content-Type": "text/html; charset=utf-8" } });
}
function genericError(status = 400) {
  return json({ ok: false, message: "We could not complete that step. Please try again." }, status);
}
function originAllowed(request: Request) {
  const origin = request.headers.get("origin");
  return !origin || origin === TRUSTED_ORIGIN;
}
async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  if (Number(request.headers.get("content-length") || "0") > 4000) return null;
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch { return null; }
}
function authenticated(request: Request): Session | null {
  const id = cookieMap(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  const current = now();
  if (!session || session.owner !== account.email ||
    current - session.lastSeen > SESSION_IDLE_MS ||
    current - session.createdAt > SESSION_ABSOLUTE_MS) {
    if (id) sessions.delete(id);
    return null;
  }
  session.lastSeen = current;
  return session;
}
function requireSession(request: Request): Session | Response {
  return authenticated(request) || json({ ok: false, message: "Please sign in again to continue." }, 401);
}
function csrf(request: Request, session: Session) {
  return originAllowed(request) && request.headers.get("x-csrf-token") === session.csrf;
}
function expectedStage(session: Session, allowed: Stage[]) {
  return allowed.includes(session.stage) ? null :
    json({ ok: false, message: "Please complete the current setup step first." }, 403);
}
function validEmail(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 120;
}
function validPassword(value: unknown): value is string {
  return typeof value === "string" && value.length >= 8 && value.length <= 128;
}
function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function validRecoveryCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z0-9]{8}-[A-Z0-9]{8}$/.test(value);
}
function codeStatus(item: ExpiringCode | null): "ok" | "locked" | "invalid" | "pending" {
  const current = now();
  if (!item || item.used || item.expiresAt < current) return "invalid";
  return item.lockedUntil > current ? "locked" : "pending";
}
async function checkCode(item: ExpiringCode | null, code: string): Promise<"ok" | "locked" | "invalid"> {
  const status = codeStatus(item);
  if (status !== "pending" || !item) return status === "locked" ? "locked" : "invalid";
  if (await hash(code) === item.hash) {
    item.used = true;
    return "ok";
  }
  item.failures++;
  if (item.failures >= MAX_FAILURES) item.lockedUntil = now() + LOCKOUT_MS;
  return item.lockedUntil > now() ? "locked" : "invalid";
}

/* Security §1/§4: no endpoint accepts user IDs; every state change needs owner session and CSRF. */
async function api(request: Request, pathname: string): Promise<Response> {
  if (!originAllowed(request)) return json({ ok: false, message: "This request is not allowed." }, 403);

  if (pathname === "/api/signin" && request.method === "POST") {
    const body = await readBody(request);
    const suppliedCsrf = cookieMap(request).mfa_csrf;
    const genericCredentials = () => json({
      ok: false, message: "Check your email and password, then try again.",
    }, 401);

    if (!body || !suppliedCsrf || request.headers.get("x-csrf-token") !== suppliedCsrf ||
      !validEmail(body.email) || !validPassword(body.password)) return genericCredentials();

    if (account.signIn.lockedUntil > now()) return genericCredentials();

    if (body.email !== account.email || body.password !== account.password) {
      account.signIn.failures++;
      if (account.signIn.failures >= MAX_FAILURES) account.signIn.lockedUntil = now() + LOCKOUT_MS;
      return genericCredentials();
    }

    account.signIn.failures = 0;
    account.signIn.lockedUntil = 0;
    const id = token(32);
    const freshCsrf = token(24);
    const stage: Stage = account.mfaEnabled ? "complete" : "identity";
    sessions.set(id, {
      id, owner: account.email, csrf: freshCsrf,
      createdAt: now(), lastSeen: now(), stage,
    });
    return json({
      ok: true, stage, csrf: freshCsrf, academicMode: ACADEMIC_MODE,
      message: stage === "complete" ? "Signed in." : "Signed in. Next, verify your identity.",
    }, 200, [sessionCookie(id), csrfCookie(freshCsrf)]);
  }

  if (pathname === "/api/me" && request.method === "GET") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    const identity = account.identity;
    return json({
      ok: true, stage: session.stage, csrf: session.csrf, academicMode: ACADEMIC_MODE,
      identitySent: !!identity && !identity.used && identity.expiresAt >= now(),
    });
  }

  if (pathname === "/api/identity/send" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session) || expectedStage(session, ["identity"])) return genericError(403);

    const previous = account.identity;
    if (previous?.lockedUntil && previous.lockedUntil > now()) {
      return json({ ok: false, message: "Identity checks are paused. Please wait, then try again." }, 429);
    }
    if (previous?.nextSendAt && previous.nextSendAt > now()) {
      return json({ ok: false, message: "Please wait a little before requesting another code." }, 429);
    }
    const code = identityCode();
    account.identity = {
      hash: await hash(code), expiresAt: now() + CODE_LIFETIME_MS, used: false,
      failures: previous?.failures || 0, lockedUntil: 0, nextSendAt: now() + RESEND_INTERVAL_MS,
    };
    return json({
      ok: true, ...(ACADEMIC_MODE ? { code } : {}),
      message: ACADEMIC_MODE
        ? "Your simulated identity code is ready. It was written to your browser console."
        : "A new identity code has been sent by the simulated secure delivery service.",
    });
  }

  if (pathname === "/api/identity/verify" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const stageError = expectedStage(session, ["identity"]);
    if (stageError) return stageError;
    const body = await readBody(request);
    if (!body || !validOtp(body.code)) {
      return json({ ok: false, message: "Enter the 6 digits, for example 123456." }, 400);
    }
    const result = await checkCode(account.identity, body.code);
    if (result === "locked") return json({ ok: false, message: "Too many tries. Please wait, then request a new code." }, 429);
    if (result !== "ok") return json({ ok: false, message: "That code did not match. Check all 6 digits or request another code." }, 400);
    session.stage = "setup";
    return json({ ok: true, message: "Identity checked. Next, set up your authenticator." });
  }

  if (pathname === "/api/authenticator/setup" && request.method === "GET") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    const stageError = expectedStage(session, ["setup"]);
    if (stageError) return stageError;
    if (!account.encryptedSecret) return json({ ok: true, provisioned: false });
    const secret = await decrypt(account.encryptedSecret);
    const uri = `otpauth://totp/Local%20Bank:marcus%40example.com?secret=${secret}&issuer=Local%20Bank&algorithm=SHA1&digits=6&period=30`;
    return json({ ok: true, provisioned: true, secret, uri });
  }

  if (pathname === "/api/authenticator/setup" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const stageError = expectedStage(session, ["setup"]);
    if (stageError) return stageError;
    if (!account.encryptedSecret) {
      account.encryptedSecret = await encrypt(ACADEMIC_MODE ? TEST_SECRET : base32(bytes(20)));
      account.totp = { failures: 0, lockedUntil: 0, acceptedCounters: new Set<number>() };
    }
    const secret = await decrypt(account.encryptedSecret);
    const uri = `otpauth://totp/Local%20Bank:marcus%40example.com?secret=${secret}&issuer=Local%20Bank&algorithm=SHA1&digits=6&period=30`;
    return json({ ok: true, provisioned: true, secret, uri, message: "Your authenticator setup key is ready." });
  }

  if (pathname === "/api/authenticator/confirm" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const stageError = expectedStage(session, ["setup", "confirm"]);
    if (stageError) return stageError;
    if (!account.encryptedSecret) return json({ ok: false, message: "Create a setup key first." }, 400);
    session.stage = "confirm";
    const testCode = ACADEMIC_MODE
      ? await totpForCounter(await decrypt(account.encryptedSecret), Math.floor(now() / 30_000))
      : undefined;
    return json({
      ok: true, ...(ACADEMIC_MODE ? { testCode } : {}),
      message: "Now enter the current code shown in the authenticator app you configured.",
    });
  }

  if (pathname === "/api/authenticator/verify" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const stageError = expectedStage(session, ["confirm"]);
    if (stageError) return stageError;
    const body = await readBody(request);
    if (!body || !validOtp(body.code)) return json({ ok: false, message: "Enter 6 digits, for example 123456." }, 400);
    const result = await verifyTotp(body.code);
    if (result === "locked") return json({ ok: false, message: "Too many tries. Please wait, then try a new code." }, 429);
    if (result !== "ok") return json({ ok: false, message: "That code did not match or was already used. Enter the current 6-digit code." }, 400);
    session.stage = "recovery";
    return json({ ok: true, message: "Authenticator confirmed. Next, save your recovery codes." });
  }

  if (pathname === "/api/recovery/create" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const stageError = expectedStage(session, ["recovery"]);
    if (stageError) return stageError;

    const codes = ACADEMIC_MODE ? [...TEST_RECOVERY_CODES] :
      Array.from({ length: 8 }, randomRecoveryCode);
    account.backupHashes = await Promise.all(codes.map(hash));
    account.recovery = { failures: 0, lockedUntil: 0 };
    return json({
      ok: true, codes,
      message: "Your recovery codes are ready. Save them somewhere private.",
    });
  }

  /* Task: authenticated CSRF-protected, owner-bound, single-use recovery redemption. */
  if (pathname === "/api/recovery/redeem" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const stageError = expectedStage(session, ["recovery", "complete"]);
    if (stageError) return stageError;

    const body = await readBody(request);
    const state = account.recovery;
    if (state.lockedUntil > now()) {
      return json({ ok: false, message: "Recovery code checks are paused. Please wait, then try again." }, 429);
    }

    let accepted = false;
    if (body && validRecoveryCode(body.code)) {
      const suppliedHash = await hash(body.code);
      const index = account.backupHashes.indexOf(suppliedHash);
      if (index >= 0) {
        /* Consume exactly once by deleting the matching stored hash. */
        account.backupHashes.splice(index, 1);
        state.failures = 0;
        accepted = true;
      }
    }
    if (accepted) return json({ ok: true, message: "Recovery code accepted. That code has now been used." });

    state.failures++;
    if (state.failures >= MAX_FAILURES) state.lockedUntil = now() + LOCKOUT_MS;
    if (state.lockedUntil > now()) {
      return json({ ok: false, message: "Recovery code checks are paused. Please wait, then try again." }, 429);
    }
    /* Generic response deliberately does not reveal whether a code existed or was used. */
    return json({ ok: false, message: "That recovery code is not available. Check the format and try another saved code." }, 400);
  }

  if (pathname === "/api/recovery/finish" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const stageError = expectedStage(session, ["recovery"]);
    if (stageError || account.backupHashes.length !== 8) return genericError(403);
    account.mfaEnabled = true;
    session.stage = "complete";
    return json({ ok: true, message: "MFA is now on." });
  }

  if (pathname === "/api/logout" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    sessions.delete(session.id);
    return json({ ok: true, message: "Signed out." }, 200, clearCookies());
  }

  return genericError(404);
}

const HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Bank · MFA setup</title>
<style>
:root{--ink:#14283d;--muted:#506477;--blue:#075bc7;--red:#a92319;--line:#c9d6e1;--bg:#f4f8fb}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.035em}
button,input{font:inherit;letter-spacing:inherit}button{cursor:pointer}.shell{width:min(100%,580px);min-height:100vh;margin:auto;padding:22px 20px 42px;background:#fff}
header{border-bottom:2px solid var(--line);padding-bottom:16px;margin-bottom:24px}.brand{font-weight:800;color:#063d82;font-size:1.15rem}.step,.small{color:var(--muted);font-size:.91rem}
h1{font-size:1.65rem;line-height:1.3;margin:0 0 14px}h2{font-size:1.1rem;margin:0 0 8px}p{margin:0 0 17px}.lead{font-size:1.05rem}
.card{border:1px solid var(--line);border-radius:12px;padding:18px;margin:18px 0}.hint{background:#f5faff;border-left:5px solid var(--blue);padding:13px 15px;border-radius:5px;color:#29445c;font-size:.94rem}
label{display:block;font-weight:700;margin:18px 0 6px}input{width:100%;padding:13px;border:2px solid #8499ac;border-radius:8px;background:#fff;color:var(--ink);font-size:1.1rem}
input:focus{outline:3px solid #80b8f6;outline-offset:2px;border-color:var(--blue)}.code-input{text-align:center;font-weight:bold;font-size:1.4rem;letter-spacing:.2em}
.primary{width:100%;border:0;border-radius:9px;padding:15px 16px;background:var(--blue);color:#fff;font-weight:800;margin-top:23px;min-height:56px}
.secondary,.text-btn{border:2px solid var(--blue);color:#064d9e;background:#fff;border-radius:8px;padding:10px 13px;font-weight:700}.text-btn{border:0;padding:4px;text-decoration:underline}
.buttons{display:grid;gap:10px;margin-top:13px}.message{padding:12px 14px;border-radius:8px;margin:16px 0;font-weight:700}.success{background:#e5f6ed;color:#075a36}.error{background:#fff0ef;color:var(--red)}
.progress{display:flex;gap:5px;margin:0 0 22px}.progress span{height:7px;flex:1;border-radius:9px;background:#d7e0e8}.progress .on{background:var(--blue)}
.secret{word-break:break-all;background:#f4f7f9;border:1px solid var(--line);padding:12px;border-radius:7px;font-family:monospace;letter-spacing:.07em;user-select:all}
.qr{display:grid;grid-template-columns:repeat(15,1fr);width:220px;height:220px;padding:10px;margin:15px auto;background:#fff;border:1px solid var(--ink)}.qr i{background:#111}.qr i:nth-child(3n),.qr i:nth-child(7n){background:#fff}
.codes{list-style:none;padding:0;margin:12px 0}.codes li{font-family:monospace;border-bottom:1px solid var(--line);padding:7px 3px;letter-spacing:.06em;user-select:all}
.logs{margin-top:32px;border-top:2px solid var(--line);padding-top:16px}.logs pre{white-space:pre-wrap;word-break:break-word;background:#0e2436;color:#dff5ff;border-radius:8px;padding:12px;font:12px/1.55 monospace;min-height:62px}
.hidden{display:none!important}.logout{color:#6b1a14}@media(max-width:370px){.shell{padding:17px 15px}body{font-size:16px}}
</style>
</head>
<body>
<main class="shell">
<header><div class="brand">🏦 Local Bank</div><div id="stepText" class="step">Secure account setup</div></header>
<section id="app" aria-live="polite"><p>Loading your secure setup…</p></section>
<section class="logs" aria-label="Simulation logs"><h2>🧾 Logs</h2><p class="small">Simulation messages appear here and in the browser console.</p><pre id="logs">Ready.</pre></section>
</main>
<script>
(()=>{
"use strict";
const app=document.getElementById("app"),stepText=document.getElementById("stepText"),logs=document.getElementById("logs");
let csrf="",academicMode=false,shownIdentity="",shownTotp="",recoveryCodes=[],identitySent=false;
const stages={signin:0,identity:1,setup:2,confirm:3,recovery:4,complete:5};

function log(text){console.log(text);logs.textContent+=(logs.textContent==="Ready."?"\\n":"\\n")+text}
function cookie(name){const p=document.cookie.split("; ").find(x=>x.startsWith(name+"="));return p?decodeURIComponent(p.slice(name.length+1)):""}
function el(tag,attrs={},text=""){const n=document.createElement(tag);for(const [k,v] of Object.entries(attrs)){if(k==="class")n.className=v;else if(k.startsWith("on"))n.addEventListener(k.slice(2),v);else n.setAttribute(k,v)}if(text)n.textContent=text;return n}
function clear(){app.replaceChildren()}
function setStep(name){const n=stages[name]||0;stepText.textContent=name==="signin"?"Step 1 of 5 · Sign in":"Step "+Math.min(n+1,5)+" of 5 · MFA enrolment"}
function msg(text,type="success"){return el("div",{class:"message "+type,role:"status"},text)}
function help(){return el("p",{class:"hint"},"💡 Need help? Take your time. You can safely retry any step.")}
function progress(n){const d=el("div",{class:"progress","aria-label":"Setup progress"});for(let i=1;i<=5;i++)d.append(el("span",{class:i<=n?"on":""}));return d}
async function api(path,method="GET",body){
 try{
  const r=await fetch(path,{method,credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:body?JSON.stringify(body):undefined});
  const d=await r.json();
  if(r.status===401){csrf="";renderSignin(d.message);return null}
  return d;
 }catch{return {ok:false,message:"Connection problem. Please try again."}}
}
function copy(text,label){
 const b=el("button",{class:"secondary",type:"button"},label);
 b.onclick=async()=>{try{await navigator.clipboard.writeText(text);b.textContent="Copied ✓";log("Clipboard copy completed.")}catch{b.textContent="Select text and copy it"}};
 return b;
}
function fakeQr(){
 const q=el("div",{class:"qr","aria-label":"QR-style setup image. You can use the copy option instead."});
 for(let i=0;i<225;i++)q.append(el("i"));
 return q;
}

function renderSignin(note=""){
 setStep("signin");clear();
 app.append(el("h1",{},"Sign in to start MFA setup"),el("p",{class:"lead"},"🔐 We will guide you through five short steps. There is no reading timer."));
 if(note)app.append(msg(note,note.includes("Signed")?"success":"error"));
 const form=el("form"),email=el("input",{type:"email",autocomplete:"username",inputmode:"email",placeholder:"name@example.com",required:""}),password=el("input",{type:"password",autocomplete:"current-password",placeholder:"Your password",required:""});
 form.append(el("label",{},"Email"),email,el("p",{class:"small"},"Example: name@example.com"),el("label",{},"Password"),password,el("button",{class:"primary",type:"submit"},"Sign in"));
 form.onsubmit=async e=>{e.preventDefault();csrf=cookie("mfa_csrf");const d=await api("/api/signin","POST",{email:email.value.trim(),password:password.value});if(!d)return;if(!d.ok){form.prepend(msg(d.message,"error"));return}csrf=d.csrf;academicMode=!!d.academicMode;log("Sign-in simulation completed.");d.stage==="complete"?renderComplete(d.message):renderIdentity(d.message)};
 app.append(form,help(),el("p",{class:"small"},"Demo sign-in: marcus@example.com · BankPass!42"));
}
function renderIdentity(note=""){
 setStep("identity");clear();app.append(progress(1),el("h1",{},"Verify it is you"),el("p",{class:"lead"},"📩 We will send one short code."));
 if(academicMode)app.append(msg("Academic simulation mode is enabled. Test values are written only to your browser console."));
 if(note)app.append(msg(note));
 const form=el("form"),input=el("input",{class:"code-input",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"123456",required:""});
 form.append(el("label",{},"Enter the 6-digit code"),input,el("p",{class:"small"},"Example: 123456"),el("button",{class:"primary",type:"submit"},"Check code"));
 form.onsubmit=async e=>{e.preventDefault();const d=await api("/api/identity/verify","POST",{code:input.value.replace(/\\s/g,"")});if(d&&d.ok){shownIdentity="";renderSetup(d.message)}else if(d)form.prepend(msg(d.message,"error"))};
 const send=el("button",{class:identitySent?"secondary":"primary",type:"button"},identitySent?"Send another code":"Send identity code");
 send.onclick=async()=>{const d=await api("/api/identity/send","POST",{});if(d&&d.ok){identitySent=true;shownIdentity=d.code||"";if(shownIdentity)log("ACADEMIC SIMULATION identity code: "+shownIdentity);renderIdentity(d.message)}else if(d)app.prepend(msg(d.message,"error"))};
 if(identitySent){app.append(form);const reveal=el("button",{class:"text-btn",type:"button"},"Reveal simulated code"),box=el("div",{class:"secret hidden"},shownIdentity);reveal.onclick=()=>box.classList.toggle("hidden");app.append(reveal,box,el("div",{class:"buttons"},send))}else app.append(send);
 app.append(help());
}
async function renderSetup(note=""){
 setStep("setup");clear();let d=await api("/api/authenticator/setup");if(!d||!d.ok){renderSignin(d&&d.message);return}if(!d.provisioned)d=await api("/api/authenticator/setup","POST",{});
 if(!d||!d.ok){app.append(msg((d&&d.message)||"Please try again.","error"));return}
 app.append(progress(2),el("h1",{},"Set up your authenticator"),el("p",{class:"lead"},"📱 Scan this QR option in your authenticator app. Or copy the setup key instead."));
 if(note)app.append(msg(note));
 const uri=el("div",{class:"secret hidden"},d.uri),show=el("button",{class:"text-btn",type:"button"},"Show provisioning link");show.onclick=()=>uri.classList.toggle("hidden");
 app.append(el("div",{class:"card"},el("h2",{},"QR code option"),fakeQr(),el("p",{class:"small"},"If scanning is difficult, use the setup key below.")),el("h2",{},"Setup key"),el("div",{class:"secret"},d.secret),el("div",{class:"buttons"},copy(d.secret,"Copy setup key"),show),uri);
 const next=el("button",{class:"primary",type:"button"},"I added it to my app");
 next.onclick=async()=>{const x=await api("/api/authenticator/confirm","POST",{});if(x&&x.ok){shownTotp=x.testCode||"";if(shownTotp)log("ACADEMIC SIMULATION authenticator code: "+shownTotp);renderConfirm(x.message)}else if(x)app.append(msg(x.message,"error"))};
 app.append(next,help());
}
function renderConfirm(note=""){
 setStep("confirm");clear();app.append(progress(3),el("h1",{},"Check your authenticator"),el("p",{class:"lead"},"🔢 Enter the current 6-digit code from your authenticator app."),el("p",{class:"small"},"Example: 123456. Take as long as you need."));
 if(note)app.append(msg(note));
 if(shownTotp){const reveal=el("button",{class:"text-btn",type:"button"},"Reveal test authenticator code"),box=el("div",{class:"secret hidden"},shownTotp);reveal.onclick=()=>box.classList.toggle("hidden");app.append(reveal,box)}
 const form=el("form"),input=el("input",{class:"code-input",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"123456",required:""});
 form.append(el("label",{},"Authenticator code"),input,el("button",{class:"primary",type:"submit"},"Confirm authenticator"));
 form.onsubmit=async e=>{e.preventDefault();const d=await api("/api/authenticator/verify","POST",{code:input.value.replace(/\\s/g,"")});if(d&&d.ok){shownTotp="";renderRecovery(d.message)}else if(d)form.prepend(msg(d.message,"error"))};
 app.append(form,help());
}
function recoveryTest(){
 const card=el("div",{class:"card"}),form=el("form"),input=el("input",{autocomplete:"one-time-code",placeholder:"DEMO0001-CODE0001",required:""});
 card.append(el("h2",{},"Test one recovery code"),el("p",{class:"small"},"This controlled test shows that a code can be accepted only once."),el("label",{},"Recovery code"),input,el("p",{class:"small"},"Example: DEMO0001-CODE0001"),form);
 form.append(el("button",{class:"secondary",type:"submit"},"Test recovery code"));
 form.onsubmit=async e=>{e.preventDefault();const d=await api("/api/recovery/redeem","POST",{code:input.value.trim().toUpperCase()});form.querySelectorAll(".message").forEach(x=>x.remove());form.prepend(msg(d.message,d.ok?"success":"error"));if(d.ok)log("Recovery-code redemption simulation accepted one code.");else log("Recovery-code redemption simulation was not accepted.")};
 return card;
}
function renderRecovery(note=""){
 setStep("recovery");clear();app.append(progress(4),el("h1",{},"Save recovery codes"),el("p",{class:"lead"},"🗝️ These help if you lose your phone. Keep them somewhere private."));
 if(note)app.append(msg(note));
 const create=async()=>{const d=await api("/api/recovery/create","POST",{});if(d&&d.ok){recoveryCodes=d.codes;log("ACADEMIC SIMULATION recovery codes: "+d.codes.join(", "));renderRecovery(d.message)}else if(d)app.append(msg(d.message,"error"))};
 if(!recoveryCodes.length){const b=el("button",{class:"primary",type:"button"},"Create recovery codes");b.onclick=create;app.append(b,help());return}
 const list=el("ul",{class:"codes","aria-label":"Recovery codes"});recoveryCodes.forEach(code=>list.append(el("li",{},code)));
 app.append(el("div",{class:"card"},el("h2",{},"Your eight codes"),list),el("div",{class:"buttons"},copy(recoveryCodes.join("\\n"),"Copy all codes")),recoveryTest());
 const finish=el("button",{class:"primary",type:"button"},"I saved my codes");
 finish.onclick=async()=>{const d=await api("/api/recovery/finish","POST",{});if(d&&d.ok){recoveryCodes=[];renderComplete(d.message)}else if(d)app.append(msg(d.message,"error"))};
 app.append(finish,help());
}
function renderComplete(note=""){
 setStep("complete");clear();app.append(progress(5),el("h1",{},"MFA is ready"),msg(note||"MFA is now on."),el("p",{class:"lead"},"✅ Your authenticator and recovery codes are set up."),el("p",{class:"hint"},"Keep recovery codes private. You can test a saved code below."));
 app.append(recoveryTest());
 const out=el("button",{class:"text-btn logout",type:"button"},"Sign out");
 out.onclick=async()=>{await api("/api/logout","POST",{});csrf="";shownIdentity="";shownTotp="";recoveryCodes=[];identitySent=false;renderSignin("You are signed out.")};
 app.append(out);
}
async function init(){
 csrf=cookie("mfa_csrf");
 if(!csrf){csrf=crypto.getRandomValues(new Uint32Array(4)).join("");document.cookie="mfa_csrf="+encodeURIComponent(csrf)+"; Path=/; Secure; SameSite=Strict"}
 const me=await api("/api/me");
 if(me&&me.ok){csrf=me.csrf;academicMode=!!me.academicMode;identitySent=!!me.identitySent;if(me.stage==="identity")renderIdentity();else if(me.stage==="setup")renderSetup();else if(me.stage==="confirm")renderConfirm();else if(me.stage==="recovery")renderRecovery();else renderComplete()}else renderSignin();
}
init();
})();
</script>
</body>
</html>`;

Bun.serve({
  port: 3000,
  hostname: "localhost",
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/" && request.method === "GET") return page();
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      return genericError(404);
    } catch {
      return genericError(500);
    }
  },
});
