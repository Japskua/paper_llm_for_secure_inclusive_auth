
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const PORT = Number(Bun.env.PORT ?? 3000);

const users = new Map<string, User>();
const sessions = new Map<string, Session>();
const signInFailures = new Map<string, SignInFailure>();

const masterKeyBytes = crypto.getRandomValues(new Uint8Array(32));
const masterKey = await crypto.subtle.importKey("raw", masterKeyBytes, "AES-GCM", false, [
  "encrypt",
  "decrypt",
]);
const recoveryPepper = randomToken(32);
const signInTrackingPepper = randomToken(32);

// Deterministic mock account credentials; this demo has one configured account.
const MARCUS_EMAIL = "marcus@example.test";
const MARCUS_PHONE = "+1 555 123 4567";
const TRUSTED_RESET_PROOF = "MARCUS-TRUSTED-RESET";

const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const TOTP_STEP_MS = 30 * 1000;
const MFA_FAILURE_LIMIT = 5;
const MFA_LOCKOUT_MS = 15 * 60 * 1000;

// Requirement 5: rolling sign-in failures have a temporary privacy-preserving lockout.
const SIGNIN_WINDOW_MS = 15 * 60 * 1000;
const SIGNIN_FAILURE_LIMIT = 5;
const SIGNIN_LOCKOUT_MS = 15 * 60 * 1000;
const SIGNIN_FAILURE_MIN_DURATION_MS = 450;

const TRUSTED_ORIGINS = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

type EncryptedSecret = { iv: string; ciphertext: string };

type Session = {
  accountId: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
};

type SignInFailure = {
  timestamps: number[];
  lockedUntil: number;
};

type User = {
  id: string;
  email: string;
  mfaActive: boolean;
  encryptedSecret?: EncryptedSecret;
  recoveryHashes: string[];
  verification?: { used: boolean; verified: boolean };
  mfaVerificationFailures: number;
  mfaVerificationLockedUntil: number;
  recoveryFailures: number;
  recoveryLocked: boolean;
};

users.set("acct_marcus", {
  id: "acct_marcus",
  email: MARCUS_EMAIL,
  mfaActive: false,
  recoveryHashes: [],
  mfaVerificationFailures: 0,
  mfaVerificationLockedUntil: 0,
  recoveryFailures: 0,
  recoveryLocked: false,
});

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function randomBase32(length: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function fromB64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

function base32Bytes(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const character of value) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("invalid base32");
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return new Uint8Array(bytes);
}

function secureEqual(a: string, b: string): boolean {
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);
  let difference = aa.length ^ bb.length;
  const max = Math.max(aa.length, bb.length);
  for (let index = 0; index < max; index++) difference |= (aa[index] ?? 0) ^ (bb[index] ?? 0);
  return difference === 0;
}

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

function normalizePhone(value: string): string {
  return value.trim().replace(/[ ()-]/g, "");
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(value);
}

function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+?[0-9 ()-]{7,22}$/.test(value);
}

function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}

function validRecoveryCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-9]{12}$/.test(value);
}

function baseHeaders(nonce = randomToken(16)): Headers {
  const headers = new Headers();
  headers.set(
    "Content-Security-Policy",
    `default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'`,
  );
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  headers.set("Cache-Control", "no-store");
  return headers;
}

function json(body: unknown, status = 200, headers = baseHeaders()): Response {
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}

function genericError(status = 400, headers = baseHeaders()): Response {
  return json({ ok: false, error: "Unable to process this request." }, status, headers);
}

function applyCors(request: Request, headers: Headers): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  let requestOrigin = "";
  try {
    requestOrigin = new URL(request.url).origin;
  } catch {
    return false;
  }
  if (origin !== requestOrigin && !TRUSTED_ORIGINS.has(origin)) return false;
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Vary", "Origin");
  headers.set("Access-Control-Allow-Credentials", "true");
  headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  return true;
}

function cookieValue(request: Request, name: string): string | undefined {
  const cookies = request.headers.get("cookie") ?? "";
  for (const part of cookies.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return undefined;
}

function sessionCookie(token: string): string {
  return `mfa_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}

function clearSessionCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

async function bodyObject(request: Request): Promise<Record<string, unknown> | null> {
  if (!request.headers.get("content-type")?.includes("application/json")) return null;
  try {
    const value = await request.json();
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const object = value as Record<string, unknown>;
    if (["id", "uid", "userId", "accountId"].some((key) => key in object)) return null;
    return object;
  } catch {
    return null;
  }
}

// Requirements 1 and 5: identity comes exclusively from an opaque server session.
function authorize(request: Request): { session: Session; user: User; token: string } | null {
  const url = new URL(request.url);
  if (["id", "uid", "userId", "accountId"].some((key) => url.searchParams.has(key))) return null;

  const token = cookieValue(request, "mfa_session");
  if (!token) return null;
  const session = sessions.get(token);
  const now = Date.now();
  if (!session || now > session.expiresAt || now - session.lastSeenAt > SESSION_IDLE_MS) {
    sessions.delete(token);
    return null;
  }
  const user = users.get(session.accountId);
  if (!user) return null;
  session.lastSeenAt = now;
  return { session, user, token };
}

function csrfValid(request: Request, session: Session): boolean {
  const token = request.headers.get("x-csrf-token") ?? "";
  return /^[A-Za-z0-9_-]{32,128}$/.test(token) && secureEqual(token, session.csrf);
}

// Requirement 3: AES-GCM protects the provisioned shared secret at rest in demo memory.
async function encryptSecret(secret: string): Promise<EncryptedSecret> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(secret));
  return { iv: b64(iv), ciphertext: b64(new Uint8Array(ciphertext)) };
}

async function decryptSecret(stored: EncryptedSecret): Promise<string> {
  const value = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(stored.iv) },
    masterKey,
    fromB64(stored.ciphertext),
  );
  return decoder.decode(value);
}

async function totpForSecret(secret: string, now = Date.now()): Promise<string> {
  const counter = Math.floor(now / TOTP_STEP_MS);
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes));
  const offset = signed[signed.length - 1] & 15;
  const number = ((signed[offset] & 127) << 24) | (signed[offset + 1] << 16) | (signed[offset + 2] << 8) | signed[offset + 3];
  return String((number >>> 0) % 1_000_000).padStart(6, "0");
}

async function hashRecoveryCode(code: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(`${recoveryPepper}:${code}`));
  return b64(new Uint8Array(digest));
}

function createRecoveryCodes(): string[] {
  return Array.from({ length: 10 }, () => randomBase32(12));
}

function locked(user: User): boolean {
  return user.mfaVerificationLockedUntil > Date.now();
}

// Requirement 5: only a keyed digest is retained, never a submitted email, phone, IP, or UA.
async function signInTrackingKey(request: Request, email: string, phone: string): Promise<string> {
  const context = (request.headers.get("user-agent") ?? "").slice(0, 256);
  const material = `${signInTrackingPepper}\u0000${normalizeEmail(email)}\u0000${normalizePhone(phone)}\u0000${context}`;
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(material));
  return b64(new Uint8Array(digest));
}

function signInLockoutActive(key: string, now: number): boolean {
  const record = signInFailures.get(key);
  if (!record) return false;
  record.timestamps = record.timestamps.filter((time) => now - time < SIGNIN_WINDOW_MS);
  if (record.lockedUntil > now) return true;
  if (record.lockedUntil && record.lockedUntil <= now) record.lockedUntil = 0;
  if (!record.timestamps.length && !record.lockedUntil) signInFailures.delete(key);
  return false;
}

function recordSignInFailure(key: string, now: number): void {
  const record = signInFailures.get(key) ?? { timestamps: [], lockedUntil: 0 };
  record.timestamps = record.timestamps.filter((time) => now - time < SIGNIN_WINDOW_MS);
  record.timestamps.push(now);
  if (record.timestamps.length >= SIGNIN_FAILURE_LIMIT) record.lockedUntil = now + SIGNIN_LOCKOUT_MS;
  signInFailures.set(key, record);
}

async function minimumFailureDuration(startedAt: number): Promise<void> {
  const remaining = SIGNIN_FAILURE_MIN_DURATION_MS - (Date.now() - startedAt);
  if (remaining > 0) await Bun.sleep(remaining);
}

async function signInFailure(startedAt: number, headers: Headers): Promise<Response> {
  await minimumFailureDuration(startedAt);
  // Same status and body for malformed credentials, invalid credentials, and active lockouts.
  return genericError(401, headers);
}

async function api(request: Request): Promise<Response> {
  const headers = baseHeaders();
  if (!applyCors(request, headers)) return genericError(403, headers);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });

  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/api/auth/signin" && request.method === "POST") {
    const startedAt = Date.now();
    const body = await bodyObject(request);

    // Requirement 5: comparisons execute unconditionally before their results are combined.
    const submittedEmail = typeof body?.email === "string" ? body.email : "";
    const submittedPhone = typeof body?.phone === "string" ? body.phone : "";
    const emailMatches = secureEqual(normalizeEmail(submittedEmail), normalizeEmail(MARCUS_EMAIL));
    const phoneMatches = secureEqual(normalizePhone(submittedPhone), normalizePhone(MARCUS_PHONE));
    const inputValid = validEmail(body?.email) && validPhone(body?.phone);
    const credentialsMatch = Boolean(Number(inputValid) & Number(emailMatches) & Number(phoneMatches));

    const trackingKey = await signInTrackingKey(request, submittedEmail, submittedPhone);
    const currentlyLocked = signInLockoutActive(trackingKey, Date.now());

    // A lockout gives exactly the same generic, minimum-duration response and creates no session.
    if (currentlyLocked || !credentialsMatch) {
      if (!currentlyLocked) recordSignInFailure(trackingKey, Date.now());
      return await signInFailure(startedAt, headers);
    }

    // Requirement 5: tracking is reset only after successful authentication.
    signInFailures.delete(trackingKey);

    const oldToken = cookieValue(request, "mfa_session");
    if (oldToken) sessions.delete(oldToken);

    // Requirement 5: rotate session ID on successful authentication.
    const token = randomToken(32);
    const now = Date.now();
    const user = users.get("acct_marcus")!;
    const session: Session = {
      accountId: user.id,
      csrf: randomToken(32),
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + SESSION_ABSOLUTE_MS,
    };
    sessions.set(token, session);
    headers.set("Set-Cookie", sessionCookie(token));
    return json({ ok: true, csrf: session.csrf, active: user.mfaActive, view: user.mfaActive ? "recovery" : "enrol" }, 200, headers);
  }

  if (path === "/api/session" && request.method === "GET") {
    const auth = authorize(request);
    if (!auth) return genericError(401, headers);
    return json({ ok: true, csrf: auth.session.csrf, active: auth.user.mfaActive, view: auth.user.mfaActive ? "recovery" : "enrol" }, 200, headers);
  }

  const auth = authorize(request);
  if (!auth) return genericError(401, headers);

  if (path === "/api/logout" && request.method === "POST") {
    if (!csrfValid(request, auth.session)) return genericError(403, headers);
    sessions.delete(auth.token);
    headers.set("Set-Cookie", clearSessionCookie());
    return json({ ok: true }, 200, headers);
  }

  if (path === "/api/mfa/trusted-reset" && request.method === "POST") {
    const body = await bodyObject(request);
    if (!body || !csrfValid(request, auth.session) || typeof body.proof !== "string" || !secureEqual(body.proof, TRUSTED_RESET_PROOF)) return genericError(403, headers);
    auth.user.mfaVerificationFailures = 0;
    auth.user.mfaVerificationLockedUntil = 0;
    auth.user.verification = undefined;
    auth.user.encryptedSecret = undefined;
    auth.user.mfaActive = false;
    auth.user.recoveryHashes = [];
    auth.user.recoveryFailures = 0;
    auth.user.recoveryLocked = false;
    return json({ ok: true, view: "enrol" }, 200, headers);
  }

  if (path === "/api/mfa/provision" && request.method === "POST") {
    const body = await bodyObject(request);
    if (!body || !csrfValid(request, auth.session) || locked(auth.user)) return genericError(403, headers);
    const secret = randomBase32(32);
    auth.user.encryptedSecret = await encryptSecret(secret);
    auth.user.verification = { used: false, verified: false };
    const testOtp = await totpForSecret(secret);
    const expiresInSeconds = Math.max(1, Math.ceil((TOTP_STEP_MS - (Date.now() % TOTP_STEP_MS)) / 1000));
    return json({ ok: true, secret, testOtp, expiresInSeconds }, 200, headers);
  }

  if (path === "/api/mfa/verify" && request.method === "POST") {
    const body = await bodyObject(request);
    if (!body || !csrfValid(request, auth.session) || !validOtp(body.otp)) return genericError(400, headers);
    const verification = auth.user.verification;
    if (!verification || verification.used || locked(auth.user)) return genericError(403, headers);
    try {
      if (!auth.user.encryptedSecret) throw new Error("missing");
      const expected = await totpForSecret(await decryptSecret(auth.user.encryptedSecret));
      if (!secureEqual(body.otp, expected)) {
        auth.user.mfaVerificationFailures++;
        if (auth.user.mfaVerificationFailures >= MFA_FAILURE_LIMIT) auth.user.mfaVerificationLockedUntil = Date.now() + MFA_LOCKOUT_MS;
        return genericError(403, headers);
      }
    } catch {
      return genericError(400, headers);
    }
    verification.used = true;
    verification.verified = true;
    auth.user.mfaVerificationFailures = 0;
    return json({ ok: true }, 200, headers);
  }

  if (path === "/api/mfa/enable" && request.method === "POST") {
    const body = await bodyObject(request);
    if (!body || !csrfValid(request, auth.session) || !auth.user.verification?.verified || !auth.user.encryptedSecret || locked(auth.user)) return genericError(403, headers);
    const codes = createRecoveryCodes();
    auth.user.recoveryHashes = await Promise.all(codes.map(hashRecoveryCode));
    auth.user.recoveryFailures = 0;
    auth.user.recoveryLocked = false;
    auth.user.mfaActive = true;
    delete auth.user.verification;
    return json({ ok: true, codes }, 200, headers);
  }

  if (path === "/api/mfa/recovery/regenerate" && request.method === "POST") {
    const body = await bodyObject(request);
    if (!body || !csrfValid(request, auth.session) || !auth.user.mfaActive) return genericError(403, headers);
    const codes = createRecoveryCodes();
    auth.user.recoveryHashes = await Promise.all(codes.map(hashRecoveryCode));
    auth.user.recoveryFailures = 0;
    auth.user.recoveryLocked = false;
    return json({ ok: true, codes }, 200, headers);
  }

  if (path === "/api/mfa/recovery/verify" && request.method === "POST") {
    const body = await bodyObject(request);
    if (!body || !csrfValid(request, auth.session) || !validRecoveryCode(body.code) || !auth.user.mfaActive) return genericError(400, headers);
    if (auth.user.recoveryLocked) return genericError(403, headers);
    const hash = await hashRecoveryCode(body.code);
    const index = auth.user.recoveryHashes.findIndex((stored) => secureEqual(stored, hash));
    if (index < 0) {
      auth.user.recoveryFailures++;
      if (auth.user.recoveryFailures >= 5) auth.user.recoveryLocked = true;
      return genericError(403, headers);
    }
    auth.user.recoveryHashes.splice(index, 1);
    auth.user.recoveryFailures = 0;
    return json({ ok: true, remaining: auth.user.recoveryHashes.length }, 200, headers);
  }

  return genericError(404, headers);
}

function page(nonce: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank — MFA enrolment</title>
<style nonce="${nonce}">
:root{--navy:#102a43;--blue:#1261a6;--line:#cbd5df;--bad:#a61b1b;--ok:#116b43}*{box-sizing:border-box}body{margin:0;background:#f2f5f8;color:#17212b;font:16px/1.45 system-ui,sans-serif}header{background:var(--navy);color:#fff;padding:1rem max(1rem,calc((100% - 620px)/2))}header p{margin:.1rem 0;color:#d7e8f8}h1{font-size:1.2rem;margin:0}h2{font-size:1.35rem;margin:.2rem 0 .8rem}main{width:min(100%,620px);margin:auto;padding:1rem}section,aside{background:#fff;border:1px solid var(--line);border-radius:12px;padding:1.1rem;margin-bottom:1rem}label{display:block;font-weight:700;margin:.8rem 0 .25rem}input{width:100%;padding:.8rem;border:1px solid #8b9bab;border-radius:7px;font:inherit}button{width:100%;margin-top:1rem;padding:.78rem;border:0;border-radius:7px;background:var(--blue);color:#fff;font:inherit;font-weight:700}.secondary{background:#e5edf4;color:#18324a}.notice{min-height:1.4rem;color:var(--bad);font-weight:700}.success{color:var(--ok)}.muted{color:#526374;font-size:.92rem}.code{word-break:break-all;background:#edf6ff;padding:.75rem;border-radius:7px;font:700 1rem ui-monospace,monospace}.logs{max-height:190px;overflow:auto;background:#0d1c29;color:#d9efff;padding:.7rem;border-radius:7px;white-space:pre-wrap;font:12px ui-monospace,monospace}ul{columns:2;padding-left:1.3rem;font-family:ui-monospace,monospace}@media(max-width:380px){ul{columns:1}main{padding:.7rem}}
</style></head><body>
<header><h1>Northstar Bank</h1><p>Secure MFA enrolment</p></header><main><div id="app" aria-live="polite">Loading secure session…</div><aside><h2>Logs</h2><p class="muted">Simulated provisioning values appear here for academic testing.</p><div id="logs" class="logs">Ready.</div></aside></main>
<script nonce="${nonce}">
(()=>{"use strict";let csrf="",screen="signin",codes=[],secret="";const app=document.getElementById("app"),logs=document.getElementById("logs");
function audit(t){console.log(t);const d=document.createElement("div");d.textContent=t;logs.appendChild(d);logs.scrollTop=logs.scrollHeight}
function msg(t,ok){const e=document.getElementById("notice");if(e){e.textContent=t||"";e.className=ok?"notice success":"notice"}}
async function call(path,data){const o={method:data===undefined?"GET":"POST",headers:{}};if(data!==undefined){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(data)}try{const r=await fetch(path,o),v=await r.json();if(!r.ok||!v.ok)throw 0;return v}catch(e){msg("We could not complete that request. Please try again.");throw e}}
function render(){if(screen==="signin"){app.innerHTML='<section><h2>Sign in and verify identity</h2><p>Enter your registered details to begin MFA enrolment.</p><form id="f"><label>Email address<input id="email" type="email" value="marcus@example.test" required></label><label>Mobile number<input id="phone" type="tel" value="+1 555 123 4567" required></label><p id="notice" class="notice"></p><button>Verify and continue</button></form></section>';document.getElementById("f").onsubmit=signin}
else if(screen==="enrol"){app.innerHTML='<section><h2>Set up your authenticator</h2><p>Use an authenticator app for payment approvals.</p><p id="notice" class="notice"></p><button id="go">Set up authenticator app</button><button id="out" class="secondary">Log out</button></section>';go.onclick=provision;out.onclick=logout}
else if(screen==="provision"){app.innerHTML='<section><h2>Add this account to your app</h2><p>Choose manual entry and enter this setup secret:</p><div id="s" class="code"></div><p class="muted">The current simulated time-bound code is in Logs.</p><form id="f"><label>Six-digit authenticator code<input id="otp" inputmode="numeric" maxlength="6" required></label><p id="notice" class="notice"></p><button>Confirm code</button></form><button id="out" class="secondary">Log out</button></section>';s.textContent=secret;f.onsubmit=verify;out.onclick=logout}
else if(screen==="confirm"){app.innerHTML='<section><h2>Code confirmed</h2><p class="success">Your authenticator is verified.</p><p id="notice" class="notice"></p><button id="enable">Activate MFA and show recovery codes</button><button id="out" class="secondary">Log out</button></section>';enable.onclick=activate;out.onclick=logout}
else{app.innerHTML='<section><h2>MFA is active</h2><p class="success">Your authenticator is ready.</p><h3>Recovery codes</h3><ul id="list"></ul><p id="notice" class="notice"></p><button id="regen">Regenerate recovery codes</button><button id="out" class="secondary">Log out</button></section><section><h2>Test a recovery code</h2><form id="f"><label>Recovery code<input id="rc" maxlength="12"></label><button>Verify recovery code</button></form></section>';codes.forEach(x=>{const i=document.createElement("li");i.textContent=x;list.appendChild(i)});regen.onclick=regenerate;out.onclick=logout;f.onsubmit=recovery}}
async function signin(e){e.preventDefault();try{const r=await fetch("/api/auth/signin",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:email.value.trim(),phone:phone.value.trim()})}),d=await r.json();if(!r.ok||!d.ok)throw 0;csrf=d.csrf;screen=d.view;audit("Simulated configured-identity verification completed in browser.");render()}catch{msg("Unable to sign in. Check your details and try again.")}}
async function provision(){try{const d=await call("/api/mfa/provision",{});secret=d.secret;audit("Simulated authenticator provisioning — manual secret: "+d.secret);audit("Simulated current TOTP-style verification OTP: "+d.testOtp+" (expires in "+d.expiresInSeconds+" seconds)");screen="provision";render()}catch{}}
async function verify(e){e.preventDefault();try{await call("/api/mfa/verify",{otp:otp.value.trim()});screen="confirm";render()}catch{}}
async function activate(){try{const d=await call("/api/mfa/enable",{});codes=d.codes;audit("Simulated recovery codes generated: "+d.codes.join(", "));screen="recovery";render()}catch{}}
async function regenerate(){try{const d=await call("/api/mfa/recovery/regenerate",{});codes=d.codes;audit("Simulated replacement recovery codes generated: "+d.codes.join(", "));render();msg("Recovery codes have been replaced.",true)}catch{}}
async function recovery(e){e.preventDefault();try{const d=await call("/api/mfa/recovery/verify",{code:rc.value.trim().toUpperCase()});msg("Recovery code accepted and consumed. "+d.remaining+" remain.",true)}catch{}}
async function logout(){try{await call("/api/logout",{})}catch{}csrf="";codes=[];secret="";audit("Session logged out and invalidated.");screen="signin";render()}
(async()=>{try{const d=await call("/api/session");csrf=d.csrf;screen=d.view}catch{}render()})()})();
</script></body></html>`;
}

const server = Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) return await api(request);
      if (request.method !== "GET" || url.pathname !== "/") return new Response("Not found", { status: 404, headers: baseHeaders() });
      const nonce = randomToken(16);
      const headers = baseHeaders(nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { headers });
    } catch {
      return new Response("Unable to process this request.", { status: 500, headers: baseHeaders() });
    }
  },
});

console.log(`MFA enrolment demo listening securely on https://localhost:${server.port}`);
