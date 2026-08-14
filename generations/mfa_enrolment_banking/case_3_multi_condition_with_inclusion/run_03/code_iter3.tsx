
/*
  MFA Enrolment System
  Single-file Bun HTTPS server and accessible mobile SPA.
  Run with: bun app.ts
*/

const PORT = Number(Bun.env.PORT || 3000);
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_PERIOD_MS = 30_000;
const OTP_WINDOW_STEPS = 1;
const LOCKOUT_MS = 5 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const REISSUE_WINDOW_MS = 10 * 60 * 1000;
const MAX_REISSUES = 3;

const serverKey = crypto.getRandomValues(new Uint8Array(32));
const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();

type EncryptedValue = { iv: string; data: string };
type AttemptState = { failures: number; lockedUntil: number };

type Session = {
  id: string;
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
  identityVerified: boolean;
  enrolledSecret?: EncryptedValue;
  acceptedTotpSteps: Set<number>;
  otpAttempts: AttemptState;
  reissues: number[];
};

type Account = {
  userId: string;
  email: string;
  phone: string;
  passwordHash: string;
  mfaEnabled: boolean;
  secret?: EncryptedValue;
  recoveryHashes: Set<string>;
  recoveryReady: boolean;
  recoveryAttempts: AttemptState;
};

const demoAccounts = [{
  userId: "account-marcus-demo",
  email: "marcus@example.com",
  phone: "07123456789",
  password: "MarcusDemo!54",
}];

function randomToken(bytes = 32) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}
async function sha256(value: string) {
  return Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))).toString("base64url");
}
function normalizeEmail(value: string) { return value.trim().toLowerCase(); }
function normalizePhone(value: string) { return value.replace(/[^\d]/g, ""); }

function base32Secret(bytes = 20) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const values = crypto.getRandomValues(new Uint8Array(bytes));
  let bits = 0, count = 0, output = "";
  for (const value of values) {
    bits = (bits << 8) | value; count += 8;
    while (count >= 5) {
      output += alphabet[(bits >>> (count - 5)) & 31];
      count -= 5;
    }
  }
  if (count) output += alphabet[(bits << (5 - count)) & 31];
  return output;
}

/* Security Evaluation 3: AES-GCM encryption for the provisioned secret at rest. */
async function encryptValue(value: string): Promise<EncryptedValue> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", serverKey, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  return { iv: Buffer.from(iv).toString("base64url"), data: Buffer.from(encrypted).toString("base64url") };
}
async function decryptValue(value: EncryptedValue) {
  const key = await crypto.subtle.importKey("raw", serverKey, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(value.iv, "base64url") },
    key,
    Buffer.from(value.data, "base64url"),
  );
  return new TextDecoder().decode(plain);
}

/* RFC 6238 TOTP, SHA-1, 30 seconds, six digits. */
function decodeBase32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, count = 0;
  const bytes: number[] = [];
  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("Invalid setup key");
    bits = (bits << 5) | index; count += 5;
    if (count >= 8) {
      bytes.push((bits >>> (count - 8)) & 255);
      count -= 8;
    }
  }
  return new Uint8Array(bytes);
}
async function totp(secret: string, step: number) {
  const data = new Uint8Array(8);
  let counter = BigInt(step);
  for (let i = 7; i >= 0; i--) { data[i] = Number(counter & 255n); counter >>= 8n; }
  const key = await crypto.subtle.importKey("raw", decodeBase32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  const offset = digest[19] & 15;
  const value = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
function currentStep() { return Math.floor(Date.now() / OTP_PERIOD_MS); }
function otpExpiry(step: number) { return (step + 1) * OTP_PERIOD_MS; }

function securityHeaders(origin?: string | null, nonce = randomToken(18)) {
  const headers: Record<string, string> = {
    "Content-Security-Policy": `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  };
  if (origin) {
    try {
      const parsed = new URL(origin);
      if (parsed.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname)) {
        headers["Access-Control-Allow-Origin"] = origin;
        headers["Vary"] = "Origin";
      }
    } catch {}
  }
  return headers;
}
function json(data: unknown, status = 200, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...securityHeaders(), "Content-Type": "application/json; charset=utf-8", ...extra } });
}
function genericError(status = 400, message = "We could not complete that step. Please try again.") {
  return json({ ok: false, message }, status);
}
function cookieValue(request: Request, name: string) {
  const cookie = request.headers.get("cookie") || "";
  const item = cookie.split(";").map(part => part.trim()).find(part => part.startsWith(name + "="));
  return item ? decodeURIComponent(item.slice(name.length + 1)) : "";
}
function sessionCookie(id: string) {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}
function expired(session: Session) {
  const now = Date.now();
  return now - session.lastSeenAt > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS;
}
function protectedSession(request: Request): Session | null {
  const id = cookieValue(request, "mfa_session"), session = sessions.get(id);
  if (!session || expired(session)) { if (id) sessions.delete(id); return null; }
  session.lastSeenAt = Date.now();
  return session;
}
function trustedRequest(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try { const from = new URL(origin), to = new URL(request.url); return from.protocol === "https:" && from.origin === to.origin; }
  catch { return false; }
}
async function readBody(request: Request) {
  if (Number(request.headers.get("content-length") || "0") > 10_000) return null;
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch { return null; }
}
const validEmail = (v: unknown) => typeof v === "string" && v.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const validPhone = (v: unknown) => typeof v === "string" && /^[0-9 +()\-]{7,25}$/.test(v);
const validPassword = (v: unknown) => typeof v === "string" && v.length >= 8 && v.length <= 128;
const validOtp = (v: unknown) => typeof v === "string" && /^\d{6}$/.test(v);
const noSuppliedAccountId = (b: Record<string, unknown>) => !("userId" in b) && !("accountId" in b) && !("emailOwner" in b);
const validRecovery = (v: unknown) => typeof v === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(v);
function csrfOk(request: Request, session: Session, body: Record<string, unknown>) {
  return trustedRequest(request) && typeof body.csrf === "string" && body.csrf.length === session.csrf.length && body.csrf === session.csrf;
}
function requireProtected(request: Request, body: Record<string, unknown>): { session: Session; account: Account } | Response {
  const session = protectedSession(request);
  if (!session) return genericError(401, "Your secure session has ended. Please sign in again.");
  if (!noSuppliedAccountId(body) || !csrfOk(request, session, body)) return genericError(403, "Please refresh the page and try again.");
  const account = accounts.get(session.userId);
  return account ? { session, account } : genericError(401, "Your secure session has ended. Please sign in again.");
}
function isLocked(state: AttemptState) { return state.lockedUntil > Date.now(); }
function failedAttempt(state: AttemptState) { state.failures++; if (state.failures >= MAX_ATTEMPTS) state.lockedUntil = Date.now() + LOCKOUT_MS; }
function clearAttempts(state: AttemptState) { state.failures = 0; state.lockedUntil = 0; }
function internalRedirect(value: unknown) { return typeof value === "string" && ["/", "/#signin", "/#settings", "/#complete"].includes(value); }

function newRecoveryCodes() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", codes: string[] = [];
  while (codes.length < 8) {
    const values = crypto.getRandomValues(new Uint8Array(12));
    let code = "";
    for (let i = 0; i < 12; i++) { code += alphabet[values[i] % alphabet.length]; if (i === 3 || i === 7) code += "-"; }
    if (!codes.includes(code)) codes.push(code);
  }
  return codes;
}

async function mockCode(secret: EncryptedValue) {
  const step = currentStep();
  return { testCode: await totp(await decryptValue(secret), step), expiresAt: otpExpiry(step) };
}

async function handler(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      if (!trustedRequest(request)) return genericError(403, "This request is not allowed.");
      return new Response(null, { status: 204, headers: { ...securityHeaders(request.headers.get("origin")), "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" } });
    }
    if (request.method === "GET" && url.pathname === "/") {
      const nonce = randomToken(18);
      return new Response(page(nonce), { headers: { ...securityHeaders(request.headers.get("origin"), nonce), "Content-Type": "text/html; charset=utf-8" } });
    }
    if (!url.pathname.startsWith("/api/")) return genericError(404, "That page is not available.");

    if (request.method === "POST" && url.pathname === "/api/signin") {
      if (!trustedRequest(request)) return genericError(403, "This request is not allowed.");
      const body = await readBody(request);
      if (!body || !validEmail(body.email) || !validPhone(body.phone) || !validPassword(body.password) || !internalRedirect(body.redirect || "/")) return genericError(401, "Those sign-in details are not recognised. Please try again.");
      const known = demoAccounts.find(x => x.email === normalizeEmail(String(body.email)) && x.phone === normalizePhone(String(body.phone)));
      const passwordHash = await sha256(String(body.password));
      const expected = known ? await sha256(known.password) : await sha256("fixed-generic-comparison-value");
      if (!known || passwordHash !== expected) return genericError(401, "Those sign-in details are not recognised. Please try again.");
      const old = cookieValue(request, "mfa_session"); if (old) sessions.delete(old);
      let account = accounts.get(known.userId);
      if (!account) {
        account = { userId: known.userId, email: known.email, phone: known.phone, passwordHash: expected, mfaEnabled: false, recoveryHashes: new Set(), recoveryReady: false, recoveryAttempts: { failures: 0, lockedUntil: 0 } };
        accounts.set(account.userId, account);
      }
      const session: Session = { id: randomToken(), userId: account.userId, csrf: randomToken(), createdAt: Date.now(), lastSeenAt: Date.now(), identityVerified: false, acceptedTotpSteps: new Set(), otpAttempts: { failures: 0, lockedUntil: 0 }, reissues: [] };
      sessions.set(session.id, session);
      return json({ ok: true, csrf: session.csrf, message: "You are signed in. Next, confirm your identity." }, 200, { "Set-Cookie": sessionCookie(session.id) });
    }

    if (request.method === "POST" && url.pathname === "/api/identity") {
      const body = await readBody(request); if (!body) return genericError();
      const access = requireProtected(request, body); if (access instanceof Response) return access;
      if (!validEmail(body.email) || !validPhone(body.phone)) return genericError(400, "Use an email like name@example.com and a phone number with at least 7 digits.");
      if (normalizeEmail(String(body.email)) !== access.account.email || normalizePhone(String(body.phone)) !== access.account.phone) return genericError(400, "Those details do not match your signed-in account. Use the same email and phone number, then try again.");
      access.session.identityVerified = true;
      return json({ ok: true, message: "Identity confirmed. You can set up your authenticator now." });
    }

    if (request.method === "POST" && url.pathname === "/api/mfa/provision") {
      const body = await readBody(request); if (!body) return genericError();
      const access = requireProtected(request, body); if (access instanceof Response) return access;
      if (!access.session.identityVerified) return genericError(403, "Confirm your identity before setting up MFA.");
      const secret = base32Secret(20);
      const provisioningUri = `otpauth://totp/${encodeURIComponent("Online Bank")}:${encodeURIComponent(access.account.email)}?secret=${secret}&issuer=${encodeURIComponent("Online Bank")}&algorithm=SHA1&digits=6&period=30`;
      access.session.enrolledSecret = await encryptValue(secret);
      access.session.acceptedTotpSteps.clear();
      return json({ ok: true, secret, provisioningUri, ...(await mockCode(access.session.enrolledSecret)), message: "Your authenticator details are ready. Add them, then enter the six-digit code." });
    }

    if (request.method === "POST" && url.pathname === "/api/mfa/reissue") {
      const body = await readBody(request); if (!body) return genericError();
      const access = requireProtected(request, body); if (access instanceof Response) return access;
      if (!access.session.enrolledSecret) return genericError(400, "Start authenticator setup first.");
      if (isLocked(access.session.otpAttempts)) return genericError(429, "Too many tries. Please wait a few minutes before trying a code again.");
      const now = Date.now();
      access.session.reissues = access.session.reissues.filter(t => now - t < REISSUE_WINDOW_MS);
      if (access.session.reissues.length >= MAX_REISSUES) return genericError(429, "You have requested several codes. Please wait a few minutes, then try again.");
      access.session.reissues.push(now);
      return json({ ok: true, ...(await mockCode(access.session.enrolledSecret)), message: "Your current authenticator code is ready." });
    }

    if (request.method === "POST" && url.pathname === "/api/mfa/verify") {
      const body = await readBody(request); if (!body) return genericError();
      const access = requireProtected(request, body); if (access instanceof Response) return access;
      if (!access.session.enrolledSecret) return genericError(400, "Start authenticator setup first.");
      if (isLocked(access.session.otpAttempts)) return genericError(429, "Too many tries. Please wait a few minutes, then request a fresh code.");
      if (!validOtp(body.otp)) return genericError(400, "Enter all six digits. Example: 123456.");

      /* Task: verify only TOTP values derived from this authenticated user's decrypted secret. */
      const secret = await decryptValue(access.session.enrolledSecret);
      const nowStep = currentStep();
      let acceptedStep: number | null = null;
      for (let step = nowStep - OTP_WINDOW_STEPS; step <= nowStep + OTP_WINDOW_STEPS; step++) {
        if (await totp(secret, step) === body.otp) { acceptedStep = step; break; }
      }
      if (acceptedStep === null || access.session.acceptedTotpSteps.has(acceptedStep)) {
        failedAttempt(access.session.otpAttempts);
        return genericError(isLocked(access.session.otpAttempts) ? 429 : 400, isLocked(access.session.otpAttempts) ? "Too many tries. Please wait a few minutes, then request a fresh code." : "That code did not match, has expired, or was already used. Open your authenticator and try its current code.");
      }
      access.session.acceptedTotpSteps.add(acceptedStep);
      clearAttempts(access.session.otpAttempts);
      access.account.secret = access.session.enrolledSecret;
      access.account.mfaEnabled = true;
      return json({ ok: true, message: "Authenticator confirmed. Next, save recovery codes." });
    }

    if (request.method === "POST" && url.pathname === "/api/recovery/generate") {
      const body = await readBody(request); if (!body) return genericError();
      const access = requireProtected(request, body); if (access instanceof Response) return access;
      if (!access.account.mfaEnabled) return genericError(403, "Set up your authenticator before making recovery codes.");
      const codes = newRecoveryCodes();
      access.account.recoveryHashes = new Set(await Promise.all(codes.map(sha256)));
      access.account.recoveryReady = false; clearAttempts(access.account.recoveryAttempts);
      return json({ ok: true, codes, message: "Your new recovery codes are ready. Save all eight somewhere safe." });
    }

    if (request.method === "POST" && url.pathname === "/api/recovery/confirm") {
      const body = await readBody(request); if (!body) return genericError();
      const access = requireProtected(request, body); if (access instanceof Response) return access;
      if (body.saved !== true) return genericError(400, "Please confirm that you saved your recovery codes.");
      if (!access.account.recoveryHashes.size) return genericError(400, "Make recovery codes first.");
      access.account.recoveryReady = true;
      return json({ ok: true, message: "Recovery codes saved. MFA enrolment is complete." });
    }

    if (request.method === "GET" && url.pathname === "/api/settings") {
      const session = protectedSession(request);
      const account = session && accounts.get(session.userId);
      if (!session || !account) return genericError(401, "Your secure session has ended. Please sign in again.");
      return json({ ok: true, enabled: account.mfaEnabled, recoveryReady: account.recoveryReady, csrf: session.csrf });
    }

    if (request.method === "POST" && url.pathname === "/api/logout") {
      const body = await readBody(request); if (!body) return genericError();
      const session = protectedSession(request);
      if (!session || !noSuppliedAccountId(body) || !csrfOk(request, session, body)) return genericError(401, "Your secure session has ended. Please sign in again.");
      sessions.delete(session.id);
      return json({ ok: true, message: "You have signed out." }, 200, { "Set-Cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
    }
    return genericError(404, "That service is not available.");
  } catch {
    return genericError(500, "Something went wrong. Please try again.");
  }
}

const html = String.raw;
function page(nonce: string) {
return html`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Online Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172433;--muted:#506174;--blue:#0756b8;--pale:#eef6ff;--line:#c8d5e1;--good:#087447;--bad:#a52c27}*{box-sizing:border-box}body{margin:0;background:#f4f7fa;color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.035em}main{max-width:620px;min-height:100vh;margin:auto;padding:18px 16px 42px}header{padding:5px 5px 17px;border-bottom:3px solid var(--blue)}.brand{font-weight:700;color:#063f83}.steps{font-size:.87rem;color:#31516e;margin-top:10px}h1{font-size:1.7rem;line-height:1.25;margin:18px 0 8px}.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:20px;margin-top:18px}.step{display:none}.step.active{display:block}label{display:block;font-weight:700;margin:15px 0 5px}input{width:100%;min-height:52px;border:2px solid #8296a8;border-radius:9px;padding:10px 12px;font:inherit}input:focus{outline:3px solid #86bdfa;border-color:var(--blue)}input[type=checkbox]{width:auto;min-height:auto;margin-right:8px}.example,.hint{color:var(--muted);font-size:.88rem}button{display:block;width:100%;border:0;border-radius:9px;padding:13px 15px;margin-top:18px;background:var(--blue);color:#fff;font:700 1rem Verdana,Arial,sans-serif;cursor:pointer}.secondary{background:#e6edf4;color:#173552;border:1px solid #a8bac9}.small{margin-top:9px;padding:10px;font-size:.9rem}.notice{border-left:5px solid var(--blue);background:var(--pale);padding:11px 13px;margin:15px 0}.error{color:var(--bad);border-left-color:var(--bad)}.success{color:#075536;border-left-color:var(--good)}.help{margin-top:18px;padding-top:13px;border-top:1px solid var(--line);font-size:.91rem;color:var(--muted)}.code-box{word-break:break-all;background:#f5f8fb;border:2px dashed #8da3b6;border-radius:9px;padding:12px;font-family:monospace}.qr{width:240px;height:240px;display:block;margin:15px auto;background:#fff;image-rendering:pixelated}.codes,#logs{list-style:none;padding:0;margin:14px 0}.codes li,#logs li{font-family:monospace;background:#f1f6fa;padding:8px 11px;border-radius:6px;margin:7px 0;word-break:break-word}.logs{font-size:.78rem}@media print{header,.steps,button,.help,#message,.logs{display:none!important}body,main{background:#fff;padding:0}.card{border:0}}
</style></head><body><main>
<header><div class="brand">◇ Online Bank</div><div class="steps" id="stepText">Step 1 of 6 · Sign in</div></header><section class="card" aria-live="polite" id="message" hidden></section>
<section class="card step active" id="signin"><h1>Set up extra payment security</h1><p>🔐 Sign in to begin. This safe demonstration uses one practice account.</p><form id="signinForm"><label for="email">Email address</label><input id="email" type="email" autocomplete="email username" placeholder="name@example.com" required><span class="example">Demo: marcus@example.com</span><label for="phone">Mobile phone number</label><input id="phone" type="tel" autocomplete="tel" placeholder="07123 456789" required><span class="example">Demo: 07123 456789</span><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" required><span class="example">Demo: MarcusDemo!54</span><button>Sign in and continue</button></form><div class="help">💡 Take your time. There is no reading timer.</div></section>
<section class="card step" id="identity"><h1>Confirm it is you</h1><p>👤 Enter the same contact details once more.</p><form id="identityForm"><label for="identityEmail">Email address</label><input id="identityEmail" type="email" autocomplete="email" required><label for="identityPhone">Mobile phone number</label><input id="identityPhone" type="tel" autocomplete="tel" required><button>Confirm my identity</button></form></section>
<section class="card step" id="setup"><h1>Add your authenticator</h1><p>📱 Scan the square, or copy the setup key instead.</p><canvas id="qr" class="qr" width="245" height="245" aria-label="Authenticator setup QR code"></canvas><div id="qrProblem" class="notice error" hidden></div><label>Setup key</label><div class="code-box" id="secret"></div><button class="secondary small" id="copySecret" type="button">Copy setup key</button><button class="secondary small" id="toggleSecret" type="button">Hide setup key</button><button id="readyForCode" type="button">I added the authenticator</button></section>
<section class="card step" id="verify"><h1>Enter the six-digit code</h1><p>🔢 Open your authenticator app and enter its code.</p><form id="verifyForm"><label for="otp">Authenticator code</label><input id="otp" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required><span class="example">Example: 123456</span><button>Verify code</button></form><button class="secondary small" id="reissue" type="button">Show current test code again</button><div class="help">💡 Codes change every 30 seconds. You may retry.</div></section>
<section class="card step" id="recovery"><h1>Save recovery codes</h1><p>🗝️ Each code works once.</p><ul class="codes" id="codes"></ul><button class="secondary small" id="copyCodes" type="button">Copy all codes</button><button class="secondary small" id="printCodes" type="button">Print or save as PDF</button><form id="confirmCodes"><label><input id="savedCodes" type="checkbox"> I saved all eight codes somewhere private.</label><button>Confirm codes are saved</button></form></section>
<section class="card step" id="complete"><h1>Setup complete</h1><p>✅ Your authenticator and recovery codes are ready.</p><button id="openSettings" type="button">Open MFA settings</button></section>
<section class="card step" id="settings"><h1>MFA settings</h1><p id="settingStatus">Loading secure settings…</p><button id="regenerate" type="button">Make new recovery codes</button><button class="secondary" id="logout" type="button">Sign out</button></section>
<section class="card logs"><h2>Logs</h2><p class="hint">Demonstration deliveries are shown here and in the browser console.</p><ul id="logs" aria-live="polite"></ul></section>
</main>
<script nonce="${nonce}">
(()=>{let csrf="",secret="",codes=[];
const $=id=>document.getElementById(id);
function log(...v){console.log(...v);const li=document.createElement("li");li.textContent=v.map(x=>typeof x==="string"?x:JSON.stringify(x)).join(" ");$("logs").prepend(li)}
function msg(t,c){const b=$("message");b.textContent=t;b.className="card notice "+(c||"");b.hidden=!t}
function show(id,label){document.querySelectorAll(".step").forEach(x=>x.classList.remove("active"));$(id).classList.add("active");$("stepText").textContent=label;msg("");scrollTo(0,0)}
async function api(path,body,method){const r=await fetch(path,{method:method||"POST",credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json"},body:method==="GET"?undefined:JSON.stringify({...body,csrf})});const d=await r.json().catch(()=>({ok:false,message:"Please try again."}));if(!r.ok||!d.ok)throw Error(d.message);return d}
async function copy(t,s){try{await navigator.clipboard.writeText(t);msg(s,"success")}catch{msg("Copy did not work here. Select the text and copy it.","error")}}

/* QR encoder: chooses a byte-mode QR version only after checking URI capacity. */
function drawQR(text){
 const bytes=[...new TextEncoder().encode(text)], versions=[
  [1,21,17,19,7,1,[]],[2,25,32,34,10,1,[6,18]],[3,29,53,55,15,1,[6,22]],[4,33,78,80,20,1,[6,26]],[5,37,106,108,26,1,[6,30]],[6,41,134,136,18,2,[6,34]],[7,45,154,156,20,2,[6,22,38]],[8,49,192,194,24,2,[6,24,42]],[9,53,230,232,30,2,[6,26,46]]
 ];
 const q=versions.find(v=>bytes.length<=v[2]); if(!q)throw Error("This setup link is too long for the built-in QR code. Copy the setup key instead.");
 const [ver,n,,dataCap,ec,blocks,align]=q, m=Array.from({length:n},()=>Array(n).fill(null)), put=(x,y,v)=>{if(x>=0&&y>=0&&x<n&&y<n)m[y][x]=v};
 const finder=(x,y)=>{for(let dy=-1;dy<8;dy++)for(let dx=-1;dx<8;dx++)put(x+dx,y,0),put(x+dx,y+dy,dx>=0&&dx<7&&dy>=0&&dy<7&&(dx===0||dx===6||dy===0||dy===6||(dx>1&&dx<5&&dy>1&&dy<5))?1:0)};
 finder(0,0);finder(n-7,0);finder(0,n-7);for(let i=8;i<n-8;i++){put(i,6,i%2===0?1:0);put(6,i,i%2===0?1:0)}
 for(const y of align)for(const x of align){if(m[y][x]!==null)continue;for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)put(x+dx,y,Math.max(Math.abs(dx),Math.abs(dy))!==1?1:0)}
 for(let i=0;i<9;i++){if(m[i][8]===null)put(8,i,0);if(m[8][i]===null)put(i,8,0)}for(let i=0;i<8;i++){if(m[n-1-i][8]===null)put(8,n-1-i,0);if(m[8][n-1-i]===null)put(n-1-i,8,0)}put(8,n-8,1);
 const bits=[0,1,0,0];for(let i=7;i>=0;i--)bits.push((bytes.length>>i)&1);bytes.forEach(b=>{for(let i=7;i>=0;i--)bits.push(b>>i&1)});while(bits.length<dataCap*8&&bits.length%8)bits.push(0);const data=[];for(let i=0;i<bits.length;i+=8)data.push(bits.slice(i,i+8).reduce((a,b)=>a*2+b,0));for(let p=0;data.length<dataCap;p++)data.push(p%2?17:236);
 const exp=[],lg=[];let z=1;for(let i=0;i<255;i++){exp[i]=z;lg[z]=i;z<<=1;if(z&256)z^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];let poly=[1];for(let i=0;i<ec;i++){const a=Array(poly.length+1).fill(0);poly.forEach((v,j)=>{a[j]^=v;a[j+1]^=exp[lg[v]+i]});poly=a}
 const chunks=[];let offset=0;for(let b=0;b<blocks;b++){const len=dataCap/blocks;const d=data.slice(offset,offset+len);offset+=len;const rem=Array(ec).fill(0);d.forEach(v=>{const f=v^rem.shift();rem.push(0);if(f)for(let j=0;j<ec;j++)rem[j]^=exp[lg[poly[j+1]]+lg[f]]});chunks.push([d,rem])}
 const stream=[];for(let i=0;i<dataCap/blocks;i++)chunks.forEach(c=>stream.push(c[0][i]));for(let i=0;i<ec;i++)chunks.forEach(c=>stream.push(c[1][i]));const sb=[];stream.forEach(b=>{for(let i=7;i>=0;i--)sb.push(b>>i&1)});
 let bit=0,up=true;for(let col=n-1;col>0;col-=2){if(col===6)col--;for(let r=0;r<n;r++){const y=up?n-1-r:r;for(let c=0;c<2;c++){const x=col-c;if(m[y][x]===null)put(x,y,(sb[bit++]||0)^((x+y)%2===0?1:0))}}up=!up}
 const fmt="111011111000100";let k=0;for(let i=0;i<=5;i++)put(8,i,+fmt[k++]);put(8,7,+fmt[k++]);put(8,8,+fmt[k++]);put(7,8,+fmt[k++]);for(let i=5;i>=0;i--)put(i,8,+fmt[k++]);k=0;for(let i=n-1;i>=n-7;i--)put(8,i,+fmt[k++]);for(let i=n-8;i<n;i++)put(i,8,+fmt[k++]);
 const c=$("qr"),ctx=c.getContext("2d"),s=c.width/n;ctx.fillStyle="#fff";ctx.fillRect(0,0,c.width,c.height);ctx.fillStyle="#111";for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(m[y][x])ctx.fillRect(Math.floor(x*s),Math.floor(y*s),Math.ceil(s),Math.ceil(s));
}
$("signinForm").addEventListener("submit",async e=>{e.preventDefault();try{const d=await api("/api/signin",{email:$("email").value.trim(),phone:$("phone").value.trim(),password:$("password").value,redirect:"/"});csrf=d.csrf;show("identity","Step 2 of 6 · Confirm identity");msg(d.message,"success")}catch(e){msg(e.message,"error")}});
$("identityForm").addEventListener("submit",async e=>{e.preventDefault();try{await api("/api/identity",{email:$("identityEmail").value.trim(),phone:$("identityPhone").value.trim()});const d=await api("/api/mfa/provision",{});secret=d.secret;$("secret").textContent=secret;try{drawQR(d.provisioningUri);$("qrProblem").hidden=true}catch(x){$("qr").hidden=true;$("qrProblem").textContent=x.message;$("qrProblem").hidden=false}log("Browser mock: authenticator setup secret delivered:",secret);log("Browser mock: TOTP code accepted by verification:",d.testCode);show("setup","Step 3 of 6 · Add authenticator");msg(d.message,"success")}catch(e){msg(e.message,"error")}});
$("copySecret").onclick=()=>copy(secret,"Setup key copied. Paste it into your authenticator app.");
$("toggleSecret").onclick=e=>{const h=$("secret").dataset.hidden==="yes";$("secret").textContent=h?secret:"•••• •••• •••• ••••";$("secret").dataset.hidden=h?"no":"yes";e.currentTarget.textContent=h?"Hide setup key":"Reveal setup key"};
$("readyForCode").onclick=()=>show("verify","Step 4 of 6 · Verify code");
$("reissue").onclick=async()=>{try{const d=await api("/api/mfa/reissue",{});log("Browser mock: current TOTP code accepted by verification:",d.testCode);msg(d.message+" It is shown in Logs.","success")}catch(e){msg(e.message,"error")}};
$("verifyForm").addEventListener("submit",async e=>{e.preventDefault();try{await api("/api/mfa/verify",{otp:$("otp").value.trim()});const d=await api("/api/recovery/generate",{});codes=d.codes;$("codes").replaceChildren(...codes.map(x=>{const l=document.createElement("li");l.textContent=x;return l}));log("Browser mock: recovery codes delivered:",codes);show("recovery","Step 5 of 6 · Save recovery codes");msg("Authenticator confirmed. Next, save recovery codes.","success")}catch(e){msg(e.message,"error")}});
$("copyCodes").onclick=()=>copy(codes.join("\\n"),"Recovery codes copied.");
$("printCodes").onclick=()=>print();
$("confirmCodes").addEventListener("submit",async e=>{e.preventDefault();try{const d=await api("/api/recovery/confirm",{saved:$("savedCodes").checked});show("complete","Step 6 of 6 · Complete");msg(d.message,"success")}catch(e){msg(e.message,"error")}});
async function settings(){try{const d=await api("/api/settings",null,"GET");csrf=d.csrf;$("settingStatus").textContent=d.enabled&&d.recoveryReady?"✅ MFA is on. Your authenticator and recovery codes are ready.":"MFA needs attention.";show("settings","MFA settings")}catch(e){show("signin","Step 1 of 6 · Sign in");msg(e.message,"error")}}
$("openSettings").onclick=settings;
$("regenerate").onclick=async()=>{try{const d=await api("/api/recovery/generate",{});codes=d.codes;$("codes").replaceChildren(...codes.map(x=>{const l=document.createElement("li");l.textContent=x;return l}));$("savedCodes").checked=false;log("Browser mock: regenerated recovery codes:",codes);show("recovery","Step 5 of 6 · Save new recovery codes");msg("New codes replace the old ones. Save these eight codes.","success")}catch(e){msg(e.message,"error")}};
$("logout").onclick=async()=>{try{await api("/api/logout",{});csrf="";secret="";codes=[];show("signin","Step 1 of 6 · Sign in");msg("You have signed out safely.","success");log("Browser mock: session logout complete.")}catch(e){msg(e.message,"error")}};
})();
</script></body></html>`;
}

Bun.serve({
  port: PORT,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  fetch: handler,
  error() { return genericError(500, "Something went wrong. Please try again."); },
});
