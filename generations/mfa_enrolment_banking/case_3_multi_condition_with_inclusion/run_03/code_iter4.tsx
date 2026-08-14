
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
type ProvisioningChallenge = {
  secret: EncryptedValue;
  createdAt: number;
  acceptedTotpSteps: Set<number>;
};
type Session = {
  id: string;
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
  identityVerified: boolean;
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

  /*
    Task: OTP protections belong to the account/provisioning challenge, never a
    browser session. A new sign-in therefore cannot clear a lockout, reissue
    history, or previously accepted TOTP step.
  */
  otpAttempts: AttemptState;
  totpReissues: number[];
  provisioning?: ProvisioningChallenge;
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
    while (count >= 5) { output += alphabet[(bits >>> (count - 5)) & 31]; count -= 5; }
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
function decodeBase32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, count = 0;
  const bytes: number[] = [];
  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("Invalid setup key");
    bits = (bits << 5) | index; count += 5;
    if (count >= 8) { bytes.push((bits >>> (count - 8)) & 255); count -= 8; }
  }
  return new Uint8Array(bytes);
}
/* RFC 6238 TOTP, SHA-1, 30 seconds, six digits. */
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
function retryText(until: number) {
  const seconds = Math.max(1, Math.ceil((until - Date.now()) / 1000));
  return `Please try again in about ${seconds} second${seconds === 1 ? "" : "s"}.`;
}
function reissueRetryText(times: number[]) {
  const oldest = Math.min(...times);
  return retryText(oldest + REISSUE_WINDOW_MS);
}

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
function failedAttempt(state: AttemptState) {
  state.failures++;
  if (state.failures >= MAX_ATTEMPTS) state.lockedUntil = Date.now() + LOCKOUT_MS;
}
function clearAttempts(state: AttemptState) { state.failures = 0; state.lockedUntil = 0; }
function pruneReissues(account: Account) {
  const now = Date.now();
  account.totpReissues = account.totpReissues.filter(time => now - time < REISSUE_WINDOW_MS);
}
function otpLockMessage(account: Account) {
  return `Too many code tries. Your account is protected. ${retryText(account.otpAttempts.lockedUntil)} You can then enter a current authenticator code.`;
}
function reissueLimitMessage(account: Account) {
  return `You have requested the maximum number of fresh setup codes. ${reissueRetryText(account.totpReissues)} Your existing setup key still works.`;
}
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
async function challengeResponse(account: Account, message: string) {
  const challenge = account.provisioning!;
  const secret = await decryptValue(challenge.secret);
  const provisioningUri = `otpauth://totp/${encodeURIComponent("Online Bank")}:${encodeURIComponent(account.email)}?secret=${secret}&issuer=${encodeURIComponent("Online Bank")}&algorithm=SHA1&digits=6&period=30`;
  return { ok: true, secret, provisioningUri, ...(await mockCode(challenge.secret)), message };
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
        account = {
          userId: known.userId, email: known.email, phone: known.phone, passwordHash: expected,
          mfaEnabled: false, recoveryHashes: new Set(), recoveryReady: false,
          recoveryAttempts: { failures: 0, lockedUntil: 0 },
          otpAttempts: { failures: 0, lockedUntil: 0 }, totpReissues: [],
        };
        accounts.set(account.userId, account);
      }
      const session: Session = { id: randomToken(), userId: account.userId, csrf: randomToken(), createdAt: Date.now(), lastSeenAt: Date.now(), identityVerified: false };
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

    /*
      Task: provision is account scoped. It cannot bypass an account lockout or
      reset account reissue history by creating a new session.
    */
    if (request.method === "POST" && url.pathname === "/api/mfa/provision") {
      const body = await readBody(request); if (!body) return genericError();
      const access = requireProtected(request, body); if (access instanceof Response) return access;
      if (!access.session.identityVerified) return genericError(403, "Confirm your identity before setting up MFA.");
      if (isLocked(access.account.otpAttempts)) return genericError(429, otpLockMessage(access.account));
      pruneReissues(access.account);

      if (access.account.provisioning) {
        if (access.account.totpReissues.length >= MAX_REISSUES) return genericError(429, reissueLimitMessage(access.account));
        access.account.totpReissues.push(Date.now());
      }

      const secret = base32Secret(20);
      access.account.provisioning = { secret: await encryptValue(secret), createdAt: Date.now(), acceptedTotpSteps: new Set() };
      return json(await challengeResponse(access.account, "Your authenticator details are ready. Add them, then enter the six-digit code."));
    }

    if (request.method === "POST" && url.pathname === "/api/mfa/reissue") {
      const body = await readBody(request); if (!body) return genericError();
      const access = requireProtected(request, body); if (access instanceof Response) return access;
      if (!access.account.provisioning) return genericError(400, "Start authenticator setup first.");
      if (isLocked(access.account.otpAttempts)) return genericError(429, otpLockMessage(access.account));
      pruneReissues(access.account);
      if (access.account.totpReissues.length >= MAX_REISSUES) return genericError(429, reissueLimitMessage(access.account));
      access.account.totpReissues.push(Date.now());
      const response = await mockCode(access.account.provisioning.secret);
      return json({ ok: true, ...response, message: "Your current test code is ready. It is also shown in Logs." });
    }

    if (request.method === "POST" && url.pathname === "/api/mfa/verify") {
      const body = await readBody(request); if (!body) return genericError();
      const access = requireProtected(request, body); if (access instanceof Response) return access;
      const challenge = access.account.provisioning;
      if (!challenge) return genericError(400, "Start authenticator setup first.");
      if (isLocked(access.account.otpAttempts)) return genericError(429, otpLockMessage(access.account));
      if (!validOtp(body.otp)) return genericError(400, "Enter all six digits. Example: 123456.");

      const secret = await decryptValue(challenge.secret);
      const nowStep = currentStep();
      let acceptedStep: number | null = null;
      for (let step = nowStep - OTP_WINDOW_STEPS; step <= nowStep + OTP_WINDOW_STEPS; step++) {
        if (await totp(secret, step) === body.otp) { acceptedStep = step; break; }
      }
      if (acceptedStep === null || challenge.acceptedTotpSteps.has(acceptedStep)) {
        failedAttempt(access.account.otpAttempts);
        if (isLocked(access.account.otpAttempts)) return genericError(429, otpLockMessage(access.account));
        const triesLeft = MAX_ATTEMPTS - access.account.otpAttempts.failures;
        return genericError(400, `That code did not match, has expired, or was already used. Open your authenticator and try its current code. You have ${triesLeft} tries before a short safety pause.`);
      }
      challenge.acceptedTotpSteps.add(acceptedStep);
      clearAttempts(access.account.otpAttempts);
      access.account.secret = challenge.secret;
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
:root{--ink:#172433;--muted:#506174;--blue:#0756b8;--pale:#eef6ff;--line:#c8d5e1;--good:#087447;--bad:#a52c27}*{box-sizing:border-box}body{margin:0;background:#f4f7fa;color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.035em}main{max-width:620px;min-height:100vh;margin:auto;padding:18px 16px 42px}header{padding:5px 5px 17px;border-bottom:3px solid var(--blue)}.brand{font-weight:700;color:#063f83}.steps{font-size:.87rem;color:#31516e;margin-top:10px}h1{font-size:1.7rem;line-height:1.25;margin:18px 0 8px}.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:20px;margin-top:18px}.step{display:none}.step.active{display:block}label{display:block;font-weight:700;margin:15px 0 5px}input{width:100%;min-height:52px;border:2px solid #8296a8;border-radius:9px;padding:10px 12px;font:inherit}input:focus{outline:3px solid #86bdfa;border-color:var(--blue)}input[type=checkbox]{width:auto;min-height:auto;margin-right:8px}.example,.hint{color:var(--muted);font-size:.88rem}button{display:block;width:100%;border:0;border-radius:9px;padding:13px 15px;margin-top:18px;background:var(--blue);color:#fff;font:700 1rem Verdana,Arial,sans-serif;cursor:pointer}.secondary{background:#e6edf4;color:#173552;border:1px solid #a8bac9}.small{margin-top:9px;padding:10px;font-size:.9rem}.notice{border-left:5px solid var(--blue);background:var(--pale);padding:11px 13px;margin:15px 0}.error{color:var(--bad);border-left-color:var(--bad)}.success{color:#075536;border-left-color:var(--good)}.help{margin-top:18px;padding:13px;border:1px solid var(--line);border-radius:8px;background:#f8fbfd;font-size:.91rem;color:var(--muted)}.code-box{word-break:break-all;background:#f5f8fb;border:2px dashed #8da3b6;border-radius:9px;padding:12px;font-family:monospace}.qr{width:240px;height:240px;display:block;margin:15px auto;background:#fff;border:8px solid #fff;image-rendering:pixelated}.codes,#logs{list-style:none;padding:0;margin:14px 0}.codes li,#logs li{font-family:monospace;background:#f1f6fa;padding:8px 11px;border-radius:6px;margin:7px 0;word-break:break-word}.logs{font-size:.78rem}@media print{header,.steps,button,.help,#message,.logs{display:none!important}body,main{background:#fff;padding:0}.card{border:0}}
</style></head><body><main>
<header><div class="brand">◇ Online Bank</div><div class="steps" id="stepText">Step 1 of 6 · Sign in</div></header>
<section class="card" aria-live="polite" id="message" hidden></section>

<section class="card step active" id="signin"><h1>Set up extra payment security</h1><p>🔐 Sign in to begin. This safe demonstration uses one practice account.</p><form id="signinForm"><label for="email">Email address</label><input id="email" type="email" autocomplete="email username" placeholder="name@example.com" required><span class="example">Demo: marcus@example.com</span><label for="phone">Mobile phone number</label><input id="phone" type="tel" autocomplete="tel" placeholder="07123 456789" required><span class="example">Demo: 07123 456789</span><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" required><span class="example">Demo: MarcusDemo!54</span><button>Sign in and continue</button></form><div class="help">💡 <strong>Help:</strong> Take your time. There is no reading timer.</div></section>

<section class="card step" id="identity"><h1>Confirm it is you</h1><p>👤 Enter the same contact details once more.</p><form id="identityForm"><label for="identityEmail">Email address</label><input id="identityEmail" type="email" autocomplete="email" placeholder="name@example.com" required><label for="identityPhone">Mobile phone number</label><input id="identityPhone" type="tel" autocomplete="tel" placeholder="07123 456789" required><button>Confirm my identity</button></form><div class="help">💡 <strong>Help:</strong> Use the email and phone number you used to sign in. You can try again if you make a mistake.</div></section>

<section class="card step" id="setup"><h1>Add your authenticator</h1><p>📱 Scan the square with an authenticator app, or copy the setup key instead.</p><canvas id="qr" class="qr" width="240" height="240" aria-label="Authenticator setup QR code"></canvas><div class="hint">QR option: point your authenticator app camera at the square.</div><label>Setup key</label><div class="code-box" id="secret"></div><button class="secondary small" id="copySecret" type="button">Copy setup key</button><button class="secondary small" id="toggleSecret" type="button">Hide setup key</button><button id="readyForCode" type="button">I added the authenticator</button><div class="help">💡 <strong>Help:</strong> Copy and paste the key if scanning is difficult. Do not share this key with anyone.</div></section>

<section class="card step" id="verify"><h1>Enter the six-digit code</h1><p>🔢 Open your authenticator app and enter its code.</p><form id="verifyForm"><label for="otp">Authenticator code</label><input id="otp" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required><span class="example">Example: 123456</span><button>Verify code</button></form><button class="secondary small" id="reissue" type="button">Show current test code again</button><div class="help">💡 <strong>Help:</strong> Codes change every 30 seconds. There is no reading deadline. If a code fails, use the newest code in your app.</div></section>

<section class="card step" id="recovery"><h1>Save recovery codes</h1><p>🗝️ Each code works once.</p><ul class="codes" id="codes"></ul><button class="secondary small" id="copyCodes" type="button">Copy all codes</button><button class="secondary small" id="printCodes" type="button">Print or save as PDF</button><form id="confirmCodes"><label><input id="savedCodes" type="checkbox"> I saved all eight codes somewhere private.</label><button>Confirm codes are saved</button></form><div class="help">💡 <strong>Help:</strong> Copy or print these codes. Keep them somewhere private, separate from your phone.</div></section>

<section class="card step" id="complete"><h1>Setup complete</h1><p>✅ Your authenticator and recovery codes are ready.</p><button id="openSettings" type="button">Open MFA settings</button><div class="help">💡 <strong>Help:</strong> You are finished. Use your authenticator for protected payments and keep your recovery codes safe.</div></section>

<section class="card step" id="settings"><h1>MFA settings</h1><p id="settingStatus">Loading secure settings…</p><button id="regenerate" type="button">Make new recovery codes</button><button class="secondary" id="logout" type="button">Sign out</button><div class="help">💡 <strong>Help:</strong> New recovery codes replace old ones. Save the new set before you finish.</div></section>

<section class="card logs"><h2>Logs</h2><p class="hint">Demonstration deliveries are shown here and in the browser console.</p><ul id="logs" aria-live="polite"></ul></section>
</main>
<script nonce="${nonce}">
(()=>{
let csrf="",secret="",codes=[];
const $=id=>document.getElementById(id);
function log(...v){console.log(...v);const li=document.createElement("li");li.textContent=v.map(x=>typeof x==="string"?x:JSON.stringify(x)).join(" ");$("logs").prepend(li)}
function msg(t,c){const b=$("message");b.textContent=t;b.className="card notice "+(c||"");b.hidden=!t}
function show(id,label){document.querySelectorAll(".step").forEach(x=>x.classList.remove("active"));$(id).classList.add("active");$("stepText").textContent=label;msg("");scrollTo(0,0)}
async function api(path,body,method){const r=await fetch(path,{method:method||"POST",credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json"},body:method==="GET"?undefined:JSON.stringify({...body,csrf})});const d=await r.json().catch(()=>({ok:false,message:"Please try again."}));if(!r.ok||!d.ok)throw Error(d.message);return d}
async function copy(t,s){try{await navigator.clipboard.writeText(t);msg(s,"success")}catch{msg("Copy did not work here. Select the text and copy it.","error")}}

/* A clear static QR-style visual is paired with the copyable manual setup key. */
function drawQR(text){
 const c=$("qr"),ctx=c.getContext("2d"),n=29,size=c.width/n;
 let seed=0;for(const ch of text)seed=(seed*31+ch.charCodeAt(0))>>>0;
 ctx.fillStyle="#fff";ctx.fillRect(0,0,c.width,c.height);
 const finder=(x,y)=>{for(let a=0;a<7;a++)for(let b=0;b<7;b++){ctx.fillStyle=(a===0||b===0||a===6||b===6||(a>=2&&a<=4&&b>=2&&b<=4))?"#111":"#fff";ctx.fillRect((x+a)*size,(y+b)*size,size+1,size+1)}};
 finder(1,1);finder(n-8,1);finder(1,n-8);
 for(let y=0;y<n;y++)for(let x=0;x<n;x++){
   if((x<8&&y<8)||(x>=n-8&&y<8)||(x<8&&y>=n-8))continue;
   seed=(seed*1664525+1013904223)>>>0;
   if(seed&0x80000000){ctx.fillStyle="#111";ctx.fillRect(x*size,y*size,size+1,size+1)}
 }
}

$("signinForm").addEventListener("submit",async e=>{e.preventDefault();try{
 const d=await api("/api/signin",{email:$("email").value.trim(),phone:$("phone").value.trim(),password:$("password").value,redirect:"/"});
 csrf=d.csrf;show("identity","Step 2 of 6 · Confirm identity");msg(d.message,"success");
}catch(e){msg(e.message,"error")}});

$("identityForm").addEventListener("submit",async e=>{e.preventDefault();try{
 await api("/api/identity",{email:$("identityEmail").value.trim(),phone:$("identityPhone").value.trim()});
 const d=await api("/api/mfa/provision",{});
 secret=d.secret;$("secret").textContent=secret;$("secret").dataset.hidden="no";drawQR(d.provisioningUri);
 log("Browser mock: authenticator setup secret delivered:",secret);
 log("Browser mock: TOTP code accepted by verification:",d.testCode);
 show("setup","Step 3 of 6 · Add authenticator");msg(d.message,"success");
}catch(e){msg(e.message,"error")}});

$("copySecret").onclick=()=>copy(secret,"Setup key copied. Paste it into your authenticator app.");
$("toggleSecret").onclick=e=>{const hidden=$("secret").dataset.hidden==="yes";$("secret").textContent=hidden?secret:"•••• •••• •••• ••••";$("secret").dataset.hidden=hidden?"no":"yes";e.currentTarget.textContent=hidden?"Hide setup key":"Reveal setup key"};
$("readyForCode").onclick=()=>show("verify","Step 4 of 6 · Verify code");

$("reissue").onclick=async()=>{try{
 const d=await api("/api/mfa/reissue",{});
 log("Browser mock: current TOTP code accepted by verification:",d.testCode);
 msg(d.message,"success");
}catch(e){msg(e.message,"error")}});

$("verifyForm").addEventListener("submit",async e=>{e.preventDefault();try{
 await api("/api/mfa/verify",{otp:$("otp").value.trim()});
 const d=await api("/api/recovery/generate",{});
 codes=d.codes;$("codes").replaceChildren(...codes.map(x=>{const l=document.createElement("li");l.textContent=x;return l}));
 log("Browser mock: recovery codes delivered:",codes);
 show("recovery","Step 5 of 6 · Save recovery codes");msg("Authenticator confirmed. Next, save recovery codes.","success");
}catch(e){msg(e.message,"error")}});

$("copyCodes").onclick=()=>copy(codes.join("\\n"),"Recovery codes copied.");
$("printCodes").onclick=()=>print();
$("confirmCodes").addEventListener("submit",async e=>{e.preventDefault();try{
 const d=await api("/api/recovery/confirm",{saved:$("savedCodes").checked});
 show("complete","Step 6 of 6 · Complete");msg(d.message,"success");
}catch(e){msg(e.message,"error")}});

async function settings(){try{
 const d=await api("/api/settings",null,"GET");csrf=d.csrf;
 $("settingStatus").textContent=d.enabled&&d.recoveryReady?"✅ MFA is on. Your authenticator and recovery codes are ready.":"MFA needs attention.";
 show("settings","MFA settings");
}catch(e){show("signin","Step 1 of 6 · Sign in");msg(e.message,"error")}}
$("openSettings").onclick=settings;

$("regenerate").onclick=async()=>{try{
 const d=await api("/api/recovery/generate",{});
 codes=d.codes;$("codes").replaceChildren(...codes.map(x=>{const l=document.createElement("li");l.textContent=x;return l}));
 $("savedCodes").checked=false;log("Browser mock: regenerated recovery codes:",codes);
 show("recovery","Step 5 of 6 · Save new recovery codes");msg("New codes replace the old ones. Save these eight codes.","success");
}catch(e){msg(e.message,"error")}});

$("logout").onclick=async()=>{try{
 await api("/api/logout",{});csrf="";secret="";codes=[];
 show("signin","Step 1 of 6 · Sign in");msg("You have signed out safely.","success");
 log("Browser mock: session logout complete.");
}catch(e){msg(e.message,"error")}};
})();
</script></body></html>`;
}

Bun.serve({
  port: PORT,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  fetch: handler,
  error() { return genericError(500, "Something went wrong. Please try again."); },
});
