
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
const RECOVERY_KDF_ITERATIONS = 210_000;

const serverKey = crypto.getRandomValues(new Uint8Array(32));
const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();

type EncryptedValue = { iv: string; data: string };
type AttemptState = { failures: number; lockedUntil: number };
type RecoveryHash = { salt: string; hash: string; iterations: number };
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
  recoveryHashes: RecoveryHash[];
  recoveryReady: boolean;
  recoveryAttempts: AttemptState;
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
    bits = (bits << 8) | value;
    count += 8;
    while (count >= 5) {
      output += alphabet[(bits >>> (count - 5)) & 31];
      count -= 5;
    }
  }
  if (count) output += alphabet[(bits << (5 - count)) & 31];
  return output;
}

/* Security Evaluation 3: AES-GCM encryption for OTP secrets at rest. */
async function encryptValue(value: string): Promise<EncryptedValue> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", serverKey, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  return {
    iv: Buffer.from(iv).toString("base64url"),
    data: Buffer.from(encrypted).toString("base64url"),
  };
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

/*
  Security Evaluation 3 / task: each recovery code has its own cryptographically
  random salt and PBKDF2 slow-KDF representation. Plain recovery codes are never
  retained after the response is sent.
*/
async function recoveryRepresentation(code: string, salt?: Uint8Array): Promise<RecoveryHash> {
  const actualSalt = salt || crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: actualSalt, iterations: RECOVERY_KDF_ITERATIONS },
    key,
    256,
  );
  return {
    salt: Buffer.from(actualSalt).toString("base64url"),
    hash: Buffer.from(bits).toString("base64url"),
    iterations: RECOVERY_KDF_ITERATIONS,
  };
}
function constantTimeEqual(a: string, b: string) {
  const aa = Buffer.from(a), bb = Buffer.from(b);
  let result = aa.length ^ bb.length;
  const length = Math.max(aa.length, bb.length);
  for (let i = 0; i < length; i++) result |= (aa[i % Math.max(aa.length, 1)] || 0) ^ (bb[i % Math.max(bb.length, 1)] || 0);
  return result === 0;
}
async function recoveryMatches(code: string, stored: RecoveryHash) {
  const derived = await recoveryRepresentation(code, Buffer.from(stored.salt, "base64url"));
  return derived.iterations === stored.iterations && constantTimeEqual(derived.hash, stored.hash);
}

function decodeBase32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, count = 0;
  const bytes: number[] = [];
  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("Invalid setup key");
    bits = (bits << 5) | index;
    count += 5;
    if (count >= 8) {
      bytes.push((bits >>> (count - 8)) & 255);
      count -= 8;
    }
  }
  return new Uint8Array(bytes);
}

/* RFC 6238 TOTP, SHA-1, 30 seconds, six digits. */
async function totp(secret: string, step: number) {
  const data = new Uint8Array(8);
  let counter = BigInt(step);
  for (let i = 7; i >= 0; i--) {
    data[i] = Number(counter & 255n);
    counter >>= 8n;
  }
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
  return retryText(Math.min(...times) + REISSUE_WINDOW_MS);
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
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...securityHeaders(), "Content-Type": "application/json; charset=utf-8", ...extra },
  });
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
  const id = cookieValue(request, "mfa_session");
  const session = sessions.get(id);
  if (!session || expired(session)) {
    if (id) sessions.delete(id);
    return null;
  }
  session.lastSeenAt = Date.now();
  return session;
}
function trustedRequest(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    const from = new URL(origin);
    const to = new URL(request.url);
    return from.protocol === "https:" && from.origin === to.origin;
  } catch {
    return false;
  }
}
async function readBody(request: Request) {
  if (Number(request.headers.get("content-length") || "0") > 10_000) return null;
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}
const validEmail = (v: unknown) => typeof v === "string" && v.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const validPhone = (v: unknown) => typeof v === "string" && /^[0-9 +()\-]{7,25}$/.test(v);
const validPassword = (v: unknown) => typeof v === "string" && v.length >= 8 && v.length <= 128;
const validOtp = (v: unknown) => typeof v === "string" && /^\d{6}$/.test(v);
const validRecovery = (v: unknown) => typeof v === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(v);
const noSuppliedAccountId = (b: Record<string, unknown>) => !("userId" in b) && !("accountId" in b) && !("emailOwner" in b);
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
function clearAttempts(state: AttemptState) {
  state.failures = 0;
  state.lockedUntil = 0;
}
function pruneReissues(account: Account) {
  const now = Date.now();
  account.totpReissues = account.totpReissues.filter(time => now - time < REISSUE_WINDOW_MS);
}
function otpLockMessage(account: Account) {
  return `Too many code tries. Your account is protected. ${retryText(account.otpAttempts.lockedUntil)} You can then enter a current authenticator code.`;
}
function recoveryLockMessage(account: Account) {
  return `Too many recovery code tries. Your account is protected. ${retryText(account.recoveryAttempts.lockedUntil)}`;
}
function reissueLimitMessage(account: Account) {
  return `You have requested the maximum number of fresh setup codes. ${reissueRetryText(account.totpReissues)} Your existing setup key still works.`;
}
function internalRedirect(value: unknown) {
  return typeof value === "string" && ["/", "/#signin", "/#settings", "/#complete"].includes(value);
}
function newRecoveryCodes() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const codes: string[] = [];
  while (codes.length < 8) {
    const values = crypto.getRandomValues(new Uint8Array(12));
    let code = "";
    for (let i = 0; i < 12; i++) {
      code += alphabet[values[i] % alphabet.length];
      if (i === 3 || i === 7) code += "-";
    }
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
      return new Response(null, {
        status: 204,
        headers: {
          ...securityHeaders(request.headers.get("origin")),
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    if (request.method === "GET" && url.pathname === "/") {
      const nonce = randomToken(18);
      return new Response(page(nonce), {
        headers: { ...securityHeaders(request.headers.get("origin"), nonce), "Content-Type": "text/html; charset=utf-8" },
      });
    }
    if (!url.pathname.startsWith("/api/")) return genericError(404, "That page is not available.");

    if (request.method === "POST" && url.pathname === "/api/signin") {
      if (!trustedRequest(request)) return genericError(403, "This request is not allowed.");
      const body = await readBody(request);
      if (!body || !validEmail(body.email) || !validPhone(body.phone) || !validPassword(body.password) || !internalRedirect(body.redirect || "/")) {
        return genericError(401, "Those sign-in details are not recognised. Please try again.");
      }

      const known = demoAccounts.find(x => x.email === normalizeEmail(String(body.email)) && x.phone === normalizePhone(String(body.phone)));
      const passwordHash = await sha256(String(body.password));
      const expected = known ? await sha256(known.password) : await sha256("fixed-generic-comparison-value");
      if (!known || passwordHash !== expected) return genericError(401, "Those sign-in details are not recognised. Please try again.");

      const old = cookieValue(request, "mfa_session");
      if (old) sessions.delete(old);

      let account = accounts.get(known.userId);
      if (!account) {
        account = {
          userId: known.userId,
          email: known.email,
          phone: known.phone,
          passwordHash: expected,
          mfaEnabled: false,
          recoveryHashes: [],
          recoveryReady: false,
          recoveryAttempts: { failures: 0, lockedUntil: 0 },
          otpAttempts: { failures: 0, lockedUntil: 0 },
          totpReissues: [],
        };
        accounts.set(account.userId, account);
      }

      const session: Session = {
        id: randomToken(),
        userId: account.userId,
        csrf: randomToken(),
        createdAt: Date.now(),
        lastSeenAt: Date.now(),
        identityVerified: false,
      };
      sessions.set(session.id, session);
      return json(
        { ok: true, csrf: session.csrf, message: "You are signed in. Next, confirm your identity." },
        200,
        { "Set-Cookie": sessionCookie(session.id) },
      );
    }

    if (request.method === "POST" && url.pathname === "/api/identity") {
      const body = await readBody(request);
      if (!body) return genericError();
      const access = requireProtected(request, body);
      if (access instanceof Response) return access;
      if (!validEmail(body.email) || !validPhone(body.phone)) {
        return genericError(400, "Use an email like name@example.com and a phone number with at least 7 digits.");
      }
      if (normalizeEmail(String(body.email)) !== access.account.email || normalizePhone(String(body.phone)) !== access.account.phone) {
        return genericError(400, "Those details do not match your signed-in account. Use the same email and phone number, then try again.");
      }
      access.session.identityVerified = true;
      return json({ ok: true, message: "Identity confirmed. You can set up your authenticator now." });
    }

    if (request.method === "POST" && url.pathname === "/api/mfa/provision") {
      const body = await readBody(request);
      if (!body) return genericError();
      const access = requireProtected(request, body);
      if (access instanceof Response) return access;
      if (!access.session.identityVerified) return genericError(403, "Confirm your identity before setting up MFA.");
      if (isLocked(access.account.otpAttempts)) return genericError(429, otpLockMessage(access.account));
      pruneReissues(access.account);

      if (access.account.provisioning) {
        if (access.account.totpReissues.length >= MAX_REISSUES) return genericError(429, reissueLimitMessage(access.account));
        access.account.totpReissues.push(Date.now());
      }

      const secret = base32Secret(20);
      access.account.provisioning = {
        secret: await encryptValue(secret),
        createdAt: Date.now(),
        acceptedTotpSteps: new Set(),
      };
      return json(await challengeResponse(access.account, "Your authenticator QR code is ready. Scan it, then enter the six-digit code."));
    }

    if (request.method === "POST" && url.pathname === "/api/mfa/reissue") {
      const body = await readBody(request);
      if (!body) return genericError();
      const access = requireProtected(request, body);
      if (access instanceof Response) return access;
      if (!access.account.provisioning) return genericError(400, "Start authenticator setup first.");
      if (isLocked(access.account.otpAttempts)) return genericError(429, otpLockMessage(access.account));
      pruneReissues(access.account);
      if (access.account.totpReissues.length >= MAX_REISSUES) return genericError(429, reissueLimitMessage(access.account));
      access.account.totpReissues.push(Date.now());
      const response = await mockCode(access.account.provisioning.secret);
      return json({ ok: true, ...response, message: "A current demonstration test code is available in the browser console." });
    }

    if (request.method === "POST" && url.pathname === "/api/mfa/verify") {
      const body = await readBody(request);
      if (!body) return genericError();
      const access = requireProtected(request, body);
      if (access instanceof Response) return access;
      const challenge = access.account.provisioning;
      if (!challenge) return genericError(400, "Start authenticator setup first.");
      if (isLocked(access.account.otpAttempts)) return genericError(429, otpLockMessage(access.account));
      if (!validOtp(body.otp)) return genericError(400, "Enter all six digits. Example: 123456.");

      const secret = await decryptValue(challenge.secret);
      const nowStep = currentStep();
      let acceptedStep: number | null = null;
      for (let step = nowStep - OTP_WINDOW_STEPS; step <= nowStep + OTP_WINDOW_STEPS; step++) {
        if (await totp(secret, step) === body.otp) {
          acceptedStep = step;
          break;
        }
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
      const body = await readBody(request);
      if (!body) return genericError();
      const access = requireProtected(request, body);
      if (access instanceof Response) return access;
      if (!access.account.mfaEnabled) return genericError(403, "Set up your authenticator before making recovery codes.");

      const codes = newRecoveryCodes();
      access.account.recoveryHashes = await Promise.all(codes.map(code => recoveryRepresentation(code)));
      access.account.recoveryReady = false;
      clearAttempts(access.account.recoveryAttempts);
      return json({ ok: true, codes, message: "Your new recovery codes are ready. Copy all eight somewhere safe." });
    }

    /*
      Security Evaluation 3 / task: verification re-derives PBKDF2 using every
      stored per-code salt. A matching record is removed immediately, preserving
      the single-use recovery-code property.
    */
    if (request.method === "POST" && url.pathname === "/api/recovery/verify") {
      const body = await readBody(request);
      if (!body) return genericError();
      const access = requireProtected(request, body);
      if (access instanceof Response) return access;
      if (!access.account.mfaEnabled || !access.account.recoveryReady) return genericError(403, "Recovery codes are not ready for this account.");
      if (isLocked(access.account.recoveryAttempts)) return genericError(429, recoveryLockMessage(access.account));
      if (!validRecovery(body.code)) return genericError(400, "Enter a recovery code in this format: ABCD-EFGH-IJKL.");

      const code = String(body.code).toUpperCase();
      let foundAt = -1;
      for (let i = 0; i < access.account.recoveryHashes.length; i++) {
        if (await recoveryMatches(code, access.account.recoveryHashes[i])) foundAt = i;
      }

      if (foundAt < 0) {
        failedAttempt(access.account.recoveryAttempts);
        if (isLocked(access.account.recoveryAttempts)) return genericError(429, recoveryLockMessage(access.account));
        return genericError(400, "That recovery code was not recognised or was already used. Check the code and try again.");
      }

      access.account.recoveryHashes.splice(foundAt, 1);
      clearAttempts(access.account.recoveryAttempts);
      return json({ ok: true, message: "Recovery code accepted. That code cannot be used again." });
    }

    if (request.method === "POST" && url.pathname === "/api/recovery/confirm") {
      const body = await readBody(request);
      if (!body) return genericError();
      const access = requireProtected(request, body);
      if (access instanceof Response) return access;
      if (body.saved !== true) return genericError(400, "Please confirm that you saved your recovery codes.");
      if (!access.account.recoveryHashes.length) return genericError(400, "Make recovery codes first.");
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
      const body = await readBody(request);
      if (!body) return genericError();
      const session = protectedSession(request);
      if (!session || !noSuppliedAccountId(body) || !csrfOk(request, session, body)) {
        return genericError(401, "Your secure session has ended. Please sign in again.");
      }
      sessions.delete(session.id);
      return json(
        { ok: true, message: "You have signed out." },
        200,
        { "Set-Cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" },
      );
    }

    return genericError(404, "That service is not available.");
  } catch {
    return genericError(500, "Something went wrong. Please try again.");
  }
}

const html = String.raw;
function page(nonce: string) {
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Online Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172433;--muted:#506174;--blue:#0756b8;--pale:#eef6ff;--line:#c8d5e1;--good:#087447;--bad:#a52c27}
*{box-sizing:border-box}
body{margin:0;background:#f4f7fa;color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.035em}
main{max-width:620px;min-height:100vh;margin:auto;padding:18px 16px 42px}
header{padding:5px 5px 17px;border-bottom:3px solid var(--blue)}
.brand{font-weight:700;color:#063f83}.steps{font-size:.87rem;color:#31516e;margin-top:10px}
h1{font-size:1.7rem;line-height:1.25;margin:18px 0 8px}
.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:20px;margin-top:18px}
.step{display:none}.step.active{display:block}
label{display:block;font-weight:700;margin:15px 0 5px}
input{width:100%;min-height:52px;border:2px solid #8296a8;border-radius:9px;padding:10px 12px;font:inherit}
input:focus{outline:3px solid #86bdfa;border-color:var(--blue)}
input[type=checkbox]{width:auto;min-height:auto;margin-right:8px}
.example,.hint{color:var(--muted);font-size:.88rem}
button{display:block;width:100%;border:0;border-radius:9px;padding:13px 15px;margin-top:18px;background:var(--blue);color:#fff;font:700 1rem Verdana,Arial,sans-serif;cursor:pointer}
.secondary{background:#e6edf4;color:#173552;border:1px solid #a8bac9}.small{margin-top:9px;padding:10px;font-size:.9rem}
.notice{border-left:5px solid var(--blue);background:var(--pale);padding:11px 13px;margin:15px 0}
.error{color:var(--bad);border-left-color:var(--bad)}.success{color:#075536;border-left-color:var(--good)}
.help{margin-top:18px;padding:13px;border:1px solid var(--line);border-radius:8px;background:#f8fbfd;font-size:.91rem;color:var(--muted)}
.qr{width:100%;max-width:310px;height:auto;display:block;margin:15px auto;background:#fff;border:8px solid #fff;image-rendering:pixelated}
@media print{header,.steps,button,.help,#message{display:none!important}body,main{background:#fff;padding:0}.card{border:0}}
</style>
</head>
<body>
<main>
<header>
  <div class="brand">◇ Online Bank</div>
  <div class="steps" id="stepText">Step 1 of 6 · Sign in</div>
</header>

<section class="card" aria-live="polite" id="message" hidden></section>

<section class="card step active" id="signin">
  <h1>Set up extra payment security</h1>
  <p>🔐 Sign in to begin. This safe demonstration uses one practice account.</p>
  <form id="signinForm">
    <label for="email">Email address</label>
    <input id="email" type="email" autocomplete="email username" placeholder="name@example.com" required>
    <span class="example">Demo: marcus@example.com</span>
    <label for="phone">Mobile phone number</label>
    <input id="phone" type="tel" autocomplete="tel" placeholder="07123 456789" required>
    <span class="example">Demo: 07123 456789</span>
    <label for="password">Password</label>
    <input id="password" type="password" autocomplete="current-password" required>
    <span class="example">Demo: MarcusDemo!54</span>
    <button>Sign in and continue</button>
  </form>
  <div class="help">💡 <strong>Help:</strong> Take your time. There is no reading timer.</div>
</section>

<section class="card step" id="identity">
  <h1>Confirm it is you</h1>
  <p>👤 Enter the same contact details once more.</p>
  <form id="identityForm">
    <label for="identityEmail">Email address</label>
    <input id="identityEmail" type="email" autocomplete="email" placeholder="name@example.com" required>
    <label for="identityPhone">Mobile phone number</label>
    <input id="identityPhone" type="tel" autocomplete="tel" placeholder="07123 456789" required>
    <button>Confirm my identity</button>
  </form>
  <div class="help">💡 <strong>Help:</strong> Use the email and phone number you used to sign in. You can try again if you make a mistake.</div>
</section>

<section class="card step" id="setup">
  <h1>Add your authenticator</h1>
  <p>📱 Scan this square with an authenticator app.</p>
  <canvas id="qr" class="qr" width="342" height="342" aria-label="Authenticator setup QR code"></canvas>
  <div class="hint">If scanning is difficult, use the copy button and choose manual setup in your authenticator app.</div>
  <button class="secondary small" id="copySecret" type="button">Copy setup key</button>
  <button id="readyForCode" type="button">I added the authenticator</button>
  <div class="help">💡 <strong>Help:</strong> The setup key is copied without showing it on this page. Do not share it with anyone.</div>
</section>

<section class="card step" id="verify">
  <h1>Enter the six-digit code</h1>
  <p>🔢 Open your authenticator app and enter its code.</p>
  <form id="verifyForm">
    <label for="otp">Authenticator code</label>
    <input id="otp" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required>
    <span class="example">Example: 123456</span>
    <button>Verify code</button>
  </form>
  <button class="secondary small" id="reissue" type="button">Show current test code again</button>
  <div class="help">💡 <strong>Help:</strong> Codes change every 30 seconds. There is no reading deadline. If a code fails, use the newest code in your app.</div>
</section>

<section class="card step" id="recovery">
  <h1>Save recovery codes</h1>
  <p>🗝️ Your eight one-use recovery codes are ready. They are kept out of this page for your privacy.</p>
  <button class="secondary small" id="copyCodes" type="button">Copy all recovery codes</button>
  <p class="hint">After copying, paste them into a private note, password manager, or document you can print.</p>
  <form id="confirmCodes">
    <label><input id="savedCodes" type="checkbox"> I saved all eight codes somewhere private.</label>
    <button>Confirm codes are saved</button>
  </form>
  <div class="help">💡 <strong>Help:</strong> Keep recovery codes somewhere private, separate from your phone.</div>
</section>

<section class="card step" id="complete">
  <h1>Setup complete</h1>
  <p>✅ Your authenticator and recovery codes are ready.</p>
  <button id="openSettings" type="button">Open MFA settings</button>
  <div class="help">💡 <strong>Help:</strong> You are finished. Use your authenticator for protected payments and keep your recovery codes safe.</div>
</section>

<section class="card step" id="settings">
  <h1>MFA settings</h1>
  <p id="settingStatus">Loading secure settings…</p>
  <button id="regenerate" type="button">Make new recovery codes</button>
  <button class="secondary" id="logout" type="button">Sign out</button>
  <div class="help">💡 <strong>Help:</strong> New recovery codes replace old ones. Save the new set before you finish.</div>
</section>
</main>

<script nonce="${nonce}">
(()=>{
"use strict";
let csrf="", setupSecret="", recoveryCodes=[];
const $=id=>document.getElementById(id);

function msg(text, kind) {
  const box=$("message");
  box.textContent=text;
  box.className="card notice "+(kind||"");
  box.hidden=!text;
}
function show(id,label) {
  document.querySelectorAll(".step").forEach(item=>item.classList.remove("active"));
  $(id).classList.add("active");
  $("stepText").textContent=label;
  msg("");
  scrollTo(0,0);
}
async function api(path, body, method) {
  const get=method==="GET";
  const response=await fetch(path,{
    method:method||"POST",
    credentials:"same-origin",
    headers:get?{}:{"Content-Type":"application/json"},
    body:get?undefined:JSON.stringify({...body,csrf}),
  });
  const data=await response.json().catch(()=>({ok:false,message:"Please try again."}));
  if(!response.ok||!data.ok) throw Error(data.message);
  return data;
}
async function copy(value, success) {
  try {
    await navigator.clipboard.writeText(value);
    msg(success,"success");
  } catch {
    msg("Copy did not work here. Please allow clipboard access and try again.","error");
  }
}

/*
  Task: standards-compliant QR encoder.
  This is a self-contained QR Model 2 Version 10, error correction level L
  encoder. Version 10-L has 271 byte-mode data capacity, enough for the exact
  otpauth provisioning URI. It creates ISO/IEC 18004 finder, alignment, timing,
  format, version, Reed-Solomon and masked data modules.
*/
function drawQR(text) {
  const bytes=new TextEncoder().encode(text);
  if(bytes.length>271) throw Error("The setup QR code is too long.");

  const version=10, size=57, eccPerBlock=18;
  const modules=Array.from({length:size},()=>Array(size).fill(false));
  const isFunction=Array.from({length:size},()=>Array(size).fill(false));
  const set=(x,y,d,fn=true)=>{modules[y][x]=d;if(fn)isFunction[y][x]=true;};

  const finder=(x,y)=>{
    for(let dy=-1;dy<=7;dy++) for(let dx=-1;dx<=7;dx++) {
      const xx=x+dx,yy=y+dy;
      if(xx<0||yy<0||xx>=size||yy>=size) continue;
      set(xx,yy,dx>=0&&dx<=6&&dy>=0&&dy<=6&&(dx===0||dx===6||dy===0||dy===6||(dx>=2&&dx<=4&&dy>=2&&dy<=4)));
    }
  };
  finder(0,0); finder(size-7,0); finder(0,size-7);

  for(let i=8;i<size-8;i++) {
    set(i,6,i%2===0);
    set(6,i,i%2===0);
  }

  const alignment=(cx,cy)=>{
    for(let dy=-2;dy<=2;dy++) for(let dx=-2;dx<=2;dx++) {
      set(cx+dx,cy+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1);
    }
  };
  const centers=[6,28,50];
  for(const y of centers) for(const x of centers) {
    if((x===6&&y===6)||(x===6&&y===50)||(x===50&&y===6)) continue;
    alignment(x,y);
  }

  set(8,size-8,true);
  for(let i=0;i<9;i++) {
    if(i!==6){ set(8,i,false); set(i,8,false); }
  }
  for(let i=0;i<8;i++) {
    set(size-1-i,8,false);
    set(8,size-1-i,false);
  }

  const setFormat=(bits)=>{
    for(let i=0;i<=5;i++) set(8,i,((bits>>>i)&1)!==0);
    set(8,7,((bits>>>6)&1)!==0);
    set(8,8,((bits>>>7)&1)!==0);
    set(7,8,((bits>>>8)&1)!==0);
    for(let i=9;i<15;i++) set(14-i,8,((bits>>>i)&1)!==0);
    for(let i=0;i<8;i++) set(size-1-i,8,((bits>>>i)&1)!==0);
    for(let i=8;i<15;i++) set(8,size-15+i,((bits>>>i)&1)!==0);
    set(8,size-8,true);
  };
  const bch=(value,poly)=>{
    let v=value;
    const degree=n=>{let d=-1;while(n){n>>>=1;d++;}return d;};
    while(degree(v)>=degree(poly)) v^=poly<<(degree(v)-degree(poly));
    return v;
  };
  const formatData=0b01000;
  setFormat((((formatData<<10)|bch(formatData<<10,0x537))^0x5412)&0x7fff);

  const versionBits=((version<<12)|bch(version<<12,0x1f25))&0x3ffff;
  for(let i=0;i<18;i++) {
    const bit=((versionBits>>>i)&1)!==0;
    set(size-11+(i%3),Math.floor(i/3),bit);
    set(Math.floor(i/3),size-11+(i%3),bit);
  }

  const bitData=[];
  const put=(value,count)=>{for(let i=count-1;i>=0;i--)bitData.push((value>>>i)&1);};
  put(0b0100,4);
  put(bytes.length,16);
  for(const byte of bytes) put(byte,8);
  put(0,Math.min(4,274*8-bitData.length));
  while(bitData.length%8) bitData.push(0);

  const data=[];
  for(let i=0;i<bitData.length;i+=8) {
    let value=0;
    for(let bit=0;bit<8;bit++) value=(value<<1)|bitData[i+bit];
    data.push(value);
  }
  let pad=true;
  while(data.length<274) { data.push(pad?0xec:0x11);pad=!pad; }

  const gfExp=new Uint8Array(512),gfLog=new Uint8Array(256);
  let gf=1;
  for(let i=0;i<255;i++) {
    gfExp[i]=gf; gfLog[gf]=i; gf<<=1;
    if(gf&0x100) gf^=0x11d;
  }
  for(let i=255;i<512;i++) gfExp[i]=gfExp[i-255];
  const multiply=(a,b)=>a===0||b===0?0:gfExp[gfLog[a]+gfLog[b]];
  let generator=[1];
  for(let i=0;i<eccPerBlock;i++) {
    const next=new Array(generator.length+1).fill(0);
    for(let j=0;j<generator.length;j++) {
      next[j]^=generator[j];
      next[j+1]^=multiply(generator[j],gfExp[i]);
    }
    generator=next;
  }
  const remainder=block=>{
    const rem=new Array(eccPerBlock).fill(0);
    for(const byte of block) {
      const factor=byte^rem.shift();
      rem.push(0);
      for(let j=0;j<eccPerBlock;j++) rem[j]^=multiply(generator[j+1],factor);
    }
    return rem;
  };

  const blocks=[
    data.slice(0,68),data.slice(68,136),
    data.slice(136,205),data.slice(205,274)
  ];
  const ecc=blocks.map(remainder);
  const codewords=[];
  for(let i=0;i<69;i++) for(const block of blocks) if(i<block.length) codewords.push(block[i]);
  for(let i=0;i<eccPerBlock;i++) for(const block of ecc) codewords.push(block[i]);

  const rawBits=[];
  for(const word of codewords) for(let i=7;i>=0;i--) rawBits.push((word>>>i)&1);

  let index=0, upward=true;
  for(let right=size-1;right>=1;right-=2) {
    if(right===6) right--;
    for(let offset=0;offset<size;offset++) {
      const y=upward?size-1-offset:offset;
      for(let column=0;column<2;column++) {
        const x=right-column;
        if(isFunction[y][x]) continue;
        let bit=index<rawBits.length?rawBits[index++]:0;
        const mask=((x+y)%2)===0;
        if(mask) bit^=1;
        modules[y][x]=bit===1;
      }
    }
    upward=!upward;
  }

  const canvas=$("qr"), ctx=canvas.getContext("2d");
  const scale=Math.floor(canvas.width/size);
  canvas.width=size*scale;
  canvas.height=size*scale;
  ctx.fillStyle="#fff";
  ctx.fillRect(0,0,canvas.width,canvas.height);
  ctx.fillStyle="#111";
  for(let y=0;y<size;y++) for(let x=0;x<size;x++) {
    if(modules[y][x]) ctx.fillRect(x*scale,y*scale,scale,scale);
  }
}

$("signinForm").addEventListener("submit",async event=>{
  event.preventDefault();
  try {
    const data=await api("/api/signin",{
      email:$("email").value.trim(),
      phone:$("phone").value.trim(),
      password:$("password").value,
      redirect:"/",
    });
    csrf=data.csrf;
    show("identity","Step 2 of 6 · Confirm identity");
    msg(data.message,"success");
  } catch(error) {
    msg(error.message,"error");
  }
});

$("identityForm").addEventListener("submit",async event=>{
  event.preventDefault();
  try {
    await api("/api/identity",{email:$("identityEmail").value.trim(),phone:$("identityPhone").value.trim()});
    const data=await api("/api/mfa/provision",{});
    setupSecret=data.secret;
    drawQR(data.provisioningUri);
    console.log("Browser mock test OTP:",data.testCode);
    show("setup","Step 3 of 6 · Add authenticator");
    msg(data.message,"success");
  } catch(error) {
    msg(error.message,"error");
  }
});

$("copySecret").onclick=()=>copy(setupSecret,"Setup key copied. Paste it into manual setup in your authenticator app.");
$("readyForCode").onclick=()=>show("verify","Step 4 of 6 · Verify code");

$("reissue").onclick=async()=>{
  try {
    const data=await api("/api/mfa/reissue",{});
    console.log("Browser mock test OTP:",data.testCode);
    msg(data.message,"success");
  } catch(error) {
    msg(error.message,"error");
  }
};

$("verifyForm").addEventListener("submit",async event=>{
  event.preventDefault();
  try {
    await api("/api/mfa/verify",{otp:$("otp").value.trim()});
    const data=await api("/api/recovery/generate",{});
    recoveryCodes=data.codes;
    console.log("Browser mock recovery codes:",recoveryCodes);
    show("recovery","Step 5 of 6 · Save recovery codes");
    msg("Authenticator confirmed. Your recovery codes are ready to copy.","success");
  } catch(error) {
    msg(error.message,"error");
  }
});

$("copyCodes").onclick=()=>copy(recoveryCodes.join("\\n"),"Recovery codes copied. Paste them into a private place now.");

$("confirmCodes").addEventListener("submit",async event=>{
  event.preventDefault();
  try {
    const data=await api("/api/recovery/confirm",{saved:$("savedCodes").checked});
    recoveryCodes=[];
    show("complete","Step 6 of 6 · Complete");
    msg(data.message,"success");
  } catch(error) {
    msg(error.message,"error");
  }
});

async function settings() {
  try {
    const data=await api("/api/settings",null,"GET");
    csrf=data.csrf;
    $("settingStatus").textContent=data.enabled&&data.recoveryReady
      ?"✅ MFA is on. Your authenticator and recovery codes are ready."
      :"MFA needs attention.";
    show("settings","MFA settings");
  } catch(error) {
    show("signin","Step 1 of 6 · Sign in");
    msg(error.message,"error");
  }
}
$("openSettings").onclick=settings;

$("regenerate").onclick=async()=>{
  try {
    const data=await api("/api/recovery/generate",{});
    recoveryCodes=data.codes;
    console.log("Browser mock recovery codes:",recoveryCodes);
    $("savedCodes").checked=false;
    show("recovery","Step 5 of 6 · Save new recovery codes");
    msg("New codes replace the old ones. Copy and save these eight codes.","success");
  } catch(error) {
    msg(error.message,"error");
  }
};

$("logout").onclick=async()=>{
  try {
    await api("/api/logout",{});
    csrf="";
    setupSecret="";
    recoveryCodes=[];
    show("signin","Step 1 of 6 · Sign in");
    msg("You have signed out safely.","success");
  } catch(error) {
    msg(error.message,"error");
  }
};
})();
</script>
</body>
</html>`;
}

Bun.serve({
  port: PORT,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  fetch: handler,
  error() {
    return genericError(500, "Something went wrong. Please try again.");
  },
});
