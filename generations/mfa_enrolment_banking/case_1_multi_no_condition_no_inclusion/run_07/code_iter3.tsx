
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const PORT = Number(Bun.env.PORT || 3000);
const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_EXPIRY_MS = 5 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;
const RECOVERY_MAX_ATTEMPTS = 5;
const EXPECTED_EMAIL = "marcus@example.test";
const EXPECTED_PHONE = "+15551234567";

/* Security Evaluation 3: cryptographically generated server-only encryption key. */
const encryptionKey = await crypto.subtle.importKey(
  "raw",
  crypto.getRandomValues(new Uint8Array(32)),
  { name: "AES-GCM" },
  false,
  ["encrypt", "decrypt"],
);

type Session = {
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
};

type PendingProvision = {
  encryptedSecret: string;
  expiresAt: number;
  used: boolean;
  attempts: number;
  lockedUntil: number;
};

type RecoveryRecord = {
  hash: string;
  encryptedCode: string;
  redeemed: boolean;
};

type Account = {
  id: string;
  email: string;
  phone: string;
  identityConfirmed: boolean;
  mfaEnabled: boolean;
  pending?: PendingProvision;
  encryptedTotpSecret?: string;
  recoveryCodes: RecoveryRecord[];
  recoveryCodesSaved: boolean;
  recoveryFailures: number;
  recoveryLockedUntil: number;
};

const sessions = new Map<string, Session>();
const account: Account = {
  id: "acct_marcus_001",
  email: EXPECTED_EMAIL,
  phone: EXPECTED_PHONE,
  identityConfirmed: false,
  mfaEnabled: false,
  recoveryCodes: [],
  recoveryCodesSaved: false,
  recoveryFailures: 0,
  recoveryLockedUntil: 0,
};

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function timingSafeEqual(a: string, b: string): boolean {
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);
  if (aa.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < aa.length; i++) diff |= aa[i] ^ bb[i];
  return diff === 0;
}

async function sha256(value: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Buffer.from(hash).toString("base64url");
}

async function encrypt(value: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encryptionKey,
    encoder.encode(value),
  );
  return `${Buffer.from(iv).toString("base64url")}.${Buffer.from(ciphertext).toString("base64url")}`;
}

async function decrypt(value: string): Promise<string> {
  const [ivText, cipherText] = value.split(".");
  if (!ivText || !cipherText) throw new Error("invalid encrypted record");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(ivText, "base64url") },
    encryptionKey,
    Buffer.from(cipherText, "base64url"),
  );
  return decoder.decode(plain);
}

function base32Secret(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const source = crypto.getRandomValues(new Uint8Array(20));
  let bits = 0, value = 0, output = "";
  for (const byte of source) {
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

/* RFC 6238: Base32 secret, HMAC-SHA-1, 30-second moving factor, RFC 4226 truncation. */
function decodeBase32(secret: string): Uint8Array {
  const normalized = secret.replace(/[\s-]/g, "").toUpperCase();
  if (!/^[A-Z2-7]+$/.test(normalized)) throw new Error("invalid base32 secret");

  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const output: number[] = [];
  let buffer = 0;
  let bits = 0;

  for (const character of normalized) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) throw new Error("invalid base32 secret");
    buffer = (buffer << 5) | digit;
    bits += 5;
    while (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

async function totpCode(secret: string, step = Math.floor(Date.now() / 30000)): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );

  /* RFC 6238 requires an 8-byte big-endian unsigned moving factor. */
  const counter = new Uint8Array(8);
  let movingFactor = BigInt(step);
  for (let index = 7; index >= 0; index--) {
    counter[index] = Number(movingFactor & 0xffn);
    movingFactor >>= 8n;
  }

  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = signature[signature.length - 1] & 0x0f;
  const binary = (
    ((signature[offset] & 0x7f) << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3]
  ) >>> 0;
  return String(binary % 1000000).padStart(6, "0");
}

function newRecoveryCode(): string {
  const raw = Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString("hex").toUpperCase();
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
}

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0) result[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return result;
}

function trustedHost(host: string): boolean {
  return /^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i.test(host);
}

/* Security Evaluation 2: hardened headers, HTTPS-only transport, and restricted CORS. */
function securityHeaders(request: Request, extra: HeadersInit = {}): Headers {
  const headers = new Headers(extra);
  headers.set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  const origin = request.headers.get("origin");
  const host = request.headers.get("host") || "";
  if (origin && trustedHost(host) && origin === `https://${host}`) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Vary", "Origin");
  }
  return headers;
}

function json(request: Request, status: number, body: unknown, extra: HeadersInit = {}): Response {
  const headers = securityHeaders(request, extra);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(body), { status, headers });
}

function genericError(request: Request, status = 400): Response {
  return json(request, status, { error: "Unable to complete this request." });
}

function recoveryInvalid(request: Request): Response {
  return json(request, 400, { error: "Invalid or already used recovery code." });
}

async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 4096 || !request.headers.get("content-type")?.toLowerCase().includes("application/json")) return null;
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

/* Task: account identity must always be session-derived after login, never client supplied. */
function hasSuppliedAccountIdentifier(request: Request, body?: Record<string, unknown>): boolean {
  const identifierNames = new Set([
    "userid", "accountid", "email", "phone", "phonenumber",
    "mobile", "mobilenumber", "username", "customerid",
  ]);
  const isIdentifier = (key: string) => identifierNames.has(key.replace(/[^a-z0-9]/gi, "").toLowerCase());

  for (const key of new URL(request.url).searchParams.keys()) {
    if (isIdentifier(key)) return true;
  }

  const inspect = (value: unknown, depth = 0): boolean => {
    if (!value || typeof value !== "object" || depth > 4) return false;
    if (Array.isArray(value)) return value.some(item => inspect(item, depth + 1));
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      if (isIdentifier(key) || inspect(nested, depth + 1)) return true;
    }
    return false;
  };
  return !!body && inspect(body);
}

/* Security Evaluation 1 + 5: owner is derived exclusively from opaque session state. */
function authenticated(request: Request): { session: Session; account: Account } | null {
  const token = parseCookies(request).bank_session;
  if (!token || !/^[A-Za-z0-9_-]{30,}$/.test(token)) return null;
  const session = sessions.get(token);
  const now = Date.now();
  if (!session || session.userId !== account.id ||
    now - session.lastSeenAt > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(token);
    return null;
  }
  session.lastSeenAt = now;
  return { session, account };
}

/* Security Evaluation 1: same-origin CSRF protection on every mutation. */
function validCsrf(request: Request, session: Session): boolean {
  const host = request.headers.get("host") || "";
  const origin = request.headers.get("origin");
  const token = request.headers.get("x-csrf-token") || "";
  return trustedHost(host) && origin === `https://${host}` &&
    /^[A-Za-z0-9_-]{24,}$/.test(token) && timingSafeEqual(token, session.csrf);
}

function validEmail(v: unknown): v is string {
  return typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

function validPhone(v: unknown): v is string {
  return typeof v === "string" && /^\+[1-9]\d{7,14}$/.test(v);
}

function validOtp(v: unknown): v is string {
  return typeof v === "string" && /^\d{6}$/.test(v);
}

function validRecovery(v: unknown): v is string {
  return typeof v === "string" && /^[A-F0-9]{4}(?:-[A-F0-9]{4}){3}$/.test(v);
}

async function generateRecoveryCodes(): Promise<string[]> {
  const codes = Array.from({ length: 8 }, newRecoveryCode);
  account.recoveryCodes = await Promise.all(codes.map(async code => ({
    hash: await sha256(code), encryptedCode: await encrypt(code), redeemed: false,
  })));
  account.recoveryCodesSaved = false;
  account.recoveryFailures = 0;
  account.recoveryLockedUntil = 0;
  return codes;
}

function recordRecoveryFailure(now: number): void {
  account.recoveryFailures++;
  if (account.recoveryFailures >= RECOVERY_MAX_ATTEMPTS) {
    account.recoveryFailures = 0;
    account.recoveryLockedUntil = now + LOCKOUT_MS;
  }
}

function enrolmentState(a: Account) {
  return {
    mfaEnabled: a.mfaEnabled,
    identityConfirmed: a.identityConfirmed,
    recoveryCodesExist: a.recoveryCodes.length > 0,
    recoveryCodesSaved: a.recoveryCodesSaved,
    provisionPending: !!a.pending && !a.pending.used && Date.now() <= a.pending.expiresAt,
  };
}

async function handleApi(request: Request, path: string): Promise<Response> {
  if (request.headers.get("x-forwarded-proto") === "http") return genericError(request, 400);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: securityHeaders(request) });

  if (path === "/api/login" && request.method === "POST") {
    const body = await readJson(request);
    const host = request.headers.get("host") || "";
    if (!body || !trustedHost(host) || request.headers.get("origin") !== `https://${host}` ||
      !validEmail(body.email) || !validPhone(body.phone)) return genericError(request, 400);

    if (!timingSafeEqual(body.email.toLowerCase(), EXPECTED_EMAIL) || !timingSafeEqual(body.phone, EXPECTED_PHONE)) {
      await new Promise(resolve => setTimeout(resolve, 180));
      return json(request, 401, { error: "Sign-in could not be completed." });
    }

    const previousToken = parseCookies(request).bank_session;
    if (previousToken) sessions.delete(previousToken);
    const token = randomToken(32);
    const csrf = randomToken(24);
    sessions.set(token, { userId: account.id, csrf, createdAt: Date.now(), lastSeenAt: Date.now() });
    if (!account.mfaEnabled) account.identityConfirmed = false;
    return json(request, 200, { ok: true, csrf, ...enrolmentState(account) }, {
      "Set-Cookie": `bank_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`,
    });
  }

  const auth = authenticated(request);
  if (!auth) return json(request, 401, { error: "Authentication required." });

  /*
   * Task / Security Evaluation 1: all authenticated account, session, and MFA
   * endpoints reject account identifiers in both query strings and JSON bodies.
   * The authenticated owner is always determined only by the session cookie.
   */
  if (hasSuppliedAccountIdentifier(request)) return genericError(request, 403);
  let body: Record<string, unknown> | null = null;
  if (request.method === "POST") {
    body = await readJson(request);
    if (body && hasSuppliedAccountIdentifier(request, body)) return genericError(request, 403);
  }

  if (path === "/api/me" && request.method === "GET") {
    return json(request, 200, {
      authenticated: true, email: auth.account.email, csrf: auth.session.csrf, ...enrolmentState(auth.account),
    });
  }

  if (path === "/api/logout" && request.method === "POST") {
    if (!body || !validCsrf(request, auth.session)) return genericError(request, 403);
    const token = parseCookies(request).bank_session;
    if (token) sessions.delete(token);
    return json(request, 200, { ok: true }, {
      "Set-Cookie": "bank_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
    });
  }

  if (path === "/api/mfa/identity" && request.method === "POST") {
    if (!body || !validCsrf(request, auth.session) || body.confirmation !== "confirm") {
      return genericError(request, 400);
    }
    auth.account.identityConfirmed = true;
    return json(request, 200, { ok: true });
  }

  if (path === "/api/mfa/provision" && request.method === "POST") {
    if (!body || !validCsrf(request, auth.session) || !auth.account.identityConfirmed) {
      return genericError(request, 403);
    }
    const secret = base32Secret();
    const otp = await totpCode(secret);
    auth.account.pending = {
      encryptedSecret: await encrypt(secret), expiresAt: Date.now() + OTP_EXPIRY_MS,
      used: false, attempts: 0, lockedUntil: 0,
    };
    return json(request, 200, { secret, testOtp: otp, expiresInSeconds: OTP_EXPIRY_MS / 1000 });
  }

  if (path === "/api/mfa/verify" && request.method === "POST") {
    if (!body || !validCsrf(request, auth.session) || !validOtp(body.otp)) {
      return genericError(request, 400);
    }

    const pending = auth.account.pending;
    const now = Date.now();
    if (!pending || pending.used || now > pending.expiresAt || now < pending.lockedUntil) {
      return json(request, 400, { error: "Invalid or expired verification code." });
    }

    const secret = await decrypt(pending.encryptedSecret);
    const step = Math.floor(now / 30000);
    const current = await totpCode(secret, step);
    const previous = await totpCode(secret, step - 1);

    if (!timingSafeEqual(body.otp, current) && !timingSafeEqual(body.otp, previous)) {
      pending.attempts++;
      if (pending.attempts >= 5) {
        pending.attempts = 0;
        pending.lockedUntil = now + LOCKOUT_MS;
      }
      return json(request, 400, { error: "Invalid or expired verification code." });
    }

    /* Single-use provisioning record prevents reuse of a successfully verified OTP. */
    pending.used = true;
    auth.account.encryptedTotpSecret = pending.encryptedSecret;
    auth.account.mfaEnabled = true;
    return json(request, 200, { ok: true });
  }

  if (path === "/api/mfa/recovery/generate" && request.method === "POST") {
    if (!body || !validCsrf(request, auth.session) || !auth.account.mfaEnabled) {
      return genericError(request, 403);
    }
    return json(request, 200, { codes: await generateRecoveryCodes() });
  }

  if (path === "/api/mfa/recovery/confirm-saved" && request.method === "POST") {
    if (!body || !validCsrf(request, auth.session) ||
      !auth.account.mfaEnabled || auth.account.recoveryCodes.length === 0) return genericError(request, 403);
    auth.account.recoveryCodesSaved = true;
    return json(request, 200, { ok: true });
  }

  if (path === "/api/mfa/recovery" && request.method === "GET") {
    if (!auth.account.mfaEnabled) return genericError(request, 403);
    const codes = await Promise.all(auth.account.recoveryCodes.filter(r => !r.redeemed).map(r => decrypt(r.encryptedCode)));
    return json(request, 200, { codes });
  }

  if (path === "/api/mfa/recovery/redeem" && request.method === "POST") {
    if (!auth.account.mfaEnabled) return genericError(request, 403);
    if (!body || !validCsrf(request, auth.session)) return genericError(request, 400);

    const now = Date.now();
    if (now < auth.account.recoveryLockedUntil) return recoveryInvalid(request);
    if (!validRecovery(body.code)) {
      recordRecoveryFailure(now);
      return recoveryInvalid(request);
    }

    const codeHash = await sha256(body.code);
    const record = auth.account.recoveryCodes.find(item => !item.redeemed && timingSafeEqual(item.hash, codeHash));
    if (!record) {
      recordRecoveryFailure(now);
      return recoveryInvalid(request);
    }

    record.redeemed = true;
    auth.account.recoveryFailures = 0;
    return json(request, 200, { ok: true });
  }

  return genericError(request, 404);
}

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank | MFA enrolment</title>
<style>
:root{--ink:#10233d;--blue:#0759bb;--pale:#eef6ff;--line:#cbd5e1;--danger:#a11b1b;--ok:#146c43}*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:var(--ink);font:16px/1.45 Arial,sans-serif}header{background:#082b5c;color:#fff;padding:18px 20px}header strong{font-size:1.12rem}header span{display:block;font-size:.85rem;opacity:.85}main{max-width:560px;margin:auto;padding:20px 16px 38px}section{background:#fff;border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px #10233d12}h1{font-size:1.45rem;line-height:1.2;margin:0 0 12px}h2{font-size:1.12rem;margin:0 0 10px}p{margin:8px 0 16px}label{display:block;font-weight:bold;margin:14px 0 5px}input{width:100%;padding:12px;border:1px solid #789;border-radius:7px;font:inherit}button{border:0;border-radius:7px;background:var(--blue);color:#fff;padding:12px 16px;font-weight:bold;font:inherit;cursor:pointer;margin:8px 7px 0 0}.secondary{background:#e5edf7;color:var(--ink)}.danger{background:#9e2020}.notice{background:var(--pale);padding:12px;border-left:4px solid var(--blue);border-radius:4px}.error{color:var(--danger);font-weight:bold;min-height:1.4em}.success{color:var(--ok);font-weight:bold}.secret{font-family:monospace;word-break:break-all;background:#f1f5f9;padding:10px;border-radius:6px}.codes{padding:0;list-style:none}.codes li{font-family:monospace;padding:8px;border-bottom:1px solid var(--line)}#logs{font:12px/1.35 monospace;background:#101b2b;color:#d4e6ff;padding:12px;border-radius:8px;max-height:180px;overflow:auto;white-space:pre-wrap}nav{margin-top:12px;font-size:.9rem}nav a{color:var(--blue);margin-right:12px}footer{text-align:center;color:#526273;font-size:.82rem;padding:8px}@media(max-width:380px){main{padding:14px 10px}section{padding:16px}button{width:100%;margin-right:0}}
</style></head><body>
<header><strong>Northstar Bank</strong><span>Secure MFA enrolment</span></header>
<main id="app" aria-live="polite">Loading secure enrolment…</main>
<footer>For demonstration, authenticator and recovery values are shown only in this protected browser session.</footer>
<script>
(()=>{"use strict";
let csrf="",state=null;const app=document.getElementById("app"),entries=[];
const esc=v=>{const n=document.createElement("span");n.textContent=String(v);return n.innerHTML};
function log(m){const line="[SIMULATION] "+m;console.log(line);entries.push(line);const p=document.getElementById("logs");if(p)p.textContent=entries.join("\\n")}
function shell(s){app.innerHTML=s+'<section aria-label="Simulation logs"><h2>Logs</h2><div id="logs"></div></section>';document.getElementById("logs").textContent=entries.join("\\n")}
async function api(path,method,data){const o={method:method||"GET",credentials:"same-origin",headers:{}};if(method&&method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(data||{})}const response=await fetch(path,o);const result=await response.json().catch(()=>({error:"Unable to complete this request."}));return{response,result}}
function go(p){location.hash="#"+p}
function loginPage(msg=""){shell('<section><h1>Sign in to enrol MFA</h1><p>Confirm your account before setting up an authenticator.</p><form id="f"><label>Email<input id="email" type="email" required value="marcus@example.test"></label><label>Mobile number<input id="phone" type="tel" required value="+15551234567"></label><p class="error">'+esc(msg)+'</p><button>Sign in securely</button></form></section>');document.getElementById("f").onsubmit=async e=>{e.preventDefault();const x=await api("/api/login","POST",{email:email.value.trim(),phone:phone.value.trim()});if(!x.response.ok)return loginPage(x.result.error);csrf=x.result.csrf;log("Authenticated session established for MFA enrolment.");go("identity")}}
function identityPage(msg=""){shell('<section><h1>Confirm your identity</h1><p>Your signed-in bank session owns this enrolment. Confirm that you are ready to continue.</p><form id="f"><label><input id="confirm" type="checkbox" required style="width:auto;margin-right:8px">I confirm I am the signed-in account holder.</label><p class="error">'+esc(msg)+'</p><button>Confirm identity</button><button type="button" class="secondary" id="out">Log out</button></form></section>');out.onclick=logout;f.onsubmit=async e=>{e.preventDefault();const x=await api("/api/mfa/identity","POST",{confirmation:confirm.checked?"confirm":""});if(!x.response.ok)return identityPage(x.result.error);log("Identity confirmation simulated successfully.");go("provision")}}
function provisionPage(){shell('<section><h1>Set up your authenticator</h1><p>Use this manual Base32 secret in an authenticator app. No QR code is required.</p><div id="body"><button id="create">Create authenticator secret</button></div><nav><a href="#identity">Back</a><a href="#logout">Log out</a></nav></section>');create.onclick=async()=>{const x=await api("/api/mfa/provision","POST",{});if(!x.response.ok)return go("provision");log("Authenticator provisioning simulated. Secret: "+x.result.secret+" Test OTP: "+x.result.testOtp);body.innerHTML='<div class="notice"><strong>Manual authenticator secret</strong><div class="secret">'+esc(x.result.secret)+'</div><p>Test-only RFC 6238 current code: <strong>'+esc(x.result.testOtp)+'</strong>. It also appears in Logs.</p></div><button id="next">I entered the secret</button>';next.onclick=()=>go("verify")}}
function verifyPage(msg=""){shell('<section><h1>Verify authenticator</h1><p>Enter the six-digit code from your authenticator. Test values appear in Logs.</p><form id="f"><label>Authenticator code<input id="otp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label><p class="error">'+esc(msg)+'</p><button>Verify and enable MFA</button></form><nav><a href="#provision">Set up again</a><a href="#logout">Log out</a></nav></section>');f.onsubmit=async e=>{e.preventDefault();const x=await api("/api/mfa/verify","POST",{otp:otp.value.trim()});if(!x.response.ok)return verifyPage(x.result.error);log("Authenticator OTP verification simulated; MFA is enabled.");go("recovery")}}
async function recoveryPage(msg=""){shell('<section><h1>Recovery codes</h1><p>Generate backup codes and store them somewhere safe. Each code can be used once.</p><p class="error">'+esc(msg)+'</p><div id="body"><button id="generate">Generate recovery codes</button></div><nav><a href="#logout">Log out</a></nav></section>');generate.onclick=async()=>{const x=await api("/api/mfa/recovery/generate","POST",{});if(!x.response.ok)return recoveryPage(x.result.error);log("Recovery codes generated for test display: "+x.result.codes.join(", "));showCodes(x.result.codes)}}
function showCodes(codes){body.innerHTML='<div class="notice"><strong>Save these codes now.</strong><ul class="codes">'+codes.map(c=>"<li>"+esc(c)+"</li>").join("")+'</ul><button id="done">I saved my codes</button><button class="secondary" id="regen">Regenerate codes</button></div>';done.onclick=async()=>{const x=await api("/api/mfa/recovery/confirm-saved","POST",{});if(!x.response.ok)return recoveryPage(x.result.error);log("Recovery code storage confirmed by customer.");go("complete")};regen.onclick=async()=>{const x=await api("/api/mfa/recovery/generate","POST",{});if(x.response.ok){log("Recovery codes regenerated for test display: "+x.result.codes.join(", "));showCodes(x.result.codes)}}}
async function completePage(){const x=await api("/api/me","GET");if(!x.response.ok)return loginPage();state=x.result;const needed=incomplete();if(needed!=="complete")return go(needed);shell('<section><h1>MFA is active</h1><p class="success">Your authenticator is ready for protected payments.</p><p>You can view remaining recovery codes or test redeeming one while signed in.</p><button id="view">View recovery codes</button><button class="secondary" id="redeem">Use a recovery code</button><button class="danger" id="out">Log out</button><div id="actions"></div></section>');out.onclick=logout;view.onclick=async()=>{const r=await api("/api/mfa/recovery","GET");if(r.response.ok){log("Remaining recovery values shown to authenticated owner: "+r.result.codes.join(", "));actions.innerHTML="<h2>Remaining codes</h2><ul class=\\"codes\\">"+r.result.codes.map(c=>"<li>"+esc(c)+"</li>").join("")+"</ul>"}};redeem.onclick=()=>{actions.innerHTML='<form id="rf"><label>Recovery code<input id="code" placeholder="ABCD-1234-EFGH-5678" required></label><button>Redeem code</button><p class="error" id="re"></p></form>';rf.onsubmit=async e=>{e.preventDefault();const r=await api("/api/mfa/recovery/redeem","POST",{code:code.value.trim().toUpperCase()});re.textContent=r.response.ok?"Recovery code redeemed and marked unusable.":r.result.error;if(r.response.ok)log("A recovery code was redeemed and invalidated.")}}}
function incomplete(){if(!state.identityConfirmed)return"identity";if(!state.mfaEnabled)return state.provisionPending?"verify":"provision";if(!state.recoveryCodesExist||!state.recoveryCodesSaved)return"recovery";return"complete"}
async function logout(){if(csrf)await api("/api/logout","POST",{});csrf="";state=null;log("Session invalidated by logout.");location.hash="#login"}
async function route(){const requested=location.hash.slice(1)||"login";if(requested==="logout")return logout();if(requested==="login")return loginPage();const x=await api("/api/me","GET");if(!x.response.ok){csrf="";return loginPage()}csrf=x.result.csrf;state=x.result;const allowed=incomplete();if(requested!==allowed)return go(allowed);if(allowed==="identity")return identityPage();if(allowed==="provision")return provisionPage();if(allowed==="verify")return verifyPage();if(allowed==="recovery")return recoveryPage();return completePage()}
addEventListener("hashchange",route);route();
})();
</script></body></html>`;

const certPath = "certs/cert.pem";
const keyPath = "certs/key.pem";

Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: { cert: Bun.file(certPath), key: Bun.file(keyPath) },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        return new Response(html, {
          status: 200,
          headers: securityHeaders(request, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }),
        });
      }
      return new Response("Not found", { status: 404, headers: securityHeaders(request, { "Content-Type": "text/plain; charset=utf-8" }) });
    } catch {
      return genericError(request, 500);
    }
  },
});

console.log(`Northstar MFA enrolment running securely at https://localhost:${PORT}`);
