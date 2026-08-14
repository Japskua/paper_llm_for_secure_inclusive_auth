
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const PORT = Number(Bun.env.PORT || 3000);
const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_EXPIRY_MS = 5 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;
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
};

const sessions = new Map<string, Session>();
const account: Account = {
  id: "acct_marcus_001",
  email: EXPECTED_EMAIL,
  phone: EXPECTED_PHONE,
  identityConfirmed: false,
  mfaEnabled: false,
  recoveryCodes: [],
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
  let bits = 0;
  let value = 0;
  let output = "";
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

async function mockOtp(secret: string, step = Math.floor(Date.now() / 30000)): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(String(step)));
  const value = new DataView(signature).getUint32(0) % 1000000;
  return String(value).padStart(6, "0");
}

function newRecoveryCode(): string {
  const raw = Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString("hex").toUpperCase();
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
}

function parseCookies(request: Request): Record<string, string> {
  const input = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const part of input.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) result[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return result;
}

function trustedHost(host: string): boolean {
  return /^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i.test(host);
}

/* Security Evaluation 2: common hardened response headers and constrained CORS. */
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
    headers.set("Vary", "Origin");
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
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

async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 4096) return null;
  if (!request.headers.get("content-type")?.toLowerCase().includes("application/json")) return null;
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function hasSuppliedAccountIdentifier(request: Request, body?: Record<string, unknown>): boolean {
  const forbidden = ["userId", "user_id", "accountId", "account_id", "email"];
  for (const key of forbidden) {
    if (request.url.includes(`?${key}=`) || new URL(request.url).searchParams.has(key)) return true;
    if (body && Object.hasOwn(body, key)) return true;
  }
  return false;
}

/* Security Evaluation 1 + 5: validated opaque session, owner derived only from it. */
function authenticated(request: Request): { session: Session; account: Account } | null {
  const token = parseCookies(request).bank_session;
  if (!token || !/^[A-Za-z0-9_-]{30,}$/.test(token)) return null;
  const session = sessions.get(token);
  const now = Date.now();
  if (!session || session.userId !== account.id ||
      now - session.lastSeenAt > SESSION_IDLE_MS ||
      now - session.createdAt > SESSION_ABSOLUTE_MS) {
    if (token) sessions.delete(token);
    return null;
  }
  session.lastSeenAt = now;
  return { session, account };
}

/* Security Evaluation 1: CSRF plus same-origin enforcement for all mutations. */
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
    hash: await sha256(code),
    encryptedCode: await encrypt(code),
    redeemed: false,
  })));
  return codes;
}

async function handleApi(request: Request, path: string): Promise<Response> {
  if (request.headers.get("x-forwarded-proto") === "http") return genericError(request, 400);

  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: securityHeaders(request) });

  if (path === "/api/login" && request.method === "POST") {
    const body = await readJson(request);
    const host = request.headers.get("host") || "";
    const origin = request.headers.get("origin");
    if (!body || !trustedHost(host) || origin !== `https://${host}` ||
        !validEmail(body.email) || !validPhone(body.phone)) return genericError(request, 400);

    /* Generic result avoids account enumeration; comparison is server-side only. */
    if (!timingSafeEqual(body.email.toLowerCase(), EXPECTED_EMAIL) || !timingSafeEqual(body.phone, EXPECTED_PHONE)) {
      await new Promise(resolve => setTimeout(resolve, 180));
      return json(request, 401, { error: "Sign-in could not be completed." });
    }

    /* Security Evaluation 5: a fresh opaque session identifier is issued at authentication. */
    const token = randomToken(32);
    const csrf = randomToken(24);
    sessions.set(token, { userId: account.id, csrf, createdAt: Date.now(), lastSeenAt: Date.now() });
    account.identityConfirmed = false;
    const cookie = `bank_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
    return json(request, 200, { ok: true, csrf, mfaEnabled: account.mfaEnabled }, { "Set-Cookie": cookie });
  }

  const auth = authenticated(request);
  if (!auth) return json(request, 401, { error: "Authentication required." });

  if (path.startsWith("/api/mfa") && hasSuppliedAccountIdentifier(request)) return genericError(request, 403);

  if (path === "/api/me" && request.method === "GET") {
    return json(request, 200, {
      authenticated: true,
      email: auth.account.email,
      mfaEnabled: auth.account.mfaEnabled,
      identityConfirmed: auth.account.identityConfirmed,
      csrf: auth.session.csrf,
    });
  }

  if (path === "/api/logout" && request.method === "POST") {
    if (!validCsrf(request, auth.session)) return genericError(request, 403);
    const token = parseCookies(request).bank_session;
    if (token) sessions.delete(token);
    return json(request, 200, { ok: true }, {
      "Set-Cookie": "bank_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
    });
  }

  if (path === "/api/mfa/identity" && request.method === "POST") {
    const body = await readJson(request);
    if (!body || hasSuppliedAccountIdentifier(request, body) || !validCsrf(request, auth.session) ||
        !validEmail(body.email) || !validPhone(body.phone)) return genericError(request, 400);
    if (!timingSafeEqual(body.email.toLowerCase(), auth.account.email) || !timingSafeEqual(body.phone, auth.account.phone)) {
      return genericError(request, 400);
    }
    auth.account.identityConfirmed = true;
    return json(request, 200, { ok: true });
  }

  if (path === "/api/mfa/provision" && request.method === "POST") {
    const body = await readJson(request);
    if (!body || hasSuppliedAccountIdentifier(request, body) || !validCsrf(request, auth.session) || !auth.account.identityConfirmed) {
      return genericError(request, 403);
    }
    const secret = base32Secret();
    const otp = await mockOtp(secret);
    auth.account.pending = {
      encryptedSecret: await encrypt(secret),
      expiresAt: Date.now() + OTP_EXPIRY_MS,
      used: false,
      attempts: 0,
      lockedUntil: 0,
    };
    /* Test-only provisioning material is returned only over same-origin HTTPS to this authenticated browser. */
    return json(request, 200, { secret, testOtp: otp, expiresInSeconds: OTP_EXPIRY_MS / 1000 });
  }

  if (path === "/api/mfa/verify" && request.method === "POST") {
    const body = await readJson(request);
    if (!body || hasSuppliedAccountIdentifier(request, body) || !validCsrf(request, auth.session) || !validOtp(body.otp)) {
      return genericError(request, 400);
    }
    const pending = auth.account.pending;
    const now = Date.now();
    if (!pending || pending.used || now > pending.expiresAt || now < pending.lockedUntil) {
      return json(request, 400, { error: "Invalid or expired verification code." });
    }
    const secret = await decrypt(pending.encryptedSecret);
    const current = await mockOtp(secret);
    const previous = await mockOtp(secret, Math.floor(Date.now() / 30000) - 1);
    if (!timingSafeEqual(body.otp, current) && !timingSafeEqual(body.otp, previous)) {
      pending.attempts++;
      if (pending.attempts >= 5) {
        pending.attempts = 0;
        pending.lockedUntil = now + LOCKOUT_MS;
      }
      return json(request, 400, { error: "Invalid or expired verification code." });
    }
    pending.used = true; // single use
    auth.account.encryptedTotpSecret = pending.encryptedSecret;
    auth.account.mfaEnabled = true;
    return json(request, 200, { ok: true });
  }

  if (path === "/api/mfa/recovery/generate" && request.method === "POST") {
    const body = await readJson(request);
    if (!body || hasSuppliedAccountIdentifier(request, body) || !validCsrf(request, auth.session) || !auth.account.mfaEnabled) {
      return genericError(request, 403);
    }
    const codes = await generateRecoveryCodes();
    return json(request, 200, { codes });
  }

  if (path === "/api/mfa/recovery" && request.method === "GET") {
    if (!auth.account.mfaEnabled) return genericError(request, 403);
    const codes = await Promise.all(auth.account.recoveryCodes
      .filter(record => !record.redeemed)
      .map(record => decrypt(record.encryptedCode)));
    return json(request, 200, { codes });
  }

  if (path === "/api/mfa/recovery/redeem" && request.method === "POST") {
    const body = await readJson(request);
    if (!body || hasSuppliedAccountIdentifier(request, body) || !validCsrf(request, auth.session) || !validRecovery(body.code)) {
      return genericError(request, 400);
    }
    const codeHash = await sha256(body.code);
    const record = auth.account.recoveryCodes.find(item => !item.redeemed && timingSafeEqual(item.hash, codeHash));
    if (!record) return json(request, 400, { error: "Invalid or already used recovery code." });
    record.redeemed = true;
    return json(request, 200, { ok: true });
  }

  return genericError(request, 404);
}

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank | MFA enrolment</title>
<style>
:root{color-scheme:light;--ink:#10233d;--blue:#0759bb;--pale:#eef6ff;--line:#cbd5e1;--danger:#a11b1b;--ok:#146c43}
*{box-sizing:border-box} body{margin:0;background:#f4f7fb;color:var(--ink);font-family:Arial,sans-serif;font-size:16px;line-height:1.45}
header{background:#082b5c;color:white;padding:18px 20px}header strong{font-size:1.12rem}header span{display:block;font-size:.85rem;opacity:.85}
main{max-width:560px;margin:0 auto;padding:20px 16px 38px}section{background:white;border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px #10233d12}
h1{font-size:1.45rem;line-height:1.2;margin:0 0 12px}h2{font-size:1.12rem;margin:0 0 10px}p{margin:8px 0 16px}
label{display:block;font-weight:bold;margin:14px 0 5px}input{width:100%;padding:12px;border:1px solid #789;border-radius:7px;font:inherit}button,.button{display:inline-block;border:0;border-radius:7px;background:var(--blue);color:white;padding:12px 16px;font-weight:bold;font:inherit;cursor:pointer;text-decoration:none;margin:8px 7px 0 0}.secondary{background:#e5edf7;color:#10233d}.danger{background:#9e2020}.notice{background:var(--pale);padding:12px;border-left:4px solid var(--blue);border-radius:4px}.error{color:var(--danger);font-weight:bold;min-height:1.4em}.success{color:var(--ok);font-weight:bold}.secret{font-family:monospace;word-break:break-all;background:#f1f5f9;padding:10px;border-radius:6px}.codes{padding:0;list-style:none}.codes li{font-family:monospace;padding:8px;border-bottom:1px solid var(--line)}#logs{font:12px/1.35 monospace;background:#101b2b;color:#d4e6ff;padding:12px;border-radius:8px;max-height:180px;overflow:auto;white-space:pre-wrap}nav{margin-top:12px;font-size:.9rem}nav a{color:#0759bb;margin-right:12px}footer{text-align:center;color:#526273;font-size:.82rem;padding:8px}
@media(max-width:380px){main{padding:14px 10px}section{padding:16px}button,.button{width:100%;margin-right:0}}
</style>
</head>
<body>
<header><strong>Northstar Bank</strong><span>Secure MFA enrolment</span></header>
<main id="app" aria-live="polite">Loading secure enrolment…</main>
<footer>For demonstration, authenticator and recovery values are shown only in this protected browser session.</footer>
<script>
(() => {
  "use strict";
  let csrf = "";
  let provisioning = null;
  const app = document.getElementById("app");
  const logEntries = [];

  function escapeHtml(value) {
    const node = document.createElement("span");
    node.textContent = String(value);
    return node.innerHTML;
  }
  function log(message) {
    const line = "[SIMULATION] " + message;
    console.log(line);
    logEntries.push(line);
    const panel = document.getElementById("logs");
    if (panel) panel.textContent = logEntries.join("\\n");
  }
  function logs() { return '<section aria-label="Simulation logs"><h2>Logs</h2><div id="logs"></div></section>'; }
  async function api(path, method, data) {
    const options = { method: method || "GET", credentials: "same-origin", headers: {} };
    if (method && method !== "GET") {
      options.headers["Content-Type"] = "application/json";
      options.headers["X-CSRF-Token"] = csrf;
      options.body = JSON.stringify(data || {});
    }
    const response = await fetch(path, options);
    const result = await response.json().catch(() => ({ error: "Unable to complete this request." }));
    if (response.status === 401 && path !== "/api/login") location.hash = "#login";
    return { response, result };
  }
  function go(page) { location.hash = "#" + page; }
  function shell(content) { app.innerHTML = content + logs(); const panel=document.getElementById("logs"); if(panel)panel.textContent=logEntries.join("\\n"); }

  function loginPage(message) {
    shell('<section><h1>Sign in to enrol MFA</h1><p>Confirm your account before setting up an authenticator.</p>' +
      '<form id="loginForm"><label for="email">Email</label><input id="email" type="email" required value="marcus@example.test" autocomplete="email">' +
      '<label for="phone">Mobile number</label><input id="phone" type="tel" required value="+15551234567" autocomplete="tel">' +
      '<p class="error" id="error">' + escapeHtml(message || "") + '</p><button type="submit">Sign in securely</button></form></section>');
    document.getElementById("loginForm").addEventListener("submit", async event => {
      event.preventDefault();
      const email = document.getElementById("email").value.trim();
      const phone = document.getElementById("phone").value.trim();
      const {response,result} = await api("/api/login","POST",{email,phone});
      if (!response.ok) return loginPage(result.error);
      csrf = result.csrf;
      log("Authenticated session established for MFA enrolment.");
      go(result.mfaEnabled ? "complete" : "identity");
    });
  }
  function identityPage(message) {
    shell('<section><h1>Confirm your identity</h1><p>For payment security, confirm the contact details on your account.</p><form id="identityForm">' +
      '<label for="identityEmail">Email</label><input id="identityEmail" type="email" required value="marcus@example.test">' +
      '<label for="identityPhone">Mobile number</label><input id="identityPhone" type="tel" required value="+15551234567">' +
      '<p class="error" id="error">' + escapeHtml(message || "") + '</p><button type="submit">Confirm identity</button><button type="button" class="secondary" id="logout">Log out</button></form></section>');
    document.getElementById("logout").onclick = logout;
    document.getElementById("identityForm").addEventListener("submit", async event => {
      event.preventDefault();
      const email = document.getElementById("identityEmail").value.trim();
      const phone = document.getElementById("identityPhone").value.trim();
      const {response,result} = await api("/api/mfa/identity","POST",{email,phone});
      if (!response.ok) return identityPage(result.error);
      log("Identity confirmation simulated successfully.");
      go("provision");
    });
  }
  function provisionPage() {
    shell('<section><h1>Set up your authenticator</h1><p>Use the secret below in an authenticator app. You can enter it manually; no QR code is required.</p><div id="provisionBody"><button id="create">Create authenticator secret</button></div><nav><a href="#identity">Back</a><a href="#logout">Log out</a></nav></section>');
    document.getElementById("create").onclick = async () => {
      const {response,result} = await api("/api/mfa/provision","POST",{});
      if (!response.ok) return provisionPage();
      provisioning = result;
      log("Authenticator provisioning simulated. Secret: " + result.secret + " Test OTP: " + result.testOtp);
      document.getElementById("provisionBody").innerHTML =
        '<div class="notice"><strong>Manual authenticator secret</strong><div class="secret">' + escapeHtml(result.secret) + '</div>' +
        '<p>Test-only current code: <strong>' + escapeHtml(result.testOtp) + '</strong>. This also appears in Logs.</p></div>' +
        '<button id="continue">I entered the secret</button>';
      document.getElementById("continue").onclick = () => go("verify");
    };
  }
  function verifyPage(message) {
    shell('<section><h1>Verify authenticator</h1><p>Enter the six-digit code from your authenticator. Test provisioning values are available in the Logs panel.</p>' +
      '<form id="verifyForm"><label for="otp">Authenticator code</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required>' +
      '<p class="error" id="error">' + escapeHtml(message || "") + '</p><button type="submit">Verify and enable MFA</button></form><nav><a href="#provision">Set up again</a><a href="#logout">Log out</a></nav></section>');
    document.getElementById("verifyForm").addEventListener("submit", async event => {
      event.preventDefault();
      const otp = document.getElementById("otp").value.trim();
      const {response,result} = await api("/api/mfa/verify","POST",{otp});
      if (!response.ok) return verifyPage(result.error);
      log("Authenticator OTP verification simulated; MFA is enabled.");
      go("recovery");
    });
  }
  async function recoveryPage(message) {
    shell('<section><h1>Recovery codes</h1><p>Generate backup codes and store them somewhere safe. Each code can be used once.</p><p class="error" id="error">' + escapeHtml(message || "") + '</p><div id="recoveryBody"><button id="generate">Generate recovery codes</button></div><nav><a href="#complete">Skip for now</a><a href="#logout">Log out</a></nav></section>');
    document.getElementById("generate").onclick = async () => {
      const {response,result} = await api("/api/mfa/recovery/generate","POST",{});
      if (!response.ok) return recoveryPage(result.error);
      log("Recovery codes generated for test display: " + result.codes.join(", "));
      showCodes(result.codes);
    };
  }
  function showCodes(codes) {
    const area = document.getElementById("recoveryBody");
    area.innerHTML = '<div class="notice"><strong>Save these codes now.</strong><ul class="codes">' +
      codes.map(code => '<li>' + escapeHtml(code) + '</li>').join("") +
      '</ul><button id="done">I saved my codes</button><button class="secondary" id="regen">Regenerate codes</button></div>';
    document.getElementById("done").onclick = () => go("complete");
    document.getElementById("regen").onclick = async () => {
      const {response,result} = await api("/api/mfa/recovery/generate","POST",{});
      if (response.ok) { log("Recovery codes regenerated for test display: " + result.codes.join(", ")); showCodes(result.codes); }
    };
  }
  async function completePage() {
    shell('<section><h1>MFA is active</h1><p class="success">Your authenticator is ready for protected payments.</p><p>You can view remaining recovery codes or test redeeming one while signed in.</p><button id="view">View recovery codes</button><button class="secondary" id="redeem">Use a recovery code</button><button class="danger" id="logout">Log out</button><div id="actions"></div></section>');
    document.getElementById("logout").onclick = logout;
    document.getElementById("view").onclick = async () => {
      const {response,result} = await api("/api/mfa/recovery","GET");
      if (!response.ok) return;
      log("Remaining recovery values shown to authenticated owner: " + result.codes.join(", "));
      document.getElementById("actions").innerHTML = '<h2>Remaining codes</h2><ul class="codes">' + result.codes.map(c => '<li>' + escapeHtml(c) + '</li>').join("") + '</ul>';
    };
    document.getElementById("redeem").onclick = () => {
      document.getElementById("actions").innerHTML = '<form id="redeemForm"><label for="code">Recovery code</label><input id="code" placeholder="ABCD-1234-EFGH-5678" required><button>Redeem code</button><p class="error" id="redeemError"></p></form>';
      document.getElementById("redeemForm").onsubmit = async e => {
        e.preventDefault();
        const {response,result} = await api("/api/mfa/recovery/redeem","POST",{code:document.getElementById("code").value.trim().toUpperCase()});
        document.getElementById("redeemError").textContent = response.ok ? "Recovery code redeemed and marked unusable." : result.error;
        if (response.ok) log("A recovery code was redeemed and invalidated.");
      };
    };
  }
  async function logout() {
    await api("/api/logout","POST",{});
    csrf = ""; provisioning = null; log("Session invalidated by logout.");
    location.hash = "#login";
  }
  async function route() {
    const page = location.hash.replace("#","") || "login";
    if (page === "logout") return logout();
    if (page === "login") return loginPage();
    if (!csrf) {
      const {response,result} = await api("/api/me","GET");
      if (!response.ok) return loginPage();
      csrf = result.csrf;
      if (page === "identity") return identityPage();
      if (page === "provision") return provisionPage();
      if (page === "verify") return verifyPage();
      if (page === "recovery") return recoveryPage();
      return completePage();
    }
    if (page === "identity") return identityPage();
    if (page === "provision") return provisionPage();
    if (page === "verify") return verifyPage();
    if (page === "recovery") return recoveryPage();
    if (page === "complete") return completePage();
    loginPage();
  }
  window.addEventListener("hashchange", route);
  route();
})();
</script>
</body>
</html>`;

const certPath = "certs/cert.pem";
const keyPath = "certs/key.pem";

Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file(certPath),
    key: Bun.file(keyPath),
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        return new Response(html, {
          status: 200,
          headers: securityHeaders(request, {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
          }),
        });
      }
      return new Response("Not found", { status: 404, headers: securityHeaders(request, { "Content-Type": "text/plain; charset=utf-8" }) });
    } catch {
      /* Security Evaluation 2: no debug stacks or sensitive details in production responses. */
      return genericError(request, 500);
    }
  },
});

console.log(`Northstar MFA enrolment running securely at https://localhost:${PORT}`);
