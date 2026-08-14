
import { serve } from "bun";

// MFA Enrolment System: single-file Bun HTTPS server + responsive vanilla-JS client.
// Security controls map to requirements: [1] access control/CSRF, [2] headers/config,
// [3] cryptography/TLS, [4] validation/output safety, [5] sessions/rate limits.

const HTTPS_PORT = 3000;
const HTTP_REDIRECT_PORT = 3001;
const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_WINDOW_MS = 30 * 1000;
const VERIFY_LOCK_MS = 5 * 60 * 1000;
const MAX_FAILURES = 5;
const encoder = new TextEncoder();

type Session = {
  id: string;
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
  phase: "identity" | "authenticated";
  identityCode?: string;
  identityExpires?: number;
  identityUsed?: boolean;
  identityFailures: number;
  identityLockedUntil: number;
  totpFailures: number;
  totpLockedUntil: number;
  recoveryFailures: number;
  recoveryLockedUntil: number;
};

type BackupRecord = { salt: string; hash: string; used: boolean };
type UserMfa = {
  enabled: boolean;
  encryptedSecret?: string;
  verifiedCounter?: number;
  lastUsedCounter?: number;
  backupCodes: BackupRecord[];
};

const sessions = new Map<string, Session>();
const users = new Map<string, { id: string; email: string; phone: string; password: string; mfa: UserMfa }>();
users.set("marcus", {
  id: "marcus",
  email: "marcus@example.test",
  phone: "5550182",
  password: "DemoPass!9",
  mfa: { enabled: false, backupCodes: [] },
});

// [3] Master key stays server-side. TOTP secrets are AES-GCM encrypted in memory at rest.
const encryptionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);

function randomToken(bytes = 32) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}
function b64(bytes: Uint8Array) {
  return Buffer.from(bytes).toString("base64url");
}
function fromB64(value: string) {
  return new Uint8Array(Buffer.from(value, "base64url"));
}
async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return b64(new Uint8Array(digest));
}
async function encryptSecret(secret: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, encoder.encode(secret));
  return `${b64(iv)}.${b64(new Uint8Array(encrypted))}`;
}
async function decryptSecret(stored: string) {
  const [ivText, cipherText] = stored.split(".");
  if (!ivText || !cipherText) throw new Error("invalid protected value");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(ivText) },
    encryptionKey,
    fromB64(cipherText),
  );
  return new TextDecoder().decode(plain);
}

// [3,5] RFC-compatible Base32 TOTP: raw Base32 secret bytes, 8-byte big-endian
// moving counter, HMAC-SHA-256, dynamic truncation, six digits, and 30-second period.
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(bytes: Uint8Array) {
  let bits = 0;
  let value = 0;
  let result = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) result += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return result;
}
function base32Decode(secret: string) {
  const clean = secret.replace(/=+$/g, "").toUpperCase();
  if (!/^[A-Z2-7]+$/.test(clean)) throw new Error("invalid Base32 secret");
  let bits = 0;
  let value = 0;
  const output: number[] = [];
  for (const character of clean) {
    value = (value << 5) | BASE32_ALPHABET.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}
async function totpFor(secret: string, counter: number) {
  if (!Number.isSafeInteger(counter) || counter < 0) throw new Error("invalid TOTP counter");
  const counterBytes = new Uint8Array(8);
  new DataView(counterBytes.buffer).setBigUint64(0, BigInt(counter), false);
  const key = await crypto.subtle.importKey(
    "raw",
    base32Decode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = signature[signature.length - 1] & 15;
  const number = (
    ((signature[offset] & 127) << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3]
  ) % 1000000;
  return String(number).padStart(6, "0");
}
function makeSecret() {
  // 20 cryptographically random bytes represented as unpadded RFC 4648 Base32.
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}
function makeIdentityCode() {
  // A per-session CSPRNG six-digit code; it is delivered only in the mock API response.
  const value = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
  return String(value).padStart(6, "0");
}
function makeRecoveryCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const raw = Array.from(crypto.getRandomValues(new Uint8Array(12)), x => alphabet[x % alphabet.length]).join("");
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
}
function validCsrf(value: unknown) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(value);
}
function json(data: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", ...headers } });
}
function genericError(status = 400) {
  return json({ error: "We could not complete that request. Please try again." }, status);
}
function parseCookies(request: Request) {
  const out: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0) out[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  }
  return out;
}
function sessionCookie(id: string) {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}
function clearCookie() {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}
function createSession(userId: string, phase: Session["phase"]) {
  const id = randomToken(32);
  const now = Date.now();
  const session: Session = {
    id, userId, csrf: randomToken(32), createdAt: now, lastSeen: now, phase,
    identityFailures: 0, identityLockedUntil: 0,
    totpFailures: 0, totpLockedUntil: 0, recoveryFailures: 0, recoveryLockedUntil: 0,
  };
  sessions.set(id, session);
  return session;
}
// [1,5] Every protected request derives identity only from the validated HttpOnly session.
function authorized(request: Request, phase: Session["phase"] = "authenticated") {
  const id = parseCookies(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  const now = Date.now();
  if (!session || session.phase !== phase || now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    if (id) sessions.delete(id);
    return null;
  }
  const user = users.get(session.userId);
  if (!user) return null;
  session.lastSeen = now;
  return { session, user };
}
function csrfOK(session: Session, body: any) {
  return validCsrf(body?.csrf) && body.csrf === session.csrf;
}
async function bodyOf(request: Request) {
  const type = request.headers.get("content-type") || "";
  if (!type.includes("application/json")) return null;
  try { return await request.json(); } catch { return null; }
}
function validOtp(value: unknown) {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function validPhone(value: unknown) {
  return typeof value === "string" && /^\d{7,15}$/.test(value);
}
function validEmail(value: unknown) {
  return typeof value === "string" && /^[A-Za-z0-9.!#$%&'*+/=?^_\`{|}~-]{1,64}@[A-Za-z0-9.-]{1,190}$/.test(value);
}
function validRecovery(value: unknown) {
  return typeof value === "string" && /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(value);
}
function allowedRedirect(value: unknown) {
  return value === undefined || value === "" || value === "/" || value === "/settings";
}
function issueHeaders(request: Request, response: Response) {
  const nonce = randomToken(18);
  response.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Content-Security-Policy", `default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; script-src 'nonce-${nonce}'`);
  response.headers.set("Referrer-Policy", "no-referrer");
  response.headers.set("Cache-Control", "no-store");
  const origin = request.headers.get("origin");
  if (origin === `https://localhost:${HTTPS_PORT}` || origin === "https://127.0.0.1:3000") {
    response.headers.set("Access-Control-Allow-Origin", origin);
    response.headers.set("Vary", "Origin");
    response.headers.set("Access-Control-Allow-Credentials", "true");
    response.headers.set("Access-Control-Allow-Headers", "Content-Type");
    response.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  return response;
}
function pageResponse() {
  const nonce = randomToken(18);
  const response = new Response(html(nonce), { headers: { "Content-Type": "text/html; charset=utf-8" } });
  response.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Referrer-Policy", "no-referrer");
  response.headers.set("Cache-Control", "no-store");
  response.headers.set("Content-Security-Policy",
    `default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; connect-src 'self'; img-src data:; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'`);
  return response;
}

function recordIdentityFailure(session: Session, now: number) {
  session.identityFailures++;
  if (session.identityFailures >= MAX_FAILURES) {
    session.identityLockedUntil = now + VERIFY_LOCK_MS;
    session.identityFailures = 0;
  }
}

async function api(request: Request, path: string): Promise<Response> {
  if (request.method === "OPTIONS") return new Response(null, { status: 204 });

  if (path === "/api/signin" && request.method === "POST") {
    const body = await bodyOf(request);
    if (!body || !validEmail(body.email) || typeof body.password !== "string" || body.password.length > 128 || !allowedRedirect(body.redirect)) return genericError(400);
    // [4,5] Generic message and uniform check avoid account enumeration.
    const account = [...users.values()].find(u => u.email === String(body.email).toLowerCase());
    const accepted = account && body.password === account.password;
    if (!accepted) return genericError(401);

    const session = createSession(account.id, "identity"); // Fresh session prevents fixation.
    session.identityCode = makeIdentityCode();
    session.identityExpires = Date.now() + 5 * 60 * 1000;
    // Mock-only delivery for the browser console/UI. This secret is never server-logged.
    return json({ csrf: session.csrf, next: "identity", testIdentityCode: session.identityCode }, 200,
      { "Set-Cookie": sessionCookie(session.id) });
  }

  if (path === "/api/identity" && request.method === "POST") {
    const auth = authorized(request, "identity");
    const body = await bodyOf(request);
    if (!auth || !body || !csrfOK(auth.session, body)) return genericError(401);

    const now = Date.now();
    if (auth.session.identityLockedUntil > now) return genericError(429);

    // [5] Both malformed and incorrect submitted phone/code values are failed attempts.
    const validSubmission = validPhone(body.phone) && validOtp(body.code);
    const accepted = validSubmission &&
      !auth.session.identityUsed &&
      !!auth.session.identityExpires &&
      now <= auth.session.identityExpires &&
      body.phone === auth.user.phone &&
      body.code === auth.session.identityCode;

    if (!accepted) {
      recordIdentityFailure(auth.session, now);
      return genericError(401);
    }

    auth.session.identityFailures = 0;
    auth.session.identityUsed = true;
    auth.session.identityCode = undefined;
    sessions.delete(auth.session.id);
    const fresh = createSession(auth.user.id, "authenticated"); // [5] Rotate after identity authentication.
    return json({ csrf: fresh.csrf, next: auth.user.mfa.enabled ? "settings" : "setup" }, 200,
      { "Set-Cookie": sessionCookie(fresh.id) });
  }

  if (path === "/api/mfa/status" && request.method === "GET") {
    const auth = authorized(request);
    if (!auth) return genericError(401);
    return json({ csrf: auth.session.csrf, enabled: auth.user.mfa.enabled, backupRemaining: auth.user.mfa.backupCodes.filter(x => !x.used).length });
  }

  if (path === "/api/mfa/provision" && request.method === "POST") {
    const auth = authorized(request);
    const body = await bodyOf(request);
    if (!auth || !body || !csrfOK(auth.session, body)) return genericError(401);

    const secret = makeSecret();
    auth.user.mfa.encryptedSecret = await encryptSecret(secret);
    auth.user.mfa.verifiedCounter = undefined;
    auth.user.mfa.lastUsedCounter = undefined;
    const counter = Math.floor(Date.now() / CODE_WINDOW_MS);
    const testOtp = await totpFor(secret, counter);
    const label = encodeURIComponent("LocalBank:marcus@example.test");
    // The URI explicitly matches the server's RFC-compatible SHA256 / 6 / 30 configuration.
    const uri = `otpauth://totp/${label}?secret=${secret}&issuer=LocalBank&algorithm=SHA256&digits=6&period=30`;
    return json({ secret, provisioningUri: uri, testOtp, validForSeconds: 30 - (Math.floor(Date.now() / 1000) % 30) });
  }

  if (path === "/api/mfa/verify-authenticator" && request.method === "POST") {
    const auth = authorized(request);
    const body = await bodyOf(request);
    if (!auth || !body || !csrfOK(auth.session, body) || !validOtp(body.otp) ||
      typeof body.manualSecret !== "string" || !/^[A-Z2-7]{16,64}$/.test(body.manualSecret)) return genericError(401);

    const now = Date.now();
    if (auth.session.totpLockedUntil > now) return genericError(429);
    if (!auth.user.mfa.encryptedSecret) return genericError(400);

    const secret = await decryptSecret(auth.user.mfa.encryptedSecret);
    const counter = Math.floor(now / CODE_WINDOW_MS);
    const expected = await totpFor(secret, counter);
    const valid = body.manualSecret === secret && body.otp === expected && auth.user.mfa.verifiedCounter !== counter;

    if (!valid) {
      auth.session.totpFailures++;
      if (auth.session.totpFailures >= MAX_FAILURES) {
        auth.session.totpLockedUntil = now + VERIFY_LOCK_MS;
        auth.session.totpFailures = 0;
      }
      return genericError(401);
    }

    auth.session.totpFailures = 0;
    auth.user.mfa.verifiedCounter = counter; // [5] Enrollment code cannot be replayed.
    return json({ verified: true });
  }

  if (path === "/api/mfa/activate" && request.method === "POST") {
    const auth = authorized(request);
    const body = await bodyOf(request);
    if (!auth || !body || !csrfOK(auth.session, body) || auth.user.mfa.verifiedCounter === undefined) return genericError(401);

    auth.user.mfa.enabled = true;
    const plaintext = Array.from({ length: 8 }, makeRecoveryCode);
    auth.user.mfa.backupCodes = [];
    for (const code of plaintext) {
      const salt = randomToken(16);
      auth.user.mfa.backupCodes.push({ salt, hash: await sha256(`${salt}:${code}`), used: false });
    }
    return json({ backupCodes: plaintext });
  }

  if (path === "/api/mfa/regenerate-backups" && request.method === "POST") {
    const auth = authorized(request);
    const body = await bodyOf(request);
    if (!auth || !body || !csrfOK(auth.session, body) || !auth.user.mfa.enabled) return genericError(401);

    const plaintext = Array.from({ length: 8 }, makeRecoveryCode);
    auth.user.mfa.backupCodes = [];
    for (const code of plaintext) {
      const salt = randomToken(16);
      auth.user.mfa.backupCodes.push({ salt, hash: await sha256(`${salt}:${code}`), used: false });
    }
    return json({ backupCodes: plaintext });
  }

  if (path === "/api/mfa/recover" && request.method === "POST") {
    const auth = authorized(request);
    const body = await bodyOf(request);
    if (!auth || !body || !csrfOK(auth.session, body) || !validRecovery(body.code) || !auth.user.mfa.enabled) return genericError(401);

    const now = Date.now();
    if (auth.session.recoveryLockedUntil > now) return genericError(429);
    const code = body.code;
    let found: BackupRecord | undefined;

    for (const record of auth.user.mfa.backupCodes) {
      if (!record.used && (await sha256(`${record.salt}:${code}`)) === record.hash) {
        found = record;
        break;
      }
    }

    if (!found) {
      auth.session.recoveryFailures++;
      if (auth.session.recoveryFailures >= MAX_FAILURES) {
        auth.session.recoveryLockedUntil = now + VERIFY_LOCK_MS;
        auth.session.recoveryFailures = 0;
      }
      return genericError(401);
    }

    found.used = true;
    auth.session.recoveryFailures = 0;
    return json({ verified: true, remaining: auth.user.mfa.backupCodes.filter(x => !x.used).length });
  }

  if (path === "/api/logout" && request.method === "POST") {
    const auth = authorized(request);
    const body = await bodyOf(request);
    if (!auth || !body || !csrfOK(auth.session, body)) return genericError(401);
    sessions.delete(auth.session.id);
    return json({ loggedOut: true }, 200, { "Set-Cookie": clearCookie() });
  }

  return genericError(404);
}

const certExists = await Bun.file("certs/cert.pem").exists();
const keyExists = await Bun.file("certs/key.pem").exists();
if (!certExists || !keyExists) throw new Error("TLS certificates are required in certs/cert.pem and certs/key.pem");

serve({
  port: HTTPS_PORT,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      let response: Response;
      if (url.pathname.startsWith("/api/")) response = await api(request, url.pathname);
      else if (url.pathname === "/" && request.method === "GET") response = pageResponse();
      else response = new Response("Not found", { status: 404 });
      return issueHeaders(request, response);
    } catch {
      return issueHeaders(request, genericError(500));
    }
  },
});

// [2,3] Non-TLS listener does not serve content; it only redirects to the TLS origin.
serve({
  port: HTTP_REDIRECT_PORT,
  fetch(request) {
    const url = new URL(request.url);
    const safePath = url.pathname === "/" ? "/" : "/";
    const response = new Response(null, { status: 308, headers: { Location: `https://localhost:${HTTPS_PORT}${safePath}` } });
    response.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    response.headers.set("X-Content-Type-Options", "nosniff");
    response.headers.set("X-Frame-Options", "DENY");
    return response;
  },
});

function html(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LocalBank MFA enrolment</title>
<style nonce="${nonce}">
:root{color-scheme:light;--navy:#102a43;--blue:#1267b3;--pale:#edf6ff;--ink:#172b3a;--muted:#526576;--line:#c8d5df;--good:#087443;--danger:#aa2437}
*{box-sizing:border-box}body{margin:0;background:#f4f8fb;color:var(--ink);font:17px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{background:var(--navy);color:white;padding:18px max(18px,calc((100% - 620px)/2));}header strong{font-size:1.25rem;letter-spacing:.02em}header span{display:block;font-size:.9rem;opacity:.88}
main{max-width:620px;margin:auto;padding:20px 16px 40px}.card{background:white;border:1px solid var(--line);border-radius:14px;padding:22px;margin:0 0 16px;box-shadow:0 2px 8px #102a4310}
h1{font-size:1.55rem;line-height:1.2;margin:0 0 12px}h2{font-size:1.15rem;margin:0 0 9px}p{margin:8px 0 15px}.hint{color:var(--muted);font-size:.94rem}.notice{background:var(--pale);border-left:4px solid var(--blue);padding:12px;margin:14px 0}.success{background:#e8f7ef;border-left-color:var(--good)}.error{background:#fff0f1;border-left-color:var(--danger);color:#7c1725}
label{display:block;font-weight:700;margin:15px 0 5px}input{width:100%;font:inherit;padding:12px;border:2px solid #9badba;border-radius:8px;background:white}input:focus{outline:3px solid #87bdeb;border-color:var(--blue)}button,.button{display:inline-block;border:0;border-radius:8px;background:var(--blue);color:white;font:700 1rem inherit;padding:12px 16px;margin:14px 8px 0 0;cursor:pointer;text-decoration:none}.secondary{background:#e7eef3;color:var(--ink)}.danger{background:var(--danger)}button:focus{outline:3px solid #f5bd51;outline-offset:2px}
.code{font:700 1.15rem ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em;word-break:break-all;background:#f1f5f7;padding:11px;border-radius:7px}.codes{padding-left:0;list-style:none}.codes li{font:700 1.05rem ui-monospace,monospace;padding:9px;border-bottom:1px solid var(--line)}.uri{font-size:.78rem;overflow-wrap:anywhere}
details{margin-top:15px}pre{max-height:150px;overflow:auto;white-space:pre-wrap;background:#081b29;color:#dcecff;padding:12px;border-radius:8px;font-size:.78rem}footer{text-align:center;color:var(--muted);font-size:.82rem;padding:5px}
@media(max-width:380px){main{padding:14px 10px}.card{padding:17px}button{width:100%;margin-right:0}}
</style>
</head>
<body>
<header><strong>LocalBank</strong><span>Secure MFA enrolment</span></header>
<main id="app" aria-live="polite"><div class="card">Loading secure service…</div></main>
<footer>Demo service · Never share recovery codes with anyone.</footer>
<script nonce="${nonce}">
(() => {
  // Client UI: secrets exist only in current JS memory, never browser storage. [3]
  const app = document.getElementById("app");
  let csrf = "", state = "signin", provision = null, issuedCodes = [], message = "", logs = [];
  const esc = value => String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  function log(text) { console.log(text); logs.unshift(text); logs = logs.slice(0, 12); }
  async function call(path, data, method = "POST") {
    const options = { method, credentials:"same-origin", headers: {} };
    if (method !== "GET") {
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify({...data, csrf});
    }
    const response = await fetch(path, options);
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || "We could not complete that request. Please try again.");
    if (result.csrf) csrf = result.csrf;
    return result;
  }
  function logsPanel() {
    return '<details><summary>Logs (test delivery simulation)</summary><p class="hint">These mirror browser console messages. Secrets are not saved after this page is left.</p><pre>' + esc(logs.join("\\n") || "No simulated delivery messages yet.") + '</pre></details>';
  }
  function showError(error) {
    message = error.message || "We could not complete that request. Please try again.";
    render();
  }
  function render() {
    let inner = "";
    const alert = message ? '<div class="notice error" role="alert">' + esc(message) + '</div>' : "";

    if (state === "signin") inner = '<section class="card"><h1>Sign in</h1><p>Sign in to enrol multi-factor authentication before higher-value payments.</p>' + alert +
      '<form id="signin"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="username" required value="marcus@example.test"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required value="DemoPass!9"><button>Continue securely</button></form><p class="hint">Demo account details are prefilled for evaluation.</p></section>';

    if (state === "identity") inner = '<section class="card"><h1>Verify your identity</h1><p>We sent a six-digit verification code to your registered phone.</p>' + alert +
      '<form id="identity"><label for="phone">Registered phone number</label><input id="phone" inputmode="numeric" autocomplete="tel" required value="5550182"><label for="identityCode">Verification code</label><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" pattern="\\\\d{6}" required><button>Verify identity</button></form><p class="hint">For security, identity verification is locked for five minutes after five unsuccessful submissions.</p></section>';

    if (state === "setup") inner = '<section class="card"><h1>Set up an authenticator</h1><p>Set up your authenticator manually using the setup key below. Enter this key into an authenticator app that supports TOTP with SHA-256, six digits, and a 30-second period.</p>' + alert +
      (provision
        ? '<h2>Manual setup key</h2><p class="code">' + esc(provision.secret) + '</p><p class="hint">Account: LocalBank / marcus@example.test</p><p class="hint uri">Provisioning details: ' + esc(provision.provisioningUri) + '</p><p class="notice">For this simulated test, the current code is <strong>' + esc(provision.testOtp) + '</strong>. It changes every 30 seconds.</p><button class="secondary" id="refresh">Create a new setup key</button><button id="toOtp">I entered the key</button>'
        : '<button id="provision">Create manual authenticator setup key</button>') + '</section>';

    if (state === "otp") inner = '<section class="card"><h1>Confirm authenticator</h1><p>Enter the six-digit code from your authenticator. You may submit the manual setup key below for this simulation.</p>' + alert +
      '<form id="otpform"><label for="manualSecret">Manual setup key</label><input id="manualSecret" required value="' + esc(provision ? provision.secret : "") + '"><label for="otp">Authenticator code</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" pattern="\\\\d{6}" required><button>Verify authenticator</button><button type="button" class="secondary" id="backSetup">Back</button></form></section>';

    if (state === "backups") inner = '<section class="card"><h1>Save recovery codes</h1><div class="notice success"><strong>MFA is active.</strong> Each code works once if you cannot access your authenticator.</div><p>Store these now. They will not be shown again.</p><ul class="codes">' + issuedCodes.map(c => '<li>' + esc(c) + '</li>').join("") + '</ul><button id="saved">I have saved these codes</button></section>';

    if (state === "settings") inner = '<section class="card"><h1>MFA settings</h1><div class="notice success"><strong>Authenticator MFA is enabled.</strong></div><p id="remaining" class="hint">Checking recovery codes…</p><button id="recover">Verify a recovery code</button><button class="secondary" id="regen">Regenerate recovery codes</button><button class="danger" id="logout">Log out</button></section>';

    if (state === "recover") inner = '<section class="card"><h1>Recovery verification</h1><p>Enter one stored recovery code. Used codes cannot be used again.</p>' + alert + '<form id="recoverform"><label for="recovery">Recovery code</label><input id="recovery" autocomplete="one-time-code" placeholder="ABCD-EFGH-JKLM" required><button>Verify recovery code</button><button type="button" class="secondary" id="backSettings">Back to settings</button></form></section>';

    if (state === "regenerate") inner = '<section class="card"><h1>Regenerate recovery codes</h1><p class="notice">This immediately invalidates all existing recovery codes.</p>' + alert + '<button class="danger" id="confirmRegen">Generate new codes</button><button class="secondary" id="cancelRegen">Cancel</button></section>';

    if (state === "logout") inner = '<section class="card"><h1>You are signed out</h1><p>Your secure session has been invalidated.</p><button id="again">Sign in again</button></section>';

    app.innerHTML = inner + logsPanel();
    bind();
  }
  function bind() {
    const by = id => document.getElementById(id);

    if (by("signin")) by("signin").onsubmit = async e => {
      e.preventDefault();
      try {
        const r = await call("/api/signin", {email:by("email").value, password:by("password").value, redirect:"/"});
        csrf = r.csrf;
        log("Simulated identity verification code delivered: " + r.testIdentityCode);
        state = "identity";
        message = "";
        render();
      } catch (e) { showError(e); }
    };

    if (by("identity")) by("identity").onsubmit = async e => {
      e.preventDefault();
      try {
        const r = await call("/api/identity", {phone:by("phone").value, code:by("identityCode").value});
        csrf = r.csrf;
        state = r.next;
        message = "";
        render();
        if (state === "settings") loadStatus();
      } catch (e) { showError(e); }
    };

    if (by("provision")) by("provision").onclick = async () => {
      try {
        provision = await call("/api/mfa/provision", {});
        log("Simulated authenticator provisioning key delivered: " + provision.secret);
        log("Simulated current authenticator OTP delivered: " + provision.testOtp);
        message = "";
        render();
      } catch (e) { showError(e); }
    };

    if (by("refresh")) by("refresh").onclick = async () => {
      try {
        provision = await call("/api/mfa/provision", {});
        log("Simulated replacement authenticator provisioning key delivered: " + provision.secret);
        log("Simulated current authenticator OTP delivered: " + provision.testOtp);
        message = "";
        render();
      } catch (e) { showError(e); }
    };

    if (by("toOtp")) by("toOtp").onclick = () => {
      state = "otp";
      message = "";
      render();
    };
    if (by("backSetup")) by("backSetup").onclick = () => {
      state = "setup";
      render();
    };

    if (by("otpform")) by("otpform").onsubmit = async e => {
      e.preventDefault();
      try {
        await call("/api/mfa/verify-authenticator", {manualSecret:by("manualSecret").value, otp:by("otp").value});
        log("Authenticator verification simulated successfully.");
        const r = await call("/api/mfa/activate", {});
        issuedCodes = r.backupCodes;
        log("Simulated backup recovery codes issued: " + r.backupCodes.join(", "));
        state = "backups";
        message = "";
        render();
      } catch (e) { showError(e); }
    };

    if (by("saved")) by("saved").onclick = () => {
      issuedCodes = [];
      provision = null;
      state = "settings";
      render();
      loadStatus();
    };
    if (by("recover")) by("recover").onclick = () => {
      state = "recover";
      message = "";
      render();
    };
    if (by("regen")) by("regen").onclick = () => {
      state = "regenerate";
      message = "";
      render();
    };
    if (by("cancelRegen")) by("cancelRegen").onclick = () => {
      state = "settings";
      render();
      loadStatus();
    };

    if (by("confirmRegen")) by("confirmRegen").onclick = async () => {
      try {
        const r = await call("/api/mfa/regenerate-backups", {});
        issuedCodes = r.backupCodes;
        log("Simulated replacement backup recovery codes issued: " + r.backupCodes.join(", "));
        state = "backups";
        message = "";
        render();
      } catch (e) { showError(e); }
    };

    if (by("backSettings")) by("backSettings").onclick = () => {
      state = "settings";
      render();
      loadStatus();
    };

    if (by("recoverform")) by("recoverform").onsubmit = async e => {
      e.preventDefault();
      try {
        const r = await call("/api/mfa/recover", {code:by("recovery").value.toUpperCase()});
        log("Recovery code verification simulated successfully; one code was consumed.");
        message = "Recovery code accepted. " + r.remaining + " recovery codes remain.";
        render();
      } catch (e) { showError(e); }
    };

    if (by("logout")) by("logout").onclick = async () => {
      try {
        await call("/api/logout", {});
        csrf = "";
        provision = null;
        issuedCodes = [];
        state = "logout";
        message = "";
        log("Secure session invalidated.");
        render();
      } catch (e) { showError(e); }
    };

    if (by("again")) by("again").onclick = () => {
      state = "signin";
      message = "";
      render();
    };
  }

  async function loadStatus() {
    try {
      const r = await call("/api/mfa/status", {}, "GET");
      const el = document.getElementById("remaining");
      if (el) el.textContent = r.backupRemaining + " unused recovery codes available.";
    } catch (e) {
      state = "signin";
      message = "Your secure session has ended. Please sign in again.";
      render();
    }
  }

  render();
})();
</script>
</body></html>`;
}
