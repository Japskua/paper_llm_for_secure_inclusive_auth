
import { timingSafeEqual } from "node:crypto";

/*
 MFA Enrolment System — Requirements 1–5:
 Single Bun HTTPS server and vanilla mobile web application.
*/
const PORT = 3000;
const CERT_FILE = "certs/cert.pem";
const KEY_FILE = "certs/key.pem";

if (!(await Bun.file(CERT_FILE).exists()) || !(await Bun.file(KEY_FILE).exists())) {
  console.error("TLS certificate files are required at certs/cert.pem and certs/key.pem.");
  process.exit(1);
}

const encoder = new TextEncoder();
const ACCOUNT = {
  id: "acct_marcus_001",
  email: "marcus@example.com",
  phone: "+15551234567",
  displayName: "Marcus",
};

const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const PREAUTH_MAX_MS = 10 * 60 * 1000;
const VERIFY_WINDOW_MS = 10 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;

type Session = {
  id: string;
  userId?: string;
  authenticated: boolean;
  createdAt: number;
  lastSeen: number;
  expiresAt: number;
  csrf: string;
  identityCode?: string;
  identityExpiresAt?: number;
  /*
   Task: This durable key is derived from the submitted normalized identity
   details and remains in the pre-authentication session for verification.
  */
  identityThrottleKey?: string;
};

type VerificationThrottle = {
  attempts: number;
  lockedUntil?: number;
};

type Enrollment = {
  encryptedSecret: string;
  expiresAt: number;
  usedCounters: Set<number>;
};

type MfaRecord = {
  encryptedSecret: string;
  enabledAt: number;
  usedCounters: Set<number>;
  backupHashes: Set<string>;
  recoveryAttempts: number;
  recoveryLockedUntil?: number;
};

const sessions = new Map<string, Session>();
const pendingEnrollments = new Map<string, Enrollment>();
const mfaRecords = new Map<string, MfaRecord>();

/*
 Task: throttles live independently of sessions. In particular, identity
 throttles are keyed from submitted details, so creating a new pre-auth
 session cannot evade a lock for those same details.
*/
const identityThrottles = new Map<string, VerificationThrottle>();
const authenticatorThrottles = new Map<string, VerificationThrottle>();

// Requirement 3: process-local cryptographic keys protect stored values at rest.
const encryptionKeyBytes = crypto.getRandomValues(new Uint8Array(32));
const hmacKeyBytes = crypto.getRandomValues(new Uint8Array(32));
const aesKeyPromise = crypto.subtle.importKey("raw", encryptionKeyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
const hmacKeyPromise = crypto.subtle.importKey("raw", hmacKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}
function unb64(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, "base64url"));
}
function token(length = 32): string {
  return b64(crypto.getRandomValues(new Uint8Array(length)));
}
function digits(): string {
  return String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
}
function secureEquals(a: string, b: string): boolean {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function base32Encode(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) result += alphabet[(buffer << (5 - bits)) & 31];
  return result;
}
function base32Decode(value: string): Uint8Array | null {
  const input = value.toUpperCase().replace(/[\s-]/g, "");
  if (!/^[A-Z2-7]{16,128}$/.test(input)) return null;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const output: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of input) {
    const n = alphabet.indexOf(char);
    if (n < 0) return null;
    buffer = (buffer << 5) | n;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}
async function encryptSecret(secret: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await aesKeyPromise,
    encoder.encode(secret),
  );
  return `${b64(iv)}.${b64(new Uint8Array(encrypted))}`;
}
async function decryptSecret(payload: string): Promise<string> {
  const [iv, ciphertext] = payload.split(".");
  if (!iv || !ciphertext) throw new Error("Invalid encrypted record");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(iv) },
    await aesKeyPromise,
    unb64(ciphertext),
  );
  return new TextDecoder().decode(plain);
}
async function backupHash(code: string): Promise<string> {
  const signed = await crypto.subtle.sign(
    "HMAC",
    await hmacKeyPromise,
    encoder.encode(`backup-code-v1:${code}`),
  );
  return b64(new Uint8Array(signed));
}
async function totp(secret: string, counter: number): Promise<string> {
  const raw = base32Decode(secret);
  if (!raw) throw new Error("Invalid OTP secret");
  const bytes = new Uint8Array(8);
  let value = BigInt(counter);
  for (let index = 7; index >= 0; index--) {
    bytes[index] = Number(value & 255n);
    value >>= 8n;
  }
  const key = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes));
  const offset = digest[digest.length - 1] & 15;
  const number = ((digest[offset] & 127) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(number % 1000000).padStart(6, "0");
}
async function verifyTotp(secret: string, otp: string, used: Set<number>): Promise<boolean> {
  const current = Math.floor(Date.now() / 30000);
  for (const counter of [current, current - 1]) {
    const expected = await totp(secret, counter);
    if (!used.has(counter) && secureEquals(expected, otp)) {
      used.add(counter);
      return true;
    }
  }
  return false;
}
function backupCodes(): string[] {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const result: string[] = [];
  for (let index = 0; index < 8; index++) {
    const random = crypto.getRandomValues(new Uint8Array(10));
    let code = "";
    for (const byte of random) code += alphabet[byte % alphabet.length];
    result.push(`${code.slice(0, 5)}-${code.slice(5)}`);
  }
  return result;
}

/* Requirement 5 and task: durable throttling helpers. */
function throttle(map: Map<string, VerificationThrottle>, key: string, now = Date.now()): VerificationThrottle {
  let record = map.get(key);
  if (!record) {
    record = { attempts: 0 };
    map.set(key, record);
  }
  if (record.lockedUntil && now >= record.lockedUntil) {
    record.attempts = 0;
    record.lockedUntil = undefined;
  }
  return record;
}
function isLocked(record: VerificationThrottle, now = Date.now()): boolean {
  return !!record.lockedUntil && now < record.lockedUntil;
}
function failed(record: VerificationThrottle, now = Date.now()): void {
  record.attempts++;
  if (record.attempts >= MAX_FAILURES) record.lockedUntil = now + LOCK_MS;
}
function resetThrottle(record: VerificationThrottle): void {
  record.attempts = 0;
  record.lockedUntil = undefined;
}

/*
 Task: normalized submitted details form the durable verification throttle key.
 It intentionally does not use a session ID or a user/account ID. This means
 repeated starts with identical details always find the same throttle record.
*/
function identityThrottleKey(normalizedEmail: string, normalizedPhone: string): string {
  return `identity-details-v1:${normalizedEmail}\u0000${normalizedPhone}`;
}
function refreshRecoveryThrottle(record: MfaRecord, now: number): void {
  if (record.recoveryLockedUntil && now >= record.recoveryLockedUntil) {
    record.recoveryAttempts = 0;
    record.recoveryLockedUntil = undefined;
  }
}
function failedRecovery(record: MfaRecord, now: number): void {
  record.recoveryAttempts++;
  if (record.recoveryAttempts >= MAX_FAILURES) record.recoveryLockedUntil = now + LOCK_MS;
}

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const split = part.indexOf("=");
    if (split > 0) result[part.slice(0, split).trim()] = decodeURIComponent(part.slice(split + 1).trim());
  }
  return result;
}
function sessionCookie(id: string): string {
  return `__Host-mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}
function expiredCookie(): string {
  return "__Host-mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}
function newSession(authenticated = false): Session {
  const now = Date.now();
  return {
    id: token(),
    authenticated,
    createdAt: now,
    lastSeen: now,
    expiresAt: now + (authenticated ? SESSION_ABSOLUTE_MS : PREAUTH_MAX_MS),
    csrf: token(),
  };
}
function currentSession(request: Request): Session | null {
  const id = parseCookies(request).__Host-mfa_session;
  const session = id ? sessions.get(id) : undefined;
  if (!session) return null;
  const now = Date.now();
  if (now > session.expiresAt || (session.authenticated && now - session.lastSeen > SESSION_IDLE_MS)) {
    sessions.delete(session.id);
    return null;
  }
  session.lastSeen = now;
  return session;
}
// Requirement 1: owner is derived only from the HttpOnly server-side session.
function owner(request: Request): Session | null {
  const session = currentSession(request);
  return session && session.authenticated && session.userId === ACCOUNT.id ? session : null;
}
function csrf(request: Request, session: Session): boolean {
  const supplied = request.headers.get("x-csrf-token") || "";
  return supplied.length > 20 && secureEquals(supplied, session.csrf);
}
function validEmail(value: unknown): value is string {
  return typeof value === "string" &&
    /^[^\s@]+@[^\s@]+\.[^\s@]{2,100}$/.test(value) &&
    value.length <= 254;
}
function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+[1-9][0-9]{7,14}$/.test(value);
}
function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function validBackup(value: unknown): value is string {
  return typeof value === "string" && /^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/.test(value);
}
function manipulated(input: Record<string, unknown>): boolean {
  return ["userId", "accountId", "ownerId", "email"].some((key) => key in input);
}
async function body(request: Request): Promise<Record<string, unknown> | null> {
  if (!request.headers.get("content-type")?.includes("application/json")) return null;
  const text = await request.text();
  if (text.length > 4096) return null;
  try {
    const value = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}
function trustedOrigin(request: Request): string | null {
  const origin = request.headers.get("origin");
  if (!origin) return null;
  try {
    const url = new URL(origin);
    return url.protocol === "https:" &&
      ["localhost", "127.0.0.1", "::1"].includes(url.hostname) &&
      url.port === String(PORT)
      ? origin
      : null;
  } catch {
    return null;
  }
}
function headers(request: Request, nonce: string): Headers {
  const result = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  });
  const origin = trustedOrigin(request);
  if (origin) {
    result.set("Access-Control-Allow-Origin", origin);
    result.set("Access-Control-Allow-Credentials", "true");
    result.set("Vary", "Origin");
  }
  return result;
}
function respond(request: Request, data: unknown, status = 200, cookie?: string): Response {
  const result = headers(request, token(16));
  result.set("Content-Type", "application/json; charset=utf-8");
  if (cookie) result.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers: result });
}
function error(request: Request, status = 400, cookie?: string): Response {
  return respond(request, { ok: false, message: "We could not complete that request. Please try again." }, status, cookie);
}

function page(nonce: string): string {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light">
<title>Northstar Bank · Security</title>
<style nonce="${nonce}">
:root{--ink:#12213a;--muted:#536278;--blue:#0759c7;--dark:#034494;--pale:#eef5ff;--line:#cad5e4;--good:#087443;--danger:#a91d35;--focus:#f1a500}*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:var(--ink);font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.shell{width:min(100%,520px);min-height:100vh;margin:auto;background:#fff;box-shadow:0 0 24px #11224412}header{padding:20px;border-bottom:1px solid var(--line)}.brand{display:flex;gap:10px;align-items:center;font-weight:800}.mark{display:grid;place-items:center;width:31px;height:31px;border-radius:9px;background:var(--blue);color:#fff}header p{margin:4px 0 0 41px;color:var(--muted);font-size:.9rem}main{padding:22px 20px 32px}h1{font-size:1.5rem;line-height:1.2;margin:0 0 10px}h2{font-size:1.1rem;margin:0 0 8px}p{margin:0 0 16px}.muted{color:var(--muted)}.card{border:1px solid var(--line);border-radius:13px;padding:16px;margin:16px 0}.notice{background:var(--pale);border-left:4px solid var(--blue);border-radius:7px;padding:12px;margin:15px 0}.success{background:#edf9f2;border-left-color:var(--good)}.error{background:#fff0f2;border-left-color:var(--danger)}label{display:block;font-weight:700;margin:15px 0 6px}input{width:100%;min-height:48px;padding:11px 12px;border:1px solid #8998ac;border-radius:8px;color:var(--ink);font:inherit}input:focus,button:focus{outline:3px solid var(--focus);outline-offset:2px}.otp{letter-spacing:.22em;font-size:1.2rem;text-align:center}button{display:inline-flex;align-items:center;justify-content:center;width:100%;min-height:48px;border:0;border-radius:8px;padding:10px 16px;background:var(--blue);color:#fff;font:700 1rem system-ui,sans-serif;cursor:pointer}button:hover{background:var(--dark)}button.secondary{background:#fff;color:var(--blue);border:1px solid var(--blue);margin-top:10px}button.danger{background:var(--danger)}.actions{margin-top:22px}.text-link{width:auto;min-height:auto;padding:8px 0;color:var(--blue);background:transparent;text-decoration:underline}.setup-code{word-break:break-all;letter-spacing:.1em;font:700 1.05rem ui-monospace,monospace;color:#072b62;background:#f5f8fc;padding:13px;border-radius:8px}.codes{list-style:none;margin:12px 0;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:8px}.codes li{padding:10px 8px;background:#f5f8fc;border-radius:6px;text-align:center;font:700 .88rem ui-monospace,monospace}.small{font-size:.88rem}.log-panel{margin:24px -20px -32px;padding:16px 20px max(18px,env(safe-area-inset-bottom));background:#13243e;color:#ecf5ff}.log-panel h2{font-size:1rem}#logs{max-height:150px;overflow:auto;margin:0;white-space:pre-wrap;font:.78rem/1.45 ui-monospace,monospace}@media(max-width:360px){main{padding-left:16px;padding-right:16px}.codes{grid-template-columns:1fr}.log-panel{margin-left:-16px;margin-right:-16px}}
</style></head><body><div class="shell">
<header><div class="brand"><span class="mark" aria-hidden="true">N</span><span>Northstar Bank</span></div><p>Security centre · MFA enrolment</p></header>
<main id="app" aria-live="polite"><p>Loading secure session…</p></main>
<section class="log-panel" aria-label="Browser simulation logs"><h2>Logs</h2><pre id="logs">No simulated delivery yet.</pre></section>
</div><script nonce="${nonce}">
(()=>{"use strict";
const app=document.getElementById("app"),logs=document.getElementById("logs");let csrf="",setupSecret="",codes=[];
function log(label,value){console.log("[MFA simulation] "+label,value);logs.textContent="["+new Date().toLocaleTimeString()+"] "+label+": "+(Array.isArray(value)?value.join(", "):String(value))+"\\n"+logs.textContent}
function note(text,type="notice"){const n=document.createElement("div");n.className="notice "+type;n.textContent=text;return n}
function showError(text){document.getElementById("form-message")?.remove();const n=note(text,"error");n.id="form-message";app.prepend(n)}
async function api(path,opts={}){const headers=Object.assign({"Content-Type":"application/json","X-CSRF-Token":csrf},opts.headers||{});const r=await fetch(path,Object.assign({credentials:"same-origin",headers},opts));let d;try{d=await r.json()}catch{d={ok:false,message:"We could not complete that request."}}if(!r.ok||!d.ok)throw Error(d.message||"We could not complete that request.");return d}
function signIn(){app.innerHTML='<section><h1>Sign in to continue</h1><p class="muted">Confirm your account details before setting up payment security.</p><form id="f" novalidate><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" placeholder="marcus@example.com" required><label for="phone">Mobile number</label><input id="phone" name="phone" type="tel" autocomplete="tel" placeholder="+15551234567" required><div class="actions"><button>Continue</button></div></form><p class="small muted">For this secure demo, use the account details shown in the placeholders.</p></section>';document.getElementById("f").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.currentTarget);try{const d=await api("/api/auth/start",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:f.get("email"),phone:f.get("phone")})});csrf=d.csrf;log("Simulated identity verification code",d.testCode);identity()}catch(x){showError(x.message)}}}
function identity(){app.innerHTML='<section><h1>Verify your identity</h1><p>We sent a six-digit verification code to your verified mobile number.</p><div class="notice">Demo delivery is shown in the visible Logs panel and browser console.</div><form id="f" novalidate><label for="code">Verification code</label><input class="otp" id="code" name="code" autocomplete="one-time-code" inputmode="numeric" maxlength="6" required><div class="actions"><button>Verify identity</button></div></form><button class="text-link" id="back" type="button">Use different details</button></section>';document.getElementById("back").onclick=signIn;document.getElementById("f").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/auth/verify",{method:"POST",body:JSON.stringify({code:new FormData(e.currentTarget).get("code")})});csrf=d.csrf;enrol()}catch(x){showError(x.message)}}}
function enrol(){app.innerHTML='<section><h1>Set up an authenticator</h1><p>Use an authenticator app for an extra check before high-value payments.</p><div class="card"><h2>What you need</h2><p class="muted">An authenticator app on your phone. It works even when you have no signal.</p></div><form id="f"><div class="actions"><button>Set up authenticator</button></div></form><button class="text-link" id="settings" type="button">Go to security settings</button></section>';document.getElementById("settings").onclick=settings;document.getElementById("f").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/mfa/setup",{method:"POST",body:"{}"});setupSecret=d.manualSecret;log("Simulated current authenticator code",d.testOtp);provision()}catch(x){showError(x.message)}}}
function provision(){app.innerHTML='<section><h1>Add this account to your app</h1><p>In your authenticator app, choose <strong>add account</strong> then enter this setup code manually.</p><div class="card"><h2>Northstar Bank · Marcus</h2><p class="small muted">Setup code</p><div class="setup-code" id="secret"></div></div><div class="notice">A test code was delivered to the Logs panel. In a real app, use the changing code from your authenticator.</div><form id="f" novalidate><label for="otp">Six-digit authenticator code</label><input class="otp" id="otp" name="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6" required><div class="actions"><button>Confirm authenticator</button></div></form><button class="text-link" id="cancel" type="button">Cancel setup</button></section>';document.getElementById("secret").textContent=setupSecret;document.getElementById("cancel").onclick=enrol;document.getElementById("f").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/mfa/confirm",{method:"POST",body:JSON.stringify({otp:new FormData(e.currentTarget).get("otp")})});codes=d.backupCodes;log("Simulated backup recovery codes",codes);backup()}catch(x){showError(x.message)}}}
function backup(){app.innerHTML='<section><h1>Save your recovery codes</h1><div class="notice success">Your authenticator is now active.</div><p>Each code works once if you lose access to your authenticator. Store them somewhere safe and private.</p><ul class="codes" id="list"></ul><div class="actions"><button id="saved" type="button">I have saved these codes</button></div></section>';const l=document.getElementById("list");codes.forEach(c=>{const i=document.createElement("li");i.textContent=c;l.appendChild(i)});document.getElementById("saved").onclick=()=>{codes=[];setupSecret="";settings()}}
async function settings(){try{const d=await api("/api/mfa/settings",{method:"GET",headers:{}});app.innerHTML='<section><h1>Security settings</h1><p>Signed in as <strong id="name"></strong></p><div class="card"><h2>Authenticator</h2><p class="muted" id="state"></p></div><div class="card"><h2>Recovery codes</h2><p class="muted">Use a recovery code once if you cannot use your authenticator.</p><button class="secondary" id="recover" type="button">Verify a recovery code</button><button class="secondary" id="regen" type="button">Generate new recovery codes</button></div><button class="danger" id="logout" type="button">Sign out</button></section>';document.getElementById("name").textContent=d.user.displayName;document.getElementById("state").textContent=d.mfaEnabled?"Active — authenticator confirmation is required.":"Not active.";document.getElementById("recover").onclick=recovery;document.getElementById("regen").onclick=regenerate;document.getElementById("logout").onclick=logout}catch(_){signIn()}}
function recovery(){app.innerHTML='<section><h1>Use a recovery code</h1><p>Enter one unused recovery code. It will be permanently consumed after verification.</p><form id="f" novalidate><label for="code">Recovery code</label><input id="code" name="code" autocomplete="off" autocapitalize="characters" placeholder="ABCDE-FGHIJ" maxlength="11" required><div class="actions"><button>Verify recovery code</button></div></form><button class="text-link" id="back" type="button">Back to settings</button></section>';document.getElementById("back").onclick=settings;document.getElementById("f").onsubmit=async e=>{e.preventDefault();const code=String(new FormData(e.currentTarget).get("code")||"").toUpperCase().trim();try{await api("/api/mfa/recovery/verify",{method:"POST",body:JSON.stringify({code})});app.innerHTML='<section><h1>Recovery code accepted</h1><div class="notice success">That recovery code has been used and cannot be used again.</div><button id="return" type="button">Return to settings</button></section>';document.getElementById("return").onclick=settings}catch(x){showError(x.message)}}}
async function regenerate(){if(!confirm("Generate new recovery codes? Your previous unused codes will stop working."))return;try{const d=await api("/api/mfa/backup/regenerate",{method:"POST",body:"{}"});codes=d.backupCodes;log("Simulated regenerated backup recovery codes",codes);backup()}catch(x){showError(x.message)}}
async function logout(){try{await api("/api/auth/logout",{method:"POST",body:"{}"})}catch(_){}csrf="";setupSecret="";codes=[];signIn()}
(async()=>{try{const d=await api("/api/me",{method:"GET",headers:{}});csrf=d.csrf||"";d.authenticated?settings():signIn()}catch(_){signIn()}})();
})();</script></body></html>`;
}

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "OPTIONS") {
    const result = headers(request, token(16));
    result.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    result.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return new Response(null, { status: 204, headers: result });
  }

  if (request.method === "GET" && path === "/") {
    const nonce = token(16);
    const result = headers(request, nonce);
    result.set("Content-Type", "text/html; charset=utf-8");
    return new Response(page(nonce), { headers: result });
  }

  if (request.method === "GET" && path === "/api/me") {
    const session = owner(request);
    return session
      ? respond(request, { ok: true, authenticated: true, csrf: session.csrf, user: { displayName: ACCOUNT.displayName } })
      : respond(request, { ok: true, authenticated: false });
  }

  if (request.method === "POST" && path === "/api/auth/start") {
    const input = await body(request);
    if (!input || !validEmail(input.email) || !validPhone(input.phone)) return error(request);

    const previous = currentSession(request);
    if (previous) sessions.delete(previous.id);

    const email = input.email.trim().toLowerCase();
    const phone = input.phone;

    /*
     Task: both constant-time comparisons are deliberately evaluated first,
     independently, before their boolean results are combined. In particular,
     the phone comparison is never skipped when the email does not match.
    */
    const emailMatches = secureEquals(email, ACCOUNT.email);
    const phoneMatches = secureEquals(phone, ACCOUNT.phone);
    const known = emailMatches && phoneMatches;

    const session = newSession(false);
    session.identityCode = digits();
    session.identityExpiresAt = Date.now() + VERIFY_WINDOW_MS;
    session.identityThrottleKey = identityThrottleKey(email, phone);
    session.userId = known ? ACCOUNT.id : "unverified";
    sessions.set(session.id, session);

    return respond(
      request,
      { ok: true, csrf: session.csrf, testCode: session.identityCode },
      200,
      sessionCookie(session.id),
    );
  }

  if (request.method === "POST" && path === "/api/auth/verify") {
    const session = currentSession(request);
    const input = await body(request);

    /*
     Task: session and CSRF are checked before a verification attempt is
     counted. The persisted details-derived key makes retries remain locked
     across newly created pre-authentication sessions until LOCK_MS expires.
    */
    if (!session || !csrf(request, session)) return error(request);

    const now = Date.now();
    const throttleKey = session.identityThrottleKey;
    if (!throttleKey) return error(request, 403);
    const limit = throttle(identityThrottles, throttleKey, now);
    if (isLocked(limit, now)) return error(request, 429);

    const suppliedCode = input && typeof input.code === "string" ? input.code : "";
    const codeFormatValid = validOtp(input?.code);
    const candidate = session.identityCode || "000000";
    const codeMatches = secureEquals(suppliedCode, candidate);
    const valid = codeFormatValid &&
      codeMatches &&
      !!session.identityExpiresAt &&
      now <= session.identityExpiresAt &&
      session.userId === ACCOUNT.id;

    if (!valid) {
      failed(limit, now);
      return error(request, isLocked(limit, now) ? 429 : 400);
    }

    resetThrottle(limit);
    sessions.delete(session.id);
    const authenticated = newSession(true);
    authenticated.userId = ACCOUNT.id;
    sessions.set(authenticated.id, authenticated);
    return respond(
      request,
      { ok: true, csrf: authenticated.csrf, user: { displayName: ACCOUNT.displayName } },
      200,
      sessionCookie(authenticated.id),
    );
  }

  if (request.method === "POST" && path === "/api/auth/logout") {
    const session = owner(request);
    const input = await body(request);
    if (!session || !input || !csrf(request, session)) return error(request, 403);
    sessions.delete(session.id);
    pendingEnrollments.delete(ACCOUNT.id);
    return respond(request, { ok: true }, 200, expiredCookie());
  }

  if (request.method === "GET" && path === "/api/mfa/settings") {
    if (!owner(request)) return error(request, 401);
    return respond(request, {
      ok: true,
      user: { displayName: ACCOUNT.displayName },
      mfaEnabled: mfaRecords.has(ACCOUNT.id),
    });
  }

  if (request.method === "POST" && path === "/api/mfa/setup") {
    const session = owner(request);
    const input = await body(request);
    if (!session || !input || manipulated(input) || !csrf(request, session)) return error(request, 403);

    const limit = throttle(authenticatorThrottles, ACCOUNT.id);
    if (isLocked(limit)) return error(request, 429);

    const secret = base32Encode(crypto.getRandomValues(new Uint8Array(20)));
    pendingEnrollments.set(ACCOUNT.id, {
      encryptedSecret: await encryptSecret(secret),
      expiresAt: Date.now() + VERIFY_WINDOW_MS,
      usedCounters: new Set(),
    });
    return respond(request, {
      ok: true,
      manualSecret: secret,
      testOtp: await totp(secret, Math.floor(Date.now() / 30000)),
    });
  }

  if (request.method === "POST" && path === "/api/mfa/confirm") {
    const session = owner(request);
    const input = await body(request);
    if (!session || !csrf(request, session)) return error(request, 403);
    if (input && manipulated(input)) return error(request, 403);

    const now = Date.now();
    const limit = throttle(authenticatorThrottles, ACCOUNT.id, now);
    if (isLocked(limit, now)) return error(request, 429);

    if (!input || !validOtp(input.otp)) {
      failed(limit, now);
      return error(request, isLocked(limit, now) ? 429 : 400);
    }

    const enrollment = pendingEnrollments.get(ACCOUNT.id);
    if (!enrollment || now > enrollment.expiresAt) return error(request);
    const secret = await decryptSecret(enrollment.encryptedSecret);

    if (!(await verifyTotp(secret, String(input.otp), enrollment.usedCounters))) {
      failed(limit, now);
      return error(request, isLocked(limit, now) ? 429 : 400);
    }

    resetThrottle(limit);
    const plainCodes = backupCodes();
    const hashes = new Set<string>();
    for (const code of plainCodes) hashes.add(await backupHash(code));
    mfaRecords.set(ACCOUNT.id, {
      encryptedSecret: enrollment.encryptedSecret,
      enabledAt: now,
      usedCounters: enrollment.usedCounters,
      backupHashes: hashes,
      recoveryAttempts: 0,
    });
    pendingEnrollments.delete(ACCOUNT.id);
    return respond(request, { ok: true, backupCodes: plainCodes });
  }

  if (request.method === "POST" && path === "/api/mfa/recovery/verify") {
    const session = owner(request);
    const input = await body(request);
    if (!session || !csrf(request, session)) return error(request, 403);
    if (input && manipulated(input)) return error(request, 403);

    const record = mfaRecords.get(ACCOUNT.id);
    const now = Date.now();
    if (!record) return error(request);
    refreshRecoveryThrottle(record, now);
    if (record.recoveryLockedUntil && now < record.recoveryLockedUntil) return error(request, 429);

    if (!input || !validBackup(input.code)) {
      failedRecovery(record, now);
      return error(request, record.recoveryLockedUntil ? 429 : 400);
    }

    const hash = await backupHash(String(input.code));
    if (!record.backupHashes.has(hash)) {
      failedRecovery(record, now);
      return error(request, record.recoveryLockedUntil ? 429 : 400);
    }

    record.backupHashes.delete(hash);
    record.recoveryAttempts = 0;
    record.recoveryLockedUntil = undefined;
    return respond(request, { ok: true });
  }

  if (request.method === "POST" && path === "/api/mfa/backup/regenerate") {
    const session = owner(request);
    const input = await body(request);
    if (!session || !input || manipulated(input) || !csrf(request, session)) return error(request, 403);

    const record = mfaRecords.get(ACCOUNT.id);
    if (!record) return error(request);

    const plainCodes = backupCodes();
    const hashes = new Set<string>();
    for (const code of plainCodes) hashes.add(await backupHash(code));

    // Existing recovery throttle state intentionally survives code replacement.
    record.backupHashes = hashes;
    return respond(request, { ok: true, backupCodes: plainCodes });
  }

  return error(request, 404);
}

Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: { cert: Bun.file(CERT_FILE), key: Bun.file(KEY_FILE) },
  async fetch(request) {
    try {
      return await handle(request);
    } catch {
      // Requirement 2: generic production error; never expose stack traces.
      return error(request, 500);
    }
  },
});

console.log(`Northstar MFA HTTPS server listening on https://localhost:${PORT}`);
