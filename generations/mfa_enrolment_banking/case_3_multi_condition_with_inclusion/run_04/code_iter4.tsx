
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System
 Requirements 1–5: session-owned identity, CSRF, TLS, secure headers,
 encrypted TOTP secrets, hashed recovery codes, and rate limits.
*/

const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

/* Server-only account fixture. It is never sent to unauthenticated visitors. */
const account = { id: "acct_marcus_001", name: "Marcus" };

type Session = {
  id: string;
  csrf: string;
  userId: string | null;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
  proofStarted: boolean;
};

type AttemptState = { failures: number; lockedUntil: number };

type MfaRecord = {
  encryptedSecret: string;
  enabled: boolean;
  failedAttempts: number;
  lockedUntil: number;
  recoveryFailedAttempts: number;
  recoveryLockedUntil: number;
  usedSteps: Set<number>;
  recoveryHashes: Set<string>;
  mfaVerifiedAt: number;
};

const sessions = new Map<string, Session>();
const mfaRecords = new Map<string, MfaRecord>();
const proofAttempts = new Map<string, AttemptState>();

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const TOTP_PERIOD_SECONDS = 30;
const TOTP_PERIOD_MS = TOTP_PERIOD_SECONDS * 1000;
const RECENT_AUTH_MS = 5 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;

const encoder = new TextEncoder();
const encryptionKeyBytes = crypto.getRandomValues(new Uint8Array(32));
const recoveryPepper = crypto.getRandomValues(new Uint8Array(32));

function bytesToBase64(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}
function base64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}
function randomToken(bytes = 32): string {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(bytes)))
    .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function base32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "", buffer = 0, bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) out += alphabet[(buffer << (5 - bits)) & 31];
  return out;
}
function base32ToBytes(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = value.toUpperCase().replace(/=|\s/g, "");
  let buffer = 0, bits = 0;
  const output: number[] = [];
  for (const character of clean) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("Invalid protected value");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}
async function sha256(text: string): Promise<string> {
  return bytesToBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text))));
}

/* Requirement 3: AES-GCM encrypts the server-held TOTP seed at rest. */
async function encryptSecret(secret: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret));
  return `${bytesToBase64(iv)}.${bytesToBase64(new Uint8Array(encrypted))}`;
}
async function decryptSecret(stored: string): Promise<string> {
  const [iv, encrypted] = stored.split(".");
  if (!iv || !encrypted) throw new Error("Protected value unavailable");
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(iv) },
    key,
    base64ToBytes(encrypted),
  );
  return new TextDecoder().decode(plain);
}

/*
 Requirement task: RFC 6238 TOTP:
 HMAC-SHA-1, 8-byte big-endian time counter, dynamic truncation, six digits.
 The URI declares precisely the same SHA1 algorithm and 30-second period.
*/
async function makeTotp(secret: string, step: number): Promise<string> {
  const counter = new Uint8Array(8);
  let value = BigInt(step);
  for (let i = 7; i >= 0; i--) {
    counter[i] = Number(value & 255n);
    value >>= 8n;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    base32ToBytes(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = digest[digest.length - 1] & 15;
  const binary = (
    ((digest[offset] & 127) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3]
  ) >>> 0;
  return String(binary % 1_000_000).padStart(6, "0");
}

function recoveryCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  let result = "";
  for (let i = 0; i < bytes.length; i++) {
    result += chars[bytes[i] % chars.length];
    if (i === 4) result += "-";
  }
  return result;
}
async function hashRecoveryCode(code: string): Promise<string> {
  return sha256(`${bytesToBase64(recoveryPepper)}:${code}`);
}

function newSession(userId: string | null): Session {
  const now = Date.now();
  const session: Session = {
    id: randomToken(), csrf: randomToken(), userId,
    createdAt: now, lastSeenAt: now, expiresAt: now + SESSION_ABSOLUTE_MS,
    proofStarted: false,
  };
  sessions.set(session.id, session);
  return session;
}
function sessionCookie(session: Session, clear = false): string {
  if (clear) return "mfa_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict";
  return `mfa_session=${session.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}
function cookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0) result[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return result;
}
function getSession(request: Request): Session | null {
  const id = cookies(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  const now = Date.now();
  if (!session || now > session.expiresAt || now - session.lastSeenAt > SESSION_IDLE_MS) {
    if (id) sessions.delete(id);
    return null;
  }
  session.lastSeenAt = now;
  return session;
}

/* Requirement 1: account identity is derived only from this authenticated session. */
function requireOwner(request: Request): { session: Session; record?: MfaRecord } | Response {
  const session = getSession(request);
  if (!session || session.userId !== account.id) return apiError("Please complete identity confirmation to continue.", 401);
  return { session, record: mfaRecords.get(account.id) };
}
function trustedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return !origin || TRUSTED_ORIGINS.has(origin);
}
function headers(nonce = ""): Headers {
  return new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
}
function apiResponse(data: unknown, status = 200, extra?: HeadersInit): Response {
  const h = headers();
  h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((value, key) => h.set(key, value));
  return new Response(JSON.stringify(data), { status, headers: h });
}
function apiError(message = "We could not complete that request. Please try again.", status = 400): Response {
  return apiResponse({ ok: false, message }, status);
}
async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}
function csrfValid(request: Request, session: Session | null): boolean {
  return !!session && trustedOrigin(request) && request.headers.get("x-csrf-token") === session.csrf;
}
function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function validRecoveryCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(value);
}
function clientProofKey(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || "direct-client";
  return `${account.id}:${forwarded}`;
}
function retryMessage(until: number, subject: string): string {
  const minutes = Math.max(1, Math.ceil((until - Date.now()) / 60000));
  return `Too many ${subject} attempts were made. Please wait about ${minutes} minute${minutes === 1 ? "" : "s"}, then try again.`;
}
function recordProofFailure(request: Request): Response {
  const key = clientProofKey(request);
  const state = proofAttempts.get(key) || { failures: 0, lockedUntil: 0 };
  state.failures++;
  if (state.failures >= MAX_FAILURES) {
    state.failures = 0;
    state.lockedUntil = Date.now() + LOCK_MS;
    proofAttempts.set(key, state);
    return apiError(retryMessage(state.lockedUntil, "identity check"), 429);
  }
  proofAttempts.set(key, state);
  const left = MAX_FAILURES - state.failures;
  return apiError(`We could not complete the identity check. Try again. You have ${left} attempt${left === 1 ? "" : "s"} before a short pause.`, 401);
}
function recoveryRetryMessage(record: MfaRecord): string {
  return retryMessage(record.recoveryLockedUntil, "recovery code");
}
function failedRecoveryAttempt(record: MfaRecord): Response {
  record.recoveryFailedAttempts++;
  if (record.recoveryFailedAttempts >= MAX_FAILURES) {
    record.recoveryFailedAttempts = 0;
    record.recoveryLockedUntil = Date.now() + LOCK_MS;
    return apiError(recoveryRetryMessage(record), 429);
  }
  const remaining = MAX_FAILURES - record.recoveryFailedAttempts;
  return apiError(`That recovery code did not work. Check the saved code and try again. You have ${remaining} attempt${remaining === 1 ? "" : "s"} before a short pause.`, 401);
}
async function verifyAuthenticator(record: MfaRecord, otp: string): Promise<boolean> {
  if (Date.now() < record.lockedUntil) return false;
  const secret = await decryptSecret(record.encryptedSecret);
  const current = Math.floor(Date.now() / TOTP_PERIOD_MS);
  for (const step of [current, current - 1]) {
    if (!record.usedSteps.has(step) && await makeTotp(secret, step) === otp) {
      record.usedSteps.add(step);
      record.failedAttempts = 0;
      record.mfaVerifiedAt = Date.now();
      return true;
    }
  }
  record.failedAttempts++;
  if (record.failedAttempts >= MAX_FAILURES) {
    record.failedAttempts = 0;
    record.lockedUntil = Date.now() + LOCK_MS;
  }
  return false;
}

async function handleApi(request: Request, path: string): Promise<Response> {
  if (!trustedOrigin(request)) return apiError("Request could not be accepted.", 403);

  if (request.method === "OPTIONS") {
    const origin = request.headers.get("origin");
    if (!origin || !TRUSTED_ORIGINS.has(origin)) return apiError("Request could not be accepted.", 403);
    const h = headers();
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    h.set("Access-Control-Allow-Credentials", "true");
    return new Response(null, { status: 204, headers: h });
  }

  if (path === "/api/session" && request.method === "GET") {
    let session = getSession(request);
    let cookie: string | undefined;
    if (!session) {
      session = newSession(null);
      cookie = sessionCookie(session);
    }
    return apiResponse({
      ok: true,
      authenticated: session.userId === account.id,
      csrf: session.csrf,
      mfaEnabled: !!mfaRecords.get(account.id)?.enabled,
    }, 200, cookie ? { "Set-Cookie": cookie } : undefined);
  }

  /*
   Requirement task: server-controlled simulated proof. No email, phone,
   account identifier, or reusable account credential is requested or exposed.
  */
  if (path === "/api/proof/start" && request.method === "POST") {
    const session = getSession(request);
    if (!csrfValid(request, session)) return apiError("Your secure page expired. Refresh and try again.", 403);
    const state = proofAttempts.get(clientProofKey(request));
    if (state && Date.now() < state.lockedUntil) return apiError(retryMessage(state.lockedUntil, "identity check"), 429);
    session!.proofStarted = true;
    return apiResponse({ ok: true, message: "Identity check is ready. Use the button below when you are ready." });
  }

  if (path === "/api/proof/complete" && request.method === "POST") {
    const old = getSession(request);
    if (!csrfValid(request, old)) return apiError("Your secure page expired. Refresh and try again.", 403);
    const state = proofAttempts.get(clientProofKey(request));
    if (state && Date.now() < state.lockedUntil) return apiError(retryMessage(state.lockedUntil, "identity check"), 429);
    const input = await body(request);
    /* The external proof is simulated server-side; false/malformed confirmations are rate limited. */
    if (!old!.proofStarted || !input || input.approved !== true) return recordProofFailure(request);
    proofAttempts.delete(clientProofKey(request));
    sessions.delete(old!.id); // rotate identifier after authentication
    const session = newSession(account.id);
    return apiResponse({ ok: true, csrf: session.csrf }, 200, { "Set-Cookie": sessionCookie(session) });
  }

  if (path === "/api/logout" && request.method === "POST") {
    const session = getSession(request);
    if (!csrfValid(request, session)) return apiError("Your secure page expired. Refresh and try again.", 403);
    sessions.delete(session!.id);
    return apiResponse({ ok: true }, 200, { "Set-Cookie": sessionCookie(session!, true) });
  }

  const owner = requireOwner(request);
  if (owner instanceof Response) return owner;
  if (request.method !== "GET" && !csrfValid(request, owner.session)) {
    return apiError("Your secure page expired. Refresh and try again.", 403);
  }

  if (path === "/api/provision" && request.method === "POST") {
    const secret = base32(crypto.getRandomValues(new Uint8Array(20)));
    const record: MfaRecord = {
      encryptedSecret: await encryptSecret(secret), enabled: false,
      failedAttempts: 0, lockedUntil: 0, recoveryFailedAttempts: 0,
      recoveryLockedUntil: 0, usedSteps: new Set(), recoveryHashes: new Set(),
      mfaVerifiedAt: 0,
    };
    mfaRecords.set(account.id, record);
    const testOtp = await makeTotp(secret, Math.floor(Date.now() / TOTP_PERIOD_MS));
    const uri = `otpauth://totp/Example%20Bank:Marcus?secret=${secret}&issuer=Example%20Bank&algorithm=SHA1&digits=6&period=${TOTP_PERIOD_SECONDS}`;
    return apiResponse({ ok: true, provisioningUri: uri, manualSecret: secret, testOtp });
  }

  if (path === "/api/verify-otp" && request.method === "POST") {
    const input = await body(request);
    if (!input || !validOtp(input.otp)) return apiError("Enter all 6 digits. Example: 123456.", 400);
    const record = owner.record;
    if (!record) return apiError("Start authenticator setup first.", 400);
    if (Date.now() < record.lockedUntil) return apiError(retryMessage(record.lockedUntil, "authenticator"), 429);
    if (!(await verifyAuthenticator(record, input.otp))) {
      return apiError("That code did not work. Check the 6 digits and try again.", 401);
    }
    record.enabled = true;
    return apiResponse({ ok: true, message: "Authenticator confirmed. Your recovery codes are ready to make." });
  }

  if (path === "/api/confirm-authenticator" && request.method === "POST") {
    const input = await body(request);
    if (!input || !validOtp(input.otp)) return apiError("Enter all 6 digits. Example: 123456.", 400);
    const record = owner.record;
    if (!record?.enabled) return apiError("Set up your authenticator first.", 400);
    if (Date.now() < record.lockedUntil) return apiError(retryMessage(record.lockedUntil, "authenticator"), 429);
    if (!(await verifyAuthenticator(record, input.otp))) return apiError("That code did not work. Check the 6 digits and try again.", 401);
    return apiResponse({ ok: true, message: "Authenticator confirmed. You can now make new recovery codes." });
  }

  /*
   Requirement task: only this server endpoint creates recovery codes.
   It uses CSPRNG, stores hashes only, and returns this one newly created set once.
   No endpoint accepts client-supplied recovery code sets.
  */
  if (path === "/api/generate-recovery" && request.method === "POST") {
    const record = owner.record;
    if (!record?.enabled) return apiError("Confirm your authenticator first.", 403);
    if (Date.now() - record.mfaVerifiedAt > RECENT_AUTH_MS) {
      return apiResponse({ ok: false, needsConfirmation: true, message: "Confirm your authenticator again before making new recovery codes." }, 403);
    }
    const codes: string[] = [];
    while (codes.length < 8) {
      const code = recoveryCode();
      if (!codes.includes(code)) codes.push(code);
    }
    const hashes = new Set<string>();
    for (const code of codes) hashes.add(await hashRecoveryCode(code));
    record.recoveryHashes = hashes;
    record.recoveryFailedAttempts = 0;
    record.recoveryLockedUntil = 0;
    return apiResponse({ ok: true, codes, message: "Your new recovery codes are ready to save. Old codes no longer work." });
  }

  if (path === "/api/check-recovery" && request.method === "POST") {
    const record = owner.record;
    if (!record) return apiError("That recovery code did not work. Try another saved code.", 401);
    if (Date.now() < record.recoveryLockedUntil) return apiError(recoveryRetryMessage(record), 429);
    const input = await body(request);
    if (!input || !validRecoveryCode(input.code)) return failedRecoveryAttempt(record);
    if (!record.recoveryHashes.delete(await hashRecoveryCode(input.code))) return failedRecoveryAttempt(record);
    record.recoveryFailedAttempts = 0;
    record.recoveryLockedUntil = 0;
    return apiResponse({ ok: true, message: "Recovery code accepted. It cannot be used again." });
  }

  return apiError("That page is not available.", 404);
}

function page(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Example Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#172437;--muted:#526174;--blue:#075fc7;--blue2:#034b9e;--bg:#f4f7fb;--card:#fff;--line:#c9d5e3;--good:#087443;--error:#aa2632;--focus:#f6b900}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Arial,Verdana,Tahoma,sans-serif;font-size:18px;line-height:1.65;letter-spacing:.035em}button,input{font:inherit;letter-spacing:.025em}button{cursor:pointer}button:focus-visible,input:focus-visible{outline:4px solid var(--focus);outline-offset:3px}.shell{max-width:590px;margin:auto;min-height:100vh;padding:18px 16px 42px}.brand{font-weight:800;font-size:1.1rem;margin:2px 0 22px}.brand span{color:var(--blue)}.progress{display:flex;gap:7px;margin:0 0 22px}.progress i{height:7px;background:#cdd7e2;border-radius:10px;flex:1}.progress i.on{background:var(--blue)}main{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:25px 21px;box-shadow:0 3px 12px #17345c12}h1{font-size:1.55rem;line-height:1.28;letter-spacing:.015em;margin:0 0 12px}p{margin:0 0 16px}.icon{font-size:1.7rem;margin-right:8px}.hint{background:#edf5ff;border-left:5px solid var(--blue);padding:12px 14px;border-radius:7px;margin:16px 0;color:#263d59;font-size:.93rem}.success{background:#e9f8ef;border-left-color:var(--good)}.error{background:#fff0f1;border-left:5px solid var(--error);padding:12px 14px;border-radius:7px;color:#77202a;margin:14px 0}.field{display:block;font-weight:700;margin:16px 0 5px}.example{font-size:.86rem;color:var(--muted);margin-bottom:5px}input{width:100%;padding:13px;border:2px solid #92a6be;border-radius:9px;background:#fff;color:var(--ink)}input.otp{font-size:1.4rem;letter-spacing:.22em;text-align:center;font-weight:700}.primary{border:0;border-radius:10px;background:var(--blue);color:#fff;font-weight:800;width:100%;padding:14px 16px;margin:21px 0 8px;min-height:55px}.primary:hover{background:var(--blue2)}.secondary{border:2px solid var(--blue);background:#fff;color:var(--blue);border-radius:9px;padding:10px 13px;font-weight:700;margin:7px 6px 0 0}.link{border:0;background:transparent;color:var(--blue);text-decoration:underline;padding:8px 2px;font-weight:700}.help{margin-top:22px;border-top:1px solid var(--line);padding-top:13px;font-size:.91rem}.qr{display:grid;grid-template-columns:repeat(11,1fr);gap:2px;width:220px;height:220px;padding:12px;margin:18px auto;background:white;border:1px solid var(--line);border-radius:10px}.qr b{background:#111}.secret,.codes{font-family:Arial,Verdana,sans-serif;letter-spacing:.12em;line-height:2;padding:12px;background:#f6f8fb;border:1px solid var(--line);border-radius:8px;word-break:break-all}.logs{margin-top:20px;font-size:.8rem}.logs pre{white-space:pre-wrap;word-break:break-word;background:#172437;color:#fff;padding:10px;border-radius:7px}@media(max-width:370px){body{font-size:16px}.shell{padding:12px 10px}main{padding:20px 16px}}
</style>
</head>
<body>
<div class="shell"><header><div class="brand">Example <span>Bank</span></div><div class="progress" aria-label="Enrolment progress"><i id="p1"></i><i id="p2"></i><i id="p3"></i><i id="p4"></i></div></header><main id="app" aria-live="polite">Loading your secure page…</main></div>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",provision=null,recoveryCodes=[],resume=false;const app=document.getElementById("app"),logLines=[];
const esc=v=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&gt;",">":"&lt;",'"':"&#39;"}[c]));
function log(message){console.log("[MFA demo]",message);logLines.push(message);const p=document.getElementById("logs");if(p)p.textContent=logLines.join("\\n")}
function progress(step){[1,2,3,4].forEach(n=>document.getElementById("p"+n).className=n<=step?"on":"")}
function err(m){return '<div class="error" role="alert">⚠️ '+esc(m)+'</div>'}
function help(){return '<div class="help">💡 <strong>Need help?</strong> You can pause, retry, reveal details, or copy them. There is no reading time limit.</div>'}
function logs(){return '<details class="logs" open><summary>Logs</summary><pre id="logs">'+esc(logLines.join("\\n"))+'</pre></details>'}
async function api(path,data,method="POST"){const o={method,headers:{"Content-Type":"application/json"}};if(method!=="GET")o.headers["X-CSRF-Token"]=csrf;if(data!==undefined)o.body=JSON.stringify(data);const r=await fetch(path,o);const result=await r.json().catch(()=>({ok:false,message:"We could not complete that request. Try again."}));if(result.csrf)csrf=result.csrf;return result}
async function copy(text,notice){try{await navigator.clipboard.writeText(text);return '<div class="hint success">✅ '+esc(notice)+'</div>'}catch{return err("Copy was not available. Please try again.")}}
function grouped(s){return s.match(/.{1,4}/g).join(" ")}
function qr(){let cells="";for(let i=0;i<121;i++)if((i*17+i*i*7+3)%5<2||i<33&&i%11<7||i>87&&i%11<7)cells+="<b></b>";else cells+="<span></span>";return '<div class="qr" role="img" aria-label="Authenticator setup QR code. You can use the manual secret instead.">'+cells+"</div>"}
function identity(message=""){progress(1);app.innerHTML='<h1><span class="icon">🪪</span>Confirm it is you</h1><p>Use this short simulated identity check. No account password or personal details are shown here.</p>'+message+'<button class="primary" id="start">Start identity check</button>'+help()+logs();start.onclick=async()=>{const r=await api("/api/proof/start",{});if(!r.ok)return identity(err(r.message));proof(r.message)}}
function proof(message){progress(1);app.innerHTML='<h1><span class="icon">✅</span>Identity check ready</h1><p>'+esc(message)+'</p><div class="hint">This demo safely simulates a completed proof of identity on the bank server.</div><button class="primary" id="completeproof">Complete identity check</button>'+help()+logs();completeproof.onclick=async()=>{const r=await api("/api/proof/complete",{approved:true});if(!r.ok)return identity(err(r.message));csrf=r.csrf;setup()}}
function setup(message=""){progress(2);app.innerHTML='<h1><span class="icon">📱</span>Add your authenticator</h1><p>Use an authenticator app on your phone. We can make your private setup details now.</p>'+message+'<button class="primary" id="create">Create my setup details</button>'+help()+logs();create.onclick=async()=>{const r=await api("/api/provision",{});if(!r.ok)return setup(err(r.message));provision=r;log("Test authenticator code: "+r.testOtp);showProvision()}}
function showProvision(message="",revealed=false){progress(2);const secret=revealed?'<div class="secret" aria-label="Manual authenticator secret">'+esc(grouped(provision.manualSecret))+'</div>':'<div class="hint">Your manual secret is hidden until you choose to show it.</div>';app.innerHTML='<h1><span class="icon">📲</span>Add this to your app</h1><p>Scan the QR option in an authenticator app. You can also reveal and copy the manual secret.</p>'+message+qr()+secret+'<button class="secondary" id="toggle">'+(revealed?"Hide manual secret":"Reveal manual secret")+'</button><button class="secondary" id="copysecret">Copy manual secret</button><button class="primary" id="continue">I added it — continue</button><button class="link" id="again">Create new setup details</button>'+help()+logs();toggle.onclick=()=>showProvision("",!revealed);copysecret.onclick=async()=>showProvision(await copy(provision.manualSecret,"Manual secret copied."),revealed);continue.onclick=()=>verify();again.onclick=()=>setup()}
function verify(message=""){progress(3);app.innerHTML='<h1><span class="icon">✅</span>Check your authenticator</h1><p>Enter the 6-digit code from your authenticator app.</p>'+message+'<label class="field" for="otp">6-digit code</label><div class="example">Example: 123456</div><input class="otp" id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6"><div class="hint">⌛ Take your time. You may retry safely.</div><button class="primary" id="verify">Confirm code</button><button class="link" id="back">I need setup details again</button>'+help()+logs();otp.focus();verify.onclick=async()=>{const r=await api("/api/verify-otp",{otp:otp.value.trim()});if(!r.ok)return verify(err(r.message));makeRecovery(r.message)};back.onclick=()=>showProvision()}
async function makeRecovery(message){const r=await api("/api/generate-recovery",{});if(!r.ok){if(r.needsConfirmation)return confirmAuthenticator(r.message);return complete(err(r.message))}recoveryCodes=r.codes;log("Test recovery codes: "+recoveryCodes.join(", "));recovery(message||r.message)}
function recovery(message){progress(4);app.innerHTML='<h1><span class="icon">🗝️</span>Save your recovery codes</h1><p>Your eight one-use recovery codes are ready. Keep them somewhere private.</p><div class="hint success">✅ '+esc(message)+'</div><div class="codes">'+recoveryCodes.map(esc).join("<br>")+'</div><button class="secondary" id="copycodes">Copy recovery codes</button><button class="primary" id="saved">I saved my codes</button>'+help()+logs();copycodes.onclick=async()=>recovery(await copy(recoveryCodes.join("\\n"),"Recovery codes copied."));saved.onclick=()=>complete()}
function confirmAuthenticator(message){progress(4);app.innerHTML='<h1><span class="icon">🔐</span>Confirm your authenticator</h1><p>For safety, enter a fresh 6-digit code before making new recovery codes.</p>'+err(message)+'<label class="field" for="otp">6-digit code</label><div class="example">Example: 123456</div><input class="otp" id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6"><button class="primary" id="confirmotp">Confirm authenticator</button><button class="link" id="return">Return to security setup</button>'+help()+logs();otp.focus();confirmotp.onclick=async()=>{const r=await api("/api/confirm-authenticator",{otp:otp.value.trim()});if(!r.ok)return confirmAuthenticator(r.message);if(resume){resume=false;return makeRecovery(r.message)}complete('<div class="hint success">✅ '+esc(r.message)+'</div>')};return.onclick=()=>complete()}
function recoveryCheck(message=""){progress(4);app.innerHTML='<h1><span class="icon">🗝️</span>Use a recovery code</h1><p>Enter one saved recovery code. Each code works once.</p>'+message+'<label class="field" for="recovery">Recovery code</label><div class="example">Example: ABCDE-FGHIJ</div><input id="recovery" autocomplete="one-time-code" autocapitalize="characters" maxlength="11"><button class="primary" id="check">Check recovery code</button><button class="link" id="return">Return to security setup</button>'+help()+logs();recovery.oninput=()=>recovery.value=recovery.value.toUpperCase().replace(/[^A-Z2-9]/g,"").slice(0,10).replace(/^(.{5})(.)/,"$1-$2");check.onclick=async()=>{const r=await api("/api/check-recovery",{code:recovery.value.trim()});if(!r.ok)return recoveryCheck(err(r.message));complete('<div class="hint success">✅ '+esc(r.message)+'</div>')};return.onclick=()=>complete()}
function complete(message=""){progress(4);recoveryCodes=[];provision=null;app.innerHTML='<h1><span class="icon">🎉</span>Your extra security is on</h1><p>You have finished MFA enrolment. Use your authenticator when a payment needs extra confirmation.</p>'+message+'<div class="hint success">✅ Authenticator enabled and recovery codes saved.</div><button class="primary" id="newcodes">Make new recovery codes</button><button class="secondary" id="usecode">Use a recovery code</button><button class="link" id="logout">Sign out</button>'+help()+logs();newcodes.onclick=()=>{resume=true;confirmAuthenticator("Confirm your authenticator before making replacement codes.")};usecode.onclick=()=>recoveryCheck();logout.onclick=async()=>{await api("/api/logout",{});identity('<div class="hint success">You are signed out.</div>')}}
async function start(){const r=await api("/api/session",undefined,"GET");if(!r.ok){app.textContent="We could not open this secure page. Refresh and try again.";return}csrf=r.csrf;if(r.authenticated&&r.mfaEnabled)complete();else if(r.authenticated)setup();else identity()}start();
})();
</script>
</body>
</html>`;
}

const cert = readFileSync(CERT_PATH);
const key = readFileSync(KEY_PATH);

/* Requirement 2: TLS-only listener, HSTS, and generic error responses. */
Bun.serve({
  port: 3000,
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:") {
        return new Response(null, { status: 308, headers: { Location: `https://${url.host}${url.pathname}` } });
      }
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = randomToken(18);
        const h = headers(nonce);
        h.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers: h });
      }
      return new Response("Page not found.", { status: 404, headers: headers() });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: headers() });
    }
  },
});

console.log("MFA enrolment server listening securely on https://localhost:3000");
