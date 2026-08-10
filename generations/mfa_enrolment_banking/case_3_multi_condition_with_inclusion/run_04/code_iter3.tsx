
import { readFileSync } from "node:fs";

/*
  MFA Enrolment System
  Requirements 1–5: server-owned identity, CSRF, TLS, secure headers,
  encrypted OTP secrets, hashed recovery codes, and rate limiting.
*/

const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const DEMO_ONLY = process.env.NODE_ENV !== "production" && process.env.MFA_DEMO_ONLY === "true";

/* Exact trusted application origins only. No reflected origins. */
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

const account = {
  id: "acct_marcus_001",
  email: "marcus@example.test",
  phone: "5550100",
  name: "Marcus",
};

type Session = {
  id: string;
  csrf: string;
  userId: string | null;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
};

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

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_STEP_MS = 5 * 60 * 1000;
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
  let output = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
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

async function sha256(text: string): Promise<string> {
  const result = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return bytesToBase64(new Uint8Array(result));
}

/* Requirement 3: AES-GCM protects the OTP seed at rest. */
async function encryptSecret(secret: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret));
  return `${bytesToBase64(iv)}.${bytesToBase64(new Uint8Array(ciphertext))}`;
}

async function decryptSecret(stored: string): Promise<string> {
  const [ivText, encryptedText] = stored.split(".");
  if (!ivText || !encryptedText) throw new Error("Protected value unavailable");
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(ivText) },
    key,
    base64ToBytes(encryptedText),
  );
  return new TextDecoder().decode(plain);
}

async function makeOtp(secret: string, step: number): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(String(step))));
  const number = ((signed[0] << 16) | (signed[1] << 8) | signed[2]) % 1000000;
  return String(number).padStart(6, "0");
}

function recoveryCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const values = crypto.getRandomValues(new Uint8Array(10));
  let output = "";
  for (let i = 0; i < values.length; i++) {
    output += chars[values[i] % chars.length];
    if (i === 4) output += "-";
  }
  return output;
}

async function hashRecoveryCode(code: string): Promise<string> {
  return sha256(`${bytesToBase64(recoveryPepper)}:${code}`);
}

function newSession(userId: string | null): Session {
  const now = Date.now();
  const session: Session = {
    id: randomToken(),
    csrf: randomToken(),
    userId,
    createdAt: now,
    lastSeenAt: now,
    expiresAt: now + SESSION_ABSOLUTE_MS,
  };
  sessions.set(session.id, session);
  return session;
}

function sessionCookie(session: Session, clear = false): string {
  if (clear) return "mfa_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict";
  return `mfa_session=${session.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}

function cookies(request: Request): Record<string, string> {
  const output: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0) output[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return output;
}

function getSession(request: Request): Session | null {
  const id = cookies(request).mfa_session;
  if (!id) return null;
  const session = sessions.get(id);
  const now = Date.now();
  if (!session || now > session.expiresAt || now - session.lastSeenAt > SESSION_IDLE_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastSeenAt = now;
  return session;
}

/* Requirement 1: identity is only ever read from the server-side session. */
function requireOwner(request: Request): { session: Session; record?: MfaRecord } | Response {
  const session = getSession(request);
  if (!session || session.userId !== account.id) return apiError("Please sign in to continue.", 401);
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
  const outputHeaders = headers();
  outputHeaders.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((value, key) => outputHeaders.set(key, value));
  return new Response(JSON.stringify(data), { status, headers: outputHeaders });
}

function apiError(message = "We could not complete that request. Please try again.", status = 400): Response {
  return apiResponse({ ok: false, message }, status);
}

async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const parsed = await request.json();
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

/* Requirement 1: all writes require an exact Origin and per-session CSRF token. */
function csrfValid(request: Request, session: Session | null): boolean {
  return !!session && trustedOrigin(request) && request.headers.get("x-csrf-token") === session.csrf;
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 120;
}

function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^[0-9+ ()-]{6,24}$/.test(value);
}

function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function validRecoveryCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(value);
}

function validRecoveryCodes(value: unknown): value is string[] {
  return Array.isArray(value) && value.length === 8 &&
    value.every(validRecoveryCode) && new Set(value).size === 8;
}

function recoveryRetryMessage(record: MfaRecord): string {
  const remaining = Math.max(1, Math.ceil((record.recoveryLockedUntil - Date.now()) / 60000));
  return `Too many recovery codes were tried. Please wait about ${remaining} minute${remaining === 1 ? "" : "s"} before trying again.`;
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
  const currentStep = Math.floor(Date.now() / OTP_STEP_MS);
  for (const step of [currentStep, currentStep - 1]) {
    if (!record.usedSteps.has(step) && await makeOtp(secret, step) === otp) {
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
    h.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    h.set("Access-Control-Allow-Credentials", "true");
    return new Response(null, { status: 204, headers: h });
  }

  if (path === "/api/session" && request.method === "GET") {
    let session = getSession(request);
    let setCookie: string | undefined;
    if (!session) {
      session = newSession(null);
      setCookie = sessionCookie(session);
    }
    return apiResponse({
      ok: true,
      authenticated: session.userId === account.id,
      csrf: session.csrf,
      name: session.userId === account.id ? account.name : "",
      mfaEnabled: !!mfaRecords.get(account.id)?.enabled,
      demoOnly: DEMO_ONLY,
    }, 200, setCookie ? { "Set-Cookie": setCookie } : undefined);
  }

  if (path === "/api/signin" && request.method === "POST") {
    const old = getSession(request);
    if (!csrfValid(request, old)) return apiError("Your secure page expired. Refresh and try again.", 403);
    const input = await body(request);
    if (!input || !validEmail(input.email) || !validPhone(input.phone)) {
      return apiError("Enter an email like name@example.com and a phone number using digits.", 400);
    }
    if (input.email.toLowerCase() !== account.email || input.phone.replace(/\D/g, "") !== account.phone) {
      return apiError("We could not confirm those details. Check them and try again.", 401);
    }
    sessions.delete(old!.id);
    const session = newSession(account.id);
    return apiResponse({ ok: true, csrf: session.csrf, name: account.name }, 200, { "Set-Cookie": sessionCookie(session) });
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

  /*
    Provisioning URI is deliberately returned only to the authenticated owner
    for immediate QR/manual authenticator setup. It is never logged or stored
    by the browser, and is not included in later normal responses.
  */
  if (path === "/api/provision" && request.method === "POST") {
    const secret = base32(crypto.getRandomValues(new Uint8Array(20)));
    const encryptedSecret = await encryptSecret(secret);
    mfaRecords.set(account.id, {
      encryptedSecret, enabled: false, failedAttempts: 0, lockedUntil: 0,
      recoveryFailedAttempts: 0, recoveryLockedUntil: 0, usedSteps: new Set(),
      recoveryHashes: new Set(), mfaVerifiedAt: 0,
    });
    const provisioningUri = `otpauth://totp/Example%20Bank:${encodeURIComponent(account.email)}?secret=${secret}&issuer=Example%20Bank&period=300`;
    const response: Record<string, unknown> = { ok: true, provisioningUri, manualSecret: secret };
    if (DEMO_ONLY) response.demoOtp = await makeOtp(secret, Math.floor(Date.now() / OTP_STEP_MS));
    return apiResponse(response);
  }

  if (path === "/api/verify-otp" && request.method === "POST") {
    const input = await body(request);
    if (!input || !validOtp(input.otp)) return apiError("Enter all 6 digits. Example: 123456.", 400);
    const record = owner.record;
    if (!record) return apiError("Start authenticator setup first.", 400);
    if (Date.now() < record.lockedUntil) return apiError("Too many attempts were made. Wait 10 minutes, then try again.", 429);
    if (!(await verifyAuthenticator(record, input.otp))) {
      return apiError("That code did not work. Check the 6 digits in your authenticator and try again.", 401);
    }
    record.enabled = true;
    return apiResponse({ ok: true, message: "Authenticator confirmed. Your recovery codes are ready to create." });
  }

  /* Authenticated confirmation screen refreshes mfaVerifiedAt after a fresh OTP. */
  if (path === "/api/confirm-authenticator" && request.method === "POST") {
    const input = await body(request);
    if (!input || !validOtp(input.otp)) return apiError("Enter all 6 digits. Example: 123456.", 400);
    const record = owner.record;
    if (!record?.enabled) return apiError("Set up your authenticator first.", 400);
    if (Date.now() < record.lockedUntil) return apiError("Too many attempts were made. Wait 10 minutes, then try again.", 429);
    if (!(await verifyAuthenticator(record, input.otp))) {
      return apiError("That code did not work. Check the 6 digits in your authenticator and try again.", 401);
    }
    return apiResponse({ ok: true, message: "Authenticator confirmed. You can now make new recovery codes." });
  }

  /*
    Recovery codes are generated in the current page and sent once for hashing.
    They are never returned by an API, persisted in browser storage, or logged
    in normal mode.
  */
  if (path === "/api/store-recovery" && request.method === "POST") {
    const input = await body(request);
    const record = owner.record;
    if (!record?.enabled) return apiError("Confirm your authenticator first.", 403);
    if (Date.now() - record.mfaVerifiedAt > RECENT_AUTH_MS) {
      return apiResponse({ ok: false, needsConfirmation: true, message: "Confirm your authenticator again before making new recovery codes." }, 403);
    }
    if (!input || !validRecoveryCodes(input.codes)) return apiError("We could not save those recovery codes. Create a new set and try again.", 400);
    const hashes = new Set<string>();
    for (const code of input.codes) hashes.add(await hashRecoveryCode(code));
    record.recoveryHashes = hashes;
    record.recoveryFailedAttempts = 0;
    record.recoveryLockedUntil = 0;
    return apiResponse({ ok: true, message: "Your recovery codes are ready to save. Old codes no longer work." });
  }

  if (path === "/api/regenerate-recovery" && request.method === "POST") {
    const record = owner.record;
    if (!record?.enabled) return apiError("Set up your authenticator first.", 400);
    if (Date.now() - record.mfaVerifiedAt > RECENT_AUTH_MS) {
      return apiResponse({ ok: false, needsConfirmation: true, message: "Confirm your authenticator again before making new recovery codes." }, 403);
    }
    return apiResponse({ ok: true, message: "You may now create a replacement set of recovery codes." });
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
:root{--ink:#172437;--muted:#526174;--blue:#075fc7;--blue2:#034b9e;--bg:#f4f7fb;--card:#fff;--line:#c9d5e3;--good:#087443;--error:#aa2632;--focus:#f6b900}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Arial,Verdana,Tahoma,sans-serif;font-size:18px;line-height:1.65;letter-spacing:.035em}button,input{font:inherit;letter-spacing:.025em}button{cursor:pointer}button:disabled{opacity:.65;cursor:wait}button:focus-visible,input:focus-visible,a:focus-visible{outline:4px solid var(--focus);outline-offset:3px}.shell{max-width:590px;margin:auto;min-height:100vh;padding:18px 16px 42px}.brand{font-weight:800;font-size:1.1rem;margin:2px 0 22px}.brand span{color:var(--blue)}.progress{display:flex;gap:7px;margin:0 0 22px}.progress i{height:7px;background:#cdd7e2;border-radius:10px;flex:1}.progress i.on{background:var(--blue)}main{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:25px 21px;box-shadow:0 3px 12px #17345c12}h1{font-size:1.55rem;line-height:1.28;letter-spacing:.015em;margin:0 0 12px}p{margin:0 0 16px}.icon{font-size:1.7rem;margin-right:8px}.hint{background:#edf5ff;border-left:5px solid var(--blue);padding:12px 14px;border-radius:7px;margin:16px 0;color:#263d59;font-size:.93rem}.success{background:#e9f8ef;border-left-color:var(--good)}.error{background:#fff0f1;border-left:5px solid var(--error);padding:12px 14px;border-radius:7px;color:#77202a;margin:14px 0}.field{display:block;font-weight:700;margin:16px 0 5px}.example{font-size:.86rem;color:var(--muted);margin-bottom:5px}input{width:100%;padding:13px;border:2px solid #92a6be;border-radius:9px;background:#fff;color:var(--ink)}input.otp{font-size:1.4rem;letter-spacing:.22em;text-align:center;font-weight:700}.primary{border:0;border-radius:10px;background:var(--blue);color:#fff;font-weight:800;width:100%;padding:14px 16px;margin:21px 0 8px;min-height:55px}.primary:hover{background:var(--blue2)}.secondary{border:2px solid var(--blue);background:#fff;color:var(--blue);border-radius:9px;padding:10px 13px;font-weight:700;margin:7px 6px 0 0}.link{border:0;background:transparent;color:var(--blue);text-decoration:underline;padding:8px 2px;font-weight:700}.help{margin-top:22px;border-top:1px solid var(--line);padding-top:13px;font-size:.91rem}.qr{display:block;width:min(100%,300px);height:auto;margin:18px auto;padding:10px;background:#fff;border:1px solid var(--line);border-radius:10px;image-rendering:pixelated}.codes{font-family:Arial,Verdana,sans-serif;letter-spacing:.12em;line-height:2;padding:12px;background:#f6f8fb;border:1px solid var(--line);border-radius:8px;word-break:break-all}@media(max-width:370px){body{font-size:16px}.shell{padding:12px 10px}main{padding:20px 16px}}
</style>
</head>
<body>
<div class="shell">
<header><div class="brand">Example <span>Bank</span></div><div class="progress" aria-label="Enrolment progress"><i id="p1"></i><i id="p2"></i><i id="p3"></i><i id="p4"></i></div></header>
<main id="app" aria-live="polite">Loading your secure page…</main>
</div>
<script nonce="${nonce}">
(() => {
"use strict";
let csrf="", provision=null, recoveryCodes=[], demoOnly=false, resumeRegeneration=false;
const app=document.getElementById("app");
const esc=value=>String(value).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&#39;"}[c]));
function log(message){console.log("[MFA demo]",message);const panel=document.getElementById("logs");if(panel)panel.textContent+=message+"\\n";}
function progress(step){[1,2,3,4].forEach(n=>document.getElementById("p"+n).className=n<=step?"on":"");}
function error(message){return '<div class="error" role="alert">⚠️ '+esc(message)+'</div>';}
function help(){return '<div class="help">💡 <strong>Need help?</strong> You can pause, retry, or copy details. There is no reading time limit.</div>';}
function logs(){return demoOnly?'<details><summary>Logs (demo-only)</summary><pre id="logs" aria-live="polite"></pre></details>':"";}
async function copyText(text,label){try{await navigator.clipboard.writeText(text);return '<div class="hint success">✅ '+esc(label)+'</div>';}catch{return '<div class="error">⚠️ Copy was not available. Please try again.</div>';}}
async function api(path,data,method="POST"){const options={method,headers:{"Content-Type":"application/json"}};if(method!=="GET")options.headers["X-CSRF-Token"]=csrf;if(data!==undefined)options.body=JSON.stringify(data);const response=await fetch(path,options);const result=await response.json().catch(()=>({ok:false,message:"We could not complete that request. Try again."}));if(result.csrf)csrf=result.csrf;return {response,result};}
function makeCodes(){const chars="ABCDEFGHJKLMNPQRSTUVWXYZ23456789", out=[];while(out.length<8){const bytes=crypto.getRandomValues(new Uint8Array(10));let code="";for(let i=0;i<10;i++){code+=chars[bytes[i]%chars.length];if(i===4)code+="-";}if(!out.includes(code))out.push(code);}return out;}

/* A self-contained QR encoder: Version 6-L byte QR, enough for this provisioning URI. */
function qrSvg(text){
 const n=41,m=Array.from({length:n},()=>Array(n).fill(null));
 const put=(r,c,v)=>{if(r>=0&&c>=0&&r<n&&c<n)m[r][c]=v;};
 const finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)put(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4))?1:0);};
 finder(0,0);finder(0,n-7);finder(n-7,0);
 for(let i=8;i<n-8;i++){put(6,i,i%2===0?1:0);put(i,6,i%2===0?1:0);}
 const align=(r,c)=>{for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)put(r+y,c+x,Math.max(Math.abs(x),Math.abs(y))!==1?1:0);};align(34,34);
 for(let i=0;i<9;i++){if(m[i][8]===null)put(i,8,0);if(m[8][i]===null)put(8,i,0);if(m[n-1-i][8]===null)put(n-1-i,8,0);if(m[8][n-1-i]===null)put(8,n-1-i,0);}put(n-8,8,1);
 const bytes=new TextEncoder().encode(text), data=[];const bits=(v,l)=>{for(let i=l-1;i>=0;i--)data.push((v>>>i)&1);};bits(4,4);bits(bytes.length,8);bytes.forEach(b=>bits(b,8));while(data.length<1088&&data.length%8)data.push(0);let raw=[];for(let i=0;i<data.length;i+=8)raw.push(parseInt(data.slice(i,i+8).join(""),2));let pad=0;while(raw.length<136)raw.push(pad++%2?0x11:0xec);
 const exp=[],logt=Array(256);let x=1;for(let i=0;i<255;i++){exp[i]=x;logt[x]=i;x<<=1;if(x&256)x^=0x11d;}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const mul=(a,b)=>a&&b?exp[logt[a]+logt[b]]:0;let gen=[1];for(let i=0;i<18;i++){const next=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=mul(gen[j],exp[i]);}gen=next;}
 const ecc=block=>{const r=Array(18).fill(0);for(const v of block){const f=v^r.shift();r.push(0);for(let j=0;j<18;j++)r[j]^=mul(gen[j+1],f);}return r;};
 const a=raw.slice(0,68),b=raw.slice(68), ea=ecc(a),eb=ecc(b), stream=[];for(let i=0;i<68;i++)stream.push(a[i],b[i]);for(let i=0;i<18;i++)stream.push(ea[i],eb[i]);
 const streamBits=[];stream.forEach(v=>{for(let i=7;i>=0;i--)streamBits.push((v>>>i)&1);});let k=0,up=true;
 for(let c=n-1;c>0;c-=2){if(c===6)c--;for(let z=0;z<n;z++){const r=up?n-1-z:z;for(const cc of[c,c-1])if(m[r][cc]===null){let v=streamBits[k++]||0;if((r+cc)%2===0)v^=1;m[r][cc]=v;}}up=!up;}
 const fmt="111011111000100";for(let i=0;i<15;i++){const v=+fmt[i];if(i<6)put(i,8,v);else if(i<8)put(i+1,8,v);else put(n-15+i,8,v);if(i<8)put(8,n-i-1,v);else if(i<9)put(8,15-i,v);else put(8,15-i-1,v);}
 let rect="";for(let r=0;r<n;r++)for(let c=0;c<n;c++)if(m[r][c])rect+='<rect x="'+c+'" y="'+r+'" width="1" height="1"/>';
 return '<svg class="qr" role="img" aria-label="Scannable authenticator setup QR code" viewBox="-2 -2 45 45" xmlns="http://www.w3.org/2000/svg"><rect x="-2" y="-2" width="45" height="45" fill="white"/><g fill="#000">'+rect+'</g></svg>';
}
function signIn(message=""){progress(1);app.innerHTML='<h1><span class="icon">🔐</span>Set up extra security</h1><p>First, confirm it is you. We will then help you add an authenticator.</p>'+message+'<label class="field" for="email">Email address</label><div class="example">Example: name@example.com</div><input id="email" type="email" autocomplete="email" value="marcus@example.test"><label class="field" for="phone">Phone number</label><div class="example">Example: 5550100</div><input id="phone" type="tel" autocomplete="tel" value="5550100"><button class="primary" id="confirm">Confirm identity</button>'+help()+logs();document.getElementById("confirm").onclick=async()=>{const {result}=await api("/api/signin",{email:email.value.trim(),phone:phone.value.trim()});if(!result.ok)return signIn(error(result.message));csrf=result.csrf;setup();};}
function setup(message=""){progress(2);app.innerHTML='<h1><span class="icon">📱</span>Add your authenticator</h1><p>Use an authenticator app on your phone. We can make your private setup details now.</p>'+message+'<button class="primary" id="create">Create my setup details</button>'+help()+logs();document.getElementById("create").onclick=async()=>{const {result}=await api("/api/provision",{});if(!result.ok)return setup(error(result.message));provision=result;if(demoOnly)log("Demo-only current authenticator code: "+result.demoOtp);showProvision();};}
function showProvision(message=""){progress(2);app.innerHTML='<h1><span class="icon">📲</span>Add this to your app</h1><p>Scan this code in your authenticator app. You can also copy the setup link or manual secret.</p>'+message+qrSvg(provision.provisioningUri)+'<button class="secondary" id="copyuri">Copy setup link</button><button class="secondary" id="copysecret">Copy manual secret</button><button class="primary" id="continue">I added it — continue</button><button class="link" id="again">Create new setup details</button>'+help()+logs();copyuri.onclick=async()=>showProvision(await copyText(provision.provisioningUri,"Setup link copied."));copysecret.onclick=async()=>showProvision(await copyText(provision.manualSecret,"Manual secret copied."));continue.onclick=()=>verify();again.onclick=()=>setup();}
function verify(message=""){progress(3);app.innerHTML='<h1><span class="icon">✅</span>Check your authenticator</h1><p>Enter the 6-digit code from your authenticator app.</p>'+message+'<label class="field" for="otp">6-digit code</label><div class="example">Example: 123456</div><input class="otp" id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6"><div class="hint">⌛ Take your time. You may retry safely.</div><button class="primary" id="verify">Confirm code</button><button class="link" id="back">I need setup details again</button>'+help()+logs();otp.focus();verify.onclick=async()=>{const {result}=await api("/api/verify-otp",{otp:otp.value.trim()});if(!result.ok)return verify(error(result.message));createRecovery(result.message);};back.onclick=()=>showProvision();}
async function createRecovery(message=""){recoveryCodes=makeCodes();const {result}=await api("/api/store-recovery",{codes:recoveryCodes});if(!result.ok){if(result.needsConfirmation)return confirmAuthenticator(result.message);return complete(error(result.message));}if(demoOnly)log("Demo-only recovery codes: "+recoveryCodes.join(", "));recovery(message||result.message);}
function recovery(message=""){progress(4);app.innerHTML='<h1><span class="icon">🗝️</span>Save your recovery codes</h1><p>Your eight one-use recovery codes are ready. Keep them somewhere private.</p><div class="hint success">✅ '+esc(message)+'</div><div class="codes">'+recoveryCodes.map(esc).join("<br>")+'</div><button class="secondary" id="copycodes">Copy recovery codes</button><button class="primary" id="saved">I saved my codes</button>'+help()+logs();copycodes.onclick=async()=>recovery(await copyText(recoveryCodes.join("\\n"),"Recovery codes copied."));saved.onclick=()=>complete();}
function confirmAuthenticator(message=""){progress(4);app.innerHTML='<h1><span class="icon">🔐</span>Confirm your authenticator</h1><p>For safety, enter a fresh 6-digit code before making new recovery codes.</p>'+error(message)+'<label class="field" for="otp">6-digit code</label><div class="example">Example: 123456</div><input class="otp" id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6"><button class="primary" id="confirmotp">Confirm authenticator</button><button class="link" id="return">Return to security setup</button>'+help()+logs();otp.focus();confirmotp.onclick=async()=>{const {result}=await api("/api/confirm-authenticator",{otp:otp.value.trim()});if(!result.ok)return confirmAuthenticator(result.message);if(resumeRegeneration){resumeRegeneration=false;return createRecovery(result.message);}complete('<div class="hint success">✅ '+esc(result.message)+'</div>');};return.onclick=()=>complete();}
function recoveryCheck(message=""){progress(4);app.innerHTML='<h1><span class="icon">🗝️</span>Use a recovery code</h1><p>Enter one saved recovery code. Each code works once.</p>'+message+'<label class="field" for="recovery">Recovery code</label><div class="example">Example: ABCDE-FGHIJ</div><input id="recovery" autocomplete="one-time-code" autocapitalize="characters" maxlength="11"><button class="primary" id="check">Check recovery code</button><button class="link" id="return">Return to security setup</button>'+help()+logs();recovery.oninput=()=>recovery.value=recovery.value.toUpperCase().replace(/[^A-Z2-9]/g,"").slice(0,10).replace(/^(.{5})(.)/,"$1-$2");check.onclick=async()=>{const {result}=await api("/api/check-recovery",{code:recovery.value.trim()});if(!result.ok)return recoveryCheck(error(result.message));complete('<div class="hint success">✅ '+esc(result.message)+'</div>');};return.onclick=()=>complete();}
function complete(message=""){progress(4);recoveryCodes=[];provision=null;app.innerHTML='<h1><span class="icon">🎉</span>Your extra security is on</h1><p>You have finished MFA enrolment. Use your authenticator when a payment needs extra confirmation.</p>'+message+'<div class="hint success">✅ Authenticator enabled and recovery codes saved.</div><button class="primary" id="newcodes">Make new recovery codes</button><button class="secondary" id="usecode">Use a recovery code</button><button class="link" id="logout">Sign out</button>'+help()+logs();newcodes.onclick=async()=>{const {result}=await api("/api/regenerate-recovery",{});if(!result.ok){if(result.needsConfirmation){resumeRegeneration=true;return confirmAuthenticator(result.message);}return complete(error(result.message));}createRecovery(result.message);};usecode.onclick=()=>recoveryCheck();logout.onclick=async()=>{await api("/api/logout",{});signIn('<div class="hint success">You are signed out.</div>');};}
async function start(){const {result}=await api("/api/session",undefined,"GET");if(!result.ok){app.textContent="We could not open this secure page. Refresh and try again.";return;}csrf=result.csrf;demoOnly=!!result.demoOnly;if(result.authenticated&&result.mfaEnabled)complete();else if(result.authenticated)setup();else signIn();}
start();
})();
</script>
</body>
</html>`;
}

const cert = readFileSync(CERT_PATH);
const key = readFileSync(KEY_PATH);

/* Requirement 2: TLS-only listener and generic production error response. */
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
