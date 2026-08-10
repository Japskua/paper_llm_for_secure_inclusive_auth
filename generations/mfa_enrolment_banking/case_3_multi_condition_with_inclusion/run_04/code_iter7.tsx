
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System
 Requirements 1–5: server-owned sessions, CSRF, TLS, secure headers,
 encrypted TOTP seeds, hashed recovery codes, rate limits, and safe output.
*/

const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

/*
 Task: This is a server-side, user-specific mock pre-authentication fixture.
 Starting a proof does not authenticate anyone. The fixture credential must
 validate before the session can be linked to Marcus's server-side account.
 */
const account = { id: "acct_marcus_001", name: "Marcus" };
const authenticatedFixture = {
  accountId: account.id,
  enabled: true,
  mockCredential: "MARCUS-DEMO-2025",
};

type Session = {
  id: string;
  csrf: string;
  userId: string | null;
  preAuthenticatedAccountId: string | null;
  proofStarted: boolean;
  proofCredential: string | null;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
};

type AttemptState = { failures: number; lockedUntil: number };

type MfaRecord = {
  encryptedSecret: string;
  enabled: boolean;
  usedSteps: Set<number>;
  failedAttempts: number;
  lockedUntil: number;
  recoveryHashes: Set<string>;
  recoveryFailedAttempts: number;
  recoveryLockedUntil: number;
  mfaVerifiedAt: number;
};

const sessions = new Map<string, Session>();
const mfaRecords = new Map<string, MfaRecord>();
const proofAttempts = new Map<string, AttemptState>();

const encoder = new TextEncoder();
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const recoveryPepper = crypto.getRandomValues(new Uint8Array(32));

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const TOTP_PERIOD_MS = 30_000;
const RECENT_AUTH_MS = 5 * 60 * 1000;

/* Task: false by default. Forwarding headers are never trusted directly. */
const TRUSTED_PROXY = false;
let server: any;

function b64(bytes: Uint8Array): string {
  let value = "";
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value);
}
function fromB64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}
function token(bytes = 32): string {
  return b64(crypto.getRandomValues(new Uint8Array(bytes)))
    .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function base32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let output = "", buffer = 0, bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) output += alphabet[(buffer << (5 - bits)) & 31];
  return output;
}
function base32Bytes(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = value.toUpperCase().replace(/=|\s/g, "");
  let buffer = 0, bits = 0;
  const output: number[] = [];
  for (const character of clean) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("Invalid value");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}
async function digest(value: string): Promise<string> {
  return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}
function fixedTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return difference === 0;
}
const fixtureCredentialHash = await digest(authenticatedFixture.mockCredential);

async function encrypt(secret: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret));
  return `${b64(iv)}.${b64(new Uint8Array(cipher))}`;
}
async function decrypt(stored: string): Promise<string> {
  const [iv, cipher] = stored.split(".");
  if (!iv || !cipher) throw new Error("Protected value unavailable");
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, key, fromB64(cipher));
  return new TextDecoder().decode(plain);
}
async function totp(secret: string, step: number): Promise<string> {
  const counter = new Uint8Array(8);
  let number = BigInt(step);
  for (let i = 7; i >= 0; i--) {
    counter[i] = Number(number & 255n);
    number >>= 8n;
  }
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const hash = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = hash[hash.length - 1] & 15;
  const numberValue = (((hash[offset] & 127) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3]) >>> 0;
  return String(numberValue % 1_000_000).padStart(6, "0");
}
function makeRecoveryCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  let output = "";
  for (let i = 0; i < 10; i++) {
    output += chars[bytes[i] % chars.length];
    if (i === 4) output += "-";
  }
  return output;
}
async function recoveryHash(code: string): Promise<string> {
  return digest(`${b64(recoveryPepper)}:${code}`);
}

function newSession(userId: string | null = null): Session {
  const now = Date.now();
  const session: Session = {
    id: token(),
    csrf: token(),
    userId,
    preAuthenticatedAccountId: null,
    proofStarted: false,
    proofCredential: null,
    createdAt: now,
    lastSeenAt: now,
    expiresAt: now + SESSION_ABSOLUTE_MS,
  };
  sessions.set(session.id, session);
  return session;
}
function cookie(session: Session, clear = false): string {
  if (clear) return "mfa_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict";
  return `mfa_session=${session.id}; Path=/; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}; HttpOnly; Secure; SameSite=Strict`;
}
function requestCookies(request: Request): Record<string, string> {
  const values: Record<string, string> = {};
  for (const piece of (request.headers.get("cookie") || "").split(";")) {
    const index = piece.indexOf("=");
    if (index > 0) values[piece.slice(0, index).trim()] = piece.slice(index + 1).trim();
  }
  return values;
}
function sessionFor(request: Request): Session | null {
  const id = requestCookies(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  const now = Date.now();
  if (!session || now > session.expiresAt || now - session.lastSeenAt > SESSION_IDLE_MS) {
    if (id) sessions.delete(id);
    return null;
  }
  session.lastSeenAt = now;
  return session;
}
function trustedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return !origin || TRUSTED_ORIGINS.has(origin);
}
function secureHeaders(nonce = ""): Headers {
  return new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
}
function json(data: unknown, status = 200, extra?: HeadersInit): Response {
  const h = secureHeaders();
  h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((value, key) => h.set(key, value));
  return new Response(JSON.stringify(data), { status, headers: h });
}
function fail(message = "We could not complete that request. Please try again.", status = 400): Response {
  return json({ ok: false, message }, status);
}
async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}
function csrf(request: Request, session: Session | null): boolean {
  return !!session && trustedOrigin(request) && request.headers.get("x-csrf-token") === session.csrf;
}
function validCredential(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z0-9-]{8,48}$/.test(value);
}
function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function validRecovery(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(value);
}

/*
 Task: The proof lockout key is based on an HttpOnly server session plus the
 server-observed network context. X-Forwarded-For is ignored unless a trusted
 proxy deployment is explicitly enabled and verified outside this application.
 Thus changing a client-supplied X-Forwarded-For cannot reset a lockout.
*/
function trustedNetworkContext(request: Request): string {
  try {
    const address = server?.requestIP?.(request);
    if (address?.address) return `direct:${address.address}`;
  } catch {}
  if (TRUSTED_PROXY) return "verified-proxy-context";
  return "direct-network-context";
}
function proofKey(request: Request, session: Session | null): string {
  return `${session?.userId || session?.preAuthenticatedAccountId || "anonymous"}:${session?.id || "no-session"}:${trustedNetworkContext(request)}`;
}
function waitMessage(until: number, subject: string): string {
  const minutes = Math.max(1, Math.ceil((until - Date.now()) / 60_000));
  return `Too many ${subject} attempts were made. Please wait about ${minutes} minute${minutes === 1 ? "" : "s"}, then try again.`;
}
function proofFailure(request: Request, session: Session | null): Response {
  const key = proofKey(request, session);
  const state = proofAttempts.get(key) || { failures: 0, lockedUntil: 0 };
  state.failures++;
  if (state.failures >= MAX_FAILURES) {
    state.failures = 0;
    state.lockedUntil = Date.now() + LOCK_MS;
    proofAttempts.set(key, state);
    return fail(waitMessage(state.lockedUntil, "identity check"), 429);
  }
  proofAttempts.set(key, state);
  return fail("We could not complete the identity check. Check your secure sign-in fixture and try again.", 401);
}
function owner(request: Request): { session: Session; record?: MfaRecord } | Response {
  const session = sessionFor(request);
  if (!session || session.userId !== account.id) return fail("Please complete identity confirmation to continue.", 401);
  return { session, record: mfaRecords.get(account.id) };
}
async function verifyTotp(record: MfaRecord, code: string): Promise<boolean> {
  if (Date.now() < record.lockedUntil) return false;
  const secret = await decrypt(record.encryptedSecret);
  const current = Math.floor(Date.now() / TOTP_PERIOD_MS);
  for (const step of [current, current - 1]) {
    if (!record.usedSteps.has(step) && fixedTimeEqual(await totp(secret, step), code)) {
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
function authLockMessage(record: MfaRecord, label: string): Response {
  return fail(waitMessage(record.lockedUntil, label), 429);
}

async function api(request: Request, path: string): Promise<Response> {
  if (!trustedOrigin(request)) return fail("Request could not be accepted.", 403);

  if (request.method === "OPTIONS") {
    const origin = request.headers.get("origin");
    if (!origin || !TRUSTED_ORIGINS.has(origin)) return fail("Request could not be accepted.", 403);
    const h = secureHeaders();
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return new Response(null, { status: 204, headers: h });
  }

  if (path === "/api/session" && request.method === "GET") {
    let session = sessionFor(request);
    let setCookie: string | undefined;
    if (!session) {
      session = newSession();
      setCookie = cookie(session);
    }
    return json({
      ok: true,
      csrf: session.csrf,
      authenticated: session.userId === account.id,
      mfaEnabled: !!mfaRecords.get(account.id)?.enabled,
    }, 200, setCookie ? { "Set-Cookie": setCookie } : undefined);
  }

  if (path === "/api/proof/start" && request.method === "POST") {
    const session = sessionFor(request);
    if (!csrf(request, session)) return fail("Your secure page expired. Refresh and try again.", 403);
    const state = proofAttempts.get(proofKey(request, session));
    if (state && Date.now() < state.lockedUntil) return fail(waitMessage(state.lockedUntil, "identity check"), 429);

    const input = await requestBody(request);
    /*
     Task: Server validation happens before a proof credential is minted.
     An anonymous start without this fixture cannot gain a Marcus session.
    */
    if (!input || !validCredential(input.credential) ||
      !authenticatedFixture.enabled ||
      !fixedTimeEqual(await digest(input.credential), fixtureCredentialHash)) {
      return proofFailure(request, session);
    }

    session!.preAuthenticatedAccountId = authenticatedFixture.accountId;
    session!.proofStarted = true;
    session!.proofCredential = token(32);
    return json({ ok: true, message: "Identity check is ready. Complete it when you are ready." });
  }

  if (path === "/api/proof/complete" && request.method === "POST") {
    const old = sessionFor(request);
    if (!csrf(request, old)) return fail("Your secure page expired. Refresh and try again.", 403);
    const state = proofAttempts.get(proofKey(request, old));
    if (state && Date.now() < state.lockedUntil) return fail(waitMessage(state.lockedUntil, "identity check"), 429);

    const valid = !!old &&
      old.proofStarted &&
      typeof old.proofCredential === "string" &&
      old.proofCredential.length >= 40 &&
      old.preAuthenticatedAccountId === account.id &&
      authenticatedFixture.enabled &&
      authenticatedFixture.accountId === account.id;

    if (!valid) return proofFailure(request, old);

    proofAttempts.delete(proofKey(request, old));
    sessions.delete(old!.id);

    /* Requirement 5: rotate the session identifier after authentication. */
    const authenticated = newSession(account.id);
    return json({ ok: true, csrf: authenticated.csrf }, 200, { "Set-Cookie": cookie(authenticated) });
  }

  if (path === "/api/logout" && request.method === "POST") {
    const session = sessionFor(request);
    if (!csrf(request, session)) return fail("Your secure page expired. Refresh and try again.", 403);
    sessions.delete(session!.id);
    return json({ ok: true }, 200, { "Set-Cookie": cookie(session!, true) });
  }

  const currentOwner = owner(request);
  if (currentOwner instanceof Response) return currentOwner;
  if (request.method !== "GET" && !csrf(request, currentOwner.session)) {
    return fail("Your secure page expired. Refresh and try again.", 403);
  }

  if (path === "/api/provision" && request.method === "POST") {
    const secret = base32(crypto.getRandomValues(new Uint8Array(20)));
    const record: MfaRecord = {
      encryptedSecret: await encrypt(secret),
      enabled: false,
      usedSteps: new Set(),
      failedAttempts: 0,
      lockedUntil: 0,
      recoveryHashes: new Set(),
      recoveryFailedAttempts: 0,
      recoveryLockedUntil: 0,
      mfaVerifiedAt: 0,
    };
    mfaRecords.set(account.id, record);
    return json({
      ok: true,
      manualSecret: secret,
      testOtp: await totp(secret, Math.floor(Date.now() / TOTP_PERIOD_MS)),
    });
  }

  if (path === "/api/verify-otp" && request.method === "POST") {
    const input = await requestBody(request);
    const record = currentOwner.record;
    if (!input || !validOtp(input.otp)) return fail("Enter all 6 digits. Example: 123456.");
    if (!record) return fail("Start authenticator setup first.");
    if (Date.now() < record.lockedUntil) return authLockMessage(record, "authenticator");
    if (!(await verifyTotp(record, input.otp))) {
      if (Date.now() < record.lockedUntil) return authLockMessage(record, "authenticator");
      return fail("That code did not work. Check the 6 digits and try again.", 401);
    }
    record.enabled = true;
    return json({ ok: true, message: "Authenticator confirmed. Your recovery codes are ready." });
  }

  if (path === "/api/generate-recovery" && request.method === "POST") {
    const record = currentOwner.record;
    if (!record?.enabled) return fail("Confirm your authenticator first.", 403);
    if (Date.now() - record.mfaVerifiedAt > RECENT_AUTH_MS) {
      return json({ ok: false, needsConfirmation: true, message: "Confirm your authenticator again before making new recovery codes." }, 403);
    }
    const codes: string[] = [];
    while (codes.length < 8) {
      const code = makeRecoveryCode();
      if (!codes.includes(code)) codes.push(code);
    }
    record.recoveryHashes = new Set(await Promise.all(codes.map(recoveryHash)));
    record.recoveryFailedAttempts = 0;
    record.recoveryLockedUntil = 0;
    return json({ ok: true, codes, message: "Your new recovery codes are ready. Old codes no longer work." });
  }

  if (path === "/api/check-recovery" && request.method === "POST") {
    const record = currentOwner.record;
    if (!record) return fail("That recovery code did not work. Try another saved code.", 401);
    if (Date.now() < record.recoveryLockedUntil) return fail(waitMessage(record.recoveryLockedUntil, "recovery code"), 429);
    const input = await requestBody(request);
    const invalid = !input || !validRecovery(input.code) || !record.recoveryHashes.delete(await recoveryHash(String(input?.code || "")));
    if (invalid) {
      record.recoveryFailedAttempts++;
      if (record.recoveryFailedAttempts >= MAX_FAILURES) {
        record.recoveryFailedAttempts = 0;
        record.recoveryLockedUntil = Date.now() + LOCK_MS;
        return fail(waitMessage(record.recoveryLockedUntil, "recovery code"), 429);
      }
      return fail("That recovery code did not work. Check the saved code and try again.", 401);
    }
    record.recoveryFailedAttempts = 0;
    return json({ ok: true, message: "Recovery code accepted. It cannot be used again." });
  }

  return fail("That page is not available.", 404);
}

function page(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Example Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#172437;--blue:#075fc7;--bg:#f4f7fb;--line:#c9d5e3;--good:#087443;--error:#aa2632;--focus:#f6b900}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:18px/1.65 Arial,Verdana,Tahoma,sans-serif;letter-spacing:.03em}.shell{max-width:590px;margin:auto;padding:18px 16px 42px}.brand{font-weight:800;margin:2px 0 17px}.brand b{color:var(--blue)}.progress{display:flex;gap:7px;margin-bottom:20px}.progress i{height:7px;flex:1;border-radius:8px;background:#cdd7e2}.progress i.on{background:var(--blue)}main,.logs{background:#fff;border:1px solid var(--line);border-radius:17px;padding:24px 20px;box-shadow:0 3px 12px #17345c12}h1{font-size:1.55rem;line-height:1.28;margin:0 0 12px;letter-spacing:.01em}p{margin:0 0 16px}.icon{font-size:1.55rem;margin-right:7px}label{display:block;font-weight:bold;margin:15px 0 4px}.example{font-size:.87rem;color:#526174;margin-bottom:5px}input{width:100%;padding:13px;border:2px solid #92a6be;border-radius:9px;font:inherit;letter-spacing:.06em}.otp{text-align:center;font-size:1.35rem;font-weight:bold;letter-spacing:.22em}.primary,.secondary,.link{font:inherit;font-weight:bold;cursor:pointer}.primary{width:100%;min-height:55px;margin:20px 0 8px;padding:13px;border:0;border-radius:10px;background:var(--blue);color:#fff}.secondary{margin:7px 6px 0 0;padding:9px 12px;border:2px solid var(--blue);border-radius:9px;color:var(--blue);background:#fff}.link{border:0;background:transparent;color:var(--blue);padding:10px 2px;text-decoration:underline}.hint,.error{margin:15px 0;padding:11px 13px;border-radius:7px}.hint{background:#edf5ff;border-left:5px solid var(--blue)}.success{background:#e9f8ef;border-left-color:var(--good)}.error{background:#fff0f1;border-left:5px solid var(--error);color:#77202a}.secret,.codes li{background:#f6f8fb;border:1px solid var(--line);border-radius:8px;padding:11px;word-break:break-all}.secret{letter-spacing:.12em}.codes{list-style:none;padding:0}.codes li{font-weight:bold;letter-spacing:.1em;margin:7px 0}.help{border-top:1px solid var(--line);margin-top:19px;padding-top:12px;font-size:.9rem}.logs{margin-top:18px;padding:14px 16px}.logs h2{font-size:1rem;margin:0 0 6px}.logs pre{white-space:pre-wrap;word-break:break-word;font:14px/1.45 Arial,sans-serif;margin:0;color:#34465d}button:focus-visible,input:focus-visible{outline:4px solid var(--focus);outline-offset:3px}@media(max-width:370px){body{font-size:16px}.shell{padding:12px 10px}main{padding:20px 16px}}
</style>
</head>
<body>
<div class="shell">
<header><div class="brand">Example <b>Bank</b></div><div class="progress" aria-label="Enrolment progress"><i id="p1"></i><i id="p2"></i><i id="p3"></i><i id="p4"></i></div></header>
<main id="app" aria-live="polite">Loading your secure page…</main>
<section class="logs" aria-label="Demo logs"><h2>Logs</h2><pre id="logs">Waiting for setup messages.</pre></section>
</div>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",provision=null,codes=[];
const app=document.querySelector("#app"),logs=document.querySelector("#logs");
const $=s=>document.querySelector(s);
const esc=v=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const note=m=>'<div class="hint">'+esc(m)+"</div>";
const error=m=>'<div class="error" role="alert">⚠️ '+esc(m)+"</div>";
const help=()=>'<div class="help">💡 <b>Need help?</b> You can pause, retry, show details, or copy them. There is no reading time limit.</div>';
function log(message){console.log(message);logs.textContent=(logs.textContent==="Waiting for setup messages."?"":logs.textContent+"\\n")+message}
function progress(n){[1,2,3,4].forEach(i=>$("#p"+i).className=i<=n?"on":"")}
async function api(path,data,method="POST"){const options={method,headers:{"Content-Type":"application/json"}};if(method!=="GET")options.headers["X-CSRF-Token"]=csrf;if(data!==undefined)options.body=JSON.stringify(data);const response=await fetch(path,options);const result=await response.json().catch(()=>({ok:false,message:"We could not complete that request. Try again."}));if(result.csrf)csrf=result.csrf;return result}
async function copy(value){try{await navigator.clipboard.writeText(value);return true}catch{return false}}
function identity(message=""){
 progress(1);app.innerHTML='<h1><span class="icon">🪪</span>Confirm it is you</h1><p>Use the short simulated bank sign-in fixture before identity confirmation.</p>'+message+'<label for="credential">Mock bank sign-in fixture</label><div class="example">Example: MARCUS-DEMO-2025</div><input id="credential" autocomplete="off" autocapitalize="characters" maxlength="48"><button class="primary" id="start">Start identity check</button>'+help();
 $("#start").onclick=async()=>{const credential=$("#credential").value.trim().toUpperCase();const r=await api("/api/proof/start",{credential});if(!r.ok)return identity(error(r.message));proof(r.message)};
}
function proof(message){
 progress(1);app.innerHTML='<h1><span class="icon">✅</span>Identity check ready</h1><p>'+esc(message)+'</p><div class="hint">This demo uses a proof held by the bank server.</div><button class="primary" id="complete">Complete identity check</button>'+help();
 $("#complete").onclick=async()=>{const r=await api("/api/proof/complete",{});if(!r.ok)return identity(error(r.message));csrf=r.csrf;setup()};
}
function setup(message=""){
 progress(2);app.innerHTML='<h1><span class="icon">📱</span>Add your authenticator</h1><p>Make private setup details for your authenticator app.</p>'+message+'<button class="primary" id="create">Create my setup details</button>'+help();
 $("#create").onclick=async()=>{const r=await api("/api/provision",{});if(!r.ok)return setup(error(r.message));provision=r;log("[MFA demo] Test authenticator code: "+r.testOtp);showSecret()};
}
function showSecret(message="",revealed=false){
 progress(2);const secret=revealed?'<div class="secret">'+esc(provision.manualSecret.match(/.{1,4}/g).join(" "))+'</div>':note("Your manual secret is hidden until you choose to show it.");
 app.innerHTML='<h1><span class="icon">🔐</span>Add this to your app</h1><p>Copy the manual secret into your authenticator app. You do not need to type it.</p>'+message+secret+'<button class="secondary" id="reveal">'+(revealed?"Hide manual secret":"Reveal manual secret")+'</button><button class="secondary" id="copy">Copy manual secret</button><button class="primary" id="next">I added it — continue</button>'+help();
 $("#reveal").onclick=()=>showSecret("",!revealed);$("#copy").onclick=async()=>showSecret(await copy(provision.manualSecret)?note("Manual secret copied. Paste it into your app."):error("Copy was not available. Reveal the secret and try again."),revealed);$("#next").onclick=verify;
}
function verify(message=""){
 progress(3);app.innerHTML='<h1><span class="icon">✅</span>Check your authenticator</h1><p>Enter the 6-digit code from your authenticator app.</p>'+message+'<label for="otp">6-digit code</label><div class="example">Example: 123456</div><input class="otp" id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6"><div class="hint">⌛ Take your time. You may retry safely.</div><button class="primary" id="check">Confirm code</button><button class="link" id="back">I need setup details again</button>'+help();
 const input=$("#otp");input.focus();$("#check").onclick=async()=>{const r=await api("/api/verify-otp",{otp:input.value.trim()});if(!r.ok)return verify(error(r.message));makeCodes(r.message)};$("#back").onclick=()=>showSecret();
}
async function makeCodes(message){
 const r=await api("/api/generate-recovery",{});if(!r.ok)return complete(error(r.message));codes=r.codes;log("[MFA demo] Test recovery codes: "+codes.join(", "));recovery(message||r.message);
}
function recovery(message="",shown=false){
 progress(4);const list=shown?'<ul class="codes">'+codes.map(c=>"<li>"+esc(c)+"</li>").join("")+"</ul>":note("Your codes are hidden. Reveal them when you are ready.");
 app.innerHTML='<h1><span class="icon">🗝️</span>Save your recovery codes</h1><p>Your eight one-use recovery codes are ready. Keep them somewhere private.</p>'+note(message)+list+'<button class="primary" id="show">'+(shown?"Hide recovery codes":"Reveal recovery codes")+'</button><button class="secondary" id="copycodes">Copy recovery codes</button><button class="secondary" id="saved">I saved my codes</button>'+help();
 $("#show").onclick=()=>recovery("",!shown);$("#copycodes").onclick=async()=>recovery(await copy(codes.join("\\n"))?"Recovery codes copied.":"Copy was not available. Reveal the codes and save them another way.",shown);$("#saved").onclick=complete;
}
function recoveryCheck(message=""){
 progress(4);app.innerHTML='<h1><span class="icon">🗝️</span>Use a recovery code</h1><p>Enter one saved recovery code. Each code works once.</p>'+message+'<label for="recovery">Recovery code</label><div class="example">Example: ABCDE-FGHIJ</div><input id="recovery" autocapitalize="characters" autocomplete="one-time-code" maxlength="11"><button class="primary" id="use">Check recovery code</button><button class="link" id="return">Return to security setup</button>'+help();
 const input=$("#recovery");input.oninput=()=>input.value=input.value.toUpperCase().replace(/[^A-Z2-9]/g,"").slice(0,10).replace(/^(.{5})(.)/,"$1-$2");$("#use").onclick=async()=>{const r=await api("/api/check-recovery",{code:input.value});if(!r.ok)return recoveryCheck(error(r.message));complete(note(r.message))};$("#return").onclick=complete;
}
function complete(message=""){
 progress(4);app.innerHTML='<h1><span class="icon">🎉</span>Your extra security is on</h1><p>You have finished MFA enrolment. Use your authenticator when a payment needs extra confirmation.</p>'+message+'<div class="hint success">✅ Authenticator enabled and recovery codes saved.</div><button class="primary" id="newcodes">Make replacement recovery codes</button><button class="secondary" id="recover">Use a recovery code</button><button class="link" id="logout">Sign out</button>'+help();
 $("#newcodes").onclick=()=>makeCodes("A new set was made. Earlier codes no longer work.");$("#recover").onclick=()=>recoveryCheck();$("#logout").onclick=async()=>{await api("/api/logout",{});csrf="";identity(note("You are signed out."))};
}
async function init(){const r=await api("/api/session",undefined,"GET");if(!r.ok){app.textContent="We could not open this secure page. Refresh and try again.";return}csrf=r.csrf;if(r.authenticated&&r.mfaEnabled)complete();else if(r.authenticated)setup();else identity()}
init();
})();
</script>
</body>
</html>`;
}

const cert = readFileSync(CERT_PATH);
const key = readFileSync(KEY_PATH);

/* Requirement 2: TLS-only Bun listener and generic production error responses. */
server = Bun.serve({
  port: 3000,
  tls: { cert, key },
  async fetch(request: Request) {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:") {
        return new Response(null, { status: 308, headers: { Location: `https://${url.host}${url.pathname}` } });
      }
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = token(18);
        const h = secureHeaders(nonce);
        h.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers: h });
      }
      return new Response("Page not found.", { status: 404, headers: secureHeaders() });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: secureHeaders() });
    }
  },
});

console.log("MFA enrolment server listening securely on https://localhost:3000");
