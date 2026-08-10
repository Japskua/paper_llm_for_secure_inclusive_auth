
import { readFileSync } from "node:fs";

/*
  MFA Enrolment System
  - Accessibility requirements: short, stable screens and dyslexia-friendly mobile layout
  - Security requirements: server-side sessions, CSRF, TLS, CSP, validation, encryption,
    rate limiting, ownership checks, and protected recovery-code handling.
*/

const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";

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
  usedSteps: Set<number>;
  recoveryHashes: Set<string>;
  mfaVerifiedAt: number;
};

const sessions = new Map<string, Session>();
const mfaRecords = new Map<string, MfaRecord>();
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_STEP_MS = 5 * 60 * 1000; // Generous entry window; no reading-time limit.
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
  const text = atob(value);
  return Uint8Array.from(text, (char) => char.charCodeAt(0));
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

/* Cryptographic Failures: AES-GCM protects the OTP seed while it is in memory. */
async function encryptSecret(secret: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret));
  return `${bytesToBase64(iv)}.${bytesToBase64(new Uint8Array(ciphertext))}`;
}

async function decryptSecret(stored: string): Promise<string> {
  const [ivText, encryptedText] = stored.split(".");
  if (!ivText || !encryptedText) throw new Error("protected value unavailable");
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(ivText) },
    key,
    base64ToBytes(encryptedText),
  );
  return new TextDecoder().decode(plain);
}

async function makeOtp(secret: string, step: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
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

async function generateRecoveryCodes(): Promise<{ codes: string[]; hashes: Set<string> }> {
  const codes: string[] = [];
  const hashes = new Set<string>();
  for (let i = 0; i < 8; i++) {
    const code = recoveryCode();
    codes.push(code);
    hashes.add(await sha256(`${bytesToBase64(recoveryPepper)}:${code}`));
  }
  return { codes, hashes };
}

/* Authentication controls: short-lived server-side sessions with rotation on login. */
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
  const raw = request.headers.get("cookie") || "";
  const out: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) out[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return out;
}

function getSession(request: Request): Session | null {
  const id = cookies(request).mfa_session;
  if (!id) return null;
  const session = sessions.get(id);
  const now = Date.now();
  if (!session || now > session.expiresAt || now - session.lastSeenAt > SESSION_IDLE_MS) {
    if (id) sessions.delete(id);
    return null;
  }
  session.lastSeenAt = now;
  return session;
}

/* Broken Access Control: no request-supplied account id is accepted or trusted. */
function requireOwner(request: Request): { session: Session; record?: MfaRecord } | Response {
  const session = getSession(request);
  if (!session || session.userId !== account.id) return apiError("Please sign in to continue.", 401);
  return { session, record: mfaRecords.get(account.id) };
}

function trustedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  return /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(origin);
}

function headers(nonce = ""): Headers {
  const value = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  return value;
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
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

/* CSRF and Origin controls apply to every state-changing endpoint. */
function csrfValid(request: Request, session: Session | null): boolean {
  return !!session &&
    trustedOrigin(request) &&
    request.headers.get("x-csrf-token") === session.csrf;
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

/* Allow-list helper retained for any future internal redirect route. */
function safeInternalPath(value: unknown): string {
  const allowed = new Set(["/", "/#signin", "/#setup", "/#complete"]);
  return typeof value === "string" && allowed.has(value) ? value : "/";
}

async function handleApi(request: Request, path: string): Promise<Response> {
  if (!trustedOrigin(request)) return apiError("Request could not be accepted.", 403);

  if (request.method === "OPTIONS") {
    const h = headers();
    h.set("Access-Control-Allow-Origin", request.headers.get("origin") || "https://localhost");
    h.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
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
    }, 200, setCookie ? { "Set-Cookie": setCookie } : undefined);
  }

  if (path === "/api/signin" && request.method === "POST") {
    const old = getSession(request);
    if (!csrfValid(request, old)) return apiError("Your secure page expired. Refresh and try again.", 403);
    const input = await body(request);
    if (!input || !validEmail(input.email) || !validPhone(input.phone)) {
      return apiError("Enter an email like name@example.com and a phone number using digits.", 400);
    }
    // Neutral result avoids account enumeration.
    if (input.email.toLowerCase() !== account.email || input.phone.replace(/\D/g, "") !== account.phone) {
      return apiError("We could not confirm those details. Check them and try again.", 401);
    }
    sessions.delete(old!.id);
    const session = newSession(account.id);
    return apiResponse({ ok: true, csrf: session.csrf, name: account.name, next: safeInternalPath("/#setup") }, 200, {
      "Set-Cookie": sessionCookie(session),
    });
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
    const encryptedSecret = await encryptSecret(secret);
    mfaRecords.set(account.id, {
      encryptedSecret,
      enabled: false,
      failedAttempts: 0,
      lockedUntil: 0,
      usedSteps: new Set(),
      recoveryHashes: new Set(),
      mfaVerifiedAt: 0,
    });
    const step = Math.floor(Date.now() / OTP_STEP_MS);
    const testOtp = await makeOtp(secret, step);
    const provisioningUri = `otpauth://totp/Example%20Bank:${encodeURIComponent(account.email)}?secret=${secret}&issuer=Example%20Bank&period=300`;
    return apiResponse({ ok: true, secret, provisioningUri, testOtp });
  }

  if (path === "/api/verify-otp" && request.method === "POST") {
    const input = await body(request);
    if (!input || !validOtp(input.otp)) return apiError("Enter all 6 digits. Example: 123456.", 400);
    const record = owner.record;
    if (!record) return apiError("Start authenticator setup first.", 400);
    if (Date.now() < record.lockedUntil) {
      return apiError("Too many attempts were made. Wait 10 minutes, then try again.", 429);
    }
    const secret = await decryptSecret(record.encryptedSecret);
    const currentStep = Math.floor(Date.now() / OTP_STEP_MS);
    const candidates = [currentStep, currentStep - 1];
    let matchingStep: number | null = null;
    for (const step of candidates) {
      if (record.usedSteps.has(step)) continue;
      if ((await makeOtp(secret, step)) === input.otp) {
        matchingStep = step;
        break;
      }
    }
    if (matchingStep === null) {
      record.failedAttempts++;
      if (record.failedAttempts >= MAX_FAILURES) {
        record.failedAttempts = 0;
        record.lockedUntil = Date.now() + LOCK_MS;
      }
      return apiError("That code did not work. Check the 6 digits in your authenticator and try again.", 401);
    }
    record.usedSteps.add(matchingStep);
    record.failedAttempts = 0;
    record.enabled = true;
    record.mfaVerifiedAt = Date.now();
    const recovery = await generateRecoveryCodes();
    record.recoveryHashes = recovery.hashes;
    return apiResponse({ ok: true, codes: recovery.codes, message: "Authenticator confirmed. Save your recovery codes next." });
  }

  if (path === "/api/regenerate-recovery" && request.method === "POST") {
    const record = owner.record;
    if (!record?.enabled || Date.now() - record.mfaVerifiedAt > 5 * 60 * 1000) {
      return apiError("Confirm your authenticator again before making new recovery codes.", 403);
    }
    const recovery = await generateRecoveryCodes();
    record.recoveryHashes = recovery.hashes;
    return apiResponse({ ok: true, codes: recovery.codes, message: "New recovery codes are ready. Your old codes no longer work." });
  }

  if (path === "/api/check-recovery" && request.method === "POST") {
    const input = await body(request);
    if (!input || !validRecoveryCode(input.code)) return apiError("Use a code in this format: ABCDE-FGHIJ.", 400);
    const record = owner.record;
    if (!record) return apiError("That code did not work. Try another saved code.", 401);
    const hash = await sha256(`${bytesToBase64(recoveryPepper)}:${input.code}`);
    if (!record.recoveryHashes.delete(hash)) return apiError("That code did not work. Try another saved code.", 401);
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
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Arial,Verdana,Tahoma,sans-serif;font-size:18px;line-height:1.65;letter-spacing:.035em}button,input{font:inherit;letter-spacing:.025em}button{cursor:pointer}button:focus-visible,input:focus-visible,a:focus-visible{outline:4px solid var(--focus);outline-offset:3px}.shell{max-width:590px;margin:auto;min-height:100vh;padding:18px 16px 42px}.brand{font-weight:800;font-size:1.1rem;margin:2px 0 22px}.brand span{color:var(--blue)}.progress{display:flex;gap:7px;margin:0 0 22px}.progress i{height:7px;background:#cdd7e2;border-radius:10px;flex:1}.progress i.on{background:var(--blue)}main{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:25px 21px;box-shadow:0 3px 12px #17345c12}h1{font-size:1.55rem;line-height:1.28;letter-spacing:.015em;margin:0 0 12px}h2{font-size:1.15rem;line-height:1.35;margin:20px 0 8px}p{margin:0 0 16px}.icon{font-size:1.7rem;margin-right:8px}.hint{background:#edf5ff;border-left:5px solid var(--blue);padding:12px 14px;border-radius:7px;margin:16px 0;color:#263d59;font-size:.93rem}.success{background:#e9f8ef;border-left-color:var(--good)}.error{background:#fff0f1;border-left:5px solid var(--error);padding:12px 14px;border-radius:7px;color:#77202a;margin:14px 0}.field{display:block;font-weight:700;margin:16px 0 5px}.example{font-size:.86rem;color:var(--muted);margin-bottom:5px}input{width:100%;padding:13px;border:2px solid #92a6be;border-radius:9px;background:#fff;color:var(--ink)}input.otp{font-size:1.4rem;letter-spacing:.22em;text-align:center;font-weight:700}.primary{border:0;border-radius:10px;background:var(--blue);color:#fff;font-weight:800;width:100%;padding:14px 16px;margin:21px 0 8px;min-height:55px}.primary:hover{background:var(--blue2)}.secondary{border:2px solid var(--blue);background:#fff;color:var(--blue);border-radius:9px;padding:10px 13px;font-weight:700;margin:7px 6px 0 0}.link{border:0;background:transparent;color:var(--blue);text-decoration:underline;padding:8px 2px;font-weight:700}.help{margin-top:22px;border-top:1px solid var(--line);padding-top:13px;font-size:.91rem}.secret{font-family:monospace;word-break:break-all;background:#f1f4f8;border:1px solid var(--line);padding:11px;border-radius:8px;font-size:.94rem;letter-spacing:.08em}.qr{width:178px;height:178px;border:9px solid #fff;outline:1px solid var(--line);margin:17px auto;background:#fff;display:grid;grid-template-columns:repeat(15,1fr);grid-template-rows:repeat(15,1fr)}.qr b{background:#172437}.codes{list-style:none;padding:0;margin:14px 0}.codes li{font-family:monospace;font-size:1.13rem;letter-spacing:.09em;background:#f1f4f8;border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin:8px 0}.logs{margin-top:20px;background:#172437;color:#eff6ff;border-radius:13px;padding:14px;font-size:.8rem;line-height:1.45;letter-spacing:.01em}.logs h2{font-size:.95rem;margin:0 0 7px;color:#fff}.logline{border-top:1px solid #42516a;padding:6px 0;word-break:break-word}.hide{display:none}@media(max-width:370px){body{font-size:16px}.shell{padding:12px 10px}.qr{width:150px;height:150px}main{padding:20px 16px}}
</style>
</head>
<body>
<div class="shell">
<header><div class="brand">Example <span>Bank</span></div><div class="progress" aria-label="Enrolment progress"><i id="p1"></i><i id="p2"></i><i id="p3"></i><i id="p4"></i></div></header>
<main id="app" aria-live="polite">Loading your secure page…</main>
<section class="logs" aria-label="Test activity log"><h2>🧾 Logs</h2><div id="loglines">Ready. Test-only details appear here when created.</div></section>
</div>
<script nonce="${nonce}">
(() => {
"use strict";
let csrf = "";
let provision = null;
let recoveryCodes = [];
const app = document.getElementById("app");
const logLines = document.getElementById("loglines");
const esc = value => String(value);
function log(message) {
  console.log("[MFA demo]", message);
  const line = document.createElement("div"); line.className = "logline"; line.textContent = message; logLines.prepend(line);
}
function progress(step) { [1,2,3,4].forEach(n => document.getElementById("p"+n).className = n <= step ? "on" : ""); }
function error(message) { return '<div class="error" role="alert">⚠️ '+esc(message)+'</div>'; }
function help() { return '<div class="help">💡 <strong>Need help?</strong> You can pause, retry, or copy details. There is no reading time limit.</div>'; }
async function api(path, data, method="POST") {
  const options = {method, headers: {"Content-Type":"application/json"}};
  if (method !== "GET") options.headers["X-CSRF-Token"] = csrf;
  if (data !== undefined) options.body = JSON.stringify(data);
  const response = await fetch(path, options);
  const result = await response.json().catch(() => ({ok:false,message:"We could not complete that request. Try again."}));
  if (result.csrf) csrf = result.csrf;
  return {response,result};
}
function signIn(message="") {
 progress(1); app.innerHTML = '<h1><span class="icon">🔐</span>Set up extra security</h1><p>First, confirm it is you. We will then help you add an authenticator.</p>'+message+
 '<label class="field" for="email">Email address</label><div class="example">Example: name@example.com</div><input id="email" type="email" autocomplete="email" inputmode="email" value="marcus@example.test">'+
 '<label class="field" for="phone">Phone number</label><div class="example">Example: 5550100</div><input id="phone" type="tel" autocomplete="tel" inputmode="tel" value="5550100">'+
 '<button class="primary" id="confirm">Confirm identity</button><p class="hint">🛡️ This is a secure practice enrolment. Your details are checked without showing account information.</p>'+help();
 document.getElementById("confirm").onclick = async () => {
   const button=document.getElementById("confirm"); button.disabled=true; button.textContent="Checking…";
   const {result}=await api("/api/signin",{email:document.getElementById("email").value.trim(),phone:document.getElementById("phone").value.trim()});
   if(!result.ok){signIn(error(result.message));return;} log("Identity confirmed for Marcus."); setup();
 };
}
function drawQr(secret) {
 const qr=document.getElementById("qr"); qr.innerHTML="";
 let seed=0; for(const c of secret) seed=(seed*31+c.charCodeAt(0))>>>0;
 for(let i=0;i<225;i++){seed=(seed*1664525+1013904223)>>>0;const cell=document.createElement("span");if((seed>>>28)>7 || (i%15<3&&Math.floor(i/15)<3) || (i%15>11&&Math.floor(i/15)<3) || (i%15<3&&Math.floor(i/15)>11)){const b=document.createElement("b");cell.appendChild(b)}qr.appendChild(cell);}
}
function setup(message="") {
 progress(2); app.innerHTML='<h1><span class="icon">📱</span>Add your authenticator</h1><p>Use an authenticator app on your phone. You can scan a setup card or copy a short secret.</p>'+message+
 '<button class="primary" id="create">Create my setup details</button><p class="hint">🧩 You only need to do this once. You can request fresh details if needed.</p>'+help();
 document.getElementById("create").onclick=async()=>{
   const b=document.getElementById("create");b.disabled=true;b.textContent="Creating…";
   const {result}=await api("/api/provision",{});
   if(!result.ok){setup(error(result.message));return;}
   provision=result; log("TEST ONLY — authenticator secret: "+result.secret); log("TEST ONLY — current authenticator code: "+result.testOtp); showProvision();
 };
}
function showProvision(message="") {
 progress(2); app.innerHTML='<h1><span class="icon">📷</span>Save this in your app</h1><p>Scan this setup card with your authenticator app. Then enter the 6-digit code it shows.</p>'+message+
 '<div id="qr" class="qr" role="img" aria-label="Simulated QR setup card"></div><p class="hint">📱 Demo setup card. If scanning is difficult, use the copy button below instead.</p>'+
 '<button class="secondary" id="copyuri">Copy setup link</button><button class="secondary" id="showsecret">Show manual secret</button><div id="manual"></div>'+
 '<button class="primary" id="continue">I added it — continue</button><button class="link" id="again">Create new setup details</button>'+help();
 drawQr(provision.secret);
 document.getElementById("copyuri").onclick=async()=>{await navigator.clipboard.writeText(provision.provisioningUri);log("Setup link copied to clipboard.");};
 document.getElementById("showsecret").onclick=()=>{document.getElementById("manual").innerHTML='<h2>Manual secret</h2><div class="secret" id="secrettext"></div><button class="secondary" id="copysecret">Copy secret</button>';document.getElementById("secrettext").textContent=provision.secret;document.getElementById("copysecret").onclick=async()=>{await navigator.clipboard.writeText(provision.secret);log("Manual secret copied to clipboard.");};};
 document.getElementById("continue").onclick=()=>verify();
 document.getElementById("again").onclick=()=>setup();
}
function verify(message="") {
 progress(3); app.innerHTML='<h1><span class="icon">✅</span>Check your authenticator</h1><p>Enter the 6-digit code from your authenticator app.</p>'+message+
 '<label class="field" for="otp">6-digit code</label><div class="example">Example: 123456</div><input class="otp" id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" aria-describedby="otphint"><div id="otphint" class="hint">⌛ Take your time. This demo code works for 5 minutes. You may retry safely.</div>'+
 '<button class="primary" id="verify">Confirm code</button><button class="link" id="back">I need setup details again</button>'+help();
 const input=document.getElementById("otp"); input.focus();
 document.getElementById("verify").onclick=async()=>{const {result}=await api("/api/verify-otp",{otp:input.value.trim()});if(!result.ok){verify(error(result.message));return;}recoveryCodes=result.codes;log("TEST ONLY — recovery codes: "+result.codes.join(", ")); recovery(result.message);};
 document.getElementById("back").onclick=()=>showProvision();
}
function recovery(message="") {
 progress(4); const items=recoveryCodes.map(code=>'<li>'+esc(code)+'</li>').join("");
 app.innerHTML='<h1><span class="icon">🗝️</span>Save your recovery codes</h1><p>These codes help if you lose your phone. Each code works once.</p><div class="hint success">✅ '+esc(message)+'</div><ul class="codes" aria-label="Your eight recovery codes">'+items+'</ul><button class="secondary" id="copycodes">Copy all codes</button><button class="primary" id="saved">I saved my codes</button><p class="hint">Keep these somewhere private. For safety, they disappear from this page after you continue.</p>'+help();
 document.getElementById("copycodes").onclick=async()=>{await navigator.clipboard.writeText(recoveryCodes.join("\\n"));log("Recovery codes copied to clipboard.");};
 document.getElementById("saved").onclick=()=>complete();
}
function complete(message="") {
 progress(4); recoveryCodes=[]; provision=null;
 app.innerHTML='<h1><span class="icon">🎉</span>Your extra security is on</h1><p>You have finished MFA enrolment. Use your authenticator when a payment needs extra confirmation.</p>'+message+
 '<div class="hint success">✅ Authenticator enabled and recovery codes saved.</div><button class="primary" id="newcodes">Make new recovery codes</button><button class="link" id="logout">Sign out</button>'+help();
 document.getElementById("newcodes").onclick=async()=>{const {result}=await api("/api/regenerate-recovery",{});if(!result.ok){complete(error(result.message));return;}recoveryCodes=result.codes;log("TEST ONLY — replacement recovery codes: "+result.codes.join(", "));recovery(result.message);};
 document.getElementById("logout").onclick=async()=>{await api("/api/logout",{});log("Signed out. Secure session removed."); signIn('<div class="hint success">You are signed out.</div>');};
}
async function start() {
 const {result}=await api("/api/session",undefined,"GET");
 if(!result.ok){app.textContent="We could not open this secure page. Refresh and try again.";return;}
 csrf=result.csrf;
 if(result.authenticated && result.mfaEnabled) complete();
 else if(result.authenticated) setup();
 else signIn();
}
start();
})();
</script>
</body></html>`;
}

const cert = readFileSync(CERT_PATH);
const key = readFileSync(KEY_PATH);

/* Security Misconfiguration: TLS-only Bun listener and generic top-level failures. */
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
      // Deliberately generic: no debug trace, secrets, or internal details.
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: headers() });
    }
  },
});

console.log("MFA enrolment server listening securely on https://localhost:3000");
