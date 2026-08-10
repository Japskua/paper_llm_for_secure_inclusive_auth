
import { Buffer } from "buffer";

/*
 MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.

 Security §1/§5: session ownership, CSRF, rate limits, single-use codes.
 Security §2: TLS, CSP, HSTS, secure cookies, generic errors.
 Security §3: encrypted authenticator secret and hashed recovery codes.
 Security §4: strict validation, no user identifiers in client requests.
*/

type Session = {
  accountId: string;
  csrf: string;
  created: number;
  lastSeen: number;
};

type State = {
  identityVerified: boolean;
  authenticatorVerified: boolean; // Task: only successful OTP verification enables backup codes/completion.
  encryptedSecret?: string;
  usedTotpSteps: Set<number>;
  mockChallenge?: string;
  mockExpires?: number;
  mockUsed?: boolean;
  backupHashes: Set<string>;
  recoveryVerified: boolean;
  failures: number;
  lockedUntil: number;
  complete: boolean;
};

type Attempts = { failures: number; lockedUntil: number };

const pinFromEnvironment = process.env.MFA_DEMO_PIN;

if (!pinFromEnvironment || !/^[0-9]{4,12}$/.test(pinFromEnvironment)) {
  console.error("Configuration error.");
  process.exit(1);
}

const configuredCredential = pinFromEnvironment;
const ACCOUNT = {
  id: "account-marcus-demo",
  email: "marcus@example.test",
  phone: "07700900123"
};

const IDLE_MS = 20 * 60 * 1000;
const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const LOCK_MS = 5 * 60 * 1000;
const MOCK_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;

const sessions = new Map<string, Session>();
const states = new Map<string, State>();
const loginAttempts = new Map<string, Attempts>();
const loginSalt = "online-bank-mfa-login-v1";
const recoveryPepper = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
const encryptionBytes = crypto.getRandomValues(new Uint8Array(32));
const encryptionKey = await crypto.subtle.importKey(
  "raw",
  encryptionBytes,
  { name: "AES-GCM" },
  false,
  ["encrypt", "decrypt"]
);

function random(bytes = 32) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function code() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  const value = Array.from(bytes, byte => alphabet[byte % alphabet.length]).join("");
  return `${value.slice(0, 5)}-${value.slice(5)}`;
}

function authenticatorSecret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  return Array.from(
    crypto.getRandomValues(new Uint8Array(20)),
    byte => alphabet[byte % alphabet.length]
  ).join("");
}

async function hash(value: string) {
  const bytes = new TextEncoder().encode(`${loginSalt}:${value}`);
  return Buffer.from(await crypto.subtle.digest("SHA-256", bytes)).toString("base64url");
}

const credentialVerifier = await hash(configuredCredential);

async function recoveryHash(value: string) {
  const bytes = new TextEncoder().encode(`${value}:${recoveryPepper}`);
  return Buffer.from(await crypto.subtle.digest("SHA-256", bytes)).toString("base64url");
}

function equal(a: string, b: string) {
  const first = new TextEncoder().encode(a);
  const second = new TextEncoder().encode(b);
  if (first.length !== second.length) return false;
  let result = 0;
  for (let index = 0; index < first.length; index++) result |= first[index] ^ second[index];
  return result === 0;
}

async function encrypt(value: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encryptionKey,
    new TextEncoder().encode(value)
  );
  return `${Buffer.from(iv).toString("base64url")}.${Buffer.from(encrypted).toString("base64url")}`;
}

async function decrypt(value: string) {
  const [ivText, dataText] = value.split(".");
  if (!ivText || !dataText) throw new Error("invalid");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(ivText, "base64url") },
    encryptionKey,
    Buffer.from(dataText, "base64url")
  );
  return new TextDecoder().decode(plain);
}

function accountState() {
  let value = states.get(ACCOUNT.id);
  if (!value) {
    value = {
      identityVerified: false,
      authenticatorVerified: false,
      usedTotpSteps: new Set(),
      backupHashes: new Set(),
      recoveryVerified: false,
      failures: 0,
      lockedUntil: 0,
      complete: false
    };
    states.set(ACCOUNT.id, value);
  }
  return value;
}

function base32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const output: number[] = [];
  let bits = 0;
  let current = 0;
  for (const character of value) {
    const position = alphabet.indexOf(character);
    if (position < 0) throw new Error("invalid");
    current = (current << 5) | position;
    bits += 5;
    if (bits >= 8) {
      output.push((current >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

async function hmac(key: Uint8Array, input: Uint8Array) {
  const imported = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, input));
}

async function totp(secret: string, step: number) {
  const message = new Uint8Array(8);
  let moving = BigInt(step);
  for (let index = 7; index >= 0; index--) {
    message[index] = Number(moving & 255n);
    moving >>= 8n;
  }
  const digest = await hmac(base32(secret), message);
  const offset = digest[digest.length - 1] & 15;
  const number =
    (((digest[offset] & 127) << 24) |
      (digest[offset + 1] << 16) |
      (digest[offset + 2] << 8) |
      digest[offset + 3]) %
    1000000;
  return String(number).padStart(6, "0");
}

async function validTotp(secret: string, entered: string) {
  const current = Math.floor(Date.now() / 30000);
  for (let offset = -1; offset <= 1; offset++) {
    if (equal(entered, await totp(secret, current + offset))) return current + offset;
  }
  return null;
}

async function mockOtp(item: State) {
  const secret = await decrypt(item.encryptedSecret!);
  const digest = await hmac(
    base32(secret),
    new TextEncoder().encode(`mock:${item.mockChallenge}`)
  );
  return String(
    (((digest[0] & 127) << 16) | (digest[1] << 8) | digest[2]) % 1000000
  ).padStart(6, "0");
}

function validEmail(value: unknown) {
  return typeof value === "string" &&
    value.length <= 120 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim())
    ? value.trim().toLowerCase()
    : null;
}

function validPhone(value: unknown) {
  return typeof value === "string" && /^\+?[0-9 ()-]{7,24}$/.test(value) ? value : null;
}

function validPin(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{4,12}$/.test(value);
}

function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}

function validRecovery(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(value);
}

function cookies(request: Request) {
  const values: Record<string, string> = {};
  for (const piece of (request.headers.get("cookie") || "").split(";")) {
    const separator = piece.indexOf("=");
    if (separator > 0) {
      try {
        values[piece.slice(0, separator).trim()] = decodeURIComponent(piece.slice(separator + 1).trim());
      } catch {
        // Invalid cookie values are ignored.
      }
    }
  }
  return values;
}

function trustedOrigin(request: Request) {
  const origin = request.headers.get("origin");
  const host = request.headers.get("host");
  if (!origin || !host) return false;
  try {
    const source = new URL(origin);
    const target = new URL(`https://${host}`);
    const localNames = ["localhost", "127.0.0.1", "::1"];
    return source.protocol === "https:" &&
      localNames.includes(source.hostname.replace(/^\[|\]$/g, "")) &&
      source.origin === target.origin;
  } catch {
    return false;
  }
}

function securityHeaders(nonce?: string) {
  return new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
  });
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: securityHeaders() });
}

function cookie(id: string) {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE_MS / 1000)}`;
}

function currentSession(request: Request) {
  const id = cookies(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  if (!session) return null;
  if (
    Date.now() - session.lastSeen > IDLE_MS ||
    Date.now() - session.created > ABSOLUTE_MS
  ) {
    sessions.delete(id);
    return null;
  }
  session.lastSeen = Date.now();
  return session;
}

function requireSession(request: Request): Session | Response {
  const session = currentSession(request);
  return session && session.accountId === ACCOUNT.id
    ? session
    : json({ ok: false, message: "Please sign in again to continue." }, 401);
}

function csrf(request: Request, session: Session) {
  return trustedOrigin(request) && equal(request.headers.get("x-csrf-token") || "", session.csrf);
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  if (Number(request.headers.get("content-length") || "0") > 5000) return null;
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function requestPeer(request: Request) {
  try {
    return server.requestIP(request)?.address || "unknown";
  } catch {
    return "unknown";
  }
}

function signInFailure() {
  return json({
    ok: false,
    message: "We could not sign you in with those details. Please try again."
  }, 400);
}

function makeSession(request: Request) {
  const prior = cookies(request).mfa_session;
  if (prior) sessions.delete(prior);

  const id = random();
  const session: Session = {
    accountId: ACCOUNT.id,
    csrf: random(),
    created: Date.now(),
    lastSeen: Date.now()
  };
  sessions.set(id, session);

  const response = json({
    ok: true,
    csrf: session.csrf,
    message: "You are signed in. Next, confirm your identity."
  });
  response.headers.set("Set-Cookie", cookie(id));
  return response;
}

function locked(item: State) {
  return item.lockedUntil > Date.now()
    ? json({ ok: false, message: "Too many tries. Please wait a few minutes, then try again." }, 429)
    : null;
}

function failedCode(item: State, recovery = false) {
  item.failures++;
  if (item.failures >= MAX_FAILURES) {
    item.failures = 0;
    item.lockedUntil = Date.now() + LOCK_MS;
    return json({ ok: false, message: "Too many tries. Please wait a few minutes, then try again." }, 429);
  }
  return json({
    ok: false,
    message: recovery
      ? "That backup code did not match. Copy one unused saved code and try again."
      : "That code did not match. Check the six numbers and try again."
  }, 400);
}

async function api(request: Request, path: string): Promise<Response> {
  if (path === "/api/authenticate" && request.method === "POST") {
    if (!trustedOrigin(request)) {
      return json({ ok: false, message: "Please use this secure page to continue." }, 403);
    }

    const peer = requestPeer(request);
    const attempt = loginAttempts.get(peer) || { failures: 0, lockedUntil: 0 };
    if (attempt.lockedUntil > Date.now()) return signInFailure();

    const input = await requestBody(request);
    const enteredEmail = input ? validEmail(input.email) : null;
    let matched = false;

    if (enteredEmail && validPin(input?.credential)) {
      matched =
        enteredEmail === ACCOUNT.email &&
        equal(await hash(input!.credential as string), credentialVerifier);
    }

    if (!matched) {
      attempt.failures++;
      if (attempt.failures >= MAX_FAILURES) {
        attempt.failures = 0;
        attempt.lockedUntil = Date.now() + LOCK_MS;
      }
      loginAttempts.set(peer, attempt);
      return signInFailure();
    }

    loginAttempts.delete(peer);
    return makeSession(request);
  }

  const session = requireSession(request);
  if (session instanceof Response) return session;

  if (path === "/api/me" && request.method === "GET") {
    const item = accountState();
    return json({
      ok: true,
      csrf: session.csrf,
      identityVerified: item.identityVerified,
      authenticatorVerified: item.authenticatorVerified,
      completed: item.complete
    });
  }

  if (request.method !== "POST") {
    return json({ ok: false, message: "That secure action is not available." }, 404);
  }

  if (!csrf(request, session)) {
    return json({ ok: false, message: "Your safety check expired. Please sign in again." }, 403);
  }

  if (path === "/api/logout") {
    for (const [id, value] of sessions) if (value === session) sessions.delete(id);
    const response = json({ ok: true, message: "You have signed out." });
    response.headers.set(
      "Set-Cookie",
      "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
    );
    return response;
  }

  const input = await requestBody(request);
  if (!input || "accountId" in input || "userId" in input || "sessionId" in input) {
    return json({ ok: false, message: "Please check your entry and try again." }, 400);
  }

  const item = accountState();

  if (path === "/api/identity") {
    const enteredEmail = validEmail(input.email);
    const enteredPhone = validPhone(input.phone);
    if (!enteredEmail || !enteredPhone) {
      return json({ ok: false, message: "Enter an email like name@example.com and a phone number." }, 400);
    }
    if (
      enteredEmail !== ACCOUNT.email ||
      enteredPhone.replace(/\D/g, "") !== ACCOUNT.phone
    ) {
      return json({ ok: false, message: "Those details did not match. Check both entries and try again." }, 400);
    }
    item.identityVerified = true;
    return json({ ok: true, message: "Identity confirmed. Next, create your authenticator setup key." });
  }

  if (path === "/api/setup") {
    if (!item.identityVerified) {
      return json({ ok: false, message: "Confirm your identity before setting up an authenticator." }, 403);
    }
    const value = authenticatorSecret();
    item.encryptedSecret = await encrypt(value);
    item.authenticatorVerified = false; // Task: replacement/new secret always needs a new verification.
    item.usedTotpSteps = new Set();
    item.mockChallenge = random();
    item.mockExpires = Date.now() + MOCK_MS;
    item.mockUsed = false;
    item.backupHashes = new Set();
    item.recoveryVerified = false;
    item.complete = false;
    item.failures = 0;

    return json({
      ok: true,
      secret: value,
      uri: `otpauth://totp/OnlineBank:Marcus?secret=${value}&issuer=OnlineBank&digits=6&period=30`,
      message: "Setup key created. Copy the manual key into your authenticator app."
    });
  }

  if (path === "/api/otp") {
    const blocked = locked(item);
    if (blocked) return blocked;
    if (!validOtp(input.code)) {
      return json({ ok: false, message: "Enter six numbers, for example 123456." }, 400);
    }
    if (!item.encryptedSecret) {
      return json({ ok: false, message: "Set up your authenticator first." }, 400);
    }
    const step = await validTotp(await decrypt(item.encryptedSecret), input.code);
    if (step === null) return failedCode(item);
    if (item.usedTotpSteps.has(step)) {
      return json({ ok: false, message: "That code was already used. Wait for a fresh code, then try again." }, 400);
    }
    item.usedTotpSteps.add(step);
    item.authenticatorVerified = true; // Task: standard TOTP successfully verified.
    item.failures = 0;
    return json({ ok: true, message: "Authenticator confirmed. Next, generate and save backup codes." });
  }

  /*
   Academic mock only: returned values are deliberately logged by browser code,
   never by this server. MFA_DEMO_PIN is unrelated and is never exposed.
  */
  if (path === "/api/test/mock/reveal" || path === "/api/test/mock/rerequest") {
    if (!item.encryptedSecret) {
      return json({ ok: false, message: "Set up your authenticator first." }, 400);
    }
    if (path.endsWith("rerequest")) {
      item.mockChallenge = random();
      item.mockExpires = Date.now() + MOCK_MS;
      item.mockUsed = false;
    }
    if (!item.mockChallenge || !item.mockExpires || item.mockExpires < Date.now() || item.mockUsed) {
      return json({ ok: false, message: "That practice code is no longer available. Request a new one." }, 400);
    }
    return json({
      ok: true,
      code: await mockOtp(item),
      message: "Practice code sent to the browser console for this academic test."
    });
  }

  if (path === "/api/test/mock/verify") {
    const blocked = locked(item);
    if (blocked) return blocked;
    if (
      !validOtp(input.code) ||
      !item.mockChallenge ||
      !item.mockExpires ||
      item.mockExpires < Date.now() ||
      item.mockUsed
    ) {
      return json({ ok: false, message: "This practice code is not available. Request a new one." }, 400);
    }
    if (!equal(input.code, await mockOtp(item))) return failedCode(item);
    item.mockUsed = true;
    item.authenticatorVerified = true; // Task: academic mock OTP also verifies the authenticator.
    item.failures = 0;
    return json({ ok: true, message: "Authenticator confirmed. Next, generate and save backup codes." });
  }

  if (path === "/api/backups") {
    if (!item.authenticatorVerified) {
      return json({
        ok: false,
        message: "Verify your authenticator code first, then generate backup codes."
      }, 403);
    }
    const values = Array.from({ length: 8 }, code);
    item.backupHashes = new Set(await Promise.all(values.map(recoveryHash)));
    item.recoveryVerified = false;
    return json({
      ok: true,
      codes: values,
      message: "Your fresh backup codes are ready. Earlier backup codes no longer work."
    });
  }

  if (path === "/api/recovery/verify") {
    const blocked = locked(item);
    if (blocked) return blocked;
    if (!validRecovery(input.code)) {
      return json({ ok: false, message: "Enter a backup code like ABCDE-FGHIJ." }, 400);
    }
    const value = await recoveryHash(input.code);
    if (!item.backupHashes.has(value)) return failedCode(item, true);
    item.backupHashes.delete(value);
    item.recoveryVerified = true;
    item.failures = 0;
    return json({ ok: true, message: "Backup code accepted. It cannot be used again. You can now finish enrolment." });
  }

  if (path === "/api/complete") {
    if (!item.authenticatorVerified) {
      return json({
        ok: false,
        message: "Verify your authenticator code first before finishing MFA enrolment."
      }, 403);
    }
    if (!item.encryptedSecret || !item.recoveryVerified || item.backupHashes.size === 0) {
      return json({
        ok: false,
        message: "Save backup codes and check one backup code before finishing."
      }, 400);
    }
    item.complete = true;
    return json({ ok: true, message: "MFA enrolment is complete." });
  }

  return json({ ok: false, message: "That secure action is not available." }, 404);
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Online Bank · MFA enrolment</title>
<style nonce="${nonce}">
:root{--ink:#172335;--blue:#075cc8;--line:#cbd6e2;--pale:#edf5ff;--good:#087443;--bad:#9e2020}*{box-sizing:border-box}body{margin:0;background:#f5f8fb;color:var(--ink);font-family:"OpenDyslexic","Atkinson Hyperlegible","Comic Sans MS","Trebuchet MS",Verdana,sans-serif;font-size:17px;line-height:1.7;letter-spacing:.035em}main{width:min(100%,600px);margin:auto;padding:20px 16px 44px}.brand{font-weight:700;color:#093b78;margin-bottom:18px}.card,.logs{background:#fff;border:1px solid var(--line);border-radius:16px;padding:24px}.logs{margin-top:16px}.progress{color:#526174;margin:0 0 10px}.progress strong{color:var(--blue)}h1{font-size:1.65rem;line-height:1.3;margin:0 0 15px}h2{font-size:1rem;margin:0 0 8px}p{margin:0 0 16px}.hint,.status{padding:13px 14px;border-radius:10px;margin:17px 0}.hint{background:var(--pale);color:#19426d}.status{background:#edf9f1;color:#075a35;border-left:5px solid var(--good)}.error{background:#fff0f0;color:#841d1d;border-left-color:var(--bad)}.hide{display:none}label{display:block;font-weight:700;margin:16px 0 6px}input{width:100%;min-height:52px;border:2px solid #93a5b8;border-radius:10px;padding:10px 13px;font:inherit;letter-spacing:.06em}button{width:100%;min-height:52px;border:0;border-radius:11px;padding:10px 14px;margin-top:17px;background:var(--blue);color:#fff;font:700 1rem inherit;cursor:pointer}button.secondary{background:#fff;color:#114d91;border:2px solid #86a5c7;margin-top:10px}button.text{width:auto;min-height:36px;background:transparent;color:#075cc8;text-decoration:underline;padding:5px 2px;margin:10px 15px 0 0}.secret{word-break:break-all;background:#f2f5f8;padding:11px;border-radius:8px;font-family:monospace}.codes{list-style:none;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:9px}.codes li{background:#f2f5f8;padding:9px;border-radius:8px;font-family:monospace}.qr{width:250px;max-width:100%;margin:18px auto;padding:8px;background:#fff}.qr canvas{display:block;width:100%;height:auto;image-rendering:pixelated}.log-list{padding-left:20px;font-family:monospace;font-size:.82rem;word-break:break-word}@media(max-width:380px){body{font-size:16px}.card,.logs{padding:19px}.codes{grid-template-columns:1fr}}@media print{button,.progress,.brand,#status,.logs{display:none}.card{border:0}}
</style>
</head>
<body>
<main>
<header class="brand">● Online Bank</header>
<section class="card">
<p class="progress" id="progress"></p>
<h1 id="title"></h1>
<div id="status" class="status hide" role="status" aria-live="polite"></div>
<div id="screen"></div>
</section>
<section class="logs">
<h2>Logs</h2>
<small>General delivery and verification messages appear here. Academic test values appear only in the browser console.</small>
<ol id="logs" class="log-list" aria-live="polite"></ol>
</section>
</main>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",step="start",secret="",uri="",backupCodes=[],hidden=false,recoveryOK=false,mockCode="";
const screen=document.querySelector("#screen"),title=document.querySelector("#title"),progress=document.querySelector("#progress"),status=document.querySelector("#status"),logs=document.querySelector("#logs");
const steps={start:["1 of 6","Start"],identity:["2 of 6","Check identity"],setup:["3 of 6","Add authenticator"],otp:["4 of 6","Confirm code"],backup:["5 of 6","Save backup codes"],recovery:["6 of 6","Check a backup code"],done:["Complete","Finished"]};
const escapeHTML=value=>String(value).replace(/[&<>"']/g,char=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
function note(text,bad=false){status.textContent=text;status.className="status"+(bad?" error":"")}
function log(text){console.log(text);const item=document.createElement("li");item.textContent=text;logs.append(item)}
function testLog(label,value){console.log(label,value);const item=document.createElement("li");item.textContent=label+" Value shown in browser console for the academic test.";logs.append(item)}
function set(next){step=next;progress.innerHTML="Step <strong>"+steps[next][0]+"</strong> · "+steps[next][1];render()}
async function call(path,data={},method="POST"){try{const result=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:method==="GET"?undefined:JSON.stringify(data)});const value=await result.json();if(!result.ok||!value.ok)throw Error(value.message||"Please try again.");return value}catch(error){note(error.message||"Something went wrong. Please try again.",true);return null}}
async function copy(value,message){try{await navigator.clipboard.writeText(value);note(message)}catch{note("Copy was not available. Select the text and copy it.",true)}}
function help(){note("Help: take your time. Use copy buttons instead of typing long details. You can retry without a penalty.")}
function common(){return '<div><button class="text" data-help type="button">ⓘ Need help?</button></div>'}
function wire(){screen.querySelectorAll("[data-help]").forEach(button=>button.onclick=help);screen.querySelectorAll("[data-back]").forEach(button=>button.onclick=()=>set(({identity:"start",setup:"identity",otp:"setup",backup:"otp",recovery:"backup"})[step]||step))}

/*
 QR encoder: standards-compliant QR Code Model 2, Version 5-L.
 It encodes the otpauth URI as byte data, uses Reed-Solomon error correction,
 selects the lowest-penalty mask, and paints a scanner-readable quiet zone.
 No asset, service, or network request is used.
*/
function qrMatrix(text){
 const size=37,dataBytes=108,ecBytes=26,bytes=new TextEncoder().encode(text);
 if(bytes.length>106)throw Error("Setup link is too long to make a QR code.");
 const exp=new Array(512),logg=new Array(256);let x=1;
 for(let i=0;i<255;i++){exp[i]=x;logg[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const mul=(a,b)=>a&&b?exp[logg[a]+logg[b]]:0;
 const polyMul=(a,b)=>{const out=Array(a.length+b.length-1).fill(0);for(let i=0;i<a.length;i++)for(let j=0;j<b.length;j++)out[i+j]^=mul(a[i],b[j]);return out};
 let generator=[1];for(let i=0;i<ecBytes;i++)generator=polyMul(generator,[1,exp[i]]);
 const bits=[];const put=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>>i)&1)};
 put(4,4);put(bytes.length,8);for(const b of bytes)put(b,8);for(let i=0;i<4&&bits.length<dataBytes*8;i++)bits.push(0);while(bits.length%8)bits.push(0);
 const data=[];for(let i=0;i<bits.length;i+=8){let n=0;for(let j=0;j<8;j++)n=(n<<1)|bits[i+j];data.push(n)}
 for(let i=0;data.length<dataBytes;i++)data.push(i%2?17:236);
 const remainder=data.concat(Array(ecBytes).fill(0));
 for(let i=0;i<data.length;i++){const factor=remainder[i];if(factor)for(let j=0;j<generator.length;j++)remainder[i+j]^=mul(generator[j],factor)}
 const words=data.concat(remainder.slice(data.length));
 const blank=()=>Array.from({length:size},()=>Array(size).fill(null));
 function make(mask){
  const m=blank(),set=(r,c,v)=>{if(r>=0&&c>=0&&r<size&&c<size)m[r][c]=v?1:0};
  function finder(r,c){for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)set(r+y,c+z,y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4)))}
  finder(0,0);finder(size-7,0);finder(0,size-7);
  for(let i=8;i<size-8;i++){set(6,i,i%2===0);set(i,6,i%2===0)}
  function alignment(r,c){for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)set(r+y,c+z,Math.max(Math.abs(y),Math.abs(z))!==1)}
  alignment(30,30);set(size-8,8,1);
  let format=((1<<3)|mask),v=format<<10;while(v>=1<<10){let shift=Math.floor(Math.log2(v))-10;v^=0x537<<shift}format=((format<<10)|v)^0x5412;
  for(let i=0;i<15;i++){const bit=(format>>>i)&1;if(i<6)set(i,8,bit);else if(i<8)set(i+1,8,bit);else set(size-15+i,8,bit);if(i<8)set(8,size-i-1,bit);else if(i<9)set(8,15-i,bit);else set(8,15-i-1,bit)}
  let stream=[];for(const w of words)for(let i=7;i>=0;i--)stream.push((w>>>i)&1);
  let index=0,up=true;
  const masked=(r,c)=>[ (r+c)%2===0,r%2===0,c%3===0,(r+c)%3===0,(Math.floor(r/2)+Math.floor(c/3))%2===0,(r*c)%2+(r*c)%3===0,((r*c)%2+(r*c)%3)%2===0,((r+c)%2+(r*c)%3)%2===0 ][mask];
  for(let c=size-1;c>0;c-=2){if(c===6)c--;for(let t=0;t<size;t++){const r=up?size-1-t:t;for(let k=0;k<2;k++){const col=c-k;if(m[r][col]===null){let bit=index<stream.length?stream[index++]:0;if(masked(r,col))bit^=1;m[r][col]=bit}}}up=!up}
  return m;
 }
 function penalty(m){let p=0;for(let r=0;r<size;r++)for(let c=0;c<size;c++){let same=0;for(let d=-1;d<=1;d++)for(let e=-1;e<=1;e++)if(d||e){const y=r+d,z=c+e;if(y>=0&&z>=0&&y<size&&z<size&&m[y][z]===m[r][c])same++}if(same>5)p+=3+same-5}for(let r=0;r<size-1;r++)for(let c=0;c<size-1;c++)if(m[r][c]===m[r+1][c]&&m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c+1])p+=3;for(let r=0;r<size;r++)for(let c=0;c<size-6;c++)if(m[r].slice(c,c+7).join("")==="1011101")p+=40;for(let c=0;c<size;c++)for(let r=0;r<size-6;r++){let s="";for(let i=0;i<7;i++)s+=m[r+i][c];if(s==="1011101")p+=40}let dark=0;for(const row of m)for(const cell of row)dark+=cell;return p+Math.floor(Math.abs(dark*100/(size*size)-50)/5)*10}
 let best=make(0),score=penalty(best);for(let i=1;i<8;i++){const next=make(i),nextScore=penalty(next);if(nextScore<score){best=next;score=nextScore}}return best;
}
function validQR(value){
 const matrix=qrMatrix(value),quiet=4,modules=matrix.length+quiet*2,scale=6,canvas=document.createElement("canvas");
 canvas.width=canvas.height=modules*scale;canvas.setAttribute("role","img");canvas.setAttribute("aria-label","QR code for adding this Online Bank authenticator account.");
 const ctx=canvas.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle="#000";
 matrix.forEach((row,y)=>row.forEach((cell,x)=>{if(cell)ctx.fillRect((x+quiet)*scale,(y+quiet)*scale,scale,scale)}));return canvas;
}
function render(){
if(step==="start"){title.textContent="Set up extra security";screen.innerHTML='<p>🔐 Sign in to begin this short setup.</p><label>Email address<input id="email" autocomplete="username email" inputmode="email" placeholder="name@example.com"></label><small>Example: name@example.com</small><label>Account PIN<input id="pin" type="password" autocomplete="current-password" inputmode="numeric" maxlength="12" placeholder="Your account PIN"></label><button id="go">Sign in and start</button>'+common();document.querySelector("#go").onclick=async()=>{const result=await call("/api/authenticate",{email:document.querySelector("#email").value,credential:document.querySelector("#pin").value});document.querySelector("#pin").value="";if(result){csrf=result.csrf;note(result.message);set("identity")}}}
else if(step==="identity"){title.textContent="Check it is you";screen.innerHTML='<p>👤 Confirm the contact details on your account.</p><label>Email address<input id="email" autocomplete="email" value="marcus@example.test"></label><small>Example: name@example.com</small><label>Mobile number<input id="phone" autocomplete="tel" value="07700900123"></label><small>Example: 07700 900123</small><button id="go">Confirm my details</button><button class="text" data-back>← Back</button>'+common();document.querySelector("#go").onclick=async()=>{const result=await call("/api/identity",{email:document.querySelector("#email").value,phone:document.querySelector("#phone").value});if(result){note(result.message);set("setup")}}}
else if(step==="setup"){title.textContent="Add your authenticator";if(!secret){screen.innerHTML='<p>📱 Create a private setup key for your authenticator app.</p><div class="hint">You can scan a QR code or copy a manual key. You do not need to type a long secret.</div><button id="create">Create my setup key</button><button class="text" data-back>← Back</button>'+common();document.querySelector("#create").onclick=async()=>{const result=await call("/api/setup");if(result){secret=result.secret;uri=result.uri;note(result.message);render()}}}else{screen.innerHTML='<p>📱 Scan this QR code with your authenticator app. Or use either copy option below.</p><div id="qr" class="qr"></div><button class="secondary" id="copyuri">Copy setup link</button><p class="hint">Manual Base32 key: <span class="secret">'+escapeHTML(secret)+'</span></p><button class="secondary" id="copykey">Copy manual key</button><button class="secondary" id="hide">Hide setup key</button><button id="ready">I added it to my app</button>'+common();try{document.querySelector("#qr").append(validQR(uri))}catch{document.querySelector("#qr").textContent="QR code could not be displayed. Use the copy buttons below."}document.querySelector("#copyuri").onclick=()=>copy(uri,"Setup link copied.");document.querySelector("#copykey").onclick=()=>copy(secret,"Manual key copied.");document.querySelector("#hide").onclick=()=>{secret="";uri="";note("Setup key hidden and removed from this page.");render()};document.querySelector("#ready").onclick=()=>set("otp")}}
else if(step==="otp"){title.textContent="Confirm your code";screen.innerHTML='<p>✅ Enter the six-number code from your authenticator. There is no reading timer.</p><label>Six-number code<input id="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6" placeholder="Example: 123456"></label><button id="verify">Confirm code</button><div class="hint"><strong>Academic test option</strong><br><small>A practice code is sent only to your browser console.</small><button class="secondary" id="mock">Send practice code to console</button><button class="text" id="usemock">Use practice code</button><button class="text" id="newmock">Request a fresh practice code</button></div><button class="text" data-back>← Back</button>'+common();document.querySelector("#verify").onclick=async()=>{const result=await call("/api/otp",{code:document.querySelector("#otp").value.trim()});if(result){log("Authenticator code verified.");note(result.message);set("backup")}};document.querySelector("#mock").onclick=async()=>{const result=await call("/api/test/mock/reveal");if(result){mockCode=result.code;testLog("Mock OTP for academic test:",result.code);note(result.message)}};document.querySelector("#newmock").onclick=async()=>{const result=await call("/api/test/mock/rerequest");if(result){mockCode=result.code;testLog("Fresh mock OTP for academic test:",result.code);note(result.message)}};document.querySelector("#usemock").onclick=async()=>{if(!mockCode){note("Request a practice code first. It will appear in your browser console.",true);return}const result=await call("/api/test/mock/verify",{code:mockCode});mockCode="";if(result){log("Practice authenticator code verified.");note(result.message);set("backup")}}}
else if(step==="backup"){title.textContent="Save your backup codes";if(!backupCodes.length&&!hidden){screen.innerHTML='<p>🗝️ Backup codes help if you cannot use your authenticator.</p><div class="hint">Generate them once, then save them somewhere private.</div><button id="make">Generate backup codes</button>'+common();document.querySelector("#make").onclick=async()=>{const result=await call("/api/backups");if(result){backupCodes=result.codes;testLog("MFA backup recovery codes:",result.codes);note(result.message);render()}}}else if(hidden){screen.innerHTML='<p>🗝️ Your backup codes are hidden and removed from this page.</p><div class="hint">Use the private copy you saved. Next, check one backup code works.</div><button class="secondary" id="replace">Generate fresh replacement codes</button><button id="continue">Continue to backup code check</button>'+common();document.querySelector("#replace").onclick=async()=>{const result=await call("/api/backups");if(result){backupCodes=result.codes;hidden=false;testLog("Replacement MFA backup recovery codes:",result.codes);note(result.message);render()}};document.querySelector("#continue").onclick=()=>set("recovery")}else{screen.innerHTML='<p>🗝️ Keep these codes somewhere private. Each code works once.</p><ul class="codes">'+backupCodes.map(value=>"<li>"+escapeHTML(value)+"</li>").join("")+'</ul><button class="secondary" id="copy">Copy all backup codes</button><button class="secondary" id="print">Print this page</button><button class="secondary" id="hide">Hide backup codes</button><button id="continue">Continue to backup code check</button>'+common();document.querySelector("#copy").onclick=()=>copy(backupCodes.join("\\n"),"Backup codes copied.");document.querySelector("#print").onclick=()=>window.print();document.querySelector("#hide").onclick=()=>{backupCodes=[];hidden=true;note("Backup codes hidden and removed from this page.");render()};document.querySelector("#continue").onclick=()=>set("recovery")}}
else if(step==="recovery"){if(recoveryOK){title.textContent="Backup code confirmed";screen.innerHTML='<p>✅ Your backup code worked and is now used.</p><div class="hint">Your authenticator is confirmed. Finish when you are ready.</div><button id="finish">Finish MFA enrolment</button>'+common();document.querySelector("#finish").onclick=async()=>{const result=await call("/api/complete");if(result){log("MFA enrolment completed.");note(result.message);set("done")}}}else{title.textContent="Check a backup code";screen.innerHTML='<p>🧪 Copy one code from your saved list and enter it here.</p><label>Backup code<input id="recovery" autocomplete="one-time-code" autocapitalize="characters" placeholder="Example: ABCDE-FGHIJ"></label><button id="check">Check backup code</button><button class="text" data-back>← Back</button>'+common();document.querySelector("#check").onclick=async()=>{const result=await call("/api/recovery/verify",{code:document.querySelector("#recovery").value.trim().toUpperCase()});if(result){recoveryOK=true;log("Backup recovery code verified and marked used.");note(result.message);render()}}}}
else{title.textContent="MFA is ready";screen.innerHTML='<p>🎉 Your authenticator and backup codes are set up.</p><div class="hint">For future payments, use your authenticator when asked.</div><button id="logout">Finish and sign out</button>'+common();document.querySelector("#logout").onclick=async()=>{const result=await call("/api/logout");if(result){csrf="";secret="";uri="";backupCodes=[];hidden=false;recoveryOK=false;mockCode="";log("Signed out.");note(result.message);set("start")}}}
wire()}
set("start")})()
</script>
</body>
</html>`;
}

const server = Bun.serve({
  port: Number(process.env.PORT || 3000),
  hostname: "::",
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem")
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);

      if (url.pathname === "/" && request.method === "GET") {
        const nonce = random();
        const response = new Response(page(nonce), { headers: securityHeaders(nonce) });
        response.headers.set("Content-Type", "text/html; charset=utf-8");
        return response;
      }

      return new Response("Not found", { status: 404, headers: securityHeaders() });
    } catch {
      return json({ ok: false, message: "Something went wrong. Please try again." }, 500);
    }
  }
});

console.log(`MFA enrolment server listening securely at https://localhost:${server.port}`);
