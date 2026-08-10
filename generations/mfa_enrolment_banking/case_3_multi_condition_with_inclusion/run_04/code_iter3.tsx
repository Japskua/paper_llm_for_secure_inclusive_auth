
import { readFileSync } from "node:fs";

/*
  MFA Enrolment System — single Bun HTTPS server and mobile SPA.
  Requirement sections: authorization, CSRF, headers, encrypted-at-rest secrets,
  input validation, session controls, rate limiting, and standard TOTP.
*/

type Stage = "anonymous" | "identity" | "mfa";
type Session = {
  id: string;
  csrf: string;
  stage: Stage;
  userId?: string;
  createdAt: number;
  lastSeen: number;
  identityCode?: string;
  identityExpiry?: number;
  identityUsed?: boolean;
  identityFails: number;
  identityLockedUntil?: number;
  encryptedSecret?: string;
  pendingOtpExpiry?: number;
  otpFails: number;
  otpLockedUntil?: number;
  otpEnabled: boolean;
  backupHashes: string[];
  recoveryFails: number;
  recoveryLockedUntil?: number;
};

const sessions = new Map<string, Session>();
const PORT = 3000;
const TRUSTED_ORIGIN = `https://localhost:${PORT}`;
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 10 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const OTP_MAX_FAILURES = 5;
const TOTP_STEP_SECONDS = 30;
const TOTP_WINDOW_STEPS = 1;
/* TOTP: RFC 6238, HMAC-SHA-1, six digits, 30-second steps, +/- one step tolerance. */
const ACCOUNT = { id: "account-marcus", email: "marcus@example.com", password: "BankDemo!9" };
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const masterKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
const recoveryPepper = randomText(32);

function randomText(length = 32) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, b => chars[b % chars.length]).join("");
}

/* Requirement 3 / task: cryptographically random RFC 4648 Base32 secret. */
function randomBase32(length = 32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, byte => alphabet[byte & 31]).join("");
}

function randomDigits(length = 6) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, b => String(b % 10)).join("");
}
function b64(bytes: Uint8Array) {
  return Buffer.from(bytes).toString("base64url");
}
function fromB64(value: string) {
  return new Uint8Array(Buffer.from(value, "base64url"));
}
async function digest(value: string) {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return b64(new Uint8Array(hash));
}
async function encryptAtRest(value: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(value));
  return `${b64(iv)}.${b64(new Uint8Array(ciphertext))}`;
}
async function decryptAtRest(value: string) {
  const [ivText, ciphertextText] = value.split(".");
  if (!ivText || !ciphertextText) throw new Error("invalid encrypted value");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(ivText) },
    masterKey,
    fromB64(ciphertextText)
  );
  return decoder.decode(plain);
}
function base32Bytes(secret: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, buffer = 0;
  const out: number[] = [];
  for (const char of secret.replace(/=+$/g, "").toUpperCase()) {
    const value = alphabet.indexOf(char);
    if (value < 0) throw new Error("invalid Base32");
    buffer = (buffer << 5) | value;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((buffer >>> bits) & 255);
    }
  }
  return new Uint8Array(out);
}

/* Standard RFC 6238 HOTP truncation using HMAC-SHA-1 and 30 second counter. */
async function totpForSecret(secret: string, step: number) {
  const key = await crypto.subtle.importKey(
    "raw",
    base32Bytes(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const counter = new Uint8Array(8);
  let value = BigInt(step);
  for (let i = 7; i >= 0; i--) {
    counter[i] = Number(value & 255n);
    value >>= 8n;
  }
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = signed[19] & 15;
  const binary = ((signed[offset] & 127) << 24) | (signed[offset + 1] << 16) | (signed[offset + 2] << 8) | signed[offset + 3];
  return String(binary % 1_000_000).padStart(6, "0");
}
async function validPendingTotp(secret: string, code: string, now = Date.now()) {
  const currentStep = Math.floor(now / 1000 / TOTP_STEP_SECONDS);
  for (let offset = -TOTP_WINDOW_STEPS; offset <= TOTP_WINDOW_STEPS; offset++) {
    const expected = await totpForSecret(secret, currentStep + offset);
    if (expected === code) return true;
  }
  return false;
}

function cookieHeader(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}
function expired(session: Session) {
  const now = Date.now();
  return now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS;
}
function newSession(stage: Stage = "anonymous", userId?: string): Session {
  const session: Session = {
    id: randomText(48), csrf: randomText(40), stage, userId,
    createdAt: Date.now(), lastSeen: Date.now(),
    identityFails: 0, otpFails: 0, otpEnabled: false,
    backupHashes: [], recoveryFails: 0
  };
  sessions.set(session.id, session);
  return session;
}
function parseCookies(request: Request) {
  const raw = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const item of raw.split(";")) {
    const index = item.indexOf("=");
    if (index > -1) result[item.slice(0, index).trim()] = item.slice(index + 1).trim();
  }
  return result;
}
function currentSession(request: Request) {
  const id = parseCookies(request).mfa_session;
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session || expired(session)) {
    sessions.delete(id);
    return undefined;
  }
  session.lastSeen = Date.now();
  return session;
}
/* Requirement 1: no user identifier comes from the client. */
function ownerSession(request: Request) {
  const session = currentSession(request);
  return session && session.stage === "mfa" && session.userId === ACCOUNT.id ? session : undefined;
}
function csrfOK(request: Request, session: Session | undefined) {
  return !!session && request.headers.get("x-csrf-token") === session.csrf;
}
function securityHeaders(nonce?: string): Record<string, string> {
  const cspNonce = nonce ? `'nonce-${nonce}'` : "'none'";
  return {
    "content-security-policy": `default-src 'self'; script-src ${cspNonce}; style-src ${cspNonce}; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "access-control-allow-origin": TRUSTED_ORIGIN,
    "access-control-allow-credentials": "true",
    "vary": "Origin"
  };
}
function json(data: unknown, status = 200, extra: HeadersInit = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...securityHeaders(), ...extra }
  });
}
function fail(message = "We could not complete that step. Please try again.", status = 400) {
  return json({ ok: false, message }, status);
}
async function body(request: Request) {
  try {
    const value = await request.json();
    return value && typeof value === "object" ? value as Record<string, unknown> : {};
  } catch {
    return {};
  }
}
function cleanInput(value: unknown, max: number) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}
function validCode(value: unknown, length = 6) {
  return typeof value === "string" && new RegExp(`^\\d{${length}}$`).test(value);
}
function validRecovery(value: unknown) {
  return typeof value === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value);
}
function createRecoveryCodes() {
  return Array.from({ length: 8 }, () => `${randomText(4).toUpperCase()}-${randomText(4).toUpperCase()}`);
}
async function storeRecoveryCodes(session: Session, codes: string[]) {
  session.backupHashes = await Promise.all(codes.map(code => digest(`${recoveryPepper}:${code}`)));
}

async function api(request: Request, path: string): Promise<Response> {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        ...securityHeaders(),
        "access-control-allow-methods": "GET, POST",
        "access-control-allow-headers": "content-type, x-csrf-token"
      }
    });
  }

  if (request.method === "GET" && path === "/api/session") {
    let session = currentSession(request);
    const created = !session;
    if (!session) session = newSession();
    return json({
      ok: true, csrf: session.csrf, stage: session.stage,
      signedIn: session.stage !== "anonymous", verified: session.stage === "mfa",
      otpEnabled: session.otpEnabled, backupCount: session.backupHashes.length
    }, 200, created ? { "set-cookie": cookieHeader(session.id) } : {});
  }

  const session = currentSession(request);

  if (request.method === "POST" && path === "/api/sign-in") {
    if (!csrfOK(request, session)) return fail("Your secure page check expired. Refresh the page and try again.", 403);
    const data = await body(request);
    const email = cleanInput(data.email, 254).toLowerCase();
    const password = cleanInput(data.password, 256);
    if (email !== ACCOUNT.email || password !== ACCOUNT.password) {
      return fail("We could not sign you in. Check your email and password, then try again.", 401);
    }
    sessions.delete(session!.id);
    const fresh = newSession("identity", ACCOUNT.id);
    fresh.identityCode = randomDigits();
    fresh.identityExpiry = Date.now() + CODE_LIFETIME_MS;
    return json({ ok: true, csrf: fresh.csrf, testCode: fresh.identityCode }, 200, { "set-cookie": cookieHeader(fresh.id) });
  }

  if (request.method === "POST" && path === "/api/identity/send") {
    if (!session || session.stage !== "identity" || session.userId !== ACCOUNT.id) return fail("Please sign in again to continue.", 401);
    if (!csrfOK(request, session)) return fail("Your secure page check expired. Refresh and try again.", 403);
    session.identityCode = randomDigits();
    session.identityExpiry = Date.now() + CODE_LIFETIME_MS;
    session.identityUsed = false;
    session.identityFails = 0;
    session.identityLockedUntil = undefined;
    return json({ ok: true, csrf: session.csrf, testCode: session.identityCode });
  }

  if (request.method === "POST" && path === "/api/identity/verify") {
    if (!session || session.stage !== "identity" || session.userId !== ACCOUNT.id) return fail("Please sign in again to continue.", 401);
    if (!csrfOK(request, session)) return fail("Your secure page check expired. Refresh and try again.", 403);
    if (session.identityLockedUntil && session.identityLockedUntil > Date.now()) {
      return fail("Too many tries. Wait ten minutes, then request a new code.", 429);
    }
    const code = cleanInput((await body(request)).code, 6);
    if (!validCode(code) || session.identityUsed || !session.identityExpiry || session.identityExpiry < Date.now() || code !== session.identityCode) {
      session.identityFails++;
      if (session.identityFails >= OTP_MAX_FAILURES) session.identityLockedUntil = Date.now() + LOCK_MS;
      return fail("That code did not work. Check all 6 digits, or request a new code.", 400);
    }
    session.identityUsed = true;
    session.stage = "mfa";
    session.csrf = randomText(40);
    return json({ ok: true, csrf: session.csrf });
  }

  const owner = ownerSession(request);
  if (!owner) return fail("Please sign in again to manage MFA.", 401);

  if (request.method === "GET" && path === "/api/mfa/status") {
    return json({ ok: true, csrf: owner.csrf, otpEnabled: owner.otpEnabled, backupCount: owner.backupHashes.length });
  }
  if (request.method !== "POST") return fail("That page is not available.", 404);
  if (!csrfOK(request, owner)) return fail("Your secure page check expired. Refresh and try again.", 403);

  if (path === "/api/authenticator/start") {
    const secret = randomBase32(32);
    owner.encryptedSecret = await encryptAtRest(secret);
    owner.pendingOtpExpiry = Date.now() + CODE_LIFETIME_MS;
    owner.otpFails = 0;
    owner.otpLockedUntil = undefined;
    const issuer = "Local Bank";
    const label = `${issuer}:marcus@example.com`;
    const provisioningUri = `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    return json({ ok: true, csrf: owner.csrf, secret, provisioningUri });
  }

  if (path === "/api/authenticator/verify") {
    const now = Date.now();
    if (owner.otpLockedUntil && owner.otpLockedUntil > now) {
      return fail("Too many authenticator code tries. This setup is locked for ten minutes. Select “Show new setup details” to start a new setup now.", 429);
    }
    if (!owner.encryptedSecret || !owner.pendingOtpExpiry || owner.pendingOtpExpiry < now) {
      owner.encryptedSecret = undefined;
      owner.pendingOtpExpiry = undefined;
      return fail("This authenticator setup has expired. Select “Show new setup details” to make a new setup.", 400);
    }
    const code = cleanInput((await body(request)).code, 6);
    let accepted = false;
    try {
      accepted = validCode(code) && await validPendingTotp(await decryptAtRest(owner.encryptedSecret), code, now);
    } catch {
      accepted = false;
    }
    if (!accepted) {
      owner.otpFails++;
      if (owner.otpFails >= OTP_MAX_FAILURES) {
        owner.otpLockedUntil = now + LOCK_MS;
        return fail("Too many authenticator code tries. This setup is locked for ten minutes. Select “Show new setup details” to start a new setup now.", 429);
      }
      return fail(`That authenticator code did not work. Check the 6 digits and try again. You have ${OTP_MAX_FAILURES - owner.otpFails} tries before this setup is paused.`);
    }
    owner.otpEnabled = true;
    owner.encryptedSecret = undefined;
    owner.pendingOtpExpiry = undefined;
    owner.otpFails = 0;
    owner.otpLockedUntil = undefined;
    return json({ ok: true, csrf: owner.csrf });
  }

  if (path === "/api/backup/generate" || path === "/api/backup/regenerate") {
    if (!owner.otpEnabled) return fail("Set up your authenticator before making recovery codes.");
    const codes = createRecoveryCodes();
    await storeRecoveryCodes(owner, codes);
    return json({ ok: true, csrf: owner.csrf, codes });
  }

  if (path === "/api/recovery/verify") {
    if (owner.recoveryLockedUntil && owner.recoveryLockedUntil > Date.now()) {
      return fail("Too many tries. Wait ten minutes before trying another recovery code.", 429);
    }
    const code = cleanInput((await body(request)).code, 9).toUpperCase();
    if (!validRecovery(code)) return fail("Enter a recovery code like ABCD-1234.");
    const codeHash = await digest(`${recoveryPepper}:${code}`);
    const index = owner.backupHashes.indexOf(codeHash);
    if (index < 0) {
      owner.recoveryFails++;
      if (owner.recoveryFails >= OTP_MAX_FAILURES) owner.recoveryLockedUntil = Date.now() + LOCK_MS;
      return fail("That recovery code was not available. Check it, or use a different unused code.");
    }
    owner.backupHashes.splice(index, 1);
    owner.recoveryFails = 0;
    return json({ ok: true, csrf: owner.csrf, remaining: owner.backupHashes.length });
  }

  if (path === "/api/logout") {
    sessions.delete(owner.id);
    return json({ ok: true }, 200, { "set-cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }
  return fail("That page is not available.", 404);
}

function page(request: Request) {
  const nonce = randomText(24);
  let session = currentSession(request);
  const created = !session;
  if (!session) session = newSession();

  return new Response(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#16253a;--muted:#526276;--blue:#075d9b;--pale:#eef7fc;--line:#c9d7e3;--good:#126b42}
*{box-sizing:border-box}body{margin:0;background:#f5f8fa;color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.035em}main{max-width:600px;margin:auto;min-height:100vh;background:#fff;padding:20px 18px 34px}.brand{font-weight:700;color:var(--blue);font-size:1.05rem}.step{margin:18px 0;padding:10px 13px;border-left:5px solid var(--blue);background:var(--pale);font-size:.95rem}h1{font-size:1.65rem;line-height:1.3;margin:22px 0 10px}h2{font-size:1.18rem;line-height:1.35}p{margin:10px 0 17px}.card{border:1px solid var(--line);border-radius:12px;padding:17px;margin:18px 0}.hint{background:#fff8dc;border-left:4px solid #a77400;padding:11px 13px;font-size:.94rem}.message{padding:12px 14px;border-radius:8px;margin:14px 0}.error{background:#fff0f0;color:#762323}.success{background:#eaf8ef;color:#145b38}label{font-weight:700;display:block;margin-top:17px}input{width:100%;font:inherit;letter-spacing:.08em;border:2px solid #90a7b8;border-radius:8px;padding:12px;margin-top:5px;color:var(--ink)}input:focus{outline:3px solid #83c5ee;outline-offset:2px}button{font:inherit;font-weight:700;letter-spacing:.025em;border-radius:8px;padding:12px 16px;cursor:pointer;margin-top:19px;width:100%;border:2px solid var(--blue);background:var(--blue);color:#fff}.secondary{background:#fff;color:var(--blue)}button:focus{outline:3px solid #f3bb45;outline-offset:3px}.row{display:grid;gap:9px}.code{font-family:monospace;letter-spacing:.08em;word-break:break-all;background:#f2f5f7;padding:12px;border-radius:7px}.qrbox{display:flex;justify-content:center;padding:12px;background:#fff;border:1px solid var(--line);border-radius:8px}.qrbox svg{width:240px;height:240px;image-rendering:pixelated}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px}.codes div{font-family:monospace;letter-spacing:.07em;padding:9px;background:#f2f5f7;border-radius:6px}.logs{margin-top:26px;border-top:2px solid var(--line);padding-top:12px}.logs pre{white-space:pre-wrap;word-break:break-word;max-height:180px;overflow:auto;background:#172435;color:#e8f3ff;padding:11px;border-radius:8px;font:12px/1.55 monospace;letter-spacing:0}.small{font-size:.9rem;color:var(--muted)}@media(min-width:520px){main{margin-top:18px;border-radius:14px;box-shadow:0 3px 16px #ccd5dc}.row{grid-template-columns:1fr 1fr}.row button{margin-top:0}}
</style>
</head>
<body><main>
<header><div class="brand">🏦 Local Bank</div><div class="step" id="step">Step 1 of 4 · Sign in</div></header>
<section id="app" aria-live="polite">Loading secure setup…</section>
<section class="logs" aria-label="Activity logs"><h2>🧾 Logs</h2><p class="small">General simulation activity appears here. Private test values are only in the browser console.</p><pre id="logs">Ready.</pre></section>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
let csrf="";
const app=document.getElementById("app"),step=document.getElementById("step"),logs=document.getElementById("logs");
function log(message){console.log(message);logs.textContent+="\\\\n"+message}
function testLog(label,value){console.log("[TEST ONLY] "+label+":",value);log("Test value sent only to the browser console.")}
async function api(path,options={}){
 const response=await fetch(path,{method:options.method||"GET",credentials:"same-origin",headers:{"content-type":"application/json","x-csrf-token":csrf,...(options.headers||{})},body:options.body?JSON.stringify(options.body):undefined});
 const data=await response.json().catch(()=>({ok:false,message:"We could not complete that step. Please try again."}));
 if(data.csrf)csrf=data.csrf;return data;
}
function message(text,good=false){return '<div class="message '+(good?"success":"error")+'">'+text+"</div>"}
function setStep(text){step.textContent=text}
function bind(id,fn){const el=document.getElementById(id);if(el)el.addEventListener("click",fn)}

function signIn(){
 setStep("Step 1 of 4 · Sign in");
 app.innerHTML='<h1>Sign in</h1><p>Use your Local Bank email and password.</p><form id="signin"><label>Email address<input id="email" type="email" autocomplete="username" inputmode="email" placeholder="name@example.com" required></label><label>Password<input id="password" type="password" autocomplete="current-password" required></label><button>Continue →</button></form><p class="hint">💡 Example email: name@example.com. Check your saved password if you need help.</p>';
 document.getElementById("signin").onsubmit=async e=>{e.preventDefault();const d=await api("/api/sign-in",{method:"POST",body:{email:document.getElementById("email").value,password:document.getElementById("password").value}});if(!d.ok){app.insertAdjacentHTML("afterbegin",message(d.message));return}testLog("Mock identity code",d.testCode);identity("A sign-in check was sent. Enter the 6 digits when ready.")};
}
function identity(note=""){
 setStep("Step 2 of 4 · Check your identity");
 app.innerHTML='<h1>Check your identity</h1>'+(note?message(note,true):'')+'<p>We sent a 6-digit check code. There is no reading timer.</p><form id="verify"><label>6-digit code<input id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" placeholder="Example: 123456" maxlength="6" required></label><button>Verify code →</button></form><button class="secondary" id="resend">↻ Send a new code</button><p class="hint">💡 Test code values are available in the browser console. You may request another code at any time.</p>';
 document.getElementById("verify").onsubmit=async e=>{e.preventDefault();const d=await api("/api/identity/verify",{method:"POST",body:{code:document.getElementById("code").value}});if(!d.ok){app.insertAdjacentHTML("afterbegin",message(d.message));return}authStart()};
 bind("resend",async()=>{const d=await api("/api/identity/send",{method:"POST"});if(d.ok){testLog("New mock identity code",d.testCode);identity("A new code was sent. The earlier code no longer works.")}else app.insertAdjacentHTML("afterbegin",message(d.message))});
}

/*
 Standards-compliant QR encoder for Version 6-L QR symbols.
 This capacity is 136 byte-mode data bytes, sufficient for this ASCII otpauth URI.
 It creates QR byte mode data, Reed-Solomon EC (two 68/18 blocks), chooses a QR
 mask by ISO/IEC 18004 penalty rules, and writes valid format information.
*/
function qrSvg(text){
 const n=41, dataBytes=136, eccBytes=18, blocks=2, bytes=new TextEncoder().encode(text);
 if(bytes.length>134)return '<p class="small">The setup link is available below.</p>';
 const raw=[];function push(v,count){for(let i=count-1;i>=0;i--)raw.push((v>>>i)&1)}
 push(4,4);push(bytes.length,8);for(const b of bytes)push(b,8);push(0,Math.min(4,dataBytes*8-raw.length));while(raw.length%8)raw.push(0);
 const plain=[];for(let i=0;i<raw.length;i+=8)plain.push(raw.slice(i,i+8).reduce((a,b)=>a*2+b,0));
 for(let pad=0;plain.length<dataBytes;pad++)plain.push(pad%2?0x11:0xec);
 const exp=[];let x=1;for(let i=0;i<255;i++){exp[i]=x;x<<=1;if(x&256)x^=285}const log=[];for(let i=0;i<255;i++)log[exp[i]]=i;
 const mul=(a,b)=>!a||!b?0:exp[(log[a]+log[b])%255];
 let gen=[1];for(let i=0;i<eccBytes;i++){const g=new Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){g[j]^=gen[j];g[j+1]^=mul(gen[j],exp[i])}gen=g}
 function rs(chunk){const rem=new Array(eccBytes).fill(0);for(const v of chunk){const f=v^rem.shift();rem.push(0);for(let j=0;j<eccBytes;j++)rem[j]^=mul(gen[j+1],f)}return rem}
 const chunks=[];for(let i=0;i<blocks;i++)chunks.push(plain.slice(i*68,(i+1)*68));const ec=chunks.map(rs), stream=[];
 for(let i=0;i<68;i++)for(let j=0;j<blocks;j++)stream.push(chunks[j][i]);
 for(let i=0;i<eccBytes;i++)for(let j=0;j<blocks;j++)stream.push(ec[j][i]);
 const bits=[];for(const v of stream)pushBits(v,8,bits);function pushBits(v,c,a){for(let i=c-1;i>=0;i--)a.push((v>>>i)&1)}
 const base=Array.from({length:n},()=>Array(n).fill(null)), fixed=Array.from({length:n},()=>Array(n).fill(false));
 function put(y,x,v){if(y>=0&&x>=0&&y<n&&x<n){base[y][x]=v;fixed[y][x]=true}}
 function finder(y,x){for(let dy=-1;dy<=7;dy++)for(let dx=-1;dx<=7;dx++){const edge=dy>=0&&dy<=6&&dx>=0&&dx<=6;put(y+dy,x+dx,edge&&(dy===0||dy===6||dx===0||dx===6||(dy>=2&&dy<=4&&dx>=2&&dx<=4))?1:0)}}
 finder(0,0);finder(0,n-7);finder(n-7,0);
 for(let i=8;i<n-8;i++){put(6,i,i%2===0?1:0);put(i,6,i%2===0?1:0)}
 function alignment(y,x){for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)put(y+dy,x+dx,Math.max(Math.abs(dx),Math.abs(dy))===2||(!dx&&!dy)?1:0)}
 alignment(34,34);put(n-8,8,1);
 for(let i=0;i<9;i++){if(i!==6){put(8,i,0);put(i,8,0)}}for(let i=0;i<8;i++){put(8,n-1-i,0);put(n-1-i,8,0)}
 function populated(){const m=base.map(r=>r.slice());let k=0,up=true;for(let right=n-1;right>0;right-=2){if(right===6)right--;for(let q=0;q<n;q++){const y=up?n-1-q:q;for(let dx=0;dx<2;dx++){const xx=right-dx;if(!fixed[y][xx])m[y][xx]=bits[k++]||0}}up=!up}return m}
 const rawMatrix=populated();
 function maskBit(mask,y,x){return [((y+x)%2===0),(y%2===0),(x%3===0),((y+x)%3===0),((Math.floor(y/2)+Math.floor(x/3))%2===0),((y*x)%2+(y*x)%3===0),(((y*x)%2+(y*x)%3)%2===0),(((y+x)%2+(y*x)%3)%2===0)][mask]}
 function format(m,mask){let v=(1<<3)|mask;let d=v<<10;while(d.toString(2).length>=11)d^=0x537<<(d.toString(2).length-11);v=((v<<10)|d)^0x5412;for(let i=0;i<15;i++){const bit=(v>>>i)&1;if(i<6)m[i][8]=bit;else if(i<8)m[i+1][8]=bit;else m[n-15+i][8]=bit;if(i<8)m[8][n-i-1]=bit;else if(i<9)m[8][15-i]=bit;else m[8][15-i-1]=bit}}
 function penalty(m){let p=0;for(let y=0;y<n;y++)for(let x=0;x<n;x++){let same=0;for(let dy=-1;dy<=1;dy++)for(let dx=-1;dx<=1;dx++)if((dx||dy)&&y+dy>=0&&x+dx>=0&&y+dy<n&&x+dx<n&&m[y+dy][x+dx]===m[y][x])same++;if(same>5)p+=3+same-5}for(let y=0;y<n-1;y++)for(let x=0;x<n-1;x++)if(m[y][x]===m[y+1][x]&&m[y][x]===m[y][x+1]&&m[y][x]===m[y+1][x+1])p+=3;for(let y=0;y<n;y++)for(let x=0;x<n-6;x++)if(m[y].slice(x,x+7).join("")==="1011101")p+=40;for(let x=0;x<n;x++)for(let y=0;y<n-6;y++){let s="";for(let i=0;i<7;i++)s+=m[y+i][x];if(s==="1011101")p+=40}let dark=0;for(const r of m)for(const v of r)dark+=v;return p+Math.floor(Math.abs(dark*20/(n*n)-10))*10}
 let best,bestScore=Infinity;for(let mask=0;mask<8;mask++){const m=rawMatrix.map(r=>r.slice());for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(!fixed[y][x]&&maskBit(mask,y,x))m[y][x]^=1;format(m,mask);const score=penalty(m);if(score<bestScore){bestScore=score;best=m}}
 let rects='';for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(best[y][x])rects+='<rect x="'+(x+4)+'" y="'+(y+4)+'" width="1" height="1"/>';
 return '<svg viewBox="0 0 '+(n+8)+' '+(n+8)+'" role="img" aria-label="Scannable QR code for authenticator setup"><title>Scan this QR code in your authenticator app</title><rect width="100%" height="100%" fill="white"/><g fill="#16253a">'+rects+'</g></svg>';
}

function authStart(){
 setStep("Step 3 of 4 · Add authenticator");
 app.innerHTML='<h1>Add your authenticator</h1><p>An authenticator app makes a 6-digit code for you.</p><div class="card"><h2>📱 Set up your app</h2><p>Show one setup. You can scan it or copy it.</p><button id="start">Show setup details →</button></div><p class="hint">💡 Take as long as you need. A new setup replaces any earlier setup.</p>';
 bind("start",async()=>{const d=await api("/api/authenticator/start",{method:"POST"});if(!d.ok){app.insertAdjacentHTML("afterbegin",message(d.message));return}testLog("Authenticator Base32 secret",d.secret);testLog("Authenticator provisioning URI",d.provisioningUri);authDetails(d)});
}
function authDetails(d){
 setStep("Step 3 of 4 · Add authenticator");
 app.innerHTML='<h1>Set up your authenticator</h1><p>The QR code, setup link, and Base32 secret below all configure the <strong>same authenticator</strong>. After setup, enter the 6-digit TOTP code it generates on this page.</p><div class="card"><h2>▣ Scan QR code</h2><div class="qrbox" id="qr"></div><h2>🔗 Setup link</h2><div class="code" id="uri"></div><button class="secondary" id="copyuri">Copy setup link</button><h2>⌨️ Manual Base32 secret</h2><div class="code" id="secret"></div><button class="secondary" id="copysecret">Copy secret</button></div><form id="otp"><label>Code from your authenticator<input id="otpcode" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6" required></label><button>Confirm authenticator →</button></form><button class="secondary" id="restart">↻ Show new setup details</button><p class="hint">💡 TOTP uses standard 6-digit codes that change in your app every 30 seconds. This setup is available for 10 minutes. Test values are only in the browser console.</p>';
 document.getElementById("qr").innerHTML=qrSvg(d.provisioningUri);
 document.getElementById("uri").textContent=d.provisioningUri;document.getElementById("secret").textContent=d.secret;
 function copy(text,label){navigator.clipboard?.writeText(text).then(()=>log(label+" copied to clipboard.")).catch(()=>log("Copy was unavailable. You can select the displayed text."))}
 bind("copyuri",()=>copy(d.provisioningUri,"Setup link"));bind("copysecret",()=>copy(d.secret,"Manual secret"));bind("restart",authStart);
 document.getElementById("otp").onsubmit=async e=>{e.preventDefault();const r=await api("/api/authenticator/verify",{method:"POST",body:{code:document.getElementById("otpcode").value}});if(!r.ok){app.insertAdjacentHTML("afterbegin",message(r.message));return}backup()};
}
function backup(){
 setStep("Step 4 of 4 · Save recovery codes");
 app.innerHTML='<h1>Save recovery codes</h1><p>Recovery codes help if you lose your phone. Each code works once.</p><button id="make">Create recovery codes →</button><p class="hint">💡 Keep them somewhere private. You can make a new set later.</p>';
 bind("make",async()=>{const d=await api("/api/backup/generate",{method:"POST"});if(!d.ok){app.insertAdjacentHTML("afterbegin",message(d.message));return}testLog("Mock recovery codes",d.codes);showCodes(d.codes)});
}
function showCodes(codes){
 setStep("Step 4 of 4 · Save recovery codes");
 app.innerHTML='<h1>Your recovery codes</h1>'+message("Your recovery codes are ready. Save them now, then continue.",true)+'<div class="codes" id="codes"></div><div class="row"><button class="secondary" id="copycodes">Copy codes</button><button class="secondary" id="download">Download text file</button></div><button id="finish">I saved my codes →</button><p class="hint">💡 Codes are not kept in browser storage.</p>';
 const box=document.getElementById("codes");codes.forEach(code=>{const x=document.createElement("div");x.textContent=code;box.appendChild(x)});
 bind("copycodes",()=>navigator.clipboard?.writeText(codes.join("\\n")).then(()=>log("Recovery codes copied to clipboard.")));
 bind("download",()=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([codes.join("\\n")],{type:"text/plain"}));a.download="local-bank-recovery-codes.txt";a.click();URL.revokeObjectURL(a.href);log("Recovery code text file prepared for download.")});
 bind("finish",settings);
}
async function settings(){
 const d=await api("/api/mfa/status");if(!d.ok){signIn();return}
 setStep("Complete · MFA settings");
 app.innerHTML='<h1>✅ MFA is ready</h1><p>Your authenticator is '+(d.otpEnabled?"on":"not set up")+". You have "+d.backupCount+' unused recovery codes.</p><div class="card"><h2>🔐 Use a recovery code</h2><form id="recovery"><label>Recovery code<input id="recoverycode" autocomplete="one-time-code" placeholder="Example: ABCD-1234" maxlength="9" required></label><button class="secondary">Use recovery code</button></form></div><button class="secondary" id="regenerate">↻ Make new recovery codes</button><button class="secondary" id="again">↻ Set up authenticator again</button><button id="logout">Log out</button><p class="hint">💡 Making new recovery codes replaces every old recovery code.</p>';
 document.getElementById("recovery").onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery/verify",{method:"POST",body:{code:document.getElementById("recoverycode").value}});if(!r.ok){app.insertAdjacentHTML("afterbegin",message(r.message));return}settings()};
 bind("regenerate",async()=>{const r=await api("/api/backup/regenerate",{method:"POST"});if(!r.ok){app.insertAdjacentHTML("afterbegin",message(r.message));return}testLog("Replacement mock recovery codes",r.codes);showCodes(r.codes)});
 bind("again",authStart);bind("logout",async()=>{await api("/api/logout",{method:"POST"});csrf="";log("Signed out. Secure session invalidated.");signIn()});
}
async function boot(){const d=await api("/api/session");if(d.verified)settings();else if(d.signedIn)identity();else signIn()}
boot();
})();
</script></body></html>`, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...securityHeaders(nonce),
      ...(created ? { "set-cookie": cookieHeader(session.id) } : {})
    }
  });
}

const cert = readFileSync("certs/cert.pem");
const key = readFileSync("certs/key.pem");

Bun.serve({
  port: PORT,
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.headers.get("x-forwarded-proto") === "http") {
        return new Response("Secure connection required.", { status: 400, headers: securityHeaders() });
      }
      const origin = request.headers.get("origin");
      if (origin && origin !== TRUSTED_ORIGIN) {
        return new Response("Not allowed.", { status: 403, headers: securityHeaders() });
      }
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      if (request.method === "GET" && url.pathname === "/") return page(request);
      return new Response("Page not found.", { status: 404, headers: securityHeaders() });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: securityHeaders() });
    }
  }
});
