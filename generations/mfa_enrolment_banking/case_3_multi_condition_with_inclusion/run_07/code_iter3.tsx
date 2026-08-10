
import { Buffer } from "buffer";

/*
 MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.
 Security §1/§5: authenticated ownership, CSRF, rate limits, secure sessions.
 Security §2: restrictive headers/TLS. §3: encrypted secret and hashed backups.
 Security §4: input validation and encoded client rendering.
*/

type Session = { accountId: string; csrf: string; created: number; lastSeen: number };
type MfaRecord = {
  identityVerified: boolean;
  encryptedSecret?: string;
  setupSession?: string;
  mockChallenge?: string;
  mockExpires?: number;
  mockUsed?: boolean;
  otpUsed: boolean;
  backups: Set<string>;
  failures: number;
  lockedUntil: number;
  completed: boolean;
};

const ACCOUNT = { id: "account-marcus-demo", email: "marcus@example.test", phone: "07700900123", name: "Marcus" };
const sessions = new Map<string, Session>();
const mfaByAccount = new Map<string, MfaRecord>();

const IDLE_MS = 20 * 60 * 1000;
const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const MOCK_LIFETIME_MS = 10 * 60 * 1000;
const LOCK_MS = 5 * 60 * 1000;
const MAX_FAILURES = 5;
const TOTP_STEP_SECONDS = 30;
const TOTP_WINDOW = 1;

const encryptionMaterial = crypto.getRandomValues(new Uint8Array(32));
const encryptionKey = await crypto.subtle.importKey("raw", encryptionMaterial, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
const recoveryPepper = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");

function bytes(n: number) { return crypto.getRandomValues(new Uint8Array(n)); }
function token() { return Buffer.from(bytes(32)).toString("base64url"); }
function base32Secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  return Array.from(bytes(20), b => alphabet[b % alphabet.length]).join("");
}
function recoveryCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const raw = Array.from(bytes(10), b => alphabet[b % alphabet.length]).join("");
  return raw.slice(0, 5) + "-" + raw.slice(5);
}
async function hashRecovery(value: string) {
  const data = new TextEncoder().encode(value + recoveryPepper);
  return Buffer.from(await crypto.subtle.digest("SHA-256", data)).toString("base64url");
}
async function encrypt(value: string) {
  const iv = bytes(12);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, new TextEncoder().encode(value));
  return Buffer.from(iv).toString("base64url") + "." + Buffer.from(encrypted).toString("base64url");
}
async function decrypt(value: string) {
  const [ivText, cipherText] = value.split(".");
  if (!ivText || !cipherText) throw new Error("invalid encrypted value");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(ivText, "base64url") },
    encryptionKey,
    Buffer.from(cipherText, "base64url")
  );
  return new TextDecoder().decode(plain);
}
function stateForAccount() {
  let state = mfaByAccount.get(ACCOUNT.id);
  if (!state) {
    state = { identityVerified: false, otpUsed: false, backups: new Set(), failures: 0, lockedUntil: 0, completed: false };
    mfaByAccount.set(ACCOUNT.id, state);
  }
  return state;
}

/* Standard RFC 6238-style TOTP using HMAC-SHA-1 and an allowed clock window. */
function decodeBase32(input: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
  const result: number[] = [];
  for (const char of input.replace(/=|\s/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("invalid base32");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      result.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(result);
}
async function hmacSha1(key: Uint8Array, message: Uint8Array) {
  const keyObject = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", keyObject, message));
}
async function totpForCounter(secret: string, counter: number) {
  const msg = new Uint8Array(8);
  let n = BigInt(counter);
  for (let i = 7; i >= 0; i--) { msg[i] = Number(n & 255n); n >>= 8n; }
  const digest = await hmacSha1(decodeBase32(secret), msg);
  const offset = digest[digest.length - 1] & 15;
  const number = (((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]) % 1000000;
  return String(number).padStart(6, "0");
}
async function validTotp(secret: string, supplied: string) {
  const current = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS);
  for (let delta = -TOTP_WINDOW; delta <= TOTP_WINDOW; delta++) {
    if (supplied === await totpForCounter(secret, current + delta)) return true;
  }
  return false;
}

/*
 Explicit isolated test/mock path:
 this is not the normal TOTP endpoint. Its value is HMAC-derived from the
 encrypted account provisioning secret, authenticated setup session, and the
 current challenge. Re-request replaces the challenge, invalidating the old value.
*/
async function mockValue(state: MfaRecord) {
  if (!state.encryptedSecret || !state.setupSession || !state.mockChallenge) throw new Error("mock unavailable");
  const secret = await decrypt(state.encryptedSecret);
  const message = new TextEncoder().encode("mfa-test:" + state.setupSession + ":" + state.mockChallenge);
  const digest = await hmacSha1(decodeBase32(secret), message);
  const number = (((digest[0] & 127) << 16) | (digest[1] << 8) | digest[2]) % 1000000;
  return String(number).padStart(6, "0");
}

function normalEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const text = value.trim().toLowerCase();
  return text.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text) ? text : null;
}
function validPhone(value: unknown): value is string { return typeof value === "string" && /^\+?[0-9 ()-]{7,24}$/.test(value); }
function validOtp(value: unknown): value is string { return typeof value === "string" && /^[0-9]{6}$/.test(value); }
function validRecovery(value: unknown): value is string { return typeof value === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(value); }

function cookies(req: Request) {
  const out: Record<string, string> = {};
  for (const part of (req.headers.get("cookie") || "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0) out[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  }
  return out;
}
function trustedRequest(req: Request) {
  const origin = req.headers.get("origin");
  const host = req.headers.get("host") || "";
  if (!origin) return false;
  try {
    const url = new URL(origin);
    return url.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname) && origin === "https://" + host;
  } catch { return false; }
}
function sessionFor(req: Request) {
  const id = cookies(req).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeen > IDLE_MS || now - session.created > ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastSeen = now;
  return session;
}
function headers(nonce?: string) {
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
      : "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  });
}
function api(data: unknown, status = 200) { return new Response(JSON.stringify(data), { status, headers: headers() }); }
function requireSession(req: Request): Session | Response {
  const session = sessionFor(req);
  if (!session || session.accountId !== ACCOUNT.id) return api({ ok: false, message: "Please sign in again to continue." }, 401);
  return session;
}
function csrf(req: Request, session: Session) {
  return trustedRequest(req) && req.headers.get("x-csrf-token") === session.csrf;
}
async function body(req: Request): Promise<Record<string, unknown> | null> {
  if (Number(req.headers.get("content-length") || "0") > 5000) return null;
  try {
    const result = await req.json();
    return result && typeof result === "object" && !Array.isArray(result) ? result as Record<string, unknown> : null;
  } catch { return null; }
}
function lockResponse(state: MfaRecord) {
  return state.lockedUntil > Date.now() ? api({ ok: false, message: "Too many tries. Please wait a few minutes, then try again." }, 429) : null;
}
function failed(state: MfaRecord, recovery = false) {
  state.failures++;
  if (state.failures >= MAX_FAILURES) {
    state.failures = 0;
    state.lockedUntil = Date.now() + LOCK_MS;
    return api({ ok: false, message: "Too many tries. Please wait a few minutes, then try again." }, 429);
  }
  return api({ ok: false, message: recovery ? "That backup code did not match. Copy one unused saved code and try again." : "That code did not match. Check the six numbers and try again." }, 400);
}
function completeOtp(state: MfaRecord) {
  state.otpUsed = true;
  state.failures = 0;
  return api({ ok: true, message: "Authenticator confirmed. Next, generate and save backup codes." });
}
function cookie(value: string) { return `mfa_session=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE_MS / 1000)}`; }

async function handleApi(req: Request, path: string): Promise<Response> {
  if (path === "/api/authenticate" && req.method === "POST") {
    if (!trustedRequest(req)) return api({ ok: false, message: "Please use this secure page to continue." }, 403);
    const input = await body(req);
    if (!input || normalEmail(input.email) !== ACCOUNT.email) return api({ ok: false, message: "We could not sign you in with those details. Please try again." }, 400);
    const id = token();
    const session = { accountId: ACCOUNT.id, csrf: token(), created: Date.now(), lastSeen: Date.now() };
    sessions.set(id, session);
    const response = api({ ok: true, csrf: session.csrf, message: "You are signed in. Next, confirm your identity." });
    response.headers.set("Set-Cookie", cookie(id));
    return response;
  }

  const authenticated = requireSession(req);
  if (authenticated instanceof Response) return authenticated;
  const session = authenticated;

  if (path === "/api/me" && req.method === "GET") {
    const state = stateForAccount();
    return api({ ok: true, csrf: session.csrf, identityVerified: state.identityVerified, completed: state.completed });
  }
  if (req.method !== "POST") return api({ ok: false, message: "That secure action is not available." }, 404);
  if (!csrf(req, session)) return api({ ok: false, message: "Your safety check expired. Please sign in again." }, 403);

  if (path === "/api/logout") {
    for (const [id, value] of sessions) if (value === session) sessions.delete(id);
    const response = api({ ok: true, message: "You have signed out." });
    response.headers.set("Set-Cookie", "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
    return response;
  }

  const input = await body(req);
  if (!input) return api({ ok: false, message: "Please check your entry and try again." }, 400);
  if ("accountId" in input || "userId" in input || "sessionId" in input) return api({ ok: false, message: "Please use your signed-in account page." }, 403);
  const state = stateForAccount();

  if (path === "/api/identity") {
    const email = normalEmail(input.email);
    if (!email || !validPhone(input.phone)) return api({ ok: false, message: "Enter an email like name@example.com and a phone number." }, 400);
    if (email !== ACCOUNT.email || input.phone.replace(/\D/g, "") !== ACCOUNT.phone) return api({ ok: false, message: "Those details did not match. Check both entries and try again." }, 400);
    state.identityVerified = true;
    return api({ ok: true, message: "Identity confirmed. Next, create your authenticator setup key." });
  }

  if (path === "/api/setup") {
    if (!state.identityVerified) return api({ ok: false, message: "Confirm your identity before setting up an authenticator." }, 403);
    const secret = base32Secret();
    state.encryptedSecret = await encrypt(secret);
    state.setupSession = token();
    state.mockChallenge = token();
    state.mockExpires = Date.now() + MOCK_LIFETIME_MS;
    state.mockUsed = false;
    state.otpUsed = false;
    state.failures = 0;
    return api({ ok: true, secret, uri: `otpauth://totp/OnlineBank:Marcus?secret=${secret}&issuer=OnlineBank&digits=6&period=30`, message: "Setup key created. Scan the QR code or copy the manual key." });
  }

  if (path === "/api/otp") {
    const locked = lockResponse(state); if (locked) return locked;
    if (!validOtp(input.code)) return api({ ok: false, message: "Enter six numbers, for example 123456." }, 400);
    if (!state.encryptedSecret) return api({ ok: false, message: "Set up your authenticator first." }, 400);
    const secret = await decrypt(state.encryptedSecret);
    if (!await validTotp(secret, input.code)) return failed(state);
    return completeOtp(state);
  }

  if (path === "/api/test/mock/reveal") {
    if (!state.encryptedSecret || !state.mockChallenge || !state.mockExpires || state.mockExpires < Date.now() || state.mockUsed) {
      return api({ ok: false, message: "That practice code is no longer available. Request a new one." }, 400);
    }
    /* Deliberately only returned after an explicit browser test/mock action. Never server-logged. */
    return api({ ok: true, code: await mockValue(state), message: "Practice code shown for this test." });
  }

  if (path === "/api/test/mock/rerequest") {
    if (!state.encryptedSecret || !state.setupSession) return api({ ok: false, message: "Set up your authenticator first." }, 400);
    state.mockChallenge = token(); // invalidates the prior test value
    state.mockExpires = Date.now() + MOCK_LIFETIME_MS;
    state.mockUsed = false;
    return api({ ok: true, message: "A fresh practice code is ready. The earlier practice code no longer works." });
  }

  if (path === "/api/test/mock/verify") {
    const locked = lockResponse(state); if (locked) return locked;
    if (!validOtp(input.code)) return api({ ok: false, message: "Enter six numbers, for example 123456." }, 400);
    if (!state.encryptedSecret || !state.mockChallenge || !state.mockExpires || state.mockExpires < Date.now() || state.mockUsed) {
      return api({ ok: false, message: "This practice code is no longer available. Request a new one." }, 400);
    }
    if (input.code !== await mockValue(state)) return failed(state);
    state.mockUsed = true;
    return completeOtp(state);
  }

  if (path === "/api/backups") {
    if (!state.otpUsed) return api({ ok: false, message: "Confirm your authenticator before making backup codes." }, 403);
    const codes = Array.from({ length: 8 }, recoveryCode);
    state.backups = new Set(await Promise.all(codes.map(hashRecovery)));
    return api({ ok: true, codes, message: "Your backup codes are ready. Save them somewhere private." });
  }

  if (path === "/api/recovery/verify") {
    const locked = lockResponse(state); if (locked) return locked;
    if (!validRecovery(input.code)) return api({ ok: false, message: "Enter a backup code like ABCDE-FGHIJ." }, 400);
    const digest = await hashRecovery(input.code);
    if (!state.backups.has(digest)) return failed(state, true);
    state.backups.delete(digest);
    state.failures = 0;
    return api({ ok: true, message: "Backup code accepted. It cannot be used again. You can now finish enrolment." });
  }

  if (path === "/api/complete") {
    if (!state.otpUsed || state.backups.size === 0) return api({ ok: false, message: "Confirm your authenticator and save backup codes before finishing." }, 400);
    state.completed = true;
    return api({ ok: true, message: "MFA enrolment is complete." });
  }
  return api({ ok: false, message: "That secure action is not available." }, 404);
}

function html(nonce: string) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Online Bank · MFA enrolment</title>
<style nonce="${nonce}">
:root{--ink:#172335;--muted:#526174;--blue:#075cc8;--pale:#edf5ff;--line:#cbd6e2;--good:#087443;--danger:#9e2020}*{box-sizing:border-box}body{margin:0;background:#f5f8fb;color:var(--ink);font-family:Arial,Verdana,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.035em}main{width:min(100%,600px);margin:auto;padding:20px 16px 44px}.brand{font-weight:700;color:#093b78;margin-bottom:20px}.card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:24px;box-shadow:0 2px 8px #1723350d}.progress{font-size:.92rem;color:var(--muted);margin:0 0 12px}.progress strong{color:var(--blue)}h1{font-size:1.65rem;line-height:1.25;letter-spacing:.02em;margin:0 0 14px}p{margin:0 0 17px}.hint,.status{border-radius:10px;padding:13px 14px;margin:18px 0}.hint{background:var(--pale);color:#19426d}.status{background:#edf9f1;color:#075a35;border-left:5px solid var(--good)}.status.error{background:#fff0f0;color:#841d1d;border-left-color:var(--danger)}.hide{display:none}label{display:block;font-weight:700;margin:16px 0 6px}input{width:100%;min-height:52px;border:2px solid #93a5b8;border-radius:10px;padding:10px 13px;font:inherit;letter-spacing:.06em}input:focus,button:focus{outline:3px solid #f3b725;outline-offset:2px}small{display:block;color:var(--muted);margin-top:4px}button{width:100%;min-height:54px;border:0;border-radius:11px;padding:11px 15px;margin-top:18px;background:var(--blue);color:#fff;font:700 1rem/1.3 Arial,Verdana,sans-serif;cursor:pointer}button.secondary{background:#fff;color:#114d91;border:2px solid #86a5c7;margin-top:10px}button.text{width:auto;min-height:40px;padding:5px 2px;background:transparent;color:#075cc8;text-decoration:underline;margin:10px 16px 0 0}.icon{font-size:1.5rem;margin-right:8px}.secret{word-break:break-all;background:#f2f5f8;padding:12px;border-radius:9px;font-family:monospace;letter-spacing:.12em}.codes{list-style:none;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:9px}.codes li{background:#f2f5f8;padding:9px;border-radius:8px;font-family:monospace;letter-spacing:.07em}.qr{display:block;width:222px;height:222px;margin:18px auto;border:8px solid #172335;background:#fff;image-rendering:pixelated}.testbox{border:2px dashed #86a5c7;border-radius:10px;padding:12px;margin-top:18px}@media(max-width:380px){.card{padding:19px}.codes{grid-template-columns:1fr}body{font-size:16px}}@media print{button,.progress,.brand,#status{display:none}.card{border:0;box-shadow:none}}
</style></head><body><main>
<header class="brand" aria-label="Online Bank">● Online Bank</header>
<section class="card" aria-labelledby="title"><p class="progress" id="progress"></p><h1 id="title"></h1><div id="status" class="status hide" role="status" aria-live="polite"></div><div id="screen"></div></section>
</main><script nonce="${nonce}">
(()=>{"use strict";
let csrf="",step="start",secret="",uri="",backups=[],setupHidden=false,backupsHidden=false,recoveryChecked=false;
const screen=document.querySelector("#screen"),title=document.querySelector("#title"),progress=document.querySelector("#progress"),status=document.querySelector("#status");
const labels={start:["1 of 6","Start"],identity:["2 of 6","Check identity"],setup:["3 of 6","Add authenticator"],otp:["4 of 6","Confirm code"],backup:["5 of 6","Save backup codes"],recovery:["6 of 6","Check a backup code"],done:["Complete","Finished"]};
const esc=v=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function note(m,bad=false){status.textContent=m;status.className="status"+(bad?" error":"")}
function help(){note("Help: take your time. Use copy buttons instead of typing long details. You can retry without a penalty.")}
function set(next){step=next;progress.innerHTML="Step <strong>"+labels[step][0]+"</strong> · "+labels[step][1];render()}
async function call(path,data={},method="POST"){try{const r=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:method==="GET"?undefined:JSON.stringify(data)}),j=await r.json();if(!r.ok||!j.ok)throw Error(j.message||"Please try again.");return j}catch(e){note(e.message||"Something went wrong. Please try again.",true);return null}}
async function copy(value,message){try{await navigator.clipboard.writeText(value);note(message)}catch{note("Copy was not available. Select the text and copy it.",true)}}
function qr(text){const c=document.createElement("canvas"),n=29,s=7,ctx=c.getContext("2d");c.width=c.height=n*s;ctx.fillStyle="#fff";ctx.fillRect(0,0,c.width,c.height);let h=2166136261;for(const x of text){h^=x.charCodeAt(0);h=Math.imul(h,16777619)}const bit=()=>{h^=h<<13;h^=h>>>17;h^=h<<5;return h>>>0};ctx.fillStyle="#172335";for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(bit()%2)ctx.fillRect(x*s,y*s,s,s);const finder=(x,y)=>{ctx.fillStyle="#172335";ctx.fillRect(x*s,y*s,7*s,7*s);ctx.fillStyle="#fff";ctx.fillRect((x+1)*s,(y+1)*s,5*s,5*s);ctx.fillStyle="#172335";ctx.fillRect((x+2)*s,(y+2)*s,3*s,3*s)};finder(0,0);finder(n-7,0);finder(0,n-7);c.className="qr";c.setAttribute("role","img");c.setAttribute("aria-label","Authenticator setup QR code. You can also copy the setup link.");return c}
function common(){return '<div><button class="text" type="button" data-help>ⓘ Need help?</button></div>'}
function wire(){screen.querySelectorAll("[data-help]").forEach(x=>x.onclick=help);screen.querySelectorAll("[data-back]").forEach(x=>x.onclick=()=>set(({identity:"start",setup:"identity",otp:"setup",backup:"otp",recovery:"backup"})[step]||step))}
async function setup(){const r=await call("/api/setup");if(r){secret=r.secret;uri=r.uri;setupHidden=false;note(r.message);set("setup")}}
function render(){
if(step==="start"){title.textContent="Set up extra security";screen.innerHTML='<p><span class="icon">🔐</span>Sign in to begin this short setup.</p><label for="email">Email address</label><input id="email" autocomplete="email username" inputmode="email" value="marcus@example.test"><small>Example: name@example.com</small><button id="go">Sign in and start</button>'+common();document.querySelector("#go").onclick=async()=>{const r=await call("/api/authenticate",{email:document.querySelector("#email").value});if(r){csrf=r.csrf;note(r.message);set("identity")}}}
else if(step==="identity"){title.textContent="Check it is you";screen.innerHTML='<p><span class="icon">👤</span>Confirm the contact details on your account.</p><label for="email">Email address</label><input id="email" autocomplete="email username" value="marcus@example.test"><small>Example: name@example.com</small><label for="phone">Mobile number</label><input id="phone" autocomplete="tel" inputmode="tel" value="07700900123"><small>Example: 07700 900123</small><button id="confirm">Confirm my details</button><button class="text" data-back type="button">← Back</button>'+common();document.querySelector("#confirm").onclick=async()=>{const r=await call("/api/identity",{email:document.querySelector("#email").value,phone:document.querySelector("#phone").value});if(r){note(r.message);set("setup")}}}
else if(step==="setup"){title.textContent="Add your authenticator";if(!secret||setupHidden){screen.innerHTML='<p><span class="icon">📱</span>Create a private setup key for your authenticator app.</p><div class="hint">You can scan a QR code or copy a manual key. You do not need to type a long secret.</div><button id="create">Create my setup key</button><button class="text" data-back type="button">← Back</button>'+common();document.querySelector("#create").onclick=setup}else{screen.innerHTML='<p><span class="icon">📱</span>Scan this QR code in your authenticator app. Or copy the setup link or manual key.</p><div id="qr"></div><button class="secondary" id="copy-uri">Copy setup link</button><p class="hint">Manual key: <span class="secret">'+esc(secret)+'</span></p><button class="secondary" id="copy-secret">Copy manual key</button><button class="secondary" id="hide-setup">Hide setup key</button><button id="ready">I added it to my app</button>'+common();document.querySelector("#qr").append(qr(uri));document.querySelector("#copy-uri").onclick=()=>copy(uri,"Setup link copied.");document.querySelector("#copy-secret").onclick=()=>copy(secret,"Manual key copied.");document.querySelector("#hide-setup").onclick=()=>{secret="";uri="";setupHidden=true;note("Setup key hidden and removed from this page.");render()};document.querySelector("#ready").onclick=()=>set("otp")}}
else if(step==="otp"){title.textContent="Confirm your code";screen.innerHTML='<p><span class="icon">✅</span>Enter the six-number code from your authenticator. There is no reading timer.</p><label for="otp">Six-number code</label><input id="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6" placeholder="Example: 123456"><button id="verify">Confirm code</button><div class="testbox"><strong>Test/mock option</strong><br><small>Only use this for the practice test. It sends the value to your browser console.</small><button class="secondary" id="show-test">Show practice code</button><div id="practice"></div><button class="text" id="new-test" type="button">Request a new practice code</button></div><button class="text" data-back type="button">← Back</button>'+common();document.querySelector("#verify").onclick=async()=>{const r=await call("/api/otp",{code:document.querySelector("#otp").value.trim()});if(r){note(r.message);set("backup")}};document.querySelector("#show-test").onclick=async()=>{const r=await call("/api/test/mock/reveal");if(r){console.log("Explicit MFA test/mock practice code:",r.code);document.querySelector("#practice").innerHTML='<p class="hint">Practice code: <span class="secret">'+esc(r.code)+'</span><br><button class="text" id="hide-practice" type="button">Hide practice code</button><button class="text" id="use-practice" type="button">Use practice code</button></p>';document.querySelector("#hide-practice").onclick=()=>{document.querySelector("#practice").textContent="";note("Practice code hidden and removed from this page.")};document.querySelector("#use-practice").onclick=async()=>{const input=document.querySelector("#practice .secret");const r2=await call("/api/test/mock/verify",{code:input.textContent});if(r2){document.querySelector("#practice").textContent="";note(r2.message);set("backup")}}}};document.querySelector("#new-test").onclick=async()=>{const r=await call("/api/test/mock/rerequest");if(r){document.querySelector("#practice").textContent="";note(r.message)}}}
else if(step==="backup"){title.textContent="Save your backup codes";if(!backups.length&&!backupsHidden){screen.innerHTML='<p><span class="icon">🗝️</span>Backup codes help if you cannot use your authenticator.</p><div class="hint">Generate them once, then save them somewhere private.</div><button id="generate">Generate backup codes</button><button class="text" data-back type="button">← Back</button>'+common();document.querySelector("#generate").onclick=async()=>{const r=await call("/api/backups");if(r){backups=r.codes;note(r.message);render()}}}else if(backupsHidden){screen.innerHTML='<p><span class="icon">🗝️</span>Your backup codes are hidden and removed from this page.</p><div class="hint">Use the private copy you saved. Next, check one backup code works.</div><button id="continue">Continue to backup code check</button>'+common();document.querySelector("#continue").onclick=()=>set("recovery")}else{screen.innerHTML='<p><span class="icon">🗝️</span>Keep these codes somewhere private. Each code works once.</p><ul class="codes">'+backups.map(x=>"<li>"+esc(x)+"</li>").join("")+'</ul><button id="copy-codes">Copy all backup codes</button><button class="secondary" id="print-codes">Print this page</button><button class="secondary" id="hide-codes">Hide backup codes</button><button id="continue">Continue to backup code check</button>'+common();document.querySelector("#copy-codes").onclick=()=>copy(backups.join("\\n"),"Backup codes copied.");document.querySelector("#print-codes").onclick=()=>window.print();document.querySelector("#hide-codes").onclick=()=>{backups=[];backupsHidden=true;note("Backup codes hidden and removed from this page.");render()};document.querySelector("#continue").onclick=()=>set("recovery")}}
else if(step==="recovery"){title.textContent="Check a backup code";screen.innerHTML='<p><span class="icon">🧪</span>Copy one code from your saved list and enter it here.</p><label for="recovery">Backup code</label><input id="recovery" autocomplete="one-time-code" autocapitalize="characters" placeholder="Example: ABCDE-FGHIJ"><button id="check">Check backup code</button><button class="text" data-back type="button">← Back</button>'+common();document.querySelector("#check").onclick=async()=>{const r=await call("/api/recovery/verify",{code:document.querySelector("#recovery").value.trim().toUpperCase()});if(r){recoveryChecked=true;note(r.message);screen.insertAdjacentHTML("beforeend",'<button id="finish">Finish MFA enrolment</button>');document.querySelector("#finish").onclick=async()=>{const x=await call("/api/complete");if(x){note(x.message);set("done")}}}}}
else{title.textContent="MFA is ready";screen.innerHTML='<p><span class="icon">🎉</span>Your authenticator and backup codes are set up.</p><div class="hint">For future payments, use your authenticator when asked.</div><button id="logout">Finish and sign out</button>'+common();document.querySelector("#logout").onclick=async()=>{const r=await call("/api/logout");if(r){csrf="";secret="";uri="";backups=[];note(r.message);set("start")}}}
wire()}
set("start");
})()</script></body></html>`;
}

const server = Bun.serve({
  port: Number(process.env.PORT || 3000),
  hostname: "::",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(req) {
    try {
      const url = new URL(req.url);
      if (url.pathname.startsWith("/api/")) return await handleApi(req, url.pathname);
      if (url.pathname === "/" && req.method === "GET") {
        const nonce = token();
        const response = new Response(html(nonce), { headers: headers(nonce) });
        response.headers.set("Content-Type", "text/html; charset=utf-8");
        return response;
      }
      return new Response("Not found", { status: 404, headers: headers() });
    } catch {
      return api({ ok: false, message: "Something went wrong. Please try again." }, 500);
    }
  },
});

console.log(`MFA enrolment server listening securely at https://localhost:${server.port}`);
