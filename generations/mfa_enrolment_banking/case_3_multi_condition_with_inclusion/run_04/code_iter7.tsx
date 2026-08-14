
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — Requirements 1–5
 Server-owned sessions, CSRF, encrypted secrets, rate limits, secure headers,
 HTTPS, strict CORS allow-list, and test-only browser console fixtures.
*/
type Stage = "anonymous" | "identity" | "mfa";
type Session = {
  id: string; csrf: string; stage: Stage; userId?: string; createdAt: number; lastSeen: number;
  identityCode?: string; identityExpiry?: number; identityUsed?: boolean; identityFails: number; identityLockedUntil?: number;
  pendingEncryptedSecret?: string; pendingOtpExpiry?: number; otpFails: number; otpLockedUntil?: number;
  enrolledEncryptedSecret?: string; otpEnabled: boolean; backupHashes: string[];
  recoveryFails: number; recoveryLockedUntil?: number;
};

const PORT = 3000;
/* Task: deterministic fixture disclosure is explicit and unavailable in production. */
const TEST_MODE = process.env.MFA_TEST_MODE === "true" && process.env.NODE_ENV !== "production";
const ALLOWED_ORIGINS = new Set([
  `https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`
]);
const ACCOUNT = { id: "account-marcus", email: "marcus@example.com", password: "BankDemo!9" };
const sessions = new Map<string, Session>();
const encoder = new TextEncoder(), decoder = new TextDecoder();
const IDLE = 20 * 60_000, ABSOLUTE = 8 * 60 * 60_000, LIFE = 10 * 60_000, LOCK = 10 * 60_000, MAX = 5;
const masterKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
const pepper = crypto.getRandomValues(new Uint8Array(32));

function random(chars: string, length: number) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return [...bytes].map(byte => chars[byte % chars.length]).join("");
}
function token(length = 32) { return random("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789", length); }
function digits(length = 6) { return TEST_MODE ? "123456".slice(0, length) : random("0123456789", length); }
function base32(length = 32) {
  return TEST_MODE ? "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".slice(0, length) : random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", length);
}
function recoveryCodes() {
  if (TEST_MODE) return ["ABCD-1234", "EFGH-2345", "JKLM-3456", "NPQR-4567", "STUV-5678", "WXYZ-6789", "BCDE-7890", "FGHJ-8901"];
  return Array.from({ length: 8 }, () => `${random("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 4)}-${random("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 4)}`);
}
function b64(bytes: Uint8Array) { return Buffer.from(bytes).toString("base64url"); }
function unb64(value: string) { return new Uint8Array(Buffer.from(value, "base64url")); }
async function hash(value: string) {
  return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(`${b64(pepper)}:${value}`))));
}
async function encrypt(value: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(value));
  return `${b64(iv)}.${b64(new Uint8Array(encrypted))}`;
}
async function decrypt(value: string) {
  const [iv, encrypted] = value.split(".");
  if (!iv || !encrypted) throw Error("invalid encrypted value");
  return decoder.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, masterKey, unb64(encrypted)));
}
function base32Bytes(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, current = 0; const output: number[] = [];
  for (const char of value.replace(/=+$/, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw Error("invalid base32");
    current = (current << 5) | index; bits += 5;
    while (bits >= 8) { bits -= 8; output.push((current >> bits) & 255); }
  }
  return new Uint8Array(output);
}
async function totp(secret: string, step = Math.floor(Date.now() / 30_000)) {
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const counter = new Uint8Array(8); let count = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(count & 255n); count >>= 8n; }
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = mac[19] & 15;
  return String((((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3]) % 1_000_000).padStart(6, "0");
}
async function validTotp(secret: string, code: string) {
  const step = Math.floor(Date.now() / 30_000);
  for (let adjustment = -1; adjustment <= 1; adjustment++) if (code === await totp(secret, step + adjustment)) return true;
  return false;
}
function session(stage: Stage = "anonymous", userId?: string) {
  const s: Session = {
    id: token(48), csrf: token(40), stage, userId, createdAt: Date.now(), lastSeen: Date.now(),
    identityFails: 0, otpFails: 0, otpEnabled: false, backupHashes: [], recoveryFails: 0
  };
  sessions.set(s.id, s); return s;
}
function cookies(request: Request) {
  const output: Record<string, string> = {};
  for (const piece of (request.headers.get("cookie") || "").split(";")) {
    const at = piece.indexOf("=");
    if (at > 0) output[piece.slice(0, at).trim()] = piece.slice(at + 1).trim();
  }
  return output;
}
function stale(s: Session) { return Date.now() - s.lastSeen > IDLE || Date.now() - s.createdAt > ABSOLUTE; }
function current(request: Request) {
  const id = cookies(request).mfa_session, s = id && sessions.get(id);
  if (!s || stale(s)) { if (id) sessions.delete(id); return undefined; }
  s.lastSeen = Date.now(); return s;
}
function owner(request: Request) {
  const s = current(request);
  return s?.stage === "mfa" && s.userId === ACCOUNT.id ? s : undefined;
}
function csrf(request: Request, s?: Session) { return !!s && request.headers.get("x-csrf-token") === s.csrf; }
function cookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE / 1000}`; }
function allowedOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return origin && ALLOWED_ORIGINS.has(origin) ? origin : "";
}
function headers(request?: Request, nonce?: string): Record<string, string> {
  const origin = request ? allowedOrigin(request) : "";
  return {
    "content-security-policy": `default-src 'self'; script-src ${nonce ? `'nonce-${nonce}'` : "'none'"}; style-src ${nonce ? `'nonce-${nonce}'` : "'none'"}; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()", "vary": "Origin",
    ...(origin ? { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" } : {})
  };
}
function out(request: Request, value: unknown, status = 200, extra: HeadersInit = {}) {
  return new Response(JSON.stringify(value), { status, headers: { ...headers(request), "content-type": "application/json; charset=utf-8", ...extra } });
}
function fail(request: Request, message: string, status = 400) { return out(request, { ok: false, message }, status); }
async function data(request: Request) {
  try { const value = await request.json(); return value && typeof value === "object" ? value as Record<string, unknown> : {}; } catch { return {}; }
}
function clean(value: unknown, max: number) { return typeof value === "string" ? value.trim().slice(0, max) : ""; }
function six(value: string) { return /^\d{6}$/.test(value); }
function recovery(value: string) { return /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value); }
async function saveCodes(s: Session, codes: string[]) { s.backupHashes = await Promise.all(codes.map(hash)); }
function provisioning(secret: string) {
  const issuer = "Local Bank", label = `${issuer}:marcus@example.com`;
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
/* Safe, non-secret enrolment progress for refresh/resume. */
function progress(s: Session) {
  if (s.stage === "anonymous") return "sign-in";
  if (s.stage === "identity") return "identity";
  if (s.pendingEncryptedSecret && s.pendingOtpExpiry && s.pendingOtpExpiry > Date.now()) return "authenticator-details";
  if (s.otpEnabled && !s.backupHashes.length) return "backup-code";
  if (s.otpEnabled) return "completion";
  return "authenticator-start";
}

async function api(request: Request, path: string): Promise<Response> {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: { ...headers(request), "access-control-allow-methods": "GET, POST", "access-control-allow-headers": "content-type, x-csrf-token" } });
  }
  if (request.method === "GET" && path === "/api/session") {
    let s = current(request), made = !s; if (!s) s = session();
    return out(request, {
      ok: true, csrf: s.csrf, signedIn: s.stage !== "anonymous", verified: s.stage === "mfa",
      otpEnabled: s.otpEnabled, backupCount: s.backupHashes.length, progress: progress(s),
      pendingAuthenticatorSetup: progress(s) === "authenticator-details", testMode: TEST_MODE
    }, 200, made ? { "set-cookie": cookie(s.id) } : {});
  }

  const s = current(request);
  if (request.method === "POST" && path === "/api/sign-in") {
    if (!csrf(request, s)) return fail(request, "Your secure page check expired. Refresh the page and try again.", 403);
    const input = await data(request), email = clean(input.email, 254).toLowerCase(), password = clean(input.password, 256);
    if (email !== ACCOUNT.email || password !== ACCOUNT.password) return fail(request, "We could not sign you in. Check your email and password, then try again.", 401);
    sessions.delete(s!.id);
    const fresh = session("identity", ACCOUNT.id);
    fresh.identityCode = digits(); fresh.identityExpiry = Date.now() + LIFE;
    return out(request, { ok: true, csrf: fresh.csrf, ...(TEST_MODE ? { testCode: fresh.identityCode } : {}) }, 200, { "set-cookie": cookie(fresh.id) });
  }
  if (request.method === "POST" && path === "/api/identity/send") {
    if (!s || s.stage !== "identity" || s.userId !== ACCOUNT.id) return fail(request, "Please sign in again to continue.", 401);
    if (!csrf(request, s)) return fail(request, "Your secure page check expired. Refresh and try again.", 403);
    /* A live abuse lock remains live; otherwise a replacement code gets a fresh counter. */
    if (s.identityLockedUntil && s.identityLockedUntil > Date.now()) return fail(request, "Too many tries. Wait ten minutes, then request a new code.", 429);
    s.identityLockedUntil = undefined; s.identityFails = 0;
    s.identityCode = digits(); s.identityExpiry = Date.now() + LIFE; s.identityUsed = false;
    return out(request, { ok: true, csrf: s.csrf, ...(TEST_MODE ? { testCode: s.identityCode } : {}) });
  }
  if (request.method === "POST" && path === "/api/identity/verify") {
    if (!s || s.stage !== "identity" || s.userId !== ACCOUNT.id) return fail(request, "Please sign in again to continue.", 401);
    if (!csrf(request, s)) return fail(request, "Your secure page check expired. Refresh and try again.", 403);
    if (s.identityLockedUntil && s.identityLockedUntil > Date.now()) return fail(request, "Too many tries. Wait ten minutes, then request a new code.", 429);
    const code = clean((await data(request)).code, 6);
    if (!six(code) || s.identityUsed || !s.identityExpiry || s.identityExpiry < Date.now() || code !== s.identityCode) {
      if (++s.identityFails >= MAX) s.identityLockedUntil = Date.now() + LOCK;
      return fail(request, "That code did not work. Check all 6 digits, or request a new code.");
    }
    s.identityUsed = true; s.stage = "mfa"; s.csrf = token(40);
    return out(request, { ok: true, csrf: s.csrf });
  }

  const o = owner(request);
  if (!o) return fail(request, "Please sign in again to manage MFA.", 401);
  if (request.method === "GET" && path === "/api/mfa/status") return out(request, { ok: true, csrf: o.csrf, otpEnabled: o.otpEnabled, backupCount: o.backupHashes.length, progress: progress(o) });
  /* An owner may re-open their still-pending setup after a refresh. */
  if (request.method === "GET" && path === "/api/authenticator/details") {
    if (!o.pendingEncryptedSecret || !o.pendingOtpExpiry || o.pendingOtpExpiry < Date.now()) return fail(request, "This setup has expired. Show new setup details to make a new setup.");
    try {
      const secret = await decrypt(o.pendingEncryptedSecret);
      return out(request, { ok: true, csrf: o.csrf, secret, provisioningUri: provisioning(secret) });
    } catch { return fail(request, "This setup is unavailable. Show new setup details to make a new setup."); }
  }
  if (request.method !== "POST") return fail(request, "That page is not available.", 404);
  if (!csrf(request, o)) return fail(request, "Your secure page check expired. Refresh and try again.", 403);

  if (path === "/api/authenticator/start") {
    if (o.otpLockedUntil && o.otpLockedUntil > Date.now()) return fail(request, "Too many authenticator code tries. This setup is locked for ten minutes. Wait, then show new setup details.", 429);
    /* A genuinely new setup resets old failures once no active lock applies. */
    o.otpFails = 0; o.otpLockedUntil = undefined;
    const secret = base32();
    o.pendingEncryptedSecret = await encrypt(secret); o.pendingOtpExpiry = Date.now() + LIFE;
    return out(request, { ok: true, csrf: o.csrf, secret, provisioningUri: provisioning(secret) });
  }
  if (path === "/api/authenticator/verify") {
    const now = Date.now();
    if (o.otpLockedUntil && o.otpLockedUntil > now) return fail(request, "Too many authenticator code tries. This setup is locked for ten minutes. Wait, then show new setup details.", 429);
    if (!o.pendingEncryptedSecret || !o.pendingOtpExpiry || o.pendingOtpExpiry < now) {
      o.pendingEncryptedSecret = undefined; o.pendingOtpExpiry = undefined;
      return fail(request, "This setup has expired. Show new setup details to make a new setup.");
    }
    const code = clean((await data(request)).code, 6); let okay = false;
    try { okay = six(code) && await validTotp(await decrypt(o.pendingEncryptedSecret), code); } catch {}
    if (!okay) {
      if (++o.otpFails >= MAX) { o.otpLockedUntil = now + LOCK; return fail(request, "Too many authenticator code tries. This setup is locked for ten minutes. Wait, then show new setup details.", 429); }
      return fail(request, `That authenticator code did not work. Check the 6 digits. You have ${MAX - o.otpFails} tries before this setup pauses.`);
    }
    o.enrolledEncryptedSecret = o.pendingEncryptedSecret; o.pendingEncryptedSecret = undefined; o.pendingOtpExpiry = undefined;
    o.otpEnabled = true; o.otpFails = 0; o.otpLockedUntil = undefined;
    return out(request, { ok: true, csrf: o.csrf });
  }
  if (path === "/api/backup/generate" || path === "/api/backup/regenerate") {
    if (!o.otpEnabled || !o.enrolledEncryptedSecret) return fail(request, "Set up your authenticator before making recovery codes.");
    const codes = recoveryCodes(); await saveCodes(o, codes);
    return out(request, { ok: true, csrf: o.csrf, codes });
  }
  if (path === "/api/recovery/verify") {
    if (o.recoveryLockedUntil && o.recoveryLockedUntil > Date.now()) return fail(request, "Too many tries. Wait ten minutes before trying another recovery code.", 429);
    const code = clean((await data(request)).code, 9).toUpperCase();
    if (!recovery(code)) {
      if (++o.recoveryFails >= MAX) { o.recoveryLockedUntil = Date.now() + LOCK; return fail(request, "Too many tries. Wait ten minutes before trying another recovery code.", 429); }
      return fail(request, "Enter a recovery code like ABCD-1234.");
    }
    const index = o.backupHashes.indexOf(await hash(code));
    if (index < 0) {
      if (++o.recoveryFails >= MAX) { o.recoveryLockedUntil = Date.now() + LOCK; return fail(request, "Too many tries. Wait ten minutes before trying another recovery code.", 429); }
      return fail(request, "That recovery code was not available. Check it, or use a different unused code.");
    }
    o.backupHashes.splice(index, 1); o.recoveryFails = 0;
    return out(request, { ok: true, csrf: o.csrf, remaining: o.backupHashes.length });
  }
  if (path === "/api/logout") {
    sessions.delete(o.id);
    return out(request, { ok: true }, 200, { "set-cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }
  return fail(request, "That page is not available.", 404);
}

function page(request: Request) {
  const nonce = token(24); let s = current(request), made = !s; if (!s) s = session();
  return new Response(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#17263a;--blue:#075d9b;--pale:#eef7fc;--line:#c9d7e3}*{box-sizing:border-box}body{margin:0;background:#f4f8fa;color:var(--ink);font:17px/1.65 Verdana,Arial,sans-serif;letter-spacing:.035em}main{max-width:600px;min-height:100vh;margin:auto;padding:20px 18px 34px;background:#fff}.brand{font-weight:bold;color:var(--blue)}.step{margin:17px 0;padding:9px 13px;background:var(--pale);border-left:5px solid var(--blue)}h1{font-size:1.6rem;line-height:1.3}h2{font-size:1.1rem}p{margin:10px 0 17px}.card{margin:18px 0;padding:16px;border:1px solid var(--line);border-radius:12px}.hint{padding:11px 13px;background:#fff8dc;border-left:4px solid #9b7200;font-size:.92rem}.message{padding:11px 13px;border-radius:8px;margin:13px 0}.success{background:#e9f8ee;color:#145b38}.error{background:#fff0f0;color:#762323}label{display:block;font-weight:bold;margin-top:15px}input{width:100%;margin-top:5px;padding:12px;border:2px solid #90a7b8;border-radius:8px;font:inherit;letter-spacing:.08em}button{width:100%;margin-top:17px;padding:12px 14px;border:2px solid var(--blue);border-radius:8px;background:var(--blue);color:#fff;font:inherit;font-weight:bold;cursor:pointer}.secondary{background:#fff;color:var(--blue)}button:focus,input:focus{outline:3px solid #f3bb45;outline-offset:3px}.code{padding:11px;background:#f1f5f7;border-radius:7px;font:14px/1.55 monospace;word-break:break-all;letter-spacing:.05em}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px}.codes div{padding:9px;background:#f1f5f7;border-radius:6px;font-family:monospace}.qr{display:block;width:min(100%,290px);height:auto;margin:16px auto;padding:8px;background:#fff;border:1px solid var(--line);image-rendering:pixelated}.logs{margin-top:28px;border-top:2px solid var(--line)}pre{max-height:180px;overflow:auto;padding:11px;background:#172435;color:#e8f3ff;border-radius:8px;white-space:pre-wrap;font:12px/1.5 monospace;letter-spacing:0}.small{font-size:.88rem;color:#526276}@media(min-width:520px){main{margin-top:18px;border-radius:14px;box-shadow:0 3px 16px #ccd5dc}}
</style></head><body><main><header><div class="brand">🏦 Local Bank</div><div class="step" id="step">Step 1 of 4 · Sign in</div></header><section id="app" aria-live="polite">Loading secure setup…</section><section class="logs"><h2>🧾 Logs</h2><p class="small">Simulation activity appears here. Private codes and setup details are never shown in this panel.</p><pre id="logs">Ready.</pre></section></main>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",resetting=false,testMode=false;
const app=document.querySelector("#app"),step=document.querySelector("#step"),logs=document.querySelector("#logs");
const log=value=>{console.log(value);logs.textContent+="\\n"+value;logs.scrollTop=logs.scrollHeight};
/* Task: browser disclosure/logging of fixtures is strictly test-mode guarded. */
const test=(name,value)=>{if(testMode&&value!==undefined)console.log("[TEST ONLY] "+name+": "+(Array.isArray(value)?value.join(", "):value))};
const msg=(value,good=false)=>'<div class="message '+(good?"success":"error")+'">'+value+"</div>";
const bind=(id,handler)=>document.querySelector("#"+id)?.addEventListener("click",handler);
async function api(path,options={}){
 const response=await fetch(path,{method:options.method||"GET",credentials:"same-origin",headers:{"content-type":"application/json","x-csrf-token":csrf},body:options.body?JSON.stringify(options.body):undefined});
 const output=await response.json().catch(()=>({ok:false,message:"We could not complete that step. Please try again."}));
 if(output.csrf)csrf=output.csrf;
 if(response.status===401&&path!=="/api/session"&&!resetting)await anonymousSession("Your session ended. Please sign in again.");
 return output;
}
async function anonymousSession(note=""){
 resetting=true;csrf="";const d=await api("/api/session");csrf=d.csrf||"";testMode=!!d.testMode;resetting=false;sign(note);
}
function sign(note=""){
 step.textContent="Step 1 of 4 · Sign in";
 app.innerHTML='<h1>Sign in</h1>'+(note?msg(note):'')+'<p>Use your Local Bank email and password.</p><form id="f"><label>Email address<input id="email" type="email" autocomplete="username" placeholder="name@example.com" required></label><label>Password<input id="pass" type="password" autocomplete="current-password" required></label><button>Continue →</button></form><p class="hint">💡 Example email: name@example.com. Your password manager can help.</p>';
 document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const d=await api("/api/sign-in",{method:"POST",body:{email:document.querySelector("#email").value,password:document.querySelector("#pass").value}});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));test("Mock identity OTP",d.testCode);log("Sign-in succeeded. Identity check code simulated.");identity("Sign-in succeeded. Next, enter the 6-digit identity code.")};
}
function identity(note=""){
 step.textContent="Step 2 of 4 · Check your identity";
 app.innerHTML='<h1>Check your identity</h1>'+(note?msg(note,true):"")+'<p>We sent a 6-digit check code. There is no reading timer.</p><form id="f"><label>6-digit code<input id="code" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6" required></label><button>Verify code →</button></form><button class="secondary" id="send">↻ Send a new code</button><p class="hint">💡 You can request another code at any time.</p>';
 document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const d=await api("/api/identity/verify",{method:"POST",body:{code:document.querySelector("#code").value}});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));authStart("Identity check succeeded. Next, set up your authenticator.")};
 bind("send",async()=>{const d=await api("/api/identity/send",{method:"POST"});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));test("New mock identity OTP",d.testCode);log("A replacement identity code was simulated.");identity("A new code was sent. The earlier code no longer works.")});
}
function authStart(note=""){
 step.textContent="Step 3 of 4 · Add authenticator";
 app.innerHTML='<h1>Add your authenticator</h1>'+(note?msg(note,true):"")+'<p>An authenticator app makes a 6-digit code for you.</p><div class="card"><h2>📱 Set up your app</h2><p>Show one setup. You can scan a QR code, copy the setup link, or copy the secret.</p><button id="start">Show setup details →</button></div><p class="hint">💡 Take as long as you need. A new setup replaces an earlier setup.</p>';
 bind("start",async()=>{const d=await api("/api/authenticator/start",{method:"POST"});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));test("Authenticator Base32 secret",d.secret);test("Authenticator provisioning URI",d.provisioningUri);log("Authenticator setup details were prepared.");details(d)});
}
/* Local QR renderer: fixed Version 10-L QR, byte mode, no network/library/assets. */
function qrSvg(text){
 const n=57,a=Array.from({length:n},()=>Array(n).fill(null)),put=(r,c,v)=>{if(r>=0&&c>=0&&r<n&&c<n)a[r][c]=v};
 const finder=(r,c)=>{for(let y=-1;y<8;y++)for(let x=-1;x<8;x++)put(r+y,c+x,y>=0&&y<7&&x>=0&&x<7&&(y==0||y==6||x==0||x==6||(y>=2&&y<=4&&x>=2&&x<=4)))};
 finder(0,0);finder(n-7,0);finder(0,n-7);
 for(let i=8;i<n-8;i++){if(a[6][i]===null)put(6,i,i%2===0);if(a[i][6]===null)put(i,6,i%2===0)}
 for(const p of [6,28,50])for(const q of [6,28,50])if(!((p==6&&q==6)||(p==6&&q==50)||(p==50&&q==6)))for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)put(p+y,q+x,Math.max(Math.abs(x),Math.abs(y))!=1);
 for(let i=0;i<9;i++){if(a[i][8]===null)put(i,8,false);if(a[8][i]===null)put(8,i,false);if(a[n-1-i][8]===null)put(n-1-i,8,false);if(a[8][n-1-i]===null)put(8,n-1-i,false)}put(n-8,8,true);
 const bytes=[...new TextEncoder().encode(text)];if(bytes.length>271)return "";
 let bits=[];const add=(v,l)=>{for(let i=l-1;i>=0;i--)bits.push((v>>i)&1)};add(4,4);add(bytes.length,16);bytes.forEach(x=>add(x,8));add(0,Math.min(4,274*8-bits.length));while(bits.length%8)bits.push(0);
 let data=[];for(let i=0;i<bits.length;i+=8)data.push(bits.slice(i,i+8).reduce((v,b)=>v*2+b,0));for(let z=0;data.length<274;z++)data.push(z%2?0x11:0xec);
 const exp=[],logg=Array(256);let x=1;for(let i=0;i<255;i++){exp[i]=x;logg[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 let gen=[1];for(let i=0;i<18;i++){let g=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){g[j]^=gen[j];g[j+1]^=exp[logg[gen[j]]+i]}gen=g}
 const blocks=[],sizes=[68,68,69,69];let at=0;for(const size of sizes){let b=data.slice(at,at+=size),r=Array(18).fill(0);for(const v of b){let f=v^r.shift();r.push(0);if(f)for(let j=0;j<18;j++)r[j]^=exp[(logg[f]+logg[gen[j+1]])%255]}blocks.push([b,r])}
 let words=[];for(let i=0;i<69;i++)for(const b of blocks)if(i<b[0].length)words.push(b[0][i]);for(let i=0;i<18;i++)for(const b of blocks)words.push(b[1][i]);
 let stream=[];words.forEach(v=>addBits(v,8));function addBits(v,l){for(let i=l-1;i>=0;i--)stream.push((v>>i)&1)}
 let k=0,up=true;for(let c=n-1;c>0;c-=2){if(c==6)c--;for(let z=0;z<n;z++){let r=up?n-1-z:z;for(let j=0;j<2;j++)if(a[r][c-j]===null){let v=stream[k++]||0;if((r+c-j)%2===0)v^=1;put(r,c-j,!!v)}}up=!up}
 let format=0x77c4;for(let i=0;i<15;i++){let v=(format>>i)&1;if(i<6)put(i,8,!!v);else if(i<8)put(i+1,8,!!v);else put(n-15+i,8,!!v);if(i<8)put(8,n-i-1,!!v);else if(i<9)put(8,15-i,!!v);else put(8,15-i-1,!!v)}
 let rect="";for(let r=0;r<n;r++)for(let c=0;c<n;c++)if(a[r][c])rect+='<rect x="'+(c+4)+'" y="'+(r+4)+'" width="1" height="1"/>';
 return '<svg class="qr" role="img" aria-label="QR code for authenticator setup" viewBox="0 0 65 65" xmlns="http://www.w3.org/2000/svg"><rect width="65" height="65" fill="white"/><g fill="#000">'+rect+"</g></svg>";
}
function details(d){
 step.textContent="Step 3 of 4 · Add authenticator";
 app.innerHTML='<h1>Set up your authenticator</h1><p>Scan the QR code, use the setup link, or enter the manual secret in your authenticator app.</p><div class="card"><button class="secondary" id="qrbutton" aria-expanded="false">▣ Show QR code</button><div id="qrbox" hidden></div><h2>🔗 Setup link</h2><div class="code" id="uri"></div><button class="secondary" id="copyuri">Copy setup link</button><button class="secondary" id="toggle" aria-expanded="false">Show manual setup details</button><div id="manual" hidden><h2>⌨️ Manual Base32 secret</h2><div class="code" id="secret"></div><button class="secondary" id="copysecret">Copy secret</button></div></div><form id="f"><label>Code from your authenticator<input id="otp" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6" required></label><button>Confirm authenticator →</button></form><button class="secondary" id="restart">↻ Show new setup details</button><p class="hint">💡 This setup is available for 10 minutes. You can retry.</p>';
 const uriBox=document.querySelector("#uri"),secretBox=document.querySelector("#secret"),manual=document.querySelector("#manual"),toggle=document.querySelector("#toggle"),qrbox=document.querySelector("#qrbox"),qrbutton=document.querySelector("#qrbutton");
 uriBox.textContent=d.provisioningUri;secretBox.textContent=d.secret;
 bind("qrbutton",()=>{const show=qrbox.hidden;qrbox.hidden=!show;qrbutton.textContent=show?"Hide QR code":"▣ Show QR code";qrbutton.setAttribute("aria-expanded",String(show));if(show&&!qrbox.innerHTML)qrbox.innerHTML=qrSvg(d.provisioningUri)});
 bind("toggle",()=>{const show=manual.hidden;manual.hidden=!show;toggle.textContent=show?"Hide manual setup details":"Show manual setup details";toggle.setAttribute("aria-expanded",String(show))});
 const copy=(value,name)=>navigator.clipboard?.writeText(value).then(()=>log(name+" copied to clipboard.")).catch(()=>log("Copy was unavailable. You can select the text."));
 bind("copyuri",()=>copy(d.provisioningUri,"Setup link"));bind("copysecret",()=>copy(d.secret,"Manual secret"));bind("restart",()=>authStart());
 document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const result=await api("/api/authenticator/verify",{method:"POST",body:{code:document.querySelector("#otp").value}});if(!result.ok)return app.insertAdjacentHTML("afterbegin",msg(result.message));backup("Authenticator verification succeeded. Next, save recovery codes.")};
}
async function resumeDetails(){const d=await api("/api/authenticator/details");if(d.ok)details(d);else authStart(d.message)}
function backup(note=""){
 step.textContent="Step 4 of 4 · Save recovery codes";
 app.innerHTML='<h1>Save recovery codes</h1>'+(note?msg(note,true):"")+'<p>Recovery codes help if you lose your phone. Each code works once.</p><button id="make">Create recovery codes →</button><p class="hint">💡 Keep them somewhere private. You can make a new set later.</p>';
 bind("make",async()=>{const d=await api("/api/backup/generate",{method:"POST"});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));test("Mock recovery codes",d.codes);log("Recovery codes were created.");codes(d.codes)});
}
function codes(values){
 step.textContent="Step 4 of 4 · Save recovery codes";
 app.innerHTML='<h1>Your recovery codes</h1>'+msg("Your recovery codes are ready. Save them now, then continue.",true)+'<button class="secondary" id="show" aria-expanded="false">Show recovery codes</button><div id="list" class="codes" hidden></div><button class="secondary" id="copy">Copy codes</button><button class="secondary" id="down">Download text file</button><button id="finish">I saved my codes →</button>';
 const list=document.querySelector("#list"),show=document.querySelector("#show");values.forEach(value=>{const item=document.createElement("div");item.textContent=value;list.append(item)});
 bind("show",()=>{const visible=list.hidden;list.hidden=!visible;show.textContent=visible?"Hide recovery codes":"Show recovery codes";show.setAttribute("aria-expanded",String(visible))});
 bind("copy",()=>navigator.clipboard?.writeText(values.join("\\n")).then(()=>log("Recovery codes copied to clipboard.")).catch(()=>log("Copy was unavailable. You can select the codes.")));
 bind("down",()=>{const link=document.createElement("a");link.href=URL.createObjectURL(new Blob([values.join("\\n")],{type:"text/plain"}));link.download="local-bank-recovery-codes.txt";link.click();URL.revokeObjectURL(link.href);log("Recovery code text file prepared for download.")});
 bind("finish",settings);
}
async function settings(){
 const d=await api("/api/mfa/status");if(!d.ok)return;
 step.textContent="Complete · MFA settings";
 app.innerHTML='<h1>✅ MFA is ready</h1><p>Your authenticator is on. You have '+d.backupCount+' unused recovery codes.</p><div class="card"><h2>🔐 Use a recovery code</h2><form id="f"><label>Recovery code<input id="rc" autocomplete="one-time-code" placeholder="Example: ABCD-1234" maxlength="9" required></label><button class="secondary">Use recovery code</button></form></div><button class="secondary" id="regen">↻ Make new recovery codes</button><button class="secondary" id="again">↻ Set up authenticator again</button><button id="logout">Log out</button>';
 document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const result=await api("/api/recovery/verify",{method:"POST",body:{code:document.querySelector("#rc").value}});if(!result.ok)return app.insertAdjacentHTML("afterbegin",msg(result.message));settings()};
 bind("regen",async()=>{const result=await api("/api/backup/regenerate",{method:"POST"});if(!result.ok)return app.insertAdjacentHTML("afterbegin",msg(result.message));test("Replacement mock recovery codes",result.codes);log("Replacement recovery codes were created.");codes(result.codes)});
 bind("again",()=>authStart());bind("logout",async()=>{await api("/api/logout",{method:"POST"});log("Signed out. Secure session invalidated.");await anonymousSession("You have signed out.")});
}
(async()=>{const d=await api("/api/session");testMode=!!d.testMode;switch(d.progress){case"identity":identity();break;case"authenticator-details":resumeDetails();break;case"authenticator-start":authStart();break;case"backup-code":backup("Your authenticator is ready. Next, save recovery codes.");break;case"completion":settings();break;default:sign()}})();
})();
</script></body></html>`, { headers: { ...headers(request, nonce), "content-type": "text/html; charset=utf-8", ...(made ? { "set-cookie": cookie(s.id) } : {}) } });
}

const cert = readFileSync("certs/cert.pem"), key = readFileSync("certs/key.pem");
Bun.serve({
  port: PORT, tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url), origin = request.headers.get("origin");
      if (request.headers.get("x-forwarded-proto") === "http") return new Response("Secure connection required.", { status: 400, headers: headers(request) });
      if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response("Not allowed.", { status: 403, headers: headers(request) });
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      if (request.method === "GET" && url.pathname === "/") return page(request);
      return new Response("Page not found.", { status: 404, headers: headers(request) });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: headers(request) });
    }
  }
});
