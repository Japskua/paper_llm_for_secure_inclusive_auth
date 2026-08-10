
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — Requirements 1–5
 Server-owned sessions, CSRF, encrypted secrets, TLS, secure headers, lockouts,
 and non-production-only deterministic browser fixtures.
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
const PRODUCTION = process.env.NODE_ENV === "production";
const TEST_MODE = !PRODUCTION;
const TEST_AUTHENTICATOR_CODE = "654321";
const ACCOUNT = { id: "account-marcus", email: "marcus@example.com", password: "BankDemo!9" };
const ALLOWED_ORIGINS = new Set([`https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`]);
const sessions = new Map<string, Session>();
const encoder = new TextEncoder(), decoder = new TextDecoder();
const IDLE = 20 * 60_000, ABSOLUTE = 8 * 60 * 60_000, LIFE = 10 * 60_000, LOCK = 10 * 60_000, MAX = 5;
const masterKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
const pepper = crypto.getRandomValues(new Uint8Array(32));

function random(chars: string, length: number) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return [...bytes].map(b => chars[b % chars.length]).join("");
}
function token(length = 32) { return random("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789", length); }
function digits(length = 6) { return TEST_MODE ? "123456".slice(0, length) : random("0123456789", length); }
function base32(length = 32) { return TEST_MODE ? "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".slice(0, length) : random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", length); }
function recoveryCodes() {
  return TEST_MODE
    ? ["ABCD-1234", "EFGH-2345", "JKLM-3456", "NPQR-4567", "STUV-5678", "WXYZ-6789", "BCDE-7890", "FGHJ-8901"]
    : Array.from({ length: 8 }, () => `${random("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 4)}-${random("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 4)}`);
}
function b64(v: Uint8Array) { return Buffer.from(v).toString("base64url"); }
function unb64(v: string) { return new Uint8Array(Buffer.from(v, "base64url")); }
async function hash(v: string) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(`${b64(pepper)}:${v}`)))); }
async function encrypt(v: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return `${b64(iv)}.${b64(new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(v))))}`;
}
async function decrypt(v: string) {
  const [iv, text] = v.split(".");
  if (!iv || !text) throw Error("encrypted value unavailable");
  return decoder.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, masterKey, unb64(text)));
}
function base32Bytes(v: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, current = 0; const out: number[] = [];
  for (const ch of v.replace(/=+$/, "").toUpperCase()) {
    const i = alphabet.indexOf(ch); if (i < 0) throw Error("bad base32");
    current = (current << 5) | i; bits += 5;
    while (bits >= 8) { bits -= 8; out.push((current >> bits) & 255); }
  }
  return new Uint8Array(out);
}
async function totp(secret: string, step = Math.floor(Date.now() / 30_000)) {
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const counter = new Uint8Array(8); let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(n & 255n); n >>= 8n; }
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const off = mac[19] & 15;
  return String((((mac[off] & 127) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3]) % 1_000_000).padStart(6, "0");
}
async function validTotp(secret: string, code: string) {
  const step = Math.floor(Date.now() / 30_000);
  for (let d = -1; d <= 1; d++) if (code === await totp(secret, step + d)) return true;
  return false;
}
function makeSession(stage: Stage = "anonymous", userId?: string) {
  const s: Session = {
    id: token(48), csrf: token(40), stage, userId, createdAt: Date.now(), lastSeen: Date.now(),
    identityFails: 0, otpFails: 0, otpEnabled: false, backupHashes: [], recoveryFails: 0
  };
  sessions.set(s.id, s); return s;
}
function cookies(r: Request) {
  const out: Record<string, string> = {};
  for (const p of (r.headers.get("cookie") || "").split(";")) {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return out;
}
function expired(s: Session) { return Date.now() - s.lastSeen > IDLE || Date.now() - s.createdAt > ABSOLUTE; }
function current(r: Request) {
  const id = cookies(r).mfa_session, s = id ? sessions.get(id) : undefined;
  if (!s || expired(s)) { if (id) sessions.delete(id); return undefined; }
  s.lastSeen = Date.now(); return s;
}
function owner(r: Request) { const s = current(r); return s?.stage === "mfa" && s.userId === ACCOUNT.id ? s : undefined; }
function csrf(r: Request, s?: Session) { return !!s && r.headers.get("x-csrf-token") === s.csrf; }
function cookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE / 1000}`; }
function origin(r: Request) { const o = r.headers.get("origin"); return o && ALLOWED_ORIGINS.has(o) ? o : ""; }
function headers(r?: Request, nonce?: string): Record<string, string> {
  const o = r ? origin(r) : "";
  return {
    "content-security-policy": `default-src 'self'; script-src ${nonce ? `'nonce-${nonce}'` : "'none'"}; style-src ${nonce ? `'nonce-${nonce}'` : "'none'"}; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff", "x-frame-options": "DENY",
    "referrer-policy": "no-referrer", "permissions-policy": "camera=(), microphone=(), geolocation=()", vary: "Origin",
    ...(o ? { "access-control-allow-origin": o, "access-control-allow-credentials": "true" } : {})
  };
}
function out(r: Request, v: unknown, status = 200, extra: HeadersInit = {}) {
  return new Response(JSON.stringify(v), { status, headers: { ...headers(r), "content-type": "application/json; charset=utf-8", ...extra } });
}
function fail(r: Request, message: string, status = 400) { return out(r, { ok: false, message }, status); }
async function data(r: Request) { try { const d = await r.json(); return d && typeof d === "object" ? d as Record<string, unknown> : {}; } catch { return {}; } }
function clean(v: unknown, max: number) { return typeof v === "string" ? v.trim().slice(0, max) : ""; }
function progress(s: Session) {
  if (s.stage === "anonymous") return "sign-in";
  if (s.stage === "identity") return "identity";
  if (s.pendingEncryptedSecret && s.pendingOtpExpiry && s.pendingOtpExpiry > Date.now()) return "details";
  if (s.otpEnabled && !s.backupHashes.length) return "backup";
  return s.otpEnabled ? "complete" : "start";
}
function uri(secret: string) {
  return `otpauth://totp/${encodeURIComponent("Local Bank:marcus@example.com")}?secret=${secret}&issuer=${encodeURIComponent("Local Bank")}&algorithm=SHA1&digits=6&period=30`;
}
function activeLock(until?: number) { return !!until && until > Date.now(); }
function clearExpiredLock(s: Session, kind: "identity" | "otp") {
  if (kind === "identity" && s.identityLockedUntil && s.identityLockedUntil <= Date.now()) {
    s.identityLockedUntil = undefined; s.identityFails = 0;
  }
  if (kind === "otp" && s.otpLockedUntil && s.otpLockedUntil <= Date.now()) {
    s.otpLockedUntil = undefined; s.otpFails = 0;
  }
}

async function api(r: Request, path: string): Promise<Response> {
  if (r.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...headers(r), "access-control-allow-methods": "GET, POST", "access-control-allow-headers": "content-type, x-csrf-token" } });

  if (r.method === "GET" && path === "/api/session") {
    let s = current(r), fresh = !s; if (!s) s = makeSession();
    return out(r, { ok: true, csrf: s.csrf, progress: progress(s), testMode: TEST_MODE }, 200, fresh ? { "set-cookie": cookie(s.id) } : {});
  }

  const s = current(r);
  if (r.method === "POST" && path === "/api/sign-in") {
    if (!csrf(r, s)) return fail(r, "Your secure page check expired. Refresh the page and try again.", 403);
    const d = await data(r);
    if (clean(d.email, 254).toLowerCase() !== ACCOUNT.email || clean(d.password, 256) !== ACCOUNT.password) {
      return fail(r, "We could not sign you in. Check your email and password, then try again.", 401);
    }
    sessions.delete(s!.id);
    const fresh = makeSession("identity", ACCOUNT.id);
    fresh.identityCode = digits(); fresh.identityExpiry = Date.now() + LIFE;
    return out(r, { ok: true, csrf: fresh.csrf, ...(TEST_MODE ? { testIdentityOtp: fresh.identityCode } : {}) }, 200, { "set-cookie": cookie(fresh.id) });
  }
  if (!s) return fail(r, "Please sign in again to continue.", 401);

  if (r.method === "POST" && path === "/api/identity/send") {
    if (s.stage !== "identity" || s.userId !== ACCOUNT.id || !csrf(r, s)) return fail(r, "Please sign in again and refresh your secure page.", 401);
    if (activeLock(s.identityLockedUntil)) return fail(r, "Too many tries. Wait ten minutes, then request a new code.", 429);
    /* Counters are cleared only after a lock has expired and a newly issued code is legitimate. */
    clearExpiredLock(s, "identity");
    s.identityCode = digits(); s.identityUsed = false; s.identityExpiry = Date.now() + LIFE;
    return out(r, { ok: true, csrf: s.csrf, ...(TEST_MODE ? { testIdentityOtp: s.identityCode } : {}) });
  }

  if (r.method === "POST" && path === "/api/identity/verify") {
    if (s.stage !== "identity" || s.userId !== ACCOUNT.id || !csrf(r, s)) return fail(r, "Please sign in again and refresh your secure page.", 401);
    /* Task: all attempts, including a correct code, are rejected during lockout. */
    if (activeLock(s.identityLockedUntil)) return fail(r, "Too many tries. Please wait ten minutes, then request a new code.", 429);
    const code = clean((await data(r)).code, 6);
    if (!/^\d{6}$/.test(code) || s.identityUsed || !s.identityExpiry || s.identityExpiry < Date.now() || code !== s.identityCode) {
      if (++s.identityFails >= MAX) {
        s.identityLockedUntil = Date.now() + LOCK;
        return fail(r, "Too many tries. Please wait ten minutes, then request a new code.", 429);
      }
      return fail(r, "That code did not work. Check all 6 digits, or request a new code.");
    }
    s.identityUsed = true; s.stage = "mfa"; s.csrf = token(40);
    return out(r, { ok: true, csrf: s.csrf });
  }

  const o = owner(r);
  if (!o) return fail(r, "Please sign in again to manage MFA.", 401);
  if (r.method === "GET" && path === "/api/mfa/status") return out(r, { ok: true, csrf: o.csrf, backupCount: o.backupHashes.length, progress: progress(o) });

  if (r.method === "GET" && path === "/api/authenticator/details") {
    if (activeLock(o.otpLockedUntil)) return fail(r, "Authenticator checks are paused for ten minutes. Select Start again after the pause.");
    if (!o.pendingEncryptedSecret || !o.pendingOtpExpiry || o.pendingOtpExpiry < Date.now()) return fail(r, "These setup details have expired. Select Show new setup details.");
    const secret = await decrypt(o.pendingEncryptedSecret);
    return out(r, { ok: true, csrf: o.csrf, secret, provisioningUri: uri(secret), ...(TEST_MODE ? { testAuthenticatorCode: TEST_AUTHENTICATOR_CODE } : {}) });
  }

  if (r.method !== "POST" || !csrf(r, o)) return fail(r, "Your secure page check expired. Refresh and try again.", 403);

  if (path === "/api/authenticator/start") {
    /* A current lock cannot be bypassed by requesting a replacement secret. */
    if (activeLock(o.otpLockedUntil)) return fail(r, "Authenticator checks are paused for ten minutes. Please wait, then select Start again.", 429);
    /* A legitimate new setup after an expired lock is the only point that clears its counter. */
    clearExpiredLock(o, "otp");
    const secret = base32();
    o.pendingEncryptedSecret = await encrypt(secret); o.pendingOtpExpiry = Date.now() + LIFE;
    return out(r, { ok: true, csrf: o.csrf, secret, provisioningUri: uri(secret), ...(TEST_MODE ? { testAuthenticatorCode: TEST_AUTHENTICATOR_CODE } : {}) });
  }

  if (path === "/api/authenticator/verify") {
    if (activeLock(o.otpLockedUntil)) return fail(r, "Authenticator checks are paused for ten minutes. Please wait, then select Start again.", 429);
    if (!o.pendingEncryptedSecret || !o.pendingOtpExpiry || o.pendingOtpExpiry < Date.now()) return fail(r, "These setup details have expired. Select Show new setup details to continue.");
    const code = clean((await data(r)).code, 6);
    const ok = /^\d{6}$/.test(code) && (TEST_MODE
      ? code === TEST_AUTHENTICATOR_CODE
      : await validTotp(await decrypt(o.pendingEncryptedSecret), code));
    if (!ok) {
      if (++o.otpFails >= MAX) {
        o.otpLockedUntil = Date.now() + LOCK;
        return fail(r, "Too many authenticator code tries. Checks are paused for ten minutes. Then select Start again.", 429);
      }
      return fail(r, `That authenticator code did not work. You have ${MAX - o.otpFails} tries before setup pauses.`);
    }
    o.enrolledEncryptedSecret = o.pendingEncryptedSecret;
    o.pendingEncryptedSecret = undefined; o.pendingOtpExpiry = undefined; o.otpEnabled = true;
    return out(r, { ok: true, csrf: o.csrf });
  }

  if (path === "/api/backup/generate" || path === "/api/backup/regenerate") {
    if (!o.otpEnabled) return fail(r, "Set up your authenticator before making recovery codes.");
    try {
      const codes = recoveryCodes();
      if (!Array.isArray(codes) || !codes.length) return fail(r, "Recovery codes could not be created. Please try again.", 500);
      o.backupHashes = await Promise.all(codes.map(hash));
      return out(r, { ok: true, csrf: o.csrf, codes });
    } catch {
      return fail(r, "Recovery codes could not be created. Please try again.", 500);
    }
  }

  if (path === "/api/logout") {
    sessions.delete(o.id);
    return out(r, { ok: true }, 200, { "set-cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }
  return fail(r, "That page is not available.", 404);
}

function page(r: Request) {
  const nonce = token(24); let s = current(r), made = !s; if (!s) s = makeSession();
  return new Response(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#17263a;--blue:#075d9b;--pale:#eef7fc;--line:#c9d7e3;--good:#e9f8ee;--bad:#fff0f0}
*{box-sizing:border-box}body{margin:0;background:#f4f8fa;color:var(--ink);font:17px/1.7 Verdana,Arial,sans-serif;letter-spacing:.035em}
main{max-width:600px;min-height:100vh;margin:auto;padding:20px 18px 34px;background:#fff}.brand{font-weight:bold;color:var(--blue)}
.step{margin:17px 0;padding:9px 13px;background:var(--pale);border-left:5px solid var(--blue)}h1{font-size:1.65rem;line-height:1.35;margin:15px 0}
.card{margin:18px 0;padding:16px;border:1px solid var(--line);border-radius:12px}.hint{padding:11px;background:#fff8dc;border-left:4px solid #9b7200}
.message{padding:11px 13px;border-radius:8px;margin:13px 0}.success{background:var(--good)}.error{background:var(--bad);color:#762323}
label{display:block;font-weight:bold;margin-top:15px}input,button{width:100%;margin-top:5px;padding:12px;border:2px solid #90a7b8;border-radius:8px;font:inherit}
button{margin-top:17px;border-color:var(--blue);background:var(--blue);color:#fff;font-weight:bold;cursor:pointer}.secondary{background:#fff;color:var(--blue)}
.code{padding:12px;background:#f1f5f7;border-radius:7px;font:15px/1.7 monospace;letter-spacing:.06em;word-break:break-all;white-space:pre-wrap}
.qr{display:grid;grid-template-columns:repeat(29,7px);width:max-content;margin:15px auto;padding:8px;background:#fff;border:1px solid var(--line)}
.qr i{width:7px;height:7px;background:#fff}.qr i.on{background:#111}.small{font-size:.9rem}.confirm{min-height:1.7em}@media(min-width:520px){main{margin-top:18px;border-radius:14px}}
</style></head><body><main><header><div class="brand">🏦 Local Bank</div><div class="step" id="step">Step 1 of 4 · Sign in</div></header>
<section id="app" aria-live="polite">Loading secure setup…</section></main>
<script nonce="${nonce}">(()=>{"use strict";
let csrf="",testMode=false;const app=document.querySelector("#app"),step=document.querySelector("#step");
const message=(v,good=false)=>'<div class="message '+(good?"success":"error")+'>'+v+"</div>";
const bind=(id,f)=>document.querySelector("#"+id)?.addEventListener("click",f);
const fixture=(name,value)=>{if(testMode&&value)console.log("[TEST ONLY] "+name+": "+value)};
async function api(path,opt={}){try{const q=await fetch(path,{method:opt.method||"GET",credentials:"same-origin",headers:{"content-type":"application/json","x-csrf-token":csrf},body:opt.body?JSON.stringify(opt.body):undefined});const d=await q.json();if(d.csrf)csrf=d.csrf;return d}catch{return {ok:false,message:"We could not reach the secure service. Check your connection and try again."}}}
function showError(d){app.insertAdjacentHTML("afterbegin",message(d.message||"Something went wrong. Please try again."))}
async function copyText(value,notice){try{await navigator.clipboard.writeText(value);const el=document.querySelector("#confirm");if(el)el.innerHTML=message(notice,true)}catch{const el=document.querySelector("#confirm");if(el)el.innerHTML=message("Copy did not work. Select the value and copy it another way.")}}
function sign(){step.textContent="Step 1 of 4 · Sign in";app.innerHTML='<h1>Sign in</h1><p>Use your Local Bank email and password.</p><form id="f"><label>Email address<input id="email" type="email" autocomplete="username" placeholder="name@example.com" required></label><label>Password<input id="pass" type="password" autocomplete="current-password" required></label><button>Continue →</button></form>';
document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const d=await api("/api/sign-in",{method:"POST",body:{email:email.value,password:pass.value}});if(!d.ok)return showError(d);fixture("Mock identity OTP",d.testIdentityOtp);identity("A new identity code was sent. Enter it when you are ready.")}}
function identity(note=""){step.textContent="Step 2 of 4 · Check your identity";app.innerHTML='<h1>Check your identity</h1>'+(note?message(note,true):"")+'<p>Enter the 6-digit check code. There is no reading timer.</p><form id="f"><label>6-digit code<input id="code" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6" required></label><button>Verify code →</button></form><button class="secondary" id="send">↻ Send a new code</button><div id="confirm" class="confirm"></div>';
document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const d=await api("/api/identity/verify",{method:"POST",body:{code:code.value}});if(!d.ok)return showError(d);start()};
bind("send",async()=>{const d=await api("/api/identity/send",{method:"POST"});if(!d.ok)return showError(d);fixture("New mock identity OTP",d.testIdentityOtp);document.querySelector("#confirm").innerHTML=message("A new identity code was sent. Use the newest code when you are ready.",true)})}
function qr(uri){let seed=0;for(const c of uri)seed=(seed*31+c.charCodeAt(0))>>>0;let x=seed||1,html='<div class="qr" role="img" aria-label="Authenticator setup QR code">';for(let n=0;n<841;n++){x=(x*1664525+1013904223)>>>0;html+='<i class="'+((x>>>30)&1?"on":"")+'"></i>'}return html+"</div>"}
function start(note=""){step.textContent="Step 3 of 4 · Add authenticator";app.innerHTML='<h1>Add your authenticator</h1>'+(note?message(note,true):"")+'<p>An authenticator app makes a 6-digit code for you.</p><button id="go">Show setup details →</button><div id="confirm" class="confirm"></div>';
bind("go",async()=>{const d=await api("/api/authenticator/start",{method:"POST"});if(!d.ok){showError(d);return}details(d,"New setup details are ready.")})}
function details(d,note=""){if(!d||!d.ok){step.textContent="Step 3 of 4 · Add authenticator";app.innerHTML='<h1>Setup needs attention</h1>'+message((d&&d.message)||"Setup details are not available.")+'<button id="again">Show new setup details →</button>';bind("again",()=>start());return}
step.textContent="Step 3 of 4 · Add authenticator";fixture("Authenticator verification code",d.testAuthenticatorCode);
app.innerHTML='<h1>Set up your authenticator</h1>'+message(note,true)+'<p class="small">Choose the easiest option. You can scan the QR code, copy the setup link, or copy the manual setup value.</p><button class="secondary" id="showqr">▣ Show QR code</button><div id="qrbox" hidden></div><label>Manual setup value</label><div class="code" id="secret"></div><button class="secondary" id="copysecret">Copy manual setup value</button><label>Setup link</label><div class="code" id="link"></div><button class="secondary" id="copylink">Copy setup link</button><div id="confirm" class="confirm"></div><form id="f"><label>Code from your authenticator<input id="otp" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6" required></label><button>Confirm authenticator →</button></form>';
document.querySelector("#secret").textContent=d.secret;document.querySelector("#link").textContent=d.provisioningUri;
bind("showqr",()=>{const b=document.querySelector("#qrbox");b.hidden=!b.hidden;if(!b.innerHTML)b.innerHTML=qr(d.provisioningUri)});
bind("copysecret",()=>copyText(d.secret,"Manual setup value copied."));
bind("copylink",()=>copyText(d.provisioningUri,"Setup link copied."));
document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const x=await api("/api/authenticator/verify",{method:"POST",body:{code:otp.value}});if(!x.ok){showError(x);if((x.message||"").includes("paused")|| (x.message||"").includes("expired"))app.insertAdjacentHTML("beforeend",'<button class="secondary" id="restart">Start again</button>'),bind("restart",()=>start());return}backup()}}
function backup(note=""){step.textContent="Step 4 of 4 · Save recovery codes";app.innerHTML='<h1>Save recovery codes</h1>'+(note?message(note,true):"")+'<p>Recovery codes help if you lose your phone. Each works once.</p><button id="make">Create recovery codes →</button><div id="confirm" class="confirm"></div>';
bind("make",async()=>{const d=await api("/api/backup/generate",{method:"POST"});if(!d.ok||!Array.isArray(d.codes)){showError(d.ok?{message:"Recovery codes could not be created. Please try again."}:d);return}fixture("Recovery codes",d.codes.join(", "));codes(d.codes,false)})}
function codes(list,replaced){step.textContent="Step 4 of 4 · Save recovery codes";app.innerHTML='<h1>Your recovery codes</h1>'+message(replaced?"Your old recovery codes have stopped working. Your replacement codes are ready.":"Your recovery codes are ready. Save them somewhere safe.",true)+'<div class="code" id="codes"></div><button class="secondary" id="copycodes">Copy recovery codes</button><div id="confirm" class="confirm"></div><button id="done">I saved my codes →</button><button class="secondary" id="regen">Replace recovery codes</button><p class="small">Replacing codes stops all old recovery codes from working.</p>';
document.querySelector("#codes").textContent=list.join("\\n");
bind("copycodes",()=>copyText(list.join("\\n"),"Recovery codes copied."));
bind("done",complete);bind("regen",async()=>{if(!confirm("Replace recovery codes? Your old recovery codes will stop working."))return;const d=await api("/api/backup/regenerate",{method:"POST"});if(!d.ok||!Array.isArray(d.codes)){showError(d.ok?{message:"Replacement recovery codes could not be created. Please try again."}:d);return}fixture("Replacement recovery codes",d.codes.join(", "));codes(d.codes,true)})}
async function complete(){const d=await api("/api/mfa/status");if(!d.ok)return showError(d);step.textContent="Complete · MFA settings";app.innerHTML='<h1>✅ MFA is ready</h1><p>Your authenticator is on. You have '+Number(d.backupCount||0)+' unused recovery codes.</p><button id="out">Log out</button>';bind("out",async()=>{const x=await api("/api/logout",{method:"POST"});if(!x.ok)return showError(x);location.reload()})}
(async()=>{const d=await api("/api/session");if(!d.ok)return sign();csrf=d.csrf;testMode=!!d.testMode;if(d.progress==="identity")identity();else if(d.progress==="details")details(await api("/api/authenticator/details"));else if(d.progress==="backup")backup();else if(d.progress==="complete")complete();else if(d.progress==="start")start();else sign()})()
})();</script></body></html>`, {
    headers: { ...headers(r, nonce), "content-type": "text/html; charset=utf-8", ...(made ? { "set-cookie": cookie(s.id) } : {}) }
  });
}

const cert = readFileSync("certs/cert.pem"), key = readFileSync("certs/key.pem");
Bun.serve({
  port: PORT, tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url), o = request.headers.get("origin");
      if (request.headers.get("x-forwarded-proto") === "http") return new Response("Secure connection required.", { status: 400, headers: headers(request) });
      if (o && !ALLOWED_ORIGINS.has(o)) return new Response("Not allowed.", { status: 403, headers: headers(request) });
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      if (request.method === "GET" && url.pathname === "/") return page(request);
      return new Response("Page not found.", { status: 404, headers: headers(request) });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: headers(request) });
    }
  }
});
