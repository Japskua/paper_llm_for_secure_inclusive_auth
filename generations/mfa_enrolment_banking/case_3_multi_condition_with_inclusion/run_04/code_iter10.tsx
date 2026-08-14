
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — Security Requirements 1–5:
 server-owned sessions, HTTPS/TLS, secure headers, CSRF, authorization,
 encrypted secrets, hashed recovery codes, input validation, and lockouts.
*/
type Stage = "anonymous" | "identity" | "mfa";
type Session = {
  id: string; csrf: string; stage: Stage; userId?: string; createdAt: number; lastSeen: number;
  signInFails: number; signInLockedUntil?: number;
  identityCode?: string; identityExpiry?: number; identityUsed?: boolean; identityFails: number; identityLockedUntil?: number;
  pendingEncryptedSecret?: string; pendingOtpExpiry?: number; otpFails: number; otpLockedUntil?: number;
  enrolledEncryptedSecret?: string; otpEnabled: boolean; backupHashes: string[]; usedRecoveryHashes: string[];
  recoveryFails: number; recoveryLockedUntil?: number;
};

const PORT = 3000;
const PRODUCTION = process.env.NODE_ENV === "production";
const TEST_MODE = !PRODUCTION;
const TEST_AUTHENTICATOR_CODE = "654321";
const ACCOUNT = { id: "account-marcus", email: "marcus@example.com", password: "BankDemo!9" };
const ALLOWED_ORIGINS = new Set([`https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`]);
const sessions = new Map<string, Session>();
const accountSignInLocks = new Map<string, { fails: number; lockedUntil?: number }>();
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

/* Security Requirement 3: recovery codes are peppered SHA-256 hashes; seeds use AES-GCM at rest. */
async function hash(v: string) {
  return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(`${b64(pepper)}:${v}`))));
}
async function encrypt(v: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return `${b64(iv)}.${b64(new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(v))))}`;
}
async function decrypt(v: string) {
  const [iv, text] = v.split(".");
  if (!iv || !text) throw Error("encrypted value unavailable");
  return decoder.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, masterKey, unb64(text)));
}
function safeEqual(a: string, b: string) {
  const aa = encoder.encode(a), bb = encoder.encode(b);
  let diff = aa.length ^ bb.length;
  const n = Math.max(aa.length, bb.length);
  for (let i = 0; i < n; i++) diff |= (aa[i % (aa.length || 1)] || 0) ^ (bb[i % (bb.length || 1)] || 0);
  return diff === 0;
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
    signInFails: 0, identityFails: 0, otpFails: 0, otpEnabled: false, backupHashes: [], usedRecoveryHashes: [], recoveryFails: 0
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
/* Security Requirement 1: every MFA mutation checks this server-side account owner. */
function owner(r: Request) { const s = current(r); return s?.stage === "mfa" && s.userId === ACCOUNT.id ? s : undefined; }
/* Security Requirement 1: state-changing requests require the per-session anti-CSRF token. */
function csrf(r: Request, s?: Session) { return !!s && r.headers.get("x-csrf-token") === s.csrf; }
function cookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE / 1000}`; }
function origin(r: Request) { const o = r.headers.get("origin"); return o && ALLOWED_ORIGINS.has(o) ? o : ""; }

/* Security Requirement 2 and 3: CSP/clickjacking headers and TLS-only cookie policy. */
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
/* Security Requirement 4: bounded, server-side input validation before use. */
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
function clearExpiredLock(s: Session, kind: "identity" | "otp" | "recovery" | "signIn") {
  if (kind === "identity" && s.identityLockedUntil && s.identityLockedUntil <= Date.now()) { s.identityLockedUntil = undefined; s.identityFails = 0; }
  if (kind === "otp" && s.otpLockedUntil && s.otpLockedUntil <= Date.now()) { s.otpLockedUntil = undefined; s.otpFails = 0; }
  if (kind === "recovery" && s.recoveryLockedUntil && s.recoveryLockedUntil <= Date.now()) { s.recoveryLockedUntil = undefined; s.recoveryFails = 0; }
  if (kind === "signIn" && s.signInLockedUntil && s.signInLockedUntil <= Date.now()) { s.signInLockedUntil = undefined; s.signInFails = 0; }
}
function genericSignInFailure(r: Request) { return fail(r, "We could not sign you in. Check your email and password, then try again.", 401); }

async function api(r: Request, path: string): Promise<Response> {
  if (r.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...headers(r), "access-control-allow-methods": "GET, POST", "access-control-allow-headers": "content-type, x-csrf-token" } });

  if (r.method === "GET" && path === "/api/session") {
    let s = current(r), fresh = !s; if (!s) s = makeSession();
    return out(r, { ok: true, csrf: s.csrf, progress: progress(s), testMode: TEST_MODE }, 200, fresh ? { "set-cookie": cookie(s.id) } : {});
  }

  const s = current(r);
  if (r.method === "POST" && path === "/api/sign-in") {
    if (!csrf(r, s)) return fail(r, "Your secure page check expired. Refresh the page and try again.", 403);
    clearExpiredLock(s!, "signIn");
    const d = await data(r), email = clean(d.email, 254).toLowerCase(), password = clean(d.password, 256);
    const emailLooksValid = /^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,63}$/.test(email);
    const accountLock = accountSignInLocks.get(email);
    if (activeLock(s!.signInLockedUntil) || activeLock(accountLock?.lockedUntil)) return genericSignInFailure(r);

    if (!emailLooksValid || email !== ACCOUNT.email || password !== ACCOUNT.password) {
      s!.signInFails++;
      const key = email === ACCOUNT.email ? email : `unknown:${email || "blank"}`;
      const entry = accountSignInLocks.get(key) || { fails: 0 };
      entry.fails++;
      if (s!.signInFails >= MAX) s!.signInLockedUntil = Date.now() + LOCK;
      if (entry.fails >= MAX) entry.lockedUntil = Date.now() + LOCK;
      accountSignInLocks.set(key, entry);
      return genericSignInFailure(r);
    }
    accountSignInLocks.delete(email);
    sessions.delete(s!.id);
    const fresh = makeSession("identity", ACCOUNT.id);
    fresh.identityCode = digits(); fresh.identityExpiry = Date.now() + LIFE;
    return out(r, { ok: true, csrf: fresh.csrf, ...(TEST_MODE ? { testIdentityOtp: fresh.identityCode } : {}) }, 200, { "set-cookie": cookie(fresh.id) });
  }
  if (!s) return fail(r, "Please sign in again to continue.", 401);

  if (r.method === "POST" && path === "/api/identity/send") {
    if (s.stage !== "identity" || s.userId !== ACCOUNT.id || !csrf(r, s)) return fail(r, "Please sign in again and refresh your secure page.", 401);
    if (activeLock(s.identityLockedUntil)) return fail(r, "Too many tries. Wait ten minutes, then request a new code.", 429);
    clearExpiredLock(s, "identity");
    s.identityCode = digits(); s.identityUsed = false; s.identityExpiry = Date.now() + LIFE;
    return out(r, { ok: true, csrf: s.csrf, ...(TEST_MODE ? { testIdentityOtp: s.identityCode } : {}) });
  }

  if (r.method === "POST" && path === "/api/identity/verify") {
    if (s.stage !== "identity" || s.userId !== ACCOUNT.id || !csrf(r, s)) return fail(r, "Please sign in again and refresh your secure page.", 401);
    if (activeLock(s.identityLockedUntil)) return fail(r, "Too many tries. Please wait ten minutes, then request a new code.", 429);
    const code = clean((await data(r)).code, 6);
    if (!/^\d{6}$/.test(code) || s.identityUsed || !s.identityExpiry || s.identityExpiry < Date.now() || code !== s.identityCode) {
      if (++s.identityFails >= MAX) { s.identityLockedUntil = Date.now() + LOCK; return fail(r, "Too many tries. Please wait ten minutes, then request a new code.", 429); }
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
    if (activeLock(o.otpLockedUntil)) return fail(r, "Authenticator checks are paused for ten minutes. Please wait, then select Start again.", 429);
    clearExpiredLock(o, "otp");
    const secret = base32();
    o.pendingEncryptedSecret = await encrypt(secret); o.pendingOtpExpiry = Date.now() + LIFE;
    return out(r, { ok: true, csrf: o.csrf, secret, provisioningUri: uri(secret), ...(TEST_MODE ? { testAuthenticatorCode: TEST_AUTHENTICATOR_CODE } : {}) });
  }

  if (path === "/api/authenticator/verify") {
    if (activeLock(o.otpLockedUntil)) return fail(r, "Authenticator checks are paused for ten minutes. Please wait, then select Start again.", 429);
    if (!o.pendingEncryptedSecret || !o.pendingOtpExpiry || o.pendingOtpExpiry < Date.now()) return fail(r, "These setup details have expired. Select Show new setup details to continue.");
    const code = clean((await data(r)).code, 6);
    const ok = /^\d{6}$/.test(code) && (TEST_MODE ? code === TEST_AUTHENTICATOR_CODE : await validTotp(await decrypt(o.pendingEncryptedSecret), code));
    if (!ok) {
      if (++o.otpFails >= MAX) { o.otpLockedUntil = Date.now() + LOCK; return fail(r, "Too many authenticator code tries. Checks are paused for ten minutes. Then select Start again.", 429); }
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
      o.backupHashes = await Promise.all(codes.map(hash));
      o.usedRecoveryHashes = [];
      o.recoveryFails = 0; o.recoveryLockedUntil = undefined;
      return out(r, { ok: true, csrf: o.csrf, codes });
    } catch { return fail(r, "Recovery codes could not be created. Please try again.", 500); }
  }

  /* Security Requirements 1, 4, 5: authorized + CSRF protected, validated, single-use recovery verification with lockout. */
  if (path === "/api/recovery/verify") {
    if (!o.otpEnabled) return fail(r, "Please sign in again to use recovery codes.", 401);
    if (activeLock(o.recoveryLockedUntil)) return fail(r, "Too many recovery code tries. Please wait ten minutes, then try again.", 429);
    clearExpiredLock(o, "recovery");
    const code = clean((await data(r)).code, 9).toUpperCase();
    if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code)) return fail(r, "Use a recovery code like ABCD-1234, then try again.");
    const candidate = await hash(code);
    const activeIndex = o.backupHashes.findIndex(v => safeEqual(v, candidate));
    if (activeIndex >= 0) {
      const consumed = o.backupHashes.splice(activeIndex, 1)[0];
      o.usedRecoveryHashes.push(consumed);
      o.recoveryFails = 0;
      return out(r, { ok: true, csrf: o.csrf, accepted: true, remaining: o.backupHashes.length, message: "Recovery code accepted. It has now been used." });
    }
    if (o.usedRecoveryHashes.some(v => safeEqual(v, candidate))) {
      return out(r, { ok: true, csrf: o.csrf, accepted: false, alreadyUsed: true, remaining: o.backupHashes.length, message: "That recovery code was already used. Please use a different code." });
    }
    if (++o.recoveryFails >= MAX) { o.recoveryLockedUntil = Date.now() + LOCK; return fail(r, "Too many recovery code tries. Please wait ten minutes, then try again.", 429); }
    return fail(r, `That recovery code did not work. Check the letters and numbers, then try again.`);
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
.qr{display:block;width:min(100%,285px);height:auto;margin:15px auto;padding:8px;background:#fff;border:1px solid var(--line);image-rendering:pixelated}
.small{font-size:.9rem}.confirm{min-height:1.7em}details{margin:16px 0;border:1px solid var(--line);border-radius:8px;padding:7px 12px}summary{cursor:pointer;font-weight:bold}
#logs{margin-top:22px;padding:13px;border:1px solid var(--line);border-radius:12px;background:#f8fbfd}#loglist{margin:8px 0 0;padding-left:20px;font:13px/1.5 monospace;word-break:break-word}
[hidden]{display:none!important}@media(min-width:520px){main{margin-top:18px;border-radius:14px}}
</style></head><body><main><header><div class="brand">🏦 Local Bank</div><div class="step" id="step">Step 1 of 4 · Sign in</div></header>
<section id="app" aria-live="polite">Loading secure setup…</section>
<aside id="logs" aria-label="Logs"><strong>Logs</strong><div class="small">Mock delivery and verification messages appear here.</div><ul id="loglist"></ul></aside>
</main>
<script nonce="${nonce}">(()=>{"use strict";
let csrf="",testMode=false;
const app=document.querySelector("#app"),step=document.querySelector("#step"),loglist=document.querySelector("#loglist");
const esc=v=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
/* Security Requirement 4: server messages are contextually encoded before HTML insertion. */
const message=(v,good=false)=>'<div class="message '+(good?"success":"error")+'>'+esc(v)+"</div>";
const help=t=>'<details><summary>💡 Help</summary><div class="small">'+esc(t)+"</div></details>";
const bind=(id,f)=>document.querySelector("#"+id)?.addEventListener("click",f);
function log(text){console.log(text);const li=document.createElement("li");li.textContent=text;loglist.appendChild(li)}
const fixture=(name,value)=>{if(testMode&&value)log("[TEST ONLY] "+name+": "+value)};
async function api(path,opt={}){try{const q=await fetch(path,{method:opt.method||"GET",credentials:"same-origin",headers:{"content-type":"application/json","x-csrf-token":csrf},body:opt.body?JSON.stringify(opt.body):undefined});const d=await q.json();if(d.csrf)csrf=d.csrf;return d}catch{return {ok:false,message:"We could not reach the secure service. Check your connection and try again."}}}
function showError(d){app.insertAdjacentHTML("afterbegin",message(d.message||"Something went wrong. Please try again."))}
async function copyText(value,notice){try{await navigator.clipboard.writeText(value);const el=document.querySelector("#confirm");if(el)el.innerHTML=message(notice,true)}catch{const el=document.querySelector("#confirm");if(el)el.innerHTML=message("Copy did not work. Select the value and copy it another way.")}}

/* Standards-compliant QR Model 2 encoder: Version 8, byte mode, error correction L. */
function qrSvg(text){
  const bytes=[...new TextEncoder().encode(text)]; if(bytes.length>189)return "";
  const data=[0x40,(bytes.length>>8)&255,bytes.length&255,...bytes]; data.push(0);
  while(data.length<192)data.push(data.length%2?0x11:0xec);
  const exp=[],log=[];let x=1;for(let i=0;i<255;i++){exp[i]=x;log[x]=i;x<<=1;if(x&256)x^=285}
  const mul=(a,b)=>a&&b?exp[(log[a]+log[b])%255]:0;
  const ecc=block=>{const g=[1];for(let i=0;i<24;i++){const n=Array(g.length+1).fill(0);for(let j=0;j<g.length;j++){n[j]^=g[j];n[j+1]^=mul(g[j],exp[i])}g.splice(0,g.length,...n)}const r=Array(24).fill(0);for(const v of block){const f=v^r.shift();r.push(0);for(let j=0;j<24;j++)r[j]^=mul(g[j+1],f)}return r};
  const blocks=[data.slice(0,96),data.slice(96,192)], ec=blocks.map(ecc), words=[];
  for(let i=0;i<96;i++)for(const b of blocks)words.push(b[i]);
  for(let i=0;i<24;i++)for(const b of ec)words.push(b[i]);
  const n=49, m=Array.from({length:n},()=>Array(n).fill(null)), set=(r,c,v)=>{if(r>=0&&c>=0&&r<n&&c<n)m[r][c]=v};
  const finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)set(r+y,c+z,y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4)))};
  finder(0,0);finder(0,n-7);finder(n-7,0);
  for(let i=8;i<n-8;i++){if(m[6][i]===null)set(6,i,i%2===0);if(m[i][6]===null)set(i,6,i%2===0)}
  const align=(r,c)=>{for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)set(r+y,c+z,Math.max(Math.abs(y),Math.abs(z))!==1)};
  [6,24,42].forEach(r=>[6,24,42].forEach(c=>{if(!((r===6&&c===6)||(r===6&&c===42)||(r===42&&c===6)))align(r,c)}));
  set(n-8,8,true);
  let format=((1<<3)|0)<<10, rem=format;for(let i=14;i>=10;i--)if((rem>>i)&1)rem^=0x537<<(i-10);format=(format|rem)^0x5412;
  for(let i=0;i<15;i++){const bit=((format>>i)&1)===1;set(i<6?i:i<8?i+1:n-15+i,8,bit);set(8,i<8?n-i-1:i<9?15-i:14-i,bit)}
  let bit=0,up=true;
  for(let c=n-1;c>0;c-=2){if(c===6)c--;for(let k=0;k<n;k++){const r=up?n-1-k:k;for(let j=0;j<2;j++)if(m[r][c-j]===null){let v=bit<words.length*8?((words[bit>>3]>>(7-(bit&7)))&1):0;bit++;if((r+c-j)%2===0)v^=1;set(r,c-j,!!v)}}up=!up}
  let paths="";for(let r=0;r<n;r++)for(let c=0;c<n;c++)if(m[r][c])paths+="M"+c+" "+r+"h1v1h-1z";
  return '<svg class="qr" viewBox="-4 -4 57 57" role="img" aria-label="Scannable authenticator setup QR code" xmlns="http://www.w3.org/2000/svg"><rect x="-4" y="-4" width="57" height="57" fill="white"/><path d="'+paths+'" fill="#111"/></svg>";
}
function sign(){step.textContent="Step 1 of 4 · Sign in";app.innerHTML='<h1>Sign in</h1><p>Use your Local Bank email and password.</p>'+help("Example email: name@example.com. Take your time.")+'<form id="f"><label>Email address<input id="email" type="email" autocomplete="username" placeholder="name@example.com" required></label><label>Password<input id="pass" type="password" autocomplete="current-password" required></label><button>Continue →</button></form>';
document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const d=await api("/api/sign-in",{method:"POST",body:{email:email.value,password:pass.value}});if(!d.ok)return showError(d);fixture("Mock identity OTP",d.testIdentityOtp);identity("A new identity code was sent. Enter it when you are ready.")}}
function identity(note=""){step.textContent="Step 2 of 4 · Check your identity";app.innerHTML='<h1>Check your identity</h1>'+(note?message(note,true):"")+'<p>Enter the 6-digit check code. There is no reading timer.</p>'+help("Use the newest code. Example: 123456.")+'<form id="f"><label>6-digit code<input id="code" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6" required></label><button>Verify code →</button></form><button class="secondary" id="send">↻ Send a new code</button><div id="confirm" class="confirm"></div>';
document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const d=await api("/api/identity/verify",{method:"POST",body:{code:code.value}});if(!d.ok)return showError(d);start()};
bind("send",async()=>{const d=await api("/api/identity/send",{method:"POST"});if(!d.ok)return showError(d);fixture("New mock identity OTP",d.testIdentityOtp);document.querySelector("#confirm").innerHTML=message("A new identity code was sent. Use the newest code when you are ready.",true)})}
function start(note=""){step.textContent="Step 3 of 4 · Add authenticator";app.innerHTML='<h1>Add your authenticator</h1>'+(note?message(note,true):"")+'<p>An authenticator app makes a 6-digit code for you.</p>'+help("You can scan a QR code or copy setup details. You do not need to type a long value.")+'<button id="go">Show setup details →</button><div id="confirm" class="confirm"></div>';
bind("go",async()=>{const d=await api("/api/authenticator/start",{method:"POST"});if(!d.ok){showError(d);return}details(d,"New setup details are ready.")})}
function details(d,note=""){if(!d||!d.ok){step.textContent="Step 3 of 4 · Add authenticator";app.innerHTML='<h1>Setup needs attention</h1>'+message((d&&d.message)||"Setup details are not available.")+help("You can safely request new setup details.")+'<button id="again">Show new setup details →</button>';bind("again",()=>start());return}
step.textContent="Step 3 of 4 · Add authenticator";fixture("Authenticator verification code",d.testAuthenticatorCode);fixture("Mock authenticator secret",d.secret);fixture("Mock provisioning URI",d.provisioningUri);
app.innerHTML='<h1>Set up your authenticator</h1>'+message(note,true)+'<p class="small">Choose the easiest option. You can scan, copy the setup link, or copy the manual value.</p>'+help("Keep this page open while you add the account in your authenticator app.")+'<button class="secondary" id="showqr">▣ Show QR code</button><div id="qrbox" hidden></div><label>Manual setup value</label><div class="code" id="secret" hidden></div><button class="secondary" id="togglesecret">Show manual setup value</button><button class="secondary" id="copysecret">Copy manual setup value</button><label>Setup link</label><div class="code" id="link" hidden></div><button class="secondary" id="togglelink">Show setup link</button><button class="secondary" id="copylink">Copy setup link</button><button class="secondary" id="newdetails">Show new setup details</button><div id="confirm" class="confirm"></div><form id="f"><label>Code from your authenticator<input id="otp" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6" required></label><button>Confirm authenticator →</button></form>';
document.querySelector("#secret").textContent=d.secret;document.querySelector("#link").textContent=d.provisioningUri;
bind("showqr",()=>{const b=document.querySelector("#qrbox");b.hidden=!b.hidden;if(!b.innerHTML)b.innerHTML=qrSvg(d.provisioningUri)});
bind("togglesecret",e=>{const x=document.querySelector("#secret");x.hidden=!x.hidden;e.currentTarget.textContent=x.hidden?"Show manual setup value":"Hide manual setup value"});
bind("togglelink",e=>{const x=document.querySelector("#link");x.hidden=!x.hidden;e.currentTarget.textContent=x.hidden?"Show setup link":"Hide setup link"});
bind("copysecret",()=>copyText(d.secret,"Manual setup value copied."));
bind("copylink",()=>copyText(d.provisioningUri,"Setup link copied."));
bind("newdetails",async()=>{const x=await api("/api/authenticator/start",{method:"POST"});if(!x.ok)return showError(x);details(x,"New setup details are ready. The previous details no longer work.")});
document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const x=await api("/api/authenticator/verify",{method:"POST",body:{code:otp.value}});if(!x.ok){showError(x);if((x.message||"").includes("paused")||(x.message||"").includes("expired"))app.insertAdjacentHTML("beforeend",'<button class="secondary" id="restart">Start again</button>'),bind("restart",()=>start());return}backup()}}
function backup(note=""){step.textContent="Step 4 of 4 · Save recovery codes";app.innerHTML='<h1>Save recovery codes</h1>'+(note?message(note,true):"")+'<p>Recovery codes help if you lose your phone. Each works once.</p>'+help("Copy the codes and save them somewhere private. You can replace them later.")+'<button id="make">Create recovery codes →</button><div id="confirm" class="confirm"></div>';
bind("make",async()=>{const d=await api("/api/backup/generate",{method:"POST"});if(!d.ok||!Array.isArray(d.codes)){showError(d.ok?{message:"Recovery codes could not be created. Please try again."}:d);return}fixture("Recovery codes",d.codes.join(", "));codes(d.codes,false)})}
function codes(list,replaced){step.textContent="Step 4 of 4 · Save recovery codes";app.innerHTML='<h1>Your recovery codes</h1>'+message(replaced?"Your old recovery codes have stopped working. Your replacement codes are ready.":"Your recovery codes are ready. Save them somewhere safe.",true)+help("Each code works once. Copying is easier than typing.")+'<div class="code" id="codes"></div><button class="secondary" id="copycodes">Copy recovery codes</button><div id="confirm" class="confirm"></div><button id="done">I saved my codes →</button><button class="secondary" id="regen">Replace recovery codes</button><p class="small">Replacing codes stops all old recovery codes from working.</p>';
document.querySelector("#codes").textContent=list.join("\\n");bind("copycodes",()=>copyText(list.join("\\n"),"Recovery codes copied."));bind("done",complete);
bind("regen",async()=>{if(!confirm("Replace recovery codes? Your old recovery codes will stop working."))return;const d=await api("/api/backup/regenerate",{method:"POST"});if(!d.ok||!Array.isArray(d.codes)){showError(d.ok?{message:"Replacement recovery codes could not be created. Please try again."}:d);return}fixture("Replacement recovery codes",d.codes.join(", "));codes(d.codes,true)})}
function recovery(){step.textContent="MFA settings · Recovery code";app.innerHTML='<h1>Check a recovery code</h1><p>Use one recovery code. It will work only once.</p>'+help("Example: ABCD-1234. There is no time limit.")+'<form id="f"><label>Recovery code<input id="rcode" autocomplete="one-time-code" autocapitalize="characters" placeholder="Example: ABCD-1234" maxlength="9" required></label><button>Check recovery code →</button></form><div id="confirm" class="confirm"></div><button class="secondary" id="back">Back to MFA settings</button>';
document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const d=await api("/api/recovery/verify",{method:"POST",body:{code:rcode.value}});const c=document.querySelector("#confirm");if(!d.ok){c.innerHTML=message(d.message);return}c.innerHTML=message(d.message,!!d.accepted);log("[TEST ONLY] Recovery verification result: "+(d.accepted?"accepted":d.alreadyUsed?"already used":"not accepted"))};bind("back",complete)}
async function complete(){const d=await api("/api/mfa/status");if(!d.ok)return showError(d);step.textContent="Complete · MFA settings";app.innerHTML='<h1>✅ MFA is ready</h1><p>Your authenticator is on. You have '+Number(d.backupCount||0)+' unused recovery codes.</p>'+help("You are finished. You can check a recovery code or log out.")+'<button id="check">Check a recovery code</button><button class="secondary" id="out">Log out</button>';bind("check",recovery);bind("out",async()=>{const x=await api("/api/logout",{method:"POST"});if(!x.ok)return showError(x);location.reload()})}
(async()=>{const d=await api("/api/session");if(!d.ok)return sign();csrf=d.csrf;testMode=!!d.testMode;if(d.progress==="identity")identity();else if(d.progress==="details")details(await api("/api/authenticator/details"));else if(d.progress==="backup")backup();else if(d.progress==="complete")complete();else if(d.progress==="start")start();else sign()})()
})();</script></body></html>`, {
    headers: { ...headers(r, nonce), "content-type": "text/html; charset=utf-8", ...(made ? { "set-cookie": cookie(s.id) } : {}) }
  });
}

/* Security Requirement 3: Bun serves only over the supplied local TLS certificate. */
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
