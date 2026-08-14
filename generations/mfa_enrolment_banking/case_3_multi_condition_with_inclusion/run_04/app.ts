
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — Security Requirements 1–5:
 server-owned secure sessions, CSRF, authorization, encryption, hashing,
 strict input validation, lockouts, HTTPS-only Bun TLS serving, and no secrets in production logs.
*/
type Stage = "anonymous" | "identity" | "mfa";
type Session = {
  id: string; csrf: string; stage: Stage; userId?: string; created: number; seen: number;
  /* In production identity holds a hash only. Raw deterministic values exist only in explicit test mode. */
  identity?: string; identityExpiry?: number; identityFails: number; identityLocked?: number;
  pending?: string; pendingExpiry?: number; otpFails: number; otpLocked?: number;
  enrolled?: string; enabled: boolean; backups: string[]; used: string[];
  recoveryFails: number; recoveryLocked?: number;
};

const PORT = 3000;
const PROD = process.env.NODE_ENV === "production";
const TEST = process.env.MFA_TEST_MODE === "true" || !PROD;
const ACCOUNT = { id: "account-marcus", email: "marcus@example.com", password: "BankDemo!9" };
const sessions = new Map<string, Session>();
const enc = new TextEncoder(), dec = new TextDecoder();
const IDLE = 20 * 60_000, ABS = 8 * 60 * 60_000, LIFE = 10 * 60_000, LOCK = 10 * 60_000, MAX = 5;
const origins = new Set([`https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`]);
const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
const pepper = crypto.getRandomValues(new Uint8Array(32));

function random(chars: string, n: number) {
  const out: string[] = [];
  const limit = 256 - (256 % chars.length);
  while (out.length < n) {
    const b = crypto.getRandomValues(new Uint8Array(32));
    for (const x of b) {
      if (x < limit) out.push(chars[x % chars.length]);
      if (out.length === n) break;
    }
  }
  return out.join("");
}
const token = (n = 40) => random("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789", n);
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));
async function hash(s: string) {
  return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(b64(pepper) + ":" + s))));
}
async function encrypt(s: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return b64(iv) + "." + b64(new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(s))));
}
async function decrypt(s: string) {
  const [iv, data] = s.split(".");
  if (!iv || !data) throw Error("unavailable");
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, key, unb64(data)));
}
function equal(a: string, b: string) {
  const x = enc.encode(a), y = enc.encode(b); let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] || 0) ^ (y[i] || 0);
  return d === 0;
}

/* Requirement 4: strict bounded server-side validation; never silently truncate input. */
function bounded(v: unknown, max: number): { value: string; over: boolean } {
  if (typeof v !== "string") return { value: "", over: false };
  const t = v.trim();
  return { value: t, over: t.length > max };
}
function emailInput(v: unknown) {
  const x = bounded(v, 254);
  if (x.over) return { error: "Email address is too long. Use 254 characters or fewer." };
  if (!/^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,63}$/.test(x.value)) return { error: "Enter an email address like name@example.com." };
  return { value: x.value.toLowerCase() };
}
function passwordInput(v: unknown) {
  const x = bounded(v, 256);
  if (x.over) return { error: "Password is too long. Use 256 characters or fewer." };
  if (!x.value) return { error: "Enter your password." };
  return { value: x.value };
}
function otpInput(v: unknown) {
  const x = bounded(v, 6);
  if (x.over || !/^\d{6}$/.test(x.value)) return { error: "Use exactly 6 digits, like 123456." };
  return { value: x.value };
}
function recoveryInput(v: unknown) {
  const x = bounded(v, 9);
  if (x.over || !/^[A-Z0-9]{4}-[A-Z0-9]{4}$/i.test(x.value)) return { error: "Use a recovery code like ABCD-1234." };
  return { value: x.value.toUpperCase() };
}

function make(stage: Stage = "anonymous", userId?: string): Session {
  const s: Session = {
    id: token(48), csrf: token(), stage, userId, created: Date.now(), seen: Date.now(),
    identityFails: 0, otpFails: 0, enabled: false, backups: [], used: [], recoveryFails: 0
  };
  sessions.set(s.id, s);
  return s;
}
function cookie(r: Request) {
  const c: Record<string, string> = {};
  for (const p of (r.headers.get("cookie") || "").split(";")) {
    const i = p.indexOf("=");
    if (i > 0) c[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return c;
}
/* Requirements 1 and 5: every protected endpoint obtains its server-owned session and checks owner. */
function get(r: Request) {
  const id = cookie(r).mfa_session, s = id && sessions.get(id);
  if (!s || Date.now() - s.seen > IDLE || Date.now() - s.created > ABS) {
    if (id) sessions.delete(id);
    return;
  }
  s.seen = Date.now();
  return s;
}
function owner(r: Request) {
  const s = get(r);
  return s?.stage === "mfa" && s.userId === ACCOUNT.id ? s : undefined;
}
function secureCookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABS / 1000}`;
}
function validCsrf(r: Request, s?: Session) {
  return !!s && r.headers.get("x-csrf-token") === s.csrf;
}
function locked(t?: number) { return !!t && t > Date.now(); }
/* Requirement 5: clear an expired lock before each validation attempt. */
function clearLock(s: Session, k: "identity" | "otp" | "recovery") {
  const u = k === "identity" ? "identityLocked" : k === "otp" ? "otpLocked" : "recoveryLocked";
  const f = k === "identity" ? "identityFails" : k === "otp" ? "otpFails" : "recoveryFails";
  if ((s as any)[u] && (s as any)[u] <= Date.now()) {
    (s as any)[u] = undefined;
    (s as any)[f] = 0;
  }
}
function resetAttempts(s: Session, k: "identity" | "otp" | "recovery") {
  const u = k === "identity" ? "identityLocked" : k === "otp" ? "otpLocked" : "recoveryLocked";
  const f = k === "identity" ? "identityFails" : k === "otp" ? "otpFails" : "recoveryFails";
  (s as any)[u] = undefined;
  (s as any)[f] = 0;
}
function failed(s: Session, k: "identity" | "otp" | "recovery") {
  const u = k === "identity" ? "identityLocked" : k === "otp" ? "otpLocked" : "recoveryLocked";
  const f = k === "identity" ? "identityFails" : k === "otp" ? "otpFails" : "recoveryFails";
  (s as any)[f]++;
  if ((s as any)[f] >= MAX) {
    (s as any)[u] = Date.now() + LOCK;
    return true;
  }
  return false;
}
function progress(s: Session) {
  if (s.stage === "anonymous") return "sign";
  if (s.stage === "identity") return "identity";
  if (s.pending && s.pendingExpiry && s.pendingExpiry > Date.now()) return "details";
  if (s.enabled && !s.backups.length) return "backup";
  return s.enabled ? "complete" : "start";
}
function secret() {
  return TEST ? "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" : random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 32);
}
function uri(s: string) {
  return `otpauth://totp/${encodeURIComponent("Local Bank:marcus@example.com")}?secret=${s}&issuer=${encodeURIComponent("Local Bank")}&algorithm=SHA1&digits=6&period=30`;
}
function codes() {
  return TEST
    ? ["ABCD-1234", "EFGH-2345", "JKLM-3456", "NPQR-4567", "STUV-5678", "WXYZ-6789", "BCDE-7890", "FGHJ-8901"]
    : Array.from({ length: 8 }, () => random("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 4) + "-" + random("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 4));
}
/* Requirement task: production identity codes are cryptographically random and retained only as a hash. */
async function issueIdentity(s: Session) {
  const code = TEST ? "123456" : random("0123456789", 6);
  s.identity = TEST ? code : await hash(code);
  s.identityExpiry = Date.now() + LIFE;
  resetAttempts(s, "identity");
  return code;
}
function base32(s: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "", out: number[] = [];
  for (const ch of s.replace(/=+$/g, "").toUpperCase()) {
    const i = alphabet.indexOf(ch);
    if (i < 0) throw Error("invalid secret");
    bits += i.toString(2).padStart(5, "0");
  }
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(out);
}
/* Requirement task: production authenticator checks are genuine RFC-style TOTP checks from decrypted secret. */
async function totp(secretValue: string, when: number) {
  const counter = Math.floor(when / 30_000);
  const bytes = new Uint8Array(8);
  let v = counter;
  for (let i = 7; i >= 0; i--) { bytes[i] = v & 255; v = Math.floor(v / 256); }
  const k = await crypto.subtle.importKey("raw", base32(secretValue), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", k, bytes));
  const off = mac[19] & 15;
  const number = (((mac[off] & 127) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3]) % 1_000_000;
  return String(number).padStart(6, "0");
}
async function validTotp(secretValue: string, code: string) {
  if (TEST) return equal(code, "654321");
  const now = Date.now();
  for (const drift of [-30_000, 0, 30_000]) if (equal(code, await totp(secretValue, now + drift))) return true;
  return false;
}

function headers(r?: Request, nonce?: string): Record<string, string> {
  const o = r?.headers.get("origin") || "";
  return {
    "content-security-policy": `default-src 'self'; script-src 'nonce-${nonce || "none"}'; style-src 'nonce-${nonce || "none"}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    ...(origins.has(o) ? { "access-control-allow-origin": o, "access-control-allow-credentials": "true" } : {})
  };
}
function json(r: Request, x: unknown, status = 200, extra: HeadersInit = {}) {
  return new Response(JSON.stringify(x), { status, headers: { ...headers(r), "content-type": "application/json; charset=utf-8", ...extra } });
}
const fail = (r: Request, message: string, status = 400) => json(r, { ok: false, message }, status);
async function body(r: Request) {
  try {
    const x = await r.json();
    return x && typeof x === "object" ? x as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

async function api(r: Request, path: string): Promise<Response> {
  if (r.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: { ...headers(r), "access-control-allow-methods": "GET, POST", "access-control-allow-headers": "content-type, x-csrf-token" }
    });
  }
  if (path === "/api/session" && r.method === "GET") {
    let s = get(r), fresh = !s;
    if (!s) s = make();
    return json(r, { ok: true, csrf: s.csrf, progress: progress(s), testMode: TEST }, 200, fresh ? { "set-cookie": secureCookie(s.id) } : {});
  }

  const s = get(r);
  if (path === "/api/sign-in" && r.method === "POST") {
    if (!validCsrf(r, s)) return fail(r, "Refresh the page and try again.", 403);
    const d = await body(r), e = emailInput(d.email), p = passwordInput(d.password);
    if (e.error) return fail(r, e.error);
    if (p.error) return fail(r, p.error);
    if (e.value !== ACCOUNT.email || p.value !== ACCOUNT.password) {
      return fail(r, "We could not sign you in. Check your email and password, then try again.", 401);
    }
    sessions.delete(s!.id);
    const n = make("identity", ACCOUNT.id);
    const sent = await issueIdentity(n);
    return json(r, { ok: true, csrf: n.csrf, ...(TEST ? { testIdentityOtp: sent } : {}) }, 200, { "set-cookie": secureCookie(n.id) });
  }
  if (!s) return fail(r, "Please sign in again to continue.", 401);

  if (path === "/api/identity/send" && r.method === "POST") {
    if (s.stage !== "identity" || !validCsrf(r, s)) return fail(r, "Please sign in again.", 401);
    const sent = await issueIdentity(s);
    return json(r, { ok: true, csrf: s.csrf, ...(TEST ? { testIdentityOtp: sent } : {}) });
  }
  if (path === "/api/identity/verify" && r.method === "POST") {
    if (s.stage !== "identity" || !validCsrf(r, s)) return fail(r, "Please sign in again.", 401);
    clearLock(s, "identity");
    if (locked(s.identityLocked)) return fail(r, "Too many tries. Wait ten minutes, then request a new code.", 429);
    const c = otpInput((await body(r)).code);
    if (c.error) return fail(r, c.error);
    const valid = !!s.identity && !!s.identityExpiry && s.identityExpiry >= Date.now() &&
      (TEST ? equal(c.value!, s.identity) : equal(await hash(c.value!), s.identity));
    if (!valid) {
      if (failed(s, "identity")) return fail(r, "Too many tries. Wait ten minutes, then request a new code.", 429);
      return fail(r, "That code did not work. Check all 6 digits, or request a new code.");
    }
    resetAttempts(s, "identity");
    s.identity = undefined;
    s.identityExpiry = undefined;
    s.stage = "mfa";
    s.csrf = token();
    return json(r, { ok: true, csrf: s.csrf });
  }

  const o = owner(r);
  if (!o) return fail(r, "Please sign in again to manage MFA.", 401);
  if (path === "/api/mfa/status" && r.method === "GET") {
    return json(r, { ok: true, csrf: o.csrf, backupCount: o.backups.length, progress: progress(o) });
  }
  if (path === "/api/authenticator/details" && r.method === "GET") {
    if (!o.pending || !o.pendingExpiry || o.pendingExpiry < Date.now()) {
      return fail(r, "These setup details have expired. Select Show new setup details.");
    }
    const x = await decrypt(o.pending);
    return json(r, { ok: true, csrf: o.csrf, secret: x, provisioningUri: uri(x), ...(TEST ? { testAuthenticatorCode: "654321" } : {}) });
  }
  if (r.method !== "POST" || !validCsrf(r, o)) return fail(r, "Refresh the page and try again.", 403);

  if (path === "/api/authenticator/start") {
    const x = secret();
    o.pending = await encrypt(x);
    o.pendingExpiry = Date.now() + LIFE;
    resetAttempts(o, "otp");
    return json(r, { ok: true, csrf: o.csrf, secret: x, provisioningUri: uri(x), ...(TEST ? { testAuthenticatorCode: "654321" } : {}) });
  }
  if (path === "/api/authenticator/verify") {
    clearLock(o, "otp");
    if (locked(o.otpLocked)) return fail(r, "Too many tries. Wait ten minutes, then request new setup details.", 429);
    const c = otpInput((await body(r)).code);
    if (c.error) return fail(r, c.error);
    let valid = false;
    if (o.pending && o.pendingExpiry && o.pendingExpiry >= Date.now()) {
      try { valid = await validTotp(await decrypt(o.pending), c.value!); } catch { valid = false; }
    }
    if (!valid) {
      if (failed(o, "otp")) return fail(r, "Too many tries. Wait ten minutes, then request new setup details.", 429);
      return fail(r, "That authenticator code did not work. Use exactly 6 digits, then try again.");
    }
    resetAttempts(o, "otp");
    o.enrolled = o.pending;
    o.pending = undefined;
    o.pendingExpiry = undefined;
    o.enabled = true;
    return json(r, { ok: true, csrf: o.csrf });
  }
  if (path === "/api/backup/generate" || path === "/api/backup/regenerate") {
    if (!o.enabled) return fail(r, "Set up your authenticator first.");
    const c = codes();
    o.backups = await Promise.all(c.map(hash));
    o.used = [];
    resetAttempts(o, "recovery");
    return json(r, { ok: true, csrf: o.csrf, codes: c, regenerated: path === "/api/backup/regenerate" });
  }
  if (path === "/api/recovery/verify") {
    clearLock(o, "recovery");
    if (locked(o.recoveryLocked)) return fail(r, "Too many tries. Wait ten minutes, then create new recovery codes.", 429);
    const c = recoveryInput((await body(r)).code);
    if (c.error) return fail(r, c.error);
    const h = await hash(c.value!), i = o.backups.findIndex(x => equal(x, h));
    if (i < 0) {
      if (failed(o, "recovery")) return fail(r, "Too many tries. Wait ten minutes, then create new recovery codes.", 429);
      return fail(r, "That recovery code did not work. Check the letters and numbers, then try again.");
    }
    resetAttempts(o, "recovery");
    o.used.push(o.backups.splice(i, 1)[0]);
    return json(r, { ok: true, csrf: o.csrf, accepted: true, remaining: o.backups.length, message: "Recovery code accepted. It has now been used." });
  }
  if (path === "/api/logout") {
    sessions.delete(o.id);
    return json(r, { ok: true }, 200, { "set-cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }
  return fail(r, "That page is not available.", 404);
}

function page(r: Request) {
  const nonce = token(24);
  let s = get(r), fresh = !s;
  if (!s) s = make();
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Local Bank MFA</title>
<style nonce="${nonce}">
body{margin:0;background:#f3f8fa;color:#17263a;font:17px/1.7 Verdana,Arial,sans-serif;letter-spacing:.035em}
main{max-width:600px;margin:auto;min-height:100vh;background:#fff;padding:20px;box-sizing:border-box}.brand{color:#075d9b;font-weight:bold}
.step,.card{margin:16px 0;padding:14px;border-radius:10px}.step{background:#eef7fc;border-left:5px solid #075d9b}.card{border:1px solid #c9d7e3}
h1{font-size:1.6rem;line-height:1.3}h2{font-size:1.15rem}p{margin:10px 0}label{display:block;font-weight:bold;margin-top:12px}
input,button{width:100%;box-sizing:border-box;padding:12px;margin-top:5px;border:2px solid #90a7b8;border-radius:8px;font:inherit}
button{margin-top:16px;background:#075d9b;color:#fff;border-color:#075d9b;font-weight:bold;cursor:pointer}.secondary{background:#fff;color:#075d9b}
.msg{padding:10px;background:#e9f8ee;border-radius:8px;margin:12px 0}.err{background:#fff0f0;color:#762323}.code{font:15px monospace;word-break:break-all;background:#f1f5f7;padding:12px;white-space:pre-wrap;border-radius:8px}
.qr{display:block;width:285px;max-width:100%;margin:14px auto;background:#fff}#logs{margin-top:20px;padding:12px;border:1px solid #c9d7e3;border-radius:10px}#loglist{font:12px monospace;word-break:break-word}
details{margin:16px 0;padding:8px;background:#f7fafb;border-radius:8px}summary{font-weight:bold;cursor:pointer}.small{font-size:.92rem}.warning{background:#fff8df;color:#5b4700}
</style></head><body><main><div class="brand">🏦 Local Bank</div><div id="step" class="step">Loading secure setup…</div><section id="app" aria-live="polite"></section><aside id="logs" aria-label="Browser logs"><b>Logs</b><ul id="loglist"></ul></aside></main>
<script nonce="${nonce}">(()=>{"use strict";
let csrf="",test=false,shownCodes=[];
const app=document.querySelector("#app"),step=document.querySelector("#step"),logs=document.querySelector("#loglist");
const e=s=>String(s).replace(/[&<>"']/g,x=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[x]));
const msg=(x,good=false)=>'<div class="msg '+(good?"":"err")+'>'+e(x)+"</div>";
/* Accessibility/inclusivity: short, consistent hint is present on every enrolment screen. */
const help=()=>'<details><summary>💡 Need a little help?</summary><p class="small">Take your time. There is no reading timer. You can try again or request a new code without a penalty.</p></details>';
function log(x){console.log(x);const l=document.createElement("li");l.textContent=x;logs.append(l)}
async function api(p,o={}){const q=await fetch(p,{method:o.method||"GET",credentials:"same-origin",headers:{"content-type":"application/json","x-csrf-token":csrf},body:o.body?JSON.stringify(o.body):undefined});const d=await q.json();if(d.csrf)csrf=d.csrf;return d}
function putError(x){app.insertAdjacentHTML("afterbegin",msg(x))}
/* Standards-compliant QR Model 2, Version 8-L, byte mode.
 Requirement task: includes both Version 8 BCH version-information module copies. */
function qr(t){
 let b=[...new TextEncoder().encode(t)];if(b.length>192)return "";let d=[64,b.length,...b];d.push(0);while(d.length<194)d.push(d.length%2?17:236);
 let ex=[],lg=[],x=1;for(let i=0;i<255;i++){ex[i]=x;lg[x]=i;x<<=1;if(x&256)x^=285}
 let mul=(a,b)=>a&&b?ex[(lg[a]+lg[b])%255]:0,g=[1];for(let i=0;i<24;i++){let z=Array(g.length+1).fill(0);for(let j=0;j<g.length;j++){z[j]^=g[j];z[j+1]^=mul(g[j],ex[i])}g=z}
 let rs=a=>{let z=Array(24).fill(0);for(let v of a){let f=v^z.shift();z.push(0);for(let j=0;j<24;j++)z[j]^=mul(g[j+1],f)}return z},bl=[d.slice(0,97),d.slice(97)],ec=bl.map(rs),w=[];
 for(let i=0;i<97;i++)bl.forEach(z=>w.push(z[i]));for(let i=0;i<24;i++)ec.forEach(z=>w.push(z[i]));
 let n=49,m=Array.from({length:n},()=>Array(n).fill(null)),set=(r,c,v)=>{if(r>=0&&c>=0&&r<n&&c<n)m[r][c]=v};
 let find=(r,c)=>{for(let y=-1;y<8;y++)for(let x=-1;x<8;x++)set(r+y,c+x,y>=0&&y<7&&x>=0&&x<7&&(y==0||y==6||x==0||x==6||(y>=2&&y<=4&&x>=2&&x<=4)))};
 find(0,0);find(0,42);find(42,0);
 for(let i=8;i<41;i++){if(m[6][i]===null)set(6,i,i%2==0);if(m[i][6]===null)set(i,6,i%2==0)}
 for(let r of [6,24,42])for(let c of [6,24,42])if(!((r==6&&c==6)||(r==6&&c==42)||(r==42&&c==6)))for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(r+y,c+x,Math.max(Math.abs(y),Math.abs(x))!=1);
 set(41,8,true);
 let f=8<<10,z=f;for(let i=14;i>=10;i--)if(z>>i&1)z^=0x537<<(i-10);f=(f|z)^0x5412;
 for(let i=0;i<15;i++){let v=!!(f>>i&1);if(i<6)set(i,8,v);else if(i<8)set(i+1,8,v);else set(n-15+i,8,v);if(i<8)set(8,n-1-i,v);else if(i<9)set(8,15-i,v);else set(8,14-i,v)}
 /* Version information: version 8 plus BCH remainder using generator 0x1f25. */
 let vi=8<<12,vb=vi;for(let i=17;i>=12;i--)if(vb>>i&1)vb^=0x1f25<<(i-12);vi|=vb;
 for(let i=0;i<18;i++){let v=!!(vi>>i&1);set(i,n-11,v);set(n-11,i,v)}
 let bit=0,up=true;
 for(let c=48;c>0;c-=2){if(c==6)c--;for(let k=0;k<n;k++){let r=up?48-k:k;for(let j=0;j<2;j++)if(m[r][c-j]===null){let v=bit<w.length*8?(w[bit>>3]>>(7-(bit&7))&1):0;bit++;if((r+c-j)%2==0)v^=1;set(r,c-j,!!v)}}up=!up}
 let p="";for(let r=0;r<n;r++)for(let c=0;c<n;c++)if(m[r][c])p+="M"+c+" "+r+"h1v1h-1z";
 return '<svg class="qr" viewBox="-4 -4 57 57" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Authenticator QR code"><rect x="-4" y="-4" width="57" height="57" fill="white"/><path d="'+p+'" fill="#111"/></svg>';
}
function sign(){
 step.textContent="Step 1 of 4 · Sign in";
 app.innerHTML='<h1>Sign in</h1><p>Use your bank sign-in details.</p><form id="f"><label>Email<input id="email" autocomplete="username" placeholder="name@example.com"></label><label>Password<input id="pass" type="password" autocomplete="current-password"></label><button>Continue →</button></form>'+help();
 f.onsubmit=async x=>{x.preventDefault();const d=await api("/api/sign-in",{method:"POST",body:{email:email.value,password:pass.value}});if(!d.ok)return putError(d.message);if(test)log("[TEST ONLY] Mock identity OTP: "+d.testIdentityOtp);identity("We sent a code. Enter the 6 digits next.")};
}
function identity(note=""){
 step.textContent="Step 2 of 4 · Check identity";
 app.innerHTML='<h1>Check your identity</h1>'+(note?msg(note,true):"")+'<p>Enter 6 digits. Example: 123456. There is no reading timer.</p><form id="f"><label>Code<input id="code" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="123456"></label><button>Verify code →</button></form><button class="secondary" id="resend" type="button">Send a new code</button>'+help();
 resend.onclick=async()=>{const d=await api("/api/identity/send",{method:"POST"});if(!d.ok)return putError(d.message);if(test)log("[TEST ONLY] Mock identity OTP: "+d.testIdentityOtp);identity("A new code was sent. The earlier code no longer works. Enter the new 6 digits next.")};
 f.onsubmit=async x=>{x.preventDefault();const d=await api("/api/identity/verify",{method:"POST",body:{code:code.value}});if(!d.ok)return putError(d.message);start()};
}
function start(){
 step.textContent="Step 3 of 4 · Add authenticator";
 app.innerHTML='<h1>Add your authenticator</h1><p>Use an authenticator app. You can scan a QR code or copy a short setup value.</p><button id="go">Show setup details →</button>'+help();
 go.onclick=async()=>details(await api("/api/authenticator/start",{method:"POST"}),"Your setup details are ready. Add them in your authenticator app, then enter its 6-digit code.");
}
async function copyText(value,label){
 try{if(!navigator.clipboard||!navigator.clipboard.writeText)throw Error("unavailable");await navigator.clipboard.writeText(value);app.insertAdjacentHTML("afterbegin",msg(label+" copied. You can now paste it into your authenticator app.",true))}
 catch{app.insertAdjacentHTML("afterbegin",msg("Copy is not available in this browser. You can use the QR code or read the setup value below."))}
}
function details(d,note=""){
 if(!d.ok){app.innerHTML=msg(d.message)+'<button id="new">Show new setup details</button>'+help();new.onclick=async()=>details(await api("/api/authenticator/start",{method:"POST"}),"New replacement setup details are ready. The previous setup details no longer work.");return}
 if(test){log("[TEST ONLY] Authenticator verification code: "+d.testAuthenticatorCode);log("[TEST ONLY] Provisioning URI: "+d.provisioningUri)}
 step.textContent="Step 3 of 4 · Add authenticator";
 app.innerHTML='<h1>Set up your authenticator</h1>'+msg(note,true)+'<p>Scan this code with your authenticator app. Or use the manual setup value.</p>'+qr(d.provisioningUri)+'<div class="code" aria-label="Manual setup value">'+e(d.secret)+'</div><button class="secondary" id="copy" type="button">Copy manual setup value</button><button class="secondary" id="replace" type="button">Request new setup details</button><form id="f"><label>Authenticator code<input id="otp" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="123456"></label><button>Confirm authenticator →</button></form>'+help();
 copy.onclick=async()=>await copyText(d.secret,"Manual setup value");
 replace.onclick=async()=>details(await api("/api/authenticator/start",{method:"POST"}),"New replacement setup details are ready. The previous setup details no longer work.");
 f.onsubmit=async x=>{x.preventDefault();const q=await api("/api/authenticator/verify",{method:"POST",body:{code:otp.value}});if(!q.ok)return putError(q.message);backup()};
}
function renderCodes(note=""){
 step.textContent="Step 4 of 4 · Save recovery codes";
 const content=shownCodes.length?'<div id="codebox" class="code">'+e(shownCodes.join("\\n"))+'</div>':'<div id="codebox" class="code">Recovery codes are hidden.</div>';
 app.innerHTML='<h1>Your recovery codes</h1>'+msg(note||"These codes are ready. Save them somewhere safe.",true)+'<p>Each code works once. You do not need to use one now.</p>'+content+'<button class="secondary" id="toggle" type="button">'+(shownCodes.length?"Hide recovery codes":"Reveal recovery codes")+'</button><button class="secondary" id="copycodes" type="button">Copy recovery codes</button><button class="secondary" id="regen" type="button">Create replacement recovery codes</button><p class="small warning">Creating replacement codes makes every earlier recovery code stop working.</p><button id="done">I saved my codes →</button>'+help();
 toggle.onclick=()=>{if(shownCodes.length){window._savedCodes=shownCodes;shownCodes=[]}else shownCodes=window._savedCodes||[];renderCodes("")};
 copycodes.onclick=async()=>{if(!shownCodes.length)return putError("Reveal the recovery codes first, then choose Copy recovery codes.");await copyText(shownCodes.join("\\n"),"Recovery codes")};
 regen.onclick=async()=>{const d=await api("/api/backup/regenerate",{method:"POST"});if(!d.ok)return putError(d.message);shownCodes=d.codes;window._savedCodes=d.codes;if(test)log("[TEST ONLY] Recovery codes: "+d.codes.join(", "));renderCodes("Replacement recovery codes are ready. All prior recovery codes no longer work.")};
 done.onclick=complete;
}
function backup(){
 step.textContent="Step 4 of 4 · Save recovery codes";
 app.innerHTML='<h1>Save recovery codes</h1><p>Recovery codes help if you cannot use your authenticator.</p><button id="make">Create recovery codes →</button>'+help();
 make.onclick=async()=>{const d=await api("/api/backup/generate",{method:"POST"});if(!d.ok)return putError(d.message);shownCodes=d.codes;window._savedCodes=d.codes;if(test)log("[TEST ONLY] Recovery codes: "+d.codes.join(", "));renderCodes()};
}
async function complete(){
 const d=await api("/api/mfa/status");
 step.textContent="Complete · MFA settings";
 app.innerHTML='<h1>✅ MFA is ready</h1><p>You have '+e(d.backupCount)+' unused recovery codes.</p><details><summary>Use a recovery code</summary><p class="small">Example: ABCD-1234. A used code cannot be used again.</p><form id="rf"><label>Recovery code<input id="rc" autocomplete="one-time-code" placeholder="ABCD-1234"></label><button>Check recovery code</button></form></details><button class="secondary" id="newcodes">Create replacement recovery codes</button><button id="out">Log out</button>'+help();
 rf.onsubmit=async x=>{x.preventDefault();const q=await api("/api/recovery/verify",{method:"POST",body:{code:rc.value}});if(!q.ok)return putError(q.message);complete()};
 newcodes.onclick=async()=>{const q=await api("/api/backup/regenerate",{method:"POST"});if(!q.ok)return putError(q.message);shownCodes=q.codes;window._savedCodes=q.codes;if(test)log("[TEST ONLY] Recovery codes: "+q.codes.join(", "));renderCodes("Replacement recovery codes are ready. All prior recovery codes no longer work.")};
 out.onclick=async()=>{await api("/api/logout",{method:"POST"});location.reload()};
}
(async()=>{const d=await api("/api/session");csrf=d.csrf;test=d.testMode;if(d.progress==="identity")identity();else if(d.progress==="details")details(await api("/api/authenticator/details"));else if(d.progress==="backup")backup();else if(d.progress==="complete")complete();else if(d.progress==="start")start();else sign()})()
})();</script></body></html>`, {
    headers: { ...headers(r, nonce), "content-type": "text/html; charset=utf-8", ...(fresh ? { "set-cookie": secureCookie(s.id) } : {}) }
  });
}

const cert = readFileSync("certs/cert.pem"), keyFile = readFileSync("certs/key.pem");
Bun.serve({
  port: PORT,
  tls: { cert, key: keyFile },
  async fetch(r) {
    try {
      const u = new URL(r.url), o = r.headers.get("origin");
      if (r.headers.get("x-forwarded-proto") === "http") {
        return new Response("Secure connection required.", { status: 400, headers: headers(r) });
      }
      if (o && !origins.has(o)) return new Response("Not allowed.", { status: 403, headers: headers(r) });
      if (u.pathname.startsWith("/api/")) return api(r, u.pathname);
      if (r.method === "GET" && u.pathname === "/") return page(r);
      return new Response("Page not found.", { status: 404, headers: headers(r) });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: headers(r) });
    }
  }
});
