
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — Bun HTTPS server + mobile single-page application.
 Requirements 1–5: authorization, CSRF, secure headers/cookies, encrypted secrets,
 input validation, rate limits, secure session lifecycle, and simulated delivery.
*/
type Stage = "anonymous" | "identity" | "mfa";
type Session = {
  id: string; csrf: string; stage: Stage; userId?: string; createdAt: number; lastSeen: number;
  identityCode?: string; identityExpiry?: number; identityUsed?: boolean; identityFails: number; identityLockedUntil?: number;
  pendingEncryptedSecret?: string; pendingOtpExpiry?: number; otpFails: number; otpLockedUntil?: number;
  enrolledEncryptedSecret?: string; otpEnabled: boolean;
  backupHashes: string[]; recoveryFails: number; recoveryLockedUntil?: number;
};

const PORT = 3000;
const TRUSTED_ORIGIN = `https://localhost:${PORT}`;
const TEST_MODE = process.env.MFA_TEST_MODE === "true"; // Explicit test-only deterministic mock mode.
const ACCOUNT = { id: "account-marcus", email: "marcus@example.com", password: "BankDemo!9" };
const sessions = new Map<string, Session>();
const encoder = new TextEncoder(), decoder = new TextDecoder();
const IDLE = 20 * 60_000, ABSOLUTE = 8 * 60 * 60_000, LIFE = 10 * 60_000, LOCK = 10 * 60_000, MAX = 5;
const masterKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
const pepper = crypto.getRandomValues(new Uint8Array(32));

function random(chars: string, length: number) {
  const b = crypto.getRandomValues(new Uint8Array(length));
  return [...b].map(x => chars[x % chars.length]).join("");
}
function token(n = 32) { return random("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789", n); }
function digits(n = 6) { return TEST_MODE ? "123456".slice(0, n) : random("0123456789", n); }
function base32(n = 32) { return TEST_MODE ? "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".slice(0, n) : random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", n); }
function b64(b: Uint8Array) { return Buffer.from(b).toString("base64url"); }
function unb64(s: string) { return new Uint8Array(Buffer.from(s, "base64url")); }
async function hash(s: string) {
  return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(`${b64(pepper)}:${s}`))));
}
async function encrypt(s: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const c = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(s));
  return `${b64(iv)}.${b64(new Uint8Array(c))}`;
}
async function decrypt(s: string) {
  const [iv, c] = s.split(".");
  if (!iv || !c) throw Error("bad encrypted value");
  return decoder.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, masterKey, unb64(c)));
}
function base32Bytes(s: string) {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, value = 0; const out: number[] = [];
  for (const char of s.replace(/=+$/, "").toUpperCase()) {
    const n = alpha.indexOf(char); if (n < 0) throw Error("bad base32");
    value = (value << 5) | n; bits += 5;
    while (bits >= 8) { bits -= 8; out.push((value >> bits) & 255); }
  }
  return new Uint8Array(out);
}
/* Requirement 3: RFC 6238 TOTP, SHA-1, six digits, 30-second time step. */
async function totp(secret: string, step = Math.floor(Date.now() / 30_000)) {
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const counter = new Uint8Array(8); let x = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(x & 255n); x >>= 8n; }
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter)), o = h[19] & 15;
  return String((((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1_000_000).padStart(6, "0");
}
async function validTotp(secret: string, code: string) {
  const step = Math.floor(Date.now() / 30_000);
  for (let i = -1; i <= 1; i++) if (code === await totp(secret, step + i)) return true;
  return false;
}
function recoveryCodes() {
  if (TEST_MODE) return ["ABCD-1234","EFGH-2345","JKLM-3456","NPQR-4567","STUV-5678","WXYZ-6789","BCDE-7890","FGHJ-8901"];
  return Array.from({ length: 8 }, () => `${random("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 4)}-${random("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 4)}`);
}
function session(stage: Stage = "anonymous", userId?: string) {
  const s: Session = { id: token(48), csrf: token(40), stage, userId, createdAt: Date.now(), lastSeen: Date.now(), identityFails: 0, otpFails: 0, otpEnabled: false, backupHashes: [], recoveryFails: 0 };
  sessions.set(s.id, s); return s;
}
function cookies(r: Request) {
  const o: Record<string, string> = {};
  for (const p of (r.headers.get("cookie") || "").split(";")) { const i = p.indexOf("="); if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim(); }
  return o;
}
function stale(s: Session) { return Date.now() - s.lastSeen > IDLE || Date.now() - s.createdAt > ABSOLUTE; }
function current(r: Request) {
  const id = cookies(r).mfa_session, s = id && sessions.get(id);
  if (!s || stale(s)) { if (id) sessions.delete(id); return undefined; }
  s.lastSeen = Date.now(); return s;
}
function owner(r: Request) { const s = current(r); return s?.stage === "mfa" && s.userId === ACCOUNT.id ? s : undefined; }
function csrf(r: Request, s?: Session) { return !!s && r.headers.get("x-csrf-token") === s.csrf; }
function cookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE / 1000}`; }
function headers(nonce?: string): Record<string, string> {
  return {
    "content-security-policy": `default-src 'self'; script-src ${nonce ? `'nonce-${nonce}'` : "'none'"}; style-src ${nonce ? `'nonce-${nonce}'` : "'none'"}; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()", "access-control-allow-origin": TRUSTED_ORIGIN,
    "access-control-allow-credentials": "true", "vary": "Origin"
  };
}
function out(v: unknown, status = 200, extra: HeadersInit = {}) { return new Response(JSON.stringify(v), { status, headers: { ...headers(), "content-type": "application/json; charset=utf-8", ...extra } }); }
function fail(message: string, status = 400) { return out({ ok: false, message }, status); }
async function data(r: Request) { try { const x = await r.json(); return x && typeof x === "object" ? x as Record<string, unknown> : {}; } catch { return {}; } }
function clean(x: unknown, max: number) { return typeof x === "string" ? x.trim().slice(0, max) : ""; }
function six(x: string) { return /^\d{6}$/.test(x); }
function recovery(x: string) { return /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(x); }
async function saveCodes(s: Session, codes: string[]) { s.backupHashes = await Promise.all(codes.map(hash)); }

async function api(r: Request, path: string): Promise<Response> {
  if (r.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...headers(), "access-control-allow-methods": "GET, POST", "access-control-allow-headers": "content-type, x-csrf-token" } });
  if (r.method === "GET" && path === "/api/session") {
    let s = current(r), made = !s; if (!s) s = session();
    return out({ ok: true, csrf: s.csrf, signedIn: s.stage !== "anonymous", verified: s.stage === "mfa", otpEnabled: s.otpEnabled, backupCount: s.backupHashes.length, testMode: TEST_MODE }, 200, made ? { "set-cookie": cookie(s.id) } : {});
  }
  const s = current(r);
  if (r.method === "POST" && path === "/api/sign-in") {
    if (!csrf(r, s)) return fail("Your secure page check expired. Refresh the page and try again.", 403);
    const d = await data(r), email = clean(d.email, 254).toLowerCase(), password = clean(d.password, 256);
    if (email !== ACCOUNT.email || password !== ACCOUNT.password) return fail("We could not sign you in. Check your email and password, then try again.", 401);
    sessions.delete(s!.id); const fresh = session("identity", ACCOUNT.id);
    fresh.identityCode = digits(); fresh.identityExpiry = Date.now() + LIFE;
    return out({ ok: true, csrf: fresh.csrf, testCode: TEST_MODE ? fresh.identityCode : undefined }, 200, { "set-cookie": cookie(fresh.id) });
  }
  if (r.method === "POST" && path === "/api/identity/send") {
    if (!s || s.stage !== "identity" || s.userId !== ACCOUNT.id) return fail("Please sign in again to continue.", 401);
    if (!csrf(r, s)) return fail("Your secure page check expired. Refresh and try again.", 403);
    s.identityCode = digits(); s.identityExpiry = Date.now() + LIFE; s.identityUsed = false; s.identityFails = 0; s.identityLockedUntil = undefined;
    return out({ ok: true, csrf: s.csrf, testCode: TEST_MODE ? s.identityCode : undefined });
  }
  if (r.method === "POST" && path === "/api/identity/verify") {
    if (!s || s.stage !== "identity" || s.userId !== ACCOUNT.id) return fail("Please sign in again to continue.", 401);
    if (!csrf(r, s)) return fail("Your secure page check expired. Refresh and try again.", 403);
    if (s.identityLockedUntil && s.identityLockedUntil > Date.now()) return fail("Too many tries. Wait ten minutes, then request a new code.", 429);
    const code = clean((await data(r)).code, 6);
    if (!six(code) || s.identityUsed || !s.identityExpiry || s.identityExpiry < Date.now() || code !== s.identityCode) {
      if (++s.identityFails >= MAX) s.identityLockedUntil = Date.now() + LOCK;
      return fail("That code did not work. Check all 6 digits, or request a new code.");
    }
    s.identityUsed = true; s.stage = "mfa"; s.csrf = token(40);
    return out({ ok: true, csrf: s.csrf });
  }
  const o = owner(r);
  if (!o) return fail("Please sign in again to manage MFA.", 401);
  if (r.method === "GET" && path === "/api/mfa/status") return out({ ok: true, csrf: o.csrf, otpEnabled: o.otpEnabled, backupCount: o.backupHashes.length });
  if (r.method !== "POST") return fail("That page is not available.", 404);
  if (!csrf(r, o)) return fail("Your secure page check expired. Refresh and try again.", 403);

  if (path === "/api/authenticator/start") {
    const secret = base32(); o.pendingEncryptedSecret = await encrypt(secret); o.pendingOtpExpiry = Date.now() + LIFE; o.otpFails = 0; o.otpLockedUntil = undefined;
    const issuer = "Local Bank", label = `${issuer}:marcus@example.com`;
    const uri = `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    return out({ ok: true, csrf: o.csrf, secret, provisioningUri: uri });
  }
  if (path === "/api/authenticator/verify") {
    const now = Date.now();
    if (o.otpLockedUntil && o.otpLockedUntil > now) return fail("Too many authenticator code tries. This setup is locked for ten minutes. Show new setup details to start again.", 429);
    if (!o.pendingEncryptedSecret || !o.pendingOtpExpiry || o.pendingOtpExpiry < now) { o.pendingEncryptedSecret = undefined; o.pendingOtpExpiry = undefined; return fail("This setup has expired. Show new setup details to make a new setup."); }
    const code = clean((await data(r)).code, 6); let ok = false;
    try { ok = six(code) && await validTotp(await decrypt(o.pendingEncryptedSecret), code); } catch {}
    if (!ok) { if (++o.otpFails >= MAX) { o.otpLockedUntil = now + LOCK; return fail("Too many authenticator code tries. This setup is locked for ten minutes. Show new setup details to start again.", 429); } return fail(`That authenticator code did not work. Check the 6 digits. You have ${MAX - o.otpFails} tries before this setup pauses.`); }
    /* Task: retain a separately encrypted enrolled secret after successful verification. */
    o.enrolledEncryptedSecret = o.pendingEncryptedSecret; o.pendingEncryptedSecret = undefined; o.pendingOtpExpiry = undefined; o.otpEnabled = true; o.otpFails = 0; o.otpLockedUntil = undefined;
    return out({ ok: true, csrf: o.csrf });
  }
  if (path === "/api/backup/generate" || path === "/api/backup/regenerate") {
    if (!o.otpEnabled || !o.enrolledEncryptedSecret) return fail("Set up your authenticator before making recovery codes.");
    const codes = recoveryCodes(); await saveCodes(o, codes); return out({ ok: true, csrf: o.csrf, codes });
  }
  if (path === "/api/recovery/verify") {
    if (o.recoveryLockedUntil && o.recoveryLockedUntil > Date.now()) return fail("Too many tries. Wait ten minutes before trying another recovery code.", 429);
    const code = clean((await data(r)).code, 9).toUpperCase();
    /* Task: malformed input is also a failed attempt and shares the lock threshold. */
    if (!recovery(code)) {
      if (++o.recoveryFails >= MAX) { o.recoveryLockedUntil = Date.now() + LOCK; return fail("Too many tries. Wait ten minutes before trying another recovery code.", 429); }
      return fail("Enter a recovery code like ABCD-1234.");
    }
    const i = o.backupHashes.indexOf(await hash(code));
    if (i < 0) {
      if (++o.recoveryFails >= MAX) { o.recoveryLockedUntil = Date.now() + LOCK; return fail("Too many tries. Wait ten minutes before trying another recovery code.", 429); }
      return fail("That recovery code was not available. Check it, or use a different unused code.");
    }
    o.backupHashes.splice(i, 1); o.recoveryFails = 0; return out({ ok: true, csrf: o.csrf, remaining: o.backupHashes.length });
  }
  if (path === "/api/logout") { sessions.delete(o.id); return out({ ok: true }, 200, { "set-cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" }); }
  return fail("That page is not available.", 404);
}

function page(r: Request) {
  const nonce = token(24); let s = current(r), made = !s; if (!s) s = session();
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Local Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#17263a;--blue:#075d9b;--pale:#eef7fc;--line:#c9d7e3}*{box-sizing:border-box}body{margin:0;background:#f4f8fa;color:var(--ink);font:17px/1.65 Verdana,Arial,sans-serif;letter-spacing:.035em}main{max-width:600px;min-height:100vh;margin:auto;padding:20px 18px 34px;background:#fff}.brand{font-weight:bold;color:var(--blue)}.step{margin:17px 0;padding:9px 13px;background:var(--pale);border-left:5px solid var(--blue)}h1{font-size:1.6rem;line-height:1.3}h2{font-size:1.1rem}p{margin:10px 0 17px}.card{margin:18px 0;padding:16px;border:1px solid var(--line);border-radius:12px}.hint{padding:11px 13px;background:#fff8dc;border-left:4px solid #9b7200;font-size:.92rem}.message{padding:11px 13px;border-radius:8px;margin:13px 0}.success{background:#e9f8ee;color:#145b38}.error{background:#fff0f0;color:#762323}label{display:block;font-weight:bold;margin-top:15px}input{width:100%;margin-top:5px;padding:12px;border:2px solid #90a7b8;border-radius:8px;font:inherit;letter-spacing:.08em}button{width:100%;margin-top:17px;padding:12px 14px;border:2px solid var(--blue);border-radius:8px;background:var(--blue);color:#fff;font:inherit;font-weight:bold;cursor:pointer}.secondary{background:#fff;color:var(--blue)}button:focus,input:focus{outline:3px solid #f3bb45;outline-offset:3px}.code{padding:11px;background:#f1f5f7;border-radius:7px;font:14px/1.55 monospace;word-break:break-all;letter-spacing:.05em}.qr{display:flex;justify-content:center;padding:12px;border:1px solid var(--line);border-radius:8px}.qr canvas{width:240px;height:240px;image-rendering:pixelated}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px}.codes div{padding:9px;background:#f1f5f7;border-radius:6px;font-family:monospace}.logs{margin-top:28px;border-top:2px solid var(--line)}pre{max-height:180px;overflow:auto;padding:11px;background:#172435;color:#e8f3ff;border-radius:8px;white-space:pre-wrap;font:12px/1.5 monospace;letter-spacing:0}.small{font-size:.88rem;color:#526276}@media(min-width:520px){main{margin-top:18px;border-radius:14px;box-shadow:0 3px 16px #ccd5dc}}
</style></head><body><main><header><div class="brand">🏦 Local Bank</div><div class="step" id="step">Step 1 of 4 · Sign in</div></header><section id="app" aria-live="polite">Loading secure setup…</section><section class="logs"><h2>🧾 Logs</h2><p class="small">Simulation activity appears here. Private test values are only in the browser console.</p><pre id="logs">Ready.</pre></section></main>
<script nonce="${nonce}">
(()=>{"use strict";let csrf="";const app=document.querySelector("#app"),step=document.querySelector("#step"),logs=document.querySelector("#logs");
const log=x=>{console.log(x);logs.textContent+="\\n"+x}, msg=(x,ok=false)=>'<div class="message '+(ok?"success":"error")+'">'+x+"</div>", bind=(id,f)=>document.querySelector("#"+id)?.addEventListener("click",f);
async function api(path,o={}){let r=await fetch(path,{method:o.method||"GET",credentials:"same-origin",headers:{"content-type":"application/json","x-csrf-token":csrf},body:o.body?JSON.stringify(o.body):undefined}),d=await r.json().catch(()=>({ok:false,message:"We could not complete that step. Please try again."}));if(d.csrf)csrf=d.csrf;return d}
function test(n,v){if(v!==undefined){console.log("[TEST ONLY] "+n+":",v);log("Test-only value sent to browser console.")}}
function sign(){step.textContent="Step 1 of 4 · Sign in";app.innerHTML='<h1>Sign in</h1><p>Use your Local Bank email and password.</p><form id="f"><label>Email address<input id="email" type="email" autocomplete="username" placeholder="name@example.com" required></label><label>Password<input id="pass" type="password" autocomplete="current-password" required></label><button>Continue →</button></form><p class="hint">💡 Example email: name@example.com. Your password manager can help.</p>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();let d=await api("/api/sign-in",{method:"POST",body:{email:email.value,password:pass.value}});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));test("Mock identity OTP",d.testCode);identity("Sign-in succeeded. Next, enter the 6-digit identity code.")}}
function identity(note=""){step.textContent="Step 2 of 4 · Check your identity";app.innerHTML='<h1>Check your identity</h1>'+ (note?msg(note,true):"")+'<p>We sent a 6-digit check code. There is no reading timer.</p><form id="f"><label>6-digit code<input id="code" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6" required></label><button>Verify code →</button></form><button class="secondary" id="send">↻ Send a new code</button><p class="hint">💡 You can request another code at any time.</p>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();let d=await api("/api/identity/verify",{method:"POST",body:{code:code.value}});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));authStart("Identity check succeeded. Next, set up your authenticator.")};bind("send",async()=>{let d=await api("/api/identity/send",{method:"POST"});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));test("New mock identity OTP",d.testCode);identity("A new code was sent. The earlier code no longer works.")})}
function qr(uri){/* Exact URI byte-mode QR renderer. Version 6-L supports this provisioning URI. */const n=41,B=136,E=18,t=[...new TextEncoder().encode(uri)];if(t.length>134)return "";let z=[];const put=(v,c)=>{for(let i=c-1;i>=0;i--)z.push(v>>i&1)};put(4,4);put(t.length,8);t.forEach(x=>put(x,8));put(0,Math.min(4,B*8-z.length));while(z.length%8)z.push(0);let d=[];for(let i=0;i<z.length;i+=8)d.push(z.slice(i,i+8).reduce((a,x)=>a*2+x,0));while(d.length<B)d.push(d.length%2?17:236);let ex=[],lg=[],x=1;for(let i=0;i<255;i++){ex[i]=x;x<<=1;if(x&256)x^=285}ex.forEach((v,i)=>lg[v]=i);let mul=(a,b)=>a&&b?ex[(lg[a]+lg[b])%255]:0,g=[1];for(let i=0;i<E;i++){let q=Array(g.length+1).fill(0);g.forEach((v,j)=>{q[j]^=v;q[j+1]^=mul(v,ex[i])});g=q}let rs=a=>{let q=Array(E).fill(0);a.forEach(v=>{let f=v^q.shift();q.push(0);for(let j=0;j<E;j++)q[j]^=mul(g[j+1],f)});return q},c=[d.slice(0,68),d.slice(68)],ec=c.map(rs),bits=[];for(let i=0;i<68;i++)for(let j=0;j<2;j++)put2(c[j][i]);for(let i=0;i<E;i++)for(let j=0;j<2;j++)put2(ec[j][i]);function put2(v){for(let i=7;i>=0;i--)bits.push(v>>i&1)}let a=Array.from({length:n},()=>Array(n).fill(null)),f=Array.from({length:n},()=>Array(n).fill(0)),p=(y,x,v)=>{if(y>=0&&x>=0&&y<n&&x<n)a[y][x]=v,f[y][x]=1},find=(y,x)=>{for(let j=-1;j<8;j++)for(let i=-1;i<8;i++){let inq=j>=0&&j<7&&i>=0&&i<7;p(y+j,x+i,inq&&(j==0||j==6||i==0||i==6||(j>=2&&j<=4&&i>=2&&i<=4))?1:0)}};find(0,0);find(0,n-7);find(n-7,0);for(let i=8;i<n-8;i++)p(6,i,i%2==0),p(i,6,i%2==0);for(let j=-2;j<=2;j++)for(let i=-2;i<=2;i++)p(34+j,34+i,Math.max(Math.abs(i),Math.abs(j))==2||(!i&&!j)?1:0);p(n-8,8,1);for(let i=0;i<9;i++)if(i!=6)p(8,i,0),p(i,8,0);for(let i=0;i<8;i++)p(8,n-1-i,0),p(n-1-i,8,0);let k=0,u=1;for(let r=n-1;r>0;r-=2){if(r==6)r--;for(let q=0;q<n;q++){let y=u?n-1-q:q;for(let j=0;j<2;j++)if(!f[y][r-j])a[y][r-j]=bits[k++]||0}u=!u}let mask=(y,x)=>(y+x)%2==0;for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(!f[y][x]&&mask(y,x))a[y][x]^=1;let v=((8<<10)|0);let rem=v;while(rem.toString(2).length>=11)rem^=0x537<<(rem.toString(2).length-11);v=(v|rem)^0x5412;for(let i=0;i<15;i++){let b=v>>i&1;if(i<6)a[i][8]=b;else if(i<8)a[i+1][8]=b;else a[n-15+i][8]=b;if(i<8)a[8][n-i-1]=b;else if(i<9)a[8][15-i]=b;else a[8][14-i]=b}let cv=document.createElement("canvas");cv.width=cv.height=n+8;let ctx=cv.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,n+8,n+8);ctx.fillStyle="#17263a";for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(a[y][x])ctx.fillRect(x+4,y+4,1,1);cv.setAttribute("role","img");cv.setAttribute("aria-label","Scannable QR code for authenticator setup");return cv}
function authStart(note=""){step.textContent="Step 3 of 4 · Add authenticator";app.innerHTML='<h1>Add your authenticator</h1>'+ (note?msg(note,true):"")+'<p>An authenticator app makes a 6-digit code for you.</p><div class="card"><h2>📱 Set up your app</h2><p>Show one setup. You can scan it or copy it.</p><button id="start">Show setup details →</button></div><p class="hint">💡 Take as long as you need. A new setup replaces an earlier setup.</p>';bind("start",async()=>{let d=await api("/api/authenticator/start",{method:"POST"});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));test("Authenticator Base32 secret",d.secret);test("Authenticator provisioning URI",d.provisioningUri);details(d)})}
function details(d){step.textContent="Step 3 of 4 · Add authenticator";app.innerHTML='<h1>Set up your authenticator</h1><p>Scan the QR code or use the manual details. Both set up the same authenticator.</p><div class="card"><h2>▣ Scan QR code</h2><div class="qr" id="qr"></div><button class="secondary" id="toggle" aria-expanded="false">Show manual setup details</button><div id="manual" hidden><h2>🔗 Setup link</h2><div class="code" id="uri"></div><button class="secondary" id="copyuri">Copy setup link</button><h2>⌨️ Manual Base32 secret</h2><div class="code" id="secret"></div><button class="secondary" id="copysecret">Copy secret</button></div></div><form id="f"><label>Code from your authenticator<input id="otp" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6" required></label><button>Confirm authenticator →</button></form><button class="secondary" id="restart">↻ Show new setup details</button><p class="hint">💡 This setup is available for 10 minutes. You can retry.</p>';qr.querySelector?.();document.querySelector("#qr").append(qr(d.provisioningUri));uri.textContent=d.provisioningUri;secret.textContent=d.secret;bind("toggle",()=>{let m=document.querySelector("#manual"),show=m.hidden;m.hidden=!show;toggle.textContent=show?"Hide manual setup details":"Show manual setup details";toggle.setAttribute("aria-expanded",String(show))});let copy=(v,n)=>navigator.clipboard?.writeText(v).then(()=>log(n+" copied to clipboard.")).catch(()=>log("Copy was unavailable. You can select the text."));bind("copyuri",()=>copy(d.provisioningUri,"Setup link"));bind("copysecret",()=>copy(d.secret,"Manual secret"));bind("restart",()=>authStart());document.querySelector("#f").onsubmit=async e=>{e.preventDefault();let r=await api("/api/authenticator/verify",{method:"POST",body:{code:otp.value}});if(!r.ok)return app.insertAdjacentHTML("afterbegin",msg(r.message));backup("Authenticator verification succeeded. Next, save recovery codes.")}}
function backup(note=""){step.textContent="Step 4 of 4 · Save recovery codes";app.innerHTML='<h1>Save recovery codes</h1>'+ (note?msg(note,true):"")+'<p>Recovery codes help if you lose your phone. Each code works once.</p><button id="make">Create recovery codes →</button><p class="hint">💡 Keep them somewhere private. You can make a new set later.</p>';bind("make",async()=>{let d=await api("/api/backup/generate",{method:"POST"});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));test("Mock recovery codes",d.codes);codes(d.codes)})}
function codes(c){step.textContent="Step 4 of 4 · Save recovery codes";app.innerHTML='<h1>Your recovery codes</h1>'+msg("Your recovery codes are ready. Save them now, then continue.",true)+'<button class="secondary" id="show" aria-expanded="false">Show recovery codes</button><div id="list" class="codes" hidden></div><button class="secondary" id="copy">Copy codes</button><button class="secondary" id="down">Download text file</button><button id="finish">I saved my codes →</button>';c.forEach(x=>{let d=document.createElement("div");d.textContent=x;list.append(d)});bind("show",()=>{let x=list.hidden;list.hidden=!x;show.textContent=x?"Hide recovery codes":"Show recovery codes";show.setAttribute("aria-expanded",String(x))});bind("copy",()=>navigator.clipboard?.writeText(c.join("\\n")).then(()=>log("Recovery codes copied to clipboard.")));bind("down",()=>{let a=document.createElement("a");a.href=URL.createObjectURL(new Blob([c.join("\\n")],{type:"text/plain"}));a.download="local-bank-recovery-codes.txt";a.click();URL.revokeObjectURL(a.href);log("Recovery code text file prepared for download.")});bind("finish",settings)}
async function settings(){let d=await api("/api/mfa/status");if(!d.ok)return sign();step.textContent="Complete · MFA settings";app.innerHTML='<h1>✅ MFA is ready</h1><p>Your authenticator is on. You have '+d.backupCount+' unused recovery codes.</p><div class="card"><h2>🔐 Use a recovery code</h2><form id="f"><label>Recovery code<input id="rc" autocomplete="one-time-code" placeholder="Example: ABCD-1234" maxlength="9" required></label><button class="secondary">Use recovery code</button></form></div><button class="secondary" id="regen">↻ Make new recovery codes</button><button class="secondary" id="again">↻ Set up authenticator again</button><button id="logout">Log out</button>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();let r=await api("/api/recovery/verify",{method:"POST",body:{code:rc.value}});if(!r.ok)return app.insertAdjacentHTML("afterbegin",msg(r.message));settings()};bind("regen",async()=>{let r=await api("/api/backup/regenerate",{method:"POST"});if(!r.ok)return app.insertAdjacentHTML("afterbegin",msg(r.message));test("Replacement mock recovery codes",r.codes);codes(r.codes)});bind("again",()=>authStart());bind("logout",async()=>{await api("/api/logout",{method:"POST"});csrf="";log("Signed out. Secure session invalidated.");sign()})}
(async()=>{let d=await api("/api/session");if(d.verified)settings();else if(d.signedIn)identity();else sign()})()})();</script></body></html>`, { headers: { ...headers(nonce), "content-type": "text/html; charset=utf-8", ...(made ? { "set-cookie": cookie(s.id) } : {}) } });
}

const cert = readFileSync("certs/cert.pem"), key = readFileSync("certs/key.pem");
Bun.serve({
  port: PORT, tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url), origin = request.headers.get("origin");
      if (request.headers.get("x-forwarded-proto") === "http") return new Response("Secure connection required.", { status: 400, headers: headers() });
      if (origin && origin !== TRUSTED_ORIGIN) return new Response("Not allowed.", { status: 403, headers: headers() });
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      if (request.method === "GET" && url.pathname === "/") return page(request);
      return new Response("Page not found.", { status: 404, headers: headers() });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: headers() });
    }
  }
});
