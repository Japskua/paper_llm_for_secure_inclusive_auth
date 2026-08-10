
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — Requirements 1–5
 Server-owned sessions, CSRF, encrypted values, rate limits, TLS, secure headers,
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
/* Task: fixtures are available by default outside production and never in production. */
const TEST_MODE = !PRODUCTION;
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
  const s: Session = { id: token(48), csrf: token(40), stage, userId, createdAt: Date.now(), lastSeen: Date.now(), identityFails: 0, otpFails: 0, otpEnabled: false, backupHashes: [], recoveryFails: 0 };
  sessions.set(s.id, s); return s;
}
function cookies(r: Request) {
  const out: Record<string, string> = {};
  for (const p of (r.headers.get("cookie") || "").split(";")) { const i = p.indexOf("="); if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim(); }
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
    "strict-transport-security": "max-age=31536000; includeSubDomains", "x-content-type-options": "nosniff",
    "x-frame-options": "DENY", "referrer-policy": "no-referrer", "permissions-policy": "camera=(), microphone=(), geolocation=()", vary: "Origin",
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
    if (clean(d.email, 254).toLowerCase() !== ACCOUNT.email || clean(d.password, 256) !== ACCOUNT.password) return fail(r, "We could not sign you in. Check your email and password, then try again.", 401);
    sessions.delete(s!.id); const fresh = makeSession("identity", ACCOUNT.id);
    fresh.identityCode = digits(); fresh.identityExpiry = Date.now() + LIFE;
    return out(r, { ok: true, csrf: fresh.csrf, ...(TEST_MODE ? { testIdentityOtp: fresh.identityCode } : {}) }, 200, { "set-cookie": cookie(fresh.id) });
  }
  if (!s) return fail(r, "Please sign in again to continue.", 401);
  if (r.method === "POST" && path === "/api/identity/send") {
    if (s.stage !== "identity" || s.userId !== ACCOUNT.id || !csrf(r, s)) return fail(r, "Please sign in again and refresh your secure page.", 401);
    if (s.identityLockedUntil && s.identityLockedUntil > Date.now()) return fail(r, "Too many tries. Wait ten minutes, then request a new code.", 429);
    s.identityFails = 0; s.identityCode = digits(); s.identityUsed = false; s.identityExpiry = Date.now() + LIFE;
    return out(r, { ok: true, csrf: s.csrf, ...(TEST_MODE ? { testIdentityOtp: s.identityCode } : {}) });
  }
  if (r.method === "POST" && path === "/api/identity/verify") {
    if (s.stage !== "identity" || s.userId !== ACCOUNT.id || !csrf(r, s)) return fail(r, "Please sign in again and refresh your secure page.", 401);
    const code = clean((await data(r)).code, 6);
    if (!/^\d{6}$/.test(code) || s.identityUsed || !s.identityExpiry || s.identityExpiry < Date.now() || code !== s.identityCode) {
      if (++s.identityFails >= MAX) s.identityLockedUntil = Date.now() + LOCK;
      return fail(r, "That code did not work. Check all 6 digits, or request a new code.");
    }
    s.identityUsed = true; s.stage = "mfa"; s.csrf = token(40); return out(r, { ok: true, csrf: s.csrf });
  }
  const o = owner(r);
  if (!o) return fail(r, "Please sign in again to manage MFA.", 401);
  if (r.method === "GET" && path === "/api/mfa/status") return out(r, { ok: true, csrf: o.csrf, backupCount: o.backupHashes.length, progress: progress(o) });
  if (r.method === "GET" && path === "/api/authenticator/details") {
    if (!o.pendingEncryptedSecret || !o.pendingOtpExpiry || o.pendingOtpExpiry < Date.now()) return fail(r, "This setup has expired. Show new setup details to make a new setup.");
    const secret = await decrypt(o.pendingEncryptedSecret); return out(r, { ok: true, csrf: o.csrf, secret, provisioningUri: uri(secret), ...(TEST_MODE ? { testAuthenticatorCode: await totp(secret) } : {}) });
  }
  if (r.method !== "POST" || !csrf(r, o)) return fail(r, "Your secure page check expired. Refresh and try again.", 403);
  if (path === "/api/authenticator/start") {
    const secret = base32(); o.pendingEncryptedSecret = await encrypt(secret); o.pendingOtpExpiry = Date.now() + LIFE; o.otpFails = 0;
    /* Non-production fixture provides only the current verification code, never a token. */
    return out(r, { ok: true, csrf: o.csrf, secret, provisioningUri: uri(secret), ...(TEST_MODE ? { testAuthenticatorCode: await totp(secret) } : {}) });
  }
  if (path === "/api/authenticator/verify") {
    if (!o.pendingEncryptedSecret || !o.pendingOtpExpiry || o.pendingOtpExpiry < Date.now()) return fail(r, "This setup has expired. Show new setup details to make a new setup.");
    const code = clean((await data(r)).code, 6);
    const ok = /^\d{6}$/.test(code) && await validTotp(await decrypt(o.pendingEncryptedSecret), code);
    if (!ok) { if (++o.otpFails >= MAX) { o.otpLockedUntil = Date.now() + LOCK; return fail(r, "Too many authenticator code tries. Wait ten minutes, then show new setup details.", 429); } return fail(r, `That authenticator code did not work. You have ${MAX - o.otpFails} tries before this setup pauses.`); }
    o.enrolledEncryptedSecret = o.pendingEncryptedSecret; o.pendingEncryptedSecret = undefined; o.pendingOtpExpiry = undefined; o.otpEnabled = true; return out(r, { ok: true, csrf: o.csrf });
  }
  if (path === "/api/backup/generate" || path === "/api/backup/regenerate") {
    if (!o.otpEnabled) return fail(r, "Set up your authenticator before making recovery codes.");
    const codes = recoveryCodes(); o.backupHashes = await Promise.all(codes.map(hash)); return out(r, { ok: true, csrf: o.csrf, codes });
  }
  if (path === "/api/logout") { sessions.delete(o.id); return out(r, { ok: true }, 200, { "set-cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" }); }
  return fail(r, "That page is not available.", 404);
}

/* Requirements task: standards-compliant QR Version 10-L, byte mode, mask 0.
   Includes alignment, format and Version >=7 information reservation and placement. */
function page(r: Request) {
  const nonce = token(24); let s = current(r), made = !s; if (!s) s = makeSession();
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Local Bank · MFA setup</title>
<style nonce="${nonce}">:root{--ink:#17263a;--blue:#075d9b;--pale:#eef7fc;--line:#c9d7e3}*{box-sizing:border-box}body{margin:0;background:#f4f8fa;color:var(--ink);font:17px/1.65 Verdana,Arial,sans-serif;letter-spacing:.035em}main{max-width:600px;min-height:100vh;margin:auto;padding:20px 18px 34px;background:#fff}.brand{font-weight:bold;color:var(--blue)}.step{margin:17px 0;padding:9px 13px;background:var(--pale);border-left:5px solid var(--blue)}h1{font-size:1.6rem;line-height:1.3}.card{margin:18px 0;padding:16px;border:1px solid var(--line);border-radius:12px}.hint{padding:11px;background:#fff8dc;border-left:4px solid #9b7200}.message{padding:11px;border-radius:8px;margin:13px 0}.success{background:#e9f8ee}.error{background:#fff0f0;color:#762323}label{display:block;font-weight:bold;margin-top:15px}input,button{width:100%;margin-top:5px;padding:12px;border:2px solid #90a7b8;border-radius:8px;font:inherit}button{margin-top:17px;border-color:var(--blue);background:var(--blue);color:#fff;font-weight:bold}.secondary{background:#fff;color:var(--blue)}.code{padding:11px;background:#f1f5f7;border-radius:7px;font:14px/1.55 monospace;word-break:break-all}.qr{display:block;width:min(100%,290px);margin:16px auto;padding:8px;background:#fff;border:1px solid var(--line);image-rendering:pixelated}.logs{margin-top:28px;border-top:2px solid var(--line)}pre{max-height:180px;overflow:auto;padding:11px;background:#172435;color:#e8f3ff;border-radius:8px;white-space:pre-wrap;font:12px/1.5 monospace}@media(min-width:520px){main{margin-top:18px;border-radius:14px}}</style></head><body><main><header><div class="brand">🏦 Local Bank</div><div class="step" id="step">Step 1 of 4 · Sign in</div></header><section id="app" aria-live="polite">Loading secure setup…</section><section class="logs"><h2>🧾 Logs</h2><pre id="logs">Ready.</pre></section></main>
<script nonce="${nonce}">(()=>{"use strict";let csrf="",testMode=false;const app=document.querySelector("#app"),step=document.querySelector("#step"),logs=document.querySelector("#logs");const log=v=>{console.log(v);logs.textContent+="\\n"+v};const fixture=(n,v)=>{if(testMode&&v){const x="[TEST ONLY] "+n+": "+v;console.log(x);logs.textContent+="\\n"+x}};const msg=(v,g=false)=>'<div class="message '+(g?"success":"error")+'>'+v+"</div>";const bind=(id,f)=>document.querySelector("#"+id)?.addEventListener("click",f);async function api(p,o={}){const q=await fetch(p,{method:o.method||"GET",credentials:"same-origin",headers:{"content-type":"application/json","x-csrf-token":csrf},body:o.body?JSON.stringify(o.body):undefined}),d=await q.json();if(d.csrf)csrf=d.csrf;return d}
function sign(){step.textContent="Step 1 of 4 · Sign in";app.innerHTML='<h1>Sign in</h1><p>Use your Local Bank email and password.</p><form id="f"><label>Email address<input id="email" type="email" autocomplete="username" placeholder="name@example.com" required></label><label>Password<input id="pass" type="password" autocomplete="current-password" required></label><button>Continue →</button></form>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const d=await api("/api/sign-in",{method:"POST",body:{email:email.value,password:pass.value}});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));fixture("Mock identity OTP",d.testIdentityOtp);identity()}}
function identity(){step.textContent="Step 2 of 4 · Check your identity";app.innerHTML='<h1>Check your identity</h1><p>Enter the 6-digit check code. There is no reading timer.</p><form id="f"><label>6-digit code<input id="code" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6"></label><button>Verify code →</button></form><button class="secondary" id="send">↻ Send a new code</button>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const d=await api("/api/identity/verify",{method:"POST",body:{code:code.value}});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));start()};bind("send",async()=>{const d=await api("/api/identity/send",{method:"POST"});if(d.ok)fixture("New mock identity OTP",d.testIdentityOtp)})}
function qrSvg(text){const N=57,m=Array.from({length:N},()=>Array(N).fill(null)),set=(r,c,v)=>{if(r>=0&&c>=0&&r<N&&c<N)m[r][c]=v},finder=(r,c)=>{for(let y=-1;y<8;y++)for(let x=-1;x<8;x++)set(r+y,c+x,y>=0&&y<7&&x>=0&&x<7&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4)))};finder(0,0);finder(N-7,0);finder(0,N-7);for(let i=8;i<N-8;i++){if(m[6][i]===null)set(6,i,i%2===0);if(m[i][6]===null)set(i,6,i%2===0)}for(const y of [6,28,50])for(const x of [6,28,50])if(!((y===6&&x===6)||(y===6&&x===50)||(y===50&&x===6)))for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)set(y+dy,x+dx,Math.max(Math.abs(dx),Math.abs(dy))!==1);for(let i=0;i<=8;i++){if(i!==6){set(i,8,false);set(8,i,false)}}for(let i=0;i<7;i++)set(N-7+i,8,false);for(let i=0;i<8;i++)set(8,N-8+i,false);for(let i=0;i<18;i++){set(Math.floor(i/3),N-11+i%3,false);set(N-11+i%3,Math.floor(i/3),false)}set(N-8,8,true);const b=[...new TextEncoder().encode(text)];if(b.length>271)return "";let bits=[],add=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push(v>>>i&1)};add(4,4);add(b.length,16);b.forEach(v=>add(v,8));add(0,Math.min(4,274*8-bits.length));while(bits.length%8)bits.push(0);let data=[];for(let i=0;i<bits.length;i+=8)data.push(bits.slice(i,i+8).reduce((a,v)=>a*2+v,0));for(let i=0;data.length<274;i++)data.push(i%2?17:236);const ex=[],lg=Array(256);let z=1;for(let i=0;i<255;i++){ex[i]=z;lg[z]=i;z<<=1;if(z&256)z^=285}for(let i=255;i<512;i++)ex[i]=ex[i-255];let gen=[1];for(let i=0;i<18;i++){const g=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){g[j]^=gen[j];g[j+1]^=ex[(lg[gen[j]]+i)%255]}gen=g}const blocks=[];let at=0;for(const len of [68,68,69,69]){const d=data.slice(at,at+=len),rem=Array(18).fill(0);for(const v of d){const f=v^rem.shift();rem.push(0);if(f)for(let j=0;j<18;j++)rem[j]^=ex[(lg[f]+lg[gen[j+1]])%255]}blocks.push([d,rem])}const words=[];for(let i=0;i<69;i++)for(const q of blocks)if(i<q[0].length)words.push(q[0][i]);for(let i=0;i<18;i++)for(const q of blocks)words.push(q[1][i]);const stream=[];words.forEach(v=>{for(let i=7;i>=0;i--)stream.push(v>>i&1)});let k=0,up=true;for(let c=N-1;c>0;c-=2){if(c===6)c--;for(let i=0;i<N;i++){const row=up?N-1-i:i;for(let j=0;j<2;j++)if(m[row][c-j]===null){let v=stream[k++]||0;if((row+c-j)%2===0)v^=1;set(row,c-j,!!v)}}up=!up}const fmt=0x77c4;for(let i=0;i<15;i++){const v=!!(fmt>>i&1);if(i<6)set(i,8,v);else if(i<8)set(i+1,8,v);else set(N-15+i,8,v);if(i<8)set(8,N-1-i,v);else if(i<9)set(8,15-i,v);else set(8,14-i,v)}let ver=10<<12;for(let x=ver;x>=0x1000;x--)if(x&0x1000)ver^=0x1f25<<(Math.floor(Math.log2(x))-12);ver=(10<<12)|ver;for(let i=0;i<18;i++){const v=!!(ver>>i&1);set(Math.floor(i/3),N-11+i%3,v);set(N-11+i%3,Math.floor(i/3),v)}let rect="";for(let y=0;y<N;y++)for(let x=0;x<N;x++)if(m[y][x])rect+='<rect x="'+(x+4)+'" y="'+(y+4)+'" width="1" height="1"/>';return '<svg class="qr" viewBox="0 0 65 65" role="img" aria-label="Scannable authenticator QR code" xmlns="http://www.w3.org/2000/svg"><rect width="65" height="65" fill="white"/><g fill="black">'+rect+"</g></svg>"}
function start(){step.textContent="Step 3 of 4 · Add authenticator";app.innerHTML='<h1>Add your authenticator</h1><p>An authenticator app makes a 6-digit code for you.</p><button id="go">Show setup details →</button>';bind("go",async()=>details(await api("/api/authenticator/start",{method:"POST"})))}
function details(d){if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));step.textContent="Step 3 of 4 · Add authenticator";fixture("Authenticator verification code",d.testAuthenticatorCode);app.innerHTML='<h1>Set up your authenticator</h1><button class="secondary" id="qr">▣ Show QR code</button><div id="box" hidden></div><p>Setup link</p><div class="code" id="u"></div><button class="secondary" id="copy">Copy setup link</button><form id="f"><label>Code from your authenticator<input id="otp" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6"></label><button>Confirm authenticator →</button></form>';u.textContent=d.provisioningUri;bind("qr",()=>{box.hidden=!box.hidden;if(!box.innerHTML)box.innerHTML=qrSvg(d.provisioningUri)});bind("copy",()=>navigator.clipboard?.writeText(d.provisioningUri).then(()=>log("Setup link copied.")));document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const x=await api("/api/authenticator/verify",{method:"POST",body:{code:otp.value}});if(!x.ok)return app.insertAdjacentHTML("afterbegin",msg(x.message));backup()}}
function backup(){step.textContent="Step 4 of 4 · Save recovery codes";app.innerHTML='<h1>Save recovery codes</h1><p>Recovery codes help if you lose your phone. Each works once.</p><button id="make">Create recovery codes →</button>';bind("make",async()=>{const d=await api("/api/backup/generate",{method:"POST"});app.innerHTML='<h1>Your recovery codes</h1><div class="code">'+d.codes.join("<br>")+'</div><button id="done">I saved my codes →</button>';bind("done",complete)})}
async function complete(){const d=await api("/api/mfa/status");step.textContent="Complete · MFA settings";app.innerHTML='<h1>✅ MFA is ready</h1><p>Your authenticator is on. You have '+d.backupCount+' unused recovery codes.</p><button id="out">Log out</button>';bind("out",async()=>{await api("/api/logout",{method:"POST"});location.reload()})}
(async()=>{const d=await api("/api/session");csrf=d.csrf;testMode=!!d.testMode;if(d.progress==="identity")identity();else if(d.progress==="details")details(await api("/api/authenticator/details"));else if(d.progress==="backup")backup();else if(d.progress==="complete")complete();else if(d.progress==="start")start();else sign()})()})();</script></body></html>`, { headers: { ...headers(r, nonce), "content-type": "text/html; charset=utf-8", ...(made ? { "set-cookie": cookie(s.id) } : {}) } });
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
