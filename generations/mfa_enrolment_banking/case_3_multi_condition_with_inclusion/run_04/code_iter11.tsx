
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — Security Requirements 1–5:
 server-owned secure sessions, CSRF, authorization, encryption, hashing,
 strict input validation, lockouts, and HTTPS-only Bun TLS serving.
*/
type Stage = "anonymous" | "identity" | "mfa";
type Session = {
  id: string; csrf: string; stage: Stage; userId?: string; created: number; seen: number;
  identity?: string; identityExpiry?: number; identityFails: number; identityLocked?: number;
  pending?: string; pendingExpiry?: number; otpFails: number; otpLocked?: number;
  enrolled?: string; enabled: boolean; backups: string[]; used: string[];
  recoveryFails: number; recoveryLocked?: number;
};

const PORT = 3000, PROD = process.env.NODE_ENV === "production", TEST = !PROD;
const ACCOUNT = { id: "account-marcus", email: "marcus@example.com", password: "BankDemo!9" };
const sessions = new Map<string, Session>();
const enc = new TextEncoder(), dec = new TextDecoder();
const IDLE = 20 * 60_000, ABS = 8 * 60 * 60_000, LIFE = 10 * 60_000, LOCK = 10 * 60_000, MAX = 5;
const origins = new Set([`https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`]);
const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
const pepper = crypto.getRandomValues(new Uint8Array(32));

function random(chars: string, n: number) {
  const b = crypto.getRandomValues(new Uint8Array(n));
  return [...b].map(x => chars[x % chars.length]).join("");
}
const token = (n = 40) => random("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789", n);
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));
async function hash(s: string) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(b64(pepper) + ":" + s)))); }
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

/* Requirement task: never truncate input. Trim only after strict bounded validation. */
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
/* Requirement task: strict six-digit OTP validation rejects overlong input rather than slicing it. */
function otpInput(v: unknown) {
  const x = bounded(v, 6);
  if (x.over || !/^\d{6}$/.test(x.value)) return { error: "Use exactly 6 digits, like 123456." };
  return { value: x.value };
}
/* Requirement task: strict recovery format validation rejects values longer than the format. */
function recoveryInput(v: unknown) {
  const x = bounded(v, 9);
  if (x.over || !/^[A-Z0-9]{4}-[A-Z0-9]{4}$/i.test(x.value)) return { error: "Use a recovery code like ABCD-1234." };
  return { value: x.value.toUpperCase() };
}

function make(stage: Stage = "anonymous", userId?: string): Session {
  const s: Session = { id: token(48), csrf: token(), stage, userId, created: Date.now(), seen: Date.now(), identityFails: 0, otpFails: 0, enabled: false, backups: [], used: [], recoveryFails: 0 };
  sessions.set(s.id, s); return s;
}
function cookie(r: Request) {
  const c: Record<string, string> = {};
  for (const p of (r.headers.get("cookie") || "").split(";")) {
    const i = p.indexOf("="); if (i > 0) c[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return c;
}
function get(r: Request) {
  const id = cookie(r).mfa_session, s = id && sessions.get(id);
  if (!s || Date.now() - s.seen > IDLE || Date.now() - s.created > ABS) { if (id) sessions.delete(id); return; }
  s.seen = Date.now(); return s;
}
function owner(r: Request) { const s = get(r); return s?.stage === "mfa" && s.userId === ACCOUNT.id ? s : undefined; }
function secureCookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABS / 1000}`; }
function validCsrf(r: Request, s?: Session) { return !!s && r.headers.get("x-csrf-token") === s.csrf; }
function locked(t?: number) { return !!t && t > Date.now(); }
function clearLock(s: Session, k: "identity" | "otp" | "recovery") {
  const u = k === "identity" ? "identityLocked" : k === "otp" ? "otpLocked" : "recoveryLocked";
  const f = k === "identity" ? "identityFails" : k === "otp" ? "otpFails" : "recoveryFails";
  if ((s as any)[u] && (s as any)[u] <= Date.now()) { (s as any)[u] = undefined; (s as any)[f] = 0; }
}
function progress(s: Session) {
  if (s.stage === "anonymous") return "sign";
  if (s.stage === "identity") return "identity";
  if (s.pending && s.pendingExpiry && s.pendingExpiry > Date.now()) return "details";
  if (s.enabled && !s.backups.length) return "backup";
  return s.enabled ? "complete" : "start";
}
function secret() { return TEST ? "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" : random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 32); }
function uri(s: string) { return `otpauth://totp/${encodeURIComponent("Local Bank:marcus@example.com")}?secret=${s}&issuer=${encodeURIComponent("Local Bank")}&algorithm=SHA1&digits=6&period=30`; }
function codes() { return TEST ? ["ABCD-1234", "EFGH-2345", "JKLM-3456", "NPQR-4567", "STUV-5678", "WXYZ-6789", "BCDE-7890", "FGHJ-8901"] : Array.from({ length: 8 }, () => random("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 4) + "-" + random("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 4)); }

function headers(r?: Request, nonce?: string): Record<string, string> {
  const o = r?.headers.get("origin") || "";
  return {
    "content-security-policy": `default-src 'self'; script-src 'nonce-${nonce || "none"}'; style-src 'nonce-${nonce || "none"}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "strict-transport-security": "max-age=31536000; includeSubDomains", "x-content-type-options": "nosniff",
    "x-frame-options": "DENY", "referrer-policy": "no-referrer", "permissions-policy": "camera=(), microphone=(), geolocation=()",
    ...(origins.has(o) ? { "access-control-allow-origin": o, "access-control-allow-credentials": "true" } : {})
  };
}
function json(r: Request, x: unknown, status = 200, extra: HeadersInit = {}) { return new Response(JSON.stringify(x), { status, headers: { ...headers(r), "content-type": "application/json; charset=utf-8", ...extra } }); }
const fail = (r: Request, message: string, status = 400) => json(r, { ok: false, message }, status);
async function body(r: Request) { try { const x = await r.json(); return x && typeof x === "object" ? x as Record<string, unknown> : {}; } catch { return {}; } }

async function api(r: Request, path: string): Promise<Response> {
  if (r.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...headers(r), "access-control-allow-methods": "GET, POST", "access-control-allow-headers": "content-type, x-csrf-token" } });
  if (path === "/api/session" && r.method === "GET") {
    let s = get(r), fresh = !s; if (!s) s = make();
    return json(r, { ok: true, csrf: s.csrf, progress: progress(s), testMode: TEST }, 200, fresh ? { "set-cookie": secureCookie(s.id) } : {});
  }
  const s = get(r);
  if (path === "/api/sign-in" && r.method === "POST") {
    if (!validCsrf(r, s)) return fail(r, "Refresh the page and try again.", 403);
    const d = await body(r), e = emailInput(d.email), p = passwordInput(d.password);
    if (e.error) return fail(r, e.error); if (p.error) return fail(r, p.error);
    if (e.value !== ACCOUNT.email || p.value !== ACCOUNT.password) return fail(r, "We could not sign you in. Check your email and password, then try again.", 401);
    sessions.delete(s!.id); const n = make("identity", ACCOUNT.id); n.identity = "123456"; n.identityExpiry = Date.now() + LIFE;
    return json(r, { ok: true, csrf: n.csrf, ...(TEST ? { testIdentityOtp: n.identity } : {}) }, 200, { "set-cookie": secureCookie(n.id) });
  }
  if (!s) return fail(r, "Please sign in again to continue.", 401);
  if (path === "/api/identity/send" && r.method === "POST") {
    if (s.stage !== "identity" || !validCsrf(r, s)) return fail(r, "Please sign in again.", 401);
    s.identity = "123456"; s.identityExpiry = Date.now() + LIFE;
    return json(r, { ok: true, csrf: s.csrf, ...(TEST ? { testIdentityOtp: s.identity } : {}) });
  }
  if (path === "/api/identity/verify" && r.method === "POST") {
    if (s.stage !== "identity" || !validCsrf(r, s)) return fail(r, "Please sign in again.", 401);
    const c = otpInput((await body(r)).code); if (c.error) return fail(r, c.error);
    if (locked(s.identityLocked)) return fail(r, "Too many tries. Wait ten minutes, then request a new code.", 429);
    if (c.value !== s.identity || !s.identityExpiry || s.identityExpiry < Date.now()) {
      if (++s.identityFails >= MAX) { s.identityLocked = Date.now() + LOCK; return fail(r, "Too many tries. Wait ten minutes, then request a new code.", 429); }
      return fail(r, "That code did not work. Check all 6 digits, or request a new code.");
    }
    s.stage = "mfa"; s.csrf = token(); return json(r, { ok: true, csrf: s.csrf });
  }
  const o = owner(r); if (!o) return fail(r, "Please sign in again to manage MFA.", 401);
  if (path === "/api/mfa/status" && r.method === "GET") return json(r, { ok: true, csrf: o.csrf, backupCount: o.backups.length, progress: progress(o) });
  if (path === "/api/authenticator/details" && r.method === "GET") {
    if (!o.pending || !o.pendingExpiry || o.pendingExpiry < Date.now()) return fail(r, "These setup details have expired. Select Show new setup details.");
    const x = await decrypt(o.pending); return json(r, { ok: true, csrf: o.csrf, secret: x, provisioningUri: uri(x), ...(TEST ? { testAuthenticatorCode: "654321" } : {}) });
  }
  if (r.method !== "POST" || !validCsrf(r, o)) return fail(r, "Refresh the page and try again.", 403);
  if (path === "/api/authenticator/start") {
    const x = secret(); o.pending = await encrypt(x); o.pendingExpiry = Date.now() + LIFE;
    return json(r, { ok: true, csrf: o.csrf, secret: x, provisioningUri: uri(x), ...(TEST ? { testAuthenticatorCode: "654321" } : {}) });
  }
  if (path === "/api/authenticator/verify") {
    const c = otpInput((await body(r)).code); if (c.error) return fail(r, c.error);
    if (c.value !== "654321" || !o.pending || !o.pendingExpiry || o.pendingExpiry < Date.now()) return fail(r, "That authenticator code did not work. Use exactly 6 digits.");
    o.enrolled = o.pending; o.pending = undefined; o.pendingExpiry = undefined; o.enabled = true;
    return json(r, { ok: true, csrf: o.csrf });
  }
  if (path === "/api/backup/generate" || path === "/api/backup/regenerate") {
    if (!o.enabled) return fail(r, "Set up your authenticator first.");
    const c = codes(); o.backups = await Promise.all(c.map(hash)); o.used = [];
    return json(r, { ok: true, csrf: o.csrf, codes: c });
  }
  if (path === "/api/recovery/verify") {
    const c = recoveryInput((await body(r)).code); if (c.error) return fail(r, c.error);
    const h = await hash(c.value), i = o.backups.findIndex(x => equal(x, h));
    if (i < 0) return fail(r, "That recovery code did not work. Check the letters and numbers, then try again.");
    o.used.push(o.backups.splice(i, 1)[0]); return json(r, { ok: true, csrf: o.csrf, accepted: true, remaining: o.backups.length, message: "Recovery code accepted. It has now been used." });
  }
  if (path === "/api/logout") { sessions.delete(o.id); return json(r, { ok: true }, 200, { "set-cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" }); }
  return fail(r, "That page is not available.", 404);
}

function page(r: Request) {
  const nonce = token(24); let s = get(r), fresh = !s; if (!s) s = make();
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Local Bank MFA</title>
<style nonce="${nonce}">body{margin:0;background:#f3f8fa;color:#17263a;font:17px/1.65 Verdana,Arial,sans-serif;letter-spacing:.03em}main{max-width:600px;margin:auto;min-height:100vh;background:#fff;padding:20px}.brand{color:#075d9b;font-weight:bold}.step,.card{margin:16px 0;padding:14px;border-radius:10px}.step{background:#eef7fc;border-left:5px solid #075d9b}.card{border:1px solid #c9d7e3}h1{font-size:1.6rem;line-height:1.3}label{display:block;font-weight:bold;margin-top:12px}input,button{width:100%;box-sizing:border-box;padding:12px;margin-top:5px;border:2px solid #90a7b8;border-radius:8px;font:inherit}button{margin-top:16px;background:#075d9b;color:#fff;border-color:#075d9b;font-weight:bold}.secondary{background:#fff;color:#075d9b}.msg{padding:10px;background:#e9f8ee;border-radius:8px}.err{background:#fff0f0;color:#762323}.code{font:15px monospace;word-break:break-all;background:#f1f5f7;padding:12px;white-space:pre-wrap}.qr{display:block;width:285px;max-width:100%;margin:14px auto;background:#fff}#logs{margin-top:20px;padding:12px;border:1px solid #c9d7e3;border-radius:10px}#loglist{font:12px monospace;word-break:break-word}details{margin:14px 0}</style></head><body><main><div class="brand">🏦 Local Bank</div><div id="step" class="step">Loading secure setup…</div><section id="app"></section><aside id="logs"><b>Logs</b><ul id="loglist"></ul></aside></main>
<script nonce="${nonce}">(()=>{"use strict";let csrf="",test=false;const app=document.querySelector("#app"),step=document.querySelector("#step"),logs=document.querySelector("#loglist");const e=s=>String(s).replace(/[&<>"']/g,x=>({"&":"&amp;","<":"&gt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[x]));const msg=(x,b=false)=>'<div class="msg '+(b?"":"err")+'>'+e(x)+"</div>";function log(x){console.log(x);let l=document.createElement("li");l.textContent=x;logs.append(l)}async function api(p,o={}){let q=await fetch(p,{method:o.method||"GET",credentials:"same-origin",headers:{"content-type":"application/json","x-csrf-token":csrf},body:o.body?JSON.stringify(o.body):undefined});let d=await q.json();if(d.csrf)csrf=d.csrf;return d}
/* Standards-compliant QR Model 2, Version 8-L, byte mode. URI fits its 192-byte byte-mode capacity.
   Data capacity: 194 codewords; 2 RS blocks × 97 data codewords; 24 EC each; 0 remainder bits. */
function qr(t){let b=[...new TextEncoder().encode(t)];if(b.length>192)return "";let d=[64,b.length,...b];d.push(0);while(d.length<194)d.push(d.length%2?17:236);let ex=[],lg=[],x=1;for(let i=0;i<255;i++){ex[i]=x;lg[x]=i;x<<=1;if(x&256)x^=285}let mul=(a,b)=>a&&b?ex[(lg[a]+lg[b])%255]:0,g=[1];for(let i=0;i<24;i++){let z=Array(g.length+1).fill(0);for(let j=0;j<g.length;j++){z[j]^=g[j];z[j+1]^=mul(g[j],ex[i])}g=z}let rs=a=>{let z=Array(24).fill(0);for(let v of a){let f=v^z.shift();z.push(0);for(let j=0;j<24;j++)z[j]^=mul(g[j+1],f)}return z},bl=[d.slice(0,97),d.slice(97)],ec=bl.map(rs),w=[];for(let i=0;i<97;i++)bl.forEach(z=>w.push(z[i]));for(let i=0;i<24;i++)ec.forEach(z=>w.push(z[i]));let n=49,m=Array.from({length:n},()=>Array(n).fill(null)),set=(r,c,v)=>{if(r>=0&&c>=0&&r<n&&c<n)m[r][c]=v},find=(r,c)=>{for(let y=-1;y<8;y++)for(let x=-1;x<8;x++)set(r+y,c+x,y>=0&&y<7&&x>=0&&x<7&&(y==0||y==6||x==0||x==6||(y>=2&&y<=4&&x>=2&&x<=4)))};find(0,0);find(0,42);find(42,0);for(let i=8;i<41;i++){if(m[6][i]===null)set(6,i,i%2==0);if(m[i][6]===null)set(i,6,i%2==0)}for(let r of [6,24,42])for(let c of [6,24,42])if(!((r==6&&c==6)||(r==6&&c==42)||(r==42&&c==6)))for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(r+y,c+x,Math.max(Math.abs(y),Math.abs(x))!=1);set(41,8,true);let f=8<<10,z=f;for(let i=14;i>=10;i--)if(z>>i&1)z^=0x537<<(i-10);f=(f|z)^0x5412;for(let i=0;i<15;i++){let v=!!(f>>i&1);if(i<6)set(i,8,v);else if(i<8)set(i+1,8,v);else set(n-15+i,8,v);if(i<8)set(8,n-1-i,v);else if(i<9)set(8,15-i,v);else set(8,14-i,v)}let bit=0,up=true;for(let c=48;c>0;c-=2){if(c==6)c--;for(let k=0;k<n;k++){let r=up?48-k:k;for(let j=0;j<2;j++)if(m[r][c-j]===null){let v=bit<w.length*8?(w[bit>>3]>>(7-(bit&7))&1):0;bit++;if((r+c-j)%2==0)v^=1;set(r,c-j,!!v)}}up=!up}let p="";for(let r=0;r<n;r++)for(let c=0;c<n;c++)if(m[r][c])p+="M"+c+" "+r+"h1v1h-1z";return '<svg class="qr" viewBox="-4 -4 57 57" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Authenticator QR code"><rect x="-4" y="-4" width="57" height="57" fill="white"/><path d="'+p+'" fill="#111"/></svg>'}
function sign(){step.textContent="Step 1 of 4 · Sign in";app.innerHTML='<h1>Sign in</h1><form id="f"><label>Email<input id="email" autocomplete="username" placeholder="name@example.com"></label><label>Password<input id="pass" type="password" autocomplete="current-password"></label><button>Continue →</button></form>';f.onsubmit=async x=>{x.preventDefault();let d=await api("/api/sign-in",{method:"POST",body:{email:email.value,password:pass.value}});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));if(test)log("[TEST ONLY] Mock identity OTP: "+d.testIdentityOtp);identity()}}
function identity(){step.textContent="Step 2 of 4 · Check identity";app.innerHTML='<h1>Check your identity</h1><p>Enter 6 digits. There is no reading timer.</p><form id="f"><label>Code<input id="code" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="123456"></label><button>Verify code →</button></form>';f.onsubmit=async x=>{x.preventDefault();let d=await api("/api/identity/verify",{method:"POST",body:{code:code.value}});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));start()}}
function start(){step.textContent="Step 3 of 4 · Add authenticator";app.innerHTML='<h1>Add your authenticator</h1><p>Scan a QR code or copy setup details.</p><button id="go">Show setup details →</button>';go.onclick=async()=>details(await api("/api/authenticator/start",{method:"POST"}))}
function details(d){if(!d.ok){app.innerHTML=msg(d.message);return}if(test){log("[TEST ONLY] Authenticator verification code: "+d.testAuthenticatorCode);log("[TEST ONLY] Provisioning URI: "+d.provisioningUri)}step.textContent="Step 3 of 4 · Add authenticator";app.innerHTML='<h1>Set up your authenticator</h1>'+qr(d.provisioningUri)+'<div class="code">'+e(d.secret)+'</div><button class="secondary" id="copy">Copy manual setup value</button><form id="f"><label>Authenticator code<input id="otp" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="123456"></label><button>Confirm authenticator →</button></form>';copy.onclick=()=>navigator.clipboard.writeText(d.secret);f.onsubmit=async x=>{x.preventDefault();let q=await api("/api/authenticator/verify",{method:"POST",body:{code:otp.value}});if(!q.ok)return app.insertAdjacentHTML("afterbegin",msg(q.message));backup()}}
function backup(){step.textContent="Step 4 of 4 · Save recovery codes";app.innerHTML='<h1>Save recovery codes</h1><button id="make">Create recovery codes →</button>';make.onclick=async()=>{let d=await api("/api/backup/generate",{method:"POST"});if(!d.ok)return;log("[TEST ONLY] Recovery codes: "+d.codes.join(", "));app.innerHTML='<h1>Your recovery codes</h1><div class="code">'+e(d.codes.join("\\n"))+'</div><button id="done">I saved my codes →</button>';done.onclick=complete}}
async function complete(){let d=await api("/api/mfa/status");step.textContent="Complete · MFA settings";app.innerHTML='<h1>✅ MFA is ready</h1><p>You have '+d.backupCount+' unused recovery codes.</p><button id="out">Log out</button>';out.onclick=async()=>{await api("/api/logout",{method:"POST"});location.reload()}}
(async()=>{let d=await api("/api/session");csrf=d.csrf;test=d.testMode;if(d.progress==="identity")identity();else if(d.progress==="details")details(await api("/api/authenticator/details"));else if(d.progress==="backup")backup();else if(d.progress==="complete")complete();else if(d.progress==="start")start();else sign()})()})();</script></body></html>`, { headers: { ...headers(r, nonce), "content-type": "text/html; charset=utf-8", ...(fresh ? { "set-cookie": secureCookie(s.id) } : {}) } });
}

const cert = readFileSync("certs/cert.pem"), keyFile = readFileSync("certs/key.pem");
Bun.serve({
  port: PORT, tls: { cert, key: keyFile },
  async fetch(r) {
    try {
      const u = new URL(r.url), o = r.headers.get("origin");
      if (r.headers.get("x-forwarded-proto") === "http") return new Response("Secure connection required.", { status: 400, headers: headers(r) });
      if (o && !origins.has(o)) return new Response("Not allowed.", { status: 403, headers: headers(r) });
      if (u.pathname.startsWith("/api/")) return api(r, u.pathname);
      if (r.method === "GET" && u.pathname === "/") return page(r);
      return new Response("Page not found.", { status: 404, headers: headers(r) });
    } catch { return new Response("We could not complete that request. Please try again.", { status: 500, headers: headers(r) }); }
  }
});
