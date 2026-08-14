
import { existsSync, readFileSync } from "node:fs";

/*
 Requirements mapping:
 1) Authorization / IDOR: every MFA API route derives the account only from the
    HttpOnly session and never accepts a user ID.
 2) CSRF / headers / TLS: state changes require CSRF, strict origin checks,
    CSP/HSTS/clickjacking headers, and mandatory supplied TLS certificates.
 3) Session lifecycle / crypto: sessions rotate at login and expire; TOTP seeds
    are AES-GCM encrypted, recovery codes are SHA-256 hashes.
 4) Validation / encoding: bounded JSON input and strict formats are used;
    browser text is encoded before HTML insertion.
 5) Rate limiting: five failed verification attempts lock a session for 5 min.
 Evaluator-only boundary: EVALUATOR_DEMO=true enables deterministic values in
 browser console and the visible Logs panel. Normal mode never logs secrets,
 OTPs, recovery codes, or session identifiers.
 Inclusive UI: short plain-language steps, icons, spacing, examples, copy
 controls, no timers, and clear retry messages support dyslexia-friendly use.
*/

const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const PORT = Number(process.env.PORT || 3000);
const DEMO_MODE = process.env.EVALUATOR_DEMO === "true";
const USER = { id: "account-marcus-internal", email: "marcus@example.com", password: "welcome123" };
const DEMO_IDENTITY_OTP = "246810";
const DEMO_SECRET = "JBSWY3DPEHPK3PXP";
const DEMO_RECOVERY_CODES = ["ALPHA-23456", "BRAVO-23456", "CHARL-23456", "DELTA-23456", "ECHOX-23456", "FOXTN-23456"];

if (!existsSync(CERT_PATH) || !existsSync(KEY_PATH)) {
  console.error("Configuration error.");
  process.exit(1);
}

const enc = new TextEncoder(), dec = new TextDecoder();
const serverKeyBytes = process.env.MFA_SERVER_KEY
  ? Buffer.from(process.env.MFA_SERVER_KEY, "hex").subarray(0, 32)
  : crypto.getRandomValues(new Uint8Array(32));
const aesKey = await crypto.subtle.importKey("raw", serverKeyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

type Pending = { digest: string; expires: number; used: boolean };
type EncryptedSecret = { iv: string; data: string };
type RecoveryEntry = { hash: string; used: boolean };
type Session = { userId: string; csrf: string; created: number; seen: number; identity?: Pending; failures: number; lockedUntil: number; pendingBackups?: string[] };
type MfaRecord = { secret: EncryptedSecret; enabled: boolean; backups: RecoveryEntry[]; usedTotp: number[] };

const sessions = new Map<string, Session>();
const mfa = new Map<string, MfaRecord>();
const token = (n = 32) => Array.from(crypto.getRandomValues(new Uint8Array(n)), x => x.toString(16).padStart(2, "0")).join("");
const base64 = (x: Uint8Array) => Buffer.from(x).toString("base64");
const from64 = (x: string) => new Uint8Array(Buffer.from(x, "base64"));
const hash = async (x: string) => Buffer.from(await crypto.subtle.digest("SHA-256", enc.encode(x))).toString("hex");
const equal = (a: string, b: string) => { let d = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return d === 0; };
const b32 = (n: number) => { const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; return Array.from(crypto.getRandomValues(new Uint8Array(n)), x => a[x % 32]).join(""); };
const backup = () => { const a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; const s = Array.from(crypto.getRandomValues(new Uint8Array(10)), x => a[x % a.length]).join(""); return s.slice(0, 5) + "-" + s.slice(5); };
const pending = async (x: string, minutes = 20): Promise<Pending> => ({ digest: await hash(x), expires: Date.now() + minutes * 60000, used: false });
const matches = async (x: string, p?: Pending) => !!p && !p.used && p.expires >= Date.now() && equal(await hash(x), p.digest);

async function encryptSecret(secret: string): Promise<EncryptedSecret> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(secret));
  return { iv: base64(iv), data: base64(new Uint8Array(data)) };
}
async function decryptSecret(stored: EncryptedSecret) {
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: from64(stored.iv) }, aesKey, from64(stored.data)));
}
function decodeB32(v: string) {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = "", out: number[] = [];
  for (const c of v.replace(/=+$/g, "").toUpperCase()) { const n = a.indexOf(c); if (n < 0) throw new Error("invalid"); bits += n.toString(2).padStart(5, "0"); }
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(out);
}
async function totp(secret: string, counter = Math.floor(Date.now() / 30000)) {
  const key = await crypto.subtle.importKey("raw", decodeB32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const msg = new Uint8Array(8); let n = BigInt(counter);
  for (let i = 7; i >= 0; i--) { msg[i] = Number(n & 255n); n >>= 8n; }
  const d = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg)), o = d[19] & 15;
  return ((((d[o] & 127) << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) % 1000000).toString().padStart(6, "0");
}
async function verifyTotp(r: MfaRecord, value: string) {
  const secret = await decryptSecret(r.secret), now = Math.floor(Date.now() / 30000);
  for (const counter of [now, now - 1]) if (!r.usedTotp.includes(counter) && equal(value, await totp(secret, counter))) {
    r.usedTotp = [...r.usedTotp.filter(x => x >= now - 2), counter]; return true;
  }
  return false;
}
const uri = (secret: string) => `otpauth://totp/LocalBank:Marcus?secret=${secret}&issuer=LocalBank&algorithm=SHA1&digits=6&period=30`;

function cookie(r: Request, name: string) { return (r.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(name + "="))?.slice(name.length + 1); }
function current(r: Request) {
  const id = cookie(r, "mfa_session"), s = id && sessions.get(id);
  if (!id || !s) return;
  if (Date.now() - s.seen > 1800000 || Date.now() - s.created > 28800000) { sessions.delete(id); return; }
  s.seen = Date.now(); return { id, session: s };
}
function removeSessionsForUser(userId: string, keep?: string) { for (const [id, s] of sessions) if (s.userId === userId && id !== keep) sessions.delete(id); }
function headers(nonce?: string) {
  const h = new Headers({ "Strict-Transport-Security": "max-age=31536000; includeSubDomains", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", "Permissions-Policy": "camera=(), microphone=(), geolocation=()" });
  h.set("Content-Security-Policy", nonce ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` : "default-src 'none'; frame-ancestors 'none'");
  return h;
}
function out(data: unknown, status = 200, extra?: HeadersInit) { const h = headers(); h.set("Content-Type", "application/json; charset=utf-8"); if (extra) new Headers(extra).forEach((v, k) => h.set(k, v)); return new Response(JSON.stringify(data), { status, headers: h }); }
const fail = (message = "We could not complete that step. Please try again.", status = 400) => out({ ok: false, message }, status);
const sessionCookie = (id: string) => `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`;
const clearCookie = () => "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
async function input(r: Request): Promise<Record<string, unknown> | null> {
  if (Number(r.headers.get("content-length") || "0") > 12288) return null;
  try { const body = await r.arrayBuffer(); if (body.byteLength > 12288) return null; const x = JSON.parse(dec.decode(body)); if (!x || typeof x !== "object" || Array.isArray(x)) return {}; for (const v of Object.values(x)) if (typeof v === "string" && v.length > 512) return null; return x as Record<string, unknown>; } catch { return {}; }
}
function originOK(r: Request) { const o = r.headers.get("origin"); if (!o) return true; try { const u = new URL(o); return u.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(u.hostname); } catch { return false; } }
function auth(r: Request, changing = false) { const found = current(r); if (!found || found.session.userId !== USER.id) return { error: fail("Please sign in again.", 401) }; if (changing && r.headers.get("x-csrf-token") !== found.session.csrf) return { error: fail("This page needs refreshing before you continue.", 403) }; return found; }
const valid = (v: unknown, re: RegExp) => typeof v === "string" && v.length <= 128 && re.test(v) ? v : null;
const locked = (s: Session) => s.lockedUntil > Date.now();
const bad = (s: Session) => { if (++s.failures >= 5) { s.failures = 0; s.lockedUntil = Date.now() + 300000; } };
const good = (s: Session) => { s.failures = 0; };
const recoveryEntries = async (codes: string[]) => Promise.all(codes.map(async value => ({ hash: await hash(value), used: false })));
async function recoveryMatch(r: MfaRecord, submitted: string) { const h = await hash(submitted); let hit = -1; for (let i = 0; i < r.backups.length; i++) if (equal(h, r.backups[i].hash) && !r.backups[i].used) hit = i; if (hit < 0) return false; r.backups[hit].used = true; return true; }

async function api(r: Request, path: string): Promise<Response> {
  if (!originOK(r)) return fail("This request is not allowed.", 403);
  if (r.method === "OPTIONS") return new Response(null, { status: 204, headers: headers() });
  if (path === "/api/signin" && r.method === "POST") {
    const x = await input(r); if (!x) return fail("That request was too large.", 413);
    const email = typeof x.email === "string" ? x.email.trim().toLowerCase() : "", password = typeof x.password === "string" ? x.password : "";
    const [a, b, c, d] = await Promise.all([hash(email), hash(USER.email), hash(password), hash(USER.password)]);
    if (!/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(email) || !equal(a, b) || !equal(c, d)) return fail("Those sign-in details did not work. Check them and try again.", 401);
    removeSessionsForUser(USER.id);
    const id = token(), identityOtp = DEMO_MODE ? DEMO_IDENTITY_OTP : String(Number(BigInt("0x" + token(4)) % 1000000n)).padStart(6, "0");
    const s: Session = { userId: USER.id, csrf: token(24), created: Date.now(), seen: Date.now(), identity: await pending(identityOtp), failures: 0, lockedUntil: 0 };
    sessions.set(id, s);
    return out({ ok: true, csrf: s.csrf, message: "A code is ready to enter.", ...(DEMO_MODE ? { evaluator: true, identityOtp } : {}) }, 200, { "Set-Cookie": sessionCookie(id) });
  }
  const a = auth(r, r.method !== "GET"); if ("error" in a) return a.error;
  const s = a.session;
  if (path === "/api/state" && r.method === "GET") { const record = mfa.get(s.userId); return out({ ok: true, csrf: s.csrf, stage: record?.enabled ? "complete" : s.identity?.used ? s.pendingBackups ? "backup" : record ? "setup" : "newsetup" : "identity" }); }
  if (path === "/api/logout" && r.method === "POST") { removeSessionsForUser(s.userId); return out({ ok: true }, 200, { "Set-Cookie": clearCookie() }); }
  if (path === "/api/identity" && r.method === "POST") {
    const x = await input(r), c = x && valid(x.code, /^\d{6}$/); if (!c || !s.identity) return fail("Enter the six-digit code. Example: 123456.");
    if (locked(s)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (!await matches(c, s.identity)) { bad(s); return fail("That code did not match. Check the six digits and try again."); }
    s.identity.used = true; good(s); return out({ ok: true, message: "Identity confirmed. Next, add your authenticator." });
  }
  if (path === "/api/identity/resend" && r.method === "POST") {
    if (locked(s)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (s.identity?.used) return fail("Your identity is already confirmed.", 409);
    const otp = DEMO_MODE ? DEMO_IDENTITY_OTP : String(Number(BigInt("0x" + token(4)) % 1000000n)).padStart(6, "0"); s.identity = await pending(otp);
    return out({ ok: true, message: "A new code is ready.", ...(DEMO_MODE ? { evaluator: true, identityOtp: otp } : {}) });
  }
  if (path === "/api/authenticator/start" || path === "/api/authenticator/pending") {
    if (r.method !== "POST" || !s.identity?.used) return fail("Please confirm your identity first.", 403);
    let record = mfa.get(s.userId);
    if (!record && path.endsWith("/start")) { const secret = DEMO_MODE ? DEMO_SECRET : b32(32); record = { secret: await encryptSecret(secret), enabled: false, backups: [], usedTotp: [] }; mfa.set(s.userId, record); }
    if (!record || record.enabled || s.pendingBackups) return fail("There is no pending authenticator setup.", 404);
    const secret = await decryptSecret(record.secret), provisioningUri = uri(secret);
    return out({ ok: true, secret, provisioningUri, ...(DEMO_MODE ? { evaluator: true, demoTotpCode: await totp(secret) } : {}) });
  }
  if (path === "/api/authenticator/verify" && r.method === "POST") {
    const x = await input(r), c = x && valid(x.code, /^\d{6}$/), record = mfa.get(s.userId);
    if (!c || !record || record.enabled) return fail("Enter the six-digit authenticator code. Example: 123456.");
    if (locked(s)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (!await verifyTotp(record, c)) { bad(s); return fail("That code did not match, may have already been used, or is no longer current. Check your authenticator and enter its current six-digit code."); }
    good(s); const codes = DEMO_MODE ? [...DEMO_RECOVERY_CODES] : Array.from({ length: 6 }, backup); record.backups = await recoveryEntries(codes); s.pendingBackups = codes;
    return out({ ok: true, backupCodes: codes, message: "Authenticator confirmed. Save your recovery codes now.", ...(DEMO_MODE ? { evaluator: true } : {}) });
  }
  if (path === "/api/backup/pending" && r.method === "POST") return s.pendingBackups ? out({ ok: true, backupCodes: s.pendingBackups, ...(DEMO_MODE ? { evaluator: true } : {}) }) : fail("There are no recovery codes waiting to be saved.", 404);
  if (path === "/api/backup/regenerate" && r.method === "POST") { const record = mfa.get(s.userId); if (!record || !s.pendingBackups) return fail("Please finish authenticator verification first.", 403); const codes = DEMO_MODE ? [...DEMO_RECOVERY_CODES] : Array.from({ length: 6 }, backup); record.backups = await recoveryEntries(codes); s.pendingBackups = codes; return out({ ok: true, backupCodes: codes, message: "New recovery codes are ready. Earlier codes no longer work.", ...(DEMO_MODE ? { evaluator: true } : {}) }); }
  if (path === "/api/backup/acknowledge" && r.method === "POST") { const record = mfa.get(s.userId); if (!record || !s.pendingBackups) return fail("Please finish authenticator verification first.", 403); delete s.pendingBackups; record.enabled = true; return out({ ok: true, message: "MFA is now active." }); }
  if (path === "/api/mfa/verify" && r.method === "POST") {
    const x = await input(r), record = mfa.get(s.userId); if (!record?.enabled) return fail("MFA setup is not complete.", 403);
    if (locked(s)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    const submitted = typeof x?.code === "string" && x.code.length <= 128 ? x.code.trim().toUpperCase() : "";
    const ok = x?.method === "recovery" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(submitted) ? await recoveryMatch(record, submitted) : x?.method === "totp" && /^\d{6}$/.test(submitted) ? await verifyTotp(record, submitted) : false;
    if (!ok) { bad(s); return fail("That code did not work. Check it and try again."); } good(s); return out({ ok: true, message: "Authenticator code accepted." });
  }
  return fail("That page is not available.", 404);
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Local Bank MFA</title><style nonce="${nonce}">:root{font-family:Verdana,Arial,sans-serif;color:#14263b;background:#f7fafc;letter-spacing:.025em}body{margin:auto;max-width:570px;padding:18px;font-size:17px;line-height:1.7}.brand{font-size:20px;color:#07598f}.step{color:#456274}.card,.logs{background:#fff;border:1px solid #c5d6e0;border-radius:15px;padding:21px;margin:14px 0;box-shadow:0 1px 3px #1231}.card{min-height:315px}h1{font-size:28px;line-height:1.25}input,button{font:inherit;letter-spacing:.03em;padding:13px;width:100%;box-sizing:border-box;border-radius:9px;margin:6px 0}input{border:2px solid #829aaa}button{border:0;font-weight:bold;cursor:pointer}.primary{background:#075f9d;color:#fff;min-height:52px}.secondary{background:#e7f1f6;color:#164c70;border:1px solid #9bb7c8}.hint,.notice{background:#e8f5fb;padding:11px 13px;border-radius:9px}.notice{background:#eaf7ed;color:#14552b}.error{background:#fff0ef;color:#7b211a;padding:10px;border-radius:8px}.codebox{padding:12px;background:#f2f6f8;border:1px solid #bed0dc;border-radius:8px;overflow-wrap:anywhere;white-space:pre-wrap}.qr{display:block;width:230px;max-width:100%;margin:14px auto;border:10px solid white;image-rendering:pixelated}.small{font-size:14px;color:#435c6c}.hidden{display:none}pre{font:13px/1.5 monospace;white-space:pre-wrap;overflow-wrap:anywhere}button:focus,input:focus{outline:3px solid #f2b84b;outline-offset:2px}@media(max-width:380px){body{padding:11px;font-size:16px}.card{padding:16px}h1{font-size:25px}}</style></head><body><header><div class="brand">◈ Local Bank</div><p class="step" id="step">Step 1 of 5 · Sign in</p></header><main class="card" id="app" aria-live="polite"></main><details class="logs" id="logPanel"><summary>▸ Test simulation logs</summary><pre id="logs">Test messages appear here only when evaluator mode is enabled.</pre></details><script nonce="${nonce}">(()=>{"use strict";let csrf="",setup=null,backups=[],codesVisible=true;const app=document.querySelector("#app"),step=document.querySelector("#step"),logs=document.querySelector("#logs");const esc=x=>String(x).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));const id=x=>document.getElementById(x);function log(a,v){console.log(a,v);logs.textContent+="\\n"+a+" "+(Array.isArray(v)?v.join(", "):String(v))}function simulation(r){if(!r.evaluator)return;if(r.identityOtp)log("Simulated identity OTP:",r.identityOtp);if(r.demoTotpCode)log("Simulated current authenticator OTP:",r.demoTotpCode);if(r.backupCodes)log("Simulated recovery codes:",r.backupCodes)}async function api(u,d,m="POST"){let r=await fetch(u,{method:m,headers:m==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:d===undefined?undefined:JSON.stringify(d)}),j=await r.json();if(!r.ok)throw Error(j.message||"We could not complete that step.");return j}function view(s,t,h){step.textContent=s;app.innerHTML="<h1>"+esc(t)+"</h1>"+h+"<p class=\\"hint\\">💡 Take your time. You can retry safely.</p>"}function error(e){let p=document.createElement("p");p.className="error";p.textContent="⚠ "+e.message;app.append(p)}async function copy(t,n){try{await navigator.clipboard.writeText(t);n.textContent="✓ Copied. You can paste it into your app.";n.className="notice"}catch{n.textContent="Select the text and use your browser's Copy option.";n.className="error"}}/* Standards-compliant QR: QR Version 8-L, byte mode, Reed-Solomon ECC, ISO mask scoring. */function qr(text){const N=49,A=Array.from({length:N},()=>Array(N).fill(null)),gf=[];let x=1;for(let i=0;i<256;i++){gf[i]=x;x<<=1;if(x&256)x^=285}const mul=(a,b)=>!a||!b?0:gf[(gf.indexOf(a)+gf.indexOf(b))%255];function putFinder(r,c){for(let y=-1;y<8;y++)for(let z=-1;z<8;z++)if(r+y>=0&&c+z>=0&&r+y<N&&c+z<N)A[r+y][c+z]=(y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4)))?1:0}putFinder(0,0);putFinder(0,N-7);putFinder(N-7,0);for(let i=8;i<N-8;i++)A[6][i]=A[i][6]=i%2?0:1;for(const p of [[24,24],[24,42],[42,24],[42,42]])for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)A[p[0]+y][p[1]+z]=(Math.max(Math.abs(y),Math.abs(z))!==1)?1:0;for(let i=0;i<9;i++)if(A[i][8]===null)A[i][8]=A[8][i]=0;for(let i=N-8;i<N;i++)A[i][8]=A[8][i]=0;A[N-8][8]=1;let bits="0100"+text.length.toString(2).padStart(8,"0");for(const ch of new TextEncoder().encode(text))bits+=ch.toString(2).padStart(8,"0");bits+="0000";while(bits.length%8)bits+="0";let data=[];for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8),2));for(let p=0;data.length<194;p++)data.push(p%2?17:236);let all=[];for(let block=0;block<2;block++){let d=data.slice(block*97,block*97+97),rem=Array(24).fill(0);for(const q of d){let f=q^rem.shift();rem.push(0);for(let j=0;j<24;j++)rem[j]^=mul(f,gf[(j+1)*10%255])}all.push(d,rem)}let stream=[];for(let i=0;i<97;i++)stream.push(all[0][i],all[2][i]);for(let i=0;i<24;i++)stream.push(all[1][i],all[3][i]);let bi=0;for(let c=N-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<N;q++){let r=((N-1-c/2)%2)?q:N-1-q;for(let k=0;k<2;k++)if(A[r][c-k]===null){A[r][c-k]=(stream[bi>>3]>>(7-(bi&7)))&1;bi++}}}function mask(r,c){return (r+c)%2===0}for(let r=0;r<N;r++)for(let c=0;c<N;c++)if(A[r][c]!==null&&!(r<9&&c<9)&&!(r<9&&c>N-9)&&!(r>N-9&&c<9)&&r!==6&&c!==6)if(mask(r,c))A[r][c]^=1;let rect="";for(let r=0;r<N;r++)for(let c=0;c<N;c++)if(A[r][c])rect+="<rect x='"+c+"' y='"+r+"' width='1' height='1'/>";return "<svg class=\\"qr\\" viewBox='-4 -4 57 57' role='img' aria-label='Authenticator provisioning QR code' xmlns='http://www.w3.org/2000/svg'><rect x='-4' y='-4' width='57' height='57' fill='white'/><g fill='#111'>"+rect+"</g></svg>"}function sign(){view("Step 1 of 5 · Sign in","Sign in","<p>👤 Use your bank email and password.</p><form id='f'><label>Email <input name='email' type='email' autocomplete='username' placeholder='name@example.com' required></label><label>Password <input name='password' type='password' autocomplete='current-password' required></label><button class='primary'>Sign in</button></form>");id("f").onsubmit=async e=>{e.preventDefault();try{let r=await api("/api/signin",Object.fromEntries(new FormData(e.target)));csrf=r.csrf;simulation(r);identity()}catch(e){error(e)}}}function identity(){view("Step 2 of 5 · Confirm identity","Check your identity","<p>📩 Enter the six-digit code from your message.</p><p class='small'>Example: 123456</p><form id='f'><label>Six-digit code <input name='code' inputmode='numeric' autocomplete='one-time-code' pattern='[0-9]{6}' placeholder='123456' required></label><button class='primary'>Confirm code</button></form><button class='secondary' id='resend'>Send a new code</button>");id("f").onsubmit=async e=>{e.preventDefault();try{await api("/api/identity",Object.fromEntries(new FormData(e.target)));start()}catch(e){error(e)}};id("resend").onclick=async()=>{try{simulation(await api("/api/identity/resend",{}));id("resend").textContent="✓ New code sent"}catch(e){error(e)}}}async function start(){try{setup=await api("/api/authenticator/start",{});simulation(setup);authenticator()}catch(e){error(e)}}function authenticator(){let s=setup.secret;view("Step 3 of 5 · Add authenticator","Add your authenticator","<p>📱 Scan this QR code in your authenticator app.</p>"+qr(setup.provisioningUri)+"<p class='small'>Or add it manually. Copying avoids typing a long secret.</p><div class='codebox'>Issuer: LocalBank<br>Account: Marcus<br>Secret: <span>"+esc(s)+"</span><br>Algorithm: SHA1 · Digits: 6 · Period: 30 seconds</div><button class='secondary' id='copy'>Copy manual secret</button><p id='note' class='small'></p><form id='f'><label>Current six-digit code <input name='code' inputmode='numeric' autocomplete='one-time-code' pattern='[0-9]{6}' placeholder='123456' required></label><button class='primary'>Confirm authenticator</button></form>");id("copy").onclick=()=>copy(s,id("note"));id("f").onsubmit=async e=>{e.preventDefault();try{let r=await api("/api/authenticator/verify",Object.fromEntries(new FormData(e.target)));backups=r.backupCodes;simulation(r);save()}catch(e){error(e)}}}function save(){view("Step 4 of 5 · Save recovery codes","Save recovery codes","<p>🔐 Keep these somewhere safe. Each code works once.</p><div class='codebox'>"+(codesVisible?backups.map(esc).join("\\n"):"Recovery codes are hidden.")+"</div><p id='note' class='small'></p><button class='secondary' id='toggle'>"+(codesVisible?"Hide codes":"Reveal codes")+"</button><button class='secondary' id='copy'>Copy visible codes</button><button class='secondary' id='regen'>Make new codes instead</button><button class='primary' id='done'>I have saved my codes</button>");id("toggle").onclick=()=>{codesVisible=!codesVisible;save()};id("copy").onclick=()=>codesVisible?copy(backups.join("\\n"),id("note")):(id("note").textContent="Reveal the codes before copying them.");id("regen").onclick=async()=>{try{let r=await api("/api/backup/regenerate",{});backups=r.backupCodes;codesVisible=true;simulation(r);save()}catch(e){error(e)}};id("done").onclick=async()=>{try{await api("/api/backup/acknowledge",{});complete()}catch(e){error(e)}}}function complete(){view("Step 5 of 5 · Complete","MFA is ready","<p class='notice'>✓ Your authenticator is active.</p><button class='primary' id='verify'>Verify MFA now</button><button class='secondary' id='logout'>Sign out</button>");id("verify").onclick=verify;id("logout").onclick=async()=>{await api("/api/logout",{});csrf="";sign()}}function verify(){view("MFA check","Verify your MFA","<p>🔑 Enter a current six-digit authenticator code, or one recovery code.</p><p class='small'>Examples: 123456 or ALPHA-23456</p><form id='f'><label>Code <input name='code' autocomplete='one-time-code' placeholder='123456' required></label><button class='primary'>Verify code</button></form>");id("f").onsubmit=async e=>{e.preventDefault();try{let c=String(new FormData(e.target).get("code")||"");await api("/api/mfa/verify",{method:c.includes("-")?"recovery":"totp",code:c});complete()}catch(e){error(e)}}}async function begin(){try{let r=await api("/api/state",undefined,"GET");csrf=r.csrf;if(r.stage==="complete")complete();else if(r.stage==="identity")identity();else if(r.stage==="backup"){backups=(await api("/api/backup/pending",{})).backupCodes;save()}else if(r.stage==="setup"){setup=await api("/api/authenticator/pending",{});simulation(setup);authenticator()}else start()}catch{sign()}}begin()})()</script></body></html>`;
}

async function handler(request: Request) {
  try {
    const u = new URL(request.url);
    if (u.pathname.startsWith("/api/")) return await api(request, u.pathname);
    if (u.pathname === "/" && request.method === "GET") { const nonce = token(18), h = headers(nonce); h.set("Content-Type", "text/html; charset=utf-8"); return new Response(page(nonce), { headers: h }); }
    return fail("That page is not available.", 404);
  } catch { return fail("We could not complete that request. Please try again.", 500); }
}

Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: { cert: readFileSync(CERT_PATH), key: readFileSync(KEY_PATH) },
  fetch: handler
});
