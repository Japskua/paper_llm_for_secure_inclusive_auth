
import {
  createCipheriv, createDecipheriv, createHmac, randomBytes, scryptSync,
  timingSafeEqual,
} from "node:crypto";
import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";

/**
 * MFA Enrolment System
 * Requirements 1–5: HTTPS-only, authenticated owner sessions, CSRF, durable encrypted
 * MFA records, standards-compatible TOTP, rate limits, and inclusive mobile UI.
 */

const PORT = 3000;
const ACCOUNT_ID = "account-marcus-001";
const ACCOUNT_EMAIL = "marcus@example.com";
const ACCOUNT_PHONE_SUFFIX = "4821";
const DATA_FILE = "./mfa-records.json";
const KEY_FILE = "./mfa-master-key.bin";
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const VERIFY_EXPIRY_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;
const MAX_FAILURES = 5;
const TOTP_STEP_SECONDS = 30;
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000",
]);

type Session = {
  id: string; csrf: string; accountId?: string; identityVerified: boolean;
  createdAt: number; lastSeenAt: number;
};
type ProtectedValue = { hash: string; expiresAt: number; used: boolean; accountId: string };
type RecoveryHash = { salt: string; hash: string };
type AccountMfa = {
  encryptedSecret?: string; secretIv?: string; secretTag?: string;
  identityCode?: ProtectedValue;
  recoveryHashes: RecoveryHash[];
  mfaEnabled: boolean;
  otpVerified: boolean;
  failures: number;
  lockedUntil: number;
};
type DurableData = { accounts: Record<string, AccountMfa> };

function loadKey() {
  if (existsSync(KEY_FILE)) {
    const key = readFileSync(KEY_FILE);
    if (key.length === 32) return key;
  }
  const key = randomBytes(32);
  writeFileSync(KEY_FILE, key, { mode: 0o600 });
  try { chmodSync(KEY_FILE, 0o600); } catch {}
  return key;
}
const encryptionKey = loadKey();

function loadData(): DurableData {
  try {
    const decoded = JSON.parse(readFileSync(DATA_FILE, "utf8"));
    if (decoded && decoded.accounts && typeof decoded.accounts === "object") return decoded;
  } catch {}
  return { accounts: {} };
}
const durable = loadData();
function persist() {
  writeFileSync(DATA_FILE, JSON.stringify(durable), { mode: 0o600 });
  try { chmodSync(DATA_FILE, 0o600); } catch {}
}
const sessions = new Map<string, Session>();

function now() { return Date.now(); }
function token(bytes = 32) { return randomBytes(bytes).toString("base64url"); }
function equal(a: string, b: string) {
  const aa = Buffer.from(a), bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function shaCode(code: string) {
  return createHmac("sha256", encryptionKey).update(code).digest("hex");
}
function protectedCode(code: string, accountId: string): ProtectedValue {
  return { hash: shaCode(code), expiresAt: now() + VERIFY_EXPIRY_MS, used: false, accountId };
}
function encrypt(value: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return {
    encryptedSecret: encrypted.toString("base64"),
    secretIv: iv.toString("base64"),
    secretTag: cipher.getAuthTag().toString("base64"),
  };
}
function decrypt(record: AccountMfa) {
  if (!record.encryptedSecret || !record.secretIv || !record.secretTag) return "";
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, Buffer.from(record.secretIv, "base64"));
  decipher.setAuthTag(Buffer.from(record.secretTag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(record.encryptedSecret, "base64")), decipher.final(),
  ]).toString("utf8");
}

/* Requirement: random RFC 4648 Base32 secret, with no ambiguous non-Base32 encoding. */
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Secret() {
  const raw = randomBytes(20);
  let bits = 0, value = 0, output = "";
  for (const byte of raw) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { output += BASE32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) output += BASE32[(value << (5 - bits)) & 31];
  return output;
}
function decodeBase32(value: string) {
  let bits = 0, buffer = 0;
  const out: number[] = [];
  for (const char of value.replace(/=|\s/g, "").toUpperCase()) {
    const n = BASE32.indexOf(char);
    if (n < 0) return Buffer.alloc(0);
    buffer = (buffer << 5) | n; bits += 5;
    if (bits >= 8) { out.push((buffer >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
/* RFC 6238 TOTP: HMAC-SHA-1, six digits, 30-second counter; acceptance is ± one step. */
function totp(secret: string, counter = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS)) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", decodeBase32(secret)).update(msg).digest();
  const offset = mac[19] & 15;
  const value = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) | mac[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
function validTotp(secret: string, code: string) {
  const current = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS);
  return [-1, 0, 1].some(offset => equal(totp(secret, current + offset), code));
}
function provisioningUri(secret: string) {
  const issuer = "SafeBank";
  const label = encodeURIComponent(`${issuer}:${ACCOUNT_EMAIL}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

function accountRecord() {
  if (!durable.accounts[ACCOUNT_ID]) {
    durable.accounts[ACCOUNT_ID] = {
      recoveryHashes: [], mfaEnabled: false, otpVerified: false, failures: 0, lockedUntil: 0,
    };
    persist();
  }
  return durable.accounts[ACCOUNT_ID];
}
function createSession(): Session {
  const session: Session = {
    id: token(), csrf: token(), identityVerified: false, createdAt: now(), lastSeenAt: now(),
  };
  sessions.set(session.id, session);
  return session;
}
function sessionCookie(id: string, expiry = false) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict${expiry ? "; Max-Age=0" : ""}`;
}
function headers(extra: Record<string, string> = {}) {
  return {
    "Content-Security-Policy": "default-src 'self'; script-src 'nonce-mfa-app'; style-src 'nonce-mfa-app'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    "Cache-Control": "no-store", ...extra,
  };
}
function json(data: unknown, status = 200, extra: Record<string, string> = {}) {
  return Response.json(data, { status, headers: headers(extra) });
}
function genericError(status = 400) {
  return json({ ok: false, message: "We could not complete that step. Please check the information and try again." }, status);
}
function parseCookies(request: Request) {
  const out: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key && value.length) out[key] = value.join("=");
  }
  return out;
}
function getLiveSession(request: Request) {
  const id = parseCookies(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  if (!session) return null;
  if (now() - session.lastSeenAt > SESSION_IDLE_MS || now() - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(session.id); return null;
  }
  session.lastSeenAt = now();
  return session;
}
function requireOwner(request: Request): Session | Response {
  const session = getLiveSession(request);
  if (!session || session.accountId !== ACCOUNT_ID) return json({ ok: false, message: "Please sign in again to continue." }, 401);
  return session;
}
function csrfOkay(request: Request, session: Session) {
  return TRUSTED_ORIGINS.has(request.headers.get("origin") || "") &&
    equal(request.headers.get("x-csrf-token") || "", session.csrf);
}
function lockMessage(record: AccountMfa) {
  return record.lockedUntil > now() ? "Too many attempts were made. Please wait a few minutes, then try again." : "";
}
function failure(record: AccountMfa) {
  record.failures++;
  if (record.failures >= MAX_FAILURES) {
    record.failures = 0;
    record.lockedUntil = now() + LOCKOUT_MS;
  }
  persist();
}
function clearFailures(record: AccountMfa) { record.failures = 0; persist(); }
function validEmail(value: unknown) { return typeof value === "string" && /^[^\s@]{1,64}@[^\s@]{1,100}\.[^\s@]{2,30}$/.test(value); }
function validPhone(value: unknown) { return typeof value === "string" && /^\d{4}$/.test(value); }
function validOtp(value: unknown) { return typeof value === "string" && /^\d{6}$/.test(value); }
function normalRecovery(value: unknown) {
  if (typeof value !== "string") return "";
  const text = value.toUpperCase().replace(/[^A-Z0-9]/g, "");
  return /^[A-Z0-9]{8}$/.test(text) ? `${text.slice(0, 4)}-${text.slice(4)}` : "";
}
async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const data = await request.json();
    return data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : null;
  } catch { return null; }
}

const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SafeBank MFA setup</title><style nonce="mfa-app">
:root{--ink:#172033;--muted:#566174;--blue:#075cc6;--soft:#eef5ff;--line:#cbd5e1;--good:#087443;--bad:#a32222}*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:var(--ink);font-family:Arial,Verdana,Tahoma,sans-serif;font-size:17px;letter-spacing:.035em;line-height:1.65}main{width:min(100%,560px);min-height:100vh;margin:auto;background:#fff;padding:22px 20px 38px}header{border-bottom:2px solid var(--line);padding-bottom:16px;margin-bottom:22px}.brand{font-size:1.25rem;font-weight:800}.step{color:var(--muted);font-size:.92rem;margin:5px 0 0}h1{font-size:1.7rem;line-height:1.25;margin:0 0 12px}h2{font-size:1.15rem}p,li{max-width:48ch}.card{border:1px solid var(--line);border-radius:14px;padding:18px;margin:18px 0}.notice{background:var(--soft);border-left:5px solid var(--blue)}.success{background:#effbf4;border-left:5px solid var(--good)}.error{background:#fff2f2;border-left:5px solid var(--bad);color:#721c1c}label{display:block;font-weight:700;margin:16px 0 5px}input{width:100%;min-height:51px;border:2px solid #9aa8ba;border-radius:9px;padding:10px 12px;font:inherit;letter-spacing:.08em}input:focus,button:focus,summary:focus{outline:3px solid #f5aa2d;outline-offset:3px}.hint{color:var(--muted);margin:3px 0 14px;font-size:.92rem}button{display:block;width:100%;min-height:53px;border:0;border-radius:9px;padding:12px 15px;font:inherit;font-weight:800;cursor:pointer;margin:15px 0 0}.primary{background:var(--blue);color:#fff}.secondary{color:#044a9e;background:#e7f0fd}.textbutton{color:#044a9e;background:transparent;text-decoration:underline;min-height:40px}.icon{font-size:1.6rem;margin-right:8px}.code{font-family:monospace;font-size:1.03rem;letter-spacing:.1em;overflow-wrap:anywhere;background:#f5f7fa;padding:11px;border-radius:8px}.qr{display:block;width:245px;max-width:100%;height:auto;margin:18px auto;image-rendering:pixelated;background:white}.small{font-size:.9rem;color:var(--muted)}details{margin-top:20px;border-top:1px solid var(--line);padding-top:14px}summary{font-weight:800;cursor:pointer;color:#044a9e}.hidden{display:none}@media(max-width:360px){main{padding:18px 15px}body{font-size:16px}h1{font-size:1.48rem}}
</style></head><body><main><header><div class="brand">🔐 SafeBank</div><p class="step" id="step">MFA setup</p></header><section id="app" aria-live="polite"></section></main>
<script nonce="mfa-app">
(()=>{"use strict";let csrf="";const app=document.getElementById("app"),step=document.getElementById("step");
function esc(v){const d=document.createElement("div");d.textContent=String(v);return d.innerHTML}
function set(label,html){step.textContent=label;app.innerHTML=html}
async function api(path,data){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data||{})});const x=await r.json().catch(()=>({ok:false,message:"Please try again."}));if(r.status===401){csrf="";signin("Your session ended. Please sign in again.")}return x}
function help(){return '<details><summary>Need help?</summary><p>You can take your time. There is no reading time limit. You can retry or ask for a new code.</p><button class="textbutton" data-start type="button">Start again</button></details>'}
function signin(message=""){set("Step 1 of 5 · sign in",'<h1><span class="icon">👋</span>Start MFA setup</h1><p>We will help you add a second check to your account.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<form id=f><label>Email address</label><p class=hint>Example: marcus@example.com</p><input id=email type=email autocomplete=email required><button class=primary>Continue</button></form>'+help());f.onsubmit=async e=>{e.preventDefault();const r=await api("/api/signin",{email});if(r.ok){csrf=r.csrf;identity()}else signin(r.message)}}
function identity(message=""){set("Step 2 of 5 · identity check",'<h1><span class=icon>🪪</span>Check it is you</h1><p>Send a six-digit test code to your phone ending in 4821.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<form id=f><label>Last 4 digits of phone</label><p class=hint>Example: 4821</p><input id=phone inputmode=numeric autocomplete=tel maxlength=4 required><label>Code</label><p class=hint>Example: 123456</p><input id=code inputmode=numeric autocomplete=one-time-code maxlength=6 required><button class=primary>Check code</button></form><button class=secondary id=send>Send or re-send code</button>'+help());send.onclick=async()=>{const r=await api("/api/identity/send",{phone:phone.value});if(r.ok){console.log("Test identity code:",r.testCode);code.focus()}else identity(r.message)};f.onsubmit=async e=>{e.preventDefault();const r=await api("/api/identity/verify",{code:code.value});r.ok?provision():identity(r.message)}}
function qr(uri){const n=49,m=Array.from({length:n},()=>Array(n).fill(null));const put=(x,y,v)=>{if(x>=0&&y>=0&&x<n&&y<n)m[y][x]=v};function finder(x,y){for(let j=-1;j<=7;j++)for(let i=-1;i<=7;i++)put(x+i,y+j,i>=0&&i<=6&&j>=0&&j<=6&&(i===0||i===6||j===0||j===6||(i>=2&&i<=4&&j>=2&&j<=4)))}finder(0,0);finder(n-7,0);finder(0,n-7);for(const p of [24,42])for(const q of [24,42]){if((p===42&&q===24)||(p===24&&q===42)||(p===42&&q===42))continue;for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)put(p+x,q+y,Math.max(Math.abs(x),Math.abs(y))!==1)}for(let i=8;i<n-8;i++){put(i,6,i%2===0);put(6,i,i%2===0)}const bits=[];const add=(v,l)=>{for(let i=l-1;i>=0;i--)bits.push((v>>i)&1)};add(4,4);add(uri.length,8);for(let i=0;i<uri.length;i++)add(uri.charCodeAt(i),8);for(let i=0;i<4&&bits.length<1552;i++)bits.push(0);while(bits.length%8)bits.push(0);let bytes=[];for(let i=0;i<bits.length;i+=8)bytes.push(bits.slice(i,i+8).reduce((a,b)=>a*2+b,0));for(let p=0;bytes.length<194;p++)bytes.push(p%2?0x11:0xec);const exp=[],log=[];let z=1;for(let i=0;i<255;i++){exp[i]=z;log[z]=i;z<<=1;if(z&256)z^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;let gen=[1];for(let i=0;i<24;i++){const g=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){g[j]^=gen[j];g[j+1]^=mul(gen[j],exp[i])}gen=g}const ecc=d=>{const r=Array(24).fill(0);for(const x of d){const f=x^r.shift();r.push(0);for(let j=0;j<24;j++)r[j]^=mul(gen[j+1],f)}return r};const blocks=[bytes.slice(0,97),bytes.slice(97)],es=blocks.map(ecc),stream=[];for(let i=0;i<97;i++)for(const b of blocks)stream.push(b[i]);for(let i=0;i<24;i++)for(const e of es)stream.push(e[i]);const data=[];stream.forEach(v=>addBits(v));function addBits(v){for(let i=7;i>=0;i--)data.push((v>>i)&1)}let k=0,up=true;for(let x=n-1;x>0;x-=2){if(x===6)x--;for(let a=0;a<n;a++){const y=up?n-1-a:a;for(const xx of [x,x-1])if(m[y][xx]===null)m[y][xx]=(data[k++]||0)^((y+xx)%2===0)}up=!up}let f=(1<<3);let q=f;for(let i=0;i<10;i++)q=(q<<1)^(((q>>9)&1)?0x537:0);f=((f<<10)|q)^0x5412;for(let i=0;i<15;i++){const b=(f>>i)&1;put(8,i<6?i:i<8?i+1:n-15+i,b);put(i<8?n-i-1:i<9?15-i:14-i,8,b)}put(8,n-8,1);let s='<svg class="qr" viewBox="0 0 '+n+' '+n+'" role="img" aria-label="Scan this QR code with your authenticator app">';for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(m[y][x])s+='<rect x="'+x+'" y="'+y+'" width="1" height="1"/>';return s+"</svg>"}
function provision(message=""){set("Step 3 of 5 · authenticator",'<h1><span class=icon>📱</span>Add your authenticator</h1><p>Scan the QR code with your authenticator app. Or copy the setup key.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<div class="card notice" id=box><p class=small>Select “Make setup key” first.</p></div><button class=primary id=make>Make setup key</button>'+help());make.onclick=async()=>{const r=await api("/api/provision",{});if(!r.ok)return provision(r.message);console.log("Test authenticator setup key:",r.secret);console.log("Test authenticator code:",r.testOtp);box.innerHTML=qr(r.uri)+'<label>Setup key</label><div class=code id=secret>'+esc(r.secret)+'</div><button class=secondary id=copy>Copy setup key</button>';copy.onclick=async()=>{try{await navigator.clipboard.writeText(r.secret);alert("Setup key copied.")}catch{alert("Copy was not available. Use the setup key shown.")}};make.textContent="Continue to check code";make.onclick=otp}}
function otp(message=""){set("Step 4 of 5 · check authenticator",'<h1><span class=icon>✅</span>Check your authenticator</h1><p>Enter the six digits from your authenticator app.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<form id=f><label>Authenticator code</label><p class=hint>Example: 123456</p><input id=code inputmode=numeric autocomplete=one-time-code maxlength=6 required><button class=primary>Check code</button></form><button class=secondary id=newcode>Get a new test code</button>'+help());newcode.onclick=async()=>{const r=await api("/api/totp/test",{});if(r.ok)console.log("Current test authenticator code:",r.testOtp);else otp(r.message)};f.onsubmit=async e=>{e.preventDefault();const r=await api("/api/otp/verify",{code:code.value});r.ok?backups():otp(r.message)}}
function backups(message=""){set("Step 5 of 5 · backup codes",'<h1><span class=icon>🧾</span>Save backup codes</h1><p>These codes help if you lose your phone. Keep them somewhere private.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<div class="card notice"><div id=codes class=code>No codes made yet.</div><button class=secondary id=copy>Copy codes</button></div><button class=primary id=make>Make backup codes</button><button class="secondary hidden" id=finish>I saved my codes</button>'+help());make.onclick=async()=>{const r=await api("/api/backups/generate",{});if(!r.ok)return backups(r.message);codes.textContent=r.codes.join("\\n");console.log("Test backup recovery codes:",r.codes);finish.classList.remove("hidden");make.textContent="Make new backup codes"};copy.onclick=async()=>{try{await navigator.clipboard.writeText(codes.textContent);alert("Backup codes copied.")}catch{alert("Copy was not available. Use the codes shown.")}};finish.onclick=async()=>{const r=await api("/api/complete",{});r.ok?success():backups(r.message)}}
function recovery(message=""){set("Recovery code check",'<h1><span class=icon>🔑</span>Use a backup code</h1><p>Enter one saved backup code. It can only be used once.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<form id=f><label>Backup code</label><p class=hint>Example: ABCD-1234</p><input id=code autocomplete=one-time-code maxlength=9 required><button class=primary>Check backup code</button></form><button class=secondary id=back>Back to setup complete</button>'+help());code.oninput=()=>{let x=code.value.toUpperCase().replace(/[^A-Z0-9]/g,"").slice(0,8);code.value=x.length>4?x.slice(0,4)+"-"+x.slice(4):x};f.onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery/verify",{code:code.value});r.ok?set("Recovery code accepted",'<h1><span class=icon>✅</span>Backup code accepted</h1><div class="card success"><p>Your backup code was used. Keep your remaining codes safe.</p></div><button class=primary id=done>Back to setup complete</button>'):recovery(r.message)};back.onclick=success;setTimeout(()=>{const d=document.getElementById("done");if(d)d.onclick=success},0)}
function success(){set("MFA setup complete",'<h1><span class=icon>🎉</span>You are all set</h1><div class="card success"><p><strong>Your authenticator and backup codes are ready.</strong></p><p>Use a saved backup code if you lose your phone.</p></div><button class=primary id=recover>Try a backup code</button><button class=secondary id=logout>Log out safely</button>'+help());recover.onclick=recovery;logout.onclick=async()=>{await api("/api/logout",{});csrf="";signin("You are logged out.")}}
document.addEventListener("click",e=>{if(e.target.dataset.start)signin()});fetch("/api/bootstrap",{credentials:"same-origin"}).then(r=>r.json()).then(r=>{csrf=r.csrf||"";signin()}).catch(()=>signin("Please refresh the page and try again."))})();
</script></body></html>`;

async function handleApi(request: Request, pathname: string): Promise<Response> {
  if (pathname === "/api/bootstrap" && request.method === "GET") {
    const old = getLiveSession(request), session = old || createSession();
    return json({ ok: true, csrf: session.csrf }, 200, old ? {} : { "Set-Cookie": sessionCookie(session.id) });
  }
  if (request.method !== "POST") return genericError(405);
  const existing = getLiveSession(request);
  if (!existing) return json({ ok: false, message: "Please refresh the page and try again." }, 401);
  if (!csrfOkay(request, existing)) return genericError(403);
  const data = await body(request);
  if (!data) return genericError();

  if (pathname === "/api/signin") {
    if (!validEmail(data.email) || String(data.email).toLowerCase() !== ACCOUNT_EMAIL) {
      return json({ ok: false, message: "We could not sign you in. Check your email and try again." }, 401);
    }
    sessions.delete(existing.id);
    const session = createSession();
    session.accountId = ACCOUNT_ID;
    return json({ ok: true, csrf: session.csrf }, 200, { "Set-Cookie": sessionCookie(session.id) });
  }
  if (pathname === "/api/logout") {
    sessions.delete(existing.id);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", true) });
  }

  const owner = requireOwner(request);
  if (owner instanceof Response) return owner;
  const record = accountRecord();
  const locked = lockMessage(record);
  if (locked) return json({ ok: false, message: locked }, 429);

  if (pathname === "/api/identity/send") {
    if (!validPhone(data.phone)) { failure(record); return json({ ok: false, message: "Enter the last four phone digits, for example 4821." }, 400); }
    if (!equal(String(data.phone), ACCOUNT_PHONE_SUFFIX)) {
      failure(record); return json({ ok: false, message: "Those phone digits did not match. Check the last four digits and try again." }, 400);
    }
    const code = String(randomBytes(4).readUInt32BE(0) % 1_000_000).padStart(6, "0");
    record.identityCode = protectedCode(code, ACCOUNT_ID); persist();
    return json({ ok: true, testCode: code });
  }
  if (pathname === "/api/identity/verify") {
    if (!validOtp(data.code)) { failure(record); return json({ ok: false, message: "Enter six numbers, for example 123456." }, 400); }
    const value = record.identityCode;
    if (!value || value.accountId !== ACCOUNT_ID || value.used || value.expiresAt < now() || !equal(value.hash, shaCode(String(data.code)))) {
      failure(record); return json({ ok: false, message: "That code did not work. Check the six numbers or ask for a new code." }, 400);
    }
    value.used = true; owner.identityVerified = true; clearFailures(record); persist();
    return json({ ok: true });
  }
  if (!owner.identityVerified) return json({ ok: false, message: "Please complete the identity check first." }, 403);

  if (pathname === "/api/provision") {
    const secret = base32Secret();
    Object.assign(record, encrypt(secret));
    record.otpVerified = false; record.mfaEnabled = false; persist();
    return json({ ok: true, secret, uri: provisioningUri(secret), testOtp: totp(secret) });
  }
  if (pathname === "/api/totp/test") {
    const secret = decrypt(record);
    if (!secret) return json({ ok: false, message: "Make a setup key first." }, 400);
    return json({ ok: true, testOtp: totp(secret) });
  }
  if (pathname === "/api/otp/verify") {
    if (!validOtp(data.code)) { failure(record); return json({ ok: false, message: "Enter six numbers, for example 123456." }, 400); }
    const secret = decrypt(record);
    if (!secret || !validTotp(secret, String(data.code))) {
      failure(record); return json({ ok: false, message: "That code did not work. Check the six numbers or get a new test code." }, 400);
    }
    record.otpVerified = true; clearFailures(record); persist();
    return json({ ok: true });
  }
  if (pathname === "/api/backups/generate") {
    if (!record.otpVerified) return json({ ok: false, message: "Please check your authenticator code first." }, 403);
    const codes: string[] = [];
    record.recoveryHashes = [];
    for (let i = 0; i < 8; i++) {
      const raw = randomBytes(8).toString("hex").toUpperCase();
      const code = `${raw.slice(0, 4)}-${raw.slice(4, 8)}`;
      const salt = randomBytes(16);
      const hash = scryptSync(code, salt, 32).toString("base64");
      record.recoveryHashes.push({ salt: salt.toString("base64"), hash });
      codes.push(code);
    }
    persist();
    return json({ ok: true, codes });
  }
  if (pathname === "/api/complete") {
    if (!record.recoveryHashes.length) return json({ ok: false, message: "Make and save backup codes before continuing." }, 400);
    record.mfaEnabled = true; persist();
    return json({ ok: true });
  }
  if (pathname === "/api/recovery/verify") {
    const code = normalRecovery(data.code);
    if (!code) { failure(record); return json({ ok: false, message: "Enter a backup code in this format: ABCD-1234." }, 400); }
    let matched = -1;
    for (let i = 0; i < record.recoveryHashes.length; i++) {
      const item = record.recoveryHashes[i];
      const attempt = scryptSync(code, Buffer.from(item.salt, "base64"), 32).toString("base64");
      if (equal(attempt, item.hash)) matched = i;
    }
    if (matched < 0) { failure(record); return json({ ok: false, message: "That backup code did not work. Check it and try again." }, 400); }
    record.recoveryHashes.splice(matched, 1); clearFailures(record); persist();
    return json({ ok: true });
  }
  return genericError(404);
}

const server = Bun.serve({
  port: PORT, hostname: "0.0.0.0",
  tls: { cert: "certs/cert.pem", key: "certs/key.pem" },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.method === "OPTIONS") {
        const origin = request.headers.get("origin") || "";
        if (!TRUSTED_ORIGINS.has(origin)) return new Response(null, { status: 403, headers: headers() });
        return new Response(null, { status: 204, headers: headers({
          "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true",
          "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        }) });
      }
      if (url.pathname === "/" && request.method === "GET") {
        return new Response(page, { headers: headers({ "Content-Type": "text/html; charset=utf-8" }) });
      }
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
      return new Response("Not found", { status: 404, headers: headers({ "Content-Type": "text/plain; charset=utf-8" }) });
    } catch {
      return new Response("Something went wrong. Please try again.", {
        status: 500, headers: headers({ "Content-Type": "text/plain; charset=utf-8" }),
      });
    }
  },
});
console.log(`MFA enrolment server listening on https://localhost:${server.port}`);
