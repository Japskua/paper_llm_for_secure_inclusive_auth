
import {
  createCipheriv, createDecipheriv, createHmac, randomBytes, scryptSync,
  timingSafeEqual,
} from "node:crypto";
import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";

/**
 * MFA Enrolment System
 * Requirements 1–5: authenticated owner sessions, CSRF, TLS headers,
 * encrypted OTP secret, hashed recovery codes, rate limiting, and inclusive UI.
 *
 * Academic fixture is deliberately isolated. It is available only when
 * MFA_TEST_MODE=1 and requires an explicit test sign-in action.
 */
const PORT = 3000;
const ACCOUNT_ID = "account-marcus-001";
const ACCOUNT_EMAIL = "marcus@example.com";
const ACCOUNT_PHONE_SUFFIX = "4821";
const TEST_MODE = process.env.MFA_TEST_MODE === "1";
const ACADEMIC_FIXTURE_CODE = "MARCUS-ACADEMIC";
const ACADEMIC_IDENTITY_CODE = "246810";
const ACADEMIC_TOTP_SECRET = "JBSWY3DPEHPK3PXP";
const DATA_FILE = "./mfa-records.json";
const KEY_FILE = "./mfa-master-key.bin";
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const VERIFY_EXPIRY_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;
const MAX_FAILURES = 5;
const TOTP_STEP_SECONDS = 30;
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

type Session = {
  id: string; csrf: string; accountId: string; identityVerified: boolean;
  createdAt: number; lastSeenAt: number;
};
type ProtectedValue = {
  hash: string; expiresAt: number; used: boolean; accountId: string;
};
type RecoveryHash = { salt: string; hash: string };
type AccountMfa = {
  encryptedSecret?: string; secretIv?: string; secretTag?: string;
  identityCode?: ProtectedValue; recoveryHashes: RecoveryHash[];
  mfaEnabled: boolean; otpVerified: boolean; failures: number;
  lockedUntil: number; lastAcceptedTotpCounter?: number;
};
type DurableData = { accounts: Record<string, AccountMfa> };

const now = () => Date.now();
const token = (bytes = 32) => randomBytes(bytes).toString("base64url");
function equal(a: string, b: string) {
  const aa = Buffer.from(a), bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function loadKey() {
  if (existsSync(KEY_FILE)) {
    const value = readFileSync(KEY_FILE);
    if (value.length === 32) return value;
  }
  const value = randomBytes(32);
  writeFileSync(KEY_FILE, value, { mode: 0o600 });
  try { chmodSync(KEY_FILE, 0o600); } catch {}
  return value;
}
const encryptionKey = loadKey();
function loadData(): DurableData {
  try {
    const data = JSON.parse(readFileSync(DATA_FILE, "utf8"));
    if (data && typeof data.accounts === "object") return data;
  } catch {}
  return { accounts: {} };
}
const durable = loadData();
function persist() {
  writeFileSync(DATA_FILE, JSON.stringify(durable), { mode: 0o600 });
  try { chmodSync(DATA_FILE, 0o600); } catch {}
}
const sessions = new Map<string, Session>();
function accountRecord() {
  if (!durable.accounts[ACCOUNT_ID]) {
    durable.accounts[ACCOUNT_ID] = {
      recoveryHashes: [], mfaEnabled: false, otpVerified: false,
      failures: 0, lockedUntil: 0,
    };
    persist();
  }
  return durable.accounts[ACCOUNT_ID];
}

/* Requirement 1: authenticated ownership is established only by this server fixture route. */
function createAuthenticatedSession(identityVerified = false): Session {
  const session: Session = {
    id: token(), csrf: token(), accountId: ACCOUNT_ID, identityVerified,
    createdAt: now(), lastSeenAt: now(),
  };
  sessions.set(session.id, session);
  return session;
}
function sessionCookie(id: string, expiry = false) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict${expiry ? "; Max-Age=0" : ""}`;
}
function headers(nonce = "", extra: Record<string, string> = {}) {
  const scripts = nonce ? `'nonce-${nonce}'` : "'none'";
  return {
    "Content-Security-Policy": `default-src 'self'; script-src ${scripts}; style-src ${scripts}; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    "Cache-Control": "no-store", ...extra,
  };
}
function json(data: unknown, status = 200, extra: Record<string, string> = {}) {
  return Response.json(data, { status, headers: headers("", extra) });
}
function genericError(status = 400) {
  return json({ ok: false, message: "We could not complete that step. Please check the information and try again." }, status);
}
function parseCookies(request: Request) {
  const result: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const [key, ...values] = part.trim().split("=");
    if (key && values.length) result[key] = values.join("=");
  }
  return result;
}
function getLiveSession(request: Request) {
  const id = parseCookies(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  if (!session) return null;
  if (now() - session.lastSeenAt > SESSION_IDLE_MS || now() - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(session.id);
    return null;
  }
  session.lastSeenAt = now();
  return session;
}
function requireOwner(request: Request): Session | Response {
  const session = getLiveSession(request);
  if (!session || session.accountId !== ACCOUNT_ID) {
    return json({ ok: false, message: "Please sign in to your secure setup page." }, 401);
  }
  return session;
}
function csrfOkay(request: Request, session: Session) {
  return TRUSTED_ORIGINS.has(request.headers.get("origin") || "") &&
    equal(request.headers.get("x-csrf-token") || "", session.csrf);
}
async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown> : null;
  } catch { return null; }
}
function protectedCode(code: string): ProtectedValue {
  return {
    hash: createHmac("sha256", encryptionKey).update(code).digest("hex"),
    expiresAt: now() + VERIFY_EXPIRY_MS, used: false, accountId: ACCOUNT_ID,
  };
}
const codeHash = (code: string) => createHmac("sha256", encryptionKey).update(code).digest("hex");
function encrypt(value: string) {
  const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return {
    encryptedSecret: encrypted.toString("base64"), secretIv: iv.toString("base64"),
    secretTag: cipher.getAuthTag().toString("base64"),
  };
}
function decrypt(record: AccountMfa) {
  if (!record.encryptedSecret || !record.secretIv || !record.secretTag) return "";
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, Buffer.from(record.secretIv, "base64"));
  decipher.setAuthTag(Buffer.from(record.secretTag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(record.encryptedSecret, "base64")), decipher.final()]).toString("utf8");
}
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Secret() {
  const raw = randomBytes(20); let bits = 0, value = 0, output = "";
  for (const byte of raw) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { output += BASE32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return bits ? output + BASE32[(value << (5 - bits)) & 31] : output;
}
function decodeBase32(value: string) {
  let bits = 0, buffer = 0; const output: number[] = [];
  for (const char of value.replace(/=|\s/g, "").toUpperCase()) {
    const item = BASE32.indexOf(char); if (item < 0) return Buffer.alloc(0);
    buffer = (buffer << 5) | item; bits += 5;
    if (bits >= 8) { output.push((buffer >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(output);
}
function totp(secret: string, counter = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS)) {
  const message = Buffer.alloc(8); message.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", decodeBase32(secret)).update(message).digest();
  const offset = mac[19] & 15;
  const value = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
function matchingTotpCounter(secret: string, code: string) {
  const current = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS);
  for (const offset of [-1, 0, 1]) if (equal(totp(secret, current + offset), code)) return current + offset;
  return null;
}
function provisioningUri(secret: string) {
  const issuer = "SafeBank";
  return `otpauth://totp/${encodeURIComponent(`${issuer}:${ACCOUNT_EMAIL}`)}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
}
function lockMessage(record: AccountMfa) {
  return record.lockedUntil > now() ? "Too many attempts were made. Please wait a few minutes, then try again." : "";
}
function failure(record: AccountMfa) {
  record.failures++;
  if (record.failures >= MAX_FAILURES) { record.failures = 0; record.lockedUntil = now() + LOCKOUT_MS; }
  persist();
}
function clearFailures(record: AccountMfa) { record.failures = 0; persist(); }
const validPhone = (value: unknown) => typeof value === "string" && /^\d{4}$/.test(value);
const validOtp = (value: unknown) => typeof value === "string" && /^\d{6}$/.test(value);
function normalRecovery(value: unknown) {
  if (typeof value !== "string") return "";
  const text = value.toUpperCase().replace(/[^A-Z0-9]/g, "");
  return /^[A-F0-9]{16}$/.test(text) ? `${text.slice(0,4)}-${text.slice(4,8)}-${text.slice(8,12)}-${text.slice(12,16)}` : "";
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeBank MFA setup</title><style nonce="${nonce}">
:root{--ink:#172033;--muted:#536074;--blue:#075cc6;--soft:#edf5ff;--line:#cbd5e1;--good:#087443;--bad:#992020}*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:var(--ink);font-family:Arial,Verdana,Tahoma,sans-serif;font-size:17px;letter-spacing:.035em;line-height:1.65}main{width:min(100%,560px);min-height:100vh;margin:auto;background:#fff;padding:22px 20px 38px}header{border-bottom:2px solid var(--line);padding-bottom:16px;margin-bottom:22px}.brand{font-size:1.25rem;font-weight:800}.step{color:var(--muted);font-size:.92rem;margin:5px 0 0}h1{font-size:1.7rem;line-height:1.25;margin:0 0 12px}p{max-width:48ch}.card{border:1px solid var(--line);border-radius:14px;padding:18px;margin:18px 0}.notice{background:var(--soft);border-left:5px solid var(--blue)}.success{background:#effbf4;border-left:5px solid var(--good)}.error{background:#fff2f2;border-left:5px solid var(--bad);color:#721c1c}label{display:block;font-weight:700;margin:16px 0 5px}input{width:100%;min-height:51px;border:2px solid #9aa8ba;border-radius:9px;padding:10px 12px;font:inherit;letter-spacing:.08em}input:focus,button:focus,summary:focus{outline:3px solid #f5aa2d;outline-offset:3px}.hint{color:var(--muted);margin:3px 0 14px;font-size:.92rem}button{display:block;width:100%;min-height:53px;border:0;border-radius:9px;padding:12px 15px;font:inherit;font-weight:800;cursor:pointer;margin:15px 0 0}.primary{background:var(--blue);color:#fff}.secondary{color:#044a9e;background:#e7f0fd}.textbutton{color:#044a9e;background:transparent;text-decoration:underline;min-height:40px}.icon{font-size:1.6rem;margin-right:8px}.code{font-family:monospace;font-size:1.03rem;letter-spacing:.1em;overflow-wrap:anywhere;background:#f5f7fa;padding:11px;border-radius:8px;white-space:pre-wrap}.qr{display:block;width:245px;max-width:100%;margin:18px auto;background:#fff;image-rendering:pixelated}.small{font-size:.9rem;color:var(--muted)}details{margin-top:20px;border-top:1px solid var(--line);padding-top:14px}summary{font-weight:800;cursor:pointer;color:#044a9e}.hidden{display:none}.test{background:#fff8df;border-left:5px solid #b77900}@media(max-width:360px){main{padding:18px 15px}body{font-size:16px}h1{font-size:1.48rem}}
</style></head><body><main><header><div class="brand">🔐 SafeBank</div><p class="step" id="step">MFA setup</p></header><section id="app" aria-live="polite"></section></main>
<script nonce="${nonce}">(()=>{"use strict";
let csrf="",testMode=false;const app=document.getElementById("app"),step=document.getElementById("step"),by=id=>document.getElementById(id);
const esc=v=>{const d=document.createElement("div");d.textContent=String(v);return d.innerHTML};const set=(label,html)=>{step.textContent=label;app.innerHTML=html};
async function api(path,data={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});const x=await r.json().catch(()=>({ok:false,message:"Please try again."}));if(r.status===401){csrf="";signedOut(x.message||"Your secure setup session ended.")}return x}
function testOutput(label,value){if(!testMode||value===undefined)return "";console.log("[ACADEMIC TEST MODE] "+label+":",value);return '<div class="card test"><strong>Academic test value</strong><div class="code">'+esc(Array.isArray(value)?value.join("\\n"):value)+'</div></div>'}
function help(){return '<details><summary>Need help?</summary><p>You can take your time. There is no reading time limit. You can retry any step.</p><button class="textbutton" data-start type="button">Start this setup again</button></details>'}
function signIn(message=""){set("Secure setup sign-in",'<h1><span class="icon">🔒</span>Secure setup</h1><div class="card notice"><p>'+esc(message||"Sign in is required before MFA settings can be opened.")+'</p></div>'+(testMode?'<div class="card test"><p><strong>Academic test mode</strong></p><p>Use the supplied fixture phrase to establish Marcus’s authenticated test session.</p><label for="fixture">Academic fixture phrase</label><p class="hint">Example: MARCUS-ACADEMIC</p><input id="fixture" autocomplete="off"><button class="primary" id="fixtureLogin">Open secure test setup</button></div>':'<p class="hint">This demonstration has no public sign-in service. An account owner must be authenticated by the bank before using this page.</p>'));if(testMode)by("fixtureLogin").onclick=async()=>{const r=await api("/api/test/login",{fixture:by("fixture").value});r.ok?location.reload():signIn(r.message)}}
function identity(message=""){set("Step 1 of 4 · identity check",'<h1><span class="icon">🪪</span>Check it is you</h1><p>We will send a six-digit code to your phone ending in 4821.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<form id="identityForm"><label for="phone">Last 4 digits of phone</label><p class="hint">Example: 4821</p><input id="phone" inputmode="numeric" autocomplete="tel" maxlength="4" required><label for="identityCode">Code</label><p class="hint">Example: 123456</p><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button class="primary">Check code</button></form><button class="secondary" id="send">Send or re-send code</button>'+help());by("send").onclick=async()=>{const r=await api("/api/identity/send",{phone:by("phone").value});if(r.ok){const box=testOutput("Identity code",r.testCode);if(box)app.insertAdjacentHTML("beforeend",box);by("identityCode").focus()}else identity(r.message)};by("identityForm").onsubmit=async e=>{e.preventDefault();const r=await api("/api/identity/verify",{code:by("identityCode").value});r.ok?provision():identity(r.message)}}
/* Valid QR Code Model 2, version 6-L encoder. It encodes the complete otpauth URI. */
function qr(text){const n=41,bytes=new TextEncoder().encode(text);if(bytes.length>134)return '<p class="error">The QR code is too large. Copy the setup key instead.</p>';let data=[64,bytes.length,...bytes],bits=[];data.forEach(x=>{for(let i=7;i>=0;i--)bits.push(x>>i&1)});bits.push(...Array(Math.min(4,1088-bits.length)).fill(0));while(bits.length%8)bits.push(0);let words=[];for(let i=0;i<bits.length;i+=8)words.push(parseInt(bits.slice(i,i+8).join(""),2));for(let i=0;words.length<136;i++)words.push(i%2?17:236);const mul=(a,b)=>{let z=0;while(b){if(b&1)z^=a;a=a&128?(a<<1)^285:a<<1;b>>=1}return z};const pow=i=>{let x=1;while(i--)x=mul(x,2);return x};const ecc=block=>{let r=Array(18).fill(0);for(const v of block){let f=v^r.shift();r.push(0);for(let j=0;j<18;j++)r[j]^=mul(pow(17-j),f)}return r};let a=words.slice(0,68),b=words.slice(68),ea=ecc(a),eb=ecc(b),cw=[];for(let i=0;i<68;i++)cw.push(a[i],b[i]);for(let i=0;i<18;i++)cw.push(ea[i],eb[i]);let raw=[];cw.forEach(x=>{for(let i=7;i>=0;i--)raw.push(x>>i&1)});const base=()=>Array.from({length:n},()=>Array(n).fill(null));const finder=(m,x,y)=>{for(let j=-1;j<8;j++)for(let i=-1;i<8;i++)if(x+i>=0&&y+j>=0&&x+i<n&&y+j<n)m[y+j][x+i]=(i>=0&&i<=6&&j>=0&&j<=6&&(i===0||i===6||j===0||j===6||(i>=2&&i<=4&&j>=2&&j<=4)))?1:0};const setup=()=>{let m=base();finder(m,0,0);finder(m,n-7,0);finder(m,0,n-7);for(let i=8;i<n-8;i++){m[6][i]=i%2?0:1;m[i][6]=i%2?0:1}for(let y=32;y<37;y++)for(let x=32;x<37;x++)m[y][x]=(x===32||x===36||y===32||y===36||(x===34&&y===34))?1:0;for(let i=0;i<9;i++){if(m[8][i]===null)m[8][i]=0;if(m[i][8]===null)m[i][8]=0}for(let i=n-8;i<n;i++){m[8][i]=0;m[i][8]=0}m[n-8][8]=1;return m};const format=(m,mask)=>{let v=(1<<3)|mask,d=v<<10;while(d.toString(2).length>=11)d^=1335<<(d.toString(2).length-11);v=((v<<10)|d)^21522;for(let i=0;i<15;i++){let bit=v>>i&1;if(i<6)m[i][8]=bit;else if(i<8)m[i+1][8]=bit;else m[n-15+i][8]=bit;if(i<8)m[8][n-i-1]=bit;else if(i<9)m[8][15-i]=bit;else m[8][15-i-1]=bit}};const build=mask=>{let m=setup(),k=0,up=true;for(let x=n-1;x>0;x-=2){if(x===6)x--;for(let q=0;q<n;q++){let y=up?n-1-q:q;for(let xx=x;xx>=x-1;xx--)if(m[y][xx]===null){let v=raw[k++]||0,on=[(y+xx)%2===0,y%2===0,xx%3===0,(y+xx)%3===0,(Math.floor(y/2)+Math.floor(xx/3))%2===0,(y*xx)%2+(y*xx)%3===0,((y*xx)%2+(y*xx)%3)%2===0,((y+xx)%2+(y*xx)%3)%2===0][mask];m[y][xx]=v^(on?1:0)}}up=!up}format(m,mask);return m};const penalty=m=>{let p=0;for(let y=0;y<n;y++)for(let x=0;x<n;x++){let same=0,v=m[y][x];for(let dy=-1;dy<=1;dy++)for(let dx=-1;dx<=1;dx++)if(dx||dy){let yy=y+dy,xx=x+dx;if(yy>=0&&xx>=0&&yy<n&&xx<n&&m[yy][xx]===v)same++}if(same>5)p+=same-5}return p};let best=build(0),score=penalty(best);for(let i=1;i<8;i++){let q=build(i),s=penalty(q);if(s<score){best=q;score=s}}let out='<svg class="qr" viewBox="-4 -4 49 49" role="img" aria-label="Authenticator setup QR code"><rect x="-4" y="-4" width="49" height="49" fill="white"/>';for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(best[y][x])out+='<rect x="'+x+'" y="'+y+'" width="1" height="1"/>';return out+"</svg>"}
function provision(message=""){set("Step 2 of 4 · authenticator",'<h1><span class="icon">📱</span>Add your authenticator</h1><p>Scan the QR code with your authenticator app. Or copy the setup key instead.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<div class="card notice" id="setupBox"><p class="small">Select “Make setup key” first.</p></div><button class="primary" id="make">Make setup key</button>'+help());by("make").onclick=()=>makeProvision()}
async function makeProvision(){const r=await api("/api/provision");if(!r.ok)return provision(r.message);by("setupBox").innerHTML=qr(r.uri)+'<label>Setup key</label><div class="code" id="secret">'+esc(r.secret)+'</div><button class="secondary" id="copy">Copy setup key</button>';by("copy").onclick=async()=>{try{await navigator.clipboard.writeText(r.secret);alert("Setup key copied.")}catch{alert("Copy was not available. Use the setup key shown.")}};const out=testOutput("Authenticator code",r.testOtp);if(out)app.insertAdjacentHTML("beforeend",out);by("make").textContent="Continue to check code";by("make").onclick=()=>otp()}
function otp(message=""){set("Step 3 of 4 · check authenticator",'<h1><span class="icon">✅</span>Check your authenticator</h1><p>Enter the six digits from your authenticator app.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<form id="otpForm"><label for="otpCode">Authenticator code</label><p class="hint">Example: 123456</p><input id="otpCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button class="primary">Check code</button></form><button class="secondary" id="newCode">Get a new test code</button>'+help());by("newCode").onclick=async()=>{const r=await api("/api/totp/test");if(!r.ok)return otp(r.message);const out=testOutput("Current authenticator code",r.testOtp);if(out)app.insertAdjacentHTML("beforeend",out);else alert("Use the current code in your authenticator app.")};by("otpForm").onsubmit=async e=>{e.preventDefault();const r=await api("/api/otp/verify",{code:by("otpCode").value});r.ok?backups():otp(r.message)}}
function backups(message=""){set("Step 4 of 4 · backup codes",'<h1><span class="icon">🧾</span>Save backup codes</h1><p>These codes help if you lose your phone. Keep them somewhere private.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<div class="card notice"><div id="codes" class="code">No codes made yet.</div><button class="secondary" id="copyCodes">Copy codes</button></div><button class="primary" id="makeCodes">Make backup codes</button><button class="secondary hidden" id="finish">I saved my codes</button>'+help());by("makeCodes").onclick=async()=>{const r=await api("/api/backups/generate");if(!r.ok)return backups(r.message);by("codes").textContent=r.codes.join("\\n");by("finish").classList.remove("hidden");by("makeCodes").textContent="Make new backup codes";if(testMode)console.log("[ACADEMIC TEST MODE] Backup recovery codes:",r.codes)};by("copyCodes").onclick=async()=>{try{await navigator.clipboard.writeText(by("codes").textContent);alert("Backup codes copied.")}catch{alert("Copy was not available. Use the codes shown.")}};by("finish").onclick=async()=>{const r=await api("/api/complete");r.ok?success():backups(r.message)}}
function recovery(message=""){set("Recovery code check",'<h1><span class="icon">🔑</span>Use a backup code</h1><p>Enter one saved backup code. It can only be used once.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<form id="recoveryForm"><label for="recoveryCode">Backup code</label><p class="hint">Example: A1B2-C3D4-E5F6-7890</p><input id="recoveryCode" autocomplete="one-time-code" maxlength="19" required><button class="primary">Check backup code</button></form><button class="secondary" id="back">Back to setup complete</button>'+help());by("recoveryCode").oninput=()=>{let x=by("recoveryCode").value.toUpperCase().replace(/[^A-F0-9]/g,"").slice(0,16);by("recoveryCode").value=x.match(/.{1,4}/g)?.join("-")||""};by("recoveryForm").onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery/verify",{code:by("recoveryCode").value});if(r.ok){set("Recovery code accepted",'<h1><span class="icon">✅</span>Backup code accepted</h1><div class="card success"><p>Your backup code was used. Keep your remaining codes safe.</p></div><button class="primary" id="done">Back to setup complete</button>');by("done").onclick=success}else recovery(r.message)};by("back").onclick=success}
function success(){set("MFA setup complete",'<h1><span class="icon">🎉</span>You are all set</h1><div class="card success"><p><strong>Your authenticator and backup codes are ready.</strong></p><p>Use a saved backup code if you lose your phone.</p></div><button class="primary" id="recover">Try a backup code</button><button class="secondary" id="logout">Log out safely</button>'+help());by("recover").onclick=recovery;by("logout").onclick=async()=>{await api("/api/logout");csrf="";signedOut("You are logged out.")}}
function signedOut(message){set("Secure setup",'<h1><span class="icon">🔒</span>Setup closed</h1><div class="card notice"><p>'+esc(message)+'</p></div><button class="primary" id="open">Open secure setup</button>');by("open").onclick=()=>location.reload()}
document.addEventListener("click",e=>{const t=e.target;if(t instanceof HTMLElement&&t.dataset.start)identity()});
fetch("/api/bootstrap",{credentials:"same-origin"}).then(async r=>{const x=await r.json();if(!x.ok){testMode=!!x.testMode;return signIn(x.message)}csrf=x.csrf;testMode=!!x.testMode;identity()}).catch(()=>signedOut("Please refresh the page and try again."));
})();</script></body></html>`;
}

async function handleApi(request: Request, pathname: string): Promise<Response> {
  if (pathname === "/api/bootstrap" && request.method === "GET") {
    const owner = requireOwner(request);
    if (owner instanceof Response) return json({ ok: false, message: "Sign in is required before MFA setup.", testMode: TEST_MODE }, 401);
    return json({ ok: true, csrf: owner.csrf, testMode: TEST_MODE });
  }

  /* Explicit, test-only authentication fixture; no visitor receives a session at GET /. */
  if (pathname === "/api/test/login" && request.method === "POST") {
    const data = await body(request);
    if (!TEST_MODE || !data || typeof data.fixture !== "string" || !equal(data.fixture, ACADEMIC_FIXTURE_CODE)) {
      return json({ ok: false, message: "The academic fixture sign-in could not be completed." }, 403);
    }
    const session = createAuthenticatedSession(false);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(session.id) });
  }

  if (request.method !== "POST") return genericError(405);
  const owner = requireOwner(request);
  if (owner instanceof Response) return owner;
  if (!csrfOkay(request, owner)) return genericError(403);
  const data = await body(request);
  if (!data) return genericError();

  if (pathname === "/api/logout") {
    sessions.delete(owner.id);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", true) });
  }

  const record = accountRecord();
  const locked = lockMessage(record);
  if (locked) return json({ ok: false, message: locked }, 429);

  if (pathname === "/api/identity/send") {
    if (!validPhone(data.phone) || !equal(String(data.phone), ACCOUNT_PHONE_SUFFIX)) {
      failure(record);
      return json({ ok: false, message: "Those phone digits did not match. Enter the last four digits, for example 4821." }, 400);
    }
    const code = TEST_MODE ? ACADEMIC_IDENTITY_CODE : String(randomBytes(4).readUInt32BE(0) % 1_000_000).padStart(6, "0");
    record.identityCode = protectedCode(code);
    persist();
    return json(TEST_MODE ? { ok: true, testCode: code } : { ok: true });
  }

  if (pathname === "/api/identity/verify") {
    if (!validOtp(data.code)) { failure(record); return json({ ok: false, message: "Enter six numbers, for example 123456." }, 400); }
    const value = record.identityCode;
    if (!value || value.accountId !== ACCOUNT_ID || value.used || value.expiresAt < now() || !equal(value.hash, codeHash(String(data.code)))) {
      failure(record);
      return json({ ok: false, message: "That code did not work. Check the six numbers or ask for a new code." }, 400);
    }
    value.used = true;
    clearFailures(record); persist();
    /* Requirement task: prevent fixation by invalidating old ID and rotating cookie/session. */
    sessions.delete(owner.id);
    const replacement = createAuthenticatedSession(true);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(replacement.id) });
  }

  if (!owner.identityVerified) return json({ ok: false, message: "Please complete the identity check first." }, 403);

  if (pathname === "/api/provision") {
    const secret = TEST_MODE ? ACADEMIC_TOTP_SECRET : base32Secret();
    Object.assign(record, encrypt(secret));
    record.lastAcceptedTotpCounter = undefined; record.otpVerified = false; record.mfaEnabled = false;
    persist();
    const result: Record<string, unknown> = { ok: true, secret, uri: provisioningUri(secret) };
    if (TEST_MODE) result.testOtp = totp(secret);
    return json(result);
  }
  if (pathname === "/api/totp/test") {
    const secret = decrypt(record);
    if (!secret) return json({ ok: false, message: "Make a setup key first." }, 400);
    return json(TEST_MODE ? { ok: true, testOtp: totp(secret) } : { ok: true });
  }
  if (pathname === "/api/otp/verify") {
    if (!validOtp(data.code)) { failure(record); return json({ ok: false, message: "Enter six numbers, for example 123456." }, 400); }
    const secret = decrypt(record), counter = secret ? matchingTotpCounter(secret, String(data.code)) : null;
    if (counter === null || record.lastAcceptedTotpCounter === counter) {
      failure(record);
      return json({ ok: false, message: counter !== null ? "That code was already used. Wait for a new code, then try again." : "That code did not work. Check the six numbers or get a new code." }, 400);
    }
    record.lastAcceptedTotpCounter = counter; record.otpVerified = true; clearFailures(record); persist();
    return json({ ok: true });
  }
  if (pathname === "/api/backups/generate") {
    if (!record.otpVerified) return json({ ok: false, message: "Please check your authenticator code first." }, 403);
    const codes: string[] = []; record.recoveryHashes = [];
    for (let i = 0; i < 8; i++) {
      const raw = randomBytes(8).toString("hex").toUpperCase();
      const code = `${raw.slice(0,4)}-${raw.slice(4,8)}-${raw.slice(8,12)}-${raw.slice(12,16)}`;
      const salt = randomBytes(16);
      record.recoveryHashes.push({ salt: salt.toString("base64"), hash: scryptSync(code, salt, 32).toString("base64") });
      codes.push(code);
    }
    persist(); return json({ ok: true, codes });
  }
  if (pathname === "/api/complete") {
    if (!record.recoveryHashes.length) return json({ ok: false, message: "Make and save backup codes before continuing." }, 400);
    record.mfaEnabled = true; persist(); return json({ ok: true });
  }
  if (pathname === "/api/recovery/verify") {
    const code = normalRecovery(data.code);
    if (!code) { failure(record); return json({ ok: false, message: "Enter a backup code in this format: A1B2-C3D4-E5F6-7890." }, 400); }
    let matched = -1;
    for (let i = 0; i < record.recoveryHashes.length; i++) {
      const item = record.recoveryHashes[i];
      const attempt = scryptSync(code, Buffer.from(item.salt, "base64"), 32).toString("base64");
      if (equal(attempt, item.hash)) matched = i;
    }
    if (matched < 0) { failure(record); return json({ ok: false, message: "That backup code did not work. Check it and try again." }, 400); }
    record.recoveryHashes.splice(matched, 1); clearFailures(record); persist(); return json({ ok: true });
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
        return new Response(null, { status: 204, headers: headers("", {
          "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true",
          "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        }) });
      }
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = randomBytes(24).toString("base64");
        return new Response(page(nonce), { headers: headers(nonce, { "Content-Type": "text/html; charset=utf-8" }) });
      }
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
      return new Response("Not found", { status: 404, headers: headers("", { "Content-Type": "text/plain; charset=utf-8" }) });
    } catch {
      return new Response("Something went wrong. Please try again.", { status: 500, headers: headers("", { "Content-Type": "text/plain; charset=utf-8" }) });
    }
  },
});
console.log(`MFA enrolment server listening on https://localhost:${server.port}`);
