
import { readFileSync } from "node:fs";

/*
 MFA enrolment system — requirements 1–5:
 server-side account ownership, CSRF, TLS, secure headers/cookies,
 encrypted OTP secrets, hashed recovery codes, validation, and rate limits.
*/
const PORT = Number(Bun.env.PORT || 3000);
const TEST_ONLY = Bun.env.MFA_TEST_MODE === "1";
/* Demo delivery is useful by default; set MFA_SIMULATED_DELIVERY=0 in production. */
const SIMULATED_DELIVERY = Bun.env.MFA_SIMULATED_DELIVERY !== "0";
const COOKIE = "__Host_mfa_session";
const IDLE = 30 * 60_000;
const ABSOLUTE = 8 * 60 * 60_000;
const CODE_LIFE = 15 * 60_000;
const LOCK = 10 * 60_000;
const MAX_ATTEMPTS = 5;
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ISSUER = "Harbor Bank";
const encoder = new TextEncoder();

const origins = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`
]);

const DEMO_ACCOUNT = {
  id: "account-marcus-demo",
  email: "marcus@example.com",
  password: "MarcusDemo!54"
};

const TEST_SECRETS = ["JBSWY3DPEHPK3PXPJBSWY", "KRUGS4ZANFZSAYJAON2X"];
const TEST_RECOVERY = [
  "ALPHA-23456", "BRAVO-23456", "CHARL-23456", "DELTA-23456",
  "ECHOX-23456", "FOXTN-23456", "GOLFY-23456", "HOTEL-23456"
];

type Protected = { cipher: string; iv: string };
type RecoveryHash = { salt: string; hash: string };
type OneCode = { hash: string; expires: number; used: boolean; attempts: number; lockedUntil: number };
type Session = {
  id: string;
  csrf: string;
  created: number;
  seen: number;
  account?: string;
  email?: string;
  identity?: OneCode;
  resends: number;
  resendStarted: number;
  setupCount: number;
};
type MfaRecord = {
  accountId: string;
  enabled: boolean;
  otpSecret?: Protected;
  recoveryHashes: RecoveryHash[];
  provisioned: boolean;
  otpAttempts: number;
  otpLockedUntil: number;
  recoveryAttempts: number;
  recoveryLockedUntil: number;
  usedTotpSteps: Set<number>;
};

/* Requirement 1/3: MFA belongs to an account, never to a browser session. */
const mfaRecords = new Map<string, MfaRecord>();
const sessions = new Map<string, Session>();
const loginLimits = new Map<string, { attempts: number; lockedUntil: number }>();
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const rateKey = crypto.getRandomValues(new Uint8Array(32));

function b64(bytes: Uint8Array) {
  let out = "";
  for (const byte of bytes) out += String.fromCharCode(byte);
  return btoa(out);
}
function unb64(value: string) {
  return Uint8Array.from(atob(value), x => x.charCodeAt(0));
}
function token(length = 32) {
  return b64(crypto.getRandomValues(new Uint8Array(length))).replace(/[+/=]/g, x => x === "+" ? "-" : x === "/" ? "_" : "");
}
function secureText(chars: string, length: number) {
  const result: string[] = [];
  const limit = 256 - (256 % chars.length);
  while (result.length < length) {
    for (const x of crypto.getRandomValues(new Uint8Array(length - result.length))) {
      if (x < limit) result.push(chars[x % chars.length]);
    }
  }
  return result.join("");
}
function fixedOrRandomIdentityCode() {
  return SIMULATED_DELIVERY ? "123456" : secureText("0123456789", 6);
}
function recoveryCodes() {
  if (TEST_ONLY) return [...TEST_RECOVERY];
  const result = new Set<string>();
  while (result.size < 8) result.add(`${secureText(B32, 5)}-${secureText(B32, 5)}`);
  return [...result];
}
async function digest(value: string) {
  return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}
function equal(a: string, b: string) {
  if (a.length !== b.length) return false;
  let n = 0;
  for (let i = 0; i < a.length; i++) n |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return n === 0;
}
async function rateId(email: string) {
  return digest(`${b64(rateKey)}:${email}`);
}
async function encrypt(value: string): Promise<Protected> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return { iv: b64(iv), cipher: b64(new Uint8Array(cipher)) };
}
async function decrypt(value: Protected) {
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(value.iv) }, key, unb64(value.cipher));
  return new TextDecoder().decode(plain);
}
async function recoveryKdf(code: string, salt: string) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: unb64(salt), iterations: 210000 },
    key, 256
  );
  return b64(new Uint8Array(bits));
}
async function hashRecovery(code: string): Promise<RecoveryHash> {
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  return { salt, hash: await recoveryKdf(code, salt) };
}
async function recoveryMatches(record: RecoveryHash, code: string) {
  return equal(record.hash, await recoveryKdf(code, record.salt));
}
function base32Bytes(value: string) {
  let bits = "";
  for (const char of value.replace(/=/g, "").toUpperCase()) {
    const index = B32.indexOf(char);
    if (index < 0) throw new Error("invalid base32");
    bits += index.toString(2).padStart(5, "0");
  }
  const result: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) result.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(result);
}
async function totp(secret: string, step: number) {
  const counter = new Uint8Array(8);
  let value = BigInt(step);
  for (let i = 7; i >= 0; i--) {
    counter[i] = Number(value & 255n);
    value >>= 8n;
  }
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = mac[19] & 15;
  const number = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}
function uri(email: string, secret: string) {
  return `otpauth://totp/${encodeURIComponent(ISSUER)}:${encodeURIComponent(email)}?secret=${secret}&issuer=${encodeURIComponent(ISSUER)}&algorithm=SHA1&digits=6&period=30`;
}
function newRecord(accountId: string): MfaRecord {
  return {
    accountId, enabled: false, recoveryHashes: [], provisioned: false,
    otpAttempts: 0, otpLockedUntil: 0, recoveryAttempts: 0,
    recoveryLockedUntil: 0, usedTotpSteps: new Set()
  };
}
function ownedRecord(session: Session) {
  if (!session.account || session.account !== DEMO_ACCOUNT.id || session.email !== DEMO_ACCOUNT.email) return undefined;
  let record = mfaRecords.get(session.account);
  if (!record) {
    record = newRecord(session.account);
    mfaRecords.set(session.account, record);
  }
  return record;
}
function newSession(account?: string, email?: string) {
  const now = Date.now();
  const session: Session = { id: token(), csrf: token(), created: now, seen: now, account, email, resends: 0, resendStarted: now, setupCount: 0 };
  sessions.set(session.id, session);
  return session;
}
function cookieValues(request: Request) {
  const result: Record<string, string> = {};
  for (const item of (request.headers.get("cookie") || "").split(";")) {
    const at = item.indexOf("=");
    if (at > 0) result[item.slice(0, at).trim()] = decodeURIComponent(item.slice(at + 1).trim());
  }
  return result;
}
function sessionFor(request: Request) {
  const session = sessions.get(cookieValues(request)[COOKIE]);
  if (!session || Date.now() - session.seen > IDLE || Date.now() - session.created > ABSOLUTE) {
    if (session) sessions.delete(session.id);
    return undefined;
  }
  session.seen = Date.now();
  return session;
}
function sessionCookie(session: Session) {
  return `${COOKIE}=${encodeURIComponent(session.id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE / 1000}`;
}
function standardHeaders(origin?: string | null, nonce?: string) {
  const headers = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'self' 'nonce-${nonce || "none"}'; style-src 'self' 'nonce-${nonce || "none"}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store"
  });
  if (origin && origins.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}
function json(body: unknown, status = 200, request?: Request, extra?: Record<string, string>) {
  const headers = standardHeaders(request?.headers.get("origin"));
  headers.set("Content-Type", "application/json; charset=utf-8");
  for (const [key, value] of Object.entries(extra || {})) headers.set(key, value);
  return new Response(JSON.stringify(body), { status, headers });
}
function fail(message: string, status: number, request: Request) {
  return json({ ok: false, message }, status, request);
}
function allowedOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return !origin || origins.has(origin);
}
async function bodyOf(request: Request): Promise<Record<string, unknown> | undefined> {
  if (Number(request.headers.get("content-length") || 0) > 10_000) return undefined;
  try {
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body) || "userId" in body || "accountId" in body || "redirect" in body) return undefined;
    return body as Record<string, unknown>;
  } catch {
    return undefined;
  }
}
function csrf(session: Session, body: Record<string, unknown>) {
  return typeof body.csrf === "string" && body.csrf.length > 30 && equal(session.csrf, body.csrf);
}
function waitMessage(until: number) {
  return `Too many tries were made. Please wait until ${new Date(until).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}, then try again.`;
}
async function sendIdentity(session: Session) {
  const code = fixedOrRandomIdentityCode();
  session.identity = { hash: await digest(code), expires: Date.now() + CODE_LIFE, used: false, attempts: 0, lockedUntil: 0 };
  /* Never log code server-side. Browser logs only simulated delivery. */
  return code;
}
function deliveryPayload(code: string) {
  return SIMULATED_DELIVERY ? { simulatedDelivery: true, simulatedIdentityCode: code } : { simulatedDelivery: false };
}
function testPayload(values: Record<string, string | string[]>) {
  return TEST_ONLY ? { testMode: true, testValues: values } : { testMode: false };
}

const page = (nonce: string) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbor Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#162631;--muted:#50616c;--blue:#075d9f;--pale:#eef7fc;--line:#bdd0db;--good:#166f46;--bad:#a52e27}*{box-sizing:border-box}body{margin:0;background:#edf3f5;color:var(--ink);font:17px/1.65 Arial,Verdana,Tahoma,sans-serif;letter-spacing:.035em;word-spacing:.07em}.shell{max-width:560px;min-height:100vh;margin:auto;background:#fff;padding:20px 18px 38px}header{padding-bottom:14px;border-bottom:2px solid var(--line);margin-bottom:20px}.brand{font-weight:700;color:#034a80}.step{margin-top:7px;color:var(--muted);font-size:.92rem}h1{font-size:1.52rem;line-height:1.3;margin:0 0 12px}h2{font-size:1.15rem}.icon{display:block;font-size:2rem;margin-bottom:8px}p{margin:0 0 16px}label{display:block;font-weight:700;margin:18px 0 5px}.hint,.small{display:block;color:var(--muted);font-size:.9rem;margin-bottom:6px}input{width:100%;min-height:52px;border:2px solid #8297a4;border-radius:9px;padding:9px 12px;font:inherit;letter-spacing:inherit}input:focus{outline:3px solid #76b9e8;outline-offset:2px;border-color:var(--blue)}button{font:inherit;letter-spacing:inherit;cursor:pointer}.primary{width:100%;min-height:55px;border:0;border-radius:9px;background:var(--blue);color:#fff;font-weight:700;margin:21px 0 10px}.secondary{min-height:44px;border:2px solid var(--blue);border-radius:8px;background:#fff;color:#034a80;padding:6px 11px;margin:4px 5px 4px 0;font-weight:700}.text{border:0;background:none;color:#034a80;padding:8px 0;text-decoration:underline;font-weight:700}.card{background:var(--pale);border:1px solid var(--line);border-radius:12px;padding:16px;margin:17px 0}.notice,.error{padding:11px 13px;margin:15px 0;border-left:5px solid var(--good);background:#edf9f1}.error{border-left-color:var(--bad);background:#fff0ef}.status{min-height:1.8em}.test{border-left-color:#8a6400;background:#fff9e8}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px}.recovery{font:15px monospace;letter-spacing:.07em;text-align:center;padding:9px 3px;border:1px solid var(--line);background:#fff;border-radius:6px}.qrwrap{text-align:center}.qr{display:grid;grid-template-columns:repeat(57,4px);width:244px;line-height:0;padding:8px;margin:auto;background:#fff;border:1px solid var(--line)}.qr i{height:4px;background:#fff}.qr i.b{background:#111}details{border-top:1px solid var(--line);padding-top:12px;margin-top:20px}summary{color:#034a80;font-weight:700;cursor:pointer}.logs{margin-top:25px;padding-top:14px;border-top:2px solid var(--line)}#logBox{min-height:76px;max-height:200px;overflow:auto;white-space:pre-wrap;border-radius:8px;padding:11px;background:#10232d;color:#e9f7ff;font:13px/1.55 monospace;letter-spacing:0}
</style></head><body><div class="shell"><header><div class="brand">◈ Harbor Bank</div><div id="step" class="step">Security setup</div></header><main id="app" aria-live="polite"></main><section class="logs"><h2>Logs</h2><p class="small">Simulated values are visible only in this demo.</p><div id="logBox">Ready. Nothing has been stored in this browser.</div></section></div>
<script nonce="${nonce}">(()=>{
const app=document.querySelector('#app'),step=document.querySelector('#step'),logBox=document.querySelector('#logBox');
let csrf='',screen='signin',secret='',setupUri='',codes=[],shownSecret=true,shownCodes=true,test={},remaining=0;const logs=[];
const esc=x=>String(x).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const say=x=>{logs.push(x);console.log(x);logBox.textContent=logs.join('\\n');logBox.scrollTop=logBox.scrollHeight};
const api=async(path,data,method='POST')=>{const r=await fetch(path,{method,credentials:'same-origin',headers:{"Content-Type":"application/json"},body:method==='GET'?undefined:JSON.stringify(data||{})});const v=await r.json().catch(()=>({message:"We could not complete that step. Please try again."}));if(!r.ok)throw Error(v.message);return v};
const note=(v,label)=>v?'<div class="notice test"><strong>Simulated demo value:</strong> '+esc(label)+': <strong>'+esc(Array.isArray(v)?v.join(', '):v)+'</strong></div>':'';
const help=()=>'<details><summary>Need help?</summary><p>Take your time. Nothing disappears while you read. You can retry safely.</p></details>';
const status=(text,bad=false)=>{const e=document.querySelector('#status');if(e){e.textContent=text;e.className=(bad?'error':'notice')+' status'}};
function simulation(r,label){test=r.testValues||{};if(r.simulatedDelivery){say('[SIMULATED IDENTITY DELIVERY] identityCode='+r.simulatedIdentityCode)}else if(r.testMode){say('[TEST SIMULATION '+label+'] '+Object.entries(test).map(([k,v])=>k+'='+(Array.isArray(v)?v.join(', '):v)).join(' | '))}else say('['+label+'] Completed securely. Private values are redacted.')}
function render(){
 const views={
 signin:()=>{step.textContent='Step 1 of 5 · Sign in';return '<span class="icon">🔐</span><h1>Sign in to start security setup</h1><p>Use your bank email and password. We will send one short identity code.</p><label for="email">Email address</label><span class="hint">Example: marcus@example.com</span><input id="email" type="email" autocomplete="email" placeholder="name@example.com"><label for="password">Password</label><span class="hint">Your password manager can fill this.</span><input id="password" type="password" autocomplete="current-password"><div id="status" class="status"></div><button class="primary" id="signin">Sign in</button><details><summary>Demo account details</summary><p>Email: marcus@example.com<br>Password: MarcusDemo!54</p></details>'+help()},
 identity:()=>{step.textContent='Step 2 of 5 · Check it is you';return '<span class="icon">✉️</span><h1>Enter your identity code</h1><p>We sent a 6-digit code to your email.</p>'+note(test.identityCode||test.simulatedIdentityCode,'Identity code')+'<label for="identity">6-digit code</label><span class="hint">Example: 123456</span><input id="identity" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><div id="status" class="status"></div><button class="primary" id="identityCheck">Check code</button><button class="text" id="resend">Send a new code</button>'+help()},
 setup:()=>{step.textContent='Step 3 of 5 · Add your authenticator';return '<span class="icon">📱</span><h1>Add Harbor Bank to your authenticator app</h1><p>Scan this QR code. Or copy and paste the setup secret.</p><div class="card qrwrap"><div class="qr" id="qr" role="img" aria-label="Authenticator setup QR code"></div><p class="small">Use the manual secret below if scanning is difficult.</p></div>'+note(test.provisioningSecret,'Test setup secret')+'<button class="secondary" id="copySecret">Copy setup secret</button><button class="secondary" id="copyUri">Copy setup link</button><button class="secondary" id="hideSecret">'+(shownSecret?'Hide secret':'Show secret')+'</button><label for="manual">Manual setup secret</label><span class="hint">Copy and paste this into your authenticator app.</span><input id="manual" type="'+(shownSecret?'text':'password')+'" spellcheck="false" value="'+esc(secret)+'"><div id="status" class="status"></div><button class="primary" id="appAdded">I added it to my app</button><button class="text" id="newSetup">Get a new setup code</button>'+help()},
 otp:()=>{step.textContent='Step 4 of 5 · Check your authenticator';return '<span class="icon">🔢</span><h1>Enter the code from your authenticator app</h1><p>Use the current 6-digit code. Take your time.</p>'+note(test.authenticatorOtp,'Test authenticator code')+'<label for="otp">Authenticator code</label><span class="hint">Example: 123456</span><input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><div id="status" class="status"></div><button class="primary" id="otpCheck">Check authenticator</button><button class="text" id="back">Go back to setup</button>'+help()},
 backup:()=>{step.textContent='Step 5 of 5 · Save backup codes';const list=shownCodes?codes.map(x=>'<div class="recovery">'+esc(x)+'</div>').join(''):'<div class="recovery">•••••-•••••</div>'.repeat(8);return '<span class="icon">🧾</span><h1>Save your backup codes</h1><p>Keep these somewhere safe. Each code works once if you cannot use your authenticator.</p><div class="card"><div class="codes">'+list+'</div></div><button class="secondary" id="copyCodes">Copy all codes</button><button class="secondary" id="hideCodes">'+(shownCodes?'Hide codes':'Show codes')+'</button><label for="confirm">Paste one saved code</label><span class="hint">Example: ABCDE-23456. This check does not use up your code.</span><input id="confirm" autocomplete="one-time-code" placeholder="ABCDE-23456"><div id="status" class="status"></div><button class="primary" id="saveCheck">Check saved code</button>'+help()},
 done:()=>{step.textContent='Complete · MFA is ready';return '<span class="icon">✓</span><h1>Your security setup is complete</h1><div class="notice">MFA is enabled. Your authenticator is ready. You have '+remaining+' backup codes available.</div><label for="useCode">Use a backup code</label><span class="hint">Example: ABCDE-23456. A used code cannot be used again.</span><input id="useCode" autocomplete="one-time-code" placeholder="ABCDE-23456"><div id="status" class="status"></div><button class="secondary" id="useRecovery">Use backup code</button><button class="secondary" id="regenerate">Replace backup codes</button><button class="primary" id="logout">Sign out</button>'+help()}
 };
 app.innerHTML=views[screen]();if(screen==='setup')drawQr(setupUri);bind();
}
/* QR Model 2 Version 10-L, byte mode, mask 0. Includes both Version Information regions with BCH. */
function drawQr(text){
 const el=document.querySelector('#qr'),n=57;if(!el)return;const g=Array.from({length:n},()=>Array(n).fill(null));const set=(x,y,v)=>{if(x>=0&&y>=0&&x<n&&y<n)g[y][x]=v};
 const finder=(x,y)=>{for(let dy=-1;dy<=7;dy++)for(let dx=-1;dx<=7;dx++){const inb=dx>=0&&dx<=6&&dy>=0&&dy<=6;set(x+dx,y+dy,inb&&(dx===0||dy===0||dx===6||dy===6||(dx>=2&&dx<=4&&dy>=2&&dy<=4)))}};
 finder(0,0);finder(50,0);finder(0,50);
 [6,28,50].forEach(y=>[6,28,50].forEach(x=>{if(g[y][x]!==null)return;for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)set(x+dx,y+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1)}));
 for(let i=8;i<n-8;i++){if(g[6][i]===null)set(i,6,i%2===0);if(g[i][6]===null)set(6,i,i%2===0)}
 for(let i=0;i<9;i++){if(g[8][i]===null)set(i,8,false);if(g[i][8]===null)set(8,i,false);if(g[8][n-1-i]===null)set(n-1-i,8,false);if(g[n-1-i][8]===null)set(8,n-1-i,false)}set(8,n-8,true);
 /* Required Version 10 BCH(18,6) information, reserved before data placement. */
 let versionBits=10<<12,work=versionBits;while(work.toString(2).length>=0x1f25.toString(2).length)work^=0x1f25<<(work.toString(2).length-0x1f25.toString(2).length);versionBits|=work;
 for(let i=0;i<18;i++){const bit=((versionBits>>>i)&1)===1;set(n-11+(i%3),Math.floor(i/3),bit);set(Math.floor(i/3),n-11+(i%3),bit)}
 const bytes=Array.from(new TextEncoder().encode(text));if(bytes.length>271){el.textContent='QR data is too long.';return}
 let bits='0100'+bytes.length.toString(2).padStart(16,'0')+bytes.map(x=>x.toString(2).padStart(8,'0')).join('');bits+='0'.repeat(Math.min(4,274*8-bits.length));while(bits.length%8)bits+='0';
 const data=[];for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8),2));for(let pad=true;data.length<274;pad=!pad)data.push(pad?0xec:0x11);
 const exp=Array(512),log=Array(256);let z=1;for(let i=0;i<255;i++){exp[i]=z;log[z]=i;z<<=1;if(z&256)z^=0x11d}for(let i=255;i<512;i++)exp[i]=exp[i-255];const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;
 let gen=[1];for(let i=0;i<18;i++){const q=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){q[j]^=gen[j];q[j+1]^=mul(gen[j],exp[i])}gen=q}const ecc=b=>{const r=Array(18).fill(0);for(const x of b){const f=x^r.shift();r.push(0);for(let j=0;j<18;j++)r[j]^=mul(gen[j+1],f)}return r};
 let pos=0;const blocks=[68,68,69,69].map(size=>{const d=data.slice(pos,pos+size);pos+=size;return {d,e:ecc(d)}}),stream=[];for(let i=0;i<69;i++)blocks.forEach(b=>{if(i<b.d.length)stream.push(b.d[i])});for(let i=0;i<18;i++)blocks.forEach(b=>stream.push(b.e[i]));
 const dataBits=stream.map(x=>x.toString(2).padStart(8,'0')).join('');let p=0,up=true;for(let x=n-1;x>0;x-=2){if(x===6)x--;for(let q=0;q<n;q++){const y=up?n-1-q:q;for(let dx=0;dx<2;dx++){const xx=x-dx;if(g[y][xx]===null){let bit=p<dataBits.length&&dataBits[p++]==='1';if((xx+y)%2===0)bit=!bit;set(xx,y,bit)}}}up=!up}
 let format=1<<3,rem=format;for(let i=0;i<10;i++)rem=(rem<<1)^(((rem>>>9)&1)?0x537:0);format=((format<<10)|rem)^0x5412;for(let i=0;i<15;i++){const bit=((format>>>i)&1)===1;if(i<6)set(i,8,bit);else if(i<8)set(i+1,8,bit);else set(n-15+i,8,bit);if(i<8)set(8,n-i-1,bit);else if(i<9)set(8,15-i,bit);else set(8,14-i,bit)}
 el.innerHTML=g.flat().map(v=>'<i class="'+(v?'b':'')+'"></i>').join('');
}
const copy=async(v,ok)=>{try{await navigator.clipboard.writeText(v);status(ok)}catch{status('Copy did not work here. Select the text and copy it instead.',true)}};
function bind(){const on=(id,fn)=>{const e=document.querySelector('#'+id);if(e)e.onclick=fn};
 on('signin',async()=>{try{const r=await api('/api/signin',{csrf,email:document.querySelector('#email').value,password:document.querySelector('#password').value});csrf=r.csrf;test=r.simulatedDelivery?{identityCode:r.simulatedIdentityCode}:{};simulation(r,'IDENTITY DELIVERY');screen='identity';render()}catch(e){status(e.message,true)}});
 on('resend',async()=>{try{const r=await api('/api/identity/resend',{csrf});test=r.simulatedDelivery?{identityCode:r.simulatedIdentityCode}:{};simulation(r,'IDENTITY DELIVERY');status('A new code was sent. Use the new code.')}catch(e){status(e.message,true)}});
 on('identityCheck',async()=>{try{const r=await api('/api/identity/verify',{csrf,code:document.querySelector('#identity').value});if(r.enabled){remaining=r.remaining;test={};screen='done';render()}else{const p=await api('/api/provision',{csrf});secret=p.secret;setupUri=p.uri;simulation(p,'AUTHENTICATOR PROVISIONING');screen='setup';render()}}catch(e){status(e.message,true)}});
 on('copySecret',()=>copy(secret,'Setup secret copied. Paste it into your authenticator app.'));on('copyUri',()=>copy(setupUri,'Setup link copied.'));on('hideSecret',()=>{shownSecret=!shownSecret;render()});
 on('newSetup',async()=>{try{const r=await api('/api/provision',{csrf});secret=r.secret;setupUri=r.uri;simulation(r,'AUTHENTICATOR PROVISIONING');render();status('A new setup secret is ready. Add this one instead.')}catch(e){status(e.message,true)}});
 on('appAdded',async()=>{try{const r=await api('/api/provision/manual',{csrf,secret:document.querySelector('#manual').value});simulation(r,'AUTHENTICATOR READY');screen='otp';render()}catch(e){status(e.message,true)}});
 on('back',()=>{screen='setup';render()});on('otpCheck',async()=>{try{const r=await api('/api/otp/verify',{csrf,code:document.querySelector('#otp').value});codes=r.recoveryCodes;simulation(r,'RECOVERY CODES');screen='backup';render()}catch(e){status(e.message,true)}});
 on('copyCodes',()=>copy(codes.join('\\n'),'Backup codes copied. Store them in a safe place.'));on('hideCodes',()=>{shownCodes=!shownCodes;render()});
 on('saveCheck',async()=>{try{const r=await api('/api/recovery/confirm',{csrf,code:document.querySelector('#confirm').value});remaining=r.remaining;codes=[];test={};screen='done';render()}catch(e){status(e.message,true)}});
 on('useRecovery',async()=>{try{const r=await api('/api/recovery/use',{csrf,code:document.querySelector('#useCode').value});remaining=r.remaining;status(r.message)}catch(e){status(e.message,true)}});
 on('regenerate',async()=>{try{const r=await api('/api/recovery/regenerate',{csrf});codes=r.recoveryCodes;simulation(r,'RECOVERY CODES');shownCodes=true;screen='backup';render();status('New backup codes are ready. The older codes no longer work.')}catch(e){status(e.message,true)}});
 on('logout',async()=>{try{await api('/api/logout',{csrf});csrf='';secret='';setupUri='';codes=[];test={};say('[SESSION] Signed out. MFA settings remain on the account.');screen='signin';render()}catch(e){status(e.message,true)}});
}
(async()=>{try{const r=await api('/api/csrf',null,'GET');csrf=r.csrf;render()}catch{app.textContent='Secure setup is unavailable. Please refresh the page.'}})();
})();</script></body></html>`;

async function api(request: Request, path: string): Promise<Response> {
  if (!allowedOrigin(request)) return fail("This request is not allowed.", 403, request);
  if (request.method === "OPTIONS") {
    const headers = standardHeaders(request.headers.get("origin"));
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type");
    return new Response(null, { status: 204, headers });
  }
  if (path === "/api/csrf" && request.method === "GET") {
    let session = sessionFor(request);
    if (!session) session = newSession();
    return json({ ok: true, csrf: session.csrf }, 200, request, { "Set-Cookie": sessionCookie(session) });
  }
  if (request.method !== "POST") return fail("That page is not available.", 404, request);
  const body = await bodyOf(request);
  if (!body) return fail("Please check the information and try again.", 400, request);

  if (path === "/api/signin") {
    const old = sessionFor(request);
    if (!old || !csrf(old, body)) return fail("Please refresh the page and try signing in again.", 403, request);
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const key = await rateId(email || "invalid");
    const limit = loginLimits.get(key);
    const now = Date.now();
    if (limit && limit.lockedUntil > now) return fail("Sign-in is temporarily unavailable. Please wait a few minutes, then try again.", 429, request);
    const submitted = await digest(`${email}\u0000${password}`);
    const expected = await digest(`${DEMO_ACCOUNT.email}\u0000${DEMO_ACCOUNT.password}`);
    const valid = /^[^\s@]+@[^\s@]+\.[^\s@]{2,100}$/.test(email) && password.length > 0 && password.length <= 200 && equal(submitted, expected);
    if (!valid) {
      const next = { attempts: (limit?.lockedUntil || 0) <= now ? (limit?.attempts || 0) + 1 : 1, lockedUntil: 0 };
      if (next.attempts >= MAX_ATTEMPTS) next.lockedUntil = now + LOCK;
      loginLimits.set(key, next);
      return fail(next.lockedUntil ? "Sign-in is temporarily unavailable. Please wait a few minutes, then try again." : "Check your email and password, then try again.", next.lockedUntil ? 429 : 401, request);
    }
    loginLimits.delete(key);
    sessions.delete(old.id); // Requirement 5: rotate session after authentication.
    const session = newSession(DEMO_ACCOUNT.id, DEMO_ACCOUNT.email);
    const code = await sendIdentity(session);
    console.log("[MFA] Authentication session created.");
    return json({ ok: true, csrf: session.csrf, ...deliveryPayload(code) }, 200, request, { "Set-Cookie": sessionCookie(session) });
  }

  /* Requirement 1: every MFA access/change requires this authorized owner. */
  const session = sessionFor(request);
  const record = session ? ownedRecord(session) : undefined;
  if (!session || !record) return fail("Your secure session has ended. Please sign in again.", 401, request);
  if (!csrf(session, body)) return fail("Please refresh the page before trying again.", 403, request);

  if (path === "/api/identity/resend") {
    if (!session.identity || session.identity.used) return fail("Please sign in again before requesting a code.", 403, request);
    if (session.identity.lockedUntil > Date.now()) return fail(waitMessage(session.identity.lockedUntil), 429, request);
    if (Date.now() - session.resendStarted > 10 * 60_000) { session.resendStarted = Date.now(); session.resends = 0; }
    if (++session.resends > 3) return fail("Too many new codes were requested. Please wait a few minutes, then try again.", 429, request);
    const code = await sendIdentity(session);
    return json({ ok: true, ...deliveryPayload(code) }, 200, request);
  }
  if (path === "/api/identity/verify") {
    const code = typeof body.code === "string" ? body.code.trim() : "";
    if (!/^\d{6}$/.test(code)) return fail("Enter the 6-digit code, for example 123456.", 400, request);
    const identity = session.identity;
    if (!identity) return fail("Please request a new identity code.", 400, request);
    if (identity.lockedUntil > Date.now()) return fail(waitMessage(identity.lockedUntil), 429, request);
    if (identity.used || identity.expires < Date.now() || !equal(await digest(code), identity.hash)) {
      if (++identity.attempts >= MAX_ATTEMPTS) identity.lockedUntil = Date.now() + LOCK;
      return fail(identity.lockedUntil ? waitMessage(identity.lockedUntil) : "That code is not right or has been used. Check it, or request a new code.", identity.lockedUntil ? 429 : 400, request);
    }
    identity.used = true;
    return json({ ok: true, enabled: record.enabled, remaining: record.recoveryHashes.length }, 200, request);
  }
  if (path === "/api/provision") {
    if (!session.identity?.used) return fail("Check your identity code before setting up an authenticator.", 403, request);
    if (record.enabled) return fail("MFA is already enabled for this account.", 400, request);
    const secret = TEST_ONLY ? TEST_SECRETS[session.setupCount++ % TEST_SECRETS.length] : secureText(B32, 20);
    record.otpSecret = await encrypt(secret);
    record.provisioned = false;
    record.usedTotpSteps = new Set();
    record.recoveryHashes = [];
    const provisioningUri = uri(session.email!, secret);
    return json({ ok: true, secret, uri: provisioningUri, ...testPayload({ provisioningSecret: secret, provisioningUri, authenticatorOtp: "654321" }) }, 200, request);
  }
  if (path === "/api/provision/manual") {
    const supplied = typeof body.secret === "string" ? body.secret.trim().toUpperCase().replaceAll(" ", "") : "";
    if (!session.identity?.used || !record.otpSecret || !/^[A-Z2-7]{16,64}$/.test(supplied)) return fail("Paste the full setup secret, then try again.", 400, request);
    if (!equal(supplied, await decrypt(record.otpSecret))) return fail("That setup secret does not match this account. Get a new setup code and try again.", 400, request);
    record.provisioned = true;
    return json({ ok: true, ...testPayload({ authenticatorOtp: "654321" }) }, 200, request);
  }
  if (path === "/api/otp/verify") {
    const code = typeof body.code === "string" ? body.code.trim() : "";
    const now = Date.now();
    if (!/^\d{6}$/.test(code)) return fail("Enter the 6-digit authenticator code, for example 123456.", 400, request);
    if (!record.provisioned || !record.otpSecret) return fail("Set up your authenticator before checking its code.", 403, request);
    if (record.otpLockedUntil > now) return fail(waitMessage(record.otpLockedUntil), 429, request);
    let used: number | undefined;
    if (TEST_ONLY) { if (equal(code, "654321")) used = -1; }
    else {
      const secret = await decrypt(record.otpSecret);
      const step = Math.floor(now / 30_000);
      for (const candidate of [step - 1, step, step + 1]) if (!record.usedTotpSteps.has(candidate) && equal(code, await totp(secret, candidate))) { used = candidate; break; }
    }
    if (used === undefined) {
      if (++record.otpAttempts >= MAX_ATTEMPTS) record.otpLockedUntil = now + LOCK;
      return fail(record.otpLockedUntil ? waitMessage(record.otpLockedUntil) : `That authenticator code is not right, is too old, or has already been used. You have ${MAX_ATTEMPTS - record.otpAttempts} tries before a short wait.`, record.otpLockedUntil ? 429 : 400, request);
    }
    record.usedTotpSteps.add(used);
    record.otpAttempts = 0;
    record.enabled = true;
    const generated = recoveryCodes();
    record.recoveryHashes = await Promise.all(generated.map(hashRecovery));
    return json({ ok: true, recoveryCodes: generated, ...testPayload({ recoveryCodes: generated }) }, 200, request);
  }
  if (path === "/api/recovery/regenerate") {
    if (!record.enabled || !session.identity?.used) return fail("Check your identity before replacing backup codes.", 403, request);
    const generated = recoveryCodes();
    record.recoveryHashes = await Promise.all(generated.map(hashRecovery));
    record.recoveryAttempts = 0;
    console.log("[MFA] Recovery codes regenerated.");
    return json({ ok: true, recoveryCodes: generated, ...testPayload({ recoveryCodes: generated }) }, 200, request);
  }
  if (path === "/api/recovery/confirm" || path === "/api/recovery/use") {
    const code = typeof body.code === "string" ? body.code.trim().toUpperCase() : "";
    const now = Date.now();
    if (!record.enabled || !/^[A-Z2-7]{5}-[A-Z2-7]{5}$/.test(code)) return fail("Paste one saved backup code in the format ABCDE-23456.", 400, request);
    if (record.recoveryLockedUntil > now) return fail(waitMessage(record.recoveryLockedUntil), 429, request);
    const matches = await Promise.all(record.recoveryHashes.map(x => recoveryMatches(x, code)));
    const index = matches.findIndex(Boolean);
    if (index < 0) {
      if (++record.recoveryAttempts >= MAX_ATTEMPTS) record.recoveryLockedUntil = now + LOCK;
      return fail(record.recoveryLockedUntil ? waitMessage(record.recoveryLockedUntil) : "That backup code was not found. Paste one of the codes you saved.", record.recoveryLockedUntil ? 429 : 400, request);
    }
    record.recoveryAttempts = 0;
    if (path === "/api/recovery/use") {
      record.recoveryHashes.splice(index, 1); // single-threaded in-memory mutation: strictly single use
      console.log("[MFA] A recovery code was accepted and consumed.");
      return json({ ok: true, message: "Your backup code was accepted and is now used.", remaining: record.recoveryHashes.length }, 200, request);
    }
    return json({ ok: true, message: "Your saved code was checked. It was not used up.", remaining: record.recoveryHashes.length }, 200, request);
  }
  if (path === "/api/logout") {
    sessions.delete(session.id);
    /* MFA record deliberately remains account-owned after logout. */
    return json({ ok: true }, 200, request, { "Set-Cookie": `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0` });
  }
  return fail("That page is not available.", 404, request);
}

Bun.serve({
  port: PORT,
  tls: {
    cert: readFileSync("certs/cert.pem", "utf8"),
    key: readFileSync("certs/key.pem", "utf8")
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:") return new Response(null, { status: 301, headers: { Location: `https://${url.host}${url.pathname}` } });
      if (url.pathname.startsWith("/api/")) return api(request, url.pathname);
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = token(18);
        const headers = standardHeaders(request.headers.get("origin"), nonce);
        headers.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers });
      }
      return new Response("Page not found.", { status: 404, headers: standardHeaders(request.headers.get("origin")) });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: standardHeaders() });
    }
  }
});

console.log(`MFA enrolment server ready at https://localhost:${PORT}`);
