
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — requirements sections 1–5:
 ownership checks, CSRF, TLS, secure cookies/headers, encryption,
 hashed recovery codes, input validation, rate limits, and safe mocks.
*/
const PORT = Number(Bun.env.PORT || 3000);
const TEST_ONLY = Bun.env.MFA_TEST_MODE === "1";
const COOKIE = "__Host_mfa_session";
const IDLE = 30 * 60 * 1000;
const ABSOLUTE = 8 * 60 * 60 * 1000;
const CODE_LIFE = 15 * 60 * 1000;
const LOCK = 10 * 60 * 1000;
const MAX = 5;
const RESEND_WINDOW = 10 * 60 * 1000;
const MAX_RESENDS = 3;
const ISSUER = "Harbor Bank";
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

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

/* Both test secrets are valid Base32 and accepted by manual provisioning. */
const TEST_SECRETS = ["JBSWY3DPEHPK3PXPJBSWY", "KRUGS4ZANFZSAYJAON2X"];
const TEST_RECOVERY = [
  "ALPHA-23456", "BRAVO-23456", "CHARL-23456", "DELTA-23456",
  "ECHOX-23456", "FOXTN-23456", "GOLFY-23456", "HOTEL-23456"
];

type Protected = { cipher: string; iv: string };
type OneCode = { hash: string; expires: number; used: boolean; attempts: number; lockedUntil: number };
type RecoveryHash = { salt: string; hash: string };
type LoginLimit = { attempts: number; lockedUntil: number };
type Session = {
  id: string;
  csrf: string;
  created: number;
  seen: number;
  account?: string;
  email?: string;
  identity?: OneCode;
  identityResends?: number;
  identityResendWindow?: number;
  secret?: Protected;
  provisioned?: boolean;
  otpVerified?: boolean;
  usedTotpSteps?: Set<number>;
  otpAttempts?: number;
  otpLockedUntil?: number;
  recovery?: { hashes: RecoveryHash[] };
  recoveryAttempts?: number;
  recoveryLockedUntil?: number;
  provisionCount?: number;
};

const sessions = new Map<string, Session>();
const loginLimits = new Map<string, LoginLimit>();
const loginRateKey = crypto.getRandomValues(new Uint8Array(32));
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const encoder = new TextEncoder();

function b64(bytes: Uint8Array) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}
function unb64(text: string) {
  return Uint8Array.from(atob(text), c => c.charCodeAt(0));
}
function token(length = 32) {
  return b64(crypto.getRandomValues(new Uint8Array(length))).replace(/[+/=]/g, c =>
    c === "+" ? "-" : c === "/" ? "_" : ""
  );
}
function secureText(chars: string, length: number) {
  const output: string[] = [];
  const limit = 256 - (256 % chars.length);
  while (output.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length - output.length))) {
      if (byte < limit) output.push(chars[byte % chars.length]);
    }
  }
  return output.join("");
}
function secureSixDigits() {
  return TEST_ONLY ? "123456" : secureText("0123456789", 6);
}
function makeRecoveryCodes() {
  if (TEST_ONLY) return [...TEST_RECOVERY];
  const values = new Set<string>();
  while (values.size < 8) values.add(`${secureText(B32, 5)}-${secureText(B32, 5)}`);
  return [...values];
}
async function hash(value: string) {
  return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}
async function loginKey(email: string) {
  return hash(`${b64(loginRateKey)}:${email}`);
}
function constantEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}
async function recoveryKdf(code: string, salt: string) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: unb64(salt), iterations: 210000 },
    key, 256
  );
  return b64(new Uint8Array(bits));
}
async function protectRecoveryCode(code: string): Promise<RecoveryHash> {
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  return { salt, hash: await recoveryKdf(code, salt) };
}
async function recoveryMatches(record: RecoveryHash, code: string) {
  return constantEqual(record.hash, await recoveryKdf(code, record.salt));
}

/* Requirement 3: AES-GCM protects the OTP seed held in server memory. */
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
function base32Bytes(value: string) {
  let bits = "";
  for (const char of value.replace(/=/g, "").toUpperCase()) {
    const index = B32.indexOf(char);
    if (index < 0) throw new Error("Invalid Base32");
    bits += index.toString(2).padStart(5, "0");
  }
  const output: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) output.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(output);
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
  return String(number % 1000000).padStart(6, "0");
}
function provisioningUri(email: string, secret: string) {
  return `otpauth://totp/${encodeURIComponent(ISSUER)}:${encodeURIComponent(email)}?secret=${secret}&issuer=${encodeURIComponent(ISSUER)}&algorithm=SHA1&digits=6&period=30`;
}
function makeSession(account?: string, email?: string) {
  const now = Date.now();
  const session: Session = { id: token(), csrf: token(), created: now, seen: now, account, email };
  sessions.set(session.id, session);
  return session;
}
function cookies(request: Request) {
  const values: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const point = part.indexOf("=");
    if (point > 0) values[part.slice(0, point).trim()] = decodeURIComponent(part.slice(point + 1).trim());
  }
  return values;
}
function getSession(request: Request) {
  const session = sessions.get(cookies(request)[COOKIE]);
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
function headers(origin?: string | null, nonce = token(18)) {
  const result = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store"
  });
  if (origin && origins.has(origin)) {
    result.set("Access-Control-Allow-Origin", origin);
    result.set("Access-Control-Allow-Credentials", "true");
    result.set("Vary", "Origin");
  }
  return result;
}
function respond(body: unknown, status = 200, request?: Request, extra?: Record<string, string>) {
  const result = headers(request?.headers.get("origin"));
  result.set("Content-Type", "application/json; charset=utf-8");
  for (const [name, value] of Object.entries(extra || {})) result.set(name, value);
  return new Response(JSON.stringify(body), { status, headers: result });
}
function fail(message: string, status = 400, request?: Request) {
  return respond({ ok: false, message }, status, request);
}
function safeOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return !origin || origins.has(origin);
}
async function input(request: Request): Promise<Record<string, unknown> | null> {
  if (Number(request.headers.get("content-length") || 0) > 10000) return null;
  try {
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body) ||
      "userId" in body || "accountId" in body || "redirect" in body) return null;
    return body as Record<string, unknown>;
  } catch {
    return null;
  }
}
function csrf(session: Session, body: Record<string, unknown>) {
  return typeof body.csrf === "string" && body.csrf.length >= 30 && constantEqual(body.csrf, session.csrf);
}
function retryMessage(until: number) {
  return `Too many tries were made. Please wait until ${new Date(until).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}, then try again.`;
}
async function consumeOne(record: OneCode, code: string) {
  if (record.lockedUntil > Date.now()) return "locked";
  if (record.used || record.expires < Date.now() || !constantEqual(await hash(code), record.hash)) {
    if (++record.attempts >= MAX) record.lockedUntil = Date.now() + LOCK;
    return record.lockedUntil > Date.now() ? "locked" : "bad";
  }
  record.used = true;
  return "ok";
}
async function newIdentityCode(session: Session) {
  const code = secureSixDigits();
  session.identity = { hash: await hash(code), expires: Date.now() + CODE_LIFE, used: false, attempts: 0, lockedUntil: 0 };
  return code;
}
function testPayload(values: Record<string, string | string[]>) {
  return TEST_ONLY ? { testMode: true, testValues: values } : { testMode: false };
}

const page = (nonce: string) => `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbor Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#182630;--muted:#52636d;--blue:#075d9f;--blue2:#034a80;--pale:#eef7fc;--line:#bed0db;--good:#147344}
*{box-sizing:border-box}body{margin:0;background:#eef3f5;color:var(--ink);font-family:Arial,Verdana,Tahoma,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.035em;word-spacing:.08em}
button,input{font:inherit;letter-spacing:inherit}button{cursor:pointer}.shell{width:min(100%,560px);min-height:100vh;margin:auto;background:#fff;padding:20px 18px 38px}header{border-bottom:2px solid var(--line);padding-bottom:14px;margin-bottom:20px}.brand{font-weight:700;color:#034a80;font-size:1.08rem}.step{margin:9px 0 0;color:var(--muted);font-size:.93rem}main{min-height:440px}h1{font-size:1.55rem;line-height:1.3;margin:0 0 13px}h2{font-size:1.18rem}p{margin:0 0 17px}.icon{font-size:2rem;display:block;margin-bottom:8px}.card{background:var(--pale);border:1px solid var(--line);border-radius:12px;padding:17px;margin:18px 0}label{display:block;font-weight:700;margin:18px 0 6px}.hint{color:var(--muted);display:block;font-size:.9rem;margin-bottom:7px}input{width:100%;min-height:52px;border:2px solid #8297a4;border-radius:9px;padding:10px 12px;color:var(--ink);background:#fff}input:focus{outline:3px solid #75b8e7;outline-offset:2px;border-color:var(--blue)}.primary{width:100%;min-height:55px;margin:22px 0 12px;border:0;border-radius:9px;background:var(--blue);color:#fff;font-weight:700}.primary:hover,.primary:focus{background:var(--blue2)}.secondary{min-height:44px;color:var(--blue2);background:#fff;border:2px solid var(--blue);border-radius:8px;padding:7px 12px;margin:4px 5px 4px 0;font-weight:700}.text-btn{color:var(--blue2);background:none;border:0;padding:8px 0;text-decoration:underline;font-weight:700}.notice{border-left:5px solid var(--good);background:#edf9f1;padding:12px 14px;margin:15px 0}.error{border-left:5px solid #b42c24;background:#fff0ef;padding:12px 14px;margin:15px 0}.status{min-height:1.8em}.codes{display:grid;grid-template-columns:1fr 1fr;gap:9px}.recovery{font-family:monospace;letter-spacing:.07em;padding:10px 6px;text-align:center;border:1px solid var(--line);border-radius:7px;background:#fff}.qrwrap{text-align:center}.qr{display:grid;grid-template-columns:repeat(57,4px);width:244px;margin:0 auto;padding:8px;background:#fff;border:1px solid var(--line);line-height:0}.qr i{height:4px;background:#fff}.qr i.b{background:#111}details{border-top:1px solid var(--line);padding-top:12px;margin-top:22px}summary{color:var(--blue2);font-weight:700;cursor:pointer}.logs{margin-top:25px;border-top:2px solid var(--line);padding-top:16px}#logBox{background:#10232d;color:#e9f7ff;font:13px/1.55 monospace;letter-spacing:0;padding:12px;min-height:78px;max-height:210px;overflow:auto;white-space:pre-wrap;border-radius:8px}.small{font-size:.88rem;color:var(--muted)}.test{border-left-color:#8b6200;background:#fff9e8}
</style></head><body><div class="shell">
<header><div class="brand">◈ Harbor Bank</div><div id="step" class="step">Security setup</div></header>
<main id="app" aria-live="polite"></main>
<section class="logs" aria-label="Security event logs"><h2>Logs</h2><p class="small">Security events are shown here. Production logs keep private values redacted.</p><div id="logBox">Ready. Nothing has been stored in this browser.</div></section>
</div><script nonce="${nonce}">(()=>{
const app=document.querySelector('#app'),step=document.querySelector('#step'),box=document.querySelector('#logBox');
let csrf='',current='signin',secret='',uri='',codes=[],showSecret=true,showCodes=true,testValues={};const logs=[];
const esc=x=>String(x).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const say=x=>{logs.push(x);console.log(x);box.textContent=logs.join('\\n');box.scrollTop=box.scrollHeight};
function simulationLog(response,kind){if(response&&response.testMode===true&&response.testValues){testValues=response.testValues;const shown=Object.entries(testValues).map(([k,v])=>k+'='+(Array.isArray(v)?v.join(', '):v)).join(' | ');say('[TEST SIMULATION '+kind+'] '+shown)}else{testValues={};say('['+kind+'] Completed securely. Private values are redacted.')}};
const api=async(path,data,method='POST')=>{const r=await fetch(path,{method,credentials:'same-origin',headers:{'Content-Type':'application/json'},body:method==='GET'?undefined:JSON.stringify(data||{})});const v=await r.json().catch(()=>({message:'We could not complete that step. Please try again.'}));if(!r.ok)throw Error(v.message);return v};
const help=()=>'<details><summary>Need help?</summary><p>Take your time. Nothing on this page disappears while you read it. You can retry safely.</p></details>';
const testNote=(key,label)=>{const v=testValues[key];return v?'<div class="notice test"><strong>Test-only value:</strong> '+esc(label)+': <strong>'+esc(Array.isArray(v)?v.join(', '):v)+'</strong></div>':''};
const msg=(text,bad=false)=>{const e=document.querySelector('#status');if(e){e.textContent=text;e.className=(bad?'error':'notice')+' status'}};
function render(){const views={
signin:()=>{step.textContent='Step 1 of 5 · Sign in';return '<span class="icon">🔐</span><h1>Sign in to start security setup</h1><p>Use your bank email and password. We will send one short identity code.</p><label for="email">Email address</label><span class="hint">Example: marcus@example.com</span><input id="email" type="email" autocomplete="email" placeholder="name@example.com"><label for="password">Password</label><span class="hint">Your password manager can fill this.</span><input id="password" type="password" autocomplete="current-password"><div id="status" class="status"></div><button class="primary" id="signIn">Sign in</button><details><summary>Demo account details</summary><p>Email: marcus@example.com<br>Password: MarcusDemo!54</p></details>'+help()},
identity:()=>{step.textContent='Step 2 of 5 · Check it is you';return '<span class="icon">✉️</span><h1>Enter your identity code</h1><p>We sent a 6-digit code to your email.</p>'+testNote('identityCode','Identity code')+'<label for="identityCode">6-digit code</label><span class="hint">Example: 123456</span><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><div id="status" class="status"></div><button class="primary" id="verifyIdentity">Check code</button><button class="text-btn" id="resendIdentity">Send a new code</button>'+help()},
setup:()=>{step.textContent='Step 3 of 5 · Add your authenticator';return '<span class="icon">📱</span><h1>Add Harbor Bank to your authenticator app</h1><p>Scan this QR code with your app. You can also copy and paste the setup secret.</p><div class="card qrwrap"><div id="qr" class="qr" role="img" aria-label="Authenticator setup QR code"></div><p class="small">Use the manual secret below if scanning is difficult.</p></div>'+testNote('provisioningSecret','Test setup secret')+testNote('provisioningUri','Test provisioning URI')+'<button class="secondary" id="copySecret">Copy setup secret</button><button class="secondary" id="copyUri">Copy setup link</button><button class="secondary" id="toggleSecret">'+(showSecret?'Hide secret':'Show secret')+'</button><label for="manualSecret">Manual setup secret</label><span class="hint">Copy and paste this into your authenticator app.</span><input id="manualSecret" type="'+(showSecret?'text':'password')+'" spellcheck="false" value="'+esc(secret)+'"><div id="status" class="status"></div><button class="primary" id="addedApp">I added it to my app</button><button class="text-btn" id="newSetup">Get a new setup code</button>'+help()},
otp:()=>{step.textContent='Step 4 of 5 · Check your authenticator';return '<span class="icon">🔢</span><h1>Enter the code from your authenticator app</h1><p>Use the current 6-digit code. Take your time.</p>'+testNote('authenticatorOtp','Authenticator code')+'<label for="otpCode">Authenticator code</label><span class="hint">Example: 123456</span><input id="otpCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><div id="status" class="status"></div><button class="primary" id="verifyOtp">Check authenticator</button><button class="text-btn" id="backSetup">Go back to setup</button>'+help()},
backup:()=>{step.textContent='Step 5 of 5 · Save backup codes';const list=showCodes?codes.map(c=>'<div class="recovery">'+esc(c)+'</div>').join(''):'<div class="recovery">•••••-•••••</div>'.repeat(8);return '<span class="icon">🧾</span><h1>Save your backup codes</h1><p>Keep these somewhere safe. Each code works once if you cannot use your authenticator.</p>'+testNote('recoveryCodes','Test recovery codes')+'<div class="card"><div class="codes">'+list+'</div></div><button class="secondary" id="copyCodes">Copy all codes</button><button class="secondary" id="toggleCodes">'+(showCodes?'Hide codes':'Show codes')+'</button><label for="confirmRecovery">Paste one saved code</label><span class="hint">Example: ABCDE-23456. This check does not use up your code.</span><input id="confirmRecovery" autocomplete="one-time-code" placeholder="ABCDE-23456"><div id="status" class="status"></div><button class="primary" id="confirmBackup">Check saved code</button>'+help()},
done:()=>{step.textContent='Complete · MFA is ready';return '<span class="icon">✓</span><h1>Your security setup is complete</h1><div class="notice">Your saved code was checked and was not used up. Your authenticator and backup codes are ready.</div><button class="primary" id="logout">Sign out</button>'+help()}
};app.innerHTML=views[current]();if(current==='setup')drawQr(uri);bind()}

/* Standards-compliant QR Model 2 encoder: Version 10-L, byte mode, mask 0. */
function drawQr(text){
 const el=document.querySelector('#qr');if(!el)return;
 const n=57,grid=Array.from({length:n},()=>Array(n).fill(null));
 const set=(x,y,v)=>{if(x>=0&&y>=0&&x<n&&y<n)grid[y][x]=v};
 const finder=(x,y)=>{for(let dy=-1;dy<=7;dy++)for(let dx=-1;dx<=7;dx++){const inBox=dx>=0&&dx<=6&&dy>=0&&dy<=6;const black=inBox&&(dx===0||dx===6||dy===0||dy===6||(dx>=2&&dx<=4&&dy>=2&&dy<=4));set(x+dx,y+dy,black)}};
 finder(0,0);finder(n-7,0);finder(0,n-7);
 [6,28,50].forEach(y=>[6,28,50].forEach(x=>{if(grid[y][x]!==null)return;for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)set(x+dx,y+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1)}));
 for(let i=8;i<n-8;i++){if(grid[6][i]===null)set(i,6,i%2===0);if(grid[i][6]===null)set(6,i,i%2===0)}
 for(let i=0;i<9;i++){if(grid[8][i]===null)set(i,8,false);if(grid[i][8]===null)set(8,i,false);if(grid[8][n-1-i]===null)set(n-1-i,8,false);if(grid[n-1-i][8]===null)set(8,n-1-i,false)}
 set(8,n-8,true);
 const bytes=Array.from(new TextEncoder().encode(text));if(bytes.length>271){el.textContent='QR data is too long.';return}
 let bits='0100'+bytes.length.toString(2).padStart(16,'0')+bytes.map(x=>x.toString(2).padStart(8,'0')).join('');
 bits+= '0'.repeat(Math.min(4,274*8-bits.length));while(bits.length%8)bits+='0';
 const data=[];for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8),2));let pad=true;while(data.length<274){data.push(pad?0xec:0x11);pad=!pad}
 const exp=new Array(512),log=new Array(256);let z=1;for(let i=0;i<255;i++){exp[i]=z;log[z]=i;z<<=1;if(z&256)z^=0x11d}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;
 let gen=[1];for(let i=0;i<18;i++){const next=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=mul(gen[j],exp[i])}gen=next}
 const ecc=block=>{const r=Array(18).fill(0);for(const value of block){const f=value^r.shift();r.push(0);for(let j=0;j<18;j++)r[j]^=mul(gen[j+1],f)}return r};
 const blocks=[],sizes=[68,68,69,69];let pos=0;for(const size of sizes){const block=data.slice(pos,pos+size);pos+=size;blocks.push({data:block,ecc:ecc(block)})}
 const stream=[];for(let i=0;i<69;i++)for(const b of blocks)if(i<b.data.length)stream.push(b.data[i]);for(let i=0;i<18;i++)for(const b of blocks)stream.push(b.ecc[i]);
 const dataBits=stream.map(x=>x.toString(2).padStart(8,'0')).join('');let p=0,up=true;
 for(let x=n-1;x>0;x-=2){if(x===6)x--;for(let q=0;q<n;q++){const y=up?n-1-q:q;for(let dx=0;dx<2;dx++){const xx=x-dx;if(grid[y][xx]===null){let bit=p<dataBits.length&&dataBits[p++]==='1';if((xx+y)%2===0)bit=!bit;set(xx,y,bit)}}}up=!up}
 let format=(1<<3);let rem=format;for(let i=0;i<10;i++)rem=(rem<<1)^(((rem>>>9)&1)?0x537:0);format=((format<<10)|rem)^0x5412;
 for(let i=0;i<15;i++){const bit=((format>>>i)&1)===1;if(i<6)set(i,8,bit);else if(i<8)set(i+1,8,bit);else set(n-15+i,8,bit);if(i<8)set(8,n-i-1,bit);else if(i<9)set(8,15-i,bit);else set(8,14-i,bit)}
 el.innerHTML=grid.flat().map(v=>'<i class="'+(v?'b':'')+'"></i>').join('');
}
const copy=async(v,ok)=>{try{await navigator.clipboard.writeText(v);msg(ok)}catch{msg('Copy did not work here. Select the text and copy it instead.',true)}};
function bind(){const on=(id,fn)=>{const e=document.querySelector('#'+id);if(e)e.onclick=fn};
on('signIn',async()=>{try{const r=await api('/api/signin',{csrf,email:document.querySelector('#email').value,password:document.querySelector('#password').value});csrf=r.csrf;simulationLog(r,'IDENTITY DELIVERY');current='identity';render()}catch(e){msg(e.message,true)}});
on('verifyIdentity',async()=>{try{await api('/api/identity/verify',{csrf,code:document.querySelector('#identityCode').value});const r=await api('/api/provision',{csrf});secret=r.secret;uri=r.uri;simulationLog(r,'AUTHENTICATOR PROVISIONING');current='setup';render()}catch(e){msg(e.message,true)}});
on('resendIdentity',async()=>{try{const r=await api('/api/identity/resend',{csrf});simulationLog(r,'IDENTITY DELIVERY');msg('A new code was sent. Use the new code.')}catch(e){msg(e.message,true)}});
on('copySecret',()=>copy(secret,'Setup secret copied. Paste it into your authenticator app.'));on('copyUri',()=>copy(uri,'Setup link copied.'));on('toggleSecret',()=>{showSecret=!showSecret;render()});
on('addedApp',async()=>{try{const r=await api('/api/provision/manual',{csrf,secret:document.querySelector('#manualSecret').value});simulationLog(r,'AUTHENTICATOR READY');current='otp';render()}catch(e){msg(e.message,true)}});
on('newSetup',async()=>{try{const r=await api('/api/provision',{csrf});secret=r.secret;uri=r.uri;simulationLog(r,'AUTHENTICATOR PROVISIONING');render();msg('A new setup secret is ready. Add this one instead.')}catch(e){msg(e.message,true)}});
on('verifyOtp',async()=>{try{const r=await api('/api/otp/verify',{csrf,code:document.querySelector('#otpCode').value});codes=r.recoveryCodes;simulationLog(r,'RECOVERY CODES');current='backup';render()}catch(e){msg(e.message,true)}});
on('backSetup',()=>{current='setup';render()});on('copyCodes',()=>copy(codes.join('\\n'),'Backup codes copied. Store them in a safe place.'));on('toggleCodes',()=>{showCodes=!showCodes;render()});
on('confirmBackup',async()=>{try{await api('/api/recovery/confirm',{csrf,code:document.querySelector('#confirmRecovery').value});codes=[];testValues={};current='done';render()}catch(e){msg(e.message,true)}});
on('logout',async()=>{try{await api('/api/logout',{csrf});csrf='';secret='';uri='';codes=[];testValues={};say('[SESSION] Signed out.');current='signin';render()}catch(e){msg(e.message,true)}});
}
(async()=>{try{const r=await api('/api/csrf',null,'GET');csrf=r.csrf;render()}catch{app.textContent='Secure setup is unavailable. Please refresh the page.'}})();
})();</script></body></html>`;

async function api(request: Request, path: string): Promise<Response> {
  if (!safeOrigin(request)) return fail("This request is not allowed.", 403, request);

  if (request.method === "OPTIONS") {
    const result = headers(request.headers.get("origin"));
    result.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    result.set("Access-Control-Allow-Headers", "Content-Type");
    return new Response(null, { status: 204, headers: result });
  }

  if (path === "/api/csrf" && request.method === "GET") {
    let session = getSession(request);
    if (!session) session = makeSession();
    return respond({ ok: true, csrf: session.csrf, testMode: TEST_ONLY }, 200, request, { "Set-Cookie": sessionCookie(session) });
  }

  if (request.method !== "POST") return fail("That page is not available.", 404, request);
  const body = await input(request);
  if (!body) return fail("Please check the information and try again.", 400, request);

  if (path === "/api/signin") {
    const old = getSession(request);
    if (!old || !csrf(old, body)) return fail("Please refresh the page and try signing in again.", 403, request);

    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const rateId = await loginKey(email || "invalid");
    const limit = loginLimits.get(rateId);
    const now = Date.now();

    if (limit && limit.lockedUntil > now) {
      return fail("Sign-in is temporarily unavailable. Please wait a few minutes, then try again.", 429, request);
    }

    /*
     Requirement 5: all malformed, unknown, and known-account submissions
     perform the same fixed-length credential digest comparison before failure.
    */
    const submittedCredential = await hash(`${email}\u0000${password}`);
    const accountCredential = await hash(`${DEMO_ACCOUNT.email}\u0000${DEMO_ACCOUNT.password}`);
    const comparedCredentials = constantEqual(submittedCredential, accountCredential);
    const validInput = /^[^\s@]+@[^\s@]+\.[^\s@]{2,100}$/.test(email) && password.length > 0 && password.length <= 200;
    const valid = validInput && comparedCredentials;

    if (!valid) {
      const updated: LoginLimit = limit && limit.lockedUntil <= now
        ? { attempts: limit.attempts + 1, lockedUntil: 0 }
        : { attempts: 1, lockedUntil: 0 };
      if (updated.attempts >= MAX) updated.lockedUntil = now + LOCK;
      loginLimits.set(rateId, updated);
      return fail(updated.lockedUntil > now
        ? "Sign-in is temporarily unavailable. Please wait a few minutes, then try again."
        : "Check your email and password, then try again.",
      updated.lockedUntil > now ? 429 : 401, request);
    }

    loginLimits.delete(rateId);
    sessions.delete(old.id);
    const session = makeSession(DEMO_ACCOUNT.id, DEMO_ACCOUNT.email);
    const deliveryCode = await newIdentityCode(session);
    console.log("[MFA] Authentication session created.");
    return respond({ ok: true, csrf: session.csrf, ...testPayload({ identityCode: deliveryCode }) }, 200, request, {
      "Set-Cookie": sessionCookie(session)
    });
  }

  /* Requirement 1: server-side owner authorization on every MFA endpoint. */
  const session = getSession(request);
  if (!session?.account || session.account !== DEMO_ACCOUNT.id || session.email !== DEMO_ACCOUNT.email) {
    return fail("Your secure session has ended. Please sign in again.", 401, request);
  }
  if (!csrf(session, body)) return fail("Please refresh the page before trying again.", 403, request);

  if (path === "/api/identity/resend") {
    const now = Date.now();
    if (!session.identity) return fail("Please sign in again before requesting a code.", 403, request);
    if (session.identity.used) return fail("Your identity has already been checked.", 400, request);
    if (session.identity.lockedUntil > now) return fail(retryMessage(session.identity.lockedUntil), 429, request);
    if (!session.identityResendWindow || now - session.identityResendWindow >= RESEND_WINDOW) {
      session.identityResendWindow = now;
      session.identityResends = 0;
    }
    session.identityResends = (session.identityResends || 0) + 1;
    if (session.identityResends > MAX_RESENDS) return fail("Too many new codes were requested. Please wait a few minutes, then try again.", 429, request);
    const deliveryCode = await newIdentityCode(session);
    return respond({ ok: true, ...testPayload({ identityCode: deliveryCode }) }, 200, request);
  }

  if (path === "/api/identity/verify") {
    const code = typeof body.code === "string" ? body.code.trim() : "";
    if (!/^\d{6}$/.test(code)) return fail("Enter the 6-digit code, for example 123456.", 400, request);
    if (!session.identity) return fail("Please request a new identity code.", 400, request);
    const result = await consumeOne(session.identity, code);
    if (result === "locked") return fail(retryMessage(session.identity.lockedUntil), 429, request);
    if (result !== "ok") return fail("That code is not right or has been used. Check it, or request a new code.", 400, request);
    return respond({ ok: true, testMode: TEST_ONLY }, 200, request);
  }

  if (path === "/api/provision") {
    if (!session.identity?.used) return fail("Check your identity code before setting up an authenticator.", 403, request);
    if (session.otpVerified) return fail("Your authenticator has already been checked.", 400, request);
    if ((session.otpLockedUntil || 0) > Date.now()) return fail(retryMessage(session.otpLockedUntil!), 429, request);
    const count = session.provisionCount || 0;
    const secret = TEST_ONLY ? TEST_SECRETS[count % TEST_SECRETS.length] : secureText(B32, 20);
    session.provisionCount = count + 1;
    session.secret = await encrypt(secret);
    session.provisioned = false;
    session.usedTotpSteps = new Set();
    session.recovery = undefined;
    const uri = provisioningUri(session.email, secret);
    return respond({ ok: true, secret, uri, ...testPayload({ provisioningSecret: secret, provisioningUri: uri, authenticatorOtp: "654321" }) }, 200, request);
  }

  if (path === "/api/provision/manual") {
    if (!session.identity?.used) return fail("Check your identity code before setting up an authenticator.", 403, request);
    if (session.otpVerified) return fail("Your authenticator has already been checked.", 400, request);
    if ((session.otpLockedUntil || 0) > Date.now()) return fail(retryMessage(session.otpLockedUntil!), 429, request);
    const supplied = typeof body.secret === "string" ? body.secret.trim().toUpperCase().replaceAll(" ", "") : "";
    if (!/^[A-Z2-7]{16,64}$/.test(supplied) || !session.secret) {
      return fail("Paste the full setup secret, then try again.", 400, request);
    }
    if (!constantEqual(supplied, await decrypt(session.secret))) {
      return fail("That setup secret does not match this session. Get a new setup code and try again.", 400, request);
    }
    session.provisioned = true;
    return respond({ ok: true, ...testPayload({ authenticatorOtp: "654321" }) }, 200, request);
  }

  if (path === "/api/otp/verify") {
    const now = Date.now();
    const code = typeof body.code === "string" ? body.code.trim() : "";
    if (session.otpVerified) return fail("Your authenticator has already been checked. Your backup codes are already active.", 400, request);
    if ((session.otpLockedUntil || 0) > now) return fail(retryMessage(session.otpLockedUntil!), 429, request);
    if (!/^\d{6}$/.test(code)) return fail("Enter the 6-digit authenticator code, for example 123456.", 400, request);
    if (!session.provisioned || !session.secret) return fail("Set up your authenticator before checking its code.", 403, request);

    let used: number | undefined;
    if (TEST_ONLY) {
      if (constantEqual(code, "654321")) used = -1;
    } else {
      const secret = await decrypt(session.secret);
      const currentStep = Math.floor(now / 30000);
      for (const candidate of [currentStep - 1, currentStep, currentStep + 1]) {
        if (!(session.usedTotpSteps || new Set()).has(candidate) && constantEqual(code, await totp(secret, candidate))) {
          used = candidate;
          break;
        }
      }
    }
    if (used === undefined) {
      session.otpAttempts = (session.otpAttempts || 0) + 1;
      if (session.otpAttempts >= MAX) {
        session.otpLockedUntil = now + LOCK;
        return fail(retryMessage(session.otpLockedUntil), 429, request);
      }
      return fail(`That authenticator code is not right, is too old, or has already been used. Check the code and try again. You have ${MAX - session.otpAttempts} tries before a short wait.`, 400, request);
    }

    (session.usedTotpSteps ||= new Set()).add(used);
    session.otpAttempts = 0;
    session.otpVerified = true;
    const recoveryCodes = makeRecoveryCodes();
    session.recovery = { hashes: await Promise.all(recoveryCodes.map(protectRecoveryCode)) };
    session.recoveryAttempts = 0;
    return respond({ ok: true, recoveryCodes, ...testPayload({ recoveryCodes }) }, 200, request);
  }

  if (path === "/api/recovery/confirm" || path === "/api/recovery/use") {
    const now = Date.now();
    const code = typeof body.code === "string" ? body.code.trim().toUpperCase() : "";
    if ((session.recoveryLockedUntil || 0) > now) return fail(retryMessage(session.recoveryLockedUntil!), 429, request);
    if (!/^[A-Z2-7]{5}-[A-Z2-7]{5}$/.test(code) || !session.otpVerified || !session.recovery) {
      return fail("Paste one saved backup code in the format ABCDE-23456.", 400, request);
    }

    /* Calculate every PBKDF comparison before selecting a result. */
    const matches = await Promise.all(session.recovery.hashes.map(record => recoveryMatches(record, code)));
    const matchIndex = matches.findIndex(Boolean);
    if (matchIndex < 0) {
      session.recoveryAttempts = (session.recoveryAttempts || 0) + 1;
      if (session.recoveryAttempts >= MAX) {
        session.recoveryLockedUntil = now + LOCK;
        return fail(retryMessage(session.recoveryLockedUntil), 429, request);
      }
      return fail("That backup code was not found. Paste one of the codes you saved.", 400, request);
    }

    session.recoveryAttempts = 0;
    if (path === "/api/recovery/confirm") {
      return respond({ ok: true, message: "Your saved code was checked. It was not used up.", testMode: TEST_ONLY }, 200, request);
    }

    /*
     Requirement 5: synchronous splice after all awaited comparison work is
     atomic in this single-threaded in-memory store. A later request cannot
     find this hash, so a recovery code is strictly single-use.
    */
    session.recovery.hashes.splice(matchIndex, 1);
    console.log("[MFA] A recovery code was accepted and consumed.");
    return respond({ ok: true, message: "Your backup code was accepted and is now used.", remaining: session.recovery.hashes.length, testMode: TEST_ONLY }, 200, request);
  }

  if (path === "/api/logout") {
    sessions.delete(session.id);
    return respond({ ok: true, testMode: TEST_ONLY }, 200, request, {
      "Set-Cookie": `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
    });
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
      if (url.protocol !== "https:") {
        return new Response(null, { status: 301, headers: { Location: `https://${url.host}${url.pathname}` } });
      }
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = token(18);
        const result = headers(request.headers.get("origin"), nonce);
        result.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers: result });
      }
      return new Response("Page not found.", { status: 404, headers: headers(request.headers.get("origin")) });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: headers() });
    }
  }
});

console.log(`MFA enrolment server ready at https://localhost:${PORT}`);
