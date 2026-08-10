
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — single Bun HTTPS server and vanilla HTML application.
 Security requirements: TLS, secure headers/cookies, CSRF, session ownership,
 encrypted OTP seed, salted slow-KDF recovery codes, validation, and rate limiting.
*/

const PORT = Number(Bun.env.PORT || 3000);
const COOKIE = "__Host_mfa_session";
const IDLE = 30 * 60 * 1000;
const ABSOLUTE = 8 * 60 * 60 * 1000;
const CODE_LIFE = 15 * 60 * 1000;
const LOCK = 10 * 60 * 1000;
const MAX = 5;
const ISSUER = "Harbor Bank";
const DEMO_IDENTITY_CODE = "123456";
const RECOVERY_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const origins = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

type Protected = { cipher: string; iv: string };
type OneCode = { hash: string; expires: number; used: boolean; attempts: number; lockedUntil: number };
type RecoveryHash = { salt: string; hash: string };
type Session = {
  id: string;
  csrf: string;
  created: number;
  seen: number;
  account?: string;
  email?: string;
  identity?: OneCode;
  secret?: Protected;
  provisioned?: boolean;
  otpVerified?: boolean;
  usedTotpSteps?: Set<number>;
  otpAttempts?: number;
  otpLockedUntil?: number;
  recovery?: { hashes: RecoveryHash[] };
  recoveryAttempts?: number;
  recoveryLockedUntil?: number;
};

const sessions = new Map<string, Session>();
const keyBytes = crypto.getRandomValues(new Uint8Array(32));
const te = new TextEncoder();

function b64(bytes: Uint8Array) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}
function unb64(text: string) {
  return Uint8Array.from(atob(text), c => c.charCodeAt(0));
}
function token(size = 32) {
  return b64(crypto.getRandomValues(new Uint8Array(size))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function secureText(alphabet: string, length: number) {
  const values = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(values, value => alphabet[value % alphabet.length]).join("");
}
function makeTotpSecret() {
  return secureText("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 20);
}
function makeRecoveryCode() {
  return `${secureText(RECOVERY_ALPHABET, 5)}-${secureText(RECOVERY_ALPHABET, 5)}`;
}
function makeRecoveryCodes() {
  const values = new Set<string>();
  while (values.size < 8) values.add(makeRecoveryCode());
  return [...values];
}
async function hash(value: string) {
  return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", te.encode(value))));
}
/* Requirement: recovery codes use an independent random salt and slow PBKDF2 at rest. */
async function recoveryKdf(code: string, salt: string) {
  const material = await crypto.subtle.importKey("raw", te.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: unb64(salt), iterations: 210000 },
    material,
    256,
  );
  return b64(new Uint8Array(bits));
}
async function protectRecoveryCode(code: string): Promise<RecoveryHash> {
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  return { salt, hash: await recoveryKdf(code, salt) };
}
function constantEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let different = 0;
  for (let i = 0; i < a.length; i++) different |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return different === 0;
}
async function recoveryMatches(record: RecoveryHash, code: string) {
  return constantEqual(record.hash, await recoveryKdf(code, record.salt));
}
async function encrypt(value: string): Promise<Protected> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, te.encode(value));
  return { cipher: b64(new Uint8Array(cipher)), iv: b64(iv) };
}
async function decrypt(value: Protected) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(value.iv) }, key, unb64(value.cipher));
  return new TextDecoder().decode(plain);
}
function base32Bytes(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of value.replaceAll("=", "").toUpperCase()) {
    const n = alphabet.indexOf(c);
    if (n < 0) throw new Error("bad base32");
    bits += n.toString(2).padStart(5, "0");
  }
  const out: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(out);
}
/* Requirement: RFC 6238 TOTP, SHA-1, 6 digits, 30 second period. */
async function totp(secret: string, step: number) {
  const counter = new Uint8Array(8);
  let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(n & 255n); n >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = mac[mac.length - 1] & 15;
  const number = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}
function makeSession(account?: string, email?: string): Session {
  const now = Date.now();
  const s: Session = { id: token(), csrf: token(), created: now, seen: now, account, email };
  sessions.set(s.id, s);
  return s;
}
function cookies(r: Request) {
  const result: Record<string, string> = {};
  for (const part of (r.headers.get("cookie") || "").split(";")) {
    const at = part.indexOf("=");
    if (at > 0) result[part.slice(0, at).trim()] = decodeURIComponent(part.slice(at + 1).trim());
  }
  return result;
}
function isExpired(s: Session) {
  return Date.now() - s.seen > IDLE || Date.now() - s.created > ABSOLUTE;
}
function getSession(r: Request) {
  const s = sessions.get(cookies(r)[COOKIE]);
  if (!s || isExpired(s)) {
    if (s) sessions.delete(s.id);
    return undefined;
  }
  s.seen = Date.now();
  return s;
}
function sessionCookie(s: Session) {
  return `${COOKIE}=${encodeURIComponent(s.id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE / 1000}`;
}
/* Requirement: each response receives a fresh CSP nonce. */
function headers(origin?: string | null, nonce = token(18)) {
  const h = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  if (origin && origins.has(origin)) {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Vary", "Origin");
  }
  return h;
}
function respond(body: unknown, status = 200, request?: Request, extra?: Record<string, string>) {
  const h = headers(request?.headers.get("origin"));
  h.set("Content-Type", "application/json; charset=utf-8");
  for (const [key, value] of Object.entries(extra || {})) h.set(key, value);
  return new Response(JSON.stringify(body), { status, headers: h });
}
function fail(message: string, status = 400, r?: Request) {
  return respond({ ok: false, message }, status, r);
}
function safeOrigin(r: Request) {
  const origin = r.headers.get("origin");
  return !origin || origins.has(origin);
}
async function input(r: Request): Promise<Record<string, unknown> | null> {
  if (Number(r.headers.get("content-length") || "0") > 10000) return null;
  try {
    const value = await r.json();
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    if ("userId" in value || "accountId" in value || "redirect" in value) return null;
    return value as Record<string, unknown>;
  } catch { return null; }
}
function csrf(s: Session, body: Record<string, unknown>) {
  return typeof body.csrf === "string" && body.csrf.length >= 30 && body.csrf === s.csrf;
}
function owner(r: Request): Session | Response {
  const s = getSession(r);
  return s?.account ? s : fail("Your secure session has ended. Please sign in again.", 401, r);
}
function responseValue(x: Session | Response): x is Response { return x instanceof Response; }
function retryMessage(until: number) {
  return `Too many tries were made. Please wait until ${new Date(until).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}, then try again.`;
}
async function consumeOne(record: OneCode, code: string) {
  if (record.lockedUntil > Date.now()) return "locked";
  if (record.used || record.expires < Date.now() || await hash(code) !== record.hash) {
    record.attempts++;
    if (record.attempts >= MAX) record.lockedUntil = Date.now() + LOCK;
    return record.lockedUntil > Date.now() ? "locked" : "bad";
  }
  record.used = true;
  return "ok";
}
function provisioningUri(email: string, secret: string) {
  const label = `${encodeURIComponent(ISSUER)}:${encodeURIComponent(email)}`;
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(ISSUER)}&algorithm=SHA1&digits=6&period=30`;
}

const page = (nonce: string) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbor Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#182630;--muted:#52636d;--blue:#075d9f;--blue2:#034a80;--pale:#eef7fc;--line:#bed0db;--good:#147344}
*{box-sizing:border-box}body{margin:0;background:#eef3f5;color:var(--ink);font-family:Arial,Verdana,Tahoma,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.035em;word-spacing:.08em}button,input{font:inherit;letter-spacing:inherit}button{cursor:pointer}.shell{width:min(100%,560px);min-height:100vh;margin:auto;background:#fff;padding:20px 18px 38px}header{border-bottom:2px solid var(--line);padding-bottom:14px;margin-bottom:20px}.brand{font-weight:700;color:#034a80;font-size:1.08rem}.step{margin:9px 0 0;color:var(--muted);font-size:.93rem}main{min-height:440px}h1{font-size:1.55rem;line-height:1.3;letter-spacing:.02em;margin:0 0 13px}h2{font-size:1.18rem;line-height:1.35}p{margin:0 0 17px}.icon{font-size:2rem;display:block;margin-bottom:8px}.card{background:var(--pale);border:1px solid var(--line);border-radius:12px;padding:17px;margin:18px 0}label{display:block;font-weight:700;margin:18px 0 6px}.hint{color:var(--muted);display:block;font-size:.9rem;margin-bottom:7px}input{width:100%;min-height:52px;border:2px solid #8297a4;border-radius:9px;padding:10px 12px;color:var(--ink);background:#fff}input:focus{outline:3px solid #75b8e7;outline-offset:2px;border-color:var(--blue)}.primary{width:100%;min-height:55px;margin:22px 0 12px;border:0;border-radius:9px;background:var(--blue);color:#fff;font-weight:700}.primary:hover,.primary:focus{background:var(--blue2)}.secondary{min-height:44px;color:var(--blue2);background:#fff;border:2px solid var(--blue);border-radius:8px;padding:7px 12px;margin:4px 5px 4px 0;font-weight:700}.text-btn{color:var(--blue2);background:none;border:0;padding:8px 0;text-decoration:underline;font-weight:700}.notice{border-left:5px solid var(--good);background:#edf9f1;padding:12px 14px;margin:15px 0}.error{border-left:5px solid #b42c24;background:#fff0ef;padding:12px 14px;margin:15px 0}.status{min-height:1.8em}.code{font-family:monospace;letter-spacing:.12em;word-break:break-all;background:#fff;padding:12px;border:1px dashed #728b99;border-radius:8px}.qr-wrap{width:230px;min-height:230px;background:#fff;padding:10px;border:1px solid var(--line);margin:14px auto}.qr-wrap canvas{display:block;width:208px;height:208px;image-rendering:pixelated}.codes{display:grid;grid-template-columns:1fr 1fr;gap:9px}.recovery{font-family:monospace;letter-spacing:.07em;padding:10px 6px;text-align:center;border:1px solid var(--line);border-radius:7px;background:#fff}details{border-top:1px solid var(--line);padding-top:12px;margin-top:22px}summary{color:var(--blue2);font-weight:700;cursor:pointer}.logs{margin-top:25px;border-top:2px solid var(--line);padding-top:16px}#logBox{background:#10232d;color:#e9f7ff;font:13px/1.55 monospace;letter-spacing:0;padding:12px;min-height:78px;max-height:190px;overflow:auto;white-space:pre-wrap;border-radius:8px}.small{font-size:.88rem;color:var(--muted)}
</style>
</head>
<body><div class="shell">
<header><div class="brand">◈ Harbor Bank</div><div id="step" class="step">Security setup</div></header>
<main id="app" aria-live="polite"></main>
<section class="logs" aria-label="Testing delivery logs"><h2>Logs</h2><p class="small">Test delivery details appear here and in the browser console.</p><div id="logBox">Ready. Nothing has been stored in this browser.</div></section>
</div>
<script nonce="${nonce}">
(()=>{const app=document.querySelector('#app'),step=document.querySelector('#step'),box=document.querySelector('#logBox');let csrf='',current='signin',secret='',uri='',codes=[],showSecret=true,showCodes=true;const logs=[];const say=x=>{logs.push(x);console.log(x);box.textContent=logs.join('\\n');box.scrollTop=box.scrollHeight};const esc=x=>String(x).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const api=async(path,data,method='POST')=>{let r=await fetch(path,{method,credentials:'same-origin',headers:{'Content-Type':'application/json'},body:method==='GET'?undefined:JSON.stringify(data||{})}),o=await r.json().catch(()=>({message:'We could not complete that step. Please try again.'}));if(!r.ok)throw Error(o.message);return o};const help=()=>'<details><summary>Need help?</summary><p>Take your time. Nothing on this page disappears while you read it. You can retry safely.</p></details>';const msg=(x,b=false)=>{let e=document.querySelector('#status');if(e){e.textContent=x;e.className=(b?'error':'notice')+' status'}};
/* Standards-compliant QR version 8-L: byte mode, RS ECC, format and version metadata. */
function drawQR(text){const N=49,gf=new Uint8Array(512),lg=new Uint8Array(256);let x=1;for(let i=0;i<255;i++){gf[i]=x;lg[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)gf[i]=gf[i-255];const mul=(a,b)=>!a||!b?0:gf[lg[a]+lg[b]];const a=new TextEncoder().encode(text),bits=[];const put=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push(v>>i&1)};if(a.length>194)throw Error('Setup QR is too large.');put(4,4);put(a.length,8);a.forEach(v=>put(v,8));put(0,Math.min(4,1552-bits.length));while(bits.length%8)bits.push(0);let data=[];for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8).join(''),2));for(let q=0;data.length<194;q++)data.push(q%2?17:236);const rs=d=>{let gen=[1];for(let i=0;i<24;i++){let z=new Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){z[j]^=gen[j];z[j+1]^=mul(gen[j],gf[i])}gen=z}let rem=new Array(24).fill(0);for(const v of d){let f=v^rem.shift();rem.push(0);for(let j=0;j<24;j++)rem[j]^=mul(gen[j+1],f)}return rem};let blocks=[data.slice(0,97),data.slice(97)],ecc=blocks.map(rs),stream=[];for(let i=0;i<97;i++)for(let b=0;b<2;b++)stream.push(blocks[b][i]);for(let i=0;i<24;i++)for(let b=0;b<2;b++)stream.push(ecc[b][i]);const m=Array.from({length:N},()=>Array(N).fill(null)),set=(r,c,v)=>{if(r>=0&&c>=0&&r<N&&c<N)m[r][c]=v};const finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)set(r+y,c+z,y>=0&&y<=6&&z>=0&&z<=6&&(y==0||y==6||z==0||z==6||(y>=2&&y<=4&&z>=2&&z<=4)))};finder(0,0);finder(0,N-7);finder(N-7,0);for(let i=8;i<N-8;i++){set(6,i,i%2==0);set(i,6,i%2==0)};for(const r of [6,24,42])for(const c of [6,24,42])if(m[r][c]===null)for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)set(r+y,c+z,Math.max(Math.abs(y),Math.abs(z))!=1);set(N-8,8,true);for(let i=0;i<9;i++){if(m[i][8]===null)set(i,8,false);if(m[8][i]===null)set(8,i,false);if(m[N-1-i][8]===null)set(N-1-i,8,false);if(m[8][N-1-i]===null)set(8,N-1-i,false)}for(let i=0;i<6;i++)for(let j=0;j<3;j++){set(i,N-11+j,false);set(N-11+j,i,false)}let k=0,up=true;for(let c=N-1;c>0;c-=2){if(c==6)c--;for(let t=0;t<N;t++){let r=up?N-1-t:t;for(const q of [c,c-1])if(m[r][q]===null){let v=k<stream.length*8?stream[k>>3]>>(7-(k&7))&1:0;k++;m[r][q]=!!(v^((r+q)%2==0))}}up=!up}let f=(1<<3)|0;for(let i=0;i<10;i++)f=(f<<1)^(((f>>9)&1)?0x537:0);f=((1<<3)|0)<<10|f;f^=0x5412;for(let i=0;i<15;i++){let v=!!(f>>i&1);if(i<6)set(i,8,v);else if(i<8)set(i+1,8,v);else set(N-15+i,8,v);if(i<8)set(8,N-i-1,v);else if(i<9)set(8,15-i,v);else set(8,15-i-1,v)}let version=8,rem=version;for(let i=0;i<12;i++)rem=(rem<<1)^(((rem>>11)&1)?0x1f25:0);let vb=(version<<12)|rem;for(let i=0;i<18;i++){let v=!!(vb>>i&1);set(Math.floor(i/3),N-11+i%3,v);set(N-11+i%3,Math.floor(i/3),v)}const c=document.querySelector('#qr'),ctx=c.getContext('2d');c.width=c.height=N;for(let r=0;r<N;r++)for(let q=0;q<N;q++){ctx.fillStyle=m[r][q]?'#000':'#fff';ctx.fillRect(q,r,1,1)}} 
function render(){const v={signin:()=>{step.textContent='Step 1 of 5 · Sign in';return '<span class="icon">🔐</span><h1>Sign in to start security setup</h1><p>Use your bank email and password. We will send one short identity code.</p><label for="email">Email address</label><span class="hint">Example: marcus@example.com</span><input id="email" type="email" autocomplete="email" placeholder="name@example.com"><label for="password">Password</label><span class="hint">Your password manager can fill this.</span><input id="password" type="password" autocomplete="current-password"><div id="status" class="status"></div><button class="primary" id="signIn">Sign in</button>'+help()},identity:()=>{step.textContent='Step 2 of 5 · Check it is you';return '<span class="icon">✉️</span><h1>Enter your identity code</h1><p>We sent a 6-digit code to your email. In this demo, check the delivery log.</p><label for="identityCode">6-digit code</label><span class="hint">Example: 123456</span><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><div id="status" class="status"></div><button class="primary" id="verifyIdentity">Check code</button><button class="text-btn" id="resendIdentity">Send a new code</button>'+help()},setup:()=>{step.textContent='Step 3 of 5 · Add your authenticator';return '<span class="icon">📱</span><h1>Add Harbor Bank to your authenticator app</h1><p>Scan this QR code. Or copy the setup secret instead.</p><div class="qr-wrap"><canvas id="qr" width="49" height="49" role="img" aria-label="QR code for Harbor Bank authenticator setup"></canvas></div><button class="secondary" id="copySecret">Copy setup secret</button><button class="secondary" id="toggleSecret">'+(showSecret?'Hide secret':'Show secret')+'</button><label for="manualSecret">Manual setup secret</label><span class="hint">Copy and paste this if scanning is difficult.</span><input id="manualSecret" type="'+(showSecret?'text':'password')+'" autocomplete="off" spellcheck="false" value="'+esc(secret)+'"><div id="status" class="status"></div><button class="primary" id="addedApp">I added it to my app</button><button class="text-btn" id="newSetup">Get a new setup code</button>'+help()},otp:()=>{step.textContent='Step 4 of 5 · Check your authenticator';return '<span class="icon">🔢</span><h1>Enter the code from your authenticator app</h1><p>Use the current 6-digit code. For this test, it is in the delivery log. Take your time.</p><label for="otpCode">Authenticator code</label><span class="hint">Example: 123456</span><input id="otpCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><div id="status" class="status"></div><button class="primary" id="verifyOtp">Check authenticator</button><button class="text-btn" id="backSetup">Go back to setup</button>'+help()},backup:()=>{step.textContent='Step 5 of 5 · Save backup codes';let list=showCodes?codes.map(c=>'<div class="recovery">'+esc(c)+'</div>').join(''):'<div class="recovery">•••••-•••••</div>'.repeat(8);return '<span class="icon">🧾</span><h1>Save your backup codes</h1><p>Keep these somewhere safe. Each code works once if you cannot use your authenticator.</p><div class="card"><div class="codes">'+list+'</div></div><button class="secondary" id="copyCodes">Copy all codes</button><button class="secondary" id="toggleCodes">'+(showCodes?'Hide codes':'Show codes')+'</button><label for="confirmRecovery">Paste one saved code</label><span class="hint">Example: ABCDE-23456. This check does not use up your code.</span><input id="confirmRecovery" autocomplete="one-time-code" placeholder="ABCDE-23456"><div id="status" class="status"></div><button class="primary" id="confirmBackup">Check saved code</button>'+help()},done:()=>{step.textContent='Complete · MFA is ready';return '<span class="icon">✓</span><h1>Your security setup is complete</h1><div class="notice">Your saved code was checked and was not used up. Your authenticator and backup codes are ready.</div><button class="primary" id="logout">Sign out</button>'+help()}};app.innerHTML=v[current]();if(current==='setup')drawQR(uri);bind()}
const copy=async(v,s)=>{try{await navigator.clipboard.writeText(v);msg(s)}catch{msg('Copy did not work here. Select the text and copy it instead.',true)}};function bind(){const on=(id,f)=>{let e=document.querySelector('#'+id);if(e)e.onclick=f};on('signIn',async()=>{try{let r=await api('/api/signin',{csrf,email:document.querySelector('#email').value,password:document.querySelector('#password').value});csrf=r.csrf;say('[Identity delivery] Email code: '+r.deliveryCode);current='identity';render()}catch(e){msg(e.message,true)}});on('verifyIdentity',async()=>{try{await api('/api/identity/verify',{csrf,code:document.querySelector('#identityCode').value});let r=await api('/api/provision',{csrf});secret=r.secret;uri=r.uri;say('[Authenticator provisioning] Secret: '+r.secret);say('[Authenticator verification test code] OTP: '+r.demoOtp);current='setup';render()}catch(e){msg(e.message,true)}});on('resendIdentity',async()=>{try{let r=await api('/api/identity/resend',{csrf});say('[Identity delivery, re-requested] Email code: '+r.deliveryCode);msg('A new code was sent. Use the new code.')}catch(e){msg(e.message,true)}});on('copySecret',()=>copy(secret,'Setup secret copied. Paste it into your authenticator app.'));on('toggleSecret',()=>{showSecret=!showSecret;render()});on('addedApp',async()=>{try{let r=await api('/api/provision/manual',{csrf,secret:document.querySelector('#manualSecret').value});say('[Authenticator verification test code] OTP: '+r.demoOtp);current='otp';render()}catch(e){msg(e.message,true)}});on('newSetup',async()=>{try{let r=await api('/api/provision',{csrf});secret=r.secret;uri=r.uri;say('[New authenticator provisioning] Secret: '+r.secret);say('[Authenticator verification test code] OTP: '+r.demoOtp);msg('A new setup secret is ready. Add this one instead.')}catch(e){msg(e.message,true)}});on('verifyOtp',async()=>{try{let r=await api('/api/otp/verify',{csrf,code:document.querySelector('#otpCode').value});codes=r.recoveryCodes;say('[Recovery code delivery] Codes: '+codes.join(', '));current='backup';render()}catch(e){msg(e.message,true)}});on('backSetup',()=>{current='setup';render()});on('copyCodes',()=>copy(codes.join('\\n'),'Backup codes copied. Store them in a safe place.'));on('toggleCodes',()=>{showCodes=!showCodes;render()});on('confirmBackup',async()=>{try{await api('/api/recovery/confirm',{csrf,code:document.querySelector('#confirmRecovery').value});codes=[];current='done';render()}catch(e){msg(e.message,true)}});on('logout',async()=>{try{await api('/api/logout',{csrf});csrf='';secret='';uri='';codes=[];say('[Session] Signed out.');current='signin';render()}catch(e){msg(e.message,true)}})}(async()=>{try{let r=await api('/api/csrf',null,'GET');csrf=r.csrf;render()}catch{app.textContent='Secure setup is unavailable. Please refresh the page.'}})()})();
</script></body></html>`;

async function api(request: Request, path: string): Promise<Response> {
  if (!safeOrigin(request)) return fail("This request is not allowed.", 403, request);
  if (request.method === "OPTIONS") {
    const h = headers(request.headers.get("origin"));
    h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    h.set("Access-Control-Allow-Headers", "Content-Type");
    return new Response(null, { status: 204, headers: h });
  }
  if (path === "/api/csrf" && request.method === "GET") {
    let s = getSession(request);
    if (!s) s = makeSession();
    return respond({ ok: true, csrf: s.csrf }, 200, request, { "Set-Cookie": sessionCookie(s) });
  }
  if (request.method !== "POST") return fail("That page is not available.", 404, request);
  const body = await input(request);
  if (!body) return fail("Please check the information and try again.", 400, request);

  if (path === "/api/signin") {
    const old = getSession(request);
    if (!old || !csrf(old, body)) return fail("Please refresh the page and try signing in again.", 403, request);
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,100}$/.test(email) || !password || password.length > 200) {
      return fail("Check your email and password, then try again.", 400, request);
    }
    sessions.delete(old.id);
    const s = makeSession("account-marcus-demo", email);
    s.identity = { hash: await hash(DEMO_IDENTITY_CODE), expires: Date.now() + CODE_LIFE, used: false, attempts: 0, lockedUntil: 0 };
    console.log("[MFA] Authentication session created.");
    return respond({ ok: true, csrf: s.csrf, deliveryCode: DEMO_IDENTITY_CODE }, 200, request, { "Set-Cookie": sessionCookie(s) });
  }

  const owned = owner(request);
  if (responseValue(owned)) return owned;
  const s = owned;
  if (!csrf(s, body)) return fail("Please refresh the page before trying again.", 403, request);

  if (path === "/api/identity/resend") {
    s.identity = { hash: await hash(DEMO_IDENTITY_CODE), expires: Date.now() + CODE_LIFE, used: false, attempts: 0, lockedUntil: 0 };
    return respond({ ok: true, deliveryCode: DEMO_IDENTITY_CODE }, 200, request);
  }
  if (path === "/api/identity/verify") {
    const code = typeof body.code === "string" ? body.code.trim() : "";
    if (!/^\d{6}$/.test(code)) return fail("Enter the 6-digit code, for example 123456.", 400, request);
    if (!s.identity) return fail("Please request a new identity code.", 400, request);
    const result = await consumeOne(s.identity, code);
    if (result === "locked") return fail(retryMessage(s.identity.lockedUntil), 429, request);
    if (result !== "ok") return fail("That code is not right or has been used. Check it, or request a new code.", 400, request);
    return respond({ ok: true }, 200, request);
  }
  if (path === "/api/provision") {
    if (!s.identity?.used) return fail("Check your identity code before setting up an authenticator.", 403, request);
    const secret = makeTotpSecret();
    s.secret = await encrypt(secret);
    s.provisioned = false;
    s.otpVerified = false;
    s.usedTotpSteps = new Set();
    s.otpAttempts = 0;
    s.otpLockedUntil = 0;
    s.recovery = undefined;
    const testCode = await totp(secret, Math.floor(Date.now() / 30000));
    return respond({ ok: true, secret, uri: provisioningUri(s.email || "marcus@example.com", secret), demoOtp: testCode }, 200, request);
  }
  if (path === "/api/provision/manual") {
    const supplied = typeof body.secret === "string" ? body.secret.trim().toUpperCase().replaceAll(" ", "") : "";
    if (!/^[A-Z2-7]{20}$/.test(supplied) || !s.secret) return fail("Paste the full setup secret, then try again.", 400, request);
    if (supplied !== await decrypt(s.secret)) return fail("That setup secret does not match this session. Get a new setup code and try again.", 400, request);
    s.provisioned = true;
    const testCode = await totp(supplied, Math.floor(Date.now() / 30000));
    return respond({ ok: true, demoOtp: testCode }, 200, request);
  }
  if (path === "/api/otp/verify") {
    const now = Date.now();
    if ((s.otpLockedUntil || 0) > now) return fail(retryMessage(s.otpLockedUntil!), 429, request);
    const code = typeof body.code === "string" ? body.code.trim() : "";
    if (!/^\d{6}$/.test(code)) return fail("Enter the 6-digit authenticator code, for example 123456.", 400, request);
    if (!s.provisioned || !s.secret) return fail("Set up your authenticator before checking its code.", 403, request);
    const secret = await decrypt(s.secret);
    const nowStep = Math.floor(now / 30000);
    let verifiedStep: number | undefined;
    for (const candidate of [nowStep - 1, nowStep, nowStep + 1]) {
      if (!(s.usedTotpSteps || new Set()).has(candidate) && code === await totp(secret, candidate)) { verifiedStep = candidate; break; }
    }
    if (verifiedStep === undefined) {
      s.otpAttempts = (s.otpAttempts || 0) + 1;
      if (s.otpAttempts >= MAX) {
        s.otpLockedUntil = now + LOCK;
        return fail(retryMessage(s.otpLockedUntil), 429, request);
      }
      return fail(`That authenticator code is not right, is too old, or has already been used. Check the code and try again. You have ${MAX - s.otpAttempts} tries before a short wait.`, 400, request);
    }
    (s.usedTotpSteps ||= new Set()).add(verifiedStep);
    s.otpAttempts = 0;
    s.otpLockedUntil = 0;
    s.otpVerified = true;
    const recoveryCodes = makeRecoveryCodes();
    s.recovery = { hashes: await Promise.all(recoveryCodes.map(protectRecoveryCode)) };
    s.recoveryAttempts = 0;
    s.recoveryLockedUntil = 0;
    return respond({ ok: true, recoveryCodes }, 200, request);
  }
  if (path === "/api/recovery/confirm") {
    const now = Date.now();
    if ((s.recoveryLockedUntil || 0) > now) return fail(retryMessage(s.recoveryLockedUntil!), 429, request);
    const code = typeof body.code === "string" ? body.code.trim().toUpperCase() : "";
    if (!/^[A-Z2-7]{5}-[A-Z2-7]{5}$/.test(code) || !s.otpVerified || !s.recovery) {
      return fail("Paste one saved backup code in the format ABCDE-23456.", 400, request);
    }
    let found = false;
    for (const record of s.recovery.hashes) {
      if (await recoveryMatches(record, code)) found = true;
    }
    if (!found) {
      s.recoveryAttempts = (s.recoveryAttempts || 0) + 1;
      if (s.recoveryAttempts >= MAX) {
        s.recoveryLockedUntil = now + LOCK;
        return fail(retryMessage(s.recoveryLockedUntil), 429, request);
      }
      return fail("That backup code was not found. Paste one of the codes you saved.", 400, request);
    }
    s.recoveryAttempts = 0;
    /* Confirmation deliberately validates only: this saved code remains available for recovery. */
    return respond({ ok: true, message: "Your saved code was checked. It was not used up." }, 200, request);
  }
  if (path === "/api/logout") {
    sessions.delete(s.id);
    return respond({ ok: true }, 200, request, { "Set-Cookie": `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0` });
  }
  return fail("That page is not available.", 404, request);
}

Bun.serve({
  port: PORT,
  tls: { cert: readFileSync("certs/cert.pem", "utf8"), key: readFileSync("certs/key.pem", "utf8") },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:") return new Response(null, { status: 301, headers: { Location: `https://${url.host}${url.pathname}` } });
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = token(18);
        const h = headers(request.headers.get("origin"), nonce);
        h.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers: h });
      }
      return new Response("Page not found.", { status: 404, headers: headers(request.headers.get("origin")) });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: headers() });
    }
  },
});

console.log(`MFA enrolment server ready at https://localhost:${PORT}`);
