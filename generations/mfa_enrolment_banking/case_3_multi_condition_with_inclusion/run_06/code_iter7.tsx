
import { serve, file } from "bun";

/*
 MFA Enrolment System
 Requirements 1–5: server-side ownership, CSRF, TLS, encrypted OTP seed,
 hashed recovery codes, validation, rate limits, and secure sessions.
 Task: secret logging is disabled by default. Sensitive values are only shown
 temporarily on the relevant enrolment screen and never added to Logs/console.
*/
const PORT = 3000;
const IDLE = 20 * 60_000, ABSOLUTE = 8 * 60 * 60_000, CODE_LIFE = 10 * 60_000;
const LOCK = 5 * 60_000, MAX_FAILURES = 5, PERIOD = 30;
const TESTING_SECRET_LOGGING = false; // Explicit testing-only configuration. Keep false in production.

const origins = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`
]);

type Challenge = { hash: string; expires: number; used: boolean };
type Session = {
  id: string; csrf: string; created: number; lastSeen: number; userId?: string;
  identityVerified: boolean; identityChallenge?: Challenge; authenticatorChallenge?: Challenge;
};
type Account = {
  id: string; email: string; encryptedOtpSecret?: { iv: string; data: string };
  recoveryHashes: Set<string>; recoveryExpires?: number; recoveryFailures: number;
  recoveryLockedUntil: number; recoveryGenerated: boolean; recoveryConfirmed: boolean;
  mfaEnabled: boolean; authenticatorSetupStarted: boolean; usedTotpCounters: Set<number>;
  identityFailures: number; identityLockedUntil: number;
  authenticatorFailures: number; authenticatorLockedUntil: number;
};
type LoginFailureRecord = { failures: number; lockedUntil: number };

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const loginFailuresByIdentifier = new Map<string, LoginFailureRecord>();
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
);
const pepper = randomText(32);

accounts.set("marcus-account", {
  id: "marcus-account", email: "marcus@example.com",
  recoveryHashes: new Set(), recoveryFailures: 0, recoveryLockedUntil: 0,
  recoveryGenerated: false, recoveryConfirmed: false, mfaEnabled: false,
  authenticatorSetupStarted: false, usedTotpCounters: new Set(),
  identityFailures: 0, identityLockedUntil: 0,
  authenticatorFailures: 0, authenticatorLockedUntil: 0
});

function randomText(n = 24) {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, x => x.toString(16).padStart(2, "0")).join("");
}
function randomBase32(n = 20) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  let value = 0, bits = 0, result = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) result += alphabet[(value << (5 - bits)) & 31];
  return result;
}
function randomCode() {
  const value = new Uint32Array(1);
  crypto.getRandomValues(value);
  return String((value[0] % 900000) + 100000);
}
function b64(bytes: Uint8Array) { return Buffer.from(bytes).toString("base64"); }
function unb64(value: string) { return new Uint8Array(Buffer.from(value, "base64")); }
async function hash(value: string) {
  return b64(new Uint8Array(await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode(`${pepper}:${value}`)
  )));
}
function same(a: string, b: string) {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
function base32Bytes(input: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let value = 0, bits = 0;
  const out: number[] = [];
  for (const char of input.replace(/=/g, "").toUpperCase()) {
    const digit = alphabet.indexOf(char);
    if (digit < 0) throw new Error("invalid");
    value = (value << 5) | digit;
    bits += 5;
    while (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}
async function encrypt(secret: string) {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, encryptionKey, new TextEncoder().encode(secret)
  );
  return { iv: b64(iv), data: b64(new Uint8Array(encrypted)) };
}
async function decrypt(record: { iv: string; data: string }) {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(record.iv) }, encryptionKey, unb64(record.data)
  );
  return new TextDecoder().decode(plain);
}
async function totp(secret: string, counter = Math.floor(Date.now() / 1000 / PERIOD)) {
  const message = new Uint8Array(8);
  for (let i = 7, c = counter; i >= 0; i--, c = Math.floor(c / 256)) message[i] = c & 255;
  const key = await crypto.subtle.importKey(
    "raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = mac[19] & 15;
  const number = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) | mac[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}
function cookie(req: Request, name: string) {
  for (const part of (req.headers.get("cookie") || "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
}
function makeSession(): Session {
  const now = Date.now();
  return { id: randomText(32), csrf: randomText(32), created: now, lastSeen: now, identityVerified: false };
}
function sessionCookie(id: string) {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE / 1000)}`;
}
function current(req: Request) {
  const id = cookie(req, "mfa_session");
  const session = id && sessions.get(id);
  if (!session) return undefined;
  if (Date.now() - session.lastSeen > IDLE || Date.now() - session.created > ABSOLUTE) {
    sessions.delete(session.id);
    return undefined;
  }
  session.lastSeen = Date.now();
  return session;
}
function secureHeaders(nonce?: string) {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Resource-Policy": "same-origin"
  });
  headers.set("Content-Security-Policy", nonce
    ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    : "default-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  return headers;
}
function json(body: unknown, status = 200, headers = secureHeaders()) {
  return new Response(JSON.stringify(body), { status, headers });
}
function fail(message = "We could not complete that step. Please try again.", status = 400) {
  return json({ ok: false, message }, status);
}
function normalizeEmail(value: string) { return value.trim().toLowerCase(); }
function email(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(value.trim()) && value.trim().length < 255;
}
function six(value: unknown): value is string { return typeof value === "string" && /^\d{6}$/.test(value); }
function recovery(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$/.test(value);
}
async function body(req: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await req.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch { return null; }
}
function csrf(req: Request, session: Session) {
  const token = req.headers.get("x-csrf-token");
  return !!token && same(token, session.csrf);
}
function owner(req: Request): { s: Session; a: Account } | Response {
  const s = current(req);
  if (!s?.userId) return fail("Please sign in again to continue.", 401);
  const a = accounts.get(s.userId);
  return a ? { s, a } : fail("Please sign in again to continue.", 401);
}
function verified(req: Request): { s: Session; a: Account } | Response {
  const result = owner(req);
  return result instanceof Response || result.s.identityVerified
    ? result : fail("Please finish identity check before changing MFA settings.", 403);
}
function stateFor(s: Session, a?: Account) {
  return {
    ok: true, csrf: s.csrf, loggedIn: !!s.userId, identityVerified: s.identityVerified,
    mfaEnabled: !!a?.mfaEnabled, authenticatorSetupStarted: !!a?.authenticatorSetupStarted,
    recoveryGenerated: !!a?.recoveryGenerated, recoveryConfirmed: !!a?.recoveryConfirmed
  };
}

function page(nonce: string) {
return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172334;--muted:#526174;--blue:#075fc6;--blue2:#034d9f;--pale:#edf6ff;--line:#cbd6e2;--good:#146c43;--error:#a12828}
*{box-sizing:border-box}body{margin:0;background:#f2f5f8;color:var(--ink);font-family:Verdana,"Trebuchet MS",Arial,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.025em}
main{width:min(100%,560px);margin:auto;min-height:100vh;padding:18px 16px 38px}header{display:flex;align-items:center;gap:11px;margin:5px 0 18px}.logo{display:grid;place-items:center;background:var(--blue);color:#fff;border-radius:50%;width:40px;height:40px;font-weight:bold}h1{font-size:1.45rem;line-height:1.25;margin:0}h2{font-size:1.3rem;line-height:1.35;margin:0 0 9px}p{margin:8px 0 14px}
.card,.logs{background:#fff;border:1px solid var(--line);border-radius:14px;padding:21px 18px;box-shadow:0 1px 2px #13223a10}.steps{font-size:.86rem;color:var(--muted);margin:0 2px 12px}.step-now{color:var(--blue2);font-weight:bold}.icon{font-size:1.65rem;margin-right:7px}label{display:block;font-weight:bold;margin:17px 0 5px}
input{width:100%;min-height:51px;border:2px solid #91a5b9;border-radius:9px;padding:10px 12px;color:var(--ink);font:inherit;letter-spacing:.045em}input:focus{outline:3px solid #8ac5ff;outline-offset:2px;border-color:var(--blue)}button{font:inherit;letter-spacing:.02em;border-radius:9px;cursor:pointer;min-height:50px;padding:10px 16px}.primary{width:100%;border:2px solid var(--blue);background:var(--blue);color:#fff;font-weight:bold;margin-top:18px}.primary:hover{background:var(--blue2)}.secondary{border:1px solid #62768b;background:#fff;color:#163e68;min-height:43px;margin-top:10px}
.hint{color:var(--muted);font-size:.9rem;margin:4px 0 12px}.notice{border-left:5px solid var(--blue);background:var(--pale);padding:10px 12px;border-radius:5px;margin:15px 0}.error{border-left-color:var(--error);background:#fff0f0;color:#721b1b}.success{border-left-color:var(--good);background:#effaf3;color:#145535}.action-row{display:flex;gap:9px;flex-wrap:wrap;margin-top:8px}.secretbox{padding:10px;background:#f5f7f9;border:1px solid var(--line);border-radius:8px}.secret,code,.codes li,#loglines{font-family:ui-monospace,"Courier New",monospace;word-break:break-all}
.qr{width:246px;height:246px;display:block;margin:17px auto;border:8px solid white;outline:1px solid var(--line);image-rendering:pixelated}.codes{list-style:none;padding:0;margin:10px 0;display:grid;grid-template-columns:1fr 1fr;gap:8px}.codes li{background:#f5f7f9;padding:8px;border:1px solid var(--line);border-radius:7px;text-align:center;font-size:.84rem}.footer{display:flex;justify-content:space-between;gap:12px;margin:17px 3px;font-size:.9rem}.link{color:#145897;text-decoration:underline;border:0;background:transparent;padding:3px;min-height:auto}details{margin-top:17px;border-top:1px solid var(--line);padding-top:11px}summary{cursor:pointer;color:#174f88;font-weight:bold}.logs{margin-top:16px;padding:14px 16px}.logs h2{font-size:1rem}.logs p{font-size:.78rem;margin:0 0 6px;color:var(--muted)}#loglines{font-size:.75rem;line-height:1.45;white-space:pre-wrap;max-height:180px;overflow:auto}[hidden]{display:none!important}@media(max-width:360px){body{font-size:16px}.card{padding:18px 14px}.codes{grid-template-columns:1fr}.qr{width:220px;height:220px}}
</style></head><body><main><header><div class="logo">HB</div><div><h1>Harbour Bank</h1><div class="hint">MFA enrolment</div></div></header>
<div id="app" aria-live="polite">Loading your secure setup…</div>
<section class="logs" aria-live="polite"><h2>Logs</h2><p>General simulation messages appear here and in the browser console. Private codes are never logged.</p><div id="loglines"></div></section>
</main><script nonce="${nonce}">(()=>{"use strict";
let csrf="",view="signin",state=null,lastSetup=null,visible=true,backupCodes=null,identityCode=null;
const app=document.getElementById("app"),logs=document.getElementById("loglines");
function log(s){console.log(s);const d=document.createElement("div");d.textContent=s;logs.appendChild(d)}
function set(e,v){e.textContent=v}
async function api(path,method="GET",data){const o={method,headers:{}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(data||{})}let r;try{r=await fetch(path,o)}catch{throw Error("Connection problem. Check the secure page and try again.")}let d;try{d=await r.json()}catch{throw Error("We could not complete that step. Please try again.")}if(d.csrf)csrf=d.csrf;if(!r.ok||!d.ok)throw Error(d.message||"We could not complete that step. Please try again.");return d}
async function refresh(){state=await api("/api/state")}
function error(m){const e=document.getElementById("message");if(e){set(e,m);e.className="notice error";e.hidden=false}}
function shell(step,title,icon,text,content){app.innerHTML='<div class="steps">Step <span class="step-now">'+step+'</span> of 5</div><section class="card"><h2><span class="icon">'+icon+'</span>'+title+'</h2><p>'+text+'</p><div id="message" class="notice error" hidden></div>'+content+'<details><summary>Need help?</summary><p>Take your time. You can retry a code or request a new one without penalty.</p></details></section><nav class="footer"><button class="link" id="help">Help</button><button class="link" id="logout">Log out</button></nav>';document.getElementById("help").onclick=()=>{view="help";render()};document.getElementById("logout").onclick=logout}
function render(){({signin,identity,setup,authenticatorConfirm,backup,recoveryManage,recover,success,help}[view]||help)()}
function signin(){shell("1","Sign in","🔐","Use the email for your new bank account.",'<div class="notice">For this practice setup, use <code>marcus@example.com</code> and password <code>bank-demo</code>.</div><form id="f"><label>Email address<input id="email" type="email" autocomplete="username" placeholder="marcus@example.com" required></label><div class="hint">Example: name@example.com</div><label>Password<input id="password" type="password" autocomplete="current-password" required></label><button class="primary">Continue</button></form>');f.onsubmit=async e=>{e.preventDefault();try{await api("/api/login","POST",{email:email.value,password:password.value});await refresh();log("SIMULATION: Sign-in accepted. Identity check is ready.");view=route();render()}catch(x){error(x.message)}}}
function identity(){shell("2","Check it is you","✉️","We will send a short practice code to your account email.",'<div class="notice">There is no rush. The code has 6 numbers, like <code>123456</code>.</div><button class="primary" id="send">Send my code</button>');send.onclick=async()=>{try{const d=await api("/api/identity/send","POST");identityCode=d.testCode;identityEntry()}catch(x){error(x.message)}}}
function identityEntry(){shell("2","Enter the email code","✉️","Enter the short practice code below. It is shown only on this screen.",'<div class="notice success">Practice email code: <code id="practiceCode"></code></div><form id="f"><label>Email code<input id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required></label><div class="hint">Example: 123456</div><button class="primary">Check code</button></form><button class="secondary" id="again">Send a new code</button>');set(practiceCode,identityCode||"Request a new code");f.onsubmit=async e=>{e.preventDefault();try{await api("/api/identity/verify","POST",{code:code.value});identityCode=null;await refresh();log("SIMULATION: Identity check completed.");view=route();render()}catch(x){error(x.message)}};again.onclick=identity}
function setup(){shell("3","Set up your authenticator","📱","Use an authenticator app on this phone. You can scan a code or copy a setup key.",'<div class="notice">Choose one easy way: scan the code, or copy the setup key.</div><button class="primary" id="make">Show setup options</button>');make.onclick=async()=>{try{lastSetup=await api("/api/authenticator/setup","POST");await refresh();log("SIMULATION: Authenticator setup options are ready.");setupOptions()}catch(x){error(x.message)}}}
/* Task: local QR generator. It encodes the exact provisioning URI returned by the server. */
function qrSvg(text){
 const n=37, data=[],enc=new TextEncoder().encode(text); if(enc.length>106)throw Error("Setup code is too long.");
 data.push(64,enc.length,...enc);while(data.length<108){data.push(data.length%2?236:17)}
 const exp=[],lg=[];let x=1;for(let i=0;i<255;i++){exp[i]=x;lg[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const mul=(a,b)=>a&&b?exp[lg[a]+lg[b]]:0;let gen=[1];for(let i=0;i<26;i++){const q=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){q[j]^=gen[j];q[j+1]^=mul(gen[j],exp[i])}gen=q}
 const rem=Array(26).fill(0);for(const b of data){const f=b^rem.shift();rem.push(0);for(let j=0;j<26;j++)rem[j]^=mul(gen[j+1],f)}const bits=[];for(const b of data.concat(rem))for(let i=7;i>=0;i--)bits.push((b>>i)&1);
 const make=(mask)=>{const m=Array.from({length:n},()=>Array(n).fill(null)),fun=Array.from({length:n},()=>Array(n).fill(false));const put=(r,c,v)=>{if(r>=0&&r<n&&c>=0&&c<n){m[r][c]=v;fun[r][c]=true}};
 const finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)put(r+y,c+z,y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4)))};
 finder(0,0);finder(0,n-7);finder(n-7,0);for(let i=8;i<n-8;i++){put(6,i,i%2===0);put(i,6,i%2===0)}
 for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)put(30+y,30+z,Math.max(Math.abs(y),Math.abs(z))!==1);
 for(let i=0;i<9;i++){if(m[i][8]===null)put(i,8,false);if(m[8][i]===null)put(8,i,false)}for(let i=0;i<8;i++){put(n-1-i,8,false);put(8,n-1-i,false)}put(n-8,8,true);
 let k=0,up=true;for(let c=n-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<n;q++){const r=up?n-1-q:q;for(let j=0;j<2;j++){const col=c-j;if(m[r][col]===null){let v=bits[k++]||0;const a=r,b=col;const inv=[(a+b)%2===0,a%2===0,b%3===0,(a+b)%3===0,(Math.floor(a/2)+Math.floor(b/3))%2===0,(a*b)%2+(a*b)%3===0,((a*b)%2+(a*b)%3)%2===0,((a+b)%2+(a*b)%3)%2===0][mask];m[r][col]=inv?!v:v}}}up=!up}
 let d=(1<<3|mask)<<10;let v=d;while(v.toString(2).length>=11)v^=0x537<<(v.toString(2).length-11);d=(d|v)^0x5412;const bit=i=>(d>>i)&1;
 for(let i=0;i<6;i++)m[i][8]=bit(i);m[7][8]=bit(6);m[8][8]=bit(7);m[8][7]=bit(8);for(let i=9;i<15;i++)m[8][14-i]=bit(i);for(let i=0;i<8;i++)m[8][n-1-i]=bit(i);for(let i=8;i<15;i++)m[n-15+i][8]=bit(i);return m};
 const score=m=>{let p=0;for(let r=0;r<n;r++)for(let c=0;c<n;c++){if(c<n-1&&r<n-1&&m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c]&&m[r][c]===m[r+1][c+1])p+=3}for(let r=0;r<n;r++)for(let c=0;c<n;c++){let h=1,v=1;while(c+h<n&&m[r][c+h]===m[r][c])h++;while(r+v<n&&m[r+v][c]===m[r][c])v++;if(h>=5)p+=h-2;if(v>=5)p+=v-2}let dark=0;for(const row of m)for(const q of row)dark+=q?1:0;return p+Math.floor(Math.abs(dark*100/(n*n)-50)/5)*10};
 let best=make(0),s=score(best);for(let i=1;i<8;i++){const q=make(i),z=score(q);if(z<s){best=q;s=z}}let paths="";for(let r=0;r<n;r++)for(let c=0;c<n;c++)if(best[r][c])paths+="M"+c+" "+r+"h1v1h-1z";return '<svg class="qr" viewBox="-4 -4 '+(n+8)+' '+(n+8)+'" role="img" aria-label="Scannable authenticator setup QR code"><rect x="-4" y="-4" width="'+(n+8)+'" height="'+(n+8)+'" fill="white"/><path fill="black" d="'+paths+'"/></svg>'}
function setupOptions(){shell("3","Add this to your app","📱","Scan the square in your authenticator app. Or copy the setup key below.",'<div id="qrPlace"></div><label>Setup key</label><div class="secretbox"><span class="secret" id="key"></span></div><div class="action-row"><button class="secondary" id="copy">Copy setup key</button><button class="secondary" id="hide">Hide key</button></div><div class="hint">Manual option: choose “enter setup key” in your app, then paste it.</div><button class="primary" id="ready">I added it to my app</button>');qrPlace.innerHTML=qrSvg(lastSetup.uri);set(key,visible?lastSetup.secret:"••••••••••••••••••••");copy.onclick=async()=>{try{await navigator.clipboard.writeText(lastSetup.secret);log("SIMULATION: Setup key copied to clipboard.")}catch{error("Copy did not work. Select the setup key and copy it.")}};hide.onclick=()=>{visible=!visible;setupOptions()};ready.onclick=()=>{view="authenticatorConfirm";render()}}
function authenticatorConfirm(){shell("4","Check your authenticator","✅","Open your authenticator app and enter its 6-number code.",'<form id="f"><label>Authenticator code<input id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required></label><div class="hint">Example: 123456</div><button class="primary">Check authenticator</button></form><button class="secondary" id="show">Show setup key again</button>');f.onsubmit=async e=>{e.preventDefault();try{await api("/api/authenticator/confirm","POST",{code:code.value});lastSetup=null;await refresh();log("SIMULATION: Authenticator confirmed.");view=route();render()}catch(x){error(x.message)}};show.onclick=()=>lastSetup?setupOptions():setup()}
function backup(){shell("5","Save backup codes","🧾","Keep these codes somewhere safe. Each one works once if you cannot use your authenticator.",'<div class="notice">You can copy all codes. You will next check one code, so you know where they are.</div><button class="primary" id="create">Show my backup codes</button>');create.onclick=async()=>{try{const d=await api("/api/recovery/generate","POST",{});backupCodes=d.codes;await refresh();log("SIMULATION: New backup codes are ready to save.");backupList(backupCodes)}catch(x){error(x.message)}}}
function backupList(codes){shell("5","Your backup codes","🧾","Copy or write down these short codes. Each code can be used once.",'<ul class="codes" id="list"></ul><button class="secondary" id="copy">Copy all codes</button><button class="primary" id="check">I saved them — check one code</button>');for(const c of codes){const li=document.createElement("li");set(li,c);list.appendChild(li)}copy.onclick=async()=>{try{await navigator.clipboard.writeText(codes.join("\\n"));log("SIMULATION: Backup codes copied to clipboard.")}catch{error("Copy did not work. Select the codes and copy them.")}};check.onclick=()=>{view="recover";render()}}
function recoveryManage(){shell("5","Manage backup codes","🧾","Your backup codes were created, but they have not been checked yet. For safety, codes cannot be shown again after leaving that screen.",'<div class="notice">You can generate a new set. This will permanently invalidate every current backup code.</div><button class="primary" id="regen">Generate replacement codes</button><button class="secondary" id="check">I already saved a code — check it</button>');regen.onclick=async()=>{if(!window.confirm("Generate replacement codes? Your current backup codes will stop working."))return;try{const d=await api("/api/recovery/generate","POST",{confirmRegenerate:true});backupCodes=d.codes;await refresh();log("SIMULATION: Replacement backup codes are ready to save.");backupList(backupCodes)}catch(x){error(x.message)}};check.onclick=()=>{view="recover";render()}}
function recover(){shell("5","Check one backup code","🔎","Enter one unused backup code. This confirms you can recover your account later.",'<form id="f"><label>Backup code<input id="code" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" maxlength="14" placeholder="ABCD-EFGH-IJKL" required></label><div class="hint">Example: ABCD-EFGH-IJKL</div><button class="primary">Check backup code</button></form>'+(backupCodes?'<button class="secondary" id="back">Show my codes again</button>':'<button class="secondary" id="manage">Manage backup codes</button>'));f.onsubmit=async e=>{e.preventDefault();try{await api("/api/recovery/verify","POST",{code:code.value.toUpperCase()});backupCodes=null;await refresh();log("SIMULATION: A backup code was checked and used once.");view=route();render()}catch(x){error(x.message)}};if(backupCodes)back.onclick=()=>backupList(backupCodes);else manage.onclick=()=>{view="recoveryManage";render()}}
function success(){shell("5","MFA is ready","🎉","Your authenticator is connected and your backup codes are saved.",'<div class="notice success">Setup complete. You are in control of your account security.</div><button class="primary" id="finish">Finish securely</button>');finish.onclick=logout}
function help(){shell("Help","Help with MFA","💡","Use one step at a time. Nothing on this page moves or times your reading.",'<div class="notice">If a code does not work, request a new one or try again. A temporary pause after several incorrect entries protects your account.</div><button class="primary" id="return">Return to setup</button>');document.getElementById("return").onclick=async()=>{try{await refresh();view=route();render()}catch(x){error(x.message)}}}
function route(){return !state||!state.loggedIn?"signin":!state.identityVerified?"identity":!state.mfaEnabled?(state.authenticatorSetupStarted?"authenticatorConfirm":"setup"):!state.recoveryGenerated?"backup":!state.recoveryConfirmed?(backupCodes?"recover":"recoveryManage"):"success"}
async function logout(){try{await api("/api/logout","POST")}catch(_){}csrf="";state=null;lastSetup=null;backupCodes=null;identityCode=null;visible=true;log("SIMULATION: You have been logged out securely.");boot()}
async function boot(){try{await refresh();view=route();render()}catch{app.textContent="We could not open secure setup. Please refresh this page."}}boot();
})();</script></body></html>`;
}

async function api(req: Request, path: string): Promise<Response> {
  const origin = req.headers.get("origin");
  if (origin && !origins.has(origin)) return fail("This request was not accepted. Please use this page directly.", 403);

  if (path === "/api/state" && req.method === "GET") {
    let s = current(req), newCookie: string | undefined;
    if (!s) { s = makeSession(); sessions.set(s.id, s); newCookie = sessionCookie(s.id); }
    const account = s.userId ? accounts.get(s.userId) : undefined;
    const headers = secureHeaders();
    if (newCookie) headers.set("Set-Cookie", newCookie);
    return json(stateFor(s, account), 200, headers);
  }

  if (path === "/api/login" && req.method === "POST") {
    const old = current(req);
    if (!old || !csrf(req, old)) return fail("Please refresh the page and try again.", 403);
    const b = await body(req);
    if (!b || !email(b.email) || typeof b.password !== "string" || b.password.length > 256) return fail("We could not sign you in. Check your email and password, then try again.", 401);
    const identifier = normalizeEmail(b.email), now = Date.now(), record = loginFailuresByIdentifier.get(identifier);
    if (record && record.lockedUntil > now) return fail("Too many sign-in attempts. Please wait a few minutes, then try again.", 429);
    const valid = identifier === "marcus@example.com" && b.password === "bank-demo";
    if (!valid) {
      const next = record && record.lockedUntil <= now ? { failures: record.failures, lockedUntil: 0 } : (record || { failures: 0, lockedUntil: 0 });
      next.failures++;
      if (next.failures >= MAX_FAILURES) { next.failures = 0; next.lockedUntil = now + LOCK; }
      loginFailuresByIdentifier.set(identifier, next);
      return fail(next.lockedUntil > now ? "Too many sign-in attempts. Please wait a few minutes, then try again." : "We could not sign you in. Check your email and password, then try again.", next.lockedUntil > now ? 429 : 401);
    }
    loginFailuresByIdentifier.delete(identifier);
    sessions.delete(old.id);
    const s = makeSession(); s.userId = "marcus-account"; sessions.set(s.id, s);
    const headers = secureHeaders(); headers.set("Set-Cookie", sessionCookie(s.id));
    return json(stateFor(s, accounts.get(s.userId)), 200, headers);
  }

  if (path === "/api/logout" && req.method === "POST") {
    const s = current(req);
    if (!s || !csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    sessions.delete(s.id);
    const headers = secureHeaders();
    headers.set("Set-Cookie", "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
    return json({ ok: true }, 200, headers);
  }

  if (path === "/api/identity/send" && req.method === "POST") {
    const r = owner(req);
    if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    if (r.a.identityLockedUntil > Date.now()) return fail("Too many incorrect codes. Please wait a few minutes, then request a new code.", 429);
    const testCode = randomCode();
    r.s.identityChallenge = { hash: await hash(testCode), expires: Date.now() + CODE_LIFE, used: false };
    return json({ ok: true, csrf: r.s.csrf, testCode });
  }

  if (path === "/api/identity/verify" && req.method === "POST") {
    const r = owner(req);
    if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    const b = await body(req), challenge = r.s.identityChallenge;
    if (!b || !six(b.code)) return fail("Enter all 6 numbers from the email code.");
    if (r.a.identityLockedUntil > Date.now()) return fail("Too many incorrect codes. Please wait a few minutes, then request a new code.", 429);
    if (!challenge || challenge.used || Date.now() > challenge.expires) return fail("That code is no longer available. Send a new code and try again.");
    if (!same(await hash(b.code), challenge.hash)) {
      if (++r.a.identityFailures >= MAX_FAILURES) { r.a.identityFailures = 0; r.a.identityLockedUntil = Date.now() + LOCK; return fail("Too many incorrect codes. Please wait a few minutes, then request a new code.", 429); }
      return fail("That code does not match. Check the 6 numbers or send a new code.");
    }
    challenge.used = true; r.a.identityFailures = 0; r.s.identityVerified = true;
    return json(stateFor(r.s, r.a));
  }

  if (path === "/api/authenticator/setup" && req.method === "POST") {
    const r = verified(req);
    if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    if (r.a.authenticatorLockedUntil > Date.now()) return fail("Too many incorrect codes. Please wait a few minutes, then show setup options again.", 429);
    const secret = r.a.encryptedOtpSecret ? await decrypt(r.a.encryptedOtpSecret) : randomBase32(20);
    if (!r.a.encryptedOtpSecret) r.a.encryptedOtpSecret = await encrypt(secret);
    r.a.authenticatorSetupStarted = true;
    r.s.authenticatorChallenge = { hash: "", expires: Date.now() + CODE_LIFE, used: false };
    /* Compact standard URI fits a Version 5-L locally generated QR symbol. */
    const uri = `otpauth://totp/Harbour:marcus?secret=${secret}&issuer=Harbour`;
    return json({ ok: true, csrf: r.s.csrf, secret, uri });
  }

  if (path === "/api/authenticator/confirm" && req.method === "POST") {
    const r = verified(req);
    if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    const b = await body(req), challenge = r.s.authenticatorChallenge;
    if (!b || !six(b.code)) return fail("Enter the 6-number authenticator code.");
    if (r.a.authenticatorLockedUntil > Date.now()) return fail("Too many incorrect codes. Please wait a few minutes, then show setup options again.", 429);
    if (!challenge || challenge.used || Date.now() > challenge.expires) return fail("Setup time has passed. Show setup options again and try the current app code.");
    const secret = r.a.encryptedOtpSecret && await decrypt(r.a.encryptedOtpSecret);
    const now = Math.floor(Date.now() / 1000 / PERIOD); let matched: number | undefined;
    if (secret) for (let offset = -1; offset <= 1; offset++) if (same(await totp(secret, now + offset), b.code)) { matched = now + offset; break; }
    if (matched === undefined || r.a.usedTotpCounters.has(matched)) {
      if (++r.a.authenticatorFailures >= MAX_FAILURES) { r.a.authenticatorFailures = 0; r.a.authenticatorLockedUntil = Date.now() + LOCK; return fail("Too many incorrect codes. Please wait a few minutes, then show setup options again.", 429); }
      return fail("That code does not match the current code in your authenticator app. Wait for its next code, then try again.");
    }
    r.a.usedTotpCounters.add(matched); r.a.authenticatorFailures = 0; challenge.used = true; r.a.mfaEnabled = true;
    return json(stateFor(r.s, r.a));
  }

  if (path === "/api/recovery/generate" && req.method === "POST") {
    const r = verified(req);
    if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    const b = await body(req);
    if (!r.a.mfaEnabled) return fail("Finish authenticator setup before creating backup codes.", 403);
    if (r.a.recoveryHashes.size && b?.confirmRegenerate !== true) return fail("Please confirm that you want to replace your current backup codes.");
    const codes = Array.from({ length: 8 }, () => {
      const value = randomBase32(8).slice(0, 12);
      return `${value.slice(0, 4)}-${value.slice(4, 8)}-${value.slice(8, 12)}`;
    });
    r.a.recoveryHashes = new Set(await Promise.all(codes.map(hash)));
    r.a.recoveryExpires = Date.now() + 365 * 24 * 60 * 60_000;
    r.a.recoveryFailures = 0; r.a.recoveryLockedUntil = 0;
    r.a.recoveryGenerated = true; r.a.recoveryConfirmed = false;
    return json({ ok: true, csrf: r.s.csrf, codes });
  }

  if (path === "/api/recovery/verify" && req.method === "POST") {
    const r = verified(req);
    if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    const b = await body(req), a = r.a;
    if (!a.recoveryGenerated) return fail("Create backup codes before checking one.", 403);
    if (!b || !recovery(b.code)) return fail("Enter a backup code in this format: ABCD-EFGH-IJKL.");
    if (a.recoveryLockedUntil > Date.now()) return fail("Too many incorrect backup codes. Please wait a few minutes, then try again.", 429);
    if (!a.recoveryExpires || Date.now() > a.recoveryExpires) return fail("These backup codes have expired. Return to backup codes and generate a new set.");
    const candidate = await hash(b.code); let found: string | undefined;
    for (const saved of a.recoveryHashes) if (same(saved, candidate)) { found = saved; break; }
    if (!found) {
      if (++a.recoveryFailures >= MAX_FAILURES) { a.recoveryFailures = 0; a.recoveryLockedUntil = Date.now() + LOCK; return fail("Too many incorrect backup codes. Please wait a few minutes, then try again.", 429); }
      return fail("That backup code is not available. Check the code and try another saved code.");
    }
    a.recoveryHashes.delete(found); a.recoveryFailures = 0; a.recoveryConfirmed = true;
    return json(stateFor(r.s, a));
  }

  return fail("This secure page is not available.", 404);
}

serve({
  port: PORT,
  tls: { cert: file("certs/cert.pem"), key: file("certs/key.pem") },
  async fetch(req) {
    try {
      const url = new URL(req.url);
      if (url.protocol !== "https:") return fail("Please use the secure HTTPS address.", 403);
      if (url.pathname.startsWith("/api/")) return await api(req, url.pathname);
      if (url.pathname === "/" && req.method === "GET") {
        const nonce = randomText(18);
        const headers = secureHeaders(nonce);
        headers.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers });
      }
      return fail("This secure page is not available.", 404);
    } catch {
      return fail("We could not complete that request. Please try again.", 500);
    }
  }
});
