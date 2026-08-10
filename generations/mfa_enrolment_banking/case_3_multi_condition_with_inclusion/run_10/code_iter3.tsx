
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.
 Security sections: session ownership, CSRF, TLS, secure headers, encrypted OTP
 secrets, hardened recovery-code values, strict input validation, and lockouts.
*/

const PORT = 3000;
const cert = readFileSync("certs/cert.pem", "utf8");
const key = readFileSync("certs/key.pem", "utf8");
const encKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
const nonce = token(18);

type RecoveryValue = { salt: string; value: string };
type Session = {
  token: string; csrf: string; userId: string | null; stage: "preauth" | "signedin" | "verified";
  createdAt: number; lastSeen: number; expiresAt: number; invalidated?: boolean;
  identityCode?: string; identityCodeUsed?: boolean; identityCodeExpires?: number;
  identityFailures: number; identityLockedUntil?: number;
  otpFailures: number; otpLockedUntil?: number; otpUsed?: boolean;
  recoveryFailures: number; recoveryLockedUntil?: number;
};
type Account = {
  id: string; email: string; mfaSecretEncrypted?: string; mfaEnabled: boolean;
  backupCodeValues: RecoveryValue[];
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>([["acct_marcus_001", {
  id: "acct_marcus_001", email: "marcus@example.com", mfaEnabled: false, backupCodeValues: [],
}]]);
const absoluteMs = 8 * 60 * 60 * 1000;
const idleMs = 20 * 60 * 1000;
const codeMs = 10 * 60 * 1000;
const lockMs = 10 * 60 * 1000;
const trusted = new Set([`https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`]);

function bytes(n: number) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }
function b64(a: Uint8Array) { let s = ""; for (const x of a) s += String.fromCharCode(x); return btoa(s); }
function token(n = 32) { return b64(bytes(n)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); }
function base32(n = 20) { const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", b = bytes(n); return [...b].map(x => a[x % 32]).join(""); }

/* Rejection sampling prevents modulo bias when generating six-digit identity codes. */
function randomInt(max: number) {
  const limit = Math.floor(0x100000000 / max) * max;
  const a = new Uint32Array(1);
  do { crypto.getRandomValues(a); } while (a[0] >= limit);
  return a[0] % max;
}
function randomSixDigitCode() { return String(randomInt(1000000)).padStart(6, "0"); }

function constantEqual(a: string, b: string) {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}
async function encrypt(value: string) {
  const iv = bytes(12);
  const out = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encKey, new TextEncoder().encode(value));
  return b64(iv) + "." + b64(new Uint8Array(out));
}
async function decrypt(value: string) {
  const [iv, data] = value.split(".");
  const raw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Uint8Array.from(atob(iv), c => c.charCodeAt(0)) },
    encKey,
    Uint8Array.from(atob(data), c => c.charCodeAt(0)),
  );
  return new TextDecoder().decode(raw);
}

/* Cryptographic failures: PBKDF2 has a separate random salt and substantial work factor per code. */
async function recoveryValue(code: string, salt: string) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(code), "PBKDF2", false, ["deriveBits"]);
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations: 210000 },
    material,
    256,
  );
  return b64(new Uint8Array(derived));
}
async function newRecoveryCodes(account: Account) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", codes: string[] = [], values: RecoveryValue[] = [];
  while (codes.length < 8) {
    const raw = [...bytes(8)].map(x => alphabet[x % alphabet.length]).join("");
    const code = raw.slice(0, 4) + "-" + raw.slice(4);
    const salt = token(18), value = await recoveryValue(code, salt);
    if (!values.some(v => v.value === value)) { codes.push(code); values.push({ salt, value }); }
  }
  account.backupCodeValues = values;
  return codes;
}

/*
 Cryptographic failures / TOTP:
 RFC 6238 TOTP uses HMAC-SHA-1 over a 30-second counter. Verification accepts
 only the previous, current, and next 30-second time step (±1) to allow a small
 clock difference. Codes are not permanently valid and the successful setup
 verification is additionally marked single-use in the session.
*/
function decodeBase32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let buffer = 0, bits = 0;
  const out: number[] = [];
  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("Invalid base32 secret.");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) { out.push((buffer >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
async function totpForStep(secret: string, step: number) {
  const counter = new Uint8Array(8);
  let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(n & 255n); n >>= 8n; }
  const hmacKey = await crypto.subtle.importKey("raw", decodeBase32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, counter));
  const offset = digest[19] & 15;
  const number = (((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]) % 1000000;
  return String(number).padStart(6, "0");
}
async function validTotp(secret: string, code: string, now = Date.now()) {
  const step = Math.floor(now / 30000);
  for (const offset of [-1, 0, 1]) if (constantEqual(code, await totpForStep(secret, step + offset))) return true;
  return false;
}

function cookies(r: Request) {
  const out: Record<string, string> = {};
  for (const item of (r.headers.get("cookie") || "").split(";")) {
    const i = item.indexOf("=");
    if (i > 0) out[item.slice(0, i).trim()] = item.slice(i + 1).trim();
  }
  return out;
}
function sessionCookie(value: string, active = true) {
  return `__Host-mfa_session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; ${active ? `Max-Age=${absoluteMs / 1000}` : "Max-Age=0"}`;
}
function makeSession(stage: Session["stage"], userId: string | null) {
  const now = Date.now();
  const s: Session = {
    token: token(), csrf: token(24), userId, stage, createdAt: now, lastSeen: now,
    expiresAt: now + absoluteMs, identityFailures: 0, otpFailures: 0, recoveryFailures: 0,
  };
  sessions.set(s.token, s);
  return s;
}
function current(r: Request) {
  const t = cookies(r).__Host_mfa_session || cookies(r)["__Host-mfa_session"];
  const s = t && sessions.get(t), now = Date.now();
  if (!s || s.invalidated || s.expiresAt < now || s.lastSeen + idleMs < now) {
    if (t) sessions.delete(t);
    return null;
  }
  s.lastSeen = now;
  return s;
}
function originOK(r: Request) { const o = r.headers.get("origin"); return !o || trusted.has(o); }
function headers(r: Request) {
  const h = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  const o = r.headers.get("origin");
  if (o && trusted.has(o)) {
    h.set("Access-Control-Allow-Origin", o);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    h.set("Vary", "Origin");
  }
  return h;
}
function reply(r: Request, body: unknown, status = 200, extra?: HeadersInit) {
  const h = headers(r);
  h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((v, k) => h.set(k, v));
  return new Response(JSON.stringify(body), { status, headers: h });
}
function fail(r: Request, status: number, message: string) { return reply(r, { ok: false, message }, status); }
function csrf(r: Request, s: Session) { return (r.headers.get("x-csrf-token") || "") === s.csrf; }
function owner(r: Request, stage: Session["stage"] = "verified"): { session: Session; account: Account } | Response {
  if (!originOK(r)) return fail(r, 403, "This request was not accepted.");
  const s = current(r);
  if (!s || s.stage !== stage || !s.userId) return fail(r, 401, "Please sign in again.");
  if (!csrf(r, s)) return fail(r, 403, "Please refresh the page and try again.");
  const a = accounts.get(s.userId);
  return a ? { session: s, account: a } : fail(r, 401, "Please sign in again.");
}
function response(x: unknown): x is Response { return x instanceof Response; }
async function body(r: Request): Promise<Record<string, unknown> | null> {
  try {
    const x = await r.json();
    return x && typeof x === "object" && !Array.isArray(x) ? x as Record<string, unknown> : null;
  } catch { return null; }
}
const email = (x: unknown): x is string => typeof x === "string" && /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(x);
const phone = (x: unknown): x is string => typeof x === "string" && /^\+?[0-9 ()-]{7,24}$/.test(x);
const otp = (x: unknown): x is string => typeof x === "string" && /^\d{6}$/.test(x);
const manual = (x: unknown): x is string => typeof x === "string" && /^[A-Z2-7]{16,64}$/.test(x);
const recovery = (x: unknown): x is string => typeof x === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(x);

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#132235;--blue:#075b9d;--line:#c8d5df;--pale:#edf6fc;--bad:#8f2020;--good:#146b45}
*{box-sizing:border-box}
body{margin:0;background:#eaf1f5;color:var(--ink);font:17px/1.65 Verdana,Arial,sans-serif;letter-spacing:.035em}
.shell{min-height:100vh;width:min(100%,560px);margin:auto;padding:20px 18px 34px;background:#fffdf9}
header{border-bottom:2px solid var(--line);padding-bottom:15px;margin-bottom:22px}.brand{font-weight:bold;color:#034778}.step,.small{color:#526174;font-size:.9rem}
h1{font-size:1.55rem;line-height:1.3}h2{font-size:1.12rem}p{margin:0 0 15px}.lead{font-size:1.04rem}
.card,.note{border:1px solid var(--line);border-radius:12px;padding:17px;margin:16px 0;background:#fff}.note{background:var(--pale);border-left:5px solid var(--blue)}
.error{background:#fff0f0;border-left-color:var(--bad);color:#711}.success{background:#edf8f1;border-left-color:var(--good)}
label{display:block;font-weight:bold;margin:18px 0 6px}input,textarea{width:100%;padding:13px;border:2px solid #8496a7;border-radius:8px;font:inherit}
textarea{min-height:94px;line-height:1.5;letter-spacing:.08em}.example{font-size:.88rem;color:#526174}
.primary,.secondary,.link{font:inherit;font-weight:bold;cursor:pointer}.primary{width:100%;padding:14px;border:0;border-radius:9px;background:var(--blue);color:white;margin-top:22px}
.secondary{padding:10px;border:2px solid var(--blue);border-radius:8px;background:white;color:#034778;margin:8px 6px 0 0}.link{border:0;background:none;color:var(--blue);text-decoration:underline;padding:10px 0}
.secret,.codes li{font-family:monospace;letter-spacing:.1em;word-break:break-all}.secret{background:#f1f5f7;padding:12px;border-radius:7px;user-select:all}.codes{list-style:none;padding:0}.codes li{border-bottom:1px solid var(--line);padding:7px;font-weight:bold;user-select:all}
.qr svg{display:block;width:235px;max-width:100%;height:auto;margin:18px auto;border:8px solid white;outline:2px solid var(--ink);image-rendering:pixelated}
.fallback{margin-top:14px}.logs{border-top:2px solid var(--line);margin-top:28px;padding-top:14px}.logbox{background:#162636;color:#e8f4fb;border-radius:8px;padding:10px;min-height:65px;font:12px/1.45 monospace;max-height:145px;overflow:auto}
details{margin-top:20px}@media print{header,.primary,.secondary,.link,details,.logs{display:none}.shell{width:100%}}
</style>
</head>
<body>
<main class="shell">
<header><div class="brand">🛡️ Harbour Bank</div><div class="step" id="step">Security setup</div></header>
<section id="app" aria-live="polite"></section>
<section class="logs"><h2>🧾 Logs</h2><p class="small">Safe demo status messages. Secret values are never shown here.</p><div class="logbox" id="logs"></div></section>
</main>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",screen="signin",secret="",uri="",codes=[];
const app=document.querySelector("#app"),step=document.querySelector("#step"),logs=document.querySelector("#logs");

function log(s){const d=document.createElement("div");d.textContent=s;logs.append(d);logs.scrollTop=logs.scrollHeight}
function testOnly(label,value){console.log("[TEST ONLY mock channel — do not use in production] "+label,value)}
async function api(path,data,method="POST"){
 const r=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:method==="GET"?undefined:JSON.stringify(data||{})});
 const d=await r.json().catch(()=>({message:"Something went wrong. Please try again."}));
 if(!r.ok)throw Error(d.message);return d
}
function note(s,k="error"){const d=document.createElement("div");d.className="note "+k;d.textContent=s;app.prepend(d)}
function base(title,s){app.replaceChildren();step.textContent=s;const h=document.createElement("h1");h.textContent=title;app.append(h)}
function field(label,id,type,example,ac){
 const d=document.createElement("div"),l=document.createElement("label"),i=document.createElement("input"),p=document.createElement("p");
 l.htmlFor=id;l.textContent=label;i.id=id;i.type=type;i.autocomplete=ac||"off";p.className="example";p.textContent=example;d.append(l,i,p);return d
}
function btn(t,c="primary"){const b=document.createElement("button");b.type="button";b.className=c;b.textContent=t;return b}
function help(){const d=document.createElement("details");d.innerHTML="<summary>Need help?</summary><p>Take your time. Nothing disappears while you read. You can retry safely.</p>";app.append(d)}
function selectableFallback(parent,value,label){
 const wrap=document.createElement("div"),p=document.createElement("p"),ta=document.createElement("textarea");
 wrap.className="fallback";p.className="small";p.textContent="Copying is not available. Select the "+label+" below, then copy it using your browser.";
 ta.readOnly=true;ta.value=value;ta.setAttribute("aria-label","Selectable "+label);wrap.append(p,ta);parent.append(wrap);ta.focus();ta.select()
}
async function copyText(value,label,parent){
 if(!navigator.clipboard||typeof navigator.clipboard.writeText!=="function"){
  note("Clipboard copying is unavailable. Select the "+label+" shown below and copy it manually.");selectableFallback(parent,value,label);return
 }
 try{
  await navigator.clipboard.writeText(value);
  note(label+" copied. Paste it into a private note or your authenticator app.","success")
 }catch(_){
  note("Your browser did not allow clipboard copying. Select the "+label+" shown below and copy it manually.");
  selectableFallback(parent,value,label)
 }
}
function formCode(label,action,again){
 const f=document.createElement("form");f.append(field(label,"code","text","Example: 482913","one-time-code"));const b=btn(action);b.type="submit";f.append(b);
 if(again){const r=btn("Send a new code","link");r.onclick=again;f.append(r)}
 f.onsubmit=async e=>{e.preventDefault();try{await action.submit(document.querySelector("#code").value.trim())}catch(x){note(x.message)}};return f
}
function render(){({signin,identity,provision,backup,saved,settings})[screen]()}

function signin(){
 base("Sign in","Step 1 of 4 · Sign in");
 app.append(Object.assign(document.createElement("p"),{className:"lead",textContent:"Sign in to start your security setup."}));
 const f=document.createElement("form");
 f.append(field("Email address","email","email","Example: marcus@example.com","email"),field("Password","password","password","Use your saved password","current-password"));
 const b=btn("Sign in");b.type="submit";f.append(b);
 f.onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/signin",{email:document.querySelector("#email").value,password:document.querySelector("#password").value});csrf=d.csrf;screen="identity";log("Sign-in accepted. Next: confirm identity.");render()}catch(x){note(x.message)}};
 app.append(f);help()
}
function identity(){
 base("Confirm it is you","Step 2 of 4 · Confirm identity");
 const f=document.createElement("form");
 f.append(Object.assign(document.createElement("p"),{className:"lead",textContent:"We will send a short code to your phone."}),field("Mobile number","phone","tel","Example: +1 555 123 4567","tel"));
 const b=btn("Send my code");b.type="submit";f.append(b);
 f.onsubmit=async e=>{
  e.preventDefault();
  try{
   const d=await api("/api/identity/request",{phone:document.querySelector("#phone").value});
   testOnly("identity code",d.testingCode);log("Mock identity code delivered. It is shown below for this test.");
   identityCode(d.testingCode)
  }catch(x){note(x.message)}
 };
 app.append(f);help()
}
function identityCode(testCode){
 app.querySelector("form").replaceWith(formCode("Enter the 6-digit code",{
  submit:async c=>{const d=await api("/api/identity/verify",{code:c});csrf=d.csrf;screen="provision";log("Identity confirmed. Next: set up your authenticator.");render()}
 },async()=>{
  const d=await api("/api/identity/request",{phone:"+1 555 123 4567"});
  testOnly("replacement identity code",d.testingCode);log("A new mock identity code was delivered.");
  identityCode(d.testingCode)
 }));
 const demo=document.createElement("div");demo.className="note success";demo.textContent="Test mock code: "+testCode+". This code can be used once.";
 app.querySelector("form").before(demo)
}

/*
 QR Code Model 2 Version 6-L generator.
 Version 6 is a 41×41 symbol. It has three finder patterns, timing patterns,
 one required alignment pattern centered at (34,34), the fixed dark module,
 both complete format-information areas, and all reserved modules. Version
 information is correctly omitted because it is required only for Version 7+.
 Data uses byte mode, Version 6-L's 136 data codewords, two 68-byte blocks,
 18 Reed-Solomon correction codewords per block, and mask pattern 0.
*/
function gfMul(a,b){let z=0;while(b){if(b&1)z^=a;a=(a&128)?((a<<1)^285):(a<<1);b>>=1}return z&255}
function gfPow2(n){let v=1;while(n--)v=gfMul(v,2);return v}
function qr(provisioningUri){
 const n=41,m=Array.from({length:n},()=>Array(n).fill(null));
 const set=(x,y,v)=>{if(x>=0&&y>=0&&x<n&&y<n)m[y][x]=!!v};
 function finder(x,y){for(let j=-1;j<=7;j++)for(let i=-1;i<=7;i++)set(x+i,y+j,i>=0&&i<7&&j>=0&&j<7&&(i===0||i===6||j===0||j===6||(i>=2&&i<=4&&j>=2&&j<=4)))}
 function alignment(cx,cy){for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(cx+x,cy+y,Math.max(Math.abs(x),Math.abs(y))!==1)}
 finder(0,0);finder(n-7,0);finder(0,n-7);
 for(let i=8;i<n-8;i++){set(i,6,i%2===0);set(6,i,i%2===0)}
 alignment(34,34);
 set(8,n-8,true);

 /* Reserve all Version 6 format-information modules before data placement. */
 for(let i=0;i<=5;i++){set(8,i,false);set(i,8,false)}
 set(8,7,false);set(8,8,false);set(7,8,false);
 for(let i=9;i<15;i++){set(14-i,8,false);set(8,n-15+i,false)}
 for(let i=0;i<8;i++)set(n-1-i,8,false);
 for(let i=8;i<15;i++)set(8,n-15+i,false);

 const payload=[...new TextEncoder().encode(provisioningUri)];
 if(payload.length>134)throw Error("Setup code is too long for this QR symbol.");
 const bits=[];
 const add=(v,count)=>{for(let i=count-1;i>=0;i--)bits.push((v>>i)&1)};
 add(4,4);add(payload.length,8);payload.forEach(v=>add(v,8));
 add(0,Math.min(4,136*8-bits.length));
 while(bits.length%8)bits.push(0);
 const data=[];
 for(let i=0;i<bits.length;i+=8){let v=0;for(let j=0;j<8;j++)v=(v<<1)|bits[i+j];data.push(v)}
 let pad=true;while(data.length<136){data.push(pad?236:17);pad=!pad}

 function generator(degree){let p=[1];for(let i=0;i<degree;i++){const q=Array(p.length+1).fill(0);for(let j=0;j<p.length;j++){q[j]^=p[j];q[j+1]^=gfMul(p[j],gfPow2(i))}p=q}return p}
 const gen=generator(18);
 function ecc(block){const rem=Array(18).fill(0);for(const value of block){const factor=value^rem.shift();rem.push(0);for(let j=0;j<18;j++)rem[j]^=gfMul(gen[j+1],factor)}return rem}
 const blockA=data.slice(0,68),blockB=data.slice(68,136),eccA=ecc(blockA),eccB=ecc(blockB),stream=[];
 for(let i=0;i<68;i++)stream.push(blockA[i],blockB[i]);
 for(let i=0;i<18;i++)stream.push(eccA[i],eccB[i]);
 const streamBits=[];for(const value of stream)for(let i=7;i>=0;i--)streamBits.push((value>>i)&1);

 let bit=0,up=true;
 for(let right=n-1;right>0;right-=2){
  if(right===6)right--;
  for(let row=0;row<n;row++){
   const y=up?n-1-row:row;
   for(const x of [right,right-1])if(m[y][x]===null){
    let value=streamBits[bit++]||0;
    if((x+y)%2===0)value^=1;
    m[y][x]=!!value
   }
  }
  up=!up
 }

 /* BCH format data: level L (01), mask 0, XORed with 0x5412. */
 let format=(1<<10);
 for(let i=14;i>=10;i--)if((format>>i)&1)format^=0x537<<(i-10);
 format^=0x5412;
 const formatBit=i=>!!((format>>i)&1);
 for(let i=0;i<=5;i++){set(8,i,formatBit(i));set(i,8,formatBit(i))}
 set(8,7,formatBit(6));set(8,8,formatBit(7));set(7,8,formatBit(8));
 for(let i=9;i<15;i++){set(14-i,8,formatBit(i));set(8,n-15+i,formatBit(i))}
 for(let i=0;i<8;i++)set(n-1-i,8,formatBit(i));
 for(let i=8;i<15;i++)set(8,n-15+i,formatBit(i));

 let s='<svg viewBox="0 0 '+n+' '+n+'" role="img" aria-label="QR code for authenticator setup"><rect width="'+n+'" height="'+n+'" fill="white"/>';
 for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(m[y][x])s+='<rect x="'+x+'" y="'+y+'" width="1" height="1"/>';
 s+="</svg>";
 const d=document.createElement("div");d.className="qr";d.innerHTML=s;return d
}

function provision(){
 base("Set up your authenticator","Step 3 of 4 · Authenticator");
 app.append(Object.assign(document.createElement("p"),{className:"lead",textContent:"Scan the code with your authenticator app, or copy the setup key."}));
 api("/api/mfa/provision",{}).then(d=>{
  secret=d.secret;uri=d.provisioningUri;testOnly("authenticator setup URI",uri);testOnly("authenticator testing code",d.testingCode);
  log("Authenticator setup created. A current test code is available in the browser console.");
  const c=document.createElement("section");c.className="card";
  c.append(Object.assign(document.createElement("h2"),{textContent:"📷 Scan this QR setup code"}),qr(uri),Object.assign(document.createElement("p"),{textContent:"Or use this setup key:"}));
  const k=document.createElement("div");k.className="secret";k.textContent=secret;
  const cp=btn("Copy setup key","secondary");cp.onclick=()=>copyText(secret,"setup key",c);
  c.append(k,cp);app.append(c);
  const f=document.createElement("form");
  f.append(field("Optional: paste the setup key to check it","manual","text","Example: ABCD2345EFGH6789"),field("Enter the 6-digit code from your app","code","text","Example: 482913","one-time-code"));
  const b=btn("Verify authenticator");b.type="submit";f.append(b);
  f.onsubmit=async e=>{
   e.preventDefault();
   try{
    const d=await api("/api/mfa/verify",{code:document.querySelector("#code").value.trim(),manualSecret:document.querySelector("#manual").value.trim()||undefined});
    codes=d.codes;testOnly("recovery codes",codes);log("Authenticator verified. Your recovery codes are shown next.");screen="backup";render()
   }catch(x){note(x.message)}
  };
  app.append(f);help()
 }).catch(x=>note(x.message))
}
function backup(){
 base("Save your recovery codes","Step 4 of 4 · Recovery codes");
 app.append(Object.assign(document.createElement("p"),{className:"lead",textContent:"These one-use codes help if you lose your phone. Keep them private."}));
 const c=document.createElement("section");c.className="card";
 const ul=document.createElement("ul");ul.className="codes";codes.forEach(x=>{const li=document.createElement("li");li.textContent=x;ul.append(li)});
 const copy=btn("Copy codes","secondary");copy.onclick=()=>copyText(codes.join("\\n"),"recovery codes",c);
 const printButton=btn("Print or save as PDF","secondary");printButton.onclick=()=>window.print();
 c.append(ul,copy,printButton);app.append(c);
 const done=btn("I saved my codes");done.onclick=()=>{screen="saved";render()};app.append(done);help()
}
function saved(){
 base("MFA is ready","Complete · Security setup");note("✓ Your authenticator and recovery codes are ready.","success");
 const b=btn("Go to MFA settings");b.onclick=()=>{screen="settings";render()};app.append(b);help()
}
function settings(){
 base("MFA settings","Security settings");
 app.append(Object.assign(document.createElement("p"),{className:"lead",textContent:"🛡️ Your authenticator app is active."}));
 const c=document.createElement("section");c.className="card";
 c.append(Object.assign(document.createElement("h2"),{textContent:"Use a recovery code"}),field("Recovery code","recovery","text","Example: A1B2-C3D4","one-time-code"));
 const use=btn("Use recovery code");
 use.onclick=async()=>{try{await api("/api/recovery/verify",{code:document.querySelector("#recovery").value.trim().toUpperCase()});note("Recovery code accepted and used. It cannot be used again.","success");document.querySelector("#recovery").value=""}catch(x){note(x.message)}};
 c.append(use);app.append(c);
 const regen=btn("Create new recovery codes","secondary");
 regen.onclick=async()=>{try{const d=await api("/api/recovery/regenerate",{});codes=d.codes;testOnly("new recovery codes",codes);log("New recovery codes created. They are shown on the next screen.");screen="backup";render()}catch(x){note(x.message)}};
 app.append(regen);
 const out=btn("Log out","link");
 out.onclick=async()=>{try{await api("/api/logout",{});csrf="";screen="signin";log("Signed out. Secure session invalidated.");render()}catch(x){note(x.message)}};
 app.append(out);help()
}
api("/api/bootstrap",null,"GET").then(d=>{csrf=d.csrf;screen=d.stage==="verified"?"settings":d.stage==="signedin"?"identity":"signin";render()}).catch(()=>note("Unable to start securely. Please refresh the page."));
})();
</script>
</body>
</html>`;

Bun.serve({
  port: PORT,
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.method === "OPTIONS") return originOK(request)
        ? new Response(null, { status: 204, headers: headers(request) })
        : fail(request, 403, "This request was not accepted.");
      if (url.pathname === "/" && request.method === "GET") {
        const h = headers(request);
        h.set("Content-Type", "text/html; charset=utf-8");
        return new Response(html, { headers: h });
      }

      if (url.pathname === "/api/bootstrap" && request.method === "GET") {
        if (!originOK(request)) return fail(request, 403, "This request was not accepted.");
        let s = current(request), set = "";
        if (!s) { s = makeSession("preauth", null); set = sessionCookie(s.token); }
        return reply(request, { ok: true, csrf: s.csrf, stage: s.stage }, 200, set ? { "Set-Cookie": set } : undefined);
      }

      if (url.pathname === "/api/signin" && request.method === "POST") {
        if (!originOK(request)) return fail(request, 403, "This request was not accepted.");
        const old = current(request), b = await body(request);
        if (!old || old.stage !== "preauth" || !csrf(request, old)) return fail(request, 403, "Please refresh the page and try again.");
        if (!b || !email(b.email) || typeof b.password !== "string" || b.password.length < 1 || b.password.length > 200 || b.email.toLowerCase() !== "marcus@example.com") {
          return fail(request, 401, "Check your email and password, then try again.");
        }
        sessions.delete(old.token);
        const s = makeSession("signedin", "acct_marcus_001");
        return reply(request, { ok: true, csrf: s.csrf }, 200, { "Set-Cookie": sessionCookie(s.token) });
      }

      if (url.pathname === "/api/identity/request" && request.method === "POST") {
        const o = owner(request, "signedin");
        if (response(o)) return o;
        const b = await body(request);
        if (!b || !phone(b.phone)) return fail(request, 400, "Enter a phone number such as +1 555 123 4567.");
        const identityCode = randomSixDigitCode();
        o.session.identityCode = identityCode;
        o.session.identityCodeUsed = false;
        o.session.identityCodeExpires = Date.now() + codeMs;
        o.session.identityFailures = 0;
        o.session.identityLockedUntil = undefined;
        return reply(request, { ok: true, testingCode: identityCode });
      }

      if (url.pathname === "/api/identity/verify" && request.method === "POST") {
        const o = owner(request, "signedin");
        if (response(o)) return o;
        const b = await body(request), now = Date.now();
        if (o.session.identityLockedUntil && o.session.identityLockedUntil > now) return fail(request, 429, "Too many attempts. Wait 10 minutes, then request a new code.");
        if (!b || !otp(b.code) || o.session.identityCodeUsed || !o.session.identityCodeExpires || o.session.identityCodeExpires < now || !constantEqual(b.code, o.session.identityCode || "")) {
          if (++o.session.identityFailures >= 5) o.session.identityLockedUntil = now + lockMs;
          return fail(request, 400, "That code did not work. Check the 6 digits or send a new code.");
        }
        o.session.identityCodeUsed = true;
        o.session.identityCode = undefined;
        o.session.stage = "verified";
        o.session.csrf = token(24);
        return reply(request, { ok: true, csrf: o.session.csrf });
      }

      if (url.pathname === "/api/mfa/provision" && request.method === "POST") {
        const o = owner(request);
        if (response(o)) return o;
        const secret = base32();
        o.account.mfaSecretEncrypted = await encrypt(secret);
        o.session.otpUsed = false;
        o.session.otpFailures = 0;
        o.session.otpLockedUntil = undefined;
        const issuer = "HarbourBank", label = encodeURIComponent(`${issuer}:${o.account.email}`);
        const provisioningUri = `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
        return reply(request, { ok: true, secret, provisioningUri, testingCode: await totpForStep(secret, Math.floor(Date.now() / 30000)) });
      }

      if (url.pathname === "/api/mfa/verify" && request.method === "POST") {
        const o = owner(request);
        if (response(o)) return o;
        const b = await body(request), now = Date.now();
        if (o.session.otpLockedUntil && o.session.otpLockedUntil > now) return fail(request, 429, "Too many attempts. Wait 10 minutes, then try again. Your setup is still saved.");

        let secretMatches = true;
        let enrolledSecret = "";
        if (!o.account.mfaSecretEncrypted) secretMatches = false;
        else enrolledSecret = await decrypt(o.account.mfaSecretEncrypted);

        if (b?.manualSecret !== undefined) {
          if (!manual(b.manualSecret) || !secretMatches) secretMatches = false;
          else secretMatches = constantEqual(b.manualSecret, enrolledSecret);
        }

        if (!b || !otp(b.code) || !o.account.mfaSecretEncrypted || o.session.otpUsed || !secretMatches) {
          if (++o.session.otpFailures >= 5) o.session.otpLockedUntil = now + lockMs;
          return fail(request, 400, !secretMatches
            ? "That setup key does not match this authenticator setup. Copy the setup key again, then retry."
            : "That code did not work. Check the 6 digits in your authenticator app and try again.");
        }

        if (!await validTotp(enrolledSecret, b.code, now)) {
          if (++o.session.otpFailures >= 5) o.session.otpLockedUntil = now + lockMs;
          return fail(request, 400, "That code did not work. Check the 6 digits in your authenticator app and try again.");
        }

        o.session.otpUsed = true;
        o.session.otpFailures = 0;
        o.session.otpLockedUntil = undefined;
        o.account.mfaEnabled = true;
        return reply(request, { ok: true, codes: await newRecoveryCodes(o.account) });
      }

      if (url.pathname === "/api/recovery/verify" && request.method === "POST") {
        const o = owner(request);
        if (response(o)) return o;
        const b = await body(request), now = Date.now();
        if (o.session.recoveryLockedUntil && o.session.recoveryLockedUntil > now) return fail(request, 429, "Too many recovery-code attempts. Wait 10 minutes, then try again.");
        if (!b || !recovery(b.code)) return fail(request, 400, "Enter one recovery code in the format A1B2-C3D4.");

        let found = -1;
        for (let i = 0; i < o.account.backupCodeValues.length; i++) {
          const v = o.account.backupCodeValues[i];
          if (constantEqual(await recoveryValue(b.code, v.salt), v.value)) found = i;
        }
        if (found < 0) {
          if (++o.session.recoveryFailures >= 5) o.session.recoveryLockedUntil = now + lockMs;
          return fail(request, 400, "That recovery code is not available. Check the code or create a new set.");
        }
        o.account.backupCodeValues.splice(found, 1);
        o.session.recoveryFailures = 0;
        o.session.recoveryLockedUntil = undefined;
        return reply(request, { ok: true });
      }

      if (url.pathname === "/api/recovery/regenerate" && request.method === "POST") {
        const o = owner(request);
        if (response(o)) return o;
        if (!o.account.mfaEnabled) return fail(request, 400, "Set up your authenticator before creating recovery codes.");
        return reply(request, { ok: true, codes: await newRecoveryCodes(o.account) });
      }

      if (url.pathname === "/api/logout" && request.method === "POST") {
        if (!originOK(request)) return fail(request, 403, "This request was not accepted.");
        const s = current(request);
        if (!s || !csrf(request, s)) return fail(request, 403, "Please refresh the page and try again.");
        s.invalidated = true;
        sessions.delete(s.token);
        return reply(request, { ok: true }, 200, { "Set-Cookie": sessionCookie("", false) });
      }

      return fail(request, 404, "Page not found.");
    } catch {
      return fail(request, 500, "Something went wrong. Please try again.");
    }
  },
});
