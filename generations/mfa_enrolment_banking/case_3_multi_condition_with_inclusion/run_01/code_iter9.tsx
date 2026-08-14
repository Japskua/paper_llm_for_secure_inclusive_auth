
import { existsSync, readFileSync } from "node:fs";
import { createCipheriv, createDecipheriv, createHmac, pbkdf2Sync, randomBytes, randomInt, timingSafeEqual } from "node:crypto";

/* Requirements: TLS-only Bun server and deterministic in-memory academic MFA demonstration. */
const PORT = Number(process.env.PORT || 3000);
const SESSION = "mfa_session";
const IDLE = 30 * 60_000, ABSOLUTE = 8 * 60 * 60_000;
const CHALLENGE = 10 * 60_000, LOCK = 10 * 60_000;
const IDENTITY_REQUEST_COOLDOWN = 30_000, PERIOD = 30_000, RECOVERY_EXPIRY = 365 * 24 * 60 * 60_000;
const key = randomBytes(32), pepper = randomBytes(32);

type Protected = { iv: Buffer; tag: Buffer; data: Buffer };
type Backup = { salt: Buffer; hash: Buffer; used: boolean; expires: number };
type Account = { id: string; email: string; mfa: boolean; secret?: Protected; backups: Backup[]; failures: number; locked?: number };
type Enrollment = { secret: Protected; failures: number; locked?: number; used: Set<number> };
type Session = {
  id: string; csrf: string; created: number; seen: number; phase: "preauth" | "auth"; user?: string;
  email?: string; code?: string; codeExpires?: number; codeUsed?: boolean;
  failures: number; locked?: number; identityRequested?: number; enrollment?: Enrollment;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const accountIds = new Map<string, Account>();
const token = (n = 32) => randomBytes(n).toString("base64url");

/* Cryptographic failures requirement: AES-GCM encrypts OTP seeds; PBKDF2 hashes recovery codes. */
function enc(value: string): Protected {
  const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return { iv, data, tag: cipher.getAuthTag() };
}
function dec(value: Protected) {
  const cipher = createDecipheriv("aes-256-gcm", key, value.iv);
  cipher.setAuthTag(value.tag);
  return Buffer.concat([cipher.update(value.data), cipher.final()]).toString("utf8");
}
function hash(value: string, salt = randomBytes(16)) {
  return { salt, hash: pbkdf2Sync(value, Buffer.concat([salt, pepper]), 210000, 32, "sha256") };
}
function matches(value: string, salt: Buffer, expected: Buffer) {
  const got = pbkdf2Sync(value, Buffer.concat([salt, pepper]), 210000, 32, "sha256");
  return got.length === expected.length && timingSafeEqual(got, expected);
}
function cookies(request: Request) {
  const result: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) result[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return result;
}

/* Authorization/session ownership requirement: every protected action resolves account only from HttpOnly session. */
function newSession(phase: "preauth" | "auth" = "preauth", user?: string) {
  const now = Date.now();
  const s: Session = { id: token(), csrf: token(), created: now, seen: now, phase, user, failures: 0 };
  sessions.set(s.id, s);
  return s;
}
function session(request: Request) {
  const s = sessions.get(cookies(request)[SESSION]);
  if (!s) return;
  const now = Date.now();
  if (now - s.seen > IDLE || now - s.created > ABSOLUTE) {
    sessions.delete(s.id);
    return;
  }
  s.seen = now;
  return s;
}
function sessionCookie(s: Session) {
  return `${SESSION}=${s.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE / 1000)}`;
}
const clearCookie = () => `${SESSION}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

/* IPv6 host normalization supports same-origin requests from https://[::1]:PORT. */
function trusted(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    const u = new URL(origin);
    const hostname = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    return u.protocol === "https:" && u.port === String(PORT) && ["localhost", "127.0.0.1", "::1"].includes(hostname);
  } catch { return false; }
}

/* TLS/security headers requirement: restrictive CSP, HSTS, anti-clickjacking and trusted-origin CORS only. */
function headers(request: Request, nonce?: string) {
  const h = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  });
  const origin = request.headers.get("origin");
  if (origin && trusted(request)) {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Vary", "Origin");
  }
  return h;
}
function reply(request: Request, data: unknown, status = 200, cookie?: string) {
  const h = headers(request);
  h.set("Content-Type", "application/json; charset=utf-8");
  if (cookie) h.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers: h });
}
const fail = (request: Request, status: number, message: string) => reply(request, { ok: false, message }, status);

async function body(request: Request): Promise<Record<string, unknown> | undefined> {
  if (Number(request.headers.get("content-length") || 0) > 4096) return;
  try {
    const parsed = await request.json();
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
  } catch { return; }
}

/* CSRF requirement: all changing API routes require same-origin request plus per-session token. */
function csrf(request: Request, s: Session) {
  const value = request.headers.get("x-csrf-token");
  return trusted(request) && !!value && value.length === s.csrf.length && timingSafeEqual(Buffer.from(value), Buffer.from(s.csrf));
}
function owner(request: Request) {
  const s = session(request);
  if (!s || s.phase !== "auth" || !s.user) return;
  const a = accountIds.get(s.user);
  return a ? { s, a } : undefined;
}
function account(email: string) {
  let a = accounts.get(email);
  if (!a) {
    a = { id: token(18), email, mfa: false, backups: [], failures: 0 };
    accounts.set(email, a);
    accountIds.set(a.id, a);
  }
  return a;
}

/* Input validation/rate-limit requirement: format checks happen server-side and failure state is session/account owned. */
const identityCode = () => String(randomInt(1_000_000)).padStart(6, "0");
function secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0, output = "";
  for (const byte of randomBytes(20)) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return bits ? output + alphabet[(value << (5 - bits)) & 31] : output;
}
function decode32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, current = 0;
  const output: number[] = [];
  for (const char of value.replace(/[=\s]/g, "")) {
    const n = alphabet.indexOf(char);
    if (n < 0) throw Error("invalid");
    current = (current << 5) | n;
    bits += 5;
    if (bits >= 8) {
      output.push((current >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}
function otp(secretValue: string, step = Math.floor(Date.now() / PERIOD)) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac("sha1", decode32(secretValue)).update(counter).digest();
  const offset = digest[19] & 15;
  return String((((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]) % 1_000_000).padStart(6, "0");
}
function backup() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let value = "";
  for (const byte of randomBytes(12)) value += alphabet[byte % alphabet.length];
  return `${value.slice(0, 4)}-${value.slice(4, 8)}-${value.slice(8)}`;
}
function newBackups(a: Account) {
  const plain = Array.from({ length: 8 }, backup);
  a.backups = plain.map(code => ({ ...hash(code), used: false, expires: Date.now() + RECOVERY_EXPIRY }));
  return plain;
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank · MFA</title>
<style nonce="${nonce}">
:root{--ink:#17263c;--blue:#075cc7;--pale:#edf6ff;--line:#d5dfeb;--muted:#526278;--good:#105537}
*{box-sizing:border-box}body{margin:0;background:#f5f8fc;color:var(--ink);font:16px/1.7 Verdana,Arial,sans-serif;letter-spacing:.035em}
main{max-width:560px;min-height:100vh;margin:auto;padding:22px 18px 32px;background:#fff}.brand{font-weight:700;color:#064b9f}.steps{display:flex;gap:5px;margin:18px 0 24px}.steps i{height:8px;flex:1;border-radius:8px;background:#dbe3ed}.steps i.on{background:var(--blue)}
h1{font-size:1.58rem;line-height:1.3;margin:0 0 10px}h2{font-size:1.16rem;line-height:1.35;margin:20px 0 8px}p{color:var(--muted);margin:8px 0 16px}
.hint,.notice,.error{padding:12px 13px;border-radius:8px;margin:14px 0;white-space:pre-line}.hint{background:var(--pale);border-left:4px solid var(--blue)}.notice{background:#eaf8f0;color:var(--good)}.error{background:#fff0e8;color:#843900}
label{display:block;font-weight:700;margin:15px 0 5px}input{width:100%;padding:13px;border:2px solid #9aaabd;border-radius:9px;font:inherit;letter-spacing:.09em}input:focus,button:focus{outline:3px solid #a9d0ff;outline-offset:2px;border-color:var(--blue)}
button{border:0;border-radius:9px;padding:13px 16px;font:inherit;font-weight:700;cursor:pointer;letter-spacing:.025em}.primary{display:block;width:100%;margin-top:18px;background:var(--blue);color:#fff}.secondary{margin:8px 6px 0 0;background:#e8f0fa;color:#17436d}.link{padding:8px 0;background:transparent;color:var(--blue);text-decoration:underline}
.secret,.codes{font-family:ui-monospace,Consolas,monospace;letter-spacing:.09em;background:#f4f7fa;padding:12px;border-radius:8px;overflow-wrap:anywhere}.codes{list-style:none}.codes li{padding:7px;border-bottom:1px solid var(--line)}
.qr{width:min(300px,100%);aspect-ratio:1;background:#fff;border:10px solid #fff;display:grid;grid-template-columns:repeat(57,1fr);margin:16px auto;image-rendering:pixelated}.q{background:#111}
[hidden]{display:none!important}@media(max-width:370px){body{font-size:15px}main{padding:17px 14px}}
</style>
</head>
<body>
<main id="app" aria-live="polite">Loading…</main>
<script nonce="${nonce}">
(()=>{"use strict";
/* Dyslexia-accessible UI requirement: short plain wording, ample spacing, no timers/motion, one primary action. */
const app=document.querySelector("#app");
const S={csrf:"",view:"signin",email:"",code:"",mfa:false,recoveryExists:false,secret:"",uri:"",otp:"",codes:[],notice:"",error:"",showQR:false,showSecret:false,showCodes:false,confirmReplace:false};
function log(message){console.log(message)}
async function api(path,method="GET",data){try{const r=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":S.csrf},body:method==="GET"?undefined:JSON.stringify(data||{})});const j=await r.json();if(r.status===401)S.view="signin";return j}catch{return{ok:false,message:"Connection problem. Please try again."}}}
function head(r,n){r.append(E("div",{class:"brand",text:"⚓ Harbour Bank"}));const steps=E("div",{class:"steps","aria-label":"Setup progress"});for(let i=1;i<5;i++)steps.append(E("i",{class:i<=n?"on":""}));r.append(steps)}
function status(r){if(S.error)r.append(E("div",{class:"error",role:"alert",text:S.error}));if(S.notice)r.append(E("div",{class:"notice",text:S.notice}))}
function help(r){r.append(E("button",{class:"link",type:"button",onClick:()=>{S.notice="Help: Take as long as you need. You can retry without penalty.";S.error="";render()},text:"? Need a little help"}))}
const E=(tag,p={},...kids)=>{const n=document.createElement(tag);for(const[k,v]of Object.entries(p)){if(k==="text")n.textContent=v;else if(k==="class")n.className=v;else if(k==="hidden")n.hidden=!!v;else if(k.startsWith("on"))n.addEventListener(k.slice(2).toLowerCase(),v);else n.setAttribute(k,String(v))}kids.forEach(x=>n.append(x instanceof Node?x:document.createTextNode(String(x))));return n};
function field(r,label,attrs){const id="field_"+Math.random().toString(36).slice(2);const input=E("input",{id,...attrs});r.append(E("label",{for:id,text:label}),input);return input}
function primary(r,text,fn){r.append(E("button",{class:"primary",type:"button",onClick:fn,text}))}
function render(){app.replaceChildren();const r=E("div");app.append(r);({signin,identity,home,enrol,codes,recovery}[S.view]||signin)(r)}

function signin(r){
 head(r,1);r.append(E("h1",{text:"Sign in to set up MFA"}),E("p",{text:"We will send one short identity code. This demo does not use a real email."}));status(r);
 const input=field(r,"Email address",{type:"email",autocomplete:"email",inputmode:"email",placeholder:"marcus@example.com"});input.value=S.email;
 r.append(E("div",{class:"hint",text:"Example: marcus@example.com"}));
 primary(r,"Send identity code",async()=>{const email=input.value.trim();if(!/^\\S+@\\S+\\.\\S+$/.test(email)){S.error="Enter an email in this format: name@example.com.";return render()}const x=await api("/api/signin/request","POST",{email});if(!x.ok){S.error=x.message;return render()}console.log("Mock identity verification code: "+x.mockCode);S.email=email;S.code=x.mockCode;S.notice="A six-digit code is ready for this demo.";S.error="";S.view="identity";render()});
 help(r);
}
function identity(r){
 head(r,1);r.append(E("h1",{text:"Check your identity"}),E("p",{text:"Enter the six-digit code we sent."}));status(r);
 if(S.code)r.append(E("div",{class:"hint",text:"Demo test code: "+S.code}));
 const input=field(r,"Identity code",{type:"text",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"Example: 123456"});
 primary(r,"Check code",async()=>{const code=input.value.replace(/\\s/g,"");if(!/^\\d{6}$/.test(code)){S.error="Enter all 6 numbers, for example 123456.";return render()}const x=await api("/api/signin/verify","POST",{code});if(!x.ok){S.error=x.message;return render()}S.csrf=x.csrf;S.mfa=x.mfa;S.recoveryExists=!!x.recoveryExists;S.code="";S.notice="Identity checked. Next, set up your authenticator.";S.error="";S.view="home";render()});
 r.append(E("button",{class:"secondary",type:"button",onClick:()=>{S.view="signin";S.notice="You can request a new code. Previous incorrect attempts still count.";S.error="";render()},text:"Request another code"}));help(r);
}
function home(r){
 head(r,S.mfa?4:2);r.append(E("h1",{text:S.mfa?"MFA is set up":"Set up your authenticator"}),E("p",{text:S.mfa?"Your account has an extra sign-in check. Keep recovery codes somewhere safe.":"Use an authenticator app to get a short code when needed."}));status(r);
 if(!S.mfa){r.append(E("div",{class:"hint",text:"You can scan a QR pattern, or reveal and copy the setup secret instead."}));primary(r,"Set up authenticator",async()=>{const x=await api("/api/mfa/enroll","POST",{});if(!x.ok){S.error=x.message;return render()}S.secret=x.secret;S.uri=x.provisioningUri;S.otp=x.mockOtp;log("Mock authenticator OTP for verification: "+x.mockOtp);S.notice=x.existing?"Your existing setup is still ready.":"Setup secret ready. Choose the method that feels easiest.";S.error="";S.view="enrol";render()})}
 else {r.append(E("div",{class:"notice",text:"Authenticator confirmed. Your next step is to save recovery codes."}));primary(r,"View recovery codes",()=>{S.view="codes";S.notice="";render()});r.append(E("button",{class:"secondary",type:"button",onClick:()=>{S.view="recovery";render()},text:"Test a recovery code"}))}
 r.append(E("button",{class:"link",type:"button",onClick:logout,text:"Sign out"}));help(r);
}

/* Dependency-free ISO/IEC 18004 QR encoder: Version 10-L, byte mode, Reed-Solomon ECC and best mask. */
function qr(payload){
 const N=57,V=10,DATA=274,EC=18;
 const utf=new TextEncoder().encode(payload);
 if(utf.length>271)return E("div",{class:"error",text:"The QR setup information is too long. Use the manual setup secret instead."});
 const exp=[],logt=Array(256);let x=1;
 for(let i=0;i<255;i++){exp[i]=x;logt[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const mul=(a,b)=>a&&b?exp[logt[a]+logt[b]]:0;
 function poly(n){let p=[1];for(let i=0;i<n;i++){const q=Array(p.length+1).fill(0);for(let j=0;j<p.length;j++){q[j]^=p[j];q[j+1]^=mul(p[j],exp[i])}p=q}return p}
 function rs(data,n){const g=poly(n),r=Array(n).fill(0);for(const v of data){const z=v^r.shift();r.push(0);for(let j=0;j<n;j++)r[j]^=mul(g[j+1],z)}return r}
 const bits=[];
 const put=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>>i)&1)};
 put(4,4);put(utf.length,16);for(const b of utf)put(b,8);
 while(bits.length<DATA*8&&bits.length%8)bits.push(0);
 const bytes=[];for(let i=0;i<bits.length;i+=8){let b=0;for(let j=0;j<8;j++)b=(b<<1)|(bits[i+j]||0);bytes.push(b)}
 for(let i=0;bytes.length<DATA;i++)bytes.push(i%2?17:236);
 const blocks=[bytes.slice(0,68),bytes.slice(68,136),bytes.slice(136,205),bytes.slice(205,274)];
 const ecc=blocks.map(b=>rs(b,EC)), stream=[];
 for(let i=0;i<69;i++)for(const b of blocks)if(i<b.length)stream.push(b[i]);
 for(let i=0;i<EC;i++)for(const b of ecc)stream.push(b[i]);
 const dataBits=[];for(const b of stream)putBits(dataBits,b,8);
 function putBits(a,v,n){for(let i=n-1;i>=0;i--)a.push((v>>>i)&1)}
 function fresh(){return Array.from({length:N},()=>Array(N).fill(null))}
 function set(m,r,c,v){if(r>=0&&c>=0&&r<N&&c<N)m[r][c]=v}
 function finder(m,r,c){for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++){const on=y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4));set(m,r+y,c+z,on?1:0)}}
 function alignment(m,r,c){for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)set(m,r+y,c+z,(Math.max(Math.abs(y),Math.abs(z))===2||(y===0&&z===0))?1:0)}
 function bch(v,g){let d=v;while((d.toString(2).length)>=(g.toString(2).length))d^=g<<(d.toString(2).length-g.toString(2).length);return d}
 function base(){
  const m=fresh();finder(m,0,0);finder(m,N-7,0);finder(m,0,N-7);
  for(let i=8;i<N-8;i++){set(m,6,i,i%2?0:1);set(m,i,6,i%2?0:1)}
  [6,28,50].forEach(r=>[6,28,50].forEach(c=>{if(m[r][c]===null)alignment(m,r,c)}));
  set(m,N-8,8,1);return m;
 }
 function format(m,mask){
  const v=(1<<3)|mask, f=((v<<10)|bch(v<<10,0x537))^0x5412;
  for(let i=0;i<15;i++){const bit=(f>>>i)&1;if(i<6)set(m,i,8,bit);else if(i<8)set(m,i+1,8,bit);else set(m,N-15+i,8,bit);if(i<8)set(m,8,N-i-1,bit);else if(i<9)set(m,8,15-i,bit);else set(m,8,14-i,bit)}
  const vv=(V<<12)|bch(V<<12,0x1f25);
  for(let i=0;i<18;i++){const bit=(vv>>>i)&1;set(m,Math.floor(i/3),N-11+i%3,bit);set(m,N-11+i%3,Math.floor(i/3),bit)}
 }
 function fill(m,mask){
  let k=0,up=true;
  for(let c=N-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<N;q++){const r=up?N-1-q:q;for(let z=0;z<2;z++){const col=c-z;if(m[r][col]===null){let b=dataBits[k++]||0;const a=[(r+col)%2===0,r%2===0,col%3===0,(r+col)%3===0,(Math.floor(r/2)+Math.floor(col/3))%2===0,(r*col)%2+(r*col)%3===0,((r*col)%2+(r*col)%3)%2===0,((r+col)%2+(r*col)%3)%2===0][mask];m[r][col]=b^(a?1:0)}}}up=!up}
 }
 function penalty(m){let p=0;for(let r=0;r<N;r++)for(let c=0;c<N;c++){let same=1;for(let q=c+1;q<N&&m[r][q]===m[r][c];q++)same++;if(same>=5)p+=3+same-5;same=1;for(let q=r+1;q<N&&m[q][c]===m[r][c];q++)same++;if(same>=5)p+=3+same-5;if(r<N-1&&c<N-1&&m[r][c]===m[r+1][c]&&m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c+1])p+=3}for(let r=0;r<N;r++)for(let c=0;c<N-6;c++){const a=m[r].slice(c,c+7).join("");if(a==="1011101")p+=40}for(let c=0;c<N;c++)for(let r=0;r<N-6;r++){let a="";for(let q=0;q<7;q++)a+=m[r+q][c];if(a==="1011101")p+=40}let dark=0;for(const row of m)for(const b of row)dark+=b;return p+Math.floor(Math.abs(dark*100/(N*N)-50)/5)*10}
 let best,bestP=Infinity;for(let mask=0;mask<8;mask++){const m=base();fill(m,mask);format(m,mask);const p=penalty(m);if(p<bestP){bestP=p;best=m}}
 const box=E("div",{class:"qr",role:"img","aria-label":"Authenticator setup QR code"});for(const row of best)for(const bit of row)box.append(E("span",{class:bit?"q":""}));return box;
}
function enrol(r){
 head(r,2);r.append(E("h1",{text:"Add the authenticator"}),E("p",{text:"In your authenticator app, add an account. Scan the QR code or copy the setup secret."}));status(r);
 r.append(E("button",{class:"secondary",type:"button","aria-expanded":String(S.showQR),onClick:()=>{S.showQR=!S.showQR;render()},text:S.showQR?"Hide QR code":"Show QR code"}));if(S.showQR)r.append(qr(S.uri));
 r.append(E("h2",{text:"Manual setup secret"}),E("button",{class:"secondary",type:"button","aria-expanded":String(S.showSecret),onClick:()=>{S.showSecret=!S.showSecret;render()},text:S.showSecret?"Hide setup secret":"Show setup secret"}));
 if(S.showSecret)r.append(E("div",{class:"secret",text:S.secret}),E("button",{class:"secondary",type:"button",onClick:()=>copy(S.secret,"The setup secret was copied."),text:"Copy setup secret"}));
 r.append(E("div",{class:"hint",text:"Demo test code: "+S.otp}));const input=field(r,"Authenticator code",{type:"text",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"Example: 123456"});
 primary(r,"Confirm authenticator",async()=>{const x=await api("/api/mfa/confirm","POST",{otp:input.value.replace(/\\s/g,"")});if(!x.ok){S.error=x.message;return render()}S.mfa=true;S.secret=S.uri=S.otp="";S.notice="Authenticator confirmed. Now save your recovery codes.";S.error="";S.view="codes";render()});
 r.append(E("button",{class:"link",type:"button",onClick:()=>{S.view="home";render()},text:"Back"}));help(r);
}
function replacementPrompt(r){
 r.append(E("div",{class:"error",role:"alert",text:"Generate new codes? All prior unused recovery codes will stop working."}));
 r.append(E("button",{class:"secondary",type:"button",onClick:()=>{S.confirmReplace=false;render()},text:"Keep current codes"}));
 primary(r,"Yes, replace all codes",async()=>{const x=await api("/api/mfa/backup/regenerate","POST",{confirm:true});if(!x.ok){S.error=x.message;S.confirmReplace=false;return render()}S.codes=x.codes;S.recoveryExists=true;S.showCodes=false;S.confirmReplace=false;log("Mock replacement recovery codes: "+x.codes.join(", "));S.notice="All old recovery codes stopped working. Save these new codes now.";S.error="";render()});
}
function codes(r){
 head(r,4);r.append(E("h1",{text:"Save recovery codes"}),E("p",{text:"Each code works once if you cannot use your authenticator. Save them somewhere private."}));status(r);
 if(S.confirmReplace){replacementPrompt(r);help(r);return}
 if(S.codes.length){r.append(E("button",{class:"secondary",type:"button","aria-expanded":String(S.showCodes),onClick:()=>{S.showCodes=!S.showCodes;render()},text:S.showCodes?"Hide recovery codes":"Show recovery codes"}));if(S.showCodes){const list=E("ul",{class:"codes"});S.codes.forEach(code=>list.append(E("li",{text:code})));r.append(list)}r.append(E("button",{class:"secondary",type:"button",onClick:()=>copy(S.codes.join("\\n"),"Recovery codes copied."),text:"Copy all codes"}));primary(r,"I saved my codes",()=>{S.codes=[];S.showCodes=false;S.notice="Recovery codes are ready when you need them.";S.view="home";render()});r.append(E("button",{class:"secondary",type:"button",onClick:()=>{S.confirmReplace=true;S.notice="";render()},text:"Generate new recovery codes"}))}
 else if(S.recoveryExists){r.append(E("div",{class:"hint",text:"Recovery codes already exist. Replacing them will stop all old unused codes."}));primary(r,"Replace recovery codes",()=>{S.confirmReplace=true;S.notice="";render()})}
 else primary(r,"Create recovery codes",async()=>{const x=await api("/api/mfa/backup/regenerate","POST",{confirm:false});if(!x.ok){S.error=x.message;return render()}S.codes=x.codes;S.recoveryExists=true;S.showCodes=false;log("Mock backup recovery codes: "+x.codes.join(", "));S.notice="New recovery codes created. Save them now.";S.error="";render()});
 r.append(E("button",{class:"secondary",type:"button",onClick:()=>{S.view="recovery";render()},text:"Use a recovery code"}));help(r);
}
function recovery(r){
 head(r,4);r.append(E("h1",{text:"Use a recovery code"}),E("p",{text:"Enter one unused recovery code. It will be used up after it works."}));status(r);const input=field(r,"Recovery code",{type:"text",autocomplete:"one-time-code",placeholder:"Example: ABCD-EFGH-JKLM"});
 primary(r,"Check recovery code",async()=>{const x=await api("/api/mfa/recovery/verify","POST",{code:input.value.trim().toUpperCase()});if(!x.ok){S.error=x.message;return render()}S.notice="Recovery code accepted and used. Your MFA remains active.";S.error="";S.view="home";render()});
 r.append(E("button",{class:"link",type:"button",onClick:()=>{S.view="home";render()},text:"Back"}));help(r);
}
async function copy(value,message){try{await navigator.clipboard.writeText(value);S.notice=message}catch{S.notice="Select the code and copy it using your browser controls."}S.error="";render()}
async function logout(){await api("/api/logout","POST",{});Object.assign(S,{csrf:"",view:"signin",mfa:false,recoveryExists:false,secret:"",uri:"",otp:"",codes:[],showCodes:false,showSecret:false,confirmReplace:false,notice:"Signed out.",error:""});render()}
(async()=>{const x=await api("/api/session");if(x.ok){S.csrf=x.csrf;S.mfa=x.mfa;S.recoveryExists=!!x.recoveryExists;S.view=x.auth?"home":"signin"}render()})();
})();
</script>
</body>
</html>`;
}

async function handler(request: Request): Promise<Response> {
  try {
    const u = new URL(request.url);
    if (request.method === "OPTIONS") {
      if (!trusted(request)) return fail(request, 403, "This request is not allowed.");
      const h = headers(request);
      h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
      return new Response(null, { status: 204, headers: h });
    }
    if (u.pathname === "/" && request.method === "GET") {
      const nonce = token(18), h = headers(request, nonce);
      h.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { headers: h });
    }
    if (!u.pathname.startsWith("/api/")) return fail(request, 404, "Page not found.");

    if (u.pathname === "/api/session" && request.method === "GET") {
      let s = session(request), cookie: string | undefined;
      if (!s) { s = newSession(); cookie = sessionCookie(s); }
      const a = s.user && accountIds.get(s.user);
      return reply(request, { ok: true, csrf: s.csrf, auth: !!a && s.phase === "auth", mfa: !!a?.mfa, recoveryExists: !!a?.backups.length }, 200, cookie);
    }
    if (u.pathname === "/api/signin/request" && request.method === "POST") {
      let s = session(request), cookie: string | undefined;
      if (!s) { s = newSession(); cookie = sessionCookie(s); }
      if (!csrf(request, s)) return fail(request, 403, "Your page check expired. Refresh the page and try again.");
      const d = await body(request), email = typeof d?.email === "string" ? d.email.trim().toLowerCase() : "";
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(email) || email.length > 120) return fail(request, 400, "Enter an email in this format: name@example.com.");
      const now = Date.now();
      if (s.identityRequested && now - s.identityRequested < IDENTITY_REQUEST_COOLDOWN) return fail(request, 429, `Please wait about ${Math.ceil((IDENTITY_REQUEST_COOLDOWN - (now - s.identityRequested)) / 1000)} seconds before requesting another code.`);
      s.email = email; s.code = identityCode(); s.codeExpires = now + CHALLENGE; s.codeUsed = false; s.identityRequested = now;
      return reply(request, { ok: true, mockCode: s.code }, 200, cookie);
    }
    if (u.pathname === "/api/signin/verify" && request.method === "POST") {
      const s = session(request);
      if (!s || !csrf(request, s)) return fail(request, 403, "Your page check expired. Refresh the page and try again.");
      const d = await body(request), code = typeof d?.code === "string" ? d.code : "", now = Date.now();
      if (s.locked && now < s.locked) return fail(request, 429, "Too many incorrect codes. Wait a few minutes, then try again.");
      if (!/^\d{6}$/.test(code)) return fail(request, 400, "Enter all 6 numbers from the code.");
      if (!s.email || !s.code || s.codeUsed || !s.codeExpires || now > s.codeExpires) return fail(request, 400, "That code is no longer available. Request a new code and try again.");
      if (!timingSafeEqual(Buffer.from(code), Buffer.from(s.code))) { if (++s.failures >= 5) s.locked = now + LOCK; return fail(request, 400, "That code did not match. Check the 6 numbers or request another code."); }
      const a = account(s.email); s.codeUsed = true; sessions.delete(s.id);
      const auth = newSession("auth", a.id);
      return reply(request, { ok: true, csrf: auth.csrf, mfa: a.mfa, recoveryExists: a.backups.length > 0 }, 200, sessionCookie(auth));
    }
    if (u.pathname === "/api/logout" && request.method === "POST") {
      const s = session(request);
      if (!s || !csrf(request, s)) return fail(request, 403, "Your page check expired. Refresh the page and try again.");
      sessions.delete(s.id); return reply(request, { ok: true }, 200, clearCookie());
    }

    const o = owner(request);
    if (!o) return fail(request, 401, "Please sign in again to continue.");
    if (!csrf(request, o.s)) return fail(request, 403, "Your page check expired. Refresh the page and try again.");

    if (u.pathname === "/api/mfa/enroll" && request.method === "POST") {
      if (o.a.mfa) return fail(request, 400, "Your authenticator is already confirmed.");
      let existing = true;
      if (!o.s.enrollment) { o.s.enrollment = { secret: enc(secret()), failures: 0, used: new Set() }; existing = false; }
      const value = dec(o.s.enrollment.secret), label = encodeURIComponent(`Harbour Bank:${o.a.email}`);
      return reply(request, { ok: true, existing, secret: value, provisioningUri: `otpauth://totp/${label}?secret=${value}&issuer=Harbour%20Bank&algorithm=SHA1&digits=6&period=30`, mockOtp: otp(value) });
    }
    if (u.pathname === "/api/mfa/confirm" && request.method === "POST") {
      const d = await body(request), value = typeof d?.otp === "string" ? d.otp : "", e = o.s.enrollment, now = Date.now();
      if (!e) return fail(request, 400, "Start authenticator setup first, then enter its code.");
      if (e.locked && now < e.locked) return fail(request, 429, "Too many incorrect codes. Wait a few minutes, then try this same setup again.");
      if (!/^\d{6}$/.test(value)) return fail(request, 400, "Enter all 6 numbers from your authenticator.");
      const sec = dec(e.secret), step = Math.floor(now / PERIOD); let hit: number | undefined;
      for (const n of [step - 1, step, step + 1]) if (otp(sec, n) === value && !e.used.has(n)) { hit = n; break; }
      if (hit === undefined) { if (++e.failures >= 5) e.locked = now + LOCK; return fail(request, 400, "That authenticator code is expired, already used, or does not match. Get a new code in your app and try again."); }
      e.used.add(hit); o.a.secret = e.secret; o.a.mfa = true; o.s.enrollment = undefined;
      return reply(request, { ok: true });
    }
    if (u.pathname === "/api/mfa/backup/regenerate" && request.method === "POST") {
      if (!o.a.mfa) return fail(request, 400, "Confirm your authenticator before creating recovery codes.");
      const d = await body(request), confirm = d?.confirm === true;
      if (o.a.backups.length && !confirm) return fail(request, 400, "Confirm that all prior unused recovery codes should stop working.");
      return reply(request, { ok: true, codes: newBackups(o.a) });
    }
    if (u.pathname === "/api/mfa/recovery/verify" && request.method === "POST") {
      const d = await body(request), value = typeof d?.code === "string" ? d.code.trim().toUpperCase() : "", now = Date.now();
      if (o.a.locked && now < o.a.locked) return fail(request, 429, "Too many incorrect codes. Wait a few minutes, then try a saved code.");
      const found = /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(value) && o.a.backups.find(x => !x.used && x.expires > now && matches(value, x.salt, x.hash));
      if (!found) { if (++o.a.failures >= 5) o.a.locked = now + LOCK; return fail(request, 400, "That recovery code is unavailable. Try another saved, unused code or create new codes."); }
      found.used = true; o.a.failures = 0; return reply(request, { ok: true });
    }
    return fail(request, 404, "Page not found.");
  } catch {
    /* No stack traces/debug output in production responses. */
    return fail(request, 500, "We could not complete that step. Please try again.");
  }
}

if (!existsSync("certs/cert.pem") || !existsSync("certs/key.pem")) throw Error("TLS certificates are required at certs/cert.pem and certs/key.pem.");
Bun.serve({
  port: PORT,
  tls: { cert: readFileSync("certs/cert.pem"), key: readFileSync("certs/key.pem") },
  fetch: handler,
});
