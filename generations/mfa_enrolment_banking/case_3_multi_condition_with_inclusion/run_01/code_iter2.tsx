
import { existsSync, readFileSync } from "node:fs";
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  pbkdf2Sync,
  randomBytes,
  randomInt,
  timingSafeEqual,
} from "node:crypto";

/*
  MFA Security Evaluation §§1–5:
  In-memory academic demonstration. Account state is server-side and is always
  reached through the authenticated account owner's session.
*/
const PORT = Number(process.env.PORT || 3000);
const SESSION_COOKIE = "mfa_session";
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CHALLENGE_MS = 10 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const RECOVERY_EXPIRY_MS = 365 * 24 * 60 * 60 * 1000;
const TOTP_PERIOD_MS = 30_000;
const encryptionKey = randomBytes(32);
const pepper = randomBytes(32);

type ProtectedValue = { iv: Buffer; tag: Buffer; data: Buffer };
type BackupCode = { salt: Buffer; hash: Buffer; used: boolean; expiresAt: number };
type Account = {
  id: string;
  email: string;
  mfaEnabled: boolean;
  otpSecret?: ProtectedValue;
  usedTotpSteps: Set<number>;
  backupCodes: BackupCode[];
  recoveryFailures: number;
  recoveryLockedUntil?: number;
};
type Session = {
  id: string;
  phase: "preauth" | "auth";
  userId?: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
  email?: string;
  identityCode?: string;
  identityExpires?: number;
  identityUsed?: boolean;
  identityFailures: number;
  identityLockedUntil?: number;
  enrollment?: {
    secret: ProtectedValue;
    failures: number;
    lockedUntil?: number;
    usedSteps: Set<number>;
  };
};

const sessions = new Map<string, Session>();
const accountsByEmail = new Map<string, Account>();
const accountsById = new Map<string, Account>();

function opaqueToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}
function encrypt(value: string): ProtectedValue {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return { iv, tag: cipher.getAuthTag(), data };
}
function decrypt(value: ProtectedValue) {
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, value.iv);
  decipher.setAuthTag(value.tag);
  return Buffer.concat([decipher.update(value.data), decipher.final()]).toString("utf8");
}
function protectedHash(value: string, salt = randomBytes(16)) {
  return { salt, hash: pbkdf2Sync(value, Buffer.concat([salt, pepper]), 210000, 32, "sha256") };
}
function hashesMatch(value: string, salt: Buffer, expected: Buffer) {
  const actual = pbkdf2Sync(value, Buffer.concat([salt, pepper]), 210000, 32, "sha256");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
function parseCookies(request: Request) {
  const cookies: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const at = part.indexOf("=");
    if (at > 0) cookies[part.slice(0, at).trim()] = part.slice(at + 1).trim();
  }
  return cookies;
}
function createSession(phase: "preauth" | "auth" = "preauth", userId?: string) {
  const now = Date.now();
  const session: Session = {
    id: opaqueToken(), phase, userId, csrf: opaqueToken(), createdAt: now, lastSeen: now,
    identityFailures: 0,
  };
  sessions.set(session.id, session);
  return session;
}
function validSession(request: Request) {
  const id = parseCookies(request)[SESSION_COOKIE];
  const session = id ? sessions.get(id) : undefined;
  if (!session) return undefined;
  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(session.id);
    return undefined;
  }
  session.lastSeen = now;
  return session;
}
function sessionCookie(session: Session) {
  return `${SESSION_COOKIE}=${session.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}
function clearCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}
function trustedOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    const u = new URL(origin);
    return u.protocol === "https:" && u.port === String(PORT) &&
      ["localhost", "127.0.0.1", "::1", "[::1]"].includes(u.hostname);
  } catch { return false; }
}
function commonHeaders(request: Request, nonce?: string) {
  const headers = new Headers({
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
  if (origin && trustedOrigin(request)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}
function json(request: Request, data: unknown, status = 200, cookie?: string) {
  const headers = commonHeaders(request);
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (cookie) headers.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers });
}
function errorResponse(request: Request, status = 400, message = "We could not complete that step. Please try again.") {
  return json(request, { ok: false, message }, status);
}
async function body(request: Request): Promise<Record<string, unknown> | undefined> {
  if (Number(request.headers.get("content-length") || "0") > 4096) return undefined;
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
  } catch { return undefined; }
}
function csrf(request: Request, session: Session) {
  if (!trustedOrigin(request)) return false;
  const token = request.headers.get("x-csrf-token");
  return !!token && token.length === session.csrf.length &&
    timingSafeEqual(Buffer.from(token), Buffer.from(session.csrf));
}

/* Security §1: account data is resolved only from the authenticated session. */
function ownedAccount(request: Request) {
  const session = validSession(request);
  if (!session || session.phase !== "auth" || !session.userId) return undefined;
  const account = accountsById.get(session.userId);
  if (!account) return undefined;
  return { session, account };
}
function accountForEmail(email: string) {
  let account = accountsByEmail.get(email);
  if (!account) {
    account = {
      id: opaqueToken(18), email, mfaEnabled: false, usedTotpSteps: new Set(),
      backupCodes: [], recoveryFailures: 0,
    };
    accountsByEmail.set(email, account);
    accountsById.set(account.id, account);
  }
  return account;
}
function createIdentityCode() {
  return String(randomInt(0, 1_000_000)).padStart(6, "0");
}
function base32Secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = randomBytes(20);
  let bits = 0, value = 0, out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(input: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
  const output: number[] = [];
  for (const char of input.replace(/=|\s/g, "")) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("invalid secret");
    value = (value << 5) | index; bits += 5;
    if (bits >= 8) { output.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(output);
}

/* Security §3 and task: RFC 6238-style HMAC-SHA1 TOTP, 30 second server step. */
function totp(secret: string, step: number) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  const number = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) | digest[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}
function currentTotp(secret: string) {
  return totp(secret, Math.floor(Date.now() / TOTP_PERIOD_MS));
}
function backupValue() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = randomBytes(12);
  let raw = "";
  for (const byte of bytes) raw += alphabet[byte % alphabet.length];
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
}
function issueBackupCodes(account: Account) {
  const plain = Array.from({ length: 8 }, backupValue);
  account.backupCodes = plain.map((code) => ({ ...protectedHash(code), used: false, expiresAt: Date.now() + RECOVERY_EXPIRY_MS }));
  return plain;
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Harbour Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#17263c;--muted:#526278;--blue:#075cc7;--blue2:#064b9f;--pale:#edf6ff;--line:#d5dfeb;--bg:#f5f8fc}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Verdana,Arial,sans-serif;letter-spacing:.035em;line-height:1.65;font-size:16px}
main{max-width:560px;margin:auto;min-height:100vh;background:#fff;padding:22px 18px 32px}.brand{font-weight:700;font-size:1.05rem;color:#064b9f}.brand span{font-size:1.35rem;margin-right:7px}h1{font-size:1.58rem;line-height:1.3;letter-spacing:.02em;margin:20px 0 8px}h2{font-size:1.2rem;line-height:1.35;margin:15px 0 8px}p{margin:7px 0 16px;color:var(--muted)}.steps{display:flex;gap:5px;margin:18px 0 24px}.step{height:8px;border-radius:8px;background:#dbe3ed;flex:1}.step.on{background:var(--blue)}
.card{border:1px solid var(--line);border-radius:14px;padding:16px;margin:16px 0}.hint{background:var(--pale);border-left:4px solid var(--blue);padding:12px 13px;border-radius:7px;color:#24445f;font-size:.92rem}.notice{padding:12px 13px;border-radius:8px;background:#eaf8f0;color:#105537;margin:14px 0}.error{padding:12px 13px;border-radius:8px;background:#fff0e8;color:#843900;margin:14px 0}
.label{font-weight:700;display:block;margin:16px 0 5px}input{width:100%;font:inherit;letter-spacing:.08em;border:2px solid #9aaabd;border-radius:9px;padding:13px;color:var(--ink)}input:focus{outline:3px solid #a9d0ff;border-color:var(--blue)}button{font:inherit;letter-spacing:.025em;border-radius:9px;border:0;padding:13px 16px;cursor:pointer;font-weight:700}button.primary{width:100%;background:var(--blue);color:#fff;margin-top:18px}button.primary:hover{background:var(--blue2)}button.secondary{background:#e8f0fa;color:#17436d;margin:8px 6px 0 0}button.link{padding:7px 0;background:transparent;color:var(--blue);text-decoration:underline;font-weight:600}.small{font-size:.88rem}
.secret{font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere;letter-spacing:.08em;background:#f4f7fa;padding:12px;border-radius:8px;color:#22384d}.codes{list-style:none;padding:0;margin:12px 0}.codes li{font-family:ui-monospace,Consolas,monospace;font-size:1.04rem;letter-spacing:.12em;padding:8px 4px;border-bottom:1px solid var(--line)}.qr{display:block;width:230px;max-width:100%;height:auto;margin:15px auto;border:8px solid white;image-rendering:pixelated}@media(max-width:370px){main{padding:17px 14px}body{font-size:15px}h1{font-size:1.4rem}}
</style></head>
<body><main id="app" aria-live="polite">Loading setup…</main>
<script nonce="${nonce}">
(()=>{
"use strict";
const app=document.getElementById("app");
const state={csrf:"",auth:false,mfa:false,view:"signin",email:"",identityMock:"",secret:"",uri:"",mockOtp:"",codes:[],notice:"",error:"",qr:false};
const views=new Set(["signin","identity","home","enrol","codes","recovery"]);
function el(tag,props={},...children){const n=document.createElement(tag);for(const [k,v] of Object.entries(props)){if(k==="class")n.className=v;else if(k==="text")n.textContent=v;else if(k.startsWith("on"))n.addEventListener(k.slice(2),v);else if(v!==false&&v!=null)n.setAttribute(k,String(v));}for(const c of children)n.append(c instanceof Node?c:document.createTextNode(String(c)));return n}
function testLog(message){console.log(message)}
async function api(path,method="GET",data){const o={method,credentials:"same-origin",headers:{}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=state.csrf;o.body=JSON.stringify(data||{})}try{const r=await fetch(path,o);const result=await r.json();if(r.status===401){state.auth=false;state.view="signin"}return result}catch{return{ok:false,message:"Connection problem. Please try again."}}}
function status(root){if(state.error)root.append(el("div",{class:"error",role:"alert",text:state.error}));if(state.notice)root.append(el("div",{class:"notice",text:state.notice}))}
function header(root,step){root.append(el("div",{class:"brand"},el("span",{text:"⚓"}),"Harbour Bank"));const s=el("div",{class:"steps","aria-label":"Setup progress"});for(let i=1;i<=4;i++)s.append(el("div",{class:"step "+(i<=step?"on":""),"aria-hidden":"true"}));root.append(s)}
function help(root){root.append(el("button",{class:"link",type:"button",onClick:()=>{state.notice="Help: Take as long as you need. You can retry this step without penalty.";state.error="";render()},text:"? Need a little help"}))}
function primary(root,text,fn){root.append(el("button",{class:"primary",type:"button",onClick:fn,text}))}
function input(label,type,attrs={}){const wrap=el("div"),id="field-"+Math.random().toString(36).slice(2);wrap.append(el("label",{class:"label",for:id,text:label}),el("input",{id,type,...attrs}));return wrap}
function render(){if(!views.has(state.view))state.view="signin";app.replaceChildren();const root=el("div");app.append(root);if(state.view==="signin")signin(root);if(state.view==="identity")identity(root);if(state.view==="home")home(root);if(state.view==="enrol")enrol(root);if(state.view==="codes")codes(root);if(state.view==="recovery")recovery(root)}
function signin(root){header(root,1);root.append(el("h1",{text:"Sign in to set up MFA"}),el("p",{text:"We will send one short identity code. This demo does not use a real email."}));status(root);const f=input("Email address","email",{autocomplete:"email",inputmode:"email",placeholder:"marcus@example.com"});f.querySelector("input").value=state.email;root.append(f,el("div",{class:"hint",text:"Example: marcus@example.com"}));primary(root,"Send identity code",async()=>{const email=f.querySelector("input").value.trim();if(!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)||email.length>120){state.error="Enter an email in this format: name@example.com.";render();return}const r=await api("/api/signin/request","POST",{email});if(!r.ok){state.error=r.message;render();return}state.email=email;state.identityMock=r.mockCode;testLog("Mock identity code delivered: "+r.mockCode);state.notice="A six-digit code is ready for this demo.";state.error="";state.view="identity";render()});help(root)}
function identity(root){header(root,1);root.append(el("h1",{text:"Check your identity"}),el("p",{text:"Enter the six-digit code we sent."}));status(root);if(state.identityMock)root.append(el("div",{class:"hint",text:"Demo test code: "+state.identityMock}));const f=input("Identity code","text",{inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"Example: 123456"});root.append(f,el("div",{class:"hint",text:"Take your time. You can request another code if you need one."}));primary(root,"Check code",async()=>{const code=f.querySelector("input").value.replace(/\\s/g,"");if(!/^\\d{6}$/.test(code)){state.error="Enter all 6 numbers, for example 123456.";render();return}const r=await api("/api/signin/verify","POST",{code});if(!r.ok){state.error=r.message;render();return}state.csrf=r.csrf;state.auth=true;state.mfa=r.mfa;state.identityMock="";state.error="";state.notice="Identity checked. Next, set up your authenticator.";state.view="home";render()});root.append(el("button",{class:"secondary",type:"button",onClick:()=>{state.view="signin";state.notice="You can request a new code.";state.error="";render()},text:"Request another code"}));help(root)}
function home(root){header(root,state.mfa?4:2);root.append(el("h1",{text:state.mfa?"MFA is set up":"Set up your authenticator"}),el("p",{text:state.mfa?"Your account has an extra sign-in check. Keep recovery codes somewhere safe.":"Use an authenticator app to get a short code when needed."}));status(root);if(!state.mfa){root.append(el("div",{class:"hint",text:"You can scan a QR code, or copy the setup secret instead."}));primary(root,"Set up authenticator",async()=>{const r=await api("/api/mfa/enroll","POST",{});if(!r.ok){state.error=r.message;render();return}state.secret=r.secret;state.uri=r.provisioningUri;state.mockOtp=r.mockOtp;testLog("Mock authenticator setup secret: "+r.secret);testLog("Mock authenticator OTP for verification: "+r.mockOtp);state.error="";state.notice="Setup secret ready. Choose the method that feels easiest.";state.view="enrol";render()})}else{root.append(el("div",{class:"notice",text:"Authenticator confirmed. Your next step is to save recovery codes."}));primary(root,"View recovery codes",()=>{state.view="codes";state.notice="";render()});root.append(el("button",{class:"secondary",type:"button",onClick:()=>{state.view="recovery";state.notice="";render()},text:"Test a recovery code"}))}root.append(el("button",{class:"link",type:"button",onClick:logout,text:"Sign out"}));help(root)}

/* QR Code Model 2 Version 6-L encoder: byte mode, Reed-Solomon correction, and mask selection. */
function qrBytes(text){return Array.from(new TextEncoder().encode(text))}
function gfMul(a,b){let p=0;while(b){if(b&1)p^=a;a=a&128?(a<<1)^285:a<<1;b>>=1}return p}
function rs(data,count){let gen=[1];for(let i=0;i<count;i++){const next=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=gfMul(gen[j],Math.pow(2,i)%255)}gen=next}const out=Array(count).fill(0);for(const d of data){const factor=d^out.shift();out.push(0);for(let j=0;j<count;j++)out[j]^=gfMul(gen[j+1],factor)}return out}
function qrMatrix(uri){
 const size=41,m=Array.from({length:size},()=>Array(size).fill(null));
 const put=(r,c,v)=>{if(r>=0&&c>=0&&r<size&&c<size)m[r][c]=v};
 function finder(r,c){for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)put(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4)))}
 finder(0,0);finder(size-7,0);finder(0,size-7);
 for(let i=8;i<size-8;i++){put(6,i,i%2===0);put(i,6,i%2===0)}
 function align(r,c){for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)put(r+y,c+x,Math.max(Math.abs(x),Math.abs(y))!==1)}
 align(34,34);put(size-8,8,true);
 for(let i=0;i<9;i++){if(m[i][8]===null)put(i,8,false);if(m[8][i]===null)put(8,i,false);if(m[size-1-i][8]===null)put(size-1-i,8,false);if(m[8][size-1-i]===null)put(8,size-1-i,false)}
 const bytes=qrBytes(uri),bits=[0,1,0,0];for(let i=7;i>=0;i--)bits.push((bytes.length>>i)&1);for(const b of bytes)for(let i=7;i>=0;i--)bits.push((b>>i)&1);for(let i=0;i<4&&bits.length<1088;i++)bits.push(0);while(bits.length%8)bits.push(0);
 const data=[];for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8).join(""),2));let pad=0;while(data.length<136)data.push(pad++%2?17:236);
 const blocks=[data.slice(0,68),data.slice(68,136)],ecs=blocks.map(b=>rs(b,18)),stream=[];for(let i=0;i<68;i++)for(const b of blocks)stream.push(b[i]);for(let i=0;i<18;i++)for(const e of ecs)stream.push(e[i]);
 const streamBits=[];for(const b of stream)for(let i=7;i>=0;i--)streamBits.push((b>>i)&1);
 function painted(mask){const a=m.map(row=>row.slice());let bit=0,up=true;for(let c=size-1;c>0;c-=2){if(c===6)c--;for(let z=0;z<size;z++){const r=up?size-1-z:z;for(let dx=0;dx<2;dx++){const x=c-dx;if(a[r][x]===null){const v=streamBits[bit++]||0;const k=[(r+x)%2===0,r%2===0,x%3===0,(r+x)%3===0,(Math.floor(r/2)+Math.floor(x/3))%2===0,(r*x)%2+(r*x)%3===0,((r*x)%2+(r*x)%3)%2===0,((r+x)%2+(r*x)%3)%2===0][mask];a[r][x]=!!(v^(k?1:0))}}up=!up}let value=(1<<3)|mask,b=value<<10;while(b.toString(2).length>=0x537.toString(2).length)b^=0x537<<(b.toString(2).length-0x537.toString(2).length);value=((value<<10)|b)^0x5412;for(let i=0;i<15;i++){const v=!!((value>>i)&1);if(i<6)a[i][8]=v;else if(i<8)a[i+1][8]=v;else a[size-15+i][8]=v;if(i<8)a[8][size-i-1]=v;else if(i<9)a[8][15-i]=v;else a[8][14-i]=v}return a}
 function penalty(a){let p=0;for(let r=0;r<size;r++)for(let c=0;c<size;c++){let same=0;for(let y=-1;y<=1;y++)for(let x=-1;x<=1;x++)if(x||y){const yy=r+y,xx=c+x;if(yy>=0&&xx>=0&&yy<size&&xx<size&&a[yy][xx]===a[r][c])same++}if(same>5)p+=3+same-5}return p}
 let best=painted(0),score=penalty(best);for(let i=1;i<8;i++){const trial=painted(i),n=penalty(trial);if(n<score){best=trial;score=n}}return best
}
function qr(uri){const matrix=qrMatrix(uri),svg=document.createElementNS("http://www.w3.org/2000/svg","svg");svg.setAttribute("class","qr");svg.setAttribute("viewBox","0 0 41 41");svg.setAttribute("role","img");svg.setAttribute("aria-label","QR code for authenticator setup");const bg=document.createElementNS(svg.namespaceURI,"rect");bg.setAttribute("width","41");bg.setAttribute("height","41");bg.setAttribute("fill","white");svg.append(bg);matrix.forEach((row,y)=>row.forEach((dark,x)=>{if(dark){const r=document.createElementNS(svg.namespaceURI,"rect");r.setAttribute("x",x);r.setAttribute("y",y);r.setAttribute("width","1");r.setAttribute("height","1");r.setAttribute("fill","#17263c");svg.append(r)}}));return svg}
function enrol(root){header(root,2);root.append(el("h1",{text:"Add the authenticator"}),el("p",{text:"In your authenticator app, add an account. Scan the QR code or use the copied secret."}));status(root);root.append(el("button",{class:"secondary",type:"button",onClick:()=>{state.qr=!state.qr;render()},text:state.qr?"Hide QR code":"Show QR code"}));if(state.qr)root.append(qr(state.uri));root.append(el("h2",{text:"Manual setup secret"}),el("div",{class:"secret",text:state.secret}),el("button",{class:"secondary",type:"button",onClick:()=>copyText(state.secret,"The setup secret was copied."),text:"Copy setup secret"}),el("div",{class:"hint",text:"Demo test code: "+state.mockOtp+". It is accepted in the current or neighbouring 30-second step."}));const f=input("Authenticator code","text",{inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"Example: 123456"});root.append(f);primary(root,"Confirm authenticator",async()=>{const otp=f.querySelector("input").value.replace(/\\s/g,"");if(!/^\\d{6}$/.test(otp)){state.error="Enter the 6 numbers from your authenticator, for example 123456.";render();return}const r=await api("/api/mfa/confirm","POST",{otp});if(!r.ok){state.error=r.message;render();return}state.mfa=true;state.secret="";state.uri="";state.mockOtp="";state.error="";state.notice="Authenticator confirmed. Now save your recovery codes.";state.view="codes";render()});root.append(el("button",{class:"link",type:"button",onClick:()=>{state.view="home";state.error="";render()},text:"Back"}));help(root)}
function codes(root){header(root,4);root.append(el("h1",{text:"Save recovery codes"}),el("p",{text:"Each code works once if you cannot use your authenticator. Save them somewhere private."}));status(root);if(state.codes.length){const list=el("ul",{class:"codes","aria-label":"New recovery codes"});state.codes.forEach(c=>list.append(el("li",{text:c})));root.append(list,el("div",{class:"hint",text:"These are shown once. Copy or download them before leaving this screen."}),el("button",{class:"secondary",type:"button",onClick:()=>copyText(state.codes.join("\\n"),"Recovery codes copied."),text:"Copy all codes"}),el("button",{class:"secondary",type:"button",onClick:downloadCodes,text:"Download codes"}));primary(root,"I saved my codes",()=>{state.codes=[];state.notice="Recovery codes are ready when you need them.";state.view="home";render()})}else{root.append(el("div",{class:"hint",text:"Choose one action to make a new set. Any older recovery codes will stop working."}));primary(root,"Create recovery codes",generateCodes)}root.append(el("button",{class:"secondary",type:"button",onClick:()=>{state.view="recovery";state.error="";state.notice="";render()},text:"Use a recovery code"}));help(root)}
async function generateCodes(){const r=await api("/api/mfa/backup/regenerate","POST",{});if(!r.ok){state.error=r.message;render();return}state.codes=r.codes;testLog("Mock backup recovery codes: "+r.codes.join(", "));state.error="";state.notice="New recovery codes created. Save them now.";render()}
function recovery(root){header(root,4);root.append(el("h1",{text:"Use a recovery code"}),el("p",{text:"Enter one unused recovery code. It will be used up after it works."}));status(root);const f=input("Recovery code","text",{autocomplete:"one-time-code",autocapitalize:"characters",placeholder:"Example: ABCD-EFGH-JKLM"});root.append(f,el("div",{class:"hint",text:"Use the dashes if they are shown. You can try another saved code if one was already used."}));primary(root,"Check recovery code",async()=>{const code=f.querySelector("input").value.trim().toUpperCase();if(!/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(code)){state.error="Use this format: ABCD-EFGH-JKLM.";render();return}const r=await api("/api/mfa/recovery/verify","POST",{code});if(!r.ok){state.error=r.message;render();return}state.error="";state.notice="Recovery code accepted and used. Your MFA remains active.";state.view="home";render()});root.append(el("button",{class:"link",type:"button",onClick:()=>{state.view="home";state.error="";render()},text:"Back"}));help(root)}
async function copyText(value,message){try{await navigator.clipboard.writeText(value);state.notice=message}catch{state.notice="Select the code and copy it using your browser controls."}state.error="";render()}
function downloadCodes(){const content="Harbour Bank recovery codes\\nKeep these private. Each code works once.\\n\\n"+state.codes.join("\\n")+"\\n";const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([content],{type:"text/plain"}));a.download="harbour-recovery-codes.txt";a.click();setTimeout(()=>URL.revokeObjectURL(a.href),500);state.notice="Recovery codes downloaded.";render()}
async function logout(){await api("/api/logout","POST",{});state.auth=false;state.mfa=false;state.secret="";state.codes=[];state.view="signin";state.notice="Signed out.";state.error="";render()}
async function boot(){const r=await api("/api/session");if(r.ok){state.csrf=r.csrf;state.auth=r.auth;state.mfa=r.mfa;if(r.auth)state.view="home"}else state.error="Please refresh the page.";render()}boot()
})();
</script></body></html>`;
}

async function handler(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      if (!trustedOrigin(request)) return errorResponse(request, 403, "This request is not allowed.");
      const headers = commonHeaders(request);
      headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
      return new Response(null, { status: 204, headers });
    }
    if (url.pathname === "/" && request.method === "GET") {
      const nonce = opaqueToken(18), headers = commonHeaders(request, nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { headers });
    }
    if (!url.pathname.startsWith("/api/")) return errorResponse(request, 404, "Page not found.");

    if (url.pathname === "/api/session" && request.method === "GET") {
      let session = validSession(request), cookie: string | undefined;
      if (!session) { session = createSession(); cookie = sessionCookie(session); }
      const account = session.userId ? accountsById.get(session.userId) : undefined;
      return json(request, { ok: true, csrf: session.csrf, auth: !!account && session.phase === "auth", mfa: !!account?.mfaEnabled }, 200, cookie);
    }
    if (url.pathname === "/api/signin/request" && request.method === "POST") {
      let session = validSession(request), cookie: string | undefined;
      if (!session) { session = createSession(); cookie = sessionCookie(session); }
      if (!csrf(request, session)) return errorResponse(request, 403, "Your page check expired. Refresh the page and try again.");
      const data = await body(request);
      const email = typeof data?.email === "string" ? data.email.trim().toLowerCase() : "";
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(email) || email.length > 120) return errorResponse(request, 400, "Enter an email in this format: name@example.com.");
      session.email = email; session.identityCode = createIdentityCode(); session.identityExpires = Date.now() + CHALLENGE_MS;
      session.identityUsed = false; session.identityFailures = 0; session.identityLockedUntil = undefined;
      return json(request, { ok: true, mockCode: session.identityCode }, 200, cookie);
    }
    if (url.pathname === "/api/signin/verify" && request.method === "POST") {
      const session = validSession(request);
      if (!session || !csrf(request, session)) return errorResponse(request, 403, "Your page check expired. Refresh the page and try again.");
      const code = typeof (await body(request))?.code === "string" ? (await body(request))?.code : "";
      const now = Date.now();
      if (session.identityLockedUntil && now < session.identityLockedUntil) return errorResponse(request, 429, "Too many incorrect codes. Wait a few minutes, then request a new code.");
      if (!/^\d{6}$/.test(code)) return errorResponse(request, 400, "Enter all 6 numbers from the code.");
      if (!session.identityCode || session.identityUsed || !session.identityExpires || now > session.identityExpires) return errorResponse(request, 400, "That code is no longer available. Request a new code and try again.");
      if (!timingSafeEqual(Buffer.from(code), Buffer.from(session.identityCode))) {
        session.identityFailures++; if (session.identityFailures >= 5) session.identityLockedUntil = now + LOCK_MS;
        return errorResponse(request, 400, "That code did not match. Check the 6 numbers or request another code.");
      }
      const account = accountForEmail(session.email!);
      session.identityUsed = true; sessions.delete(session.id);
      const authenticated = createSession("auth", account.id);
      return json(request, { ok: true, csrf: authenticated.csrf, mfa: account.mfaEnabled }, 200, sessionCookie(authenticated));
    }
    if (url.pathname === "/api/logout" && request.method === "POST") {
      const session = validSession(request);
      if (!session || !csrf(request, session)) return errorResponse(request, 403, "Your page check expired. Refresh the page and try again.");
      sessions.delete(session.id);
      return json(request, { ok: true }, 200, clearCookie());
    }
    if (url.pathname === "/api/mfa/enroll" && request.method === "POST") {
      const owner = ownedAccount(request);
      if (!owner) return errorResponse(request, 401, "Please sign in again to continue.");
      if (!csrf(request, owner.session)) return errorResponse(request, 403, "Your page check expired. Refresh the page and try again.");
      const secret = base32Secret();
      owner.session.enrollment = { secret: encrypt(secret), failures: 0, usedSteps: new Set() };
      const label = encodeURIComponent(`Harbour Bank:${owner.account.email}`);
      return json(request, { ok: true, secret, provisioningUri: `otpauth://totp/${label}?secret=${secret}&issuer=Harbour%20Bank&algorithm=SHA1&digits=6&period=30`, mockOtp: currentTotp(secret) });
    }
    if (url.pathname === "/api/mfa/confirm" && request.method === "POST") {
      const owner = ownedAccount(request);
      if (!owner) return errorResponse(request, 401, "Please sign in again to continue.");
      if (!csrf(request, owner.session)) return errorResponse(request, 403, "Your page check expired. Refresh the page and try again.");
      const data = await body(request), otp = typeof data?.otp === "string" ? data.otp : "";
      const enrollment = owner.session.enrollment, now = Date.now();
      if (!enrollment) return errorResponse(request, 400, "Start authenticator setup first, then enter its code.");
      if (enrollment.lockedUntil && now < enrollment.lockedUntil) return errorResponse(request, 429, "Too many incorrect codes. Wait a few minutes, then start setup again.");
      if (!/^\d{6}$/.test(otp)) return errorResponse(request, 400, "Enter the 6 numbers from your authenticator.");
      const secret = decrypt(enrollment.secret), step = Math.floor(now / TOTP_PERIOD_MS);
      let matchedStep: number | undefined;
      for (const candidate of [step - 1, step, step + 1]) {
        if (totp(secret, candidate) === otp && !enrollment.usedSteps.has(candidate)) { matchedStep = candidate; break; }
      }
      if (matchedStep === undefined) {
        enrollment.failures++; if (enrollment.failures >= 5) enrollment.lockedUntil = now + LOCK_MS;
        return errorResponse(request, 400, "That authenticator code is expired, already used, or does not match. Get a new code in your app and try again.");
      }
      enrollment.usedSteps.add(matchedStep);
      owner.account.otpSecret = enrollment.secret;
      owner.account.usedTotpSteps.add(matchedStep);
      owner.account.mfaEnabled = true;
      owner.session.enrollment = undefined;
      return json(request, { ok: true });
    }
    if (url.pathname === "/api/mfa/backup/regenerate" && request.method === "POST") {
      const owner = ownedAccount(request);
      if (!owner) return errorResponse(request, 401, "Please sign in again to continue.");
      if (!csrf(request, owner.session)) return errorResponse(request, 403, "Your page check expired. Refresh the page and try again.");
      if (!owner.account.mfaEnabled) return errorResponse(request, 400, "Confirm your authenticator before creating recovery codes.");
      return json(request, { ok: true, codes: issueBackupCodes(owner.account) });
    }
    if (url.pathname === "/api/mfa/recovery/verify" && request.method === "POST") {
      const owner = ownedAccount(request);
      if (!owner) return errorResponse(request, 401, "Please sign in again to continue.");
      if (!csrf(request, owner.session)) return errorResponse(request, 403, "Your page check expired. Refresh the page and try again.");
      const data = await body(request), code = typeof data?.code === "string" ? data.code.trim().toUpperCase() : "", now = Date.now();
      const account = owner.account;
      if (account.recoveryLockedUntil && now < account.recoveryLockedUntil) return errorResponse(request, 429, "Too many incorrect codes. Wait a few minutes, then try a saved code.");
      if (!/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(code)) return errorResponse(request, 400, "Use this format: ABCD-EFGH-JKLM.");
      const match = account.backupCodes.find(c => !c.used && c.expiresAt > now && hashesMatch(code, c.salt, c.hash));
      if (!match) {
        account.recoveryFailures++; if (account.recoveryFailures >= 5) account.recoveryLockedUntil = now + LOCK_MS;
        return errorResponse(request, 400, "That recovery code is unavailable. Try another saved, unused code or create new codes.");
      }
      match.used = true; account.recoveryFailures = 0;
      return json(request, { ok: true });
    }
    return errorResponse(request, 404, "Page not found.");
  } catch {
    return errorResponse(request, 500, "We could not complete that step. Please try again.");
  }
}

if (!existsSync("certs/cert.pem") || !existsSync("certs/key.pem")) {
  throw new Error("TLS certificates are required at certs/cert.pem and certs/key.pem.");
}
Bun.serve({
  port: PORT,
  tls: { cert: readFileSync("certs/cert.pem"), key: readFileSync("certs/key.pem") },
  fetch: handler,
});
