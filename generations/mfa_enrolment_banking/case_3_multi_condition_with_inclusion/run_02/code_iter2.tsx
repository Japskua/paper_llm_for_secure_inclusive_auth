
import { } from "bun";

/*
  MFA Enrolment System
  Single Bun HTTPS server and single-page client.
  Run: bun app.ts
  TLS certificates are expected at certs/cert.pem and certs/key.pem.
*/

const PORT = 3000;
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_PERIOD_SECONDS = 300;
const OTP_WINDOW_MS = OTP_PERIOD_SECONDS * 1000;
const OTP_DIGITS = 6;
const OTP_ALGORITHM = "SHA1";
const LOCK_MS = 5 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const encoder = new TextEncoder();

type Session = {
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
  identityVerified: boolean;
};

type EncryptedValue = {
  nonce: string;
  cipher: string;
};

type BackupCode = {
  salt: string;
  hash: string;
  used: boolean;
};

type Account = {
  id: string;
  email: string;
  password: string;
  pendingSecret?: EncryptedValue;
  activeSecret?: EncryptedValue;
  otpUsedSlots: Set<number>;
  otpFailures: number;
  otpLockedUntil: number;
  backupCodes: BackupCode[];
  backupFailures: number;
  backupLockedUntil: number;
  identityFailures: number;
  identityLockedUntil: number;
};

const sessions = new Map<string, Session>();

/* Security requirement 3: a process-protected AES key encrypts OTP seeds at rest. */
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt", "decrypt"],
);

const account: Account = {
  id: "account-marcus-001",
  email: "marcus@example.com",
  password: "River!47",
  otpUsedSlots: new Set(),
  otpFailures: 0,
  otpLockedUntil: 0,
  backupCodes: [],
  backupFailures: 0,
  backupLockedUntil: 0,
  identityFailures: 0,
  identityLockedUntil: 0,
};

function bytes(length: number): Uint8Array {
  const result = new Uint8Array(length);
  crypto.getRandomValues(result);
  return result;
}

function base64url(data: Uint8Array | ArrayBuffer): string {
  const values = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
  let binary = "";
  for (const value of values) binary += String.fromCharCode(value);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function randomToken(length = 32): string {
  return base64url(bytes(length));
}

function base32(data: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let output = "";
  let value = 0;
  let bits = 0;
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function parseCookies(request: Request): Record<string, string> {
  const raw = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const position = part.indexOf("=");
    if (position > 0) result[part.slice(0, position).trim()] = part.slice(position + 1).trim();
  }
  return result;
}

function cookie(value: string, maxAge?: number): string {
  const age = maxAge === undefined ? "" : `; Max-Age=${maxAge}`;
  /* Security requirements 1, 2, 5: secure HttpOnly SameSite session cookie. */
  return `mfa_session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict${age}`;
}

function isTrustedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  const trusted = new Set([
    "https://localhost:3000",
    "https://127.0.0.1:3000",
    "https://[::1]:3000",
  ]);
  return !!origin && trusted.has(origin);
}

function headers(nonce?: string, request?: Request): Headers {
  const result = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    /* Security requirement 2: restrictive browser hardening headers. */
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
  });
  const origin = request?.headers.get("origin");
  if (origin && isTrustedOrigin(request!)) {
    result.set("Access-Control-Allow-Origin", origin);
    result.set("Access-Control-Allow-Credentials", "true");
    result.set("Vary", "Origin");
  }
  return result;
}

function json(data: unknown, status = 200, request?: Request, extra?: HeadersInit): Response {
  const resultHeaders = headers(undefined, request);
  if (extra) for (const [key, value] of new Headers(extra)) resultHeaders.set(key, value);
  return new Response(JSON.stringify(data), { status, headers: resultHeaders });
}

function genericError(status: number, request?: Request): Response {
  /* Security requirement 2: no debug details or stack traces are returned. */
  return json({ ok: false, message: "We could not complete that request. Please try again." }, status, request);
}

function sessionFor(request: Request): { id: string; session: Session } | null {
  const id = parseCookies(request).mfa_session;
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeenAt > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastSeenAt = now;
  return { id, session };
}

/* Security requirement 1: every MFA API route calls this authorization guard. */
function authorized(request: Request): { id: string; session: Session } | Response {
  const found = sessionFor(request);
  if (!found || found.session.userId !== account.id) {
    return json({ ok: false, message: "Please sign in to continue." }, 401, request);
  }
  return found;
}

/* Security requirement 1: anti-CSRF token plus trusted same-origin check on mutations. */
function csrfAuthorized(request: Request): { id: string; session: Session } | Response {
  const found = authorized(request);
  if (found instanceof Response) return found;
  if (!isTrustedOrigin(request) || request.headers.get("x-csrf-token") !== found.session.csrf) {
    return json({ ok: false, message: "This page needs to be refreshed before continuing." }, 403, request);
  }
  return found;
}

async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function text(value: unknown, max: number): string | null {
  return typeof value === "string" && value.length <= max ? value.trim() : null;
}

async function encryptSecret(secret: string): Promise<EncryptedValue> {
  const nonce = bytes(12);
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    encryptionKey,
    encoder.encode(secret),
  );
  return { nonce: base64url(nonce), cipher: base64url(cipher) };
}

function fromBase64url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
  const raw = atob(padded);
  return Uint8Array.from(raw, char => char.charCodeAt(0));
}

async function decryptSecret(value: EncryptedValue): Promise<string> {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64url(value.nonce) },
    encryptionKey,
    fromBase64url(value.cipher),
  );
  return new TextDecoder().decode(plain);
}

function decodeBase32(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = value.toUpperCase().replaceAll("=", "").replaceAll(/\s/g, "");
  let bits = 0;
  let buffer = 0;
  const output: number[] = [];
  for (const char of clean) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("Invalid base32");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

/*
 Security requirement 5: RFC 6238 TOTP using HMAC-SHA-1 and dynamic truncation.
 The provisioning URI explicitly declares this algorithm, six digits, and five-minute period.
*/
async function otpFor(secret: string, slot: number): Promise<string> {
  const counter = new Uint8Array(8);
  let value = BigInt(Math.max(0, slot));
  for (let index = 7; index >= 0; index--) {
    counter[index] = Number(value & 255n);
    value >>= 8n;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = signature[signature.length - 1] & 15;
  const binary = ((signature[offset] & 127) << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];
  return String(binary % (10 ** OTP_DIGITS)).padStart(OTP_DIGITS, "0");
}

async function hashRecovery(code: string, salt: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveBits"]);
  const output = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: encoder.encode(salt), iterations: 100_000 },
    key,
    256,
  );
  return base64url(output);
}

function makeRecoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const raw = bytes(10);
  let code = "";
  for (let i = 0; i < 10; i++) {
    if (i === 5) code += "-";
    code += alphabet[raw[i] % alphabet.length];
  }
  return code;
}

async function createBackupCodes(): Promise<string[]> {
  const visible: string[] = [];
  const hashed: BackupCode[] = [];
  for (let i = 0; i < 8; i++) {
    const code = makeRecoveryCode();
    const salt = randomToken(16);
    visible.push(code);
    hashed.push({ salt, hash: await hashRecovery(code, salt), used: false });
  }
  account.backupCodes = hashed;
  return visible;
}

function html(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172331;--muted:#526273;--blue:#075ca8;--blue2:#03457f;--paper:#fff;--wash:#edf5fa;--line:#cbd8e3;--good:#126b43;--bad:#a32727}
*{box-sizing:border-box}body{margin:0;background:var(--wash);color:var(--ink);font-family:Verdana,Arial,sans-serif;letter-spacing:.035em;line-height:1.62;font-size:16px}main{max-width:560px;min-height:100vh;margin:auto;background:var(--paper);padding:22px 20px 38px}header{border-bottom:2px solid var(--line);padding-bottom:15px;margin-bottom:24px}.brand{font-weight:700;color:var(--blue);font-size:1.07rem}.step{color:var(--muted);font-size:.9rem;margin-top:9px}h1{font-size:1.65rem;line-height:1.26;letter-spacing:.02em;margin:0 0 15px}h2{font-size:1.16rem;line-height:1.35;margin:23px 0 9px}p{margin:0 0 15px}.card{border:1px solid var(--line);border-radius:12px;padding:18px;margin:16px 0;background:#fff}.notice{background:#eef8f2;border-left:5px solid var(--good);padding:13px 14px;margin:15px 0}.error{background:#fff0f0;border-left:5px solid var(--bad);padding:13px 14px;margin:15px 0}.hint{background:#f4f8fb;padding:13px;border-radius:8px;color:#33495e;font-size:.94rem}label{display:block;font-weight:700;margin:18px 0 6px}input{width:100%;min-height:51px;border:2px solid #8da1b4;border-radius:8px;padding:10px 12px;font:inherit;letter-spacing:.07em;color:var(--ink)}input:focus{outline:3px solid #8bc7ec;outline-offset:2px;border-color:var(--blue)}button{width:100%;min-height:53px;border:0;border-radius:8px;background:var(--blue);color:#fff;font:700 1rem Verdana,Arial,sans-serif;letter-spacing:.035em;padding:12px 14px;cursor:pointer;margin-top:21px}button:hover{background:var(--blue2)}button.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue);margin-top:12px}.smalllink{background:none;border:0;color:var(--blue);text-decoration:underline;width:auto;min-height:auto;padding:4px;margin:12px 0 0;font:inherit;cursor:pointer}.code{font-family:ui-monospace,Consolas,monospace;letter-spacing:.11em;word-break:break-all;background:#f4f8fb;border:1px solid var(--line);border-radius:8px;padding:12px;margin:10px 0}.codes{font-family:ui-monospace,Consolas,monospace;letter-spacing:.1em;line-height:2;background:#f4f8fb;padding:13px;border-radius:8px;white-space:pre-wrap}.qr{display:block;width:225px;height:225px;border:10px solid white;image-rendering:pixelated;margin:14px auto}.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}@media(max-width:380px){main{padding:18px 15px}body{font-size:15px}h1{font-size:1.45rem}.qr{width:205px;height:205px}}
</style>
</head>
<body><main id="app" aria-live="polite">Loading securely…</main>
<script nonce="${nonce}">
(() => {
"use strict";
/* Inclusivity requirements: short plain text, clear stages, no timers/motion, generous mobile spacing. */
const app=document.getElementById("app");
let csrf="", provision=null, recoveryCodes=null;
function log(message){console.log(message);}
function el(tag,props={},children=[]){
  const node=document.createElement(tag);
  for(const [k,v] of Object.entries(props)){
    if(k==="className")node.className=v;
    else if(k==="text")node.textContent=v;
    else if(k.startsWith("on")&&typeof v==="function")node.addEventListener(k.slice(2).toLowerCase(),v);
    else node.setAttribute(k,String(v));
  }
  for(const child of children)node.append(child);
  return node;
}
function page(step,title){app.replaceChildren();const header=el("header",{},[el("div",{className:"brand",text:"Northstar Bank"}),el("div",{className:"step",text:"MFA set-up · Step "+step+" of 4"})]);app.append(header,el("h1",{text:title}));}
function message(text,kind="notice"){return el("div",{className:kind,text,role:"status"});}
function help(){return el("div",{className:"hint"},[el("strong",{text:"Need help? "}),document.createTextNode("You can pause here. Nothing will disappear while you read.")]);}
async function api(path,method="GET",data){
  const options={method,headers:{}};
  if(method!=="GET"){options.headers["Content-Type"]="application/json";options.headers["X-CSRF-Token"]=csrf;options.body=JSON.stringify(data||{});}
  let r;
  try{r=await fetch(path,options);}catch{return {ok:false,message:"Connection problem. Please try again."};}
  const value=await r.json().catch(()=>({ok:false,message:"We could not complete that request."}));
  if(r.status===401)signIn(value.message);
  return value;
}
function primary(text,fn){return el("button",{type:"button",text,onClick:fn});}
function copy(value,button){navigator.clipboard?.writeText(value).then(()=>{button.textContent="Copied";}).catch(()=>{button.textContent="Select the value above to copy";});}
function signIn(error){
  page("1","Sign in");
  app.append(el("p",{text:"Use your bank sign-in details. This demo keeps your sign-in private."}));
  if(error)app.append(message(error,"error"));
  const form=el("form");
  const email=el("input",{id:"email",type:"email",autocomplete:"username",inputmode:"email",placeholder:"name@example.com"});
  const password=el("input",{id:"password",type:"password",autocomplete:"current-password",placeholder:"Your password"});
  const submit=async event=>{
    event.preventDefault();
    const result=await api("/api/signin","POST",{email:email.value,password:password.value});
    if(!result.ok)return signIn(result.message);
    csrf=result.csrf;
    log("Mock sign-in completed. A secure server session was created.");
    identity();
  };
  form.addEventListener("submit",submit);
  form.append(el("label",{for:"email",text:"Email"}),email,el("p",{className:"hint",text:"Example: marcus@example.com"}),el("label",{for:"password",text:"Password"}),password,primary("Sign in",submit));
  app.append(form,help(),el("p",{className:"hint",text:"Demo sign-in: marcus@example.com and River!47"}));
}
function identity(error){
  page("2","Check it is you");
  app.append(el("p",{text:"We need one quick identity check before MFA set-up."}));
  if(error)app.append(message(error,"error"));
  const input=el("input",{type:"text",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"246810","aria-describedby":"identity-example"});
  app.append(el("label",{for:"identity-code",text:"Identity check code"}));
  input.id="identity-code";
  app.append(input,el("p",{id:"identity-example",className:"hint",text:"Example: 246810"}),primary("Confirm identity",async()=>{
    const result=await api("/api/identity","POST",{code:input.value});
    if(!result.ok)return identity(result.message);
    log("Mock identity check completed.");
    setup();
  }),help());
}
function setup(error){
  page("3","Set up your authenticator");
  app.append(el("p",{text:"Open your authenticator app. You can scan the square or copy the setup value."}));
  if(error)app.append(message(error,"error"));
  app.append(el("div",{className:"card"},[el("div",{text:"📱 Choose “add account” in your authenticator app."}),el("div",{text:"▣ Scan the square on the next screen."})]),primary("Show setup options",async()=>{
    const result=await api("/api/mfa/provision","POST",{});
    if(!result.ok)return setup(result.message);
    provision=result;
    /* Required test output: secrets and mock OTPs are only in browser DevTools console, never rendered. */
    log("Test provisioning value: "+result.secret);
    log("Test authenticator code: "+result.testOtp);
    provisionScreen();
  }),help());
}

/* Standards-compliant QR Code Model 2 encoder: Version 7, error correction level L, byte mode. */
function drawQR(value){
  const utf8=new TextEncoder().encode(value);
  const version=7,size=45,dataCapacity=156,blockCount=2,dataPerBlock=78,eccPerBlock=20;
  if(utf8.length>dataCapacity-2)throw new Error("Setup value is too long for the QR code.");
  const data=[];
  const pushBits=(number,length)=>{for(let i=length-1;i>=0;i--)data.push((number>>>i)&1);};
  pushBits(4,4);pushBits(utf8.length,8);for(const byte of utf8)pushBits(byte,8);
  for(let i=0;i<Math.min(4,dataCapacity*8-data.length);i++)data.push(0);
  while(data.length%8)data.push(0);
  const codewords=[];for(let i=0;i<data.length;i+=8){let n=0;for(let j=0;j<8;j++)n=(n<<1)|data[i+j];codewords.push(n);}
  for(let pad=0;codewords.length<dataCapacity;pad++)codewords.push(pad%2?0x11:0xec);
  const multiply=(a,b)=>{let out=0;while(b){if(b&1)out^=a;a=(a<<1)^((a&128)?0x11d:0);b>>>=1;}return out;};
  const divisor=[1];for(let i=0;i<eccPerBlock;i++){const next=new Array(divisor.length+1).fill(0);for(let j=0;j<divisor.length;j++){next[j]^=divisor[j];next[j+1]^=multiply(divisor[j],1<<i);}divisor.splice(0,divisor.length,...next);}
  const remainder=block=>{const rem=new Array(eccPerBlock).fill(0);for(const byte of block){const factor=byte^rem.shift();rem.push(0);for(let i=0;i<eccPerBlock;i++)rem[i]^=multiply(divisor[i+1],factor);}return rem;};
  const blocks=[];for(let i=0;i<blockCount;i++)blocks.push(codewords.slice(i*dataPerBlock,(i+1)*dataPerBlock));
  const ecc=blocks.map(remainder), stream=[];
  for(let i=0;i<dataPerBlock;i++)for(const block of blocks)stream.push(block[i]);
  for(let i=0;i<eccPerBlock;i++)for(const block of ecc)stream.push(block[i]);
  const modules=Array.from({length:size},()=>Array(size).fill(null));
  const set=(x,y,v)=>{if(x>=0&&y>=0&&x<size&&y<size)modules[y][x]=v;};
  const finder=(cx,cy)=>{for(let dy=-4;dy<=4;dy++)for(let dx=-4;dx<=4;dx++){const d=Math.max(Math.abs(dx),Math.abs(dy));set(cx+dx,cy+dy,d!==2&&d!==4);}};
  finder(3,3);finder(size-4,3);finder(3,size-4);
  for(const y of [6,22,38])for(const x of [6,22,38]){if((x===6&&y===6)||(x===38&&y===6)||(x===6&&y===38))continue;for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++){const d=Math.max(Math.abs(dx),Math.abs(dy));set(x+dx,y+dy,d!==1);}}
  for(let i=8;i<size-8;i++){if(modules[6][i]===null)set(i,6,i%2===0);if(modules[i][6]===null)set(6,i,i%2===0);}
  const reserve=(x,y)=>{if(modules[y][x]===null)modules[y][x]=false;};
  for(let i=0;i<=5;i++){reserve(8,i);reserve(i,8);}reserve(8,7);reserve(8,8);reserve(7,8);
  for(let i=9;i<=14;i++){reserve(8,size-15+i);reserve(14-i,8);}for(let i=0;i<8;i++)reserve(size-1-i,8);
  for(let i=0;i<18;i++){reserve(size-11+i%3,Math.floor(i/3));reserve(Math.floor(i/3),size-11+i%3);}
  const dataCells=[];let upward=true;
  for(let right=size-1;right>=1;right-=2){if(right===6)right--;for(let offset=0;offset<size;offset++){const y=upward?size-1-offset:offset;for(let x=right;x>=right-1;x--)if(modules[y][x]===null)dataCells.push([x,y]);}upward=!upward;}
  for(let i=0;i<dataCells.length;i++){const pair=dataCells[i];const bit=i<stream.length*8?((stream[i>>>3]>>>(7-(i&7)))&1):0;const x=pair[0],y=pair[1];modules[y][x]=Boolean(bit^((x+y)%2===0));}
  const formatData=(1<<3)|0;let format=formatData<<10;const bchMod=0x537;while((format.toString(2).length)>=11){format^=bchMod<<(format.toString(2).length-11);}format=((formatData<<10)|format)^0x5412;
  const fbit=i=>Boolean((format>>>i)&1);
  for(let i=0;i<=5;i++)set(8,i,fbit(i));set(8,7,fbit(6));set(8,8,fbit(7));set(7,8,fbit(8));
  for(let i=9;i<=14;i++)set(14-i,8,fbit(i));for(let i=0;i<8;i++)set(size-1-i,8,fbit(i));for(let i=8;i<=14;i++)set(8,size-15+i,fbit(i));
  set(8,size-8,true);
  let versionBits=version<<12;const versionPoly=0x1f25;while(versionBits.toString(2).length>=13)versionBits^=versionPoly<<(versionBits.toString(2).length-13);versionBits=(version<<12)|versionBits;
  for(let i=0;i<18;i++){const bit=Boolean((versionBits>>>i)&1);set(size-11+i%3,Math.floor(i/3),bit);set(Math.floor(i/3),size-11+i%3,bit);}
  const canvas=el("canvas",{className:"qr",width:String(size*5),height:String(size*5),"aria-label":"Authenticator provisioning QR code"});
  const context=canvas.getContext("2d");context.fillStyle="#fff";context.fillRect(0,0,size*5,size*5);context.fillStyle="#111";
  for(let y=0;y<size;y++)for(let x=0;x<size;x++)if(modules[y][x])context.fillRect(x*5,y*5,5,5);
  return canvas;
}
function provisionScreen(){
  page("3","Add this account");
  app.append(el("p",{text:"Scan this code in your authenticator app. If scanning is difficult, copy the setup value instead."}),drawQR(provision.uri),el("h2",{text:"Manual setup value"}),el("div",{className:"code",text:provision.secret}));
  const cp=el("button",{className:"secondary",type:"button",text:"Copy setup value",onClick:()=>copy(provision.secret,cp)});
  app.append(cp,primary("I have added it",verify),help());
}
function verify(error){
  page("4","Enter the 6-digit code");
  app.append(el("p",{text:"Your authenticator app now shows a 6-digit code. Take your time."}));
  if(error)app.append(message(error,"error"));
  const input=el("input",{type:"text",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"123456"});
  app.append(el("label",{for:"otp",text:"Authenticator code"}));
  input.id="otp";
  app.append(input,el("p",{className:"hint",text:"Example: 123456"}),primary("Verify code",async()=>{
    const result=await api("/api/mfa/verify","POST",{otp:input.value});
    if(!result.ok)return verify(result.message);
    recoveryCodes=result.codes;
    log("Test backup recovery codes: "+result.codes.join(", "));
    backups();
  }),el("button",{className:"smalllink",type:"button",text:"Show setup options again",onClick:provisionScreen}),help());
}
function backups(){
  page("4","Save your backup codes");
  app.append(message("Authenticator set up. Save these backup codes somewhere safe. Each one works once."));
  const value=recoveryCodes.join("\\n");
  app.append(el("div",{className:"codes",text:value}));
  const cp=el("button",{className:"secondary",type:"button",text:"Copy all backup codes",onClick:()=>copy(value,cp)});
  const dl=el("button",{className:"secondary",type:"button",text:"Download a text copy",onClick:()=>{
    const url=URL.createObjectURL(new Blob([value],{type:"text/plain"}));
    const a=document.createElement("a");a.href=url;a.download="northstar-backup-codes.txt";a.click();setTimeout(()=>URL.revokeObjectURL(url),0);
  }});
  app.append(cp,dl,primary("I saved my codes",settings),help());
}
function settings(error){
  page("4","MFA is ready");
  app.append(el("p",{text:"Your authenticator is active. Backup codes are available if you lose your device."}));
  if(error)app.append(message(error,error.startsWith("That backup code worked")?"notice":"error"));
  const input=el("input",{type:"text",autocomplete:"one-time-code",placeholder:"ABCDE-12345",maxlength:"11"});
  app.append(el("h2",{text:"Try a backup code"}),el("label",{for:"recovery",text:"Recovery code"}));
  input.id="recovery";
  app.append(input,el("p",{className:"hint",text:"Example: ABCDE-12345"}),primary("Use recovery code",async()=>{
    const result=await api("/api/recovery/verify","POST",{code:input.value});
    if(!result.ok)return settings(result.message);
    settings("That backup code worked and cannot be used again.");
  }),el("button",{className:"secondary",type:"button",text:"Make new backup codes",onClick:async()=>{
    const result=await api("/api/backup/regenerate","POST",{});
    if(!result.ok)return settings(result.message);
    recoveryCodes=result.codes;
    log("Replacement test backup recovery codes: "+result.codes.join(", "));
    backups();
  }}),el("button",{className:"smalllink",type:"button",text:"Sign out",onClick:async()=>{
    await api("/api/logout","POST",{});
    csrf="";provision=null;recoveryCodes=null;
    log("Signed out. Server session invalidated.");
    signIn();
  }}),help());
}
async function boot(){
  const result=await api("/api/status");
  if(result.ok){csrf=result.csrf;result.mfaActive?settings():result.identityVerified?setup():identity();}else signIn();
}
boot();
})();
</script></body></html>`;
}

async function route(request: Request): Promise<Response> {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    if (!isTrustedOrigin(request)) return genericError(403, request);
    const result = new Response(null, { status: 204, headers: headers(undefined, request) });
    result.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    result.headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return result;
  }

  if (url.pathname === "/" && request.method === "GET") {
    const nonce = randomToken(18);
    const resultHeaders = headers(nonce, request);
    resultHeaders.set("Content-Type", "text/html; charset=utf-8");
    return new Response(html(nonce), { headers: resultHeaders });
  }

  if (url.pathname === "/api/signin" && request.method === "POST") {
    const input = await body(request);
    const email = text(input?.email, 254);
    const password = text(input?.password, 128);
    /* Security requirement 4/5: strict validation and non-enumerating auth response. */
    if (!email || !password || !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email) ||
        email.toLowerCase() !== account.email || password !== account.password) {
      return json({ ok: false, message: "Those sign-in details did not match. Check both fields and try again." }, 401, request);
    }
    const id = randomToken(32);
    const session: Session = {
      userId: account.id,
      csrf: randomToken(32),
      createdAt: Date.now(),
      lastSeenAt: Date.now(),
      identityVerified: false,
    };
    sessions.set(id, session);
    return json({ ok: true, csrf: session.csrf }, 200, request, { "Set-Cookie": cookie(id) });
  }

  if (url.pathname === "/api/status" && request.method === "GET") {
    const found = authorized(request);
    if (found instanceof Response) return found;
    return json({
      ok: true,
      csrf: found.session.csrf,
      identityVerified: found.session.identityVerified,
      mfaActive: !!account.activeSecret,
    }, 200, request);
  }

  if (url.pathname === "/api/identity" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    if (Date.now() < account.identityLockedUntil) {
      return json({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, request);
    }
    const input = await body(request);
    const code = text(input?.code, 6);
    if (!code || !/^\\d{6}$/.test(code) || code !== "246810") {
      account.identityFailures++;
      if (account.identityFailures >= MAX_ATTEMPTS) {
        account.identityFailures = 0;
        account.identityLockedUntil = Date.now() + LOCK_MS;
        return json({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, request);
      }
      return json({ ok: false, message: "That identity code did not work. Check the 6 numbers and try again." }, 400, request);
    }
    account.identityFailures = 0;
    found.session.identityVerified = true;
    return json({ ok: true }, 200, request);
  }

  if (url.pathname === "/api/mfa/provision" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    if (!found.session.identityVerified) return json({ ok: false, message: "Complete the identity check before setting up MFA." }, 403, request);
    const secret = base32(bytes(20));
    account.pendingSecret = await encryptSecret(secret);
    account.otpUsedSlots.clear();
    account.otpFailures = 0;
    account.otpLockedUntil = 0;
    const testOtp = await otpFor(secret, Math.floor(Date.now() / OTP_WINDOW_MS));
    const label = encodeURIComponent(`Northstar:${account.email}`);
    const uri = `otpauth://totp/${label}?secret=${secret}&issuer=Northstar&algorithm=${OTP_ALGORITHM}&digits=${OTP_DIGITS}&period=${OTP_PERIOD_SECONDS}`;
    return json({ ok: true, secret, uri, testOtp }, 200, request);
  }

  if (url.pathname === "/api/mfa/verify" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    const input = await body(request);
    const otp = text(input?.otp, 6);
    if (!otp || !/^\\d{6}$/.test(otp)) return json({ ok: false, message: "Enter all 6 numbers from your authenticator app." }, 400, request);
    if (!account.pendingSecret) return json({ ok: false, message: "Choose setup options first, then enter the code." }, 400, request);
    if (Date.now() < account.otpLockedUntil) return json({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, request);

    const secret = await decryptSecret(account.pendingSecret);
    const slot = Math.floor(Date.now() / OTP_WINDOW_MS);
    let matchedSlot: number | null = null;
    if (otp === await otpFor(secret, slot)) matchedSlot = slot;
    else if (otp === await otpFor(secret, slot - 1)) matchedSlot = slot - 1;

    /* Security requirement 5: record exactly the matched current or previous TOTP slot. */
    if (matchedSlot === null || account.otpUsedSlots.has(matchedSlot)) {
      account.otpFailures++;
      if (account.otpFailures >= MAX_ATTEMPTS) {
        account.otpFailures = 0;
        account.otpLockedUntil = Date.now() + LOCK_MS;
        return json({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, request);
      }
      return json({ ok: false, message: "That code did not work. Check your authenticator app and try a fresh 6-digit code." }, 400, request);
    }

    account.otpUsedSlots.add(matchedSlot);
    account.otpFailures = 0;
    account.activeSecret = account.pendingSecret;
    account.pendingSecret = undefined;
    const codes = await createBackupCodes();
    return json({ ok: true, codes }, 200, request);
  }

  if (url.pathname === "/api/recovery/verify" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    const input = await body(request);
    const code = text(input?.code, 11)?.toUpperCase();
    if (!code || !/^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/.test(code)) {
      return json({ ok: false, message: "Enter a backup code in the format ABCDE-12345." }, 400, request);
    }
    if (Date.now() < account.backupLockedUntil) return json({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, request);
    for (const stored of account.backupCodes) {
      if (!stored.used && await hashRecovery(code, stored.salt) === stored.hash) {
        stored.used = true;
        account.backupFailures = 0;
        return json({ ok: true }, 200, request);
      }
    }
    account.backupFailures++;
    if (account.backupFailures >= MAX_ATTEMPTS) {
      account.backupFailures = 0;
      account.backupLockedUntil = Date.now() + LOCK_MS;
      return json({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, request);
    }
    return json({ ok: false, message: "That backup code did not work. Check the saved code and try another one." }, 400, request);
  }

  if (url.pathname === "/api/backup/regenerate" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    if (!account.activeSecret) return json({ ok: false, message: "Set up an authenticator before making backup codes." }, 400, request);
    const codes = await createBackupCodes();
    return json({ ok: true, codes }, 200, request);
  }

  if (url.pathname === "/api/logout" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    sessions.delete(found.id);
    return json({ ok: true }, 200, request, { "Set-Cookie": cookie("", 0) });
  }

  return genericError(404, request);
}

Bun.serve({
  port: PORT,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      return await route(request);
    } catch {
      return genericError(500, request);
    }
  },
});

console.log(`MFA demo listening securely at https://localhost:${PORT}`);
