
import { Buffer } from "buffer";

/*
 MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.
 Security §1/§5 authorization, sessions and rate limits; §2 headers; §3 crypto;
 §4 validation; inclusive UI requirements are implemented in the HTML below.
*/

type Session = { accountId: string; csrf: string; created: number; lastSeen: number };
type MfaRecord = {
  identityVerified: boolean;
  encryptedSecret?: string;
  otpExpires?: number;
  otpUsed?: boolean;
  backups: Set<string>;
  failures: number;
  lockedUntil: number;
  completed: boolean;
};

const sessions = new Map<string, Session>();
const mfaByAccount = new Map<string, MfaRecord>();
const ACCOUNT = {
  id: "account-marcus-demo",
  email: "marcus@example.test",
  phone: "07700900123",
  name: "Marcus",
};

const IDLE_MS = 20 * 60 * 1000;
const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_LIFETIME_MS = 10 * 60 * 1000;
const LOCK_MS = 5 * 60 * 1000;
const MAX_FAILURES = 5;
const OTP_FOR_PRACTICE = "246810";

const encryptionKey = await crypto.subtle.importKey(
  "raw",
  crypto.getRandomValues(new Uint8Array(32)),
  { name: "AES-GCM" },
  false,
  ["encrypt"]
);
const recoveryPepper = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64");

function bytes(count: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(count));
}
function opaqueToken(): string {
  return Buffer.from(bytes(32)).toString("base64url");
}
function base32Secret(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  return Array.from(bytes(20), byte => alphabet[byte % alphabet.length]).join("");
}
function recoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const value = Array.from(bytes(10), byte => alphabet[byte % alphabet.length]).join("");
  return value.slice(0, 5) + "-" + value.slice(5);
}
async function sha256(value: string): Promise<string> {
  const output = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value + recoveryPepper));
  return Buffer.from(output).toString("base64url");
}
async function encrypt(value: string): Promise<string> {
  const iv = bytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encryptionKey,
    new TextEncoder().encode(value)
  );
  return Buffer.from(iv).toString("base64url") + "." + Buffer.from(ciphertext).toString("base64url");
}
function mfaState(): MfaRecord {
  let state = mfaByAccount.get(ACCOUNT.id);
  if (!state) {
    state = { identityVerified: false, backups: new Set(), failures: 0, lockedUntil: 0, completed: false };
    mfaByAccount.set(ACCOUNT.id, state);
  }
  return state;
}

/* Validation and normalization — security §4. */
function normalEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const result = value.trim().toLowerCase();
  return result.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(result) ? result : null;
}
function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+?[0-9 ()-]{7,24}$/.test(value);
}
function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}
function validRecovery(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(value);
}
function validInternalRedirect(value: unknown): boolean {
  return typeof value === "string" && ["/", "/?step=identity", "/?step=complete"].includes(value);
}
function parseCookies(req: Request): Record<string, string> {
  const values: Record<string, string> = {};
  for (const item of (req.headers.get("cookie") || "").split(";")) {
    const at = item.indexOf("=");
    if (at > 0) values[item.slice(0, at).trim()] = decodeURIComponent(item.slice(at + 1).trim());
  }
  return values;
}
function trustedRequest(req: Request): boolean {
  const origin = req.headers.get("origin");
  const host = req.headers.get("host") || "";
  if (!origin) return false;
  try {
    const source = new URL(origin);
    return source.protocol === "https:" &&
      ["localhost", "127.0.0.1", "::1", "[::1]"].includes(source.hostname) &&
      origin === "https://" + host;
  } catch {
    return false;
  }
}
function sessionFor(req: Request): Session | null {
  const token = parseCookies(req).mfa_session;
  const session = token ? sessions.get(token) : undefined;
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeen > IDLE_MS || now - session.created > ABSOLUTE_MS) {
    sessions.delete(token!);
    return null;
  }
  session.lastSeen = now;
  return session;
}
function requireSession(req: Request): { session: Session } | { error: Response } {
  const session = sessionFor(req);
  if (!session || session.accountId !== ACCOUNT.id) {
    return { error: api({ ok: false, message: "Please sign in again to continue." }, 401) };
  }
  return { session };
}
function requireCsrf(req: Request, session: Session): Response | null {
  if (!trustedRequest(req) || req.headers.get("x-csrf-token") !== session.csrf) {
    return api({ ok: false, message: "Your safety check expired. Please sign in again." }, 403);
  }
  return null;
}
async function requestBody(req: Request): Promise<Record<string, unknown> | null> {
  if (Number(req.headers.get("content-length") || "0") > 5000) return null;
  try {
    const body = await req.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

/* Production response protections — security §2. */
function responseHeaders(nonce?: string): Headers {
  return new Headers({
    "Content-Type": "application/json; charset=utf-8",
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
}
function api(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: responseHeaders() });
}
function page(content: string, nonce: string): Response {
  const headers = responseHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(content, { headers });
}
function sessionCookie(token: string): string {
  return `mfa_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE_MS / 1000)}`;
}
function clearCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}
function locked(state: MfaRecord): Response | null {
  return state.lockedUntil > Date.now()
    ? api({ ok: false, message: "Too many tries. Please wait a few minutes, then try again." }, 429)
    : null;
}
function failedAttempt(state: MfaRecord, recovery = false): Response {
  state.failures++;
  if (state.failures >= MAX_FAILURES) {
    state.failures = 0;
    state.lockedUntil = Date.now() + LOCK_MS;
    return api({ ok: false, message: "Too many tries. Please wait a few minutes, then try again." }, 429);
  }
  return api({
    ok: false,
    message: recovery
      ? "That backup code did not match. Copy one unused code from your saved list and try again."
      : "That code did not match. Check the example and try again.",
  }, 400);
}

async function handleApi(req: Request, path: string): Promise<Response> {
  if (path === "/api/authenticate" && req.method === "POST") {
    if (!trustedRequest(req)) return api({ ok: false, message: "Please use this secure page to continue." }, 403);
    const body = await requestBody(req);
    const email = body ? normalEmail(body.email) : null;
    /* Same generic response for malformed and non-matching accounts, avoiding enumeration. */
    if (!email || email !== ACCOUNT.email) {
      return api({ ok: false, message: "We could not sign you in with those details. Please try again." }, 400);
    }
    const token = opaqueToken();
    const session: Session = { accountId: ACCOUNT.id, csrf: opaqueToken(), created: Date.now(), lastSeen: Date.now() };
    sessions.set(token, session);
    const response = api({ ok: true, csrf: session.csrf, name: ACCOUNT.name, message: "You are signed in. Next, confirm your identity." });
    response.headers.set("Set-Cookie", sessionCookie(token));
    return response;
  }

  const auth = requireSession(req);
  if ("error" in auth) return auth.error;
  const { session } = auth;

  if (path === "/api/me" && req.method === "GET") {
    const state = mfaState();
    return api({ ok: true, csrf: session.csrf, identityVerified: state.identityVerified, completed: state.completed });
  }

  if (path === "/api/logout" && req.method === "POST") {
    const check = requireCsrf(req, session);
    if (check) return check;
    for (const [token, saved] of sessions) if (saved === session) sessions.delete(token);
    const response = api({ ok: true, message: "You have signed out." });
    response.headers.set("Set-Cookie", clearCookie());
    return response;
  }

  const csrfError = requireCsrf(req, session);
  if (csrfError) return csrfError;
  const body = await requestBody(req);
  if (!body) return api({ ok: false, message: "Please check your entry and try again." }, 400);
  if ("accountId" in body || "userId" in body) return api({ ok: false, message: "Please use your signed-in account page." }, 403);
  const state = mfaState();

  if (path === "/api/identity" && req.method === "POST") {
    const email = normalEmail(body.email);
    if (!email || !validPhone(body.phone)) return api({ ok: false, message: "Enter an email like name@example.com and a phone number." }, 400);
    if (email !== ACCOUNT.email || body.phone.replace(/\D/g, "") !== ACCOUNT.phone) {
      return api({ ok: false, message: "Those details did not match. Check both entries and try again." }, 400);
    }
    state.identityVerified = true;
    return api({ ok: true, message: "Identity confirmed. Next, create your authenticator setup key." });
  }

  if (path === "/api/setup" && req.method === "POST") {
    if (!state.identityVerified) return api({ ok: false, message: "Confirm your identity before setting up an authenticator." }, 403);
    const secret = base32Secret();
    state.encryptedSecret = await encrypt(secret);
    state.otpExpires = Date.now() + OTP_LIFETIME_MS;
    state.otpUsed = false;
    state.failures = 0;
    return api({
      ok: true,
      secret,
      uri: `otpauth://totp/OnlineBank:Marcus?secret=${secret}&issuer=OnlineBank&digits=6`,
      message: "Setup key created. Scan the QR code or copy the manual key, then enter the six-digit code.",
    });
  }

  if (path === "/api/otp/rerequest" && req.method === "POST") {
    if (!state.encryptedSecret) return api({ ok: false, message: "Set up your authenticator first." }, 400);
    state.otpExpires = Date.now() + OTP_LIFETIME_MS;
    state.otpUsed = false;
    return api({ ok: true, message: "A fresh practice code is ready. You may take as long as you need." });
  }

  if (path === "/api/otp" && req.method === "POST") {
    const lock = locked(state);
    if (lock) return lock;
    if (!validOtp(body.code)) return api({ ok: false, message: "Enter six numbers, for example 123456." }, 400);
    if (!state.encryptedSecret || !state.otpExpires || state.otpExpires < Date.now() || state.otpUsed) {
      return api({ ok: false, message: "This code is no longer available. Choose request a new code and try again." }, 400);
    }
    if (body.code !== OTP_FOR_PRACTICE) return failedAttempt(state);
    state.otpUsed = true;
    state.failures = 0;
    return api({ ok: true, message: "Authenticator confirmed. Next, generate and save backup codes." });
  }

  if (path === "/api/backups" && req.method === "POST") {
    if (!state.otpUsed) return api({ ok: false, message: "Confirm your authenticator before making backup codes." }, 403);
    const codes = Array.from({ length: 8 }, recoveryCode);
    state.backups = new Set(await Promise.all(codes.map(sha256)));
    return api({ ok: true, codes, message: "Your backup codes are ready. Save them somewhere private." });
  }

  if (path === "/api/recovery/verify" && req.method === "POST") {
    const lock = locked(state);
    if (lock) return lock;
    if (!validRecovery(body.code)) return api({ ok: false, message: "Enter a backup code like ABCDE-FGHIJ." }, 400);
    const digest = await sha256(body.code);
    if (!state.backups.has(digest)) return failedAttempt(state, true);
    state.backups.delete(digest);
    state.failures = 0;
    return api({ ok: true, message: "Backup code accepted. It cannot be used again. You can now finish enrolment." });
  }

  if (path === "/api/complete" && req.method === "POST") {
    if (!state.otpUsed || state.backups.size === 0) return api({ ok: false, message: "Confirm your authenticator and save backup codes before finishing." }, 400);
    if ("redirect" in body && !validInternalRedirect(body.redirect)) return api({ ok: false, message: "Please continue on this secure page." }, 400);
    state.completed = true;
    return api({ ok: true, message: "MFA enrolment is complete." });
  }
  return api({ ok: false, message: "That secure action is not available." }, 404);
}

function html(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Online Bank · MFA enrolment</title>
<style nonce="${nonce}">
:root{color-scheme:light;--ink:#172335;--muted:#526174;--blue:#075cc8;--pale:#edf5ff;--line:#cbd6e2;--good:#087443;--danger:#a32121}*{box-sizing:border-box}body{margin:0;background:#f5f8fb;color:var(--ink);font-family:Arial,Helvetica,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.035em}main{width:min(100%,600px);margin:auto;padding:20px 16px 44px}.brand{font-weight:700;font-size:1.05rem;color:#093b78;margin-bottom:20px}.card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:24px;box-shadow:0 2px 8px #1723350d}.progress{font-size:.92rem;color:var(--muted);margin:0 0 12px}.progress strong{color:var(--blue)}h1{font-size:1.65rem;line-height:1.25;letter-spacing:.02em;margin:0 0 14px}h2{font-size:1.18rem;line-height:1.35}p{margin:0 0 17px}.hint,.status{border-radius:10px;padding:13px 14px;margin:18px 0}.hint{background:var(--pale);color:#19426d}.status{background:#edf9f1;color:#075a35;border-left:5px solid var(--good)}.status.error{background:#fff0f0;color:#841d1d;border-left-color:var(--danger)}label{display:block;font-weight:700;margin:16px 0 6px}input{width:100%;min-height:52px;border:2px solid #93a5b8;border-radius:10px;padding:10px 13px;font:inherit;letter-spacing:.06em;color:var(--ink)}input:focus,button:focus{outline:3px solid #f3b725;outline-offset:2px}small{display:block;color:var(--muted);margin-top:4px}button{width:100%;min-height:54px;border:0;border-radius:11px;padding:11px 15px;margin-top:18px;background:var(--blue);color:white;font:700 1rem/1.3 Arial,Helvetica,sans-serif;letter-spacing:.025em;cursor:pointer}button.secondary{background:white;color:#114d91;border:2px solid #86a5c7;margin-top:10px}button.text{width:auto;min-height:40px;padding:5px 2px;background:transparent;color:#075cc8;text-decoration:underline;margin:10px 16px 0 0}.actions{margin-top:16px}.icon{font-size:1.5rem;margin-right:8px}.qr{display:block;width:244px;height:244px;margin:18px auto;image-rendering:pixelated;border:8px solid #172335;background:white}.secret{word-break:break-all;background:#f2f5f8;padding:12px;border-radius:9px;font-family:monospace;letter-spacing:.12em}.codes{list-style:none;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:9px}.codes li{background:#f2f5f8;padding:9px;border-radius:8px;font-family:monospace;letter-spacing:.07em}.logs{margin-top:22px;border-top:1px solid var(--line);padding-top:16px}.logs h2{margin-bottom:5px}.logbox{background:#101c2a;color:#e8f1ff;border-radius:10px;padding:12px;min-height:68px;font:13px/1.5 monospace;white-space:pre-wrap;word-break:break-word}.hide{display:none}@media(max-width:380px){.card{padding:19px}.codes{grid-template-columns:1fr}body{font-size:16px}}@media print{.brand,.progress,.actions,.logs,#status,button{display:none}body{background:white}.card{border:0;box-shadow:none}}
</style>
</head>
<body>
<main>
<header class="brand" aria-label="Online Bank">● Online Bank</header>
<section class="card" aria-labelledby="title">
<p class="progress" id="progress">Step <strong>1 of 6</strong> · Start</p>
<h1 id="title">Set up extra security</h1>
<div id="status" class="status hide" role="status" aria-live="polite"></div>
<div id="screen"></div>
</section>
<aside class="logs" aria-labelledby="logs-title">
<h2 id="logs-title">Logs</h2>
<p class="hint">Practice delivery messages appear here. They are also sent to the browser console.</p>
<div id="logbox" class="logbox" aria-live="polite">Ready.</div>
</aside>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
let csrf="", step="start", secret="", provisionUri="", backupCodes=[], recoveryChecked=false;
const screen=document.getElementById("screen"), title=document.getElementById("title"), progress=document.getElementById("progress"), status=document.getElementById("status"), logbox=document.getElementById("logbox");
const steps={start:["1 of 6","Start"],identity:["2 of 6","Check identity"],setup:["3 of 6","Add authenticator"],otp:["4 of 6","Confirm code"],backup:["5 of 6","Save backup codes"],recovery:["6 of 6","Check a backup code"],done:["Complete","Finished"]};
function esc(v){return String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function log(message){console.log(message);logbox.textContent+="\\n"+message;}
function notice(message,bad=false){status.textContent=message;status.className="status"+(bad?" error":"");}
function clearNotice(){status.textContent="";status.className="status hide";}
function setStep(next){step=next;const info=steps[step];progress.innerHTML="Step <strong>"+info[0]+"</strong> · "+info[1];render();}
async function api(path,data={},method="POST"){try{const response=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:method==="GET"?undefined:JSON.stringify(data)});const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.message||"Please try again.");return result;}catch(error){notice(error.message||"Something went wrong. Please try again.",true);return null;}}
function help(){notice("Help: take your time. Use copy buttons instead of typing long details. You can retry without a penalty.");}
async function copy(value,message){try{await navigator.clipboard.writeText(value);notice(message);}catch{notice("Copy was not available. Select the text and copy it.",true);}}
/* A local QR Version 5-L encoder. It encodes the returned otpauth URI without external calls. */
function qrCanvas(text){
 const version=5,n=37,dataCap=108,ecLen=26;
 const raw=Array.from(new TextEncoder().encode(text)); if(raw.length>106)return "";
 const bits=[]; const put=(v,count)=>{for(let i=count-1;i>=0;i--)bits.push((v>>i)&1);};
 put(4,4);put(raw.length,8);raw.forEach(x=>put(x,8));put(0,Math.min(4,dataCap*8-bits.length));while(bits.length%8)bits.push(0);
 const data=[];for(let i=0;i<bits.length;i+=8)data.push(bits.slice(i,i+8).reduce((a,b)=>a*2+b,0));let pad=0;while(data.length<dataCap)data.push(pad++%2?0x11:0xec);
 const exp=[],logt=[],mul=(a,b)=>{let z=0;while(b){if(b&1)z^=a;a=(a<<1)^(a&128?0x11d:0);b>>=1;}return z;};let x=1;for(let i=0;i<255;i++){exp[i]=x;logt[x]=i;x=mul(x,2);}
 let gen=[1];for(let i=0;i<ecLen;i++){const next=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=mul(gen[j],exp[i]);}gen=next;}
 const rem=Array(ecLen).fill(0);for(const b of data){const f=b^rem.shift();rem.push(0);for(let j=0;j<ecLen;j++)rem[j]^=mul(gen[j+1],f);}
 const code=data.concat(rem), matrix=Array.from({length:n},()=>Array(n).fill(null)), reserve=Array.from({length:n},()=>Array(n).fill(false));
 const set=(r,c,v,mark=true)=>{if(r>=0&&c>=0&&r<n&&c<n){matrix[r][c]=v;if(mark)reserve[r][c]=true;}};
 const finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)set(r+y,c+z,y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4)));};
 finder(0,0);finder(0,n-7);finder(n-7,0);
 for(let i=8;i<n-8;i++){set(6,i,i%2===0);set(i,6,i%2===0);}
 const align=(r,c)=>{for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)set(r+y,c+z,Math.max(Math.abs(y),Math.abs(z))!==1);};align(30,30);
 for(let i=0;i<9;i++){if(!reserve[i][8])set(i,8,false);if(!reserve[8][i])set(8,i,false);if(!reserve[n-1-i][8])set(n-1-i,8,false);if(!reserve[8][n-1-i])set(8,n-1-i,false);}set(n-8,8,true);
 const stream=[];code.forEach(b=>{for(let i=7;i>=0;i--)stream.push((b>>i)&1);});
 let k=0,up=true;for(let c=n-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<n;q++){const r=up?n-1-q:q;for(let d=0;d<2;d++){const col=c-d;if(!reserve[r][col]){const bit=stream[k++]||0;matrix[r][col]=bit^(((r+col)%2)===0?1:0);}}}up=!up;}
 /* Format bits: level L, mask 0, BCH-protected value 0x77c4. */
 const fmt=0x77c4;for(let i=0;i<15;i++){const bit=(fmt>>i)&1;if(i<6)set(i,8,bit);else if(i<8)set(i+1,8,bit);else set(n-15+i,8,bit);if(i<8)set(8,n-i-1,bit);else if(i<9)set(8,15-i,bit);else set(8,14-i-1,bit);}
 const canvas=document.createElement("canvas"),scale=6;canvas.width=canvas.height=n*scale;const ctx=canvas.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle="#172335";for(let r=0;r<n;r++)for(let c=0;c<n;c++)if(matrix[r][c])ctx.fillRect(c*scale,r*scale,scale,scale);canvas.className="qr";canvas.setAttribute("role","img");canvas.setAttribute("aria-label","Scannable QR code for authenticator setup");return canvas;
}
function common(){return '<div class="actions"><button class="text" type="button" data-help>ⓘ Need help?</button></div>';}
function wireCommon(){screen.querySelectorAll("[data-help]").forEach(b=>b.onclick=help);screen.querySelectorAll("[data-back]").forEach(b=>b.onclick=()=>{const back={identity:"start",setup:"identity",otp:"setup",backup:"otp",recovery:"backup"};if(back[step])setStep(back[step]);});}
async function createSetup(){const r=await api("/api/setup");if(r){secret=r.secret;provisionUri=r.uri;notice(r.message);setStep("setup");}}
function render(){
 if(step==="start"){title.textContent="Set up extra security";screen.innerHTML='<p><span class="icon">🔐</span>Sign in to begin this short setup.</p><label for="signin-email">Email address</label><input id="signin-email" autocomplete="email username" inputmode="email" value="marcus@example.test"><small>Example: name@example.com</small><button id="begin">Sign in and start</button>'+common();document.getElementById("begin").onclick=async()=>{const r=await api("/api/authenticate",{email:document.getElementById("signin-email").value});if(r){csrf=r.csrf;notice(r.message);setStep("identity");}};}
 else if(step==="identity"){title.textContent="Check it is you";screen.innerHTML='<p><span class="icon">👤</span>Confirm the contact details on your account.</p><label for="email">Email address</label><input id="email" autocomplete="email username" inputmode="email" value="marcus@example.test"><small>Example: name@example.com</small><label for="phone">Mobile number</label><input id="phone" autocomplete="tel" inputmode="tel" value="07700900123"><small>Example: 07700 900123</small><button id="identity">Confirm my details</button><div class="actions"><button class="text" data-back type="button">← Back</button></div>'+common();document.getElementById("identity").onclick=async()=>{const r=await api("/api/identity",{email:document.getElementById("email").value,phone:document.getElementById("phone").value.trim()});if(r){notice(r.message);setStep("setup");}};}
 else if(step==="setup"){title.textContent="Add your authenticator";if(!secret){screen.innerHTML='<p><span class="icon">📱</span>Create a private setup key for your authenticator app.</p><div class="hint">You can scan a QR code or copy a manual key. You do not need to type a long secret.</div><button id="create">Create my setup key</button><div class="actions"><button class="text" data-back type="button">← Back</button></div>'+common();document.getElementById("create").onclick=createSetup;}else{screen.innerHTML='<p><span class="icon">📱</span>Scan this QR code in your authenticator app. Or copy the manual key.</p><div id="qr-holder"></div><button class="secondary" id="copy-uri" type="button">Copy setup link</button><p class="hint">Manual key: <span class="secret">'+esc(secret)+'</span></p><button class="secondary" id="copy-secret" type="button">Copy manual key</button><button class="secondary" id="recreate" type="button">Create a new setup key</button><button id="ready">I added it to my app</button><div class="actions"><button class="text" data-back type="button">← Back</button></div>'+common();const canvas=qrCanvas(provisionUri);if(canvas)document.getElementById("qr-holder").appendChild(canvas);document.getElementById("copy-uri").onclick=()=>copy(provisionUri,"Setup link copied.");document.getElementById("copy-secret").onclick=()=>copy(secret,"Manual key copied.");document.getElementById("recreate").onclick=createSetup;document.getElementById("ready").onclick=()=>setStep("otp");}}
 else if(step==="otp"){title.textContent="Confirm your code";screen.innerHTML='<p><span class="icon">✅</span>Enter the six-number code from your authenticator. There is no reading timer.</p><label for="otp">Six-number code</label><input id="otp" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="Example: 123456"><button id="verify">Confirm code</button><div class="actions"><button class="secondary" id="reveal" type="button">Show practice code</button><button class="text" id="new-code" type="button">Request a new code</button><button class="text" data-back type="button">← Back</button></div>'+common();document.getElementById("verify").onclick=async()=>{const r=await api("/api/otp",{code:document.getElementById("otp").value.trim()});if(r){notice(r.message);setStep("backup");}};document.getElementById("reveal").onclick=()=>{notice("Practice code: 246810");log("Mock authenticator OTP for testing: 246810");};document.getElementById("new-code").onclick=async()=>{const r=await api("/api/otp/rerequest");if(r){notice(r.message);log("Mock authenticator OTP re-requested: 246810");}};}
 else if(step==="backup"){title.textContent="Save your backup codes";if(!backupCodes.length){screen.innerHTML='<p><span class="icon">🗝️</span>Backup codes help if you cannot use your authenticator.</p><div class="hint">Generate them once, then save them somewhere private.</div><button id="generate">Generate backup codes</button><div class="actions"><button class="text" data-back type="button">← Back</button></div>'+common();document.getElementById("generate").onclick=async()=>{const r=await api("/api/backups");if(r){backupCodes=r.codes;log("Mock recovery codes for testing: "+backupCodes.join(", "));notice(r.message);render();}};}else{const items=backupCodes.map(c=>"<li>"+esc(c)+"</li>").join("");screen.innerHTML='<p><span class="icon">🗝️</span>Keep these codes somewhere private. Each code works once.</p><ul class="codes" aria-label="Backup recovery codes">'+items+'</ul><button id="copy-codes">Copy all backup codes</button><button class="secondary" id="print-codes" type="button">Print this page</button><button class="secondary" id="continue" type="button">Continue to backup code check</button>'+common();document.getElementById("copy-codes").onclick=()=>copy(backupCodes.join("\\n"),"Backup codes copied.");document.getElementById("print-codes").onclick=()=>window.print();document.getElementById("continue").onclick=()=>{notice("Your codes are shown above. Next, check one code works.");setStep("recovery");};}}
 else if(step==="recovery"){title.textContent="Check a backup code";screen.innerHTML='<p><span class="icon">🧪</span>Copy one code from your saved list and enter it here. This checks your recovery option.</p><label for="recovery">Backup code</label><input id="recovery" autocomplete="one-time-code" autocapitalize="characters" placeholder="Example: ABCDE-FGHIJ"><button id="check-recovery">Check backup code</button><div class="actions"><button class="text" data-back type="button">← Back to my codes</button></div>'+common();document.getElementById("check-recovery").onclick=async()=>{const value=document.getElementById("recovery").value.trim().toUpperCase();const r=await api("/api/recovery/verify",{code:value});if(r){recoveryChecked=true;notice(r.message);render();}};if(recoveryChecked){screen.innerHTML+='<button id="finish">Finish MFA enrolment</button>';document.getElementById("finish").onclick=async()=>{const r=await api("/api/complete",{redirect:"/?step=complete"});if(r){notice(r.message);setStep("done");}};}}
 else{title.textContent="MFA is ready";screen.innerHTML='<p><span class="icon">🎉</span>Your authenticator and backup codes are set up.</p><div class="hint">For future payments, use your authenticator when asked.</div><button id="logout">Finish and sign out</button>'+common();document.getElementById("logout").onclick=async()=>{const r=await api("/api/logout");if(r){csrf="";secret="";provisionUri="";backupCodes=[];recoveryChecked=false;notice(r.message);setStep("start");}};}
 wireCommon();
}
render();
})();
</script>
</body>
</html>`;
}

const server = Bun.serve({
  port: Number(process.env.PORT || 3000),
  hostname: "::",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(req) {
    try {
      const url = new URL(req.url);
      if (url.pathname.startsWith("/api/")) return await handleApi(req, url.pathname);
      if (url.pathname === "/" && req.method === "GET") {
        const nonce = opaqueToken();
        return page(html(nonce), nonce);
      }
      return new Response("Not found", { status: 404, headers: responseHeaders() });
    } catch {
      return api({ ok: false, message: "Something went wrong. Please try again." }, 500);
    }
  },
});

console.log(`MFA enrolment server listening securely at https://localhost:${server.port}`);
