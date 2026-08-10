
import { Buffer } from "buffer";

/*
 MFA Enrolment System — Bun HTTPS server and mobile SPA.
 Security §1/§5: authenticated ownership, CSRF, rate limiting, session rotation.
 Security §2: TLS and restrictive response headers.
 Security §3: encrypted TOTP secret and hashed recovery codes.
 Security §4: validated inputs and contextual client-side output encoding.
*/

type Session = { accountId: string; csrf: string; created: number; lastSeen: number };
type MfaState = {
  identityVerified: boolean; encryptedSecret?: string; mockChallenge?: string;
  mockExpires?: number; mockUsed?: boolean; otpUsed: boolean; usedSteps: Set<number>;
  backupHashes: Set<string>; recoveryVerified: boolean; failures: number;
  lockedUntil: number; completed: boolean;
};
type Attempt = { failures: number; lockedUntil: number };

const ACCOUNT = { id: "account-marcus-demo", email: "marcus@example.test", phone: "07700900123" };
const IDLE_MS = 20 * 60 * 1000, ABSOLUTE_MS = 8 * 60 * 60 * 1000, LOCK_MS = 5 * 60 * 1000;
const MOCK_MS = 10 * 60 * 1000, MAX_FAILURES = 5;
const configuredCredential = process.env.MFA_DEMO_PIN || "482913";
const loginSalt = "online-bank-mfa-login-v1";
const sessions = new Map<string, Session>(), states = new Map<string, MfaState>(), loginAttempts = new Map<string, Attempt>();
const encryptionBytes = crypto.getRandomValues(new Uint8Array(32));
const encryptionKey = await crypto.subtle.importKey("raw", encryptionBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
const recoveryPepper = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");

function random(n = 32) { return Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url"); }
function secureCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const v = Array.from(crypto.getRandomValues(new Uint8Array(10)), x => chars[x % chars.length]).join("");
  return v.slice(0, 5) + "-" + v.slice(5);
}
function secret() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  return Array.from(crypto.getRandomValues(new Uint8Array(20)), x => chars[x % chars.length]).join("");
}
async function digest(v: string) { return Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(loginSalt + ":" + v))).toString("base64url"); }
const credentialVerifier = await digest(configuredCredential);
async function recoveryHash(v: string) { return Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v + ":" + recoveryPepper))).toString("base64url"); }
function same(a: string, b: string) {
  const aa = new TextEncoder().encode(a), bb = new TextEncoder().encode(b);
  if (aa.length !== bb.length) return false;
  let result = 0; for (let i = 0; i < aa.length; i++) result |= aa[i] ^ bb[i];
  return result === 0;
}
async function encrypt(v: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, new TextEncoder().encode(v));
  return Buffer.from(iv).toString("base64url") + "." + Buffer.from(data).toString("base64url");
}
async function decrypt(v: string) {
  const [iv, data] = v.split(".");
  if (!iv || !data) throw new Error("invalid");
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(iv, "base64url") }, encryptionKey, Buffer.from(data, "base64url")));
}
function state() {
  let value = states.get(ACCOUNT.id);
  if (!value) {
    value = { identityVerified: false, otpUsed: false, usedSteps: new Set(), backupHashes: new Set(), recoveryVerified: false, failures: 0, lockedUntil: 0, completed: false };
    states.set(ACCOUNT.id, value);
  }
  return value;
}
function base32(v: string) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, current = 0; const output: number[] = [];
  for (const c of v) {
    const index = chars.indexOf(c); if (index < 0) throw new Error("bad secret");
    current = (current << 5) | index; bits += 5;
    if (bits >= 8) { output.push((current >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(output);
}
async function hmac(key: Uint8Array, data: Uint8Array) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}
async function totp(key: string, step: number) {
  const data = new Uint8Array(8); let value = BigInt(step);
  for (let i = 7; i >= 0; i--) { data[i] = Number(value & 255n); value >>= 8n; }
  const hash = await hmac(base32(key), data), offset = hash[hash.length - 1] & 15;
  const n = (((hash[offset] & 127) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3]) % 1000000;
  return String(n).padStart(6, "0");
}
async function validTotp(key: string, code: string) {
  const current = Math.floor(Date.now() / 30000);
  for (let offset = -1; offset <= 1; offset++) if (code === await totp(key, current + offset)) return current + offset;
  return null;
}
async function mockCode(item: MfaState) {
  const key = await decrypt(item.encryptedSecret!);
  const hash = await hmac(base32(key), new TextEncoder().encode("mock:" + item.mockChallenge));
  return String((((hash[0] & 127) << 16 | hash[1] << 8 | hash[2]) % 1000000)).padStart(6, "0");
}

function email(v: unknown) { return typeof v === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim()) && v.length <= 120 ? v.trim().toLowerCase() : null; }
function phone(v: unknown) { return typeof v === "string" && /^\+?[0-9 ()-]{7,24}$/.test(v) ? v : null; }
function pin(v: unknown): v is string { return typeof v === "string" && /^[0-9]{4,12}$/.test(v); }
function otp(v: unknown): v is string { return typeof v === "string" && /^[0-9]{6}$/.test(v); }
function recovery(v: unknown): v is string { return typeof v === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(v); }
function cookieMap(req: Request) {
  const out: Record<string, string> = {};
  for (const part of (req.headers.get("cookie") || "").split(";")) {
    const i = part.indexOf("="); if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function trusted(req: Request) {
  const origin = req.headers.get("origin"), host = req.headers.get("host");
  if (!origin || !host) return false;
  try {
    const source = new URL(origin), target = new URL("https://" + host);
    return source.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(source.hostname.replace(/^\[|\]$/g, "")) && source.origin === target.origin;
  } catch { return false; }
}
function headers(nonce?: string) {
  return new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Content-Security-Policy": nonce ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` : "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
  });
}
function response(data: unknown, status = 200) { return new Response(JSON.stringify(data), { status, headers: headers() }); }
function sessionCookie(id: string) { return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE_MS / 1000)}`; }
function currentSession(req: Request) {
  const id = cookieMap(req).mfa_session, item = id ? sessions.get(id) : undefined;
  if (!item) return null;
  if (Date.now() - item.lastSeen > IDLE_MS || Date.now() - item.created > ABSOLUTE_MS) { sessions.delete(id!); return null; }
  item.lastSeen = Date.now(); return item;
}
function requireSession(req: Request): Session | Response {
  const item = currentSession(req);
  return item && item.accountId === ACCOUNT.id ? item : response({ ok: false, message: "Please sign in again to continue." }, 401);
}
function csrf(req: Request, item: Session) { return trusted(req) && req.headers.get("x-csrf-token") === item.csrf; }
async function body(req: Request): Promise<Record<string, unknown> | null> {
  if (Number(req.headers.get("content-length") || "0") > 5000) return null;
  try { const v = await req.json(); return v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : null; } catch { return null; }
}
function peer(req: Request) { try { return server.requestIP(req)?.address || "unknown"; } catch { return "unknown"; } }
function loginFailure() { return response({ ok: false, message: "We could not sign you in with those details. Please try again." }, 400); }
function authenticatedResponse(req: Request) {
  const old = cookieMap(req).mfa_session; if (old) sessions.delete(old);
  const id = random(), item: Session = { accountId: ACCOUNT.id, csrf: random(), created: Date.now(), lastSeen: Date.now() };
  sessions.set(id, item);
  const result = response({ ok: true, csrf: item.csrf, message: "You are signed in. Next, confirm your identity." });
  result.headers.set("Set-Cookie", sessionCookie(id)); return result;
}
function locked(item: MfaState) { return item.lockedUntil > Date.now() ? response({ ok: false, message: "Too many tries. Please wait a few minutes, then try again." }, 429) : null; }
function failure(item: MfaState, backup = false) {
  item.failures++;
  if (item.failures >= MAX_FAILURES) { item.failures = 0; item.lockedUntil = Date.now() + LOCK_MS; return response({ ok: false, message: "Too many tries. Please wait a few minutes, then try again." }, 429); }
  return response({ ok: false, message: backup ? "That backup code did not match. Copy one unused saved code and try again." : "That code did not match. Check the six numbers and try again." }, 400);
}

async function api(req: Request, path: string): Promise<Response> {
  if (path === "/api/authenticate" && req.method === "POST") {
    if (!trusted(req)) return response({ ok: false, message: "Please use this secure page to continue." }, 403);
    const key = peer(req), attempt = loginAttempts.get(key) || { failures: 0, lockedUntil: 0 };
    if (attempt.lockedUntil > Date.now()) return loginFailure();
    const input = await body(req), enteredEmail = input ? email(input.email) : null;
    let matched = false;
    if (enteredEmail && pin(input?.credential)) matched = enteredEmail === ACCOUNT.email && same(await digest(input!.credential as string), credentialVerifier);
    if (!matched) {
      attempt.failures++; if (attempt.failures >= MAX_FAILURES) { attempt.failures = 0; attempt.lockedUntil = Date.now() + LOCK_MS; }
      loginAttempts.set(key, attempt); return loginFailure();
    }
    loginAttempts.delete(key); return authenticatedResponse(req);
  }

  const auth = requireSession(req); if (auth instanceof Response) return auth;
  if (path === "/api/me" && req.method === "GET") { const item = state(); return response({ ok: true, csrf: auth.csrf, identityVerified: item.identityVerified, completed: item.completed }); }
  if (req.method !== "POST") return response({ ok: false, message: "That secure action is not available." }, 404);
  if (!csrf(req, auth)) return response({ ok: false, message: "Your safety check expired. Please sign in again." }, 403);

  if (path === "/api/logout") {
    for (const [id, value] of sessions) if (value === auth) sessions.delete(id);
    const result = response({ ok: true, message: "You have signed out." });
    result.headers.set("Set-Cookie", "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"); return result;
  }

  const input = await body(req);
  if (!input || "accountId" in input || "userId" in input || "sessionId" in input) return response({ ok: false, message: "Please check your entry and try again." }, 400);
  const item = state();

  if (path === "/api/identity") {
    const enteredEmail = email(input.email), enteredPhone = phone(input.phone);
    if (!enteredEmail || !enteredPhone) return response({ ok: false, message: "Enter an email like name@example.com and a phone number." }, 400);
    if (enteredEmail !== ACCOUNT.email || enteredPhone.replace(/\D/g, "") !== ACCOUNT.phone) return response({ ok: false, message: "Those details did not match. Check both entries and try again." }, 400);
    item.identityVerified = true; return response({ ok: true, message: "Identity confirmed. Next, create your authenticator setup key." });
  }
  if (path === "/api/setup") {
    if (!item.identityVerified) return response({ ok: false, message: "Confirm your identity before setting up an authenticator." }, 403);
    const value = secret(); item.encryptedSecret = await encrypt(value);
    item.mockChallenge = random(); item.mockExpires = Date.now() + MOCK_MS; item.mockUsed = false;
    item.otpUsed = false; item.usedSteps = new Set(); item.recoveryVerified = false; item.failures = 0;
    return response({ ok: true, secret: value, uri: `otpauth://totp/OnlineBank:Marcus?secret=${value}&issuer=OnlineBank&digits=6&period=30`, message: "Setup key created. Scan the QR code or copy the manual key." });
  }
  if (path === "/api/otp") {
    const block = locked(item); if (block) return block;
    if (!otp(input.code)) return response({ ok: false, message: "Enter six numbers, for example 123456." }, 400);
    if (!item.encryptedSecret) return response({ ok: false, message: "Set up your authenticator first." }, 400);
    const step = await validTotp(await decrypt(item.encryptedSecret), input.code);
    if (step === null) return failure(item);
    if (item.usedSteps.has(step)) return response({ ok: false, message: "That code was already used. Wait for a fresh code, then try again." }, 400);
    item.usedSteps.add(step); item.otpUsed = true; item.failures = 0;
    return response({ ok: true, message: "Authenticator confirmed. Next, generate and save backup codes." });
  }
  if (path === "/api/test/mock/reveal") {
    if (!item.encryptedSecret || !item.mockChallenge || !item.mockExpires || item.mockExpires < Date.now() || item.mockUsed) return response({ ok: false, message: "That practice code is no longer available. Request a new one." }, 400);
    return response({ ok: true, code: await mockCode(item), message: "Practice code sent to the browser console for this academic test." });
  }
  if (path === "/api/test/mock/rerequest") {
    if (!item.encryptedSecret) return response({ ok: false, message: "Set up your authenticator first." }, 400);
    item.mockChallenge = random(); item.mockExpires = Date.now() + MOCK_MS; item.mockUsed = false;
    return response({ ok: true, code: await mockCode(item), message: "A fresh practice code was sent to the browser console. The earlier one no longer works." });
  }
  if (path === "/api/test/mock/verify") {
    const block = locked(item); if (block) return block;
    if (!otp(input.code) || !item.mockChallenge || !item.mockExpires || item.mockExpires < Date.now() || item.mockUsed) return response({ ok: false, message: "This practice code is not available. Request a new one." }, 400);
    if (input.code !== await mockCode(item)) return failure(item);
    item.mockUsed = true; item.otpUsed = true; item.failures = 0;
    return response({ ok: true, message: "Authenticator confirmed. Next, generate and save backup codes." });
  }
  if (path === "/api/backups") {
    if (!item.otpUsed) return response({ ok: false, message: "Confirm your authenticator before making backup codes." }, 403);
    const codes = Array.from({ length: 8 }, secureCode);
    item.backupHashes = new Set(await Promise.all(codes.map(recoveryHash))); item.recoveryVerified = false;
    return response({ ok: true, codes, message: "Your fresh backup codes are ready. Earlier backup codes no longer work." });
  }
  if (path === "/api/recovery/verify") {
    const block = locked(item); if (block) return block;
    if (!recovery(input.code)) return response({ ok: false, message: "Enter a backup code like ABCDE-FGHIJ." }, 400);
    const value = await recoveryHash(input.code);
    if (!item.backupHashes.has(value)) return failure(item, true);
    item.backupHashes.delete(value); item.recoveryVerified = true; item.failures = 0;
    return response({ ok: true, message: "Backup code accepted. It cannot be used again. You can now finish enrolment." });
  }
  if (path === "/api/complete") {
    if (!item.otpUsed || !item.recoveryVerified || item.backupHashes.size === 0) return response({ ok: false, message: "Confirm your authenticator, save backup codes, and check one backup code before finishing." }, 400);
    item.completed = true; return response({ ok: true, message: "MFA enrolment is complete." });
  }
  return response({ ok: false, message: "That secure action is not available." }, 404);
}

function html(nonce: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Online Bank · MFA enrolment</title>
<style nonce="${nonce}">
:root{--ink:#172335;--blue:#075cc8;--line:#cbd6e2;--pale:#edf5ff;--good:#087443;--bad:#9e2020}*{box-sizing:border-box}body{margin:0;background:#f5f8fb;color:var(--ink);font-family:"OpenDyslexic","Atkinson Hyperlegible","Comic Sans MS","Trebuchet MS",Verdana,sans-serif;font-size:17px;line-height:1.7;letter-spacing:.035em}main{width:min(100%,600px);margin:auto;padding:20px 16px 44px}.brand{font-weight:700;color:#093b78;margin-bottom:18px}.card,.logs{background:#fff;border:1px solid var(--line);border-radius:16px;padding:24px}.logs{margin-top:16px}.progress{color:#526174;margin:0 0 10px}.progress strong{color:var(--blue)}h1{font-size:1.65rem;line-height:1.3;margin:0 0 15px}h2{font-size:1rem;margin:0 0 8px}p{margin:0 0 16px}.hint,.status,.warning{padding:13px 14px;border-radius:10px;margin:17px 0}.hint{background:var(--pale);color:#19426d}.status{background:#edf9f1;color:#075a35;border-left:5px solid var(--good)}.error{background:#fff0f0;color:#841d1d;border-left-color:var(--bad)}.warning{background:#fff8df;border-left:5px solid #b77600}.hide{display:none}label{display:block;font-weight:700;margin:16px 0 6px}input{width:100%;min-height:52px;border:2px solid #93a5b8;border-radius:10px;padding:10px 13px;font:inherit;letter-spacing:.06em}button{width:100%;min-height:52px;border:0;border-radius:11px;padding:10px 14px;margin-top:17px;background:var(--blue);color:#fff;font:700 1rem "OpenDyslexic","Atkinson Hyperlegible","Comic Sans MS","Trebuchet MS",Verdana,sans-serif;cursor:pointer}button.secondary{background:#fff;color:#114d91;border:2px solid #86a5c7;margin-top:10px}button.text{width:auto;min-height:36px;background:transparent;color:#075cc8;text-decoration:underline;padding:5px 2px;margin:10px 15px 0 0}.secret{word-break:break-all;background:#f2f5f8;padding:11px;border-radius:8px;font-family:monospace}.codes{list-style:none;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:9px}.codes li{background:#f2f5f8;padding:9px;border-radius:8px;font-family:monospace}.qr{width:230px;height:230px;margin:18px auto;display:block;border:8px solid #fff;image-rendering:pixelated}.log-list{padding-left:20px;font-family:monospace;font-size:.82rem;word-break:break-word}@media(max-width:380px){body{font-size:16px}.card,.logs{padding:19px}.codes{grid-template-columns:1fr}}@media print{button,.progress,.brand,#status,.logs{display:none}.card{border:0}}
</style></head><body><main><header class="brand">● Online Bank</header><section class="card"><p class="progress" id="progress"></p><h1 id="title"></h1><div id="status" class="status hide" role="status" aria-live="polite"></div><div id="screen"></div></section><section class="logs"><h2>Logs</h2><small>General delivery and verification messages appear here. Secret test values appear only in the browser console.</small><ol id="logs" class="log-list" aria-live="polite"></ol></section></main>
<script nonce="${nonce}">(()=>{"use strict";
let csrf="",step="start",setupSecret="",uri="",codes=[],codesHidden=false,recoveryOK=false,mock="";
const screen=document.querySelector("#screen"),title=document.querySelector("#title"),progress=document.querySelector("#progress"),status=document.querySelector("#status"),logs=document.querySelector("#logs");
const names={start:["1 of 6","Start"],identity:["2 of 6","Check identity"],setup:["3 of 6","Add authenticator"],otp:["4 of 6","Confirm code"],backup:["5 of 6","Save backup codes"],recovery:["6 of 6","Check a backup code"],done:["Complete","Finished"]};
const esc=v=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function note(text,bad=false){status.textContent=text;status.className="status"+(bad?" error":"")}
function log(text){console.log(text);const li=document.createElement("li");li.textContent=text;logs.append(li)}
function secretLog(label,value){console.log(label,value)}
function removeRecoveryLog(){for(const x of [...logs.children])if(x.dataset.recovery==="yes")x.remove()}
function set(next){step=next;progress.innerHTML="Step <strong>"+names[next][0]+"</strong> · "+names[next][1];render()}
async function call(path,data={},method="POST"){try{const r=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:method==="GET"?undefined:JSON.stringify(data)}),j=await r.json();if(!r.ok||!j.ok)throw Error(j.message||"Please try again.");return j}catch(e){note(e.message||"Something went wrong. Please try again.",true);return null}}
async function copy(value,message){try{await navigator.clipboard.writeText(value);note(message)}catch{note("Copy was not available. Select the text and copy it.",true)}}

/* Task: standards-compliant QR encoder, Version 7 / ECC M, byte mode. It encodes the exact otpauth URI. */
function qr(text){
 const bytes=[...new TextEncoder().encode(text)],V=7,N=45,DATA=124,ECC=18,BL=4;
 if(bytes.length>122)throw Error("Setup link is too long for this QR code.");
 const data=[];let bits=[];
 const put=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>>i)&1)};put(4,4);put(bytes.length,8);bytes.forEach(x=>put(x,8));
 while(bits.length%8)bits.push(0);for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8).join(""),2));
 for(let pad=0;data.length<DATA;pad++)data.push(pad%2?0x11:0xec);
 const exp=new Array(512),log=new Array(256);let x=1;for(let i=0;i<255;i++){exp[i]=x;log[x]=i;x<<=1;if(x&256)x^=0x11d}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;
 let gen=[1];for(let i=0;i<ECC;i++){const next=new Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=mul(gen[j],exp[i])}gen=next}
 const rs=block=>{const r=new Array(ECC).fill(0);for(const byte of block){const f=byte^r.shift();r.push(0);for(let j=0;j<ECC;j++)r[j]^=mul(gen[j+1],f)}return r};
 const blocks=[];for(let i=0;i<BL;i++)blocks.push(data.slice(i*31,i*31+31));const ecc=blocks.map(rs), stream=[];
 for(let i=0;i<31;i++)for(let b=0;b<BL;b++)stream.push(blocks[b][i]);for(let i=0;i<ECC;i++)for(let b=0;b<BL;b++)stream.push(ecc[b][i]);
 const raw=[];stream.forEach(byte=>{for(let i=7;i>=0;i--)raw.push((byte>>>i)&1)});
 const bch=(v,p)=>{let d=0,t=v;while(t){d++;t>>>=1}let pd=0,q=p;while(q){pd++;q>>>=1}while(d>=pd){v^=p<<(d-pd);d=0;t=v;while(t){d++;t>>>=1}}return v};
 const format=(mask)=>{let v=(0<<3)|mask;return ((v<<10)|bch(v<<10,0x537))^0x5412};
 const version=()=>{const v=V;return(v<<12)|bch(v<<12,0x1f25)};
 function matrix(mask){
  const m=Array.from({length:N},()=>Array(N).fill(null)),set=(r,c,v=true)=>{if(r>=0&&r<N&&c>=0&&c<N)m[r][c]=v};
  function finder(r,c){for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)set(r+y,c+z,y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4)))}
  finder(0,0);finder(N-7,0);finder(0,N-7);
  for(let i=8;i<N-8;i++){if(m[i][6]===null)set(i,6,i%2===0);if(m[6][i]===null)set(6,i,i%2===0)}
  for(const r of [6,22,38])for(const c of [6,22,38])if(m[r][c]===null)for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)set(r+y,c+z,Math.max(Math.abs(y),Math.abs(z))!==1);
  set(N-8,8,true);
  const f=format(mask);for(let i=0;i<15;i++){const bit=((f>>>i)&1)===1;if(i<6)set(i,8,bit);else if(i<8)set(i+1,8,bit);else set(N-15+i,8,bit);if(i<8)set(8,N-i-1,bit);else if(i<9)set(8,15-i,bit);else set(8,15-i-1,bit)}
  const vv=version();for(let i=0;i<18;i++){const bit=((vv>>>i)&1)===1;set(Math.floor(i/3),N-11+i%3,bit);set(N-11+i%3,Math.floor(i/3),bit)}
  let bit=0,up=true;for(let c=N-1;c>0;c-=2){if(c===6)c--;for(let k=0;k<N;k++){const r=up?N-1-k:k;for(let j=0;j<2;j++)if(m[r][c-j]===null){let v=bit<raw.length?raw[bit++]:0;const col=c-j;const invert=[(r+col)%2===0,r%2===0,col%3===0,(r+col)%3===0,(Math.floor(r/2)+Math.floor(col/3))%2===0,(r*col)%2+(r*col)%3===0,((r*col)%2+(r*col)%3)%2===0,((r+col)%2+(r*col)%3)%2===0][mask];m[r][col]=invert?!v:!!v}}up=!up}return m;
 }
 function penalty(m){let p=0;for(let r=0;r<N;r++)for(let c=0;c<N;c++){let n=0,v=m[r][c];for(let y=-1;y<=1;y++)for(let z=-1;z<=1;z++)if((y||z)&&r+y>=0&&r+y<N&&c+z>=0&&c+z<N&&m[r+y][c+z]===v)n++;if(n>5)p+=3+n-5}for(let r=0;r<N-1;r++)for(let c=0;c<N-1;c++)if(m[r][c]===m[r+1][c]&&m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c+1])p+=3;for(let r=0;r<N;r++)for(let c=0;c<N-6;c++)if(m[r][c]&&!m[r][c+1]&&m[r][c+2]&&m[r][c+3]&&m[r][c+4]&&!m[r][c+5]&&m[r][c+6])p+=40;for(let c=0;c<N;c++)for(let r=0;r<N-6;r++)if(m[r][c]&&!m[r+1][c]&&m[r+2][c]&&m[r+3][c]&&m[r+4][c]&&!m[r+5][c]&&m[r+6][c])p+=40;let dark=0;m.forEach(row=>row.forEach(v=>dark+=v));return p+Math.abs(100*dark/N/N-50)/5*10}
 let best=matrix(0),score=penalty(best);for(let i=1;i<8;i++){const candidate=matrix(i),s=penalty(candidate);if(s<score){best=candidate;score=s}}
 const c=document.createElement("canvas"),scale=6,ctx=c.getContext("2d");c.width=c.height=N*scale;ctx.fillStyle="#fff";ctx.fillRect(0,0,c.width,c.height);ctx.fillStyle="#172335";for(let r=0;r<N;r++)for(let col=0;col<N;col++)if(best[r][col])ctx.fillRect(col*scale,r*scale,scale,scale);
 c.className="qr";c.setAttribute("role","img");c.setAttribute("aria-label","Authenticator setup QR code. You can also copy the manual key.");return c;
}
function help(){note("Help: take your time. Use copy buttons instead of typing long details. You can retry without a penalty.")}
function common(){return '<div><button class="text" data-help type="button">ⓘ Need help?</button></div>'}
function wire(){screen.querySelectorAll("[data-help]").forEach(x=>x.onclick=help);screen.querySelectorAll("[data-back]").forEach(x=>x.onclick=()=>set(({identity:"start",setup:"identity",otp:"setup",backup:"otp",recovery:"backup"})[step]||step))}
function render(){
if(step==="start"){title.textContent="Set up extra security";screen.innerHTML='<p>🔐 Sign in to begin this short setup.</p><label>Email address<input id="email" autocomplete="username email" inputmode="email" placeholder="name@example.com"></label><small>Example: name@example.com</small><label>Account PIN<input id="pin" type="password" autocomplete="current-password" inputmode="numeric" maxlength="12" placeholder="Your account PIN"></label><button id="go">Sign in and start</button>'+common();document.querySelector("#go").onclick=async()=>{const r=await call("/api/authenticate",{email:document.querySelector("#email").value,credential:document.querySelector("#pin").value});if(r){document.querySelector("#pin").value="";csrf=r.csrf;note(r.message);set("identity")}}}
else if(step==="identity"){title.textContent="Check it is you";screen.innerHTML='<p>👤 Confirm the contact details on your account.</p><label>Email address<input id="email" autocomplete="email" value="marcus@example.test"></label><small>Example: name@example.com</small><label>Mobile number<input id="phone" autocomplete="tel" value="07700900123"></label><small>Example: 07700 900123</small><button id="go">Confirm my details</button><button class="text" data-back>← Back</button>'+common();document.querySelector("#go").onclick=async()=>{const r=await call("/api/identity",{email:document.querySelector("#email").value,phone:document.querySelector("#phone").value});if(r){note(r.message);set("setup")}}}
else if(step==="setup"){title.textContent="Add your authenticator";if(!setupSecret){screen.innerHTML='<p>📱 Create a private setup key for your authenticator app.</p><div class="hint">You can scan a QR code or copy a manual key. You do not need to type a long secret.</div><button id="create">Create my setup key</button><button class="text" data-back>← Back</button>'+common();document.querySelector("#create").onclick=async()=>{const r=await call("/api/setup");if(r){setupSecret=r.secret;uri=r.uri;note(r.message);render()}}}else{screen.innerHTML='<p>📱 Scan this QR code in your authenticator app. Or copy the setup link or manual key.</p><div id="qr"></div><button class="secondary" id="copyuri">Copy setup link</button><p class="hint">Manual key: <span class="secret">'+esc(setupSecret)+'</span></p><button class="secondary" id="copykey">Copy manual key</button><button class="secondary" id="hide">Hide setup key</button><button id="ready">I added it to my app</button>'+common();document.querySelector("#qr").append(qr(uri));document.querySelector("#copyuri").onclick=()=>copy(uri,"Setup link copied.");document.querySelector("#copykey").onclick=()=>copy(setupSecret,"Manual key copied.");document.querySelector("#hide").onclick=()=>{setupSecret="";uri="";note("Setup key hidden and removed from this page.");render()};document.querySelector("#ready").onclick=()=>set("otp")}}
else if(step==="otp"){title.textContent="Confirm your code";screen.innerHTML='<p>✅ Enter the six-number code from your authenticator. There is no reading timer.</p><label>Six-number code<input id="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6" placeholder="Example: 123456"></label><button id="verify">Confirm code</button><div class="hint"><strong>Academic test option</strong><br><small>A practice code is sent only to your browser console. It is not shown in this page or Logs panel.</small><button class="secondary" id="mock">Send practice code to console</button><button class="text" id="usemock">Use practice code</button><button class="text" id="newmock">Request a fresh practice code</button></div><button class="text" data-back>← Back</button>'+common();document.querySelector("#verify").onclick=async()=>{const r=await call("/api/otp",{code:document.querySelector("#otp").value.trim()});if(r){log("Authenticator code verified.");note(r.message);set("backup")}};document.querySelector("#mock").onclick=async()=>{const r=await call("/api/test/mock/reveal");if(r){mock=r.code;secretLog("Mock OTP for academic test:",r.code);note(r.message)}};document.querySelector("#newmock").onclick=async()=>{const r=await call("/api/test/mock/rerequest");if(r){mock=r.code;secretLog("Fresh mock OTP for academic test:",r.code);note(r.message)}};document.querySelector("#usemock").onclick=async()=>{if(!mock){note("Request a practice code first. It will appear in your browser console.",true);return}const r=await call("/api/test/mock/verify",{code:mock});mock="";if(r){log("Practice authenticator code verified.");note(r.message);set("backup")}}}
else if(step==="backup"){title.textContent="Save your backup codes";if(!codes.length&&!codesHidden){screen.innerHTML='<p>🗝️ Backup codes help if you cannot use your authenticator.</p><div class="hint">Generate them once, then save them somewhere private.</div><button id="make">Generate backup codes</button>'+common();document.querySelector("#make").onclick=async()=>{const r=await call("/api/backups");if(r){codes=r.codes;secretLog("MFA backup recovery codes:",r.codes);note(r.message);render()}}}else if(codesHidden){screen.innerHTML='<p>🗝️ Your backup codes are hidden and removed from this page.</p><div class="hint">Use the private copy you saved. Next, check one backup code works.</div><button class="secondary" id="replace">Generate fresh replacement codes</button><button id="continue">Continue to backup code check</button>'+common();document.querySelector("#replace").onclick=async()=>{const r=await call("/api/backups");if(r){codes=r.codes;codesHidden=false;secretLog("Replacement MFA backup recovery codes:",r.codes);note(r.message);render()}};document.querySelector("#continue").onclick=()=>set("recovery")}else{screen.innerHTML='<p>🗝️ Keep these codes somewhere private. Each code works once.</p><ul class="codes">'+codes.map(x=>"<li>"+esc(x)+"</li>").join("")+'</ul><button class="secondary" id="copy">Copy all backup codes</button><button class="secondary" id="print">Print this page</button><button class="secondary" id="hide">Hide backup codes</button><button id="continue">Continue to backup code check</button>'+common();document.querySelector("#copy").onclick=()=>copy(codes.join("\\n"),"Backup codes copied.");document.querySelector("#print").onclick=()=>window.print();document.querySelector("#hide").onclick=()=>{codes=[];codesHidden=true;removeRecoveryLog();note("Backup codes hidden and removed from this page.");render()};document.querySelector("#continue").onclick=()=>set("recovery")}}
else if(step==="recovery"){if(recoveryOK){title.textContent="Backup code confirmed";screen.innerHTML='<p>✅ Your backup code worked and is now used.</p><div class="hint">Your authenticator is confirmed. Finish when you are ready.</div><button id="finish">Finish MFA enrolment</button>'+common();document.querySelector("#finish").onclick=async()=>{const r=await call("/api/complete");if(r){log("MFA enrolment completed.");note(r.message);set("done")}}}else{title.textContent="Check a backup code";screen.innerHTML='<p>🧪 Copy one code from your saved list and enter it here.</p><label>Backup code<input id="recovery" autocomplete="one-time-code" autocapitalize="characters" placeholder="Example: ABCDE-FGHIJ"></label><button id="check">Check backup code</button><button class="text" data-back>← Back</button>'+common();document.querySelector("#check").onclick=async()=>{const r=await call("/api/recovery/verify",{code:document.querySelector("#recovery").value.trim().toUpperCase()});if(r){recoveryOK=true;const li=document.createElement("li");li.dataset.recovery="yes";li.textContent="Backup recovery code verified and marked used.";logs.append(li);note(r.message);render()}}}}
else{title.textContent="MFA is ready";screen.innerHTML='<p>🎉 Your authenticator and backup codes are set up.</p><div class="hint">For future payments, use your authenticator when asked.</div><button id="logout">Finish and sign out</button>'+common();document.querySelector("#logout").onclick=async()=>{const r=await call("/api/logout");if(r){csrf="";setupSecret="";uri="";codes=[];codesHidden=false;recoveryOK=false;mock="";log("Signed out.");note(r.message);set("start")}}}
wire()}set("start")})()</script></body></html>`;
}

const server = Bun.serve({
  port: Number(process.env.PORT || 3000),
  hostname: "::",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(req) {
    try {
      const url = new URL(req.url);
      if (url.pathname.startsWith("/api/")) return await api(req, url.pathname);
      if (url.pathname === "/" && req.method === "GET") {
        const nonce = random(), result = new Response(html(nonce), { headers: headers(nonce) });
        result.headers.set("Content-Type", "text/html; charset=utf-8"); return result;
      }
      return new Response("Not found", { status: 404, headers: headers() });
    } catch {
      return response({ ok: false, message: "Something went wrong. Please try again." }, 500);
    }
  }
});

console.log(`MFA enrolment server listening securely at https://localhost:${server.port}`);
