
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — Requirements 1–5:
 server-side ownership checks, CSRF, secure headers/cookies, encrypted MFA
 secrets, input validation, rate limiting, session lifecycle, and browser-only mocks.
*/
type Stage = "anonymous" | "identity" | "mfa";
type Session = {
  id: string; csrf: string; stage: Stage; userId?: string; createdAt: number; lastSeen: number;
  identityCode?: string; identityExpiry?: number; identityUsed?: boolean; identityFails: number; identityLockedUntil?: number;
  pendingEncryptedSecret?: string; pendingOtpExpiry?: number; otpFails: number; otpLockedUntil?: number;
  enrolledEncryptedSecret?: string; otpEnabled: boolean; backupHashes: string[];
  recoveryFails: number; recoveryLockedUntil?: number;
};

const PORT = 3000;
const TRUSTED_ORIGIN = `https://localhost:${PORT}`;
/* Simulation mode deliberately returns stable test values only to the browser UI. */
const TEST_MODE = true;
const ACCOUNT = { id: "account-marcus", email: "marcus@example.com", password: "BankDemo!9" };
const sessions = new Map<string, Session>();
const encoder = new TextEncoder(), decoder = new TextDecoder();
const IDLE = 20 * 60_000, ABSOLUTE = 8 * 60 * 60_000, LIFE = 10 * 60_000, LOCK = 10 * 60_000, MAX = 5;
const masterKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
const pepper = crypto.getRandomValues(new Uint8Array(32));

function random(chars: string, length: number) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return [...bytes].map(byte => chars[byte % chars.length]).join("");
}
function token(length = 32) { return random("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789", length); }
function digits(length = 6) { return TEST_MODE ? "123456".slice(0, length) : random("0123456789", length); }
function base32(length = 32) { return TEST_MODE ? "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".slice(0, length) : random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", length); }
function b64(bytes: Uint8Array) { return Buffer.from(bytes).toString("base64url"); }
function unb64(value: string) { return new Uint8Array(Buffer.from(value, "base64url")); }
async function hash(value: string) {
  return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(`${b64(pepper)}:${value}`))));
}
async function encrypt(value: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(value));
  return `${b64(iv)}.${b64(new Uint8Array(encrypted))}`;
}
async function decrypt(value: string) {
  const [iv, encrypted] = value.split(".");
  if (!iv || !encrypted) throw Error("invalid encrypted value");
  return decoder.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, masterKey, unb64(encrypted)));
}
function base32Bytes(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, current = 0; const output: number[] = [];
  for (const char of value.replace(/=+$/, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw Error("invalid base32");
    current = (current << 5) | index; bits += 5;
    while (bits >= 8) { bits -= 8; output.push((current >> bits) & 255); }
  }
  return new Uint8Array(output);
}
/* Requirement 3: RFC 6238 TOTP with SHA-1, 30-second steps, six digits. */
async function totp(secret: string, step = Math.floor(Date.now() / 30_000)) {
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const counter = new Uint8Array(8); let count = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(count & 255n); count >>= 8n; }
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = mac[19] & 15;
  return String((((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3]) % 1_000_000).padStart(6, "0");
}
async function validTotp(secret: string, code: string) {
  const step = Math.floor(Date.now() / 30_000);
  for (let adjustment = -1; adjustment <= 1; adjustment++) if (code === await totp(secret, step + adjustment)) return true;
  return false;
}
function recoveryCodes() {
  if (TEST_MODE) return ["ABCD-1234", "EFGH-2345", "JKLM-3456", "NPQR-4567", "STUV-5678", "WXYZ-6789", "BCDE-7890", "FGHJ-8901"];
  return Array.from({ length: 8 }, () => `${random("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 4)}-${random("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 4)}`);
}
function session(stage: Stage = "anonymous", userId?: string) {
  const s: Session = {
    id: token(48), csrf: token(40), stage, userId, createdAt: Date.now(), lastSeen: Date.now(),
    identityFails: 0, otpFails: 0, otpEnabled: false, backupHashes: [], recoveryFails: 0
  };
  sessions.set(s.id, s); return s;
}
function cookies(request: Request) {
  const output: Record<string, string> = {};
  for (const piece of (request.headers.get("cookie") || "").split(";")) {
    const at = piece.indexOf("=");
    if (at > 0) output[piece.slice(0, at).trim()] = piece.slice(at + 1).trim();
  }
  return output;
}
function stale(s: Session) { return Date.now() - s.lastSeen > IDLE || Date.now() - s.createdAt > ABSOLUTE; }
function current(request: Request) {
  const id = cookies(request).mfa_session, s = id && sessions.get(id);
  if (!s || stale(s)) { if (id) sessions.delete(id); return undefined; }
  s.lastSeen = Date.now(); return s;
}
/* Requirement 1: account ID is never accepted from the client. */
function owner(request: Request) {
  const s = current(request);
  return s?.stage === "mfa" && s.userId === ACCOUNT.id ? s : undefined;
}
function csrf(request: Request, s?: Session) { return !!s && request.headers.get("x-csrf-token") === s.csrf; }
function cookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE / 1000}`; }
function headers(nonce?: string): Record<string, string> {
  return {
    "content-security-policy": `default-src 'self'; script-src ${nonce ? `'nonce-${nonce}'` : "'none'"}; style-src ${nonce ? `'nonce-${nonce}'` : "'none'"}; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "access-control-allow-origin": TRUSTED_ORIGIN, "access-control-allow-credentials": "true", "vary": "Origin"
  };
}
function out(value: unknown, status = 200, extra: HeadersInit = {}) {
  return new Response(JSON.stringify(value), { status, headers: { ...headers(), "content-type": "application/json; charset=utf-8", ...extra } });
}
function fail(message: string, status = 400) { return out({ ok: false, message }, status); }
async function data(request: Request) {
  try { const value = await request.json(); return value && typeof value === "object" ? value as Record<string, unknown> : {}; } catch { return {}; }
}
function clean(value: unknown, max: number) { return typeof value === "string" ? value.trim().slice(0, max) : ""; }
function six(value: string) { return /^\d{6}$/.test(value); }
function recovery(value: string) { return /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value); }
async function saveCodes(s: Session, codes: string[]) { s.backupHashes = await Promise.all(codes.map(hash)); }

async function api(request: Request, path: string): Promise<Response> {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...headers(), "access-control-allow-methods": "GET, POST", "access-control-allow-headers": "content-type, x-csrf-token" } });

  if (request.method === "GET" && path === "/api/session") {
    let s = current(request), made = !s; if (!s) s = session();
    return out({ ok: true, csrf: s.csrf, signedIn: s.stage !== "anonymous", verified: s.stage === "mfa", otpEnabled: s.otpEnabled, backupCount: s.backupHashes.length, testMode: TEST_MODE }, 200, made ? { "set-cookie": cookie(s.id) } : {});
  }

  const s = current(request);
  if (request.method === "POST" && path === "/api/sign-in") {
    if (!csrf(request, s)) return fail("Your secure page check expired. Refresh the page and try again.", 403);
    const input = await data(request), email = clean(input.email, 254).toLowerCase(), password = clean(input.password, 256);
    if (email !== ACCOUNT.email || password !== ACCOUNT.password) return fail("We could not sign you in. Check your email and password, then try again.", 401);
    sessions.delete(s!.id);
    const fresh = session("identity", ACCOUNT.id);
    fresh.identityCode = digits(); fresh.identityExpiry = Date.now() + LIFE;
    /* Test mock is returned to UI only. The server does not log it. */
    return out({ ok: true, csrf: fresh.csrf, testCode: fresh.identityCode }, 200, { "set-cookie": cookie(fresh.id) });
  }

  if (request.method === "POST" && path === "/api/identity/send") {
    if (!s || s.stage !== "identity" || s.userId !== ACCOUNT.id) return fail("Please sign in again to continue.", 401);
    if (!csrf(request, s)) return fail("Your secure page check expired. Refresh and try again.", 403);
    /* Preserve failed attempts and active lock when requesting another delivery. */
    if (s.identityLockedUntil && s.identityLockedUntil > Date.now()) return fail("Too many tries. Wait ten minutes, then request a new code.", 429);
    s.identityCode = digits(); s.identityExpiry = Date.now() + LIFE; s.identityUsed = false;
    return out({ ok: true, csrf: s.csrf, testCode: s.identityCode });
  }

  if (request.method === "POST" && path === "/api/identity/verify") {
    if (!s || s.stage !== "identity" || s.userId !== ACCOUNT.id) return fail("Please sign in again to continue.", 401);
    if (!csrf(request, s)) return fail("Your secure page check expired. Refresh and try again.", 403);
    if (s.identityLockedUntil && s.identityLockedUntil > Date.now()) return fail("Too many tries. Wait ten minutes, then request a new code.", 429);
    const code = clean((await data(request)).code, 6);
    if (!six(code) || s.identityUsed || !s.identityExpiry || s.identityExpiry < Date.now() || code !== s.identityCode) {
      if (++s.identityFails >= MAX) s.identityLockedUntil = Date.now() + LOCK;
      return fail("That code did not work. Check all 6 digits, or request a new code.");
    }
    s.identityUsed = true; s.stage = "mfa"; s.csrf = token(40);
    return out({ ok: true, csrf: s.csrf });
  }

  const o = owner(request);
  if (!o) return fail("Please sign in again to manage MFA.", 401);
  if (request.method === "GET" && path === "/api/mfa/status") return out({ ok: true, csrf: o.csrf, otpEnabled: o.otpEnabled, backupCount: o.backupHashes.length });
  if (request.method !== "POST") return fail("That page is not available.", 404);
  if (!csrf(request, o)) return fail("Your secure page check expired. Refresh and try again.", 403);

  if (path === "/api/authenticator/start") {
    /* Preserve authenticator failures / active lock across regenerated setup requests. */
    if (o.otpLockedUntil && o.otpLockedUntil > Date.now()) return fail("Too many authenticator code tries. This setup is locked for ten minutes. Wait, then show new setup details.", 429);
    const secret = base32();
    o.pendingEncryptedSecret = await encrypt(secret); o.pendingOtpExpiry = Date.now() + LIFE;
    const issuer = "Local Bank", label = `${issuer}:marcus@example.com`;
    const uri = `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    return out({ ok: true, csrf: o.csrf, secret, provisioningUri: uri });
  }

  if (path === "/api/authenticator/verify") {
    const now = Date.now();
    if (o.otpLockedUntil && o.otpLockedUntil > now) return fail("Too many authenticator code tries. This setup is locked for ten minutes. Wait, then show new setup details.", 429);
    if (!o.pendingEncryptedSecret || !o.pendingOtpExpiry || o.pendingOtpExpiry < now) {
      o.pendingEncryptedSecret = undefined; o.pendingOtpExpiry = undefined;
      return fail("This setup has expired. Show new setup details to make a new setup.");
    }
    const code = clean((await data(request)).code, 6); let okay = false;
    try { okay = six(code) && await validTotp(await decrypt(o.pendingEncryptedSecret), code); } catch {}
    if (!okay) {
      if (++o.otpFails >= MAX) { o.otpLockedUntil = now + LOCK; return fail("Too many authenticator code tries. This setup is locked for ten minutes. Wait, then show new setup details.", 429); }
      return fail(`That authenticator code did not work. Check the 6 digits. You have ${MAX - o.otpFails} tries before this setup pauses.`);
    }
    o.enrolledEncryptedSecret = o.pendingEncryptedSecret; o.pendingEncryptedSecret = undefined; o.pendingOtpExpiry = undefined;
    o.otpEnabled = true; o.otpFails = 0; o.otpLockedUntil = undefined;
    return out({ ok: true, csrf: o.csrf });
  }

  if (path === "/api/backup/generate" || path === "/api/backup/regenerate") {
    if (!o.otpEnabled || !o.enrolledEncryptedSecret) return fail("Set up your authenticator before making recovery codes.");
    const codes = recoveryCodes(); await saveCodes(o, codes);
    /* Deterministic simulated codes are deliberately sent only to this authenticated browser. */
    return out({ ok: true, csrf: o.csrf, codes });
  }

  if (path === "/api/recovery/verify") {
    if (o.recoveryLockedUntil && o.recoveryLockedUntil > Date.now()) return fail("Too many tries. Wait ten minutes before trying another recovery code.", 429);
    const code = clean((await data(request)).code, 9).toUpperCase();
    if (!recovery(code)) {
      if (++o.recoveryFails >= MAX) { o.recoveryLockedUntil = Date.now() + LOCK; return fail("Too many tries. Wait ten minutes before trying another recovery code.", 429); }
      return fail("Enter a recovery code like ABCD-1234.");
    }
    const index = o.backupHashes.indexOf(await hash(code));
    if (index < 0) {
      if (++o.recoveryFails >= MAX) { o.recoveryLockedUntil = Date.now() + LOCK; return fail("Too many tries. Wait ten minutes before trying another recovery code.", 429); }
      return fail("That recovery code was not available. Check it, or use a different unused code.");
    }
    o.backupHashes.splice(index, 1); o.recoveryFails = 0;
    return out({ ok: true, csrf: o.csrf, remaining: o.backupHashes.length });
  }

  if (path === "/api/logout") {
    sessions.delete(o.id);
    return out({ ok: true }, 200, { "set-cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }
  return fail("That page is not available.", 404);
}

function page(request: Request) {
  const nonce = token(24); let s = current(request), made = !s; if (!s) s = session();
  return new Response(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#17263a;--blue:#075d9b;--pale:#eef7fc;--line:#c9d7e3}*{box-sizing:border-box}body{margin:0;background:#f4f8fa;color:var(--ink);font:17px/1.65 Verdana,Arial,sans-serif;letter-spacing:.035em}main{max-width:600px;min-height:100vh;margin:auto;padding:20px 18px 34px;background:#fff}.brand{font-weight:bold;color:var(--blue)}.step{margin:17px 0;padding:9px 13px;background:var(--pale);border-left:5px solid var(--blue)}h1{font-size:1.6rem;line-height:1.3}h2{font-size:1.1rem}p{margin:10px 0 17px}.card{margin:18px 0;padding:16px;border:1px solid var(--line);border-radius:12px}.hint{padding:11px 13px;background:#fff8dc;border-left:4px solid #9b7200;font-size:.92rem}.message{padding:11px 13px;border-radius:8px;margin:13px 0}.success{background:#e9f8ee;color:#145b38}.error{background:#fff0f0;color:#762323}label{display:block;font-weight:bold;margin-top:15px}input{width:100%;margin-top:5px;padding:12px;border:2px solid #90a7b8;border-radius:8px;font:inherit;letter-spacing:.08em}button{width:100%;margin-top:17px;padding:12px 14px;border:2px solid var(--blue);border-radius:8px;background:var(--blue);color:#fff;font:inherit;font-weight:bold;cursor:pointer}.secondary{background:#fff;color:var(--blue)}button:focus,input:focus{outline:3px solid #f3bb45;outline-offset:3px}.code{padding:11px;background:#f1f5f7;border-radius:7px;font:14px/1.55 monospace;word-break:break-all;letter-spacing:.05em}.qr{display:flex;justify-content:center;padding:12px;border:1px solid var(--line);border-radius:8px}.qr canvas{width:240px;height:240px;image-rendering:pixelated}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px}.codes div{padding:9px;background:#f1f5f7;border-radius:6px;font-family:monospace}.logs{margin-top:28px;border-top:2px solid var(--line)}pre{max-height:180px;overflow:auto;padding:11px;background:#172435;color:#e8f3ff;border-radius:8px;white-space:pre-wrap;font:12px/1.5 monospace;letter-spacing:0}.small{font-size:.88rem;color:#526276}@media(min-width:520px){main{margin-top:18px;border-radius:14px;box-shadow:0 3px 16px #ccd5dc}}
</style></head><body><main><header><div class="brand">🏦 Local Bank</div><div class="step" id="step">Step 1 of 4 · Sign in</div></header><section id="app" aria-live="polite">Loading secure setup…</section><section class="logs"><h2>🧾 Logs</h2><p class="small">Simulation activity appears here. Test values are shown only for this local simulation.</p><pre id="logs">Ready.</pre></section></main>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="";
const app=document.querySelector("#app"),step=document.querySelector("#step"),logs=document.querySelector("#logs");
const log=value=>{console.log(value);logs.textContent+="\\n"+value;logs.scrollTop=logs.scrollHeight};
const msg=(value,good=false)=>'<div class="message '+(good?"success":"error")+'">'+value+"</div>";
const bind=(id,handler)=>document.querySelector("#"+id)?.addEventListener("click",handler);
async function api(path,options={}){const response=await fetch(path,{method:options.method||"GET",credentials:"same-origin",headers:{"content-type":"application/json","x-csrf-token":csrf},body:options.body?JSON.stringify(options.body):undefined});const output=await response.json().catch(()=>({ok:false,message:"We could not complete that step. Please try again."}));if(output.csrf)csrf=output.csrf;return output}
function test(name,value){if(value!==undefined){const line="[TEST ONLY] "+name+": "+(Array.isArray(value)?value.join(", "):value);console.log(line);log(line)}}

function sign(){
 step.textContent="Step 1 of 4 · Sign in";
 app.innerHTML='<h1>Sign in</h1><p>Use your Local Bank email and password.</p><form id="f"><label>Email address<input id="email" type="email" autocomplete="username" placeholder="name@example.com" required></label><label>Password<input id="pass" type="password" autocomplete="current-password" required></label><button>Continue →</button></form><p class="hint">💡 Example email: name@example.com. Your password manager can help.</p>';
 document.querySelector("#f").onsubmit=async event=>{event.preventDefault();const d=await api("/api/sign-in",{method:"POST",body:{email:document.querySelector("#email").value,password:document.querySelector("#pass").value}});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));test("Mock identity OTP",d.testCode);identity("Sign-in succeeded. Next, enter the 6-digit identity code.")};
}
function identity(note=""){
 step.textContent="Step 2 of 4 · Check your identity";
 app.innerHTML='<h1>Check your identity</h1>'+(note?msg(note,true):"")+'<p>We sent a 6-digit check code. There is no reading timer.</p><form id="f"><label>6-digit code<input id="code" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6" required></label><button>Verify code →</button></form><button class="secondary" id="send">↻ Send a new code</button><p class="hint">💡 You can request another code at any time.</p>';
 document.querySelector("#f").onsubmit=async event=>{event.preventDefault();const d=await api("/api/identity/verify",{method:"POST",body:{code:document.querySelector("#code").value}});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));authStart("Identity check succeeded. Next, set up your authenticator.")};
 bind("send",async()=>{const d=await api("/api/identity/send",{method:"POST"});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));test("New mock identity OTP",d.testCode);identity("A new code was sent. The earlier code no longer works.")});
}

/* Valid QR Code Model 2, version 7-L, byte mode, mask 0.
   Version 7-L has 154 byte payload capacity. The generated otpauth URI is
   encoded directly, including its generated secret, and receives correct
   Reed-Solomon blocks, alignment/version/format information. */
function qr(uri){
 const bytes=[...new TextEncoder().encode(uri)],n=45,dataWords=156,ecWords=20,blocks=2;
 if(bytes.length>154)return null;
 const stream=[],put=(value,count)=>{for(let i=count-1;i>=0;i--)stream.push((value>>i)&1)};
 put(4,4);put(bytes.length,8);bytes.forEach(value=>put(value,8));put(0,Math.min(4,dataWords*8-stream.length));while(stream.length%8)stream.push(0);
 const data=[];for(let i=0;i<stream.length;i+=8)data.push(stream.slice(i,i+8).reduce((a,b)=>(a<<1)|b,0));while(data.length<dataWords)data.push(data.length%2?17:236);
 const exp=[],logarithm=[],poly=[1];let power=1;
 for(let i=0;i<255;i++){exp[i]=power;logarithm[power]=i;power<<=1;if(power&256)power^=285}
 const multiply=(a,b)=>a&&b?exp[(logarithm[a]+logarithm[b])%255]:0;
 for(let i=0;i<ecWords;i++){const next=Array(poly.length+1).fill(0);poly.forEach((v,j)=>{next[j]^=v;next[j+1]^=multiply(v,exp[i])});poly.splice(0,poly.length,...next)}
 const rs=input=>{const remainder=Array(ecWords).fill(0);input.forEach(value=>{const factor=value^remainder.shift();remainder.push(0);for(let j=0;j<ecWords;j++)remainder[j]^=multiply(poly[j+1],factor)});return remainder};
 const chunks=[data.slice(0,78),data.slice(78,156)],ecc=chunks.map(rs),bits=[];
 const pushByte=value=>{for(let i=7;i>=0;i--)bits.push((value>>i)&1)};
 for(let i=0;i<78;i++)for(let j=0;j<blocks;j++)pushByte(chunks[j][i]);
 for(let i=0;i<ecWords;i++)for(let j=0;j<blocks;j++)pushByte(ecc[j][i]);

 const matrix=Array.from({length:n},()=>Array(n).fill(null)),fixed=Array.from({length:n},()=>Array(n).fill(false));
 const set=(row,col,value)=>{if(row>=0&&col>=0&&row<n&&col<n){matrix[row][col]=value;fixed[row][col]=true}};
 const finder=(row,col)=>{for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++){const inside=y>=0&&y<7&&x>=0&&x<7;set(row+y,col+x,inside&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4))?1:0)}};
 finder(0,0);finder(0,n-7);finder(n-7,0);
 const align=(row,col)=>{for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++){const edge=Math.max(Math.abs(x),Math.abs(y))===2;set(row+y,col+x,edge||(!x&&!y)?1:0)}};
 /* Version 7 alignment centres: 6, 22, 38. Finder-overlap locations omitted. */
 [[22,22],[22,38],[38,22],[38,38]].forEach(position=>align(position[0],position[1]));
 for(let i=8;i<n-8;i++){set(6,i,i%2===0);set(i,6,i%2===0)}
 set(n-8,8,1);
 for(let i=0;i<9;i++)if(i!==6){set(8,i,0);set(i,8,0)}
 for(let i=0;i<8;i++){set(8,n-1-i,0);set(n-1-i,8,0)}
 /* Reserve Model 2 version-information modules before placing data. */
 for(let i=0;i<18;i++){set(Math.floor(i/3),n-11+(i%3),0);set(n-11+(i%3),Math.floor(i/3),0)}

 let bit=0,up=true;
 for(let col=n-1;col>0;col-=2){if(col===6)col--;for(let q=0;q<n;q++){const row=up?n-1-q:q;for(let side=0;side<2;side++)if(!fixed[row][col-side])matrix[row][col-side]=bits[bit++]||0}up=!up}
 for(let row=0;row<n;row++)for(let col=0;col<n;col++)if(!fixed[row][col]&&((row+col)%2===0))matrix[row][col]^=1;

 let format=(1<<3)|0,rem=format<<10;
 while(rem.toString(2).length>=11)rem^=0x537<<(rem.toString(2).length-11);
 format=((format<<10)|rem)^0x5412;
 for(let i=0;i<15;i++){
  const value=(format>>i)&1;
  if(i<6)matrix[i][8]=value;else if(i<8)matrix[i+1][8]=value;else if(i===8)matrix[8][7]=value;else matrix[n-15+i][8]=value;
  if(i<8)matrix[8][n-i-1]=value;else if(i<9)matrix[8][15-i]=value;else matrix[8][14-i]=value;
 }
 let version=7<<12,versionRem=version;
 while(versionRem.toString(2).length>=13)versionRem^=0x1f25<<(versionRem.toString(2).length-13);
 version|=versionRem;
 for(let i=0;i<18;i++){const value=(version>>i)&1;matrix[Math.floor(i/3)][n-11+(i%3)]=value;matrix[n-11+(i%3)][Math.floor(i/3)]=value}

 const canvas=document.createElement("canvas");canvas.width=canvas.height=n+8;
 const context=canvas.getContext("2d");context.fillStyle="#fff";context.fillRect(0,0,n+8,n+8);context.fillStyle="#17263a";
 for(let row=0;row<n;row++)for(let col=0;col<n;col++)if(matrix[row][col])context.fillRect(col+4,row+4,1,1);
 canvas.setAttribute("role","img");canvas.setAttribute("aria-label","Scannable QR code for authenticator setup");return canvas;
}
function authStart(note=""){
 step.textContent="Step 3 of 4 · Add authenticator";
 app.innerHTML='<h1>Add your authenticator</h1>'+(note?msg(note,true):"")+'<p>An authenticator app makes a 6-digit code for you.</p><div class="card"><h2>📱 Set up your app</h2><p>Show one setup. You can scan it or copy it.</p><button id="start">Show setup details →</button></div><p class="hint">💡 Take as long as you need. A new setup replaces an earlier setup.</p>';
 bind("start",async()=>{const d=await api("/api/authenticator/start",{method:"POST"});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));test("Authenticator Base32 secret",d.secret);test("Authenticator provisioning URI",d.provisioningUri);details(d)});
}
function details(d){
 step.textContent="Step 3 of 4 · Add authenticator";
 app.innerHTML='<h1>Set up your authenticator</h1><p>Scan the QR code or use the manual details. Both set up the same authenticator.</p><div class="card"><h2>▣ Scan QR code</h2><div class="qr" id="qr"></div><button class="secondary" id="toggle" aria-expanded="false">Show manual setup details</button><div id="manual" hidden><h2>🔗 Setup link</h2><div class="code" id="uri"></div><button class="secondary" id="copyuri">Copy setup link</button><h2>⌨️ Manual Base32 secret</h2><div class="code" id="secret"></div><button class="secondary" id="copysecret">Copy secret</button></div></div><form id="f"><label>Code from your authenticator<input id="otp" inputmode="numeric" autocomplete="one-time-code" placeholder="Example: 123456" maxlength="6" required></label><button>Confirm authenticator →</button></form><button class="secondary" id="restart">↻ Show new setup details</button><p class="hint">💡 This setup is available for 10 minutes. You can retry.</p>';
 const qrBox=document.querySelector("#qr"),uriBox=document.querySelector("#uri"),secretBox=document.querySelector("#secret"),manual=document.querySelector("#manual"),toggle=document.querySelector("#toggle");
 const canvas=qr(d.provisioningUri);if(canvas)qrBox.append(canvas);else qrBox.textContent="Use the manual setup details below.";
 uriBox.textContent=d.provisioningUri;secretBox.textContent=d.secret;
 bind("toggle",()=>{const show=manual.hidden;manual.hidden=!show;toggle.textContent=show?"Hide manual setup details":"Show manual setup details";toggle.setAttribute("aria-expanded",String(show))});
 const copy=(value,name)=>navigator.clipboard?.writeText(value).then(()=>log(name+" copied to clipboard.")).catch(()=>log("Copy was unavailable. You can select the text."));
 bind("copyuri",()=>copy(d.provisioningUri,"Setup link"));bind("copysecret",()=>copy(d.secret,"Manual secret"));bind("restart",()=>authStart());
 document.querySelector("#f").onsubmit=async event=>{event.preventDefault();const result=await api("/api/authenticator/verify",{method:"POST",body:{code:document.querySelector("#otp").value}});if(!result.ok)return app.insertAdjacentHTML("afterbegin",msg(result.message));backup("Authenticator verification succeeded. Next, save recovery codes.")};
}
function backup(note=""){
 step.textContent="Step 4 of 4 · Save recovery codes";
 app.innerHTML='<h1>Save recovery codes</h1>'+(note?msg(note,true):"")+'<p>Recovery codes help if you lose your phone. Each code works once.</p><button id="make">Create recovery codes →</button><p class="hint">💡 Keep them somewhere private. You can make a new set later.</p>';
 bind("make",async()=>{const d=await api("/api/backup/generate",{method:"POST"});if(!d.ok)return app.insertAdjacentHTML("afterbegin",msg(d.message));test("Mock recovery codes",d.codes);codes(d.codes)});
}
function codes(values){
 step.textContent="Step 4 of 4 · Save recovery codes";
 app.innerHTML='<h1>Your recovery codes</h1>'+msg("Your recovery codes are ready. Save them now, then continue.",true)+'<button class="secondary" id="show" aria-expanded="false">Show recovery codes</button><div id="list" class="codes" hidden></div><button class="secondary" id="copy">Copy codes</button><button class="secondary" id="down">Download text file</button><button id="finish">I saved my codes →</button>';
 const list=document.querySelector("#list"),show=document.querySelector("#show");
 values.forEach(value=>{const item=document.createElement("div");item.textContent=value;list.append(item)});
 bind("show",()=>{const visible=list.hidden;list.hidden=!visible;show.textContent=visible?"Hide recovery codes":"Show recovery codes";show.setAttribute("aria-expanded",String(visible))});
 bind("copy",()=>navigator.clipboard?.writeText(values.join("\\n")).then(()=>log("Recovery codes copied to clipboard.")).catch(()=>log("Copy was unavailable. You can select the codes.")));
 bind("down",()=>{const link=document.createElement("a");link.href=URL.createObjectURL(new Blob([values.join("\\n")],{type:"text/plain"}));link.download="local-bank-recovery-codes.txt";link.click();URL.revokeObjectURL(link.href);log("Recovery code text file prepared for download.")});
 bind("finish",settings);
}
async function settings(){
 const d=await api("/api/mfa/status");if(!d.ok)return sign();
 step.textContent="Complete · MFA settings";
 app.innerHTML='<h1>✅ MFA is ready</h1><p>Your authenticator is on. You have '+d.backupCount+' unused recovery codes.</p><div class="card"><h2>🔐 Use a recovery code</h2><form id="f"><label>Recovery code<input id="rc" autocomplete="one-time-code" placeholder="Example: ABCD-1234" maxlength="9" required></label><button class="secondary">Use recovery code</button></form></div><button class="secondary" id="regen">↻ Make new recovery codes</button><button class="secondary" id="again">↻ Set up authenticator again</button><button id="logout">Log out</button>';
 document.querySelector("#f").onsubmit=async event=>{event.preventDefault();const result=await api("/api/recovery/verify",{method:"POST",body:{code:document.querySelector("#rc").value}});if(!result.ok)return app.insertAdjacentHTML("afterbegin",msg(result.message));settings()};
 bind("regen",async()=>{const result=await api("/api/backup/regenerate",{method:"POST"});if(!result.ok)return app.insertAdjacentHTML("afterbegin",msg(result.message));test("Replacement mock recovery codes",result.codes);codes(result.codes)});
 bind("again",()=>authStart());bind("logout",async()=>{await api("/api/logout",{method:"POST"});csrf="";log("Signed out. Secure session invalidated.");sign()});
}
(async()=>{const d=await api("/api/session");if(d.verified)settings();else if(d.signedIn)identity();else sign()})();
})();
</script></body></html>`, { headers: { ...headers(nonce), "content-type": "text/html; charset=utf-8", ...(made ? { "set-cookie": cookie(s.id) } : {}) } });
}

const cert = readFileSync("certs/cert.pem"), key = readFileSync("certs/key.pem");
Bun.serve({
  port: PORT, tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url), origin = request.headers.get("origin");
      if (request.headers.get("x-forwarded-proto") === "http") return new Response("Secure connection required.", { status: 400, headers: headers() });
      if (origin && origin !== TRUSTED_ORIGIN) return new Response("Not allowed.", { status: 403, headers: headers() });
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      if (request.method === "GET" && url.pathname === "/") return page(request);
      return new Response("Page not found.", { status: 404, headers: headers() });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: headers() });
    }
  }
});
