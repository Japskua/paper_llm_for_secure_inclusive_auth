
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — Bun HTTPS server and mobile SPA.
 Requirements 1–5: owner-bound HttpOnly sessions, CSRF, TLS/headers,
 encrypted TOTP secrets, hashed recovery codes, validation and lockouts.
*/
const PORT = 3000;
const cert = readFileSync("certs/cert.pem", "utf8");
const key = readFileSync("certs/key.pem", "utf8");

const ACADEMIC_LOCALHOST_TEST_MODE = true;
const ACCOUNT_ID = "acct_marcus_001";
const ACCOUNT_EMAIL = "marcus@example.com";
const ACCOUNT_PHONE = "+15551234567";
const DEMO_PASSWORD = "MarcusDemo!42";
const absoluteMs = 8 * 60 * 60 * 1000;
const idleMs = 20 * 60 * 1000;
const codeMs = 10 * 60 * 1000;
const lockMs = 10 * 60 * 1000;
const throttleMs = 20 * 1000;

const trusted = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

const encKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

type RecoveryValue = { salt: string; value: string };
type Stage = "preauth" | "signedin" | "provision" | "mfaChallenge" | "recoveryAck" | "settings";
type Account = {
  id: string; email: string; normalizedPhone: string; passwordSalt: string; passwordValue: string;
  mfaEnabled: boolean; mfaSecretEncrypted?: string; mfaLastCounter?: number; backupCodeValues: RecoveryValue[];
};
type Session = {
  token: string; csrf: string; userId: string | null; stage: Stage; createdAt: number; lastSeen: number; expiresAt: number;
  invalidated?: boolean; identityCode?: string; identityCodeUsed?: boolean; identityCodeExpires?: number;
  identityFailures: number; identityLockedUntil?: number; identityLastRequestedAt?: number; provisionSecret?: string;
  otpFailures: number; otpLockedUntil?: number; recoveryFailures: number; recoveryLockedUntil?: number;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();

function bytes(n: number) { const x = new Uint8Array(n); crypto.getRandomValues(x); return x; }
function b64(x: Uint8Array) { let s = ""; for (const n of x) s += String.fromCharCode(n); return btoa(s); }
function unb64(s: string) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function token(n = 32) { return b64(bytes(n)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); }
function same(a: string, b: string) {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b);
  let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] || 0) ^ (y[i] || 0);
  return d === 0;
}
function randomChars(n: number, alphabet: string) {
  const out: string[] = [], limit = Math.floor(256 / alphabet.length) * alphabet.length;
  while (out.length < n) for (const x of bytes(32)) {
    if (x < limit) out.push(alphabet[x % alphabet.length]);
    if (out.length === n) break;
  }
  return out.join("");
}
function otp() { return randomChars(6, "0123456789"); }
function base32(n = 32) { return randomChars(n, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"); }
function recoveryCode() { const x = randomChars(8, "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"); return x.slice(0, 4) + "-" + x.slice(4); }

async function encrypt(value: string) {
  const iv = bytes(12);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encKey, new TextEncoder().encode(value));
  return b64(iv) + "." + b64(new Uint8Array(encrypted));
}
async function decrypt(value: string) {
  const [iv, encrypted] = value.split(".");
  if (!iv || !encrypted) throw new Error("invalid encrypted value");
  const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, encKey, unb64(encrypted));
  return new TextDecoder().decode(raw);
}
async function hash(value: string, salt: string) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(value), "PBKDF2", false, ["deriveBits"]);
  const output = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations: 210000 },
    material, 256
  );
  return b64(new Uint8Array(output));
}
async function newRecoveryCodes() {
  const codes: string[] = [], values: RecoveryValue[] = [];
  for (let i = 0; i < 8; i++) {
    const code = recoveryCode(), salt = token(24);
    codes.push(code);
    values.push({ salt, value: await hash(code, salt) });
  }
  return { codes, values };
}
function b32bytes(value: string) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of value) {
    const i = chars.indexOf(c);
    if (i < 0) throw new Error("invalid base32");
    bits += i.toString(2).padStart(5, "0");
  }
  const result: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) result.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(result);
}
async function totp(secret: string, counter: number) {
  const counterBytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) { counterBytes[i] = counter & 255; counter = Math.floor(counter / 256); }
  const key = await crypto.subtle.importKey("raw", b32bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = mac[19] & 15;
  const value = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(value % 1000000).padStart(6, "0");
}
function validOtp(v: unknown): v is string { return typeof v === "string" && /^\d{6}$/.test(v); }
function validEmail(v: unknown): v is string { return typeof v === "string" && /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(v); }
function validSecret(v: unknown): v is string { return typeof v === "string" && /^[A-Z2-7]{16,64}$/.test(v); }
function validRecovery(v: unknown): v is string { return typeof v === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(v); }
function phone(v: unknown) {
  if (typeof v !== "string" || v.length > 32 || !/^\+?[0-9 ()-]{7,24}$/.test(v.trim())) return null;
  const n = v.replace(/\D/g, "");
  return n.length >= 8 && n.length <= 15 ? "+" + n : null;
}
async function acceptedCounter(account: Account, code: string) {
  if (!account.mfaSecretEncrypted || !validOtp(code)) return null;
  const secret = await decrypt(account.mfaSecretEncrypted), now = Math.floor(Date.now() / 30000);
  for (const c of [now - 1, now, now + 1]) {
    if (same(code, await totp(secret, c)) && (account.mfaLastCounter === undefined || c > account.mfaLastCounter)) return c;
  }
  return null;
}

const passwordSalt = "academic-demo-password-salt-v1";
accounts.set(ACCOUNT_ID, {
  id: ACCOUNT_ID, email: ACCOUNT_EMAIL, normalizedPhone: ACCOUNT_PHONE, passwordSalt,
  passwordValue: await hash(DEMO_PASSWORD, passwordSalt), mfaEnabled: false, backupCodeValues: [],
});

function parseCookies(request: Request) {
  const out: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
function sessionCookie(value: string, active = true) {
  return `Host-mfa_session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; ${active ? `Max-Age=${absoluteMs / 1000}` : "Max-Age=0"}`;
}
function makeSession(stage: Stage, userId: string | null) {
  const now = Date.now();
  const session: Session = {
    token: token(), csrf: token(24), userId, stage, createdAt: now, lastSeen: now, expiresAt: now + absoluteMs,
    identityFailures: 0, otpFailures: 0, recoveryFailures: 0,
  };
  sessions.set(session.token, session);
  return session;
}

/* Requirement task: retrieve the emitted Host-mfa_session cookie exclusively with bracket notation. */
function current(request: Request) {
  const id = parseCookies(request)["Host-mfa_session"];
  const session = id ? sessions.get(id) : undefined, now = Date.now();
  if (!session || session.invalidated || session.expiresAt < now || session.lastSeen + idleMs < now) {
    if (id) sessions.delete(id);
    return null;
  }
  session.lastSeen = now;
  return session;
}
function originOK(request: Request) { const origin = request.headers.get("origin"); return !origin || trusted.has(origin); }
function headers(request: Request, nonce = token(18)) {
  const h = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  const origin = request.headers.get("origin");
  if (origin && trusted.has(origin)) {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    h.set("Vary", "Origin");
  }
  return h;
}
function reply(request: Request, data: unknown, status = 200, extra?: HeadersInit) {
  const h = headers(request);
  h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((v, k) => h.set(k, v));
  return new Response(JSON.stringify(data), { status, headers: h });
}
function fail(request: Request, status: number, message: string) { return reply(request, { ok: false, message }, status); }
function csrfOK(request: Request, session: Session) { return same(request.headers.get("x-csrf-token") || "", session.csrf); }
function isResponse(v: unknown): v is Response { return v instanceof Response; }
function owner(request: Request, stages: Stage | Stage[]) {
  if (!originOK(request)) return fail(request, 403, "This request was not accepted.");
  const session = current(request), allowed = Array.isArray(stages) ? stages : [stages];
  if (!session || !session.userId || !allowed.includes(session.stage)) return fail(request, 401, "Please sign in again.");
  if (!csrfOK(request, session)) return fail(request, 403, "Please refresh the page and try again.");
  const account = accounts.get(session.userId);
  return account ? { session, account } : fail(request, 401, "Please sign in again.");
}
async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch { return null; }
}
async function useRecovery(session: Session, account: Account, code: unknown) {
  const now = Date.now();
  if (session.recoveryLockedUntil && session.recoveryLockedUntil > now) return "Too many recovery-code attempts. Wait 10 minutes, then try again.";
  if (!validRecovery(code)) return "Enter one recovery code in the format A1B2-C3D4.";
  let found = -1;
  for (let i = 0; i < account.backupCodeValues.length; i++) {
    const saved = account.backupCodeValues[i];
    if (same(await hash(code, saved.salt), saved.value)) found = i;
  }
  if (found < 0) {
    if (++session.recoveryFailures >= 5) session.recoveryLockedUntil = now + lockMs;
    return "That recovery code is not available. Check the code or create a new set.";
  }
  account.backupCodeValues.splice(found, 1);
  session.recoveryFailures = 0;
  session.recoveryLockedUntil = undefined;
  return null;
}
function testMode(request: Request) {
  const host = new URL(request.url).hostname;
  return ACADEMIC_LOCALHOST_TEST_MODE && (host === "localhost" || host === "127.0.0.1" || host === "::1");
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#14263a;--blue:#075d9f;--line:#c6d5df;--pale:#edf6fb;--bad:#8d1f25;--good:#176c48}*{box-sizing:border-box}body{margin:0;background:#eaf1f5;color:var(--ink);font:17px/1.7 Verdana,Arial,sans-serif;letter-spacing:.035em}.shell{min-height:100vh;max-width:560px;margin:auto;padding:20px 18px 34px;background:#fffdf9}header{border-bottom:2px solid var(--line);padding-bottom:15px;margin-bottom:21px}.brand{font-weight:bold;color:#034778}.step,.small,.example{color:#526174;font-size:.9rem}h1{font-size:1.55rem;line-height:1.3;margin:0 0 13px}h2{font-size:1.12rem}p{margin:0 0 15px}.lead{font-size:1.04rem}.card,.note{border:1px solid var(--line);border-radius:12px;padding:17px;margin:16px 0;background:#fff}.note{background:var(--pale);border-left:5px solid var(--blue)}.error{background:#fff0f0;border-left-color:var(--bad);color:#70141a}.success{background:#edf8f1;border-left-color:var(--good)}label{display:block;font-weight:bold;margin:18px 0 5px}input,textarea{width:100%;padding:13px;border:2px solid #8496a7;border-radius:8px;font:inherit;letter-spacing:.04em}.primary,.secondary,.link{font:inherit;font-weight:bold;cursor:pointer}.primary{width:100%;padding:14px;border:0;border-radius:9px;background:var(--blue);color:#fff;margin-top:22px}.secondary{padding:10px;border:2px solid var(--blue);border-radius:8px;background:#fff;color:#034778;margin:8px 6px 0 0}.link{border:0;background:none;color:var(--blue);text-decoration:underline;padding:12px 0}.secret,.codes li{font-family:monospace;letter-spacing:.11em;word-break:break-all}.secret{background:#f0f5f7;padding:12px;border-radius:7px;user-select:all}.codes{list-style:none;padding:0}.codes li{border-bottom:1px solid var(--line);padding:7px;font-weight:bold;user-select:all}.qr{display:block;width:250px;height:250px;margin:16px auto;background:#fff;border:8px solid #fff;image-rendering:pixelated}.logs{border-top:2px solid var(--line);margin-top:28px;padding-top:14px}.logbox{background:#162636;color:#e8f4fb;border-radius:8px;padding:10px;min-height:65px;font:12px/1.45 monospace;max-height:180px;overflow:auto;white-space:pre-wrap}details{margin-top:20px}@media print{header,.primary,.secondary,.link,details,.logs{display:none}.shell{max-width:none}}
</style></head><body><main class="shell"><header><div class="brand">🛡️ Harbour Bank</div><div class="step" id="step">Security setup</div></header><section id="app" aria-live="polite"></section><section class="logs"><h2>🧾 Logs</h2><p class="small">Safe status messages only.</p><div class="logbox" id="logs"></div></section></main>
<script nonce="${nonce}">(()=>{"use strict";
let csrf="",screen="signin",identityPhone="",secret="",uri="",codes=[],visible=true;
const app=document.querySelector("#app"),step=document.querySelector("#step"),logs=document.querySelector("#logs");
function log(text){console.log(text);const line=document.createElement("div");line.textContent=text;logs.append(line);logs.scrollTop=logs.scrollHeight}
function consoleSecret(label,value){console.log(label,value)}
async function api(path,data,method="POST"){const r=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:method==="GET"?undefined:JSON.stringify(data||{})});const j=await r.json().catch(()=>({message:"Something went wrong. Please try again."}));if(!r.ok)throw Error(j.message);return j}
function base(title,progress){app.replaceChildren();step.textContent=progress;const h=document.createElement("h1");h.textContent=title;app.append(h)}
function note(text,type="error"){const n=document.createElement("div");n.className="note "+type;n.textContent=text;app.prepend(n)}
function field(label,id,type,example,autocomplete){const w=document.createElement("div"),l=document.createElement("label"),i=document.createElement("input"),p=document.createElement("p");l.htmlFor=id;l.textContent=label;i.id=id;i.type=type;i.autocomplete=autocomplete||"off";p.className="example";p.textContent=example;w.append(l,i,p);return w}
function button(text,kind="primary"){const b=document.createElement("button");b.type="button";b.className=kind;b.textContent=text;return b}
function help(){const d=document.createElement("details"),s=document.createElement("summary"),p=document.createElement("p");s.textContent="Need help?";p.textContent="Take your time. Nothing disappears while you read. You can safely retry.";d.append(s,p);app.append(d)}
async function copy(value,label,parent){try{await navigator.clipboard.writeText(value);note(label+" copied. Paste it where you need it.","success")}catch(_){const t=document.createElement("textarea");t.readOnly=true;t.value=value;t.setAttribute("aria-label","Selectable "+label);parent.append(t);t.focus();t.select();note("Select the "+label+" below and copy it manually.")}}

/* QR Code Model 2, Version 6, error correction level L, mask 0.
   Format modules are reserved before data placement; output encodes the exact URI. */
function qrSvg(text){
 const raw=new TextEncoder().encode(text),N=41,DATA=136,ECC=18;
 if(raw.length>134)return null;
 const data=[],bits="0100"+raw.length.toString(2).padStart(8,"0")+Array.from(raw,x=>x.toString(2).padStart(8,"0")).join("")+"0000";
 for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8).padEnd(8,"0"),2));
 for(let i=0;data.length<DATA;i++)data.push(i%2?0x11:0xec);
 const exp=[],lg=[];let z=1;for(let i=0;i<512;i++){exp[i]=z;if(i<255)lg[z]=i;z=(z<<1)^(z&128?285:0)}
 const mul=(a,b)=>!a||!b?0:exp[(lg[a]+lg[b])%255];
 const gen=[146,217,67,75,80,17,148,99,60,170,83,19,149,25,75,76,113,44];
 function rs(block){const r=Array(ECC).fill(0);for(const v of block){const f=v^r.shift();r.push(0);for(let j=0;j<ECC;j++)r[j]^=mul(gen[j],f)}return r}
 const a=data.slice(0,68),b=data.slice(68),ea=rs(a),eb=rs(b),stream=[];
 for(let i=0;i<68;i++)stream.push(a[i],b[i]);for(let i=0;i<ECC;i++)stream.push(ea[i],eb[i]);
 const m=Array.from({length:N},()=>Array(N).fill(null)),set=(r,c,v)=>{if(r>=0&&c>=0&&r<N&&c<N)m[r][c]=v};
 function finder(r,c){for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)set(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4)))}
 function align(r,c){for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(r+y,c+x,Math.max(Math.abs(y),Math.abs(x))!==1)}
 finder(0,0);finder(0,N-7);finder(N-7,0);align(34,34);
 for(let i=8;i<N-8;i++){if(m[6][i]===null)set(6,i,i%2===0);if(m[i][6]===null)set(i,6,i%2===0)}
 set(N-8,8,true);
 const format="111011111000100";
 for(let i=0;i<15;i++){const v=format[i]==="1";if(i<6)set(i,8,v);else if(i<8)set(i+1,8,v);else set(N-15+i,8,v);if(i<8)set(8,N-1-i,v);else if(i===8)set(8,7,v);else set(8,14-i,v)}
 let k=0,up=true;
 for(let c=N-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<N;q++){const r=up?N-1-q:q;for(const cc of [c,c-1])if(m[r][cc]===null){let v=k<stream.length*8&&((stream[Math.floor(k/8)]>>(7-k%8))&1)===1;k++;if((r+cc)%2===0)v=!v;set(r,cc,v)}}up=!up}
 let cells="";for(let r=0;r<N;r++)for(let c=0;c<N;c++)if(m[r][c])cells+='<rect x="'+c+'" y="'+r+'" width="1" height="1"/>';
 const svg=document.createElementNS("http://www.w3.org/2000/svg","svg");svg.setAttribute("class","qr");svg.setAttribute("viewBox","0 0 "+N+" "+N);svg.setAttribute("role","img");svg.setAttribute("aria-label","QR code for authenticator setup");svg.innerHTML=cells;return svg;
}
function render(){({signin,identity,provision,challenge,backup,saved,settings})[screen]()}
function signin(){base("Sign in","Step 1 of 4 · Sign in");const f=document.createElement("form"),lead=document.createElement("p"),hint=document.createElement("p");lead.className="lead";lead.textContent="Sign in to start your security setup.";hint.className="note";hint.textContent="Academic demo sign-in: marcus@example.com and MarcusDemo!42.";f.append(field("Email address","email","email","Example: marcus@example.com","email"),field("Password","password","password","Use your saved password","current-password"));const b=button("Sign in");b.type="submit";f.append(b);f.onsubmit=async e=>{e.preventDefault();try{const r=await api("/api/signin",{email:document.querySelector("#email").value,password:document.querySelector("#password").value});csrf=r.csrf;screen="identity";log("Sign-in accepted. Next: confirm identity.");render()}catch(x){note(x.message)}};app.append(lead,hint,f);help()}
function identity(){base("Confirm it is you","Step 2 of 4 · Confirm identity");const f=document.createElement("form"),lead=document.createElement("p");lead.className="lead";lead.textContent="We will send a short code to your account phone.";f.append(lead,field("Mobile number","phone","tel","Example: +1 555 123 4567","tel"));const b=button("Send my code");b.type="submit";f.append(b);f.onsubmit=async e=>{e.preventDefault();identityPhone=document.querySelector("#phone").value;try{const r=await api("/api/identity/request",{phone:identityPhone});if(r.testingCode)consoleSecret("Academic identity OTP",r.testingCode);log("Identity code requested. Enter the code when it arrives.");identityCode()}catch(x){note(x.message)}};app.append(f);help()}
function identityCode(){const f=document.createElement("form");f.append(field("Enter the 6-digit code","code","text","Example: 123456","one-time-code"));const yes=button("Confirm code");yes.type="submit";const again=button("Send a new code","link");again.onclick=async()=>{try{const r=await api("/api/identity/request",{phone:identityPhone});if(r.testingCode)consoleSecret("Academic replacement identity OTP",r.testingCode);log("A replacement identity code was requested.")}catch(x){note(x.message)}};f.append(yes,again);f.onsubmit=async e=>{e.preventDefault();try{const r=await api("/api/identity/verify",{code:document.querySelector("#code").value.trim()});csrf=r.csrf;screen=r.nextStage==="mfaChallenge"?"challenge":"provision";log("Identity confirmed. Continue with your security check.");render()}catch(x){note(x.message)}};app.querySelector("form").replaceWith(f)}
function provision(){base("Set up your authenticator","Step 3 of 4 · Authenticator");const lead=document.createElement("p");lead.className="lead";lead.textContent="Use your authenticator app to scan the QR option, or copy the setup key.";app.append(lead);api("/api/mfa/provision",{}).then(r=>{secret=r.secret;uri=r.provisioningUri;if(r.testingCode)consoleSecret("Academic authenticator verification code",r.testingCode);const card=document.createElement("section"),h=document.createElement("h2"),text=document.createElement("p"),key=document.createElement("div"),cp=button("Copy setup key","secondary");card.className="card";h.textContent="📷 QR setup option";const q=qrSvg(uri);if(q)card.append(h,q);else{const p=document.createElement("p");p.textContent="Use the setup key below.";card.append(h,p)}text.textContent="Setup key";key.className="secret";key.textContent=secret;cp.onclick=()=>copy(secret,"Setup key",card);card.append(text,key,cp);app.append(card);const f=document.createElement("form");f.append(field("Optional: paste setup key to check it","manual","text","Example: ABCD2345EFGH6789"),field("Enter the 6-digit code from your app","code","text","Example: 123456","one-time-code"));const b=button("Verify authenticator");b.type="submit";f.append(b);f.onsubmit=async e=>{e.preventDefault();try{const done=await api("/api/mfa/verify",{code:document.querySelector("#code").value.trim(),manualSecret:document.querySelector("#manual").value.trim()||undefined});csrf=done.csrf;codes=done.codes;visible=true;consoleSecret("Issued recovery codes",codes);log("Authenticator verified. Save your recovery codes next.");screen="backup";render()}catch(x){note(x.message)}};app.append(f);help()}).catch(x=>note(x.message))}
function challenge(){base("Confirm your authenticator","Step 3 of 4 · Security check");const lead=document.createElement("p"),f=document.createElement("form");lead.className="lead";lead.textContent="Enter a code from your existing authenticator app. You may use one recovery code instead.";f.append(lead,field("Authenticator code or recovery code","existingCode","text","Examples: 123456 or A1B2-C3D4","one-time-code"));const b=button("Continue");b.type="submit";f.append(b);f.onsubmit=async e=>{e.preventDefault();try{const r=await api("/api/mfa/existing/verify",{code:document.querySelector("#existingCode").value.trim().toUpperCase()});csrf=r.csrf;log("Authenticator confirmed. MFA settings are available.");screen="settings";render()}catch(x){note(x.message)}};app.append(f);help()}
function backup(){base("Save your recovery codes","Step 4 of 4 · Recovery codes");const lead=document.createElement("p"),card=document.createElement("section");lead.className="lead";lead.textContent="These one-use codes help if you lose your phone. Keep them private.";card.className="card";const toggle=button(visible?"Hide codes":"Reveal codes","secondary");toggle.onclick=()=>{visible=!visible;render()};card.append(toggle);if(visible){const list=document.createElement("ul");list.className="codes";codes.forEach(c=>{const li=document.createElement("li");li.textContent=c;list.append(li)});const cp=button("Copy codes","secondary"),print=button("Print or save as PDF","secondary");cp.onclick=()=>copy(codes.join("\\n"),"Recovery codes",card);print.onclick=()=>window.print();card.append(list,cp,print)}else{const p=document.createElement("p");p.className="note";p.textContent="Your recovery codes are hidden. Select Reveal codes whenever you are ready.";card.append(p)}const done=button("I saved my codes");done.onclick=async()=>{try{const r=await api("/api/recovery/acknowledge",{});csrf=r.csrf;codes=[];log("Recovery codes acknowledged. MFA setup is complete.");screen="saved";render()}catch(x){note(x.message)}};app.append(lead,card,done);help()}
function saved(){base("MFA is ready","Complete · Security setup");note("✓ Your authenticator and recovery codes are ready.","success");const b=button("Go to MFA settings");b.onclick=()=>{screen="settings";render()};app.append(b);help()}
function settings(){base("MFA settings","Security settings");const lead=document.createElement("p"),card=document.createElement("section");lead.className="lead";lead.textContent="🛡️ Your authenticator app is active.";card.className="card";const h=document.createElement("h2");h.textContent="Use a recovery code";card.append(h,field("Recovery code","recovery","text","Example: A1B2-C3D4","one-time-code"));const use=button("Use recovery code");use.onclick=async()=>{try{await api("/api/recovery/verify",{code:document.querySelector("#recovery").value.trim().toUpperCase()});note("Recovery code accepted and used. It cannot be used again.","success");document.querySelector("#recovery").value=""}catch(x){note(x.message)}};card.append(use);const regen=button("Create new recovery codes","secondary");regen.onclick=async()=>{try{const r=await api("/api/recovery/regenerate",{});csrf=r.csrf;codes=r.codes;visible=true;consoleSecret("Regenerated recovery codes",codes);log("New recovery codes created. Save them before continuing.");screen="backup";render()}catch(x){note(x.message)}};const out=button("Log out","link");out.onclick=async()=>{try{await api("/api/logout",{});csrf="";codes=[];screen="signin";log("Signed out. Secure session invalidated.");render()}catch(x){note(x.message)}};app.append(lead,card,regen,out);help()}
api("/api/bootstrap",null,"GET").then(r=>{csrf=r.csrf;screen=r.stage==="signedin"?"identity":r.stage==="provision"?"provision":r.stage==="mfaChallenge"?"challenge":r.stage==="recoveryAck"?"backup":r.stage==="settings"?"settings":"signin";render()}).catch(()=>note("Unable to start securely. Please refresh the page."));
})();</script></body></html>`;
}

Bun.serve({
  port: PORT,
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);

      if (request.method === "OPTIONS") return originOK(request) ? new Response(null, { status: 204, headers: headers(request) }) : fail(request, 403, "This request was not accepted.");
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = token(18), h = headers(request, nonce);
        h.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers: h });
      }

      if (url.pathname === "/api/bootstrap" && request.method === "GET") {
        if (!originOK(request)) return fail(request, 403, "This request was not accepted.");
        let session = current(request), cookie = "";
        if (!session) { session = makeSession("preauth", null); cookie = sessionCookie(session.token); }
        return reply(request, { ok: true, csrf: session.csrf, stage: session.stage }, 200, cookie ? { "Set-Cookie": cookie } : undefined);
      }

      if (url.pathname === "/api/signin" && request.method === "POST") {
        if (!originOK(request)) return fail(request, 403, "This request was not accepted.");
        const old = current(request), data = await body(request);
        if (!old || old.stage !== "preauth" || !csrfOK(request, old)) return fail(request, 403, "Please refresh the page and try again.");
        const email = validEmail(data?.email) ? data.email.toLowerCase() : "";
        const password = typeof data?.password === "string" && data.password.length <= 200 ? data.password : "";
        const account = email === ACCOUNT_EMAIL ? accounts.get(ACCOUNT_ID) : undefined;
        const submitted = await hash(password, account?.passwordSalt || passwordSalt);
        if (!account || !same(submitted, account.passwordValue)) return fail(request, 401, "Check your email and password, then try again.");
        sessions.delete(old.token);
        const session = makeSession("signedin", account.id);
        return reply(request, { ok: true, csrf: session.csrf }, 200, { "Set-Cookie": sessionCookie(session.token) });
      }

      if (url.pathname === "/api/identity/request" && request.method === "POST") {
        const owned = owner(request, "signedin"); if (isResponse(owned)) return owned;
        const now = Date.now();
        if (owned.session.identityLockedUntil && owned.session.identityLockedUntil > now) return fail(request, 429, "Too many attempts. Wait 10 minutes, then request a new code.");
        if (owned.session.identityLastRequestedAt && now - owned.session.identityLastRequestedAt < throttleMs) return fail(request, 429, "Please wait a short moment before requesting another code.");
        const normalized = phone((await body(request))?.phone);
        if (!normalized) return fail(request, 400, "Enter a phone number such as +1 555 123 4567.");
        if (!same(normalized, owned.account.normalizedPhone)) return fail(request, 403, "Use the mobile number saved on this account.");
        owned.session.identityCode = otp();
        owned.session.identityCodeUsed = false;
        owned.session.identityCodeExpires = now + codeMs;
        owned.session.identityLastRequestedAt = now;
        const result: Record<string, unknown> = { ok: true };
        if (testMode(request)) result.testingCode = owned.session.identityCode;
        return reply(request, result);
      }

      if (url.pathname === "/api/identity/verify" && request.method === "POST") {
        const owned = owner(request, "signedin"); if (isResponse(owned)) return owned;
        const now = Date.now(), data = await body(request);
        if (owned.session.identityLockedUntil && owned.session.identityLockedUntil > now) return fail(request, 429, "Too many attempts. Wait 10 minutes, then request a new code.");
        const matches = validOtp(data?.code) && !!owned.session.identityCode && same(data.code, owned.session.identityCode);
        if (owned.session.identityCodeUsed || !owned.session.identityCodeExpires || owned.session.identityCodeExpires < now || !matches) {
          if (++owned.session.identityFailures >= 5) owned.session.identityLockedUntil = now + lockMs;
          return fail(request, 400, "That code did not work. Check the 6 digits or send a new code.");
        }
        owned.session.identityCodeUsed = true;
        owned.session.identityCode = undefined;
        owned.session.identityCodeExpires = undefined;
        owned.session.identityFailures = 0;
        owned.session.identityLockedUntil = undefined;
        owned.session.stage = owned.account.mfaEnabled ? "mfaChallenge" : "provision";
        owned.session.csrf = token(24);
        return reply(request, { ok: true, csrf: owned.session.csrf, nextStage: owned.session.stage });
      }

      if (url.pathname === "/api/mfa/provision" && request.method === "POST") {
        const owned = owner(request, "provision"); if (isResponse(owned)) return owned;
        if (owned.account.mfaEnabled) return fail(request, 400, "Your authenticator is already active.");
        const now = Date.now();
        if (owned.session.otpLockedUntil && owned.session.otpLockedUntil > now) return fail(request, 429, "Authenticator checks are locked. Wait 10 minutes, then try again.");
        const secret = base32(32);
        owned.session.provisionSecret = secret;
        owned.account.mfaSecretEncrypted = await encrypt(secret);
        const provisioningUri = `otpauth://totp/Harbour%3Amarcus?secret=${secret}&issuer=Harbour&algorithm=SHA1&digits=6&period=30`;
        const result: Record<string, unknown> = { ok: true, secret, provisioningUri };
        if (testMode(request)) result.testingCode = await totp(secret, Math.floor(now / 30000));
        return reply(request, result);
      }

      if (url.pathname === "/api/mfa/verify" && request.method === "POST") {
        const owned = owner(request, "provision"); if (isResponse(owned)) return owned;
        const now = Date.now(), data = await body(request);
        if (owned.session.otpLockedUntil && owned.session.otpLockedUntil > now) return fail(request, 429, "Too many attempts. Wait 10 minutes, then try again.");
        let secretMatches = !!owned.session.provisionSecret;
        if (data?.manualSecret !== undefined) secretMatches = secretMatches && validSecret(data.manualSecret) && same(data.manualSecret, owned.session.provisionSecret!);
        const counter = secretMatches && validOtp(data?.code) ? await acceptedCounter(owned.account, data.code) : null;
        if (counter === null) {
          if (++owned.session.otpFailures >= 5) owned.session.otpLockedUntil = now + lockMs;
          return fail(request, 400, !secretMatches ? "That setup key does not match this setup. Copy the key again, then retry." : "That code did not work. Check the 6 digits in your authenticator app and try again.");
        }
        owned.account.mfaLastCounter = counter;
        owned.account.mfaEnabled = true;
        owned.session.provisionSecret = undefined;
        owned.session.otpFailures = 0;
        owned.session.otpLockedUntil = undefined;
        const recovery = await newRecoveryCodes();
        owned.account.backupCodeValues = recovery.values;
        owned.session.stage = "recoveryAck";
        owned.session.csrf = token(24);
        return reply(request, { ok: true, csrf: owned.session.csrf, codes: recovery.codes });
      }

      if (url.pathname === "/api/mfa/existing/verify" && request.method === "POST") {
        const owned = owner(request, "mfaChallenge"); if (isResponse(owned)) return owned;
        if (!owned.account.mfaEnabled) return fail(request, 400, "Set up your authenticator first.");

        /* Task: parse the request body once and retain its code value for both verification paths. */
        const data = await body(request);
        const submitted = typeof data?.code === "string" ? data.code : "";
        const code = submitted.toUpperCase();
        const now = Date.now();

        if (validRecovery(code)) {
          const error = await useRecovery(owned.session, owned.account, code);
          if (error) return fail(request, 400, error);
        } else {
          if (owned.session.otpLockedUntil && owned.session.otpLockedUntil > now) return fail(request, 429, "Too many attempts. Wait 10 minutes, then try again.");
          const counter = await acceptedCounter(owned.account, code);
          if (counter === null) {
            if (++owned.session.otpFailures >= 5) owned.session.otpLockedUntil = now + lockMs;
            return fail(request, 400, "That authenticator code did not work. Check the 6 digits or use a recovery code.");
          }
          owned.account.mfaLastCounter = counter;
          owned.session.otpFailures = 0;
          owned.session.otpLockedUntil = undefined;
        }
        owned.session.stage = "settings";
        owned.session.csrf = token(24);
        return reply(request, { ok: true, csrf: owned.session.csrf, nextStage: "settings" });
      }

      if (url.pathname === "/api/recovery/acknowledge" && request.method === "POST") {
        const owned = owner(request, "recoveryAck"); if (isResponse(owned)) return owned;
        owned.session.stage = "settings";
        owned.session.csrf = token(24);
        return reply(request, { ok: true, csrf: owned.session.csrf });
      }

      if (url.pathname === "/api/recovery/verify" && request.method === "POST") {
        const owned = owner(request, "settings"); if (isResponse(owned)) return owned;
        if (!owned.account.mfaEnabled) return fail(request, 400, "Set up your authenticator first.");
        const error = await useRecovery(owned.session, owned.account, (await body(request))?.code);
        return error ? fail(request, 400, error) : reply(request, { ok: true });
      }

      if (url.pathname === "/api/recovery/regenerate" && request.method === "POST") {
        const owned = owner(request, "settings"); if (isResponse(owned)) return owned;
        if (!owned.account.mfaEnabled) return fail(request, 400, "Set up your authenticator before creating recovery codes.");
        const recovery = await newRecoveryCodes();
        owned.account.backupCodeValues = recovery.values;
        owned.session.stage = "recoveryAck";
        owned.session.csrf = token(24);
        return reply(request, { ok: true, csrf: owned.session.csrf, codes: recovery.codes });
      }

      if (url.pathname === "/api/logout" && request.method === "POST") {
        if (!originOK(request)) return fail(request, 403, "This request was not accepted.");
        const session = current(request);
        if (!session || !csrfOK(request, session)) return fail(request, 403, "Please refresh the page and try again.");
        session.invalidated = true;
        sessions.delete(session.token);
        return reply(request, { ok: true }, 200, { "Set-Cookie": sessionCookie("", false) });
      }

      return fail(request, 404, "Page not found.");
    } catch {
      return fail(request, 500, "Something went wrong. Please try again.");
    }
  },
});
