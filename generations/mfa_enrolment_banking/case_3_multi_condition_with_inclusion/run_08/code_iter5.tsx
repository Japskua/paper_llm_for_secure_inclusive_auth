
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const sessions = new Map<string, Session>();

/* Security requirement 2: only exact local HTTPS origins are trusted. */
const allowedOrigins = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

const USER = { id: "acct_marcus_01", email: "marcus@example.test" };
const DEMO_OWNER_CREDENTIAL = "Marcus-Access-54";
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFE_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60 * 1000;
const MAX_JSON_BODY_BYTES = 4096;

type Challenge = { accountId: string; value: string; expires: number; used: boolean };
type AccountMfaState = {
  identityAttempts: number; identityLockedUntil: number;
  totpAttempts: number; totpLockedUntil: number;
  recoveryAttempts: number; recoveryLockedUntil: number;
  encryptedSecret?: string; acceptedTotpSteps: Set<number>;
  recoveryHashes: Set<string>; mfaEnrolled: boolean;
};
type Session = {
  id: string; userId: string; csrf: string; createdAt: number; lastSeen: number;
  identityVerified: boolean; mfaVerified: boolean; identityChallenge?: Challenge;
};

const accountMfa: AccountMfaState = {
  identityAttempts: 0, identityLockedUntil: 0, totpAttempts: 0, totpLockedUntil: 0,
  recoveryAttempts: 0, recoveryLockedUntil: 0, acceptedTotpSteps: new Set(),
  recoveryHashes: new Set(), mfaEnrolled: false,
};

function randomBytes(count: number) {
  const bytes = new Uint8Array(count);
  crypto.getRandomValues(bytes);
  return bytes;
}
function base64Url(bytes: Uint8Array) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromBase64Url(value: string) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
function secureToken(bytes = 32) { return base64Url(randomBytes(bytes)); }
function randomDigits() {
  const value = new Uint32Array(1);
  crypto.getRandomValues(value);
  return String(value[0] % 1_000_000).padStart(6, "0");
}
const recoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function recoveryCode() {
  const bytes = randomBytes(8);
  let output = "";
  for (const byte of bytes) output += recoveryAlphabet[byte % recoveryAlphabet.length];
  return output.slice(0, 4) + "-" + output.slice(4);
}
function secretValue() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = randomBytes(20);
  let output = "";
  for (const byte of bytes) output += alphabet[byte % alphabet.length];
  return output;
}

const masterMaterial = randomBytes(32);
const masterKey = await crypto.subtle.importKey("raw", masterMaterial, "AES-GCM", false, ["encrypt", "decrypt"]);
const hashPepper = secureToken(24);

async function protectAtRest(value: string) {
  const iv = randomBytes(12);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(value));
  const packed = new Uint8Array(12 + cipher.byteLength);
  packed.set(iv);
  packed.set(new Uint8Array(cipher), 12);
  return base64Url(packed);
}
async function revealAtRest(value: string) {
  const packed = fromBase64Url(value);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: packed.slice(0, 12) }, masterKey, packed.slice(12));
  return decoder.decode(plain);
}
async function codeHash(value: string) {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(hashPepper + ":" + value));
  return base64Url(new Uint8Array(hash));
}
function createChallenge(accountId: string): Challenge {
  return { accountId, value: randomDigits(), expires: Date.now() + CODE_LIFE_MS, used: false };
}
function validOrigin(req: Request) {
  const origin = req.headers.get("origin");
  return origin === null || allowedOrigins.has(origin);
}

function secureHeaders(nonce: string, origin?: string | null) {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  if (origin && allowedOrigins.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}
function json(data: unknown, status = 200, req?: Request) {
  return new Response(JSON.stringify(data), {
    status, headers: secureHeaders(secureToken(16), req?.headers.get("origin")),
  });
}
function getCookie(req: Request, key: string) {
  const raw = req.headers.get("cookie") || "";
  const part = raw.split(";").map(v => v.trim()).find(v => v.startsWith(key + "="));
  return part ? part.slice(key.length + 1) : "";
}
function htmlResponse() {
  const nonce = secureToken(16);
  const headers = secureHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(page(nonce), { headers });
}

/* Security requirements 1 and 5: every protected endpoint checks account owner session. */
function authenticated(req: Request): { session?: Session; error?: Response } {
  const id = getCookie(req, "mfa_session");
  const session = sessions.get(id);
  const now = Date.now();
  if (!session) return { error: json({ error: "Please sign in again." }, 401, req) };
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return { error: json({ error: "Your session ended for safety. Please sign in again." }, 401, req) };
  }
  session.lastSeen = now;
  return { session };
}

/* Task: body size is checked before JSON.parse/request.json processing. */
async function requestBody(req: Request): Promise<Record<string, unknown>> {
  if (!(req.headers.get("content-type") || "").toLowerCase().includes("application/json")) throw new Error("invalid");
  const statedLength = req.headers.get("content-length");
  if (statedLength && (!/^\d+$/.test(statedLength) || Number(statedLength) > MAX_JSON_BODY_BYTES)) throw new Error("too-large");
  if (!req.body) throw new Error("invalid");
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      length += result.value.byteLength;
      if (length > MAX_JSON_BODY_BYTES) {
        await reader.cancel();
        throw new Error("too-large");
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const all = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { all.set(chunk, offset); offset += chunk.byteLength; }
  let body: unknown;
  try { body = JSON.parse(decoder.decode(all)); } catch { throw new Error("invalid"); }
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("invalid");
  return body as Record<string, unknown>;
}
function stateAllowed(req: Request, session: Session, body: Record<string, unknown>) {
  if (req.headers.get("x-csrf-token") !== session.csrf) return "This request could not be confirmed. Refresh and try again.";
  if ("userId" in body && body.userId !== session.userId) return "This account request is not allowed.";
  return "";
}

/* Task: bounded safe-email and bounded authentication input validation. */
function safeEmail(value: unknown) {
  return typeof value === "string" &&
    value.length >= 3 && value.length <= 120 &&
    /^[A-Za-z0-9.!#$%&'*+/=?^_\`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/.test(value);
}
function safeCredential(value: unknown) {
  return typeof value === "string" && value.length >= 1 && value.length <= 128 && /^[\x20-\x7E]+$/.test(value);
}
function safeCode(value: unknown, recovery = false) {
  return typeof value === "string" &&
    (recovery ? value.length === 9 && /^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(value) : value.length === 6 && /^\d{6}$/.test(value));
}
function lockMessage(kind: "identity" | "totp" | "recovery") {
  if (kind === "identity") return "Too many tries. Please wait 15 minutes, then request a new code.";
  if (kind === "recovery") return "Too many recovery code tries. Please wait 15 minutes, then try again.";
  return "Too many tries. Please wait 15 minutes, then try again.";
}

async function verifyChallenge(session: Session, code: string) {
  const challenge = session.identityChallenge;
  if (accountMfa.identityLockedUntil > Date.now()) return { ok: false, message: lockMessage("identity") };
  if (!challenge || challenge.accountId !== session.userId) return { ok: false, message: "Request a new code, then try again." };
  if (challenge.used) return { ok: false, message: "That code was already used. Request a new code." };
  if (challenge.expires < Date.now()) return { ok: false, message: "That code has expired. Request a new code." };
  if (challenge.value !== code) {
    accountMfa.identityAttempts++;
    if (accountMfa.identityAttempts >= MAX_FAILURES) {
      accountMfa.identityLockedUntil = Date.now() + LOCK_MS;
      return { ok: false, message: lockMessage("identity") };
    }
    return { ok: false, message: `That code does not match. Check the six numbers and try again (${MAX_FAILURES - accountMfa.identityAttempts} tries left).` };
  }
  challenge.used = true; accountMfa.identityAttempts = 0; accountMfa.identityLockedUntil = 0;
  return { ok: true, message: "" };
}
function base32Decode(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, count = 0;
  const result: number[] = [];
  for (const char of value.toUpperCase()) {
    const n = alphabet.indexOf(char);
    if (n < 0) throw new Error("invalid");
    bits = (bits << 5) | n; count += 5;
    if (count >= 8) { result.push((bits >>> (count - 8)) & 255); count -= 8; }
  }
  return new Uint8Array(result);
}
async function totpForStep(secret: string, step: number) {
  const counter = new Uint8Array(8);
  let value = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(value & 255n); value >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = signed[19] & 15;
  const number = ((signed[offset] & 127) << 24) | (signed[offset + 1] << 16) | (signed[offset + 2] << 8) | signed[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}
async function verifyTotp(code: string) {
  if (!accountMfa.encryptedSecret) return { ok: false, message: "Return to set-up and add an authenticator first." };
  if (accountMfa.totpLockedUntil > Date.now()) return { ok: false, message: lockMessage("totp") };
  const secret = await revealAtRest(accountMfa.encryptedSecret);
  const current = Math.floor(Date.now() / 30000);
  for (let offset = -1; offset <= 1; offset++) {
    const step = current + offset;
    if (await totpForStep(secret, step) === code) {
      if (accountMfa.acceptedTotpSteps.has(step)) return { ok: false, message: "That authenticator code was already used. Wait for your app to show a new code." };
      accountMfa.acceptedTotpSteps.add(step); accountMfa.totpAttempts = 0; accountMfa.totpLockedUntil = 0;
      return { ok: true, message: "" };
    }
  }
  accountMfa.totpAttempts++;
  if (accountMfa.totpAttempts >= MAX_FAILURES) {
    accountMfa.totpLockedUntil = Date.now() + LOCK_MS;
    return { ok: false, message: lockMessage("totp") };
  }
  return { ok: false, message: `That code does not match your authenticator. Check the six numbers and try again (${MAX_FAILURES - accountMfa.totpAttempts} tries left).` };
}
async function verifyRecoveryCode(submitted: unknown) {
  if (accountMfa.recoveryLockedUntil > Date.now()) return { ok: false, message: lockMessage("recovery") };
  const code = typeof submitted === "string" && submitted.length <= 9 ? submitted.trim().toUpperCase() : "";
  let valid = safeCode(code, true);
  if (valid) valid = accountMfa.recoveryHashes.delete(await codeHash(code));
  if (valid) {
    accountMfa.recoveryAttempts = 0; accountMfa.recoveryLockedUntil = 0;
    return { ok: true, message: "" };
  }
  accountMfa.recoveryAttempts++;
  if (accountMfa.recoveryAttempts >= MAX_FAILURES) {
    accountMfa.recoveryLockedUntil = Date.now() + LOCK_MS;
    return { ok: false, message: lockMessage("recovery") };
  }
  return { ok: false, message: safeCode(code, true) ? `That recovery code cannot be used. Try another saved code (${MAX_FAILURES - accountMfa.recoveryAttempts} tries left).` : `Use the format ABCD-EFGH. Try again (${MAX_FAILURES - accountMfa.recoveryAttempts} tries left).` };
}
function createSession() {
  const now = Date.now();
  const session: Session = { id: secureToken(), userId: USER.id, csrf: secureToken(), createdAt: now, lastSeen: now, identityVerified: false, mfaVerified: false, identityChallenge: createChallenge(USER.id) };
  sessions.set(session.id, session);
  return session;
}
function sessionCookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}
function provisioningUri(secret: string) {
  return `otpauth://totp/Example%20Bank:${encodeURIComponent(USER.email)}?secret=${secret}&issuer=Example%20Bank&algorithm=SHA1&digits=6&period=30`;
}
async function generateRecovery() {
  const codes = Array.from({ length: 8 }, recoveryCode);
  accountMfa.recoveryHashes = new Set(await Promise.all(codes.map(codeHash)));
  return codes;
}
async function provision(fresh: boolean) {
  if (fresh && accountMfa.totpLockedUntil > Date.now()) throw new Error(lockMessage("totp"));
  if (fresh || !accountMfa.encryptedSecret) {
    const secret = secretValue();
    accountMfa.encryptedSecret = await protectAtRest(secret);
    accountMfa.mfaEnrolled = false;
    accountMfa.acceptedTotpSteps.clear();
  }
  const secret = await revealAtRest(accountMfa.encryptedSecret);
  return { secret, uri: provisioningUri(secret), testSecret: secret, testCode: await totpForStep(secret, Math.floor(Date.now() / 30000)) };
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Example Bank — security set-up</title>
<style nonce="${nonce}">
:root{--ink:#172535;--blue:#075bb8;--pale:#edf6ff;--line:#c9d6e2;--bad:#a7202c;--good:#146c43}*{box-sizing:border-box}body{margin:0;background:#f2f6f9;color:var(--ink);font:17px/1.7 Arial,Verdana,sans-serif;letter-spacing:.025em}.shell{max-width:520px;min-height:100vh;margin:auto;background:white;padding:20px 22px 35px}header{border-bottom:1px solid var(--line);margin-bottom:24px}.brand{font-weight:bold;color:var(--blue);margin:0}.progress{color:#526476;font-size:.92rem;margin:8px 0 14px}h1{font-size:1.62rem;line-height:1.28}label{display:block;font-weight:bold;margin:15px 0 5px}input{width:100%;min-height:53px;border:2px solid #7c90a4;border-radius:8px;padding:10px;font:inherit;letter-spacing:.06em}.primary,.secondary{min-height:52px;padding:10px;border-radius:8px;font:inherit;font-weight:bold;cursor:pointer}.primary{width:100%;margin-top:20px;border:0;background:var(--blue);color:white}.secondary{border:1px solid var(--blue);background:white;color:var(--blue);margin:8px 7px 0 0}.card,.note{border:1px solid var(--line);border-radius:10px;padding:15px;margin:17px 0}.note{background:var(--pale);border-left:5px solid var(--blue)}.error,.success{padding:10px 13px;border-left:5px solid;margin:14px 0;font-weight:bold}.error{background:#fff0f1;border-color:var(--bad)}.success{background:#edf9f1;border-color:var(--good)}.hint,.small{color:#526476;font-size:.92rem}.code{font-family:monospace;word-break:break-all;letter-spacing:.08em;background:#f4f7f9;padding:10px;border-radius:7px}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:0;list-style:none;font-family:monospace}.codes li{background:#f4f7f9;padding:8px;text-align:center}.logs{margin-top:26px;border-top:1px solid var(--line);padding-top:12px}summary{font-weight:bold;color:var(--blue)}#logbox{white-space:pre-wrap;max-height:160px;overflow:auto;background:#152536;color:#e7f2ff;padding:10px;border-radius:7px;font:12px/1.45 monospace}.check{display:flex;gap:10px;align-items:center}.check input{width:25px}.qr{width:246px;height:246px;margin:12px auto;background:#fff;display:block;border:1px solid var(--line);image-rendering:pixelated}.verify{font-size:.85rem;word-break:break-word}button:focus,input:focus{outline:3px solid #f0a100;outline-offset:2px}@media(max-width:360px){.shell{padding:18px 16px;font-size:16px}.qr{width:220px;height:220px}}</style></head>
<body><div class="shell"><header><p class="brand">◈ Example Bank security set-up</p><p id="progress" class="progress"></p></header><main id="app" aria-live="polite"></main></div>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",screen="signin",pendingEmail="",provision={secret:"",uri:""},codes=[],ack=false;
const app=document.getElementById("app"),progress=document.getElementById("progress"),logs=[];
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function log(s){console.log(s);logs.push(s);const e=document.getElementById("logbox");if(e)e.textContent=logs.join("\\n")}
function footer(){return '<aside class="note"><strong>ⓘ Need help?</strong><br><span class="small">Take your time. You can retry or request a fresh code without penalty.</span></aside><details class="logs"><summary>▣ Logs for this demo</summary><div id="logbox">'+esc(logs.join("\\n"))+'</div><p class="small">Test values appear here and in the browser console.</p></details>'}
function msg(t,good){return t?'<div class="'+(good?"success":"error")+'" role="alert">'+esc(t)+"</div>":""}
async function api(path,body={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body)});const d=await r.json().catch(()=>({error:"Something went wrong. Please try again."}));if(!r.ok)throw Error(d.error||"Something went wrong. Please try again.");return d}
function copy(t,ok){navigator.clipboard.writeText(t).then(()=>render(screen,ok,true)).catch(()=>render(screen,"Copy did not work. Please select the value and copy it another way."))}

/* Task: standards-compliant QR Model 2 byte-mode encoder.
   It selects a fitting version, uses QR-L error correction blocks, RS parity,
   alignment/timing patterns, all eight masks, BCH format bits, and penalty selection. */
function drawQR(text){
 const data=new TextEncoder().encode(text),E=[7,10,15,20,26,18,20,24,30,18,20,24,26,30,22,24,28,30,28,28,28,28,30,30,26,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30],B=[1,1,1,1,1,2,2,2,2,4,4,4,4,4,6,6,6,6,7,8,8,9,9,10,12,12,12,13,14,15,16,17,18,19,19,20,21,21,22,24];
 let v=0;
 for(let i=1;i<=40;i++){let raw=(16*i+128)*i+64;if(i>=2){const n=Math.floor(i/7)+2;raw-=(25*n-10)*n-55;if(i>=7)raw-=36}const cap=Math.floor((raw/8-E[i-1]*B[i-1])*8);if(4+(i<10?8:16)+data.length*8<=cap){v=i;break}}
 if(!v)throw Error("This set-up link is too long for a QR code.");
 const size=v*4+17,raw=(()=>{let n=(16*v+128)*v+64;if(v>=2){const a=Math.floor(v/7)+2;n-=(25*a-10)*a-55;if(v>=7)n-=36}return n})(),dc=Math.floor(raw/8)-E[v-1]*B[v-1],bits=[];
 const put=(x,n)=>{for(let i=n-1;i>=0;i--)bits.push((x>>>i)&1)};put(4,4);put(data.length,v<10?8:16);data.forEach(x=>put(x,8));put(0,Math.min(4,dc*B[v-1]*8-bits.length));while(bits.length%8)bits.push(0);
 const dat=[];for(let i=0;i<bits.length;i+=8)dat.push(bits.slice(i,i+8).reduce((a,x)=>a*2+x,0));for(let i=0;dat.length<dc*B[v-1];i++)dat.push(i%2?17:236);
 const exp=[],lg=[];let z=1;for(let i=0;i<255;i++){exp[i]=z;lg[z]=i;z<<=1;if(z&256)z^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];const mul=(a,b)=>a&&b?exp[lg[a]+lg[b]]:0;
 const gen=[1];for(let i=0;i<E[v-1];i++){const n=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){n[j]^=gen[j];n[j+1]^=mul(gen[j],exp[i])}gen.splice(0,gen.length,...n)}
 const blocks=[],par=[];let k=0,short=B[v-1]-raw%B[v-1];for(let i=0;i<B[v-1];i++){let len=dc+(i>=short?1:0);blocks.push(dat.slice(k,k+len));k+=len}
 for(const block of blocks){const r=Array(E[v-1]).fill(0);for(const d of block){const f=d^r.shift();r.push(0);for(let j=0;j<E[v-1];j++)r[j]^=mul(gen[j+1],f)}par.push(r)}
 const stream=[];for(let i=0;i<Math.max(...blocks.map(x=>x.length));i++)for(const b of blocks)if(i<b.length)stream.push(b[i]);for(let i=0;i<E[v-1];i++)for(const p of par)stream.push(p[i]);
 const align=()=>{if(v===1)return [];const n=Math.floor(v/7)+2,step=v===32?26:Math.ceil((v*4+n*2+1)/(n*2-2))*2,a=[6];for(let p=size-7;a.length<n;p-=step)a.splice(1,0,p);return a};
 function matrix(mask){
  const m=Array.from({length:size},()=>Array(size).fill(null)),set=(r,c,x)=>{if(r>=0&&c>=0&&r<size&&c<size)m[r][c]=!!x},finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)set(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4)))};
  finder(0,0);finder(size-7,0);finder(0,size-7);const a=align();for(const r of a)for(const c of a)if(m[r][c]===null)for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(r+y,c+x,Math.max(Math.abs(x),Math.abs(y))!==1);
  for(let i=8;i<size-8;i++){if(m[i][6]===null)set(i,6,i%2===0);if(m[6][i]===null)set(6,i,i%2===0)}set(size-8,8,1);
  let fmt=(1<<3)|mask,rem=fmt;for(let i=0;i<10;i++)rem=(rem<<1)^(((rem>>>9)&1)*0x537);fmt=((fmt<<10)|rem)^0x5412;
  for(let i=0;i<15;i++){const bit=(fmt>>>i)&1,set(i<6?i:i<8?i+1:size-15+i,8,bit),set(8,i<8?size-i-1:i<9?15-i-1:15-i,bit)}
  let bit=0,up=true;const inv=(r,c)=>mask===0?(r+c)%2===0:mask===1?r%2===0:mask===2?c%3===0:mask===3?(r+c)%3===0:mask===4?(Math.floor(r/2)+Math.floor(c/3))%2===0:mask===5?(r*c)%2+(r*c)%3===0:mask===6?((r*c)%2+(r*c)%3)%2===0:((r+c)%2+(r*c)%3)%2===0;
  for(let c=size-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<size;q++){const r=up?size-1-q:q;for(let x=0;x<2;x++)if(m[r][c-x]===null){const val=bit<stream.length*8?((stream[bit>>>3]>>>(7-(bit&7)))&1):0;bit++;set(r,c-x,val^inv(r,c-x))}}up=!up}return m;
 }
 function score(m){let s=0;for(let r=0;r<size;r++)for(let c=0;c<size;c++){let same=0;for(let y=-1;y<=1;y++)for(let x=-1;x<=1;x++)if(x||y){const rr=r+y,cc=c+x;if(rr>=0&&cc>=0&&rr<size&&cc<size&&m[rr][cc]===m[r][c])same++}if(same>5)s+=3+same-5}for(let r=0;r<size;r++)for(let c=0;c<size-6;c++)if(m[r].slice(c,c+7).join("")==="1011101")s+=40;for(let c=0;c<size;c++)for(let r=0;r<size-6;r++){let x="";for(let i=0;i<7;i++)x+=m[r+i][c]?1:0;if(x==="1011101")s+=40}let dark=0;for(const row of m)for(const x of row)dark+=x;s+=Math.floor(Math.abs(dark*20-size*size*10)/size/size)*10;return s}
 let best=matrix(0),bestScore=score(best);for(let i=1;i<8;i++){const q=matrix(i),s=score(q);if(s<bestScore){best=q;bestScore=s}}
 const c=document.getElementById("qr"),ctx=c.getContext("2d"),scale=c.width/size;ctx.fillStyle="#fff";ctx.fillRect(0,0,c.width,c.height);ctx.fillStyle="#000";for(let r=0;r<size;r++)for(let col=0;col<size;col++)if(best[r][col])ctx.fillRect(Math.round(col*scale),Math.round(r*scale),Math.ceil(scale),Math.ceil(scale));
}
function render(next,notice="",good=false){
 screen=next;progress.textContent={signin:"Step 1 of 7",owner:"Step 2 of 7",identity:"Step 3 of 7",setup:"Step 4 of 7",confirm:"Step 5 of 7",recovery:"Step 6 of 7",done:"Step 7 of 7",recoververify:"Recovery code check"}[next]||"";
 let h="";
 if(next==="signin")h='<h1>Sign in to set up extra protection</h1><p>We will help you add a second step before high-value payments.</p>'+msg(notice,good)+'<form id="sign"><label>Email address</label><input id="email" type="email" autocomplete="email" placeholder="name@example.com" required><p class="hint">Example: marcus@example.test</p><button class="primary">Continue</button></form>';
 if(next==="owner")h='<h1>Confirm your sign-in</h1><p>First, use your account credential. This keeps identity codes private.</p>'+msg(notice,good)+'<form id="ownerform"><label>Account credential</label><input id="credential" type="password" autocomplete="current-password" maxlength="128" placeholder="Example: Marcus-Access-54" required><p class="hint">Demo credential: Marcus-Access-54</p><button class="primary">Confirm and send code</button></form><button class="secondary" id="back">← Back</button>';
 if(next==="identity")h='<h1>Check it is you</h1><p>We sent a six-number code to your email in this safe demo.</p>'+msg(notice,good)+'<form id="identity"><label>Email code</label><input id="code" autocomplete="one-time-code" inputmode="numeric" maxlength="6" placeholder="Example: 123456" required><button class="primary">Verify code</button></form><button class="secondary" id="resend">↻ Send a new code</button>';
 if(next==="setup")h='<h1>Add your authenticator</h1><p>Use your authenticator app. Scanning is easier than typing.</p>'+msg(notice,good)+'<section class="note"><strong>▣ Scan this set-up pattern</strong><canvas id="qr" class="qr" width="246" height="246" aria-label="Authenticator set-up QR code"></canvas><strong>✓ QR check</strong><p class="small verify">This QR code contains exactly the same set-up link and secret shown below.</p><div id="payloadcheck" class="code verify"></div><span class="small">Or use the manual secret below.</span></section><button class="secondary" id="copyuri">⧉ Copy set-up link</button><div class="card"><strong>Manual secret</strong><div id="secret" class="code"></div><button class="secondary" id="copysecret">⧉ Copy secret</button></div><button class="primary" id="continue">I added it — continue</button>';
 if(next==="confirm")h='<h1>Check your authenticator</h1><p>Open the app and enter the six-number code it shows.</p>'+msg(notice,good)+'<form id="otpform"><label>Authenticator code</label><input id="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6" placeholder="Example: 123456" required><p class="hint">There is no reading timer.</p><button class="primary">Verify authenticator</button></form><button class="secondary" id="fresh">↻ Start with a new set-up code</button>';
 if(next==="recovery")h='<h1>Save recovery codes</h1><p>These one-use codes help if you lose your phone. Keep them somewhere private.</p>'+msg(notice,good)+(codes.length?'<section class="card"><ul class="codes">'+codes.map(c=>'<li>'+esc(c)+'</li>').join("")+'</ul><button class="secondary" id="copycodes">⧉ Copy codes</button><button class="secondary" id="regen">↻ Make new codes</button></section><div class="check"><input id="ack" type="checkbox" '+(ack?"checked":"")+'><label>I saved my recovery codes in a private place.</label></div><button class="primary" id="finish">Finish set-up</button>':'<button class="primary" id="make">Show recovery codes</button>');
 if(next==="done")h='<h1>✓ Extra protection is ready</h1><p>Your authenticator is set up. You can now approve protected payments.</p>'+msg(notice||"You have completed MFA enrolment.",true)+'<button class="primary" id="tryrecovery">Use a recovery code</button><button class="secondary" id="logout">Sign out safely</button>';
 if(next==="recoververify")h='<h1>Use a recovery code</h1><p>Enter one saved code if you cannot use your authenticator.</p>'+msg(notice,good)+'<form id="recoveryform"><label>Recovery code</label><input id="recoverycode" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" maxlength="9" placeholder="Example: ABCD-EFGH" required><p class="hint">Use one code once. Format: ABCD-EFGH.</p><button class="primary">Verify recovery code</button></form><button class="secondary" id="backdone">← Back</button>';
 app.innerHTML=h+footer();bind();
 if(next==="setup"){api("/api/mfa/provision").then(d=>{provision=d;log("[Demo] Authenticator secret: "+d.testSecret);log("[Demo] Authenticator verification code: "+d.testCode);document.getElementById("secret").textContent=d.secret;document.getElementById("payloadcheck").textContent=d.uri;drawQR(d.uri)}).catch(e=>render("identity",e.message))}
}
function bind(){
 const on=(id,fn)=>{const e=document.getElementById(id);if(e)e.onclick=fn};
 if(screen==="signin")document.getElementById("sign").onsubmit=async e=>{e.preventDefault();pendingEmail=document.getElementById("email").value.trim();try{await api("/api/auth/signin",{email:pendingEmail});render("owner","Continue with your account credential.",true)}catch(x){render("signin",x.message)}};
 if(screen==="owner"){document.getElementById("ownerform").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/auth/owner",{email:pendingEmail,credential:document.getElementById("credential").value});csrf=d.csrf;log("[Demo] Identity verification code: "+d.testCode);render("identity","A code was sent.",true)}catch(x){render("owner",x.message)}};on("back",()=>render("signin"))}
 if(screen==="identity"){document.getElementById("identity").onsubmit=async e=>{e.preventDefault();try{await api("/api/identity/verify",{code:document.getElementById("code").value.trim()});render("setup","Identity confirmed. Now add your authenticator.",true)}catch(x){render("identity",x.message)}};on("resend",async()=>{try{const d=await api("/api/identity/resend");log("[Demo] New identity code: "+d.testCode);render("identity","A new code was sent.",true)}catch(x){render("identity",x.message)}})}
 if(screen==="setup"){on("copyuri",()=>copy(provision.uri,"Set-up link copied."));on("copysecret",()=>copy(provision.secret,"Manual secret copied."));on("continue",()=>render("confirm"))}
 if(screen==="confirm"){document.getElementById("otpform").onsubmit=async e=>{e.preventDefault();try{await api("/api/mfa/verify",{code:document.getElementById("otp").value.trim()});render("recovery","Authenticator confirmed. Save recovery codes next.",true)}catch(x){render("confirm",x.message)}};on("fresh",async()=>{try{await api("/api/mfa/provision/new");render("setup","A fresh set-up code was created.",true)}catch(x){render("confirm",x.message)}})}
 if(screen==="recovery"){const make=async()=>{try{const d=await api("/api/mfa/recovery/generate");codes=d.codes;ack=false;log("[Demo] Recovery codes: "+codes.join(", "));render("recovery","Your recovery codes are ready.",true)}catch(x){render("recovery",x.message)}};on("make",make);on("regen",make);on("copycodes",()=>copy(codes.join("\\n"),"Recovery codes copied."));const a=document.getElementById("ack");if(a)a.onchange=()=>ack=a.checked;on("finish",()=>ack?render("done"):render("recovery","Please tick the box after you have saved the codes."))}
 if(screen==="done"){on("tryrecovery",()=>render("recoververify"));on("logout",async()=>{try{await api("/api/auth/logout")}catch(_){}csrf="";codes=[];render("signin","You are signed out safely.",true)})}
 if(screen==="recoververify"){document.getElementById("recoveryform").onsubmit=async e=>{e.preventDefault();try{await api("/api/mfa/recovery/verify",{code:document.getElementById("recoverycode").value.trim().toUpperCase()});render("recoververify","Recovery code accepted. It cannot be used again.",true)}catch(x){render("recoververify",x.message)}};on("backdone",()=>render("done"))}
}
render("signin");})();
</script></body></html>`;
}

async function fixedSigninDelay() {
  await new Promise(resolve => setTimeout(resolve, 180));
}

async function handle(req: Request): Promise<Response> {
  try {
    const url = new URL(req.url);
    if (!validOrigin(req)) return json({ error: "Request not allowed." }, 403, req);
    if (req.method === "OPTIONS") {
      const origin = req.headers.get("origin");
      if (!origin || !allowedOrigins.has(origin)) return json({ error: "Request not allowed." }, 403, req);
      const headers = secureHeaders(secureToken(16), origin);
      headers.set("Access-Control-Allow-Methods", "POST");
      headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
      return new Response(null, { status: 204, headers });
    }
    if (req.method === "GET" && url.pathname === "/") return htmlResponse();
    if (req.method !== "POST") return json({ error: "Not found." }, 404, req);

    /* Invalid and unknown emails produce the identical delayed anti-enumeration reply. */
    if (url.pathname === "/api/auth/signin") {
      let body: Record<string, unknown> | undefined;
      try { body = await requestBody(req); } catch { body = undefined; }
      const email = typeof body?.email === "string" ? body.email.trim().toLowerCase() : "";
      const acceptedFormat = safeEmail(email);
      void acceptedFormat;
      await fixedSigninDelay();
      return json({ ok: true, message: "Continue with your account credential." }, 200, req);
    }

    if (url.pathname === "/api/auth/owner") {
      let body: Record<string, unknown>;
      try { body = await requestBody(req); } catch {
        await fixedSigninDelay();
        return json({ error: "We could not confirm those sign-in details. Check them and try again." }, 401, req);
      }
      const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
      const credential = body.credential;
      await fixedSigninDelay();
      if (!safeEmail(email) || email !== USER.email || !safeCredential(credential) || credential !== DEMO_OWNER_CREDENTIAL) {
        return json({ error: "We could not confirm those sign-in details. Check them and try again." }, 401, req);
      }
      if (accountMfa.identityLockedUntil > Date.now()) return json({ error: lockMessage("identity") }, 429, req);
      const old = getCookie(req, "mfa_session");
      if (old) sessions.delete(old);
      const session = createSession();
      const response = json({ csrf: session.csrf, testCode: session.identityChallenge!.value }, 200, req);
      response.headers.set("Set-Cookie", sessionCookie(session.id));
      return response;
    }

    const auth = authenticated(req);
    if (auth.error) return auth.error;
    const session = auth.session!;
    const body = await requestBody(req);
    const csrfError = stateAllowed(req, session, body);
    if (csrfError) return json({ error: csrfError }, 403, req);

    if (url.pathname === "/api/auth/logout") {
      sessions.delete(session.id);
      const response = json({ ok: true }, 200, req);
      response.headers.set("Set-Cookie", "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
      return response;
    }
    if (url.pathname === "/api/identity/resend") {
      if (accountMfa.identityLockedUntil > Date.now()) return json({ error: lockMessage("identity") }, 429, req);
      session.identityVerified = false;
      session.identityChallenge = createChallenge(session.userId);
      return json({ testCode: session.identityChallenge.value }, 200, req);
    }
    if (url.pathname === "/api/identity/verify") {
      if (!safeCode(body.code)) return json({ error: "Enter the six numbers from the code." }, 400, req);
      const result = await verifyChallenge(session, body.code as string);
      if (!result.ok) return json({ error: result.message }, 400, req);
      session.identityVerified = true;
      return json({ ok: true }, 200, req);
    }
    if (!session.identityVerified) return json({ error: "Complete the identity check before changing MFA settings." }, 403, req);
    if (url.pathname === "/api/mfa/provision") return json(await provision(false), 200, req);
    if (url.pathname === "/api/mfa/provision/new") {
      try { return json(await provision(true), 200, req); }
      catch (error) { return json({ error: error instanceof Error ? error.message : "Please try again." }, 429, req); }
    }
    if (url.pathname === "/api/mfa/verify") {
      if (!safeCode(body.code)) return json({ error: "Enter the six numbers from your authenticator app." }, 400, req);
      const result = await verifyTotp(body.code as string);
      if (!result.ok) return json({ error: result.message }, 400, req);
      session.mfaVerified = true; accountMfa.mfaEnrolled = true;
      return json({ ok: true }, 200, req);
    }
    if (url.pathname === "/api/mfa/recovery/generate") {
      if (!session.mfaVerified) return json({ error: "Confirm your authenticator before making recovery codes." }, 403, req);
      if (accountMfa.recoveryLockedUntil > Date.now()) return json({ error: lockMessage("recovery") }, 429, req);
      return json({ codes: await generateRecovery() }, 200, req);
    }
    if (url.pathname === "/api/mfa/recovery/verify") {
      if (!session.mfaVerified) return json({ error: "MFA is not ready." }, 403, req);
      const result = await verifyRecoveryCode(body.code);
      if (!result.ok) return json({ error: result.message }, 400, req);
      return json({ ok: true }, 200, req);
    }
    return json({ error: "Not found." }, 404, req);
  } catch {
    return json({ error: "Something went wrong. Please try again." }, 500, req);
  }
}

/* TLS requirement: Bun serves HTTPS using supplied local mkcert files. */
Bun.serve({
  port: 3000,
  hostname: "0.0.0.0",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  fetch: handle,
});
