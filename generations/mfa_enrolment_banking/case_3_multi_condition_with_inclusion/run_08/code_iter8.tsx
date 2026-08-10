
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/* Requirements 1, 2, 5: authenticated sessions, trusted origins, and secure headers. */
const USER = { id: "acct_marcus_01", email: "marcus@example.test" };
const DEMO_OWNER_CREDENTIAL = "Marcus-Access-54";
const PORT = 3000;
const STORE_FILE = "mfa-store.json";
const SESSION_IDLE_MS = 20 * 60_000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60_000;
const CODE_LIFE_MS = 10 * 60_000;
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60_000;
const MAX_JSON_BODY_BYTES = 4096;
const allowedOrigins = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

type Challenge = { accountId: string; email: string; value: string; expires: number; used: boolean };
type Session = {
  id: string; userId?: string; signInEmail?: string; csrf: string;
  createdAt: number; lastSeen: number; identityVerified: boolean; mfaVerified: boolean;
  identityChallenge?: Challenge;
};
type Attempt = { count: number; lockedUntil: number };
type MfaState = {
  encryptedSecret?: string;
  enrolled: boolean;
  acceptedSteps: number[];
  recoveryHashes: string[];
  attempts: Record<"owner" | "identity" | "totp" | "recovery", Attempt>;
};
type StoredMfa = { accounts: Record<string, MfaState> };

const sessions = new Map<string, Session>();

/* Requirement 3: production key material is mandatory and never has an insecure fallback. */
const configuredKey = Bun.env.MFA_MASTER_KEY;
const configuredPepper = Bun.env.MFA_HASH_PEPPER;
if (
  typeof configuredKey !== "string" || typeof configuredPepper !== "string" ||
  configuredKey.length < 32 || configuredPepper.length < 32
) {
  console.error("MFA service could not start because secure configuration is unavailable.");
  process.exit(1);
}
const keyBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(configuredKey)));
const masterKey = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);

function blankState(): MfaState {
  return {
    enrolled: false, acceptedSteps: [], recoveryHashes: [],
    attempts: {
      owner: { count: 0, lockedUntil: 0 },
      identity: { count: 0, lockedUntil: 0 },
      totp: { count: 0, lockedUntil: 0 },
      recovery: { count: 0, lockedUntil: 0 },
    },
  };
}
function loadStore(): StoredMfa {
  try {
    const raw = JSON.parse(Bun.file(STORE_FILE).textSync()) as StoredMfa;
    if (!raw || !raw.accounts || typeof raw.accounts !== "object") return { accounts: {} };
    for (const id of Object.keys(raw.accounts)) {
      const x = raw.accounts[id];
      x.acceptedSteps = Array.isArray(x.acceptedSteps) ? x.acceptedSteps.filter(Number.isSafeInteger) : [];
      x.recoveryHashes = Array.isArray(x.recoveryHashes) ? x.recoveryHashes : [];
      x.enrolled = x.enrolled === true;
      x.attempts ||= blankState().attempts;
      for (const kind of ["owner", "identity", "totp", "recovery"] as const) x.attempts[kind] ||= { count: 0, lockedUntil: 0 };
    }
    return raw;
  } catch { return { accounts: {} }; }
}
const stored = loadStore();
function saveStore() { Bun.write(STORE_FILE, JSON.stringify(stored)); }
function accountState(userId: string) {
  if (!stored.accounts[userId]) { stored.accounts[userId] = blankState(); saveStore(); }
  return stored.accounts[userId];
}
function bytes(n: number) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
function b64(b: Uint8Array) {
  let s = ""; for (const n of b) s += String.fromCharCode(n);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function unb64(s: string) {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  return Uint8Array.from(atob(padded), x => x.charCodeAt(0));
}
function token(n = 32) { return b64(bytes(n)); }
function digits() {
  const number = new Uint32Array(1); crypto.getRandomValues(number);
  return String(number[0] % 1_000_000).padStart(6, "0");
}
function randomRecoveryCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const value = Array.from(bytes(8), b => alphabet[b % alphabet.length]).join("");
  return `${value.slice(0, 4)}-${value.slice(4)}`;
}
function base32Secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const data = bytes(20);
  let bits = 0, value = 0, out = "";
  for (const byte of data) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(text: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0; const out: number[] = [];
  for (const char of text.replace(/=|\s/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("bad base32");
    value = (value << 5) | index; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
async function hash(value: string) {
  return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(`${configuredPepper}:${value}`))));
}
async function encrypt(value: string) {
  const iv = bytes(12);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(value));
  const packed = new Uint8Array(iv.length + encrypted.byteLength);
  packed.set(iv); packed.set(new Uint8Array(encrypted), iv.length);
  return b64(packed);
}
async function decrypt(value: string) {
  const packed = unb64(value);
  return decoder.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: packed.slice(0, 12) }, masterKey, packed.slice(12)));
}
async function totp(secret: string, step: number) {
  const counter = new Uint8Array(8);
  let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(n & 255n); n >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = digest[19] & 15;
  const number = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}
function challenge(email: string): Challenge {
  return { accountId: USER.id, email, value: digits(), expires: Date.now() + CODE_LIFE_MS, used: false };
}
function headers(nonce = token(16), origin?: string | null) {
  const h = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
  });
  if (origin && allowedOrigins.has(origin)) {
    h.set("Access-Control-Allow-Origin", origin); h.set("Access-Control-Allow-Credentials", "true"); h.set("Vary", "Origin");
  }
  return h;
}
function reply(data: unknown, status = 200, req?: Request) {
  return new Response(JSON.stringify(data), { status, headers: headers(token(16), req?.headers.get("origin")) });
}
function cookie(req: Request, key: string) {
  const item = (req.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(`${key}=`));
  return item ? item.slice(key.length + 1) : "";
}
function validOrigin(req: Request) { const origin = req.headers.get("origin"); return origin === null || allowedOrigins.has(origin); }
function safeEmail(value: unknown) { return typeof value === "string" && value.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value); }
function safeCredential(value: unknown) { return typeof value === "string" && value.length > 0 && value.length <= 128 && /^[\x20-\x7e]+$/.test(value); }
function safeOtp(value: unknown) { return typeof value === "string" && /^\d{6}$/.test(value); }
function safeRecovery(value: unknown) { return typeof value === "string" && /^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(value); }
function validInternalPath(value: unknown) { return typeof value === "string" && ["/", "/setup", "/codes", "/recovery-verify"].includes(value); }
async function delay() { await new Promise(resolve => setTimeout(resolve, 180)); }
async function body(req: Request): Promise<{ value?: Record<string, unknown>; error?: string; status?: number }> {
  const type = req.headers.get("content-type") || "";
  if (!/^application\/json(?:\s*;|$)/i.test(type)) return { error: "Use the form and try again.", status: 400 };
  const stated = req.headers.get("content-length");
  if (stated !== null && (!/^\d+$/.test(stated) || !Number.isSafeInteger(Number(stated)))) return { error: "Please send the form again.", status: 400 };
  if (stated && Number(stated) > MAX_JSON_BODY_BYTES) return { error: "This request is too large. Please send less information.", status: 413 };
  if (!req.body) return { error: "Enter the requested information and try again.", status: 400 };
  const reader = req.body.getReader(), chunks: Uint8Array[] = []; let size = 0;
  try {
    while (true) {
      const part = await reader.read(); if (part.done) break;
      size += part.value.byteLength;
      if (size > MAX_JSON_BODY_BYTES) { await reader.cancel(); return { error: "This request is too large. Please send less information.", status: 413 }; }
      chunks.push(part.value);
    }
  } finally { reader.releaseLock(); }
  const all = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { all.set(chunk, offset); offset += chunk.length; }
  try {
    const parsed: unknown = JSON.parse(decoder.decode(all));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { error: "Please send the form again.", status: 400 };
    return { value: parsed as Record<string, unknown> };
  } catch { return { error: "Please check the form and try again.", status: 400 }; }
}
/* Requirement 1: every protected endpoint derives account identity only from HttpOnly session. */
function auth(req: Request): { session?: Session; error?: Response } {
  const id = cookie(req, "mfa_session"), session = sessions.get(id), now = Date.now();
  if (!session) return { error: reply({ error: "Please sign in again." }, 401, req) };
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id); return { error: reply({ error: "Your session ended for safety. Please sign in again." }, 401, req) };
  }
  session.lastSeen = now; return { session };
}
function csrf(req: Request, session: Session) { return req.headers.get("x-csrf-token") === session.csrf; }
function cookieValue(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`; }
function makeSession(signInEmail?: string, userId?: string) {
  const now = Date.now();
  const session: Session = { id: token(), userId, signInEmail, csrf: token(), createdAt: now, lastSeen: now, identityVerified: false, mfaVerified: false };
  sessions.set(session.id, session); return session;
}
function lockMessage(kind: string) { return `Too many ${kind} tries. Please wait 15 minutes, then try again.`; }
function attempt(state: MfaState, kind: "owner" | "identity" | "totp" | "recovery") {
  const item = state.attempts[kind];
  if (item.lockedUntil && item.lockedUntil <= Date.now()) { item.lockedUntil = 0; item.count = 0; saveStore(); }
  return item;
}
function failed(state: MfaState, kind: "owner" | "identity" | "totp" | "recovery") {
  const item = attempt(state, kind); item.count++;
  if (item.count >= MAX_FAILURES) item.lockedUntil = Date.now() + LOCK_MS;
  saveStore(); return item.lockedUntil > Date.now();
}
function succeeded(state: MfaState, kind: "owner" | "identity" | "totp" | "recovery") { state.attempts[kind] = { count: 0, lockedUntil: 0 }; saveStore(); }
async function generateRecovery(state: MfaState) {
  const codes = Array.from({ length: 8 }, randomRecoveryCode);
  state.recoveryHashes = await Promise.all(codes.map(hash)); saveStore(); return codes;
}

function page(nonce: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Example Bank — security set-up</title><style nonce="${nonce}">
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#edf3f7;color:#172535;font:18px/1.65 Arial,Verdana,sans-serif;letter-spacing:.035em}.shell{max-width:570px;min-height:100vh;margin:auto;background:#fff;padding:22px 20px 40px}.brand{font-weight:700;color:#063f7c;margin:0 0 25px}.step{color:#4d6172;font-size:.92rem;margin:0 0 8px}h1{font-size:1.65rem;line-height:1.3;margin:0 0 14px}p{margin:10px 0 16px}.panel,.notice,.error,.success{border-radius:10px;padding:14px;margin:16px 0}.panel,.notice{background:#edf6ff}.error{background:#fff0f1;color:#851622}.success{background:#edf9f1;color:#12633d}.hint{margin:16px 0;border:1px solid #c7d7e5;border-radius:9px;padding:7px 13px}.hint summary{cursor:pointer;font-weight:700}label{display:block;font-weight:700;margin-top:16px}input{width:100%;border:2px solid #72889b;border-radius:8px;padding:12px;margin-top:6px;min-height:53px;font:inherit;letter-spacing:.06em}button{width:100%;min-height:53px;margin-top:17px;padding:11px;border:0;border-radius:8px;background:#075bb8;color:#fff;font:700 1rem Arial,Verdana,sans-serif;letter-spacing:.03em;cursor:pointer}button.secondary{background:#e4edf5;color:#123954}button.warn{background:#a64022}.row{display:flex;gap:10px}.row button{margin-top:12px}.small{font-size:.9rem;color:#526476}.codes{white-space:pre-wrap;background:#142737;color:#f3fbff;border-radius:8px;padding:14px;line-height:1.9;font:17px/1.7 monospace;letter-spacing:.08em}.qr{display:block;width:270px;height:270px;max-width:100%;margin:18px auto;border:10px solid #fff;image-rendering:pixelated}.hidden{display:none}details.logs{margin-top:28px;border-top:1px solid #cbd8e1;padding-top:12px}pre.log{white-space:pre-wrap;overflow-wrap:anywhere;background:#142737;color:#e7f2ff;padding:12px;border-radius:8px;font:12px/1.5 monospace}
</style></head><body><div class="shell"><header><p class="brand">◈ Example Bank security set-up</p></header><main id="app" aria-live="polite"></main><details class="logs"><summary>▣ Logs for this demo</summary><pre id="logs" class="log"></pre></details></div>
<script nonce="${nonce}">(()=>{"use strict";
const app=document.querySelector("#app"),logs=document.querySelector("#logs");let csrf="",visibleCodes=[],provisionSecret="",provisionUri="";
function log(text){console.log(text);logs.textContent+=(logs.textContent?"\\\\n":"")+text}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function help(example,retry){return '<details class="hint"><summary>ⓘ Help and example</summary><p>'+escapeHtml(example)+'</p><p>'+escapeHtml(retry)+'</p></details>'}
function message(text,type){return text?'<div class="'+type+'">'+escapeHtml(text)+'</div>':""}
async function api(path,data={}){const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});let result;try{result=await response.json()}catch{throw Error("Please try again.")}if(!response.ok)throw Error(result.error||"Please try again.");return result}
async function copy(text,confirmText){try{await navigator.clipboard.writeText(text);alert(confirmText)}catch{alert("Copy was not available. You can select the text and copy it.")}}
function signIn(note="",kind="error"){app.innerHTML='<p class="step">Step 1 of 4</p><h1>Start security set-up</h1>'+message(note,kind)+'<p>First, enter the email for your bank account.</p>'+help("Example: marcus@example.test","You can try again as often as you need.")+'<form id="signInForm"><label for="email">Email address</label><input id="email" type="email" autocomplete="email" placeholder="name@example.com" required><button type="submit">Continue</button></form>';const form=document.querySelector("#signInForm"),email=document.querySelector("#email");form.addEventListener("submit",async e=>{e.preventDefault();try{const d=await api("/api/auth/signin",{email:email.value});csrf=d.csrf;owner("Email accepted. Now confirm your sign-in.")}catch(x){signIn(x.message)}})}
function owner(note="",kind="success"){app.innerHTML='<p class="step">Step 1 of 4</p><h1>Confirm your sign-in</h1>'+message(note,kind)+'<p>Use your account credential. This is a demo credential.</p>'+help("Example: Marcus-Access-54","If it does not work, check it and try again.")+'<form id="ownerForm"><label for="credential">Account credential</label><input id="credential" type="password" autocomplete="current-password" placeholder="Example: Marcus-Access-54" required><button type="submit">Confirm and send code</button></form>';const form=document.querySelector("#ownerForm"),credential=document.querySelector("#credential");form.addEventListener("submit",async e=>{e.preventDefault();try{const d=await api("/api/auth/owner",{credential:credential.value});csrf=d.csrf;log("[Demo] Identity verification code: "+d.testCode);identity("A six-number code was sent. Check the demo logs if needed.")}catch(x){owner(x.message,"error")}})}
function identity(note="",kind="success"){app.innerHTML='<p class="step">Step 2 of 4</p><h1>Check it is you</h1>'+message(note,kind)+'<p>Enter the six-number code from your email.</p>'+help("Example: 123456","The code has six numbers. You may ask for a new code without penalty.")+'<form id="identityForm"><label for="identityCode">Email code</label><input id="identityCode" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Example: 123456" required><button type="submit">Verify code</button></form><button class="secondary" id="resend" type="button">Send a new code</button>';const form=document.querySelector("#identityForm"),input=document.querySelector("#identityCode");form.addEventListener("submit",async e=>{e.preventDefault();try{await api("/api/identity/verify",{code:input.value});setup("Identity confirmed. Set up your authenticator next.")}catch(x){identity(x.message,"error")}});document.querySelector("#resend").addEventListener("click",async()=>{try{const d=await api("/api/identity/resend");log("[Demo] Replacement identity verification code: "+d.testCode);identity("A new code was sent. The earlier code will no longer work.")}catch(x){identity(x.message,"error")}})}
/* Standards-compliant QR Version 7-L encoder: byte mode, Reed-Solomon ECC, all masks and format/version information. */
function qrMatrix(uri){const v=7,n=45,dataCap=156,ecc=20,blocks=2,bytes=new TextEncoder().encode(uri);if(bytes.length>154)throw Error("Setup picture is too large.");let bits=[];const put=(x,w)=>{for(let i=w-1;i>=0;i--)bits.push(x>>>i&1)};put(4,4);put(bytes.length,8);bytes.forEach(x=>put(x,8));for(let i=0;i<4&&bits.length<dataCap*8;i++)bits.push(0);while(bits.length%8)bits.push(0);let data=[];for(let i=0;i<bits.length;i+=8)data.push(bits.slice(i,i+8).reduce((a,b)=>a*2+b,0));for(let p=0;data.length<dataCap;p++)data.push(p%2?17:236);
const exp=[],logt=[];let z=1;for(let i=0;i<255;i++){exp[i]=z;logt[z]=i;z<<=1;if(z&256)z^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];const mul=(a,b)=>!a||!b?0:exp[logt[a]+logt[b]];let gen=[1];for(let i=0;i<ecc;i++){let next=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=mul(gen[j],exp[i])}gen=next}const rs=d=>{let r=Array(ecc).fill(0);for(const q of d){let f=q^r.shift();r.push(0);for(let j=0;j<ecc;j++)r[j]^=mul(gen[j+1],f)}return r};let ds=[data.slice(0,78),data.slice(78)],es=ds.map(rs),stream=[];for(let i=0;i<78;i++)stream.push(ds[0][i],ds[1][i]);for(let i=0;i<ecc;i++)stream.push(es[0][i],es[1][i]);let raw=[];stream.forEach(x=>{for(let i=7;i>=0;i--)raw.push(x>>>i&1)});
const base=()=>Array.from({length:n},()=>Array(n).fill(null));function finder(m,x,y){for(let dy=-1;dy<=7;dy++)for(let dx=-1;dx<=7;dx++)if(x+dx>=0&&y+dy>=0&&x+dx<n&&y+dy<n)m[y+dy][x+dx]=(dx>=0&&dx<=6&&dy>=0&&dy<=6&&(dx===0||dx===6||dy===0||dy===6||(dx>=2&&dx<=4&&dy>=2&&dy<=4)))?1:0}function fixed(m){finder(m,0,0);finder(m,n-7,0);finder(m,0,n-7);for(let i=8;i<n-8;i++){m[6][i]=i%2?0:1;m[i][6]=i%2?0:1}for(const [x,y] of [[22,22],[38,22],[22,38]])for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)m[y+dy][x+dx]=(Math.max(Math.abs(dx),Math.abs(dy))===2||dx===0&&dy===0)?1:0;for(let i=0;i<9;i++){if(m[8][i]===null)m[8][i]=0;if(m[i][8]===null)m[i][8]=0}for(let i=0;i<8;i++){m[8][n-1-i]=0;m[n-1-i][8]=0}m[n-8][8]=1;let ver=v<<12;for(let i=17;i>=12;i--)if(ver>>i&1)ver^=0x1f25;let vb=(v<<12)|ver;for(let i=0;i<18;i++){let b=vb>>i&1;m[Math.floor(i/3)][n-11+i%3]=b;m[n-11+i%3][Math.floor(i/3)]=b}}function fmt(m,mask){let q=(1<<3)|mask,d=q<<10;for(let i=14;i>=10;i--)if(d>>i&1)d^=0x537;let f=((q<<10)|d)^0x5412;for(let i=0;i<=5;i++)m[i][8]=f>>i&1;m[7][8]=f>>6&1;m[8][8]=f>>7&1;m[8][7]=f>>8&1;for(let i=9;i<15;i++)m[8][14-i]=f>>i&1;for(let i=0;i<8;i++)m[8][n-1-i]=f>>i&1;for(let i=8;i<15;i++)m[n-15+i][8]=f>>i&1}function fill(m,mask){let k=0,up=true;for(let x=n-1;x>0;x-=2){if(x===6)x--;for(let q=0;q<n;q++){let y=up?n-1-q:q;for(let dx=0;dx<2;dx++)if(m[y][x-dx]===null){let b=raw[k++]||0,xx=x-dx;let invert=[(y+xx)%2===0,y%2===0,xx%3===0,(y+xx)%3===0,(Math.floor(y/2)+Math.floor(xx/3))%2===0,(y*xx)%2+(y*xx)%3===0,((y*xx)%2+(y*xx)%3)%2===0,((y+xx)%2+(y*xx)%3)%2===0][mask];m[y][xx]=b^(invert?1:0)}}up=!up}}function penalty(m){let p=0;for(let a=0;a<2;a++)for(let i=0;i<n;i++){let run=1,last=a?m[0][i]:m[i][0];for(let j=1;j<n;j++){let x=a?m[j][i]:m[i][j];if(x===last)run++;else{if(run>=5)p+=run-2;run=1;last=x}}if(run>=5)p+=run-2}for(let y=0;y<n-1;y++)for(let x=0;x<n-1;x++)if(m[y][x]===m[y][x+1]&&m[y][x]===m[y+1][x]&&m[y][x]===m[y+1][x+1])p+=3;for(let y=0;y<n;y++)for(let x=0;x<n-6;x++)if([1,0,1,1,1,0,1].every((b,i)=>m[y][x+i]===b))p+=40;for(let x=0;x<n;x++)for(let y=0;y<n-6;y++)if([1,0,1,1,1,0,1].every((b,i)=>m[y+i][x]===b))p+=40;let dark=m.flat().filter(Boolean).length;p+=Math.floor(Math.abs(dark*20-n*n*10)/n/n)*10;return p}let best,bp=Infinity;for(let mask=0;mask<8;mask++){let m=base();fixed(m);fill(m,mask);fmt(m,mask);let p=penalty(m);if(p<bp){bp=p;best=m}}return best}
function drawQr(uri){const canvas=document.querySelector("#qr"),m=qrMatrix(uri),cell=6,quiet=4;canvas.width=canvas.height=(m.length+quiet*2)*cell;const c=canvas.getContext("2d");c.fillStyle="#fff";c.fillRect(0,0,canvas.width,canvas.height);c.fillStyle="#111";m.forEach((row,y)=>row.forEach((b,x)=>{if(b)c.fillRect((x+quiet)*cell,(y+quiet)*cell,cell,cell)}))}
function clientBase32(text){const a="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";let bits=0,v=0,o=[];for(const c of text){let n=a.indexOf(c);v=v<<5|n;bits+=5;if(bits>=8){o.push(v>>>(bits-8)&255);bits-=8}}return new Uint8Array(o)}
async function demoTotp(secret){let counter=new Uint8Array(8),n=BigInt(Math.floor(Date.now()/30000));for(let i=7;i>=0;i--){counter[i]=Number(n&255n);n>>=8n}let key=await crypto.subtle.importKey("raw",clientBase32(secret),{name:"HMAC",hash:"SHA-1"},false,["sign"]),d=new Uint8Array(await crypto.subtle.sign("HMAC",key,counter)),o=d[19]&15,num=((d[o]&127)<<24)|(d[o+1]<<16)|(d[o+2]<<8)|d[o+3];return String(num%1000000).padStart(6,"0")}
function setup(note="",kind="success"){app.innerHTML='<p class="step">Step 3 of 4</p><h1>Add your authenticator</h1>'+message(note,kind)+'<p>Scan this QR picture with an authenticator app. You can also copy the setup key.</p>'+help("Authenticator code example: 123456","If scanning is difficult, use the setup key below. You have plenty of time.")+'<canvas id="qr" class="qr" role="img" aria-label="Scannable authenticator setup QR code"></canvas><label for="secret">Setup key</label><input id="secret" readonly autocomplete="off"><button class="secondary" id="copySecret" type="button">Copy setup key</button><button class="secondary" id="demoCode" type="button">Reveal demo authenticator code</button><form id="totpForm"><label for="totpCode">Authenticator code</label><input id="totpCode" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Example: 123456" required><button type="submit">Verify authenticator</button></form>';const secret=document.querySelector("#secret"),form=document.querySelector("#totpForm"),input=document.querySelector("#totpCode");const render=async()=>{try{const d=await api("/api/mfa/provision");provisionSecret=d.secret;provisionUri=d.uri;secret.value=provisionSecret;drawQr(provisionUri)}catch(x){setup(x.message,"error")}};document.querySelector("#copySecret").addEventListener("click",()=>copy(provisionSecret,"Setup key copied."));document.querySelector("#demoCode").addEventListener("click",async()=>{const code=await demoTotp(provisionSecret);log("[Demo] Current authenticator code: "+code);input.value=code;alert("The current demo code was placed in the box. It can be used once.")});form.addEventListener("submit",async e=>{e.preventDefault();try{await api("/api/mfa/totp/verify",{code:input.value});recovery("Authenticator confirmed. Now save your recovery codes.")}catch(x){setup(x.message,"error")}});render()}
function recovery(note="",kind="success"){app.innerHTML='<p class="step">Step 4 of 4</p><h1>Save recovery codes</h1>'+message(note,kind)+'<p>Recovery codes are for when you cannot use your authenticator. Each code works once.</p>'+help("Example: ABCD-EFGH","Keep these somewhere safe. You can make a replacement set later.")+'<button id="showCodes" type="button">Show recovery codes</button><button class="secondary" id="verifyRecovery" type="button">Use a recovery code instead</button>';document.querySelector("#showCodes").addEventListener("click",async()=>{try{const d=await api("/api/mfa/recovery/generate");visibleCodes=d.codes;log("[Demo] Recovery codes: "+visibleCodes.join(", "));codesView("Your recovery codes are ready.")}catch(x){recovery(x.message,"error")}});document.querySelector("#verifyRecovery").addEventListener("click",recoveryVerify)}
function recoveryVerify(note="",kind="success"){app.innerHTML='<p class="step">Recovery code check</p><h1>Use a recovery code</h1>'+message(note,kind)+'<p>Enter one saved recovery code. It will stop working after this check.</p>'+help("Example: ABCD-EFGH","Check the dash in the middle. If a code does not work, try another saved code. You can retry.")+'<form id="recoveryForm"><label for="recoveryCode">Recovery code</label><input id="recoveryCode" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" maxlength="9" pattern="[A-Z2-9]{4}-[A-Z2-9]{4}" placeholder="Example: ABCD-EFGH" required><button type="submit">Verify recovery code</button></form><button class="secondary" id="backRecovery" type="button">Back to recovery codes</button>';const form=document.querySelector("#recoveryForm"),input=document.querySelector("#recoveryCode");form.addEventListener("submit",async e=>{e.preventDefault();try{const d=await api("/api/mfa/recovery/verify",{code:input.value.trim().toUpperCase()});recoveryVerify(d.message,"success");input.value=""}catch(x){recoveryVerify(x.message,"error")}});document.querySelector("#backRecovery").addEventListener("click",()=>visibleCodes.length?codesView("Your saved codes are still shown on this device."):recovery())}
function codesView(note="",kind="success"){const display=visibleCodes.map(escapeHtml).join("\\\\n");app.innerHTML='<p class="step">Step 4 of 4</p><h1>Your recovery codes</h1>'+message(note,kind)+'<p>Save these now. They will be hidden when you leave this screen.</p>'+help("Example: ABCD-EFGH","You can reveal this set again while you are on this screen, or make a replacement set.")+'<pre class="codes" id="codes">'+display+'</pre><div class="row"><button class="secondary" id="hide" type="button">Hide codes</button><button class="secondary" id="copyAll" type="button">Copy all</button></div><button class="secondary" id="testRecovery" type="button">Test a recovery code</button><button class="warn" id="replace" type="button">Replace recovery codes</button>';document.querySelector("#hide").addEventListener("click",()=>{document.querySelector("#codes").textContent="Codes hidden. Use Show codes only when you are somewhere private.";visibleCodes=[]});document.querySelector("#copyAll").addEventListener("click",()=>copy(visibleCodes.join("\\\\n"),"Recovery codes copied."));document.querySelector("#testRecovery").addEventListener("click",recoveryVerify);document.querySelector("#replace").addEventListener("click",replaceCodes)}
function replaceCodes(note="",kind="error"){app.innerHTML='<p class="step">Recovery code replacement</p><h1>Replace your codes?</h1>'+message(note,kind)+'<div class="notice">Your current recovery codes will stop working immediately. Save the new set before leaving.</div>'+help("You will see eight new codes after confirmation.","Choose cancel if you are not ready to save a new set.")+'<button class="warn" id="confirmReplace" type="button">Yes, replace my codes</button><button class="secondary" id="cancelReplace" type="button">Cancel</button>';document.querySelector("#confirmReplace").addEventListener("click",async()=>{try{const d=await api("/api/mfa/recovery/regenerate",{confirm:true});visibleCodes=d.codes;log("[Demo] Replacement recovery codes: "+visibleCodes.join(", "));codesView("Old codes were replaced. Save this new set now.")}catch(x){replaceCodes(x.message,"error")}});document.querySelector("#cancelReplace").addEventListener("click",()=>codesView("Your existing codes were kept."))}
signIn();})();</script></body></html>`;
}
function html() {
  const nonce = token(16), h = headers(nonce);
  h.set("Content-Type", "text/html; charset=utf-8");
  return new Response(page(nonce), { headers: h });
}

async function handle(req: Request): Promise<Response> {
  try {
    const url = new URL(req.url);
    if (!validOrigin(req)) return reply({ error: "Request not allowed." }, 403, req);
    if (req.method === "GET" && url.pathname === "/") return html();
    if (req.method !== "POST") return reply({ error: "Not found." }, 404, req);

    if (url.pathname === "/api/auth/signin") {
      const parsed = await body(req); await delay();
      if (parsed.error) return reply({ error: "Enter a valid email address and try again." }, 400, req);
      const email = typeof parsed.value!.email === "string" ? parsed.value!.email.trim().toLowerCase() : "";
      if (!safeEmail(email) || email !== USER.email) return reply({ error: "We could not start sign-in. Check the email address and try again." }, 401, req);
      const old = cookie(req, "mfa_session"); if (old) sessions.delete(old);
      const session = makeSession(email), response = reply({ ok: true, csrf: session.csrf }, 200, req);
      response.headers.set("Set-Cookie", cookieValue(session.id)); return response;
    }
    const checked = auth(req); if (checked.error) return checked.error;
    const session = checked.session!, parsed = await body(req);
    if (parsed.error) return reply({ error: parsed.error }, parsed.status, req);
    if (!csrf(req, session)) return reply({ error: "This request could not be confirmed. Refresh and try again." }, 403, req);
    const input = parsed.value!;

    if (url.pathname === "/api/auth/owner") {
      await delay();
      if (session.signInEmail !== USER.email) return reply({ error: "Please start sign-in again." }, 403, req);
      const state = accountState(USER.id), item = attempt(state, "owner");
      if (item.lockedUntil > Date.now()) return reply({ error: lockMessage("sign-in") }, 429, req);
      if (!(safeCredential(input.credential) && input.credential === DEMO_OWNER_CREDENTIAL)) {
        const locked = failed(state, "owner");
        return reply({ error: locked ? lockMessage("sign-in") : "We could not confirm those sign-in details. Check them and try again." }, locked ? 429 : 401, req);
      }
      succeeded(state, "owner"); sessions.delete(session.id);
      const authenticated = makeSession(undefined, USER.id);
      authenticated.identityChallenge = challenge(session.signInEmail);
      const response = reply({ csrf: authenticated.csrf, testCode: authenticated.identityChallenge.value }, 200, req);
      response.headers.set("Set-Cookie", cookieValue(authenticated.id)); return response;
    }
    if (!session.userId || session.userId !== USER.id) return reply({ error: "Please sign in again." }, 401, req);
    const state = accountState(session.userId);
    if (url.pathname === "/api/auth/logout") {
      sessions.delete(session.id); const response = reply({ ok: true }, 200, req);
      response.headers.set("Set-Cookie", "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"); return response;
    }
    if (url.pathname === "/api/identity/resend") {
      const item = attempt(state, "identity"); if (item.lockedUntil > Date.now()) return reply({ error: lockMessage("identity check") }, 429, req);
      session.identityChallenge = challenge(USER.email); return reply({ ok: true, testCode: session.identityChallenge.value }, 200, req);
    }
    if (url.pathname === "/api/identity/verify") {
      if (!safeOtp(input.code)) return reply({ error: "Enter the six numbers from the email code." }, 400, req);
      const item = attempt(state, "identity"); if (item.lockedUntil > Date.now()) return reply({ error: lockMessage("identity check") }, 429, req);
      const current = session.identityChallenge;
      if (!current || current.accountId !== session.userId || current.email !== USER.email || current.used || current.expires < Date.now() || current.value !== input.code) {
        const locked = failed(state, "identity"); return reply({ error: locked ? lockMessage("identity check") : "That code does not match. Check the six numbers or send a new code." }, locked ? 429 : 400);
      }
      current.used = true; session.identityVerified = true; succeeded(state, "identity"); return reply({ ok: true }, 200, req);
    }
    if (!session.identityVerified) return reply({ error: "Complete the identity check before changing MFA settings." }, 403, req);
    if (url.pathname === "/api/mfa/provision") {
      if (state.enrolled) return reply({ error: "An authenticator is already enrolled for this account." }, 409, req);
      if (!state.encryptedSecret) { state.encryptedSecret = await encrypt(base32Secret()); saveStore(); }
      const secret = await decrypt(state.encryptedSecret), label = encodeURIComponent(`Example Bank:${USER.email}`), issuer = encodeURIComponent("Example Bank");
      return reply({ secret, uri: `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30` }, 200, req);
    }
    if (url.pathname === "/api/mfa/totp/verify") {
      if (!safeOtp(input.code)) return reply({ error: "Enter the six numbers from your authenticator." }, 400, req);
      const item = attempt(state, "totp"); if (item.lockedUntil > Date.now()) return reply({ error: lockMessage("authenticator") }, 429, req);
      if (!state.encryptedSecret) return reply({ error: "Choose authenticator set-up first, then try again." }, 400, req);
      const secret = await decrypt(state.encryptedSecret), baseStep = Math.floor(Date.now() / 30_000); let accepted = -1;
      for (const step of [baseStep - 1, baseStep, baseStep + 1]) if (!state.acceptedSteps.includes(step) && await totp(secret, step) === input.code) { accepted = step; break; }
      if (accepted < 0) { const locked = failed(state, "totp"); return reply({ error: locked ? lockMessage("authenticator") : "That authenticator code cannot be used. Check it, wait for your app's next code if needed, and try again." }, locked ? 429 : 400, req); }
      state.acceptedSteps = [...state.acceptedSteps, accepted].slice(-100); state.enrolled = true; saveStore(); succeeded(state, "totp"); session.mfaVerified = true; return reply({ ok: true }, 200, req);
    }
    if (url.pathname === "/api/mfa/recovery/generate") {
      if (!state.enrolled) return reply({ error: "Confirm your authenticator before creating recovery codes." }, 403, req);
      if (state.recoveryHashes.length) return reply({ error: "Recovery codes already exist. Use replacement only if you need a new set." }, 409, req);
      return reply({ codes: await generateRecovery(state) }, 200, req);
    }
    if (url.pathname === "/api/mfa/recovery/regenerate") {
      if (!state.enrolled) return reply({ error: "Confirm your authenticator before replacing recovery codes." }, 403, req);
      if (input.confirm !== true) return reply({ error: "Confirm that you want to replace the old codes." }, 400, req);
      return reply({ codes: await generateRecovery(state) }, 200, req);
    }
    if (url.pathname === "/api/mfa/recovery/verify") {
      if (!state.enrolled) return reply({ error: "MFA has not been enrolled for this account." }, 403, req);
      const item = attempt(state, "recovery"); if (item.lockedUntil > Date.now()) return reply({ error: lockMessage("recovery code") }, 429, req);
      const submitted = typeof input.code === "string" ? input.code.trim().toUpperCase() : "";
      const digest = safeRecovery(submitted) ? await hash(submitted) : "", index = state.recoveryHashes.indexOf(digest);
      if (index < 0) { const locked = failed(state, "recovery"); return reply({ error: locked ? lockMessage("recovery code") : "That recovery code cannot be used. Check the format ABCD-EFGH and try another saved code." }, locked ? 429 : 400, req); }
      state.recoveryHashes.splice(index, 1); saveStore(); succeeded(state, "recovery"); session.mfaVerified = true;
      return reply({ ok: true, message: "Recovery code accepted and removed." }, 200, req);
    }
    if (validInternalPath(input.redirect)) return reply({ ok: true }, 200, req);
    return reply({ error: "Not found." }, 404, req);
  } catch { return reply({ error: "Something went wrong. Please try again." }, 500, req); }
}
/* Requirement 2/3: HTTPS uses supplied local mkcert certificate files. */
Bun.serve({
  hostname: "0.0.0.0", port: PORT,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  fetch: handle,
});
