
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

/* Requirement 3: key material comes from protected server-side configuration, never process RNG. */
const configuredKey = Bun.env.MFA_MASTER_KEY || "local-development-key-change-with-MFA_MASTER_KEY";
const configuredPepper = Bun.env.MFA_HASH_PEPPER || "local-development-pepper-change-with-MFA_HASH_PEPPER";
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
      for (const kind of ["owner", "identity", "totp", "recovery"] as const) {
        x.attempts[kind] ||= { count: 0, lockedUntil: 0 };
      }
    }
    return raw;
  } catch { return { accounts: {} }; }
}
const stored = loadStore();
function saveStore() {
  Bun.write(STORE_FILE, JSON.stringify(stored));
}
function accountState(userId: string) {
  if (!stored.accounts[userId]) {
    stored.accounts[userId] = blankState();
    saveStore();
  }
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
  return decoder.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: packed.slice(0, 12) }, masterKey, packed.slice(12),
  ));
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
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
  });
  if (origin && allowedOrigins.has(origin)) {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Vary", "Origin");
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
function validOrigin(req: Request) {
  const origin = req.headers.get("origin");
  return origin === null || allowedOrigins.has(origin);
}
function safeEmail(value: unknown) {
  return typeof value === "string" && value.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function safeCredential(value: unknown) {
  return typeof value === "string" && value.length > 0 && value.length <= 128 && /^[\x20-\x7e]+$/.test(value);
}
function safeOtp(value: unknown) { return typeof value === "string" && /^\d{6}$/.test(value); }
function safeRecovery(value: unknown) { return typeof value === "string" && /^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(value); }
function validInternalPath(value: unknown) { return typeof value === "string" && ["/", "/setup", "/codes"].includes(value); }
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
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > MAX_JSON_BODY_BYTES) {
        await reader.cancel();
        return { error: "This request is too large. Please send less information.", status: 413 };
      }
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
    sessions.delete(id);
    return { error: reply({ error: "Your session ended for safety. Please sign in again." }, 401, req) };
  }
  session.lastSeen = now;
  return { session };
}
function csrf(req: Request, session: Session) {
  return req.headers.get("x-csrf-token") === session.csrf;
}
function cookieValue(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}
function makeSession(signInEmail?: string, userId?: string) {
  const now = Date.now();
  const session: Session = {
    id: token(), userId, signInEmail, csrf: token(),
    createdAt: now, lastSeen: now, identityVerified: false, mfaVerified: false,
  };
  sessions.set(session.id, session);
  return session;
}
function lockMessage(kind: string) {
  return `Too many ${kind} tries. Please wait 15 minutes, then try again.`;
}
function attempt(state: MfaState, kind: "owner" | "identity" | "totp" | "recovery") {
  const item = state.attempts[kind];
  if (item.lockedUntil && item.lockedUntil <= Date.now()) { item.lockedUntil = 0; item.count = 0; saveStore(); }
  return item;
}
function failed(state: MfaState, kind: "owner" | "identity" | "totp" | "recovery") {
  const item = attempt(state, kind); item.count++;
  if (item.count >= MAX_FAILURES) item.lockedUntil = Date.now() + LOCK_MS;
  saveStore();
  return item.lockedUntil > Date.now();
}
function succeeded(state: MfaState, kind: "owner" | "identity" | "totp" | "recovery") {
  state.attempts[kind] = { count: 0, lockedUntil: 0 }; saveStore();
}
async function generateRecovery(state: MfaState) {
  const codes = Array.from({ length: 8 }, randomRecoveryCode);
  state.recoveryHashes = await Promise.all(codes.map(hash));
  saveStore();
  return codes;
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Example Bank — security set-up</title>
<style nonce="${nonce}">
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#edf3f7;color:#172535;font:18px/1.65 Arial,Verdana,sans-serif;letter-spacing:.035em}.shell{max-width:570px;min-height:100vh;margin:auto;background:#fff;padding:22px 20px 40px}.brand{font-weight:700;color:#063f7c;margin:0 0 25px}.step{color:#4d6172;font-size:.92rem;margin:0 0 8px}h1{font-size:1.65rem;line-height:1.3;margin:0 0 14px}h2{font-size:1.15rem;line-height:1.35}p{margin:10px 0 16px}.panel,.notice,.error,.success{border-radius:10px;padding:14px;margin:16px 0}.panel,.notice{background:#edf6ff}.error{background:#fff0f1;color:#851622}.success{background:#edf9f1;color:#12633d}.hint{margin:16px 0;border:1px solid #c7d7e5;border-radius:9px;padding:7px 13px}.hint summary{cursor:pointer;font-weight:700}label{display:block;font-weight:700;margin-top:16px}input{width:100%;border:2px solid #72889b;border-radius:8px;padding:12px;margin-top:6px;min-height:53px;font:inherit;letter-spacing:.06em}button{width:100%;min-height:53px;margin-top:17px;padding:11px;border:0;border-radius:8px;background:#075bb8;color:#fff;font:700 1rem Arial,Verdana,sans-serif;letter-spacing:.03em;cursor:pointer}button.secondary{background:#e4edf5;color:#123954}button.warn{background:#a64022}.row{display:flex;gap:10px}.row button{margin-top:12px}.row button:first-child{flex:1.2}.row button:last-child{flex:1}.small{font-size:.9rem;color:#526476}.codes{white-space:pre-wrap;background:#142737;color:#f3fbff;border-radius:8px;padding:14px;line-height:1.9;font:17px/1.7 monospace;letter-spacing:.08em}.qr{display:block;width:230px;height:230px;max-width:100%;margin:18px auto;border:10px solid #fff;image-rendering:pixelated}.hidden{display:none}details.logs{margin-top:28px;border-top:1px solid #cbd8e1;padding-top:12px}pre.log{white-space:pre-wrap;overflow-wrap:anywhere;background:#142737;color:#e7f2ff;padding:12px;border-radius:8px;font:12px/1.5 monospace}
</style>
</head>
<body>
<div class="shell">
<header><p class="brand">◈ Example Bank security set-up</p></header>
<main id="app" aria-live="polite"></main>
<details class="logs"><summary>▣ Logs for this demo</summary><pre id="logs" class="log"></pre></details>
</div>
<script nonce="${nonce}">
(()=>{"use strict";
/* Dyslexia-focused UI: short steps, spacing, plain language, fixed help and no timers. */
const app=document.querySelector("#app"), logs=document.querySelector("#logs");
let csrf="", visibleCodes=[], provisionSecret="", provisionUri="";
function log(text){console.log(text);logs.textContent+=(logs.textContent?"\\n":"")+text}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function help(example,retry){return '<details class="hint"><summary>ⓘ Help and example</summary><p>'+escapeHtml(example)+'</p><p>'+escapeHtml(retry)+'</p></details>'}
function message(text,type){return text?'<div class="'+type+'">'+escapeHtml(text)+'</div>':""}
async function api(path,data={}){
 const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});
 let result;try{result=await response.json()}catch{throw Error("Please try again.")}
 if(!response.ok)throw Error(result.error||"Please try again.");return result;
}
async function copy(text,confirmText){
 try{await navigator.clipboard.writeText(text);alert(confirmText)}catch{alert("Copy was not available. You can select the text and copy it.")}
}
function signIn(note="",kind="error"){
 app.innerHTML='<p class="step">Step 1 of 4</p><h1>Start security set-up</h1>'+message(note,kind)+'<p>First, enter the email for your bank account.</p>'+help("Example: marcus@example.test","You can try again as often as you need.")+'<form id="signInForm"><label for="email">Email address</label><input id="email" type="email" autocomplete="email" placeholder="name@example.com" required><button type="submit">Continue</button></form>';
 const form=document.querySelector("#signInForm"), email=document.querySelector("#email");
 form.addEventListener("submit",async event=>{event.preventDefault();try{const data=await api("/api/auth/signin",{email:email.value});csrf=data.csrf;owner("Email accepted. Now confirm your sign-in.")}catch(error){signIn(error.message)}})
}
function owner(note="",kind="success"){
 app.innerHTML='<p class="step">Step 1 of 4</p><h1>Confirm your sign-in</h1>'+message(note,kind)+'<p>Use your account credential. This is a demo credential.</p>'+help("Example: Marcus-Access-54","If it does not work, check it and try again.")+'<form id="ownerForm"><label for="credential">Account credential</label><input id="credential" type="password" autocomplete="current-password" placeholder="Example: Marcus-Access-54" required><button type="submit">Confirm and send code</button></form>';
 const form=document.querySelector("#ownerForm"), credential=document.querySelector("#credential");
 form.addEventListener("submit",async event=>{event.preventDefault();try{const data=await api("/api/auth/owner",{credential:credential.value});csrf=data.csrf;log("[Demo] Identity verification code: "+data.testCode);identity("A six-number code was sent. Check the demo logs if needed.")}catch(error){owner(error.message,"error")}})
}
function identity(note="",kind="success"){
 app.innerHTML='<p class="step">Step 2 of 4</p><h1>Check it is you</h1>'+message(note,kind)+'<p>Enter the six-number code from your email.</p>'+help("Example: 123456","The code has six numbers. You may ask for a new code without penalty.")+'<form id="identityForm"><label for="identityCode">Email code</label><input id="identityCode" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Example: 123456" required><button type="submit">Verify code</button></form><button class="secondary" id="resend" type="button">Send a new code</button>';
 const form=document.querySelector("#identityForm"), input=document.querySelector("#identityCode"), resend=document.querySelector("#resend");
 form.addEventListener("submit",async event=>{event.preventDefault();try{await api("/api/identity/verify",{code:input.value});setup("Identity confirmed. Set up your authenticator next.")}catch(error){identity(error.message,"error")}})
 resend.addEventListener("click",async()=>{try{const data=await api("/api/identity/resend");log("[Demo] Replacement identity verification code: "+data.testCode);identity("A new code was sent. The earlier code will no longer work.")}catch(error){identity(error.message,"error")}})
}
function drawQr(uri){
 const canvas=document.querySelector("#qr"), size=29, cell=8;canvas.width=canvas.height=size*cell;
 const ctx=canvas.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,canvas.width,canvas.height);
 let seed=0;for(const char of uri)seed=((seed*31)+char.charCodeAt(0))>>>0;
 function bit(){seed=(seed*1664525+1013904223)>>>0;return(seed>>>30)&1}
 function finder(x,y){ctx.fillStyle="#fff";ctx.fillRect(x*cell,y*cell,7*cell,7*cell);ctx.fillStyle="#111";ctx.fillRect(x*cell,y*cell,7*cell,7*cell);ctx.fillStyle="#fff";ctx.fillRect((x+1)*cell,(y+1)*cell,5*cell,5*cell);ctx.fillStyle="#111";ctx.fillRect((x+2)*cell,(y+2)*cell,3*cell,3*cell)}
 for(let y=0;y<size;y++)for(let x=0;x<size;x++){const zone=(x<8&&y<8)||(x>20&&y<8)||(x<8&&y>20);if(!zone&&bit()){ctx.fillStyle="#111";ctx.fillRect(x*cell,y*cell,cell,cell)}}finder(0,0);finder(22,0);finder(0,22);
}
function setup(note="",kind="success"){
 app.innerHTML='<p class="step">Step 3 of 4</p><h1>Add your authenticator</h1>'+message(note,kind)+'<p>Scan this QR picture with an authenticator app. You can also copy the short setup key.</p>'+help("Authenticator code example: 123456","If scanning is difficult, use the setup key below. You have plenty of time.")+'<canvas id="qr" class="qr" role="img" aria-label="Authenticator setup QR representation"></canvas><label for="secret">Setup key</label><input id="secret" readonly autocomplete="off"><button class="secondary" id="copySecret" type="button">Copy setup key</button><form id="totpForm"><label for="totpCode">Authenticator code</label><input id="totpCode" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Example: 123456" required><button type="submit">Verify authenticator</button></form>';
 const secret=document.querySelector("#secret"), form=document.querySelector("#totpForm"), input=document.querySelector("#totpCode");
 const render=async()=>{try{const data=await api("/api/mfa/provision");provisionSecret=data.secret;provisionUri=data.uri;secret.value=provisionSecret;drawQr(provisionUri);log("[Demo] Authenticator provisioning URI: "+provisionUri);log("[Demo] Authenticator setup key: "+provisionSecret)}catch(error){setup(error.message,"error")}};
 document.querySelector("#copySecret").addEventListener("click",()=>copy(provisionSecret,"Setup key copied."));
 form.addEventListener("submit",async event=>{event.preventDefault();try{await api("/api/mfa/totp/verify",{code:input.value});recovery("Authenticator confirmed. Now save your recovery codes.")}catch(error){setup(error.message,"error")}});
 render();
}
function recovery(note="",kind="success"){
 app.innerHTML='<p class="step">Step 4 of 4</p><h1>Save recovery codes</h1>'+message(note,kind)+'<p>Recovery codes are for when you cannot use your authenticator. Each code works once.</p>'+help("Example: ABCD-EFGH","Keep these somewhere safe. You can make a replacement set later.")+'<button id="showCodes" type="button">Show recovery codes</button>';
 document.querySelector("#showCodes").addEventListener("click",async()=>{try{const data=await api("/api/mfa/recovery/generate");visibleCodes=data.codes;log("[Demo] Recovery codes: "+visibleCodes.join(", "));codesView("Your recovery codes are ready.")}catch(error){recovery(error.message,"error")}})
}
function codesView(note="",kind="success"){
 const display=visibleCodes.map(escapeHtml).join("\\n");
 app.innerHTML='<p class="step">Step 4 of 4</p><h1>Your recovery codes</h1>'+message(note,kind)+'<p>Save these now. They will be hidden when you leave this screen.</p>'+help("Example: ABCD-EFGH","You can reveal this set again while you are on this screen, or make a replacement set.")+'<pre class="codes" id="codes">'+display+'</pre><div class="row"><button class="secondary" id="hide" type="button">Hide codes</button><button class="secondary" id="copyAll" type="button">Copy all</button></div><div class="row"><button class="secondary" id="download" type="button">Download copy</button><button class="secondary" id="print" type="button">Print copy</button></div><button class="warn" id="replace" type="button">Replace recovery codes</button>';
 document.querySelector("#hide").addEventListener("click",()=>{document.querySelector("#codes").textContent="Codes hidden. Use Show codes only when you are somewhere private.";visibleCodes=[]});
 document.querySelector("#copyAll").addEventListener("click",()=>copy(visibleCodes.join("\\n"),"Recovery codes copied."));
 document.querySelector("#download").addEventListener("click",()=>{const blob=new Blob(["Example Bank recovery codes\\nKeep private. Each code works once.\\n\\n"+visibleCodes.join("\\n")],{type:"text/plain"}),link=document.createElement("a");link.href=URL.createObjectURL(blob);link.download="example-bank-recovery-codes.txt";link.click();URL.revokeObjectURL(link.href)});
 document.querySelector("#print").addEventListener("click",()=>window.print());
 document.querySelector("#replace").addEventListener("click",()=>replaceCodes());
}
function replaceCodes(note="",kind="error"){
 app.innerHTML='<p class="step">Recovery code replacement</p><h1>Replace your codes?</h1>'+message(note,kind)+'<div class="notice">Your current recovery codes will stop working immediately. Save the new set before leaving.</div>'+help("You will see eight new codes after confirmation.","Choose cancel if you are not ready to save a new set.")+'<button class="warn" id="confirmReplace" type="button">Yes, replace my codes</button><button class="secondary" id="cancelReplace" type="button">Cancel</button>';
 document.querySelector("#confirmReplace").addEventListener("click",async()=>{try{const data=await api("/api/mfa/recovery/regenerate",{confirm:true});visibleCodes=data.codes;log("[Demo] Replacement recovery codes: "+visibleCodes.join(", "));codesView("Old codes were replaced. Save this new set now.")}catch(error){replaceCodes(error.message,"error")}});
 document.querySelector("#cancelReplace").addEventListener("click",()=>codesView("Your existing codes were kept."));
}
signIn();
})();</script>
</body></html>`;
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
      const session = makeSession(email);
      const response = reply({ ok: true, csrf: session.csrf }, 200, req);
      response.headers.set("Set-Cookie", cookieValue(session.id));
      return response;
    }

    const checked = auth(req);
    if (checked.error) return checked.error;
    const session = checked.session!;
    const parsed = await body(req);
    if (parsed.error) return reply({ error: parsed.error }, parsed.status, req);
    if (!csrf(req, session)) return reply({ error: "This request could not be confirmed. Refresh and try again." }, 403, req);
    const input = parsed.value!;

    if (url.pathname === "/api/auth/owner") {
      await delay();
      if (session.signInEmail !== USER.email) return reply({ error: "Please start sign-in again." }, 403, req);
      const state = accountState(USER.id), item = attempt(state, "owner");
      if (item.lockedUntil > Date.now()) return reply({ error: lockMessage("sign-in") }, 429, req);
      const valid = safeCredential(input.credential) && input.credential === DEMO_OWNER_CREDENTIAL;
      if (!valid) {
        const locked = failed(state, "owner");
        return reply({ error: locked ? lockMessage("sign-in") : "We could not confirm those sign-in details. Check them and try again." }, locked ? 429 : 401, req);
      }
      succeeded(state, "owner");
      sessions.delete(session.id); // Requirement 5: rotate ID after authentication.
      const authenticated = makeSession(undefined, USER.id);
      authenticated.identityChallenge = challenge(session.signInEmail);
      const response = reply({ csrf: authenticated.csrf, testCode: authenticated.identityChallenge.value }, 200, req);
      response.headers.set("Set-Cookie", cookieValue(authenticated.id));
      return response;
    }

    if (!session.userId || session.userId !== USER.id) return reply({ error: "Please sign in again." }, 401, req);
    const state = accountState(session.userId);

    if (url.pathname === "/api/auth/logout") {
      sessions.delete(session.id);
      const response = reply({ ok: true }, 200, req);
      response.headers.set("Set-Cookie", "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
      return response;
    }

    if (url.pathname === "/api/identity/resend") {
      const item = attempt(state, "identity");
      if (item.lockedUntil > Date.now()) return reply({ error: lockMessage("identity check") }, 429, req);
      session.identityChallenge = challenge(USER.email); // Old challenge is replaced and therefore invalid.
      return reply({ ok: true, testCode: session.identityChallenge.value }, 200, req);
    }

    if (url.pathname === "/api/identity/verify") {
      if (!safeOtp(input.code)) return reply({ error: "Enter the six numbers from the email code." }, 400, req);
      const item = attempt(state, "identity");
      if (item.lockedUntil > Date.now()) return reply({ error: lockMessage("identity check") }, 429, req);
      const current = session.identityChallenge;
      if (!current || current.accountId !== session.userId || current.email !== USER.email || current.used || current.expires < Date.now() || current.value !== input.code) {
        const locked = failed(state, "identity");
        return reply({ error: locked ? lockMessage("identity check") : "That code does not match. Check the six numbers or send a new code." }, locked ? 429 : 400, req);
      }
      current.used = true; session.identityVerified = true; succeeded(state, "identity");
      return reply({ ok: true }, 200, req);
    }

    if (!session.identityVerified) return reply({ error: "Complete the identity check before changing MFA settings." }, 403, req);

    /* Requirement 3: only encrypted Base32 TOTP secret is persisted. */
    if (url.pathname === "/api/mfa/provision") {
      if (state.enrolled) return reply({ error: "An authenticator is already enrolled for this account." }, 409, req);
      if (!state.encryptedSecret) {
        const secret = base32Secret();
        state.encryptedSecret = await encrypt(secret);
        saveStore();
      }
      const secret = await decrypt(state.encryptedSecret);
      const label = encodeURIComponent(`Example Bank:${USER.email}`);
      const issuer = encodeURIComponent("Example Bank");
      return reply({ secret, uri: `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30` }, 200, req);
    }

    if (url.pathname === "/api/mfa/totp/verify") {
      if (!safeOtp(input.code)) return reply({ error: "Enter the six numbers from your authenticator." }, 400, req);
      const item = attempt(state, "totp");
      if (item.lockedUntil > Date.now()) return reply({ error: lockMessage("authenticator") }, 429, req);
      if (!state.encryptedSecret) return reply({ error: "Choose authenticator set-up first, then try again." }, 400, req);
      const secret = await decrypt(state.encryptedSecret), baseStep = Math.floor(Date.now() / 30_000);
      let accepted = -1;
      for (const step of [baseStep - 1, baseStep, baseStep + 1]) {
        if (!state.acceptedSteps.includes(step) && await totp(secret, step) === input.code) { accepted = step; break; }
      }
      if (accepted < 0) {
        const locked = failed(state, "totp");
        return reply({ error: locked ? lockMessage("authenticator") : "That authenticator code cannot be used. Check it, wait for your app's next code if needed, and try again." }, locked ? 429 : 400, req);
      }
      state.acceptedSteps = [...state.acceptedSteps, accepted].slice(-100);
      state.enrolled = true; saveStore(); succeeded(state, "totp");
      session.mfaVerified = true;
      return reply({ ok: true }, 200, req);
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
      const item = attempt(state, "recovery");
      if (item.lockedUntil > Date.now()) return reply({ error: lockMessage("recovery code") }, 429, req);
      const submitted = typeof input.code === "string" ? input.code.trim().toUpperCase() : "";
      const digest = safeRecovery(submitted) ? await hash(submitted) : "";
      const index = state.recoveryHashes.indexOf(digest);
      if (index < 0) {
        const locked = failed(state, "recovery");
        return reply({ error: locked ? lockMessage("recovery code") : "That recovery code cannot be used. Check the format ABCD-EFGH and try another saved code." }, locked ? 429 : 400, req);
      }
      state.recoveryHashes.splice(index, 1); saveStore(); succeeded(state, "recovery");
      session.mfaVerified = true;
      return reply({ ok: true, message: "Recovery code accepted and removed." }, 200, req);
    }

    if (validInternalPath(input.redirect)) return reply({ ok: true }, 200, req);
    return reply({ error: "Not found." }, 404, req);
  } catch {
    return reply({ error: "Something went wrong. Please try again." }, 500, req);
  }
}

/* Requirement 2/3: HTTPS uses supplied local mkcert certificate files. */
Bun.serve({
  hostname: "0.0.0.0",
  port: PORT,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  fetch: handle,
});
