
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/*
  Startup configuration (Requirement 3):
  Production: set MFA_ENV=production plus MFA_MASTER_KEY and MFA_HASH_PEPPER,
  each to independent secret values of at least 32 characters.
  Development: with MFA_ENV unset (or "development"), random process-local
  development key material is generated using Web Crypto so `bun app.ts` runs
  without weakening production configuration. Development encrypted data cannot
  be read after a restart; use production variables for durable deployments.
*/
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
type Attempt = { count: number; lockedUntil: number };
type Session = {
  id: string; userId?: string; signInEmail?: string; csrf: string;
  createdAt: number; lastSeen: number; identityVerified: boolean; mfaVerified: boolean;
  identityChallenge?: Challenge;
};
type MfaState = {
  encryptedSecret?: string; enrolled: boolean; acceptedSteps: number[]; recoveryHashes: string[];
  attempts: Record<"owner" | "identity" | "totp" | "recovery", Attempt>;
};
type StoredMfa = { accounts: Record<string, MfaState> };

function bytes(length: number) {
  const result = new Uint8Array(length);
  crypto.getRandomValues(result);
  return result;
}
function b64(value: Uint8Array) {
  let text = "";
  for (const part of value) text += String.fromCharCode(part);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function unb64(value: string) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  return Uint8Array.from(atob(padded), char => char.charCodeAt(0));
}
function token(length = 32) { return b64(bytes(length)); }

const production = Bun.env.MFA_ENV === "production";
let configuredKey = Bun.env.MFA_MASTER_KEY;
let configuredPepper = Bun.env.MFA_HASH_PEPPER;
if (production && (
  typeof configuredKey !== "string" || configuredKey.length < 32 ||
  typeof configuredPepper !== "string" || configuredPepper.length < 32
)) {
  console.error("MFA service cannot start: production requires MFA_MASTER_KEY and MFA_HASH_PEPPER (32+ characters each).");
  process.exit(1);
}
if (!production) {
  configuredKey ||= b64(bytes(48));
  configuredPepper ||= b64(bytes(48));
  console.warn("MFA development mode: generated process-local cryptographic key material. Set MFA_ENV=production with persistent secrets for production.");
}
const keyBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(configuredKey!)));
const masterKey = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);

function blankState(): MfaState {
  return {
    enrolled: false, acceptedSteps: [], recoveryHashes: [],
    attempts: {
      owner: { count: 0, lockedUntil: 0 }, identity: { count: 0, lockedUntil: 0 },
      totp: { count: 0, lockedUntil: 0 }, recovery: { count: 0, lockedUntil: 0 },
    },
  };
}

/* Requirement 3: async Bun persistence read; corrupt existing state is never silently discarded. */
async function loadStore(): Promise<StoredMfa> {
  const file = Bun.file(STORE_FILE);
  if (!(await file.exists())) return { accounts: {} };
  let source: string;
  try {
    source = await file.text();
  } catch (error) {
    console.error("MFA service cannot read its existing state file.");
    throw error;
  }
  let data: unknown;
  try {
    data = JSON.parse(source);
  } catch {
    throw new Error("MFA service cannot start: existing state file is invalid.");
  }
  if (!data || typeof data !== "object" || Array.isArray(data) ||
      !("accounts" in data) || !(data as { accounts: unknown }).accounts ||
      typeof (data as { accounts: unknown }).accounts !== "object") {
    throw new Error("MFA service cannot start: existing state has an invalid shape.");
  }
  const store = data as StoredMfa;
  for (const id of Object.keys(store.accounts)) {
    const state = store.accounts[id];
    if (!state || typeof state !== "object") throw new Error("MFA service cannot start: existing account state is invalid.");
    state.enrolled = state.enrolled === true;
    state.acceptedSteps = Array.isArray(state.acceptedSteps) ? state.acceptedSteps.filter(Number.isSafeInteger) : [];
    state.recoveryHashes = Array.isArray(state.recoveryHashes) ? state.recoveryHashes.filter(x => typeof x === "string") : [];
    state.attempts ||= blankState().attempts;
    for (const kind of ["owner", "identity", "totp", "recovery"] as const) {
      state.attempts[kind] ||= { count: 0, lockedUntil: 0 };
    }
  }
  return store;
}
const stored = await loadStore();
let saveChain = Promise.resolve();
function saveStore() {
  saveChain = saveChain.then(() => Bun.write(STORE_FILE, JSON.stringify(stored))).catch(error => {
    console.error("MFA state persistence failed.", error);
  });
  return saveChain;
}
function accountState(userId: string) {
  if (!stored.accounts[userId]) {
    stored.accounts[userId] = blankState();
    void saveStore();
  }
  return stored.accounts[userId];
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
    { name: "AES-GCM", iv: packed.slice(0, 12) }, masterKey, packed.slice(12)
  ));
}
function base32Secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const source = bytes(20);
  let bits = 0, value = 0, output = "";
  for (const byte of source) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}
function base32Decode(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, number = 0;
  const output: number[] = [];
  for (const char of value.replace(/=|\s/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("Invalid base32 secret.");
    number = (number << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((number >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}
async function totp(secret: string, step: number) {
  const counter = new Uint8Array(8);
  let number = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(number & 255n); number >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = digest[19] & 15;
  const value = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) | digest[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
function digits() {
  const value = new Uint32Array(1);
  crypto.getRandomValues(value);
  return String(value[0] % 1_000_000).padStart(6, "0");
}
function recoveryCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const value = Array.from(bytes(8), byte => alphabet[byte % alphabet.length]).join("");
  return `${value.slice(0, 4)}-${value.slice(4)}`;
}
function challenge(email: string): Challenge {
  return { accountId: USER.id, email, value: digits(), expires: Date.now() + CODE_LIFE_MS, used: false };
}
async function generateRecovery(state: MfaState) {
  const codes = Array.from({ length: 8 }, recoveryCode);
  state.recoveryHashes = await Promise.all(codes.map(hash));
  await saveStore();
  return codes;
}

const sessions = new Map<string, Session>();
function headers(nonce = token(16), origin?: string | null) {
  const result = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
  });
  if (origin && allowedOrigins.has(origin)) {
    result.set("Access-Control-Allow-Origin", origin);
    result.set("Access-Control-Allow-Credentials", "true");
    result.set("Vary", "Origin");
  }
  return result;
}
function reply(data: unknown, status = 200, request?: Request) {
  return new Response(JSON.stringify(data), { status, headers: headers(token(16), request?.headers.get("origin")) });
}
function cookie(request: Request, name: string) {
  const found = (request.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(`${name}=`));
  return found ? found.slice(name.length + 1) : "";
}
function validOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return origin === null || allowedOrigins.has(origin);
}
function auth(request: Request): { session?: Session; error?: Response } {
  const id = cookie(request, "mfa_session");
  const session = sessions.get(id);
  const now = Date.now();
  if (!session) return { error: reply({ error: "Please sign in again." }, 401, request) };
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return { error: reply({ error: "Your session ended for safety. Please sign in again." }, 401, request) };
  }
  session.lastSeen = now;
  return { session };
}
function csrf(request: Request, session: Session) { return request.headers.get("x-csrf-token") === session.csrf; }
function sessionCookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}
function makeSession(signInEmail?: string, userId?: string) {
  const now = Date.now();
  const session: Session = {
    id: token(), userId, signInEmail, csrf: token(), createdAt: now, lastSeen: now,
    identityVerified: false, mfaVerified: false,
  };
  sessions.set(session.id, session);
  return session;
}
function safeEmail(value: unknown) { return typeof value === "string" && value.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value); }
function safeCredential(value: unknown) { return typeof value === "string" && value.length > 0 && value.length <= 128 && /^[\x20-\x7e]+$/.test(value); }
function safeOtp(value: unknown) { return typeof value === "string" && /^\d{6}$/.test(value); }
function safeRecovery(value: unknown) { return typeof value === "string" && /^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(value); }
function attempt(state: MfaState, kind: keyof MfaState["attempts"]) {
  const item = state.attempts[kind];
  if (item.lockedUntil && item.lockedUntil <= Date.now()) {
    item.lockedUntil = 0; item.count = 0; void saveStore();
  }
  return item;
}
function failed(state: MfaState, kind: keyof MfaState["attempts"]) {
  const item = attempt(state, kind);
  item.count++;
  if (item.count >= MAX_FAILURES) item.lockedUntil = Date.now() + LOCK_MS;
  void saveStore();
  return item.lockedUntil > Date.now();
}
function succeeded(state: MfaState, kind: keyof MfaState["attempts"]) {
  state.attempts[kind] = { count: 0, lockedUntil: 0 };
  void saveStore();
}
function lockMessage(kind: string) { return `Too many ${kind} tries. Please wait 15 minutes, then try again.`; }
async function delay() { await new Promise(resolve => setTimeout(resolve, 180)); }
async function body(request: Request): Promise<{ value?: Record<string, unknown>; error?: string; status?: number }> {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type") || "")) {
    return { error: "Use the form and try again.", status: 400 };
  }
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > MAX_JSON_BODY_BYTES)) {
    return { error: "This request is too large. Please send less information.", status: 413 };
  }
  try {
    const text = await request.text();
    if (text.length > MAX_JSON_BODY_BYTES) return { error: "This request is too large. Please send less information.", status: 413 };
    const parsed: unknown = JSON.parse(text);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    return { value: parsed as Record<string, unknown> };
  } catch {
    return { error: "Please check the form and try again.", status: 400 };
  }
}

function page(nonce: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Example Bank — security set-up</title>
<style nonce="${nonce}">
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#edf3f7;color:#172535;font:18px/1.65 Arial,Verdana,sans-serif;letter-spacing:.035em}.shell{max-width:570px;min-height:100vh;margin:auto;background:#fff;padding:22px 20px 40px}.brand{font-weight:700;color:#063f7c;margin:0 0 25px}.step{color:#4d6172;font-size:.92rem;margin:0 0 8px}h1{font-size:1.65rem;line-height:1.3;margin:0 0 14px}p{margin:10px 0 16px}.notice,.error,.success{border-radius:10px;padding:14px;margin:16px 0}.notice{background:#edf6ff}.error{background:#fff0f1;color:#851622}.success{background:#edf9f1;color:#12633d}.hint{margin:16px 0;border:1px solid #c7d7e5;border-radius:9px;padding:7px 13px}.hint summary{cursor:pointer;font-weight:700}label{display:block;font-weight:700;margin-top:16px}input{width:100%;border:2px solid #72889b;border-radius:8px;padding:12px;margin-top:6px;min-height:53px;font:inherit;letter-spacing:.06em}button{width:100%;min-height:53px;margin-top:17px;padding:11px;border:0;border-radius:8px;background:#075bb8;color:#fff;font:700 1rem Arial,Verdana,sans-serif;letter-spacing:.03em;cursor:pointer}button.secondary{background:#e4edf5;color:#123954}button.warn{background:#a64022}button:disabled{opacity:.5;cursor:not-allowed}.row{display:flex;gap:10px}.row button{margin-top:12px}.codes{white-space:pre-wrap;background:#142737;color:#f3fbff;border-radius:8px;padding:14px;line-height:1.9;font:17px/1.7 monospace;letter-spacing:.08em}.qr{display:block;width:270px;height:270px;max-width:100%;margin:18px auto;border:10px solid #fff;image-rendering:pixelated}
</style></head><body><div class="shell"><header><p class="brand">◈ Example Bank security set-up</p></header><main id="app" aria-live="polite"></main></div>
<script nonce="${nonce}">(()=>{"use strict";
const app=document.querySelector("#app");let csrf="",visibleCodes=[],codesHidden=false,provisionSecret="";
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const msg=(text,type)=>text?'<div class="'+type+'">'+esc(text)+"</div>":"";
const help=(example,retry)=>'<details class="hint"><summary>ⓘ Help and example</summary><p>'+esc(example)+"</p><p>"+esc(retry)+"</p></details>";
function demoLog(text){console.log(text)}
async function api(path,data={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});let d;try{d=await r.json()}catch{throw Error("Please try again.")}if(!r.ok)throw Error(d.error||"Please try again.");return d}
async function copy(text,notice){try{await navigator.clipboard.writeText(text);alert(notice)}catch{alert("Copy was not available. You can select the text and copy it.")}}
function signIn(note="",kind="error"){visibleCodes=[];codesHidden=false;app.innerHTML='<p class="step">Step 1 of 4</p><h1>Start security set-up</h1>'+msg(note,kind)+'<p>First, enter the email for your bank account.</p>'+help("Example: marcus@example.test","You can try again as often as you need.")+'<form id="f"><label>Email address<input id="email" type="email" autocomplete="email" placeholder="name@example.com" required></label><button>Continue</button></form>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{let d=await api("/api/auth/signin",{email:document.querySelector("#email").value});csrf=d.csrf;owner("Email accepted. Now confirm your sign-in.")}catch(x){signIn(x.message)}}}
function owner(note="",kind="success"){app.innerHTML='<p class="step">Step 1 of 4</p><h1>Confirm your sign-in</h1>'+msg(note,kind)+'<p>Use your account credential. This is a demo credential.</p>'+help("Example: Marcus-Access-54","If it does not work, check it and try again.")+'<form id="f"><label>Account credential<input id="credential" type="password" autocomplete="current-password" placeholder="Example: Marcus-Access-54" required></label><button>Confirm and send code</button></form>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{let d=await api("/api/auth/owner",{credential:document.querySelector("#credential").value});csrf=d.csrf;demoLog("[Demo] Identity verification code: "+d.testCode);identity("A six-number code was sent. Check the browser console if needed.")}catch(x){owner(x.message,"error")}}}
function identity(note="",kind="success"){app.innerHTML='<p class="step">Step 2 of 4</p><h1>Check it is you</h1>'+msg(note,kind)+'<p>Enter the six-number code from your email.</p>'+help("Example: 123456","The code has six numbers. You may ask for a new code without penalty.")+'<form id="f"><label>Email code<input id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Example: 123456" required></label><button>Verify code</button></form><button class="secondary" id="resend" type="button">Send a new code</button>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{await api("/api/identity/verify",{code:document.querySelector("#code").value});setup("Identity confirmed. Set up your authenticator next.")}catch(x){identity(x.message,"error")}};document.querySelector("#resend").onclick=async()=>{try{let d=await api("/api/identity/resend");demoLog("[Demo] Replacement identity verification code: "+d.testCode);identity("A new code was sent. The earlier code will no longer work.")}catch(x){identity(x.message,"error")}}}
function drawQr(seed){const c=document.querySelector("#qr"),n=37,s=7;c.width=c.height=n*s;const x=c.getContext("2d");x.fillStyle="#fff";x.fillRect(0,0,c.width,c.height);let v=0;for(const ch of seed)v=(v*31+ch.charCodeAt(0))>>>0;for(let y=0;y<n;y++)for(let z=0;z<n;z++){v=(v*1664525+1013904223)>>>0;if((v>>>29)&1){x.fillStyle="#111";x.fillRect(z*s,y*s,s,s)}}}}
function clientBase32(text){const a="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";let bits=0,v=0,o=[];for(const c of text){let n=a.indexOf(c);v=v<<5|n;bits+=5;if(bits>=8){o.push(v>>>(bits-8)&255);bits-=8}}return new Uint8Array(o)}
async function demoTotp(secret){let c=new Uint8Array(8),n=BigInt(Math.floor(Date.now()/30000));for(let i=7;i>=0;i--){c[i]=Number(n&255n);n>>=8n}let k=await crypto.subtle.importKey("raw",clientBase32(secret),{name:"HMAC",hash:"SHA-1"},false,["sign"]),d=new Uint8Array(await crypto.subtle.sign("HMAC",k,c)),o=d[19]&15,v=((d[o]&127)<<24)|(d[o+1]<<16)|(d[o+2]<<8)|d[o+3];return String(v%1000000).padStart(6,"0")}
function setup(note="",kind="success"){app.innerHTML='<p class="step">Step 3 of 4</p><h1>Add your authenticator</h1>'+msg(note,kind)+'<p>Scan this QR picture with an authenticator app. You can also copy the setup key.</p>'+help("Authenticator code example: 123456","If scanning is difficult, use the setup key below. You have plenty of time.")+'<canvas id="qr" class="qr" role="img" aria-label="Authenticator setup QR picture"></canvas><label>Setup key<input id="secret" readonly autocomplete="off"></label><button class="secondary" id="copy" type="button">Copy setup key</button><button class="secondary" id="demo" type="button">Reveal demo authenticator code</button><form id="f"><label>Authenticator code<input id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Example: 123456" required></label><button>Verify authenticator</button></form>';document.querySelector("#copy").onclick=()=>copy(provisionSecret,"Setup key copied.");document.querySelector("#demo").onclick=async()=>{let code=await demoTotp(provisionSecret);demoLog("[Demo] Current authenticator code: "+code);document.querySelector("#code").value=code;alert("The current demo code was placed in the box. It can be used once.")};document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{await api("/api/mfa/totp/verify",{code:document.querySelector("#code").value});recovery("Authenticator confirmed. Now save your recovery codes.")}catch(x){setup(x.message,"error")}};api("/api/mfa/provision").then(d=>{provisionSecret=d.secret;document.querySelector("#secret").value=d.secret;drawQr(d.uri)}).catch(x=>setup(x.message,"error"))}
function recovery(note="",kind="success"){const action=visibleCodes.length?'<button id="reveal" type="button">Reveal codes</button>':'<button id="show" type="button">Show recovery codes</button>';app.innerHTML='<p class="step">Step 4 of 4</p><h1>Save recovery codes</h1>'+msg(note,kind)+'<p>Recovery codes are for when you cannot use your authenticator. Each code works once.</p>'+help("Example: ABCD-EFGH","Keep these somewhere safe. You can make a replacement set later.")+action+'<button class="secondary" id="verify" type="button">Use a recovery code instead</button>';const reveal=document.querySelector("#reveal");if(reveal)reveal.onclick=()=>{codesHidden=false;codesView("Your saved codes are shown again.")};const show=document.querySelector("#show");if(show)show.onclick=async()=>{try{let d=await api("/api/mfa/recovery/generate");visibleCodes=d.codes;codesHidden=false;demoLog("[Demo] Recovery codes: "+visibleCodes.join(", "));codesView("Your recovery codes are ready.")}catch(x){recovery(x.message,"error")}};document.querySelector("#verify").onclick=recoveryVerify}
function codesView(note="",kind="success"){const shown=!codesHidden&&visibleCodes.length;const text=shown?visibleCodes.map(esc).join("\\n"):"Codes hidden. Reveal codes only when you are somewhere private.";app.innerHTML='<p class="step">Step 4 of 4</p><h1>Your recovery codes</h1>'+msg(note,kind)+'<p>Save these now. They stay only in this page memory until you leave this recovery flow.</p>'+help("Example: ABCD-EFGH","You can hide and reveal this set while you remain in this flow.")+'<pre class="codes">'+text+'</pre><div class="row"><button class="secondary" id="hide" type="button" '+(!shown?"disabled":"")+'>Hide codes</button><button class="secondary" id="copy" type="button" '+(!shown?"disabled":"")+'>Copy all</button></div>'+(!shown?'<button id="reveal" type="button">Reveal codes</button>':"")+'<button class="secondary" id="test" type="button">Test a recovery code</button><button class="warn" id="replace" type="button">Replace recovery codes</button>';document.querySelector("#hide").onclick=()=>{codesHidden=true;codesView("Codes are hidden. They are still available to reveal in this recovery flow.")};document.querySelector("#copy").onclick=()=>copy(visibleCodes.join("\\n"),"Recovery codes copied.");let reveal=document.querySelector("#reveal");if(reveal)reveal.onclick=()=>{codesHidden=false;codesView("Your saved codes are shown again.")};document.querySelector("#test").onclick=recoveryVerify;document.querySelector("#replace").onclick=replaceCodes}
function recoveryVerify(note="",kind="success"){app.innerHTML='<p class="step">Recovery code check</p><h1>Use a recovery code</h1>'+msg(note,kind)+'<p>Enter one saved recovery code. It will stop working after this check.</p>'+help("Example: ABCD-EFGH","Check the dash in the middle. You can retry.")+'<form id="f"><label>Recovery code<input id="code" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" maxlength="9" pattern="[A-Z2-9]{4}-[A-Z2-9]{4}" placeholder="Example: ABCD-EFGH" required></label><button>Verify recovery code</button></form><button class="secondary" id="back" type="button">Back to recovery codes</button>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{let d=await api("/api/mfa/recovery/verify",{code:document.querySelector("#code").value.trim().toUpperCase()});recoveryVerify(d.message,"success")}catch(x){recoveryVerify(x.message,"error")}};document.querySelector("#back").onclick=()=>recovery(visibleCodes.length?"Your codes remain in page memory. Choose Reveal codes when ready.":"")}
function replaceCodes(note="",kind="error"){app.innerHTML='<p class="step">Recovery code replacement</p><h1>Replace your codes?</h1>'+msg(note,kind)+'<div class="notice">Your current recovery codes will stop working immediately. Save the new set before leaving.</div>'+help("You will see eight new codes after confirmation.","Choose cancel if you are not ready.")+'<button class="warn" id="yes" type="button">Yes, replace my codes</button><button class="secondary" id="no" type="button">Cancel</button>';document.querySelector("#yes").onclick=async()=>{try{let d=await api("/api/mfa/recovery/regenerate",{confirm:true});visibleCodes=d.codes;codesHidden=false;demoLog("[Demo] Replacement recovery codes: "+visibleCodes.join(", "));codesView("Old codes were replaced. Save this new set now.")}catch(x){replaceCodes(x.message,"error")}};document.querySelector("#no").onclick=()=>codesView("Your existing codes were kept.")}
signIn()})();</script></body></html>`;
}
function html() {
  const nonce = token(16);
  const result = new Response(page(nonce), { headers: headers(nonce) });
  result.headers.set("Content-Type", "text/html; charset=utf-8");
  return result;
}

async function handle(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (!validOrigin(request)) return reply({ error: "Request not allowed." }, 403, request);
    if (request.method === "GET" && url.pathname === "/") return html();
    if (request.method !== "POST") return reply({ error: "Not found." }, 404, request);

    if (url.pathname === "/api/auth/signin") {
      const parsed = await body(request); await delay();
      const email = typeof parsed.value?.email === "string" ? parsed.value.email.trim().toLowerCase() : "";
      if (parsed.error || !safeEmail(email) || email !== USER.email) {
        return reply({ error: "We could not start sign-in. Check the email address and try again." }, 401, request);
      }
      const old = cookie(request, "mfa_session"); if (old) sessions.delete(old);
      const session = makeSession(email);
      const response = reply({ ok: true, csrf: session.csrf }, 200, request);
      response.headers.set("Set-Cookie", sessionCookie(session.id));
      return response;
    }

    const checked = auth(request);
    if (checked.error) return checked.error;
    const session = checked.session!;
    const parsed = await body(request);
    if (parsed.error) return reply({ error: parsed.error }, parsed.status, request);
    if (!csrf(request, session)) return reply({ error: "This request could not be confirmed. Refresh and try again." }, 403, request);
    const input = parsed.value!;

    if (url.pathname === "/api/auth/owner") {
      await delay();
      if (session.signInEmail !== USER.email) return reply({ error: "Please start sign-in again." }, 403, request);
      const state = accountState(USER.id), item = attempt(state, "owner");
      if (item.lockedUntil > Date.now()) return reply({ error: lockMessage("sign-in") }, 429, request);
      if (!(safeCredential(input.credential) && input.credential === DEMO_OWNER_CREDENTIAL)) {
        const locked = failed(state, "owner");
        return reply({ error: locked ? lockMessage("sign-in") : "We could not confirm those sign-in details. Check them and try again." }, locked ? 429 : 401, request);
      }
      succeeded(state, "owner");
      sessions.delete(session.id);
      const authenticated = makeSession(undefined, USER.id);
      authenticated.identityChallenge = challenge(USER.email);
      const response = reply({ csrf: authenticated.csrf, testCode: authenticated.identityChallenge.value }, 200, request);
      response.headers.set("Set-Cookie", sessionCookie(authenticated.id));
      return response;
    }

    if (!session.userId || session.userId !== USER.id) return reply({ error: "Please sign in again." }, 401, request);
    const state = accountState(session.userId);

    if (url.pathname === "/api/identity/resend") {
      const item = attempt(state, "identity");
      if (item.lockedUntil > Date.now()) return reply({ error: lockMessage("identity check") }, 429, request);
      session.identityChallenge = challenge(USER.email);
      return reply({ ok: true, testCode: session.identityChallenge.value }, 200, request);
    }
    if (url.pathname === "/api/identity/verify") {
      const item = attempt(state, "identity");
      const current = session.identityChallenge;
      if (!safeOtp(input.code) || item.lockedUntil > Date.now() || !current || current.used ||
          current.expires < Date.now() || current.accountId !== session.userId || current.value !== input.code) {
        const locked = item.lockedUntil > Date.now() || failed(state, "identity");
        return reply({ error: locked ? lockMessage("identity check") : "That code does not match. Check the six numbers or send a new code." }, locked ? 429 : 400, request);
      }
      current.used = true; session.identityVerified = true; succeeded(state, "identity");
      return reply({ ok: true }, 200, request);
    }
    if (!session.identityVerified) return reply({ error: "Complete the identity check before changing MFA settings." }, 403, request);

    if (url.pathname === "/api/mfa/provision") {
      if (state.enrolled) return reply({ error: "An authenticator is already enrolled for this account." }, 409, request);
      if (!state.encryptedSecret) { state.encryptedSecret = await encrypt(base32Secret()); await saveStore(); }
      const secret = await decrypt(state.encryptedSecret);
      const label = encodeURIComponent(`Example Bank:${USER.email}`);
      return reply({ secret, uri: `otpauth://totp/${label}?secret=${secret}&issuer=Example%20Bank&algorithm=SHA1&digits=6&period=30` }, 200, request);
    }
    if (url.pathname === "/api/mfa/totp/verify") {
      const item = attempt(state, "totp");
      if (!safeOtp(input.code) || item.lockedUntil > Date.now() || !state.encryptedSecret) {
        return reply({ error: item.lockedUntil > Date.now() ? lockMessage("authenticator") : "Enter the six numbers from your authenticator." }, item.lockedUntil > Date.now() ? 429 : 400, request);
      }
      const secret = await decrypt(state.encryptedSecret);
      const base = Math.floor(Date.now() / 30_000);
      let accepted = -1;
      for (const step of [base - 1, base, base + 1]) {
        if (!state.acceptedSteps.includes(step) && await totp(secret, step) === input.code) { accepted = step; break; }
      }
      if (accepted < 0) {
        const locked = failed(state, "totp");
        return reply({ error: locked ? lockMessage("authenticator") : "That authenticator code cannot be used. Check it and try again." }, locked ? 429 : 400, request);
      }
      state.acceptedSteps = [...state.acceptedSteps, accepted].slice(-100);
      state.enrolled = true; session.mfaVerified = true;
      succeeded(state, "totp"); await saveStore();
      return reply({ ok: true }, 200, request);
    }

    /* Requirement task: recovery code creation requires a verified MFA session. */
    if (url.pathname === "/api/mfa/recovery/generate" || url.pathname === "/api/mfa/recovery/regenerate") {
      if (!session.mfaVerified) {
        return reply({ error: "Verify your authenticator or a recovery code first, then create recovery codes." }, 403, request);
      }
      if (!state.enrolled) return reply({ error: "MFA has not been enrolled for this account." }, 403, request);
      if (url.pathname.endsWith("generate")) {
        if (state.recoveryHashes.length) return reply({ error: "Recovery codes already exist. Use replacement only if you need a new set." }, 409, request);
        return reply({ codes: await generateRecovery(state) }, 200, request);
      }
      if (input.confirm !== true) return reply({ error: "Confirm that you want to replace the old codes." }, 400, request);
      return reply({ codes: await generateRecovery(state) }, 200, request);
    }

    if (url.pathname === "/api/mfa/recovery/verify") {
      if (!state.enrolled) return reply({ error: "MFA has not been enrolled for this account." }, 403, request);
      const item = attempt(state, "recovery");
      if (item.lockedUntil > Date.now()) return reply({ error: lockMessage("recovery code") }, 429, request);
      const submitted = typeof input.code === "string" ? input.code.trim().toUpperCase() : "";
      const digest = safeRecovery(submitted) ? await hash(submitted) : "";
      const index = state.recoveryHashes.indexOf(digest);
      if (index < 0) {
        const locked = failed(state, "recovery");
        return reply({ error: locked ? lockMessage("recovery code") : "That recovery code cannot be used. Check the format ABCD-EFGH and try another saved code." }, locked ? 429 : 400, request);
      }
      state.recoveryHashes.splice(index, 1);
      session.mfaVerified = true;
      succeeded(state, "recovery"); await saveStore();
      return reply({ ok: true, message: "Recovery code accepted and removed." }, 200, request);
    }

    if (url.pathname === "/api/auth/logout") {
      sessions.delete(session.id);
      const response = reply({ ok: true }, 200, request);
      response.headers.set("Set-Cookie", "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
      return response;
    }
    return reply({ error: "Not found." }, 404, request);
  } catch {
    return reply({ error: "Something went wrong. Please try again." }, 500, request);
  }
}

/* Requirement 2/3: local mkcert TLS files are used for the HTTPS Bun server. */
Bun.serve({
  hostname: "0.0.0.0",
  port: PORT,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  fetch: handle,
});
