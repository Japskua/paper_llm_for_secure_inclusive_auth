
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const sessions = new Map<string, Session>();
/* Security requirement 2: only the exact deployed HTTPS origins are trusted. */
const allowedOrigins = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);
const USER = { id: "acct_marcus_01", email: "marcus@example.test" };
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFE_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60 * 1000;

type Challenge = {
  value: string;
  expires: number;
  used: boolean;
  attempts: number;
  lockedUntil: number;
};

type Session = {
  id: string;
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
  identityVerified: boolean;
  mfaVerified: boolean;
  identityChallenge?: Challenge;
  encryptedSecret?: string;
  totpAttempts: number;
  totpLockedUntil: number;
  acceptedTotpSteps: Set<number>;
  recoveryHashes: Set<string>;
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
  const text = atob(padded);
  return Uint8Array.from(text, c => c.charCodeAt(0));
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
  let result = "";
  for (let i = 0; i < 8; i++) result += recoveryAlphabet[bytes[i] % recoveryAlphabet.length];
  return result.slice(0, 4) + "-" + result.slice(4);
}
function secretValue() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = randomBytes(20);
  let value = "";
  for (const byte of bytes) value += alphabet[byte % alphabet.length];
  return value;
}

const masterMaterial = randomBytes(32);
const masterKey = await crypto.subtle.importKey("raw", masterMaterial, "AES-GCM", false, ["encrypt", "decrypt"]);
const hashPepper = secureToken(24);

async function protectAtRest(value: string) {
  const iv = randomBytes(12);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(value));
  const output = new Uint8Array(iv.length + cipher.byteLength);
  output.set(iv);
  output.set(new Uint8Array(cipher), iv.length);
  return base64Url(output);
}
async function revealAtRest(value: string) {
  const packed = fromBase64Url(value);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: packed.slice(0, 12) }, masterKey, packed.slice(12));
  return decoder.decode(plain);
}
async function codeHash(value: string) {
  const bytes = await crypto.subtle.digest("SHA-256", encoder.encode(hashPepper + ":" + value));
  return base64Url(new Uint8Array(bytes));
}
function createChallenge(): Challenge {
  return { value: randomDigits(), expires: Date.now() + CODE_LIFE_MS, used: false, attempts: 0, lockedUntil: 0 };
}
function validOrigin(req: Request) {
  const origin = req.headers.get("origin");
  /* No Origin is permitted only for direct same-site navigation; supplied origins must be exact. */
  return origin === null || allowedOrigins.has(origin);
}

/* Security requirements 2 and 4: strict headers, trusted-origin CORS, no verbose errors. */
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
  const nonce = secureToken(16);
  return new Response(JSON.stringify(data), { status, headers: secureHeaders(nonce, req?.headers.get("origin")) });
}
function htmlResponse() {
  const nonce = secureToken(16);
  const headers = secureHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(page(nonce), { headers });
}
function getCookie(req: Request, key: string) {
  const raw = req.headers.get("cookie") || "";
  const item = raw.split(";").map(v => v.trim()).find(v => v.startsWith(key + "="));
  return item ? item.slice(key.length + 1) : "";
}

/* Security requirement 1 & 5: ownership, expiry and secure session enforcement on every protected API route. */
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
async function requestBody(req: Request) {
  const type = req.headers.get("content-type") || "";
  if (!type.includes("application/json")) throw new Error("invalid");
  const body = await req.json();
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("invalid");
  return body as Record<string, unknown>;
}
function stateAllowed(req: Request, session: Session, body: Record<string, unknown>) {
  if (req.headers.get("x-csrf-token") !== session.csrf) return "This request could not be confirmed. Refresh and try again.";
  if ("userId" in body && body.userId !== session.userId) return "This account request is not allowed.";
  return "";
}
function safeEmail(value: unknown) {
  return typeof value === "string" && value.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function safeCode(value: unknown, recovery = false) {
  const pattern = recovery ? /^[A-Z2-9]{4}-[A-Z2-9]{4}$/ : /^\d{6}$/;
  return typeof value === "string" && pattern.test(value);
}
async function verifyChallenge(challenge: Challenge | undefined, code: string) {
  if (!challenge) return { ok: false, message: "Request a new code, then try again." };
  if (challenge.lockedUntil > Date.now()) return { ok: false, message: "Too many tries. Please wait 15 minutes, then request a new code." };
  if (challenge.used) return { ok: false, message: "That code was already used. Request a new code." };
  if (challenge.expires < Date.now()) return { ok: false, message: "That code has expired. Request a new code." };
  if (challenge.value !== code) {
    challenge.attempts++;
    if (challenge.attempts >= MAX_FAILURES) {
      challenge.lockedUntil = Date.now() + LOCK_MS;
      return { ok: false, message: "Too many tries. Please wait 15 minutes, then request a new code." };
    }
    return { ok: false, message: `That code does not match. Check the six numbers and try again (${MAX_FAILURES - challenge.attempts} tries left).` };
  }
  challenge.used = true;
  return { ok: true, message: "" };
}

/* Security requirement 3 and task: real RFC 6238 simulated TOTP, SHA-1, six digits, 30 seconds. */
function base32Decode(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, bitCount = 0;
  const out: number[] = [];
  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const n = alphabet.indexOf(char);
    if (n < 0) throw new Error("invalid secret");
    bits = (bits << 5) | n;
    bitCount += 5;
    if (bitCount >= 8) {
      out.push((bits >>> (bitCount - 8)) & 255);
      bitCount -= 8;
    }
  }
  return new Uint8Array(out);
}
async function totpForStep(secret: string, step: number) {
  const counter = new Uint8Array(8);
  let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(n & 255n); n >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = signed[19] & 15;
  const value = ((signed[offset] & 127) << 24) | (signed[offset + 1] << 16) | (signed[offset + 2] << 8) | signed[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
async function verifyTotp(session: Session, code: string) {
  if (!session.encryptedSecret) return { ok: false, message: "Return to set-up and add an authenticator first." };
  if (session.totpLockedUntil > Date.now()) return { ok: false, message: "Too many tries. Please wait 15 minutes, then try again." };
  const secret = await revealAtRest(session.encryptedSecret);
  const currentStep = Math.floor(Date.now() / 30000);
  for (let offset = -1; offset <= 1; offset++) {
    const step = currentStep + offset;
    if (await totpForStep(secret, step) === code) {
      if (session.acceptedTotpSteps.has(step)) return { ok: false, message: "That authenticator code was already used. Wait for your app to show a new code." };
      session.acceptedTotpSteps.add(step);
      session.totpAttempts = 0;
      return { ok: true, message: "" };
    }
  }
  session.totpAttempts++;
  if (session.totpAttempts >= MAX_FAILURES) {
    session.totpLockedUntil = Date.now() + LOCK_MS;
    return { ok: false, message: "Too many tries. Please wait 15 minutes, then try again." };
  }
  return { ok: false, message: `That code does not match your authenticator. Check the six numbers and try again (${MAX_FAILURES - session.totpAttempts} tries left).` };
}
function createSession() {
  const now = Date.now();
  const session: Session = {
    id: secureToken(), userId: USER.id, csrf: secureToken(), createdAt: now, lastSeen: now,
    identityVerified: false, mfaVerified: false, totpAttempts: 0, totpLockedUntil: 0,
    acceptedTotpSteps: new Set(), recoveryHashes: new Set(),
  };
  session.identityChallenge = createChallenge();
  sessions.set(session.id, session);
  return session;
}
function sessionCookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}
function provisioningUri(secret: string) {
  return `otpauth://totp/Example%20Bank:${encodeURIComponent(USER.email)}?secret=${secret}&issuer=Example%20Bank&algorithm=SHA1&digits=6&period=30`;
}
async function generateRecovery(session: Session) {
  const codes = Array.from({ length: 8 }, recoveryCode);
  session.recoveryHashes = new Set(await Promise.all(codes.map(codeHash)));
  return codes;
}

function page(nonce: string) {
return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Example Bank — security set-up</title>
<style nonce="${nonce}">
:root{--ink:#172535;--muted:#526476;--blue:#075bb8;--blue-dark:#03448e;--pale:#edf6ff;--line:#c9d6e2;--good:#146c43;--bad:#ad2430;--focus:#f0a100}*{box-sizing:border-box}body{margin:0;background:#f3f7fa;color:var(--ink);font-family:Arial,Verdana,Tahoma,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.025em}button,input{font:inherit;letter-spacing:.03em}button{cursor:pointer}.shell{width:min(100%,520px);margin:auto;min-height:100vh;background:#fff;box-shadow:0 0 20px #b9c7d155}header{padding:20px 22px 14px;border-bottom:1px solid var(--line)}.brand{margin:0;font-size:1.15rem;font-weight:700}.brand span{color:var(--blue)}.progress{margin:14px 0 0;color:var(--muted);font-size:.91rem}main{padding:24px 22px 36px}h1{font-size:1.65rem;line-height:1.25;margin:0 0 12px;letter-spacing:.01em}p{margin:0 0 17px}.lead{font-size:1.07rem}.card{border:1px solid var(--line);border-radius:12px;padding:17px;margin:18px 0;background:#fff}.note{background:var(--pale);border-left:5px solid var(--blue)}label{display:block;font-weight:700;margin:15px 0 6px}input{width:100%;min-height:52px;padding:10px 13px;border:2px solid #8295a8;border-radius:8px;color:var(--ink);background:#fff}input:focus,button:focus{outline:3px solid var(--focus);outline-offset:2px}.hint{color:var(--muted);font-size:.92rem;margin-top:5px}.primary{width:100%;min-height:54px;margin:22px 0 10px;padding:10px;border:0;border-radius:9px;background:var(--blue);color:#fff;font-weight:700}.primary:hover{background:var(--blue-dark)}.secondary,.linkbutton{min-height:42px;padding:7px 10px;border:1px solid var(--blue);border-radius:7px;background:#fff;color:var(--blue);font-weight:700}.linkbutton{border:0;padding:4px;text-decoration:underline}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:10px}.error{background:#fff0f1;border-left:5px solid var(--bad);padding:10px 13px;margin:15px 0;font-weight:700}.success{background:#edf9f1;border-left:5px solid var(--good);padding:10px 13px;margin:15px 0;font-weight:700}.hidden{display:none!important}.code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:1.08rem;letter-spacing:.11em;word-break:break-all;background:#f4f7f9;border:1px solid var(--line);padding:12px;border-radius:8px}.qr{width:245px;height:245px;display:block;background:#fff;border:1px solid var(--line);margin:12px auto;image-rendering:pixelated}.codes{display:grid;grid-template-columns:1fr 1fr;gap:9px;list-style:none;padding:0}.codes li{font-family:ui-monospace,monospace;letter-spacing:.07em;padding:9px;background:#f4f7f9;border-radius:6px;text-align:center}.checkline{display:flex;gap:11px;align-items:flex-start;margin-top:20px}.checkline input{width:25px;min-height:25px;margin-top:4px}.help{margin-top:27px;border-top:1px solid var(--line);padding-top:15px}.logs{margin-top:24px;border-top:2px solid var(--line);padding-top:12px}.logs summary{font-weight:700;color:var(--blue);cursor:pointer}#logbox{max-height:170px;overflow:auto;white-space:pre-wrap;font-family:ui-monospace,monospace;font-size:.77rem;line-height:1.45;background:#152536;color:#e7f2ff;border-radius:8px;padding:10px;margin-top:9px}.small{font-size:.9rem;color:var(--muted)}@media(max-width:360px){main{padding:20px 16px 30px}header{padding:18px 16px 12px}body{font-size:16px}}
</style></head><body><div class="shell"><header><p class="brand">◈ <span>Example Bank</span> security set-up</p><p id="progress" class="progress">Step 1 of 6</p></header><main id="app" aria-live="polite"></main></div>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",recoveryCodes=[],recoveryAcknowledged=false,current="signin",provisioning={secret:"",uri:""};
const app=document.getElementById("app"),progress=document.getElementById("progress"),logLines=[];
function visibleLog(message){console.log(message);logLines.push(message);const b=document.getElementById("logbox");if(b){b.textContent=logLines.join("\\n");b.scrollTop=b.scrollHeight}}
function esc(v){return String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function logs(){return '<details class="logs"><summary>▣ Logs for this demo</summary><div id="logbox"></div><p class="small">Test values are shown here and in the browser console. In a real bank, they would not be shown.</p></details>'}
function help(){return '<aside class="help"><strong>ⓘ Need help?</strong><br><span class="small">Take your time. You can retry or request a fresh code without penalty.</span></aside>'}
function message(t,g=false){return t?'<div class="'+(g?"success":"error")+'" role="alert">'+esc(t)+"</div>":""}
function render(screen,alertText="",good=false){
 current=screen;progress.textContent=({signin:"Step 1 of 6",identity:"Step 2 of 6",setup:"Step 3 of 6",confirm:"Step 4 of 6",recovery:"Step 5 of 6",done:"Step 6 of 6"})[screen]||"";
 let body="";
 if(screen==="signin")body='<h1>Sign in to set up extra protection</h1><p class="lead">We will help you add a second step before high-value payments.</p>'+message(alertText,good)+'<form id="signForm"><label for="email">✉ Email address</label><input id="email" type="email" autocomplete="email" inputmode="email" placeholder="name@example.com" required maxlength="120"><p class="hint">Example: marcus@example.com</p><button class="primary">Continue</button></form>'+help();
 if(screen==="identity")body='<h1>Check it is you</h1><p>We sent a six-number code to your email in this safe demo.</p>'+message(alertText,good)+'<form id="identityForm"><label for="identityCode">🔐 Email code</label><input id="identityCode" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="Example: 123456" required><p class="hint">Enter six numbers. There is no reading timer.</p><button class="primary">Verify code</button></form><div class="actions"><button class="secondary" id="resendIdentity">↻ Send a new code</button><button class="linkbutton" id="backSign">← Back</button></div>'+help();
 if(screen==="setup")body='<h1>Add your authenticator</h1><p>Use an authenticator app on your phone. Scanning is easier than typing.</p>'+message(alertText,good)+'<section class="card note"><strong>▣ Scan this QR code</strong><canvas class="qr" id="qr" width="245" height="245" aria-label="QR code for authenticator set-up"></canvas><p class="small">Use your app’s scan option, or use the copy button below.</p></section><button class="secondary" id="copyUri">⧉ Copy set-up link</button><button class="linkbutton" id="showManual">Show manual secret instead</button><div id="manual" class="hidden"><label>Manual secret</label><div class="code" id="secretText"></div><div class="actions"><button class="secondary" id="copySecret">⧉ Copy secret</button><button class="secondary" id="hideManual">Hide secret</button></div></div><button class="primary" id="continueConfirm">I added it — continue</button><button class="linkbutton" id="backIdentity">← Back</button>'+help();
 if(screen==="confirm")body='<h1>Check your authenticator</h1><p>Open the app and enter the six-number code it shows.</p>'+message(alertText,good)+'<form id="otpForm"><label for="otp">🔑 Authenticator code</label><input id="otp" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="Example: 123456" required><p class="hint">You have plenty of time. If needed, go back and start again.</p><button class="primary">Verify authenticator</button></form><div class="actions"><button class="secondary" id="newAuth">↻ Start with a new set-up code</button><button class="linkbutton" id="backSetup">← Back</button></div>'+help();
 if(screen==="recovery")body='<h1>Save recovery codes</h1><p>These one-use codes help if you lose your phone. Keep them somewhere private.</p>'+message(alertText,good)+'<section id="codePanel" class="card '+(recoveryCodes.length?"":"hidden")+'"><ul id="codeList" class="codes"></ul><div class="actions"><button class="secondary" id="copyCodes">⧉ Copy codes</button><button class="secondary" id="printCodes">▤ Print or save</button></div><button class="secondary" id="regenCodes">↻ Make new codes</button></section><button class="primary '+(recoveryCodes.length?"hidden":"")+'" id="makeCodes">Show recovery codes</button><div id="ackWrap" class="checkline '+(recoveryCodes.length?"":"hidden")+'"><input id="ack" type="checkbox" '+(recoveryAcknowledged?"checked":"")+'><label for="ack">I saved my recovery codes in a private place.</label></div><button class="primary '+(recoveryCodes.length?"":"hidden")+'" id="finish">Finish set-up</button>'+help();
 if(screen==="done")body='<h1>✓ Extra protection is ready</h1><p class="lead">Your authenticator is set up. You can now approve protected payments.</p>'+message(alertText||"You have completed MFA enrolment.",true)+'<section class="card note"><strong>What happens next</strong><br>You will use your authenticator when a payment needs extra protection.</section><button class="primary" id="logout">Sign out safely</button>'+help();
 app.innerHTML=body+logs();const b=document.getElementById("logbox");if(b)b.textContent=logLines.join("\\n");bind(screen);if(screen==="recovery"&&recoveryCodes.length)fillCodes();
}
async function api(path,body={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body)}),d=await r.json().catch(()=>({error:"Something went wrong. Please try again."}));if(!r.ok)throw new Error(d.error||"Something went wrong. Please try again.");return d}
function copy(text,ok){navigator.clipboard.writeText(text).then(()=>render(current,ok,true)).catch(()=>render(current,"Copy did not work. Select the text and copy it another way."))}
function fillCodes(){const list=document.getElementById("codeList");if(list)list.innerHTML=recoveryCodes.map(c=>"<li>"+esc(c)+"</li>").join("");const a=document.getElementById("ack");if(a)a.checked=recoveryAcknowledged}

/* Standards-compliant QR encoder: QR Version 8, level L, byte mode, encoding the exact otpauth URI. */
function qrCode(text){
 const bytes=new TextEncoder().encode(text),N=49,data=[],push=(v,n)=>{for(let i=n-1;i>=0;i--)data.push((v>>i)&1)};push(4,4);push(bytes.length,8);bytes.forEach(x=>push(x,8));for(let i=0;i<4&&data.length<1552;i++)data.push(0);while(data.length%8)data.push(0);
 let words=[];for(let i=0;i<data.length;i+=8)words.push(data.slice(i,i+8).reduce((a,b)=>a*2+b,0));for(let p=0;words.length<194;p++)words.push(p%2?236:17);
 const exp=[],log=[];let x=1;for(let i=0;i<255;i++){exp[i]=x;log[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;
 let gen=[1];for(let i=0;i<24;i++){const next=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=mul(gen[j],exp[i])}gen=next}
 const ecc=block=>{let r=Array(24).fill(0);for(const v of block){const f=v^r.shift();r.push(0);for(let j=0;j<24;j++)r[j]^=mul(gen[j+1],f)}return r};
 const blocks=[words.slice(0,97),words.slice(97)],ec=blocks.map(ecc),stream=[];for(let i=0;i<97;i++)for(const b of blocks)stream.push(b[i]);for(let i=0;i<24;i++)for(const b of ec)stream.push(b[i]);
 const bits=[];stream.forEach(v=>pushTo(bits,v,8));function pushTo(a,v,n){for(let i=n-1;i>=0;i--)a.push((v>>i)&1)}
 const make=mask=>{const m=Array.from({length:N},()=>Array(N).fill(null)),reserved=Array.from({length:N},()=>Array(N).fill(false)),set=(r,c,v,res=true)=>{if(r>=0&&c>=0&&r<N&&c<N){m[r][c]=v;if(res)reserved[r][c]=true}};
 const finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)set(r+y,c+z,y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4))?1:0)};
 finder(0,0);finder(0,N-7);finder(N-7,0);for(let i=8;i<N-8;i++){set(6,i,i%2?0:1);set(i,6,i%2?0:1)}
 const align=(r,c)=>{for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)set(r+y,c+z,Math.max(Math.abs(y),Math.abs(z))===2||(!y&&!z)?1:0)};[6,24,42].forEach(r=>[6,24,42].forEach(c=>{if(!((r===6&&c===6)||(r===6&&c===42)||(r===42&&c===6)))align(r,c)}));set(N-8,8,1);
 for(let i=0;i<9;i++){if(i!==6){set(8,i,0);set(i,8,0)}}for(let i=0;i<8;i++){set(N-1-i,8,0);set(8,N-1-i,0)}
 let v=8<<12;let d=v;while(d.toString(2).length>=13)d^=0x1f25;v|=d;for(let i=0;i<18;i++){const bit=(v>>i)&1;set(Math.floor(i/3),N-11+i%3,bit);set(N-11+i%3,Math.floor(i/3),bit)}
 let k=0,up=true;for(let c=N-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<N;q++){const r=up?N-1-q:q;for(let z=0;z<2;z++){const col=c-z;if(!reserved[r][col]){let bit=bits[k++]||0;const flip=[(r+col)%2===0,r%2===0,col%3===0,(r+col)%3===0,(Math.floor(r/2)+Math.floor(col/3))%2===0,(r*col)%2+(r*col)%3===0,((r*col)%2+(r*col)%3)%2===0,((r+col)%2+(r*col)%3)%2===0][mask];m[r][col]=bit^(flip?1:0)}}}up=!up}
 let fmt=(1<<3)|mask;let f=fmt<<10,t=f;while(t.toString(2).length>=11)t^=0x537;f=(f|t)^0x5412;for(let i=0;i<15;i++){const bit=(f>>i)&1;if(i<6)set(i,8,bit);else if(i<8)set(i+1,8,bit);else set(N-15+i,8,bit);if(i<8)set(8,N-i-1,bit);else if(i<9)set(8,15-i,bit);else set(8,15-i-1,bit)}return m};
 const score=m=>{let s=0;for(let r=0;r<N;r++)for(let c=0;c<N;c++){let n=0;for(let y=-1;y<=1;y++)for(let z=-1;z<=1;z++)if((y||z)&&m[r+y]?.[c+z]===m[r][c])n++;if(n>5)s+=3+n-5}for(let r=0;r<N-6;r++)for(let c=0;c<N-6;c++){const a=m[r][c];if(m[r+6][c]===a&&m[r][c+6]===a&&m[r+6][c+6]===a&&m[r+2][c+2]===a&&m[r+4][c+2]===a&&m[r+2][c+4]===a&&m[r+4][c+4]===a)s+=3}let dark=m.flat().filter(Boolean).length;s+=Math.floor(Math.abs(dark*100/N/N-50)/5)*10;return s};
 let best=make(0);for(let i=1;i<8;i++){const q=make(i);if(score(q)<score(best))best=q}return best;
}
function drawQr(uri){const c=document.getElementById("qr");if(!c)return;const m=qrCode(uri),ctx=c.getContext("2d"),unit=c.width/m.length;ctx.fillStyle="#fff";ctx.fillRect(0,0,c.width,c.height);ctx.fillStyle="#102a43";m.forEach((row,y)=>row.forEach((v,x)=>{if(v)ctx.fillRect(x*unit,y*unit,Math.ceil(unit),Math.ceil(unit))}))}
function bind(screen){
 const on=(id,fn)=>{const e=document.getElementById(id);if(e)e.addEventListener("click",fn)};
 if(screen==="signin")document.getElementById("signForm").addEventListener("submit",async e=>{e.preventDefault();try{const d=await api("/api/auth/signin",{email:document.getElementById("email").value.trim()});csrf=d.csrf;visibleLog("[Demo] Identity verification code: "+d.testCode);render("identity","A code was sent. Enter the six numbers.",true)}catch(err){render("signin",err.message)}});
 if(screen==="identity"){document.getElementById("identityForm").addEventListener("submit",async e=>{e.preventDefault();try{await api("/api/identity/verify",{code:document.getElementById("identityCode").value.trim()});render("setup","Identity confirmed. Now add your authenticator.",true)}catch(err){render("identity",err.message)}});on("resendIdentity",async()=>{try{const d=await api("/api/identity/resend",{});visibleLog("[Demo] New identity code: "+d.testCode);render("identity","A new code was sent.",true)}catch(err){render("identity",err.message)}});on("backSign",()=>render("signin"))}
 if(screen==="setup"){api("/api/mfa/provision",{}).then(d=>{provisioning=d;visibleLog("[Demo] Authenticator secret: "+d.testSecret);visibleLog("[Demo] Authenticator verification code: "+d.testCode);drawQr(d.uri);document.getElementById("secretText").textContent=d.secret}).catch(err=>render("identity",err.message));on("copyUri",()=>copy(provisioning.uri,"Set-up link copied."));on("showManual",()=>document.getElementById("manual").classList.remove("hidden"));on("hideManual",()=>document.getElementById("manual").classList.add("hidden"));on("copySecret",()=>copy(provisioning.secret,"Manual secret copied."));on("continueConfirm",()=>render("confirm"));on("backIdentity",()=>render("identity"))}
 if(screen==="confirm"){document.getElementById("otpForm").addEventListener("submit",async e=>{e.preventDefault();try{await api("/api/mfa/verify",{code:document.getElementById("otp").value.trim()});render("recovery","Authenticator confirmed. Save recovery codes next.",true)}catch(err){render("confirm",err.message)}});on("newAuth",async()=>{try{provisioning={secret:"",uri:""};await api("/api/mfa/provision/new",{});render("setup","A fresh set-up code was created.",true)}catch(err){render("confirm",err.message)}});on("backSetup",()=>render("setup"))}
 if(screen==="recovery"){const make=async()=>{try{const d=await api("/api/mfa/recovery/generate",{});recoveryCodes=d.codes;recoveryAcknowledged=false;visibleLog("[Demo] Recovery codes: "+d.codes.join(", "));render("recovery","Your recovery codes are ready.",true)}catch(err){render("recovery",err.message)}};on("makeCodes",make);on("regenCodes",make);on("copyCodes",()=>copy(recoveryCodes.join("\\n"),"Recovery codes copied."));on("printCodes",()=>{const w=window.open("","_blank");if(!w){render("recovery","Printing was blocked. Use Copy codes instead.");return}w.document.write("<pre>Example Bank recovery codes\\n\\n"+recoveryCodes.join("\\n")+"</pre>");w.document.close();w.print()});const ack=document.getElementById("ack");if(ack)ack.addEventListener("change",()=>recoveryAcknowledged=ack.checked);on("finish",()=>{if(!recoveryAcknowledged){render("recovery","Please tick the box after you have saved the codes.");return}recoveryCodes=[];recoveryAcknowledged=false;render("done")})}
 if(screen==="done")on("logout",async()=>{try{await api("/api/auth/logout",{})}catch(_){}csrf="";provisioning={secret:"",uri:""};render("signin","You are signed out safely.",true)})
}
render("signin")})();
</script></body></html>`;
}

async function provision(session: Session, fresh: boolean) {
  if (fresh || !session.encryptedSecret) {
    const secret = secretValue();
    session.encryptedSecret = await protectAtRest(secret);
    session.mfaVerified = false;
    session.totpAttempts = 0;
    session.totpLockedUntil = 0;
    session.acceptedTotpSteps.clear();
  }
  const secret = await revealAtRest(session.encryptedSecret!);
  const step = Math.floor(Date.now() / 30000);
  return { secret, uri: provisioningUri(secret), testSecret: secret, testCode: await totpForStep(secret, step) };
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

    if (url.pathname === "/api/auth/signin") {
      const body = await requestBody(req);
      if (!safeEmail(body.email)) return json({ error: "Enter an email in the format name@example.com." }, 400, req);
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
      session.identityChallenge = createChallenge();
      return json({ testCode: session.identityChallenge.value }, 200, req);
    }
    if (url.pathname === "/api/identity/verify") {
      if (!safeCode(body.code)) return json({ error: "Enter the six numbers from the code." }, 400, req);
      const result = await verifyChallenge(session.identityChallenge, body.code as string);
      if (!result.ok) return json({ error: result.message }, 400, req);
      session.identityVerified = true;
      return json({ ok: true }, 200, req);
    }
    if (!session.identityVerified) return json({ error: "Complete the identity check before changing MFA settings." }, 403, req);

    if (url.pathname === "/api/mfa/provision") return json(await provision(session, false), 200, req);
    if (url.pathname === "/api/mfa/provision/new") return json(await provision(session, true), 200, req);

    if (url.pathname === "/api/mfa/verify") {
      if (!safeCode(body.code)) return json({ error: "Enter the six numbers from your authenticator app." }, 400, req);
      const result = await verifyTotp(session, body.code as string);
      if (!result.ok) return json({ error: result.message }, 400, req);
      session.mfaVerified = true;
      return json({ ok: true }, 200, req);
    }
    if (url.pathname === "/api/mfa/recovery/generate") {
      if (!session.mfaVerified) return json({ error: "Confirm your authenticator before making recovery codes." }, 403, req);
      return json({ codes: await generateRecovery(session) }, 200, req);
    }
    if (url.pathname === "/api/mfa/recovery/verify") {
      if (!session.mfaVerified) return json({ error: "MFA is not ready." }, 403, req);
      const code = typeof body.code === "string" ? body.code.toUpperCase() : "";
      if (!safeCode(code, true)) return json({ error: "Use the format ABCD-EFGH." }, 400, req);
      const hashed = await codeHash(code);
      if (!session.recoveryHashes.delete(hashed)) return json({ error: "That recovery code cannot be used. Try another saved code." }, 400, req);
      return json({ ok: true }, 200, req);
    }
    return json({ error: "Not found." }, 404, req);
  } catch {
    return json({ error: "Something went wrong. Please try again." }, 500, req);
  }
}

/* TLS requirement: Bun serves HTTPS using the supplied local mkcert files. */
Bun.serve({
  port: 3000,
  hostname: "0.0.0.0",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  fetch: handle,
});
