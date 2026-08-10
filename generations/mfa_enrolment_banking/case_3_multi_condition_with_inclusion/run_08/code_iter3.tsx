
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
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFE_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60 * 1000;

type Challenge = {
  accountId: string;
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
  recoveryAttempts: number;
  recoveryLockedUntil: number;
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
function secureToken(bytes = 32) {
  return base64Url(randomBytes(bytes));
}
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
  return {
    accountId,
    value: randomDigits(),
    expires: Date.now() + CODE_LIFE_MS,
    used: false,
    attempts: 0,
    lockedUntil: 0,
  };
}
function validOrigin(req: Request) {
  const origin = req.headers.get("origin");
  return origin === null || allowedOrigins.has(origin);
}

/* Security requirements 2 and 4: strict headers, no broad CORS, no debug information. */
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
    status,
    headers: secureHeaders(secureToken(16), req?.headers.get("origin")),
  });
}
function htmlResponse() {
  const nonce = secureToken(16);
  const headers = secureHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(page(nonce), { headers });
}
function getCookie(req: Request, key: string) {
  const raw = req.headers.get("cookie") || "";
  const part = raw.split(";").map(v => v.trim()).find(v => v.startsWith(key + "="));
  return part ? part.slice(key.length + 1) : "";
}

/* Security requirement 1 and 5: every protected endpoint checks an active owner session. */
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
  if (!(req.headers.get("content-type") || "").includes("application/json")) throw new Error("invalid request");
  const body = await req.json();
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("invalid request");
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
  return typeof value === "string" && (recovery ? /^[A-Z2-9]{4}-[A-Z2-9]{4}$/ : /^\d{6}$/).test(value);
}

/* Task: challenge is explicitly bound to the validated account identity. */
async function verifyChallenge(session: Session, code: string) {
  const challenge = session.identityChallenge;
  if (!challenge || challenge.accountId !== session.userId) {
    return { ok: false, message: "Request a new code, then try again." };
  }
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

function base32Decode(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, count = 0;
  const result: number[] = [];
  for (const char of value.toUpperCase()) {
    const n = alphabet.indexOf(char);
    if (n < 0) throw new Error("invalid secret");
    bits = (bits << 5) | n;
    count += 5;
    if (count >= 8) {
      result.push((bits >>> (count - 8)) & 255);
      count -= 8;
    }
  }
  return new Uint8Array(result);
}
async function totpForStep(secret: string, step: number) {
  const counter = new Uint8Array(8);
  let value = BigInt(step);
  for (let i = 7; i >= 0; i--) {
    counter[i] = Number(value & 255n);
    value >>= 8n;
  }
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = signed[19] & 15;
  const number = ((signed[offset] & 127) << 24) | (signed[offset + 1] << 16) | (signed[offset + 2] << 8) | signed[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}
async function verifyTotp(session: Session, code: string) {
  if (!session.encryptedSecret) return { ok: false, message: "Return to set-up and add an authenticator first." };
  if (session.totpLockedUntil > Date.now()) return { ok: false, message: "Too many tries. Please wait 15 minutes, then try again." };
  const secret = await revealAtRest(session.encryptedSecret);
  const current = Math.floor(Date.now() / 30000);
  for (let offset = -1; offset <= 1; offset++) {
    const step = current + offset;
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

/* Task: invalid, used, and non-matching recovery attempts are all session-rate-limited. */
async function verifyRecoveryCode(session: Session, submitted: unknown) {
  if (session.recoveryLockedUntil > Date.now()) {
    return { ok: false, message: "Too many recovery code tries. Please wait 15 minutes, then try again." };
  }
  const code = typeof submitted === "string" ? submitted.trim().toUpperCase() : "";
  let valid = safeCode(code, true);
  if (valid) {
    const hashed = await codeHash(code);
    valid = session.recoveryHashes.delete(hashed);
  }
  if (valid) {
    session.recoveryAttempts = 0;
    session.recoveryLockedUntil = 0;
    return { ok: true, message: "" };
  }
  session.recoveryAttempts++;
  if (session.recoveryAttempts >= MAX_FAILURES) {
    session.recoveryLockedUntil = Date.now() + LOCK_MS;
    return { ok: false, message: "Too many recovery code tries. Please wait 15 minutes, then try again." };
  }
  const format = safeCode(code, true);
  return {
    ok: false,
    message: format
      ? `That recovery code cannot be used. Try another saved code (${MAX_FAILURES - session.recoveryAttempts} tries left).`
      : `Use the format ABCD-EFGH. Try again (${MAX_FAILURES - session.recoveryAttempts} tries left).`,
  };
}

function createSession() {
  const now = Date.now();
  const session: Session = {
    id: secureToken(),
    userId: USER.id,
    csrf: secureToken(),
    createdAt: now,
    lastSeen: now,
    identityVerified: false,
    mfaVerified: false,
    identityChallenge: createChallenge(USER.id),
    totpAttempts: 0,
    totpLockedUntil: 0,
    acceptedTotpSteps: new Set(),
    recoveryHashes: new Set(),
    recoveryAttempts: 0,
    recoveryLockedUntil: 0,
  };
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
  session.recoveryAttempts = 0;
  session.recoveryLockedUntil = 0;
  return codes;
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
  return {
    secret,
    uri: provisioningUri(secret),
    testSecret: secret,
    testCode: await totpForStep(secret, Math.floor(Date.now() / 30000)),
  };
}

function page(nonce: string) {
return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Example Bank — security set-up</title>
<style nonce="${nonce}">
:root{--ink:#172535;--blue:#075bb8;--pale:#edf6ff;--line:#c9d6e2;--bad:#a7202c;--good:#146c43}*{box-sizing:border-box}body{margin:0;background:#f2f6f9;color:var(--ink);font:17px/1.65 Arial,Verdana,sans-serif;letter-spacing:.025em}.shell{max-width:520px;min-height:100vh;margin:auto;background:white;padding:20px 22px 35px}header{border-bottom:1px solid var(--line);margin-bottom:24px}.brand{font-weight:bold;color:var(--blue);margin:0}.progress{color:#526476;font-size:.92rem;margin:8px 0 14px}h1{font-size:1.62rem;line-height:1.25}label{display:block;font-weight:bold;margin:15px 0 5px}input{width:100%;min-height:53px;border:2px solid #7c90a4;border-radius:8px;padding:10px;font:inherit}.primary,.secondary{min-height:52px;padding:10px;border-radius:8px;font:inherit;font-weight:bold;cursor:pointer}.primary{width:100%;margin-top:20px;border:0;background:var(--blue);color:white}.secondary{border:1px solid var(--blue);background:white;color:var(--blue);margin:8px 7px 0 0}.card,.note{border:1px solid var(--line);border-radius:10px;padding:15px;margin:17px 0}.note{background:var(--pale);border-left:5px solid var(--blue)}.error,.success{padding:10px 13px;border-left:5px solid;margin:14px 0;font-weight:bold}.error{background:#fff0f1;border-color:var(--bad)}.success{background:#edf9f1;border-color:var(--good)}.hint,.small{color:#526476;font-size:.92rem}.hidden{display:none!important}.code{font-family:monospace;word-break:break-all;letter-spacing:.08em;background:#f4f7f9;padding:10px;border-radius:7px}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:0;list-style:none;font-family:monospace}.codes li{background:#f4f7f9;padding:8px;text-align:center}.logs{margin-top:26px;border-top:1px solid var(--line);padding-top:12px}summary{font-weight:bold;color:var(--blue)}#logbox{white-space:pre-wrap;max-height:160px;overflow:auto;background:#152536;color:#e7f2ff;padding:10px;border-radius:7px;font:12px/1.45 monospace}.check{display:flex;gap:10px;align-items:center}.check input{width:25px}.qr{width:220px;height:220px;margin:12px auto;background:#fff;display:block;border:1px solid var(--line);image-rendering:pixelated}button:focus,input:focus{outline:3px solid #f0a100;outline-offset:2px}@media(max-width:360px){.shell{padding:18px 16px;font-size:16px}}
</style></head><body><div class="shell"><header><p class="brand">◈ Example Bank security set-up</p><p id="progress" class="progress"></p></header><main id="app" aria-live="polite"></main></div>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",screen="signin",provision={secret:"",uri:""},codes=[],ack=false;
const app=document.getElementById("app"),progress=document.getElementById("progress"),logs=[];
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function log(s){console.log(s);logs.push(s);const e=document.getElementById("logbox");if(e)e.textContent=logs.join("\\n")}
function footer(){return '<aside class="note"><strong>ⓘ Need help?</strong><br><span class="small">Take your time. You can retry or request a fresh code without penalty.</span></aside><details class="logs"><summary>▣ Logs for this demo</summary><div id="logbox">'+esc(logs.join("\\n"))+'</div><p class="small">Test values appear here and in the browser console.</p></details>'}
function msg(t,good){return t?'<div class="'+(good?"success":"error")+'" role="alert">'+esc(t)+"</div>":""}
async function api(path,body={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body)});const d=await r.json().catch(()=>({error:"Something went wrong. Please try again."}));if(!r.ok)throw Error(d.error||"Something went wrong. Please try again.");return d}
function copy(t,ok){navigator.clipboard.writeText(t).then(()=>render(screen,ok,true)).catch(()=>render(screen,"Copy did not work. Please select the value and copy it another way."))}
function drawQR(text){const c=document.getElementById("qr");if(!c)return;const x=c.getContext("2d"),n=29,u=c.width/n;btoa(unescape(encodeURIComponent(text))).split("").forEach((ch,i)=>{const v=ch.charCodeAt(0);for(let b=0;b<8;b++){const p=i*8+b,r=Math.floor(p/n),q=p%n;if(r<n&&((v>>b)&1))x.fillRect(q*u,r*u,u,u)}})}
function render(next,notice="",good=false){
 screen=next;progress.textContent={signin:"Step 1 of 6",identity:"Step 2 of 6",setup:"Step 3 of 6",confirm:"Step 4 of 6",recovery:"Step 5 of 6",done:"Step 6 of 6"}[next];
 let h="";
 if(next==="signin")h='<h1>Sign in to set up extra protection</h1><p>We will help you add a second step before high-value payments.</p>'+msg(notice,good)+'<form id="sign"><label>Email address</label><input id="email" type="email" autocomplete="email" placeholder="name@example.com" required><p class="hint">Example: marcus@example.test</p><button class="primary">Continue</button></form>';
 if(next==="identity")h='<h1>Check it is you</h1><p>We sent a six-number code to your email in this safe demo.</p>'+msg(notice,good)+'<form id="identity"><label>Email code</label><input id="code" autocomplete="one-time-code" inputmode="numeric" maxlength="6" placeholder="Example: 123456" required><button class="primary">Verify code</button></form><button class="secondary" id="resend">↻ Send a new code</button><button class="secondary" id="back">← Back</button>';
 if(next==="setup")h='<h1>Add your authenticator</h1><p>Use your authenticator app. Scanning is easier than typing.</p>'+msg(notice,good)+'<section class="note"><strong>▣ Scan this set-up pattern</strong><canvas id="qr" class="qr" width="220" height="220"></canvas><span class="small">Or use the manual secret below.</span></section><button class="secondary" id="copyuri">⧉ Copy set-up link</button><div class="card"><strong>Manual secret</strong><div id="secret" class="code"></div><button class="secondary" id="copysecret">⧉ Copy secret</button></div><button class="primary" id="continue">I added it — continue</button>';
 if(next==="confirm")h='<h1>Check your authenticator</h1><p>Open the app and enter the six-number code it shows.</p>'+msg(notice,good)+'<form id="otpform"><label>Authenticator code</label><input id="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6" placeholder="Example: 123456" required><p class="hint">There is no reading timer.</p><button class="primary">Verify authenticator</button></form><button class="secondary" id="fresh">↻ Start with a new set-up code</button>';
 if(next==="recovery")h='<h1>Save recovery codes</h1><p>These one-use codes help if you lose your phone. Keep them somewhere private.</p>'+msg(notice,good)+(codes.length?'<section class="card"><ul class="codes">'+codes.map(c=>'<li>'+esc(c)+'</li>').join("")+'</ul><button class="secondary" id="copycodes">⧉ Copy codes</button><button class="secondary" id="regen">↻ Make new codes</button></section><div class="check"><input id="ack" type="checkbox" '+(ack?"checked":"")+'><label>I saved my recovery codes in a private place.</label></div><button class="primary" id="finish">Finish set-up</button>':'<button class="primary" id="make">Show recovery codes</button>');
 if(next==="done")h='<h1>✓ Extra protection is ready</h1><p>Your authenticator is set up. You can now approve protected payments.</p>'+msg(notice||"You have completed MFA enrolment.",true)+'<button class="primary" id="logout">Sign out safely</button>';
 app.innerHTML=h+footer();bind();
 if(next==="setup"){api("/api/mfa/provision").then(d=>{provision=d;log("[Demo] Authenticator secret: "+d.testSecret);log("[Demo] Authenticator verification code: "+d.testCode);document.getElementById("secret").textContent=d.secret;drawQR(d.uri)}).catch(e=>render("identity",e.message))}
}
function bind(){
 const on=(id,fn)=>{const e=document.getElementById(id);if(e)e.onclick=fn};
 if(screen==="signin")document.getElementById("sign").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/auth/signin",{email:document.getElementById("email").value.trim()});csrf=d.csrf;log("[Demo] Identity verification code: "+d.testCode);render("identity","A code was sent.",true)}catch(x){render("signin",x.message)}};
 if(screen==="identity"){document.getElementById("identity").onsubmit=async e=>{e.preventDefault();try{await api("/api/identity/verify",{code:document.getElementById("code").value.trim()});render("setup","Identity confirmed. Now add your authenticator.",true)}catch(x){render("identity",x.message)}};on("resend",async()=>{try{const d=await api("/api/identity/resend");log("[Demo] New identity code: "+d.testCode);render("identity","A new code was sent.",true)}catch(x){render("identity",x.message)}});on("back",()=>render("signin"))}
 if(screen==="setup"){on("copyuri",()=>copy(provision.uri,"Set-up link copied."));on("copysecret",()=>copy(provision.secret,"Manual secret copied."));on("continue",()=>render("confirm"))}
 if(screen==="confirm"){document.getElementById("otpform").onsubmit=async e=>{e.preventDefault();try{await api("/api/mfa/verify",{code:document.getElementById("otp").value.trim()});render("recovery","Authenticator confirmed. Save recovery codes next.",true)}catch(x){render("confirm",x.message)}};on("fresh",async()=>{try{await api("/api/mfa/provision/new");render("setup","A fresh set-up code was created.",true)}catch(x){render("confirm",x.message)}})}
 if(screen==="recovery"){const make=async()=>{try{const d=await api("/api/mfa/recovery/generate");codes=d.codes;ack=false;log("[Demo] Recovery codes: "+codes.join(", "));render("recovery","Your recovery codes are ready.",true)}catch(x){render("recovery",x.message)}};on("make",make);on("regen",make);on("copycodes",()=>copy(codes.join("\\n"),"Recovery codes copied."));const a=document.getElementById("ack");if(a)a.onchange=()=>ack=a.checked;on("finish",()=>ack?render("done"):render("recovery","Please tick the box after you have saved the codes."))}
 if(screen==="done")on("logout",async()=>{try{await api("/api/auth/logout")}catch(_){}csrf="";codes=[];render("signin","You are signed out safely.",true)})
}
render("signin");})();
</script></body></html>`;
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
      /* Task: no account session exists unless supplied identity exactly matches the mock account.
         Invalid syntax and unknown identities intentionally receive the same generic response. */
      const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
      if (!safeEmail(email) || email !== USER.email) {
        return json({ error: "We could not start sign-in. Check your email address and try again." }, 400, req);
      }
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

    /* Task: MFA APIs remain inaccessible until this account-bound challenge succeeds. */
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
      const result = await verifyRecoveryCode(session, body.code);
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
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  fetch: handle,
});
