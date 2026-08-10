
import { createHash, randomBytes, createCipheriv, createDecipheriv, createHmac } from "crypto";

/*
  MFA Enrolment System
  Requirements sections:
  - Security 1/5: opaque sessions, ownership checks, CSRF, expiry, lockouts/rate limits
  - Security 2/3/4: TLS-only service, secure headers, trusted origins, protected secrets
  - Accessibility: concise mobile screens, generous spacing, no reading time limits
*/

type FailureState = {
  attempts: number;
  lockedUntil?: number;
  requestTimes?: number[];
};

type Session = {
  id: string;
  userId?: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
  stage: "signed-out" | "identity" | "setup" | "backup" | "success";
  identity?: {
    codeHash?: string;
    expiresAt?: number;
    attempts: number;
    used: boolean;
    lockedUntil?: number;
    requestTimes: number[];
  };
  pendingSecret?: string;
  pendingOtpHash?: string;
  pendingOtpExpires?: number;
  authenticatorFailures?: FailureState;
  signInFailures?: FailureState;
};

type Account = {
  id: string;
  email: string;
  phone: string;
  authenticatorSecret?: string;
  backupCodes: Map<string, boolean>;
  recoveryFailures?: FailureState;
  signInFailures?: FailureState;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const encryptionKey = randomBytes(32);
const hashPepper = randomBytes(32);

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 10 * 60 * 1000;
const LOCKOUT_MS = 15 * 60 * 1000;
const MAX_FAILURES = 5;
const IDENTITY_REQUEST_WINDOW_MS = 15 * 60 * 1000;
const MAX_IDENTITY_REQUESTS = 3;

accounts.set("marcus-001", {
  id: "marcus-001",
  email: "marcus@example.test",
  phone: "+15555550142",
  backupCodes: new Map(),
});

function opaque(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

function hash(value: string) {
  return createHash("sha256").update(hashPepper).update(value).digest("hex");
}

function protect(plain: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return `${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${ciphertext.toString("base64url")}`;
}

function reveal(protectedValue: string) {
  const [ivText, tagText, dataText] = protectedValue.split(".");
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, Buffer.from(ivText, "base64url"));
  decipher.setAuthTag(Buffer.from(tagText, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(dataText, "base64url")), decipher.final()]).toString("utf8");
}

function base32(bytes: Buffer) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0, result = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) result += alphabet[(value << (5 - bits)) & 31];
  return result;
}

function otpFor(secret: string) {
  const window = Math.floor(Date.now() / CODE_LIFETIME_MS);
  const digest = createHmac("sha256", secret).update(String(window)).digest();
  return String(digest.readUInt32BE(0) % 1_000_000).padStart(6, "0");
}

function recoveryCodes() {
  return Array.from({ length: 8 }, () => {
    const raw = randomBytes(5).toString("hex").toUpperCase();
    return `${raw.slice(0, 5)}-${raw.slice(5)}`;
  });
}

function cookieValue(request: Request, name: string) {
  const found = (request.headers.get("cookie") || "").split(";").map(v => v.trim()).find(v => v.startsWith(`${name}=`));
  return found ? decodeURIComponent(found.slice(name.length + 1)) : "";
}

function sessionCookie(id: string) {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}

function clearCookie() {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

function freshSession(userId?: string): Session {
  const session: Session = {
    id: opaque(),
    csrf: opaque(),
    userId,
    createdAt: Date.now(),
    lastSeen: Date.now(),
    stage: userId ? "identity" : "signed-out",
    signInFailures: { attempts: 0 },
  };
  sessions.set(session.id, session);
  return session;
}

function getSession(request: Request) {
  const id = cookieValue(request, "mfa_session");
  const session = sessions.get(id);
  if (!session) return undefined;
  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return undefined;
  }
  session.lastSeen = now;
  return session;
}

function validEmail(value: unknown) {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validOtp(value: unknown) {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}

function validRecovery(value: unknown) {
  return typeof value === "string" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(value);
}

function allowedOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  const url = new URL(request.url);
  return origin === `${url.protocol}//${url.host}`;
}

function isLocked(state?: FailureState) {
  return !!state?.lockedUntil && Date.now() < state.lockedUntil;
}

function failedAttempt(state: FailureState) {
  state.attempts++;
  if (state.attempts >= MAX_FAILURES) state.lockedUntil = Date.now() + LOCKOUT_MS;
}

function clearFailures(state?: FailureState) {
  if (!state) return;
  state.attempts = 0;
  state.lockedUntil = undefined;
}

function retryMessage() {
  return "Too many attempts were made. Please wait 15 minutes, then try again.";
}

/* Requirement: refuse startup entirely unless TLS certificate material exists. */
const certFile = Bun.file("./certs/cert.pem");
const keyFile = Bun.file("./certs/key.pem");
if (!await certFile.exists() || !await keyFile.exists()) {
  throw new Error("TLS certificates are required: certs/cert.pem and certs/key.pem");
}

function headersFor(request: Request, nonce: string) {
  const origin = request.headers.get("origin");
  const ownOrigin = `${new URL(request.url).protocol}//${new URL(request.url).host}`;
  const headers: Record<string, string> = {
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  };
  if (origin === ownOrigin) {
    headers["Access-Control-Allow-Origin"] = ownOrigin;
    headers["Vary"] = "Origin";
  }
  return headers;
}

function json(request: Request, data: unknown, status = 200, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...headersFor(request, opaque(12)), "Content-Type": "application/json; charset=utf-8", ...extra },
  });
}

async function body(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 10_000) return null;
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

/* Security 1: every authenticated mutation checks ownership, same origin and CSRF. */
function requireSession(request: Request, mutation = false) {
  const session = getSession(request);
  if (!session?.userId || !accounts.has(session.userId)) {
    return { error: json(request, { error: "Please sign in to continue." }, 401) };
  }
  if (mutation) {
    if (!allowedOrigin(request)) return { error: json(request, { error: "This request was not accepted. Please try again." }, 403) };
    const token = request.headers.get("x-csrf-token");
    if (!token || token !== session.csrf) {
      return { error: json(request, { error: "Your security check expired. Refresh and try again." }, 403) };
    }
  }
  return { session, account: accounts.get(session.userId)! };
}

function authSummary(session: Session) {
  return { signedIn: true, stage: session.stage, csrf: session.csrf, email: "marcus@example.test" };
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Harbour Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#17243b;--blue:#1255b3;--pale:#edf5ff;--line:#c8d4e5;--good:#176b45;--bad:#a32727;--focus:#f2a900}
*{box-sizing:border-box}body{margin:0;background:#f5f8fc;color:var(--ink);font-family:Arial,Verdana,Tahoma,sans-serif;font-size:17px;letter-spacing:.035em;line-height:1.6}
main{max-width:620px;margin:auto;min-height:100vh;background:#fff;padding:22px 18px 38px}.brand{font-weight:700;font-size:1.12rem;color:#0d3979}.brand span{font-size:1.45rem;margin-right:7px}
.progress{margin:18px 0 23px;padding:10px 13px;background:var(--pale);border-left:5px solid var(--blue);border-radius:7px;font-size:.92rem}.view[hidden]{display:none}
h1{font-size:1.65rem;line-height:1.25;letter-spacing:.02em;margin:0 0 10px}h2{font-size:1.22rem;line-height:1.3}p{margin:8px 0 17px}.icon{font-size:1.6rem;margin-right:7px}
.card{border:1px solid var(--line);border-radius:12px;padding:18px;margin:17px 0;background:#fff}.hint{background:#fff8df;border-radius:9px;padding:11px 13px;font-size:.94rem}
.status{border-radius:8px;padding:11px 13px;margin:15px 0;font-weight:600}.status.good{background:#e8f7ef;color:var(--good)}.status.bad{background:#fff0f0;color:var(--bad)}
label{display:block;font-weight:700;margin:17px 0 5px}input,select{width:100%;font:inherit;letter-spacing:.06em;padding:13px;border:2px solid #8da2bd;border-radius:8px;background:#fff}
input:focus,select:focus,button:focus,a:focus{outline:4px solid var(--focus);outline-offset:2px}
button,.button{display:block;width:100%;border:0;border-radius:8px;padding:14px 15px;font:700 1rem Arial,sans-serif;letter-spacing:.03em;background:var(--blue);color:#fff;cursor:pointer;text-align:center;text-decoration:none;margin-top:20px}
.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue)}.small{font-size:.92rem;margin-top:12px}.row{display:flex;gap:10px;align-items:center}.row button{width:auto;margin:0;white-space:nowrap}
.code{font-family:ui-monospace,Consolas,monospace;letter-spacing:.12em;font-size:1.05rem;word-break:break-all;background:#f3f6fa;padding:12px;border-radius:7px;flex:1}
.codes{display:grid;grid-template-columns:1fr 1fr;gap:9px}.codes div{font-family:ui-monospace,monospace;background:#f3f6fa;padding:9px;border-radius:6px;font-size:.88rem;letter-spacing:.06em}
.check{display:flex;gap:10px;align-items:flex-start}.check input{width:22px;height:22px;margin-top:5px}.check label{margin:0;font-weight:normal}
.qr{display:flex;justify-content:center;background:#fff;padding:10px;border-radius:8px;overflow:auto}.qr canvas{width:min(100%,296px);height:auto;image-rendering:pixelated}
.logs{margin-top:30px;border-top:2px solid var(--line);padding-top:14px}.logs pre{white-space:pre-wrap;word-break:break-word;background:#101c2e;color:#eaf4ff;border-radius:8px;padding:12px;min-height:64px;font-size:.78rem;letter-spacing:0}
a{color:#064da9;font-weight:700}@media(max-width:380px){main{padding:17px 13px}.codes{grid-template-columns:1fr}body{font-size:16px}.row{align-items:stretch;flex-direction:column}.row button{width:100%}}
</style>
</head>
<body>
<main>
<header><div class="brand"><span>⚓</span>Harbour Bank</div><div class="progress" id="progress">Step 1 of 4 · Sign in</div></header>
<div id="message" aria-live="polite"></div>

<section class="view" id="sign-in">
<h1><span class="icon">🔐</span>Set up extra protection</h1>
<p>Sign in first. Then we will help you add your authenticator.</p>
<form id="loginForm">
<label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="username" inputmode="email" placeholder="name@example.com" required>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" placeholder="Your password" required>
<button>Sign in</button></form>
<div class="hint">💡 Demo sign-in: use <strong>marcus@example.test</strong> and <strong>CorrectHorse1!</strong></div>
<p class="small"><a href="#help">Need help?</a></p>
</section>

<section class="view" id="identity" hidden>
<h1><span class="icon">🪪</span>Check it is you</h1>
<p>We can send one short code to your email or phone.</p>
<label for="method">Send the code to</label><select id="method"><option value="email">Email: marcus@example.test</option><option value="phone">Phone ending 0142</option></select>
<button id="sendIdentity">Send code</button>
<div id="identityEntry" hidden><div class="status good">A code was sent. Enter the 6 numbers when you are ready.</div>
<label for="identityCode">Verification code</label><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456">
<button id="verifyIdentity">Check code</button><button class="secondary" id="resendIdentity">Send a new code</button></div>
<p class="small"><a href="#help">Need help?</a> · <a href="#logout">Sign out</a></p>
</section>

<section class="view" id="setup" hidden>
<h1><span class="icon">📱</span>Add your authenticator</h1>
<p>Open your authenticator app. Scan the square, or copy the setup key. You do not need to rush.</p>
<button id="startAuthenticator">Show setup options</button>
<div id="provision" hidden>
<div class="card"><h2>Option 1: scan this setup square</h2><div class="qr" id="qr" aria-label="Scannable authenticator setup QR code"></div></div>
<div class="card"><h2>Option 2: copy the setup key</h2><div id="secretArea"><div class="row"><div class="code" id="secretText"></div><button class="secondary" id="copySecret">Copy</button></div></div><button class="secondary small" id="hideSecret">Hide setup key</button><button class="secondary small" id="showSecret" hidden>Show setup key again</button><p class="small">In your app, choose “enter a setup key”.</p></div>
<label for="authCode">Code from your authenticator</label><input id="authCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456">
<button id="verifyAuthenticator">Confirm authenticator</button>
</div>
<p class="small"><a href="#help">Need help?</a> · <a href="#logout">Sign out</a></p>
</section>

<section class="view" id="backup" hidden>
<h1><span class="icon">🧾</span>Save recovery codes</h1>
<p>Keep these codes somewhere safe. Each code works once if you lose your phone.</p>
<button id="makeBackups">Show recovery codes</button>
<div id="backupDisplay" hidden><div id="codesArea"><div class="codes" id="codes"></div><button class="secondary" id="copyCodes">Copy all codes</button><button class="secondary" id="downloadCodes">Download a text file</button></div><button class="secondary small" id="hideCodes">Hide recovery codes</button><button class="secondary small" id="showCodes" hidden>Show recovery codes again</button>
<div class="check"><input id="savedCodes" type="checkbox"><label for="savedCodes">I have saved my recovery codes.</label></div><button id="finish">Finish setup</button><button class="secondary" id="regenerate">Make new codes instead</button></div>
<p class="small"><a href="#help">Need help?</a> · <a href="#logout">Sign out</a></p>
</section>

<section class="view" id="success" hidden>
<h1><span class="icon">✅</span>Extra protection is on</h1>
<p>Your authenticator and recovery codes are ready. You can use a recovery code once if needed.</p>
<div class="card"><label for="recoveryTest">Try one saved recovery code</label><input id="recoveryTest" autocomplete="one-time-code" placeholder="Example: ABC12-DEF34"><button id="testRecovery">Use recovery code</button></div>
<button class="secondary" id="logoutSuccess">Sign out safely</button>
</section>

<section class="view" id="help" hidden><h1><span class="icon">💡</span>Help</h1><p>Take your time. Nothing on this page moves or expires while you read it.</p><p>If a code does not work, ask for a new identity code or check the 6 numbers in your authenticator.</p><button class="secondary" id="back">Go back</button></section>
<section class="logs" aria-label="Logs"><h2>Logs</h2><p class="small">Testing messages appear here and in the browser console.</p><pre id="logPanel"></pre></section>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
let csrf="",current="sign-in",viewBeforeHelp="sign-in",secret="",backupCodes=[];
const $=id=>document.getElementById(id);
const views=["sign-in","identity","setup","backup","success","help"];
function log(message){console.log(message);$("logPanel").textContent+=message+"\\n";}
function note(text,good=true){const e=$("message");e.className="status "+(good?"good":"bad");e.textContent=text;}
function show(name){current=name;views.forEach(id=>$(id).hidden=id!==name);const labels={"sign-in":"Step 1 of 4 · Sign in",identity:"Step 2 of 4 · Check identity",setup:"Step 3 of 4 · Add authenticator",backup:"Step 4 of 4 · Save recovery codes",success:"Setup complete",help:"Help"};$("progress").textContent=labels[name];window.scrollTo(0,0);}
async function api(path,data,method="POST"){const options={method,headers:{"Content-Type":"application/json"}};if(method!=="GET")options.headers["X-CSRF-Token"]=csrf;if(data!==undefined)options.body=JSON.stringify(data);const response=await fetch(path,options);const result=await response.json().catch(()=>({error:"Please try again."}));if(!response.ok)throw new Error(result.error||"Please try again.");if(result.csrf)csrf=result.csrf;return result;}
async function copy(text,message){try{await navigator.clipboard.writeText(text);note(message);}catch{note("Copy was not available. You can select the text instead.",false);}}

/* Valid QR encoder: QR Version 5-L, byte mode, Reed-Solomon ECC, no external library. */
function renderQr(text){
  const bytes=[...new TextEncoder().encode(text)];
  const size=37,dataCapacity=108,eccLength=26;
  if(bytes.length>106)throw new Error("The setup square could not be made. Please use the setup key.");
  const data=[0x40,bytes.length,...bytes];
  while(data.length<dataCapacity&&data.length<Math.ceil((bytes.length*8+12+4)/8))data.push(0);
  while(data.length<dataCapacity)data.push(data.length%2?0x11:0xec);
  const exp=[],logt=[];let x=1;
  for(let i=0;i<255;i++){exp[i]=x;logt[x]=i;x<<=1;if(x&256)x^=0x11d;}
  for(let i=255;i<512;i++)exp[i]=exp[i-255];
  const mul=(a,b)=>a&&b?exp[logt[a]+logt[b]]:0;
  let gen=[1];
  for(let i=0;i<eccLength;i++){const next=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=mul(gen[j],exp[i]);}gen=next;}
  const work=data.concat(Array(eccLength).fill(0));
  for(let i=0;i<data.length;i++){const lead=work[i];if(lead)for(let j=0;j<gen.length;j++)work[i+j]^=mul(gen[j],lead);}
  const stream=data.concat(work.slice(data.length));
  const m=Array.from({length:size},()=>Array(size).fill(null));
  const set=(r,c,v)=>{if(r>=0&&r<size&&c>=0&&c<size)m[r][c]=v;};
  function finder(r,c){for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++){const on=y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4));set(r+y,c+z,on);}}
  finder(0,0);finder(size-7,0);finder(0,size-7);
  for(let i=8;i<size-8;i++){set(6,i,i%2===0);set(i,6,i%2===0);}
  for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)set(30+y,30+z,Math.max(Math.abs(y),Math.abs(z))!==1);
  for(let i=0;i<9;i++){if(m[8][i]===null)m[8][i]=false;if(m[i][8]===null)m[i][8]=false;if(m[8][size-1-i]===null)m[8][size-1-i]=false;if(m[size-1-i][8]===null)m[size-1-i][8]=false;}
  set(size-8,8,true);
  let bit=0,up=true;
  for(let col=size-1;col>0;col-=2){if(col===6)col--;for(let step=0;step<size;step++){const row=up?size-1-step:step;for(let dx=0;dx<2;dx++){const c=col-dx;if(m[row][c]===null){const value=bit<stream.length*8?((stream[Math.floor(bit/8)]>>(7-bit%8))&1)===1:false;bit++;m[row][c]=((row+c)%2===0)?!value:value;}}}up=!up;}
  let format=(1<<3)|0,rem=format<<10;
  while(rem.toString(2).length>=11)rem^=0x537<<(rem.toString(2).length-11);
  format=((format<<10)|rem)^0x5412;
  const fbit=i=>((format>>i)&1)===1;
  for(let i=0;i<15;i++){const v=fbit(i);if(i<6)set(i,8,v);else if(i<8)set(i+1,8,v);else set(size-15+i,8,v);if(i<8)set(8,size-i-1,v);else if(i<9)set(8,15-i,v);else set(8,14-i,v);}
  const canvas=document.createElement("canvas"),scale=8;canvas.width=canvas.height=size*scale;const ctx=canvas.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle="#000";for(let r=0;r<size;r++)for(let c=0;c<size;c++)if(m[r][c])ctx.fillRect(c*scale,r*scale,scale,scale);canvas.setAttribute("aria-label","Authenticator setup QR code");$("qr").replaceChildren(canvas);
}
function error(e){note(e.message||"Please try again.",false);}
async function boot(){try{const r=await api("/api/bootstrap",undefined,"GET");csrf=r.csrf;if(r.signedIn)show(r.stage==="identity"?"identity":r.stage);}catch{note("We could not start securely. Refresh and try again.",false);}}
$("loginForm").addEventListener("submit",async e=>{e.preventDefault();try{const r=await api("/api/signin",{email:$("email").value,password:$("password").value});csrf=r.csrf;note("Signed in. Next, check it is you.");show("identity");}catch(e){error(e);}});
async function sendIdentity(){try{const r=await api("/api/identity/request",{method:$("method").value});$("identityEntry").hidden=false;note("A new code is ready. Enter it when you are ready.");log("TEST identity verification code: "+r.testCode);}catch(e){error(e);}}
$("sendIdentity").onclick=sendIdentity;$("resendIdentity").onclick=sendIdentity;
$("verifyIdentity").onclick=async()=>{try{await api("/api/identity/verify",{code:$("identityCode").value});note("Identity checked. Next, add your authenticator.");show("setup");}catch(e){error(e);}};
$("startAuthenticator").onclick=async()=>{try{const r=await api("/api/authenticator/start",{});secret=r.secret;$("secretText").textContent=secret;renderQr(r.provisioningUri);$("secretArea").hidden=false;$("hideSecret").hidden=false;$("showSecret").hidden=true;$("provision").hidden=false;note("Setup options are shown. Add the key, then enter the short code.");log("TEST authenticator setup key: "+r.secret);log("TEST authenticator confirmation code: "+r.testCode);}catch(e){error(e);}};
$("copySecret").onclick=()=>copy(secret,"Setup key copied. Paste it into your authenticator app.");
$("hideSecret").onclick=()=>{$("secretArea").hidden=true;$("hideSecret").hidden=true;$("showSecret").hidden=false;note("Setup key hidden. You can show it again when needed.");};
$("showSecret").onclick=()=>{$("secretArea").hidden=false;$("hideSecret").hidden=false;$("showSecret").hidden=true;note("Setup key shown again.");};
$("verifyAuthenticator").onclick=async()=>{try{await api("/api/authenticator/verify",{code:$("authCode").value});note("Authenticator confirmed. Next, save your recovery codes.");show("backup");}catch(e){error(e);}};
function paintCodes(){const area=$("codes");area.replaceChildren(...backupCodes.map(c=>{const d=document.createElement("div");d.textContent=c;return d;}));}
async function makeBackups(){try{const r=await api("/api/backup/generate",{});backupCodes=r.codes;paintCodes();$("codesArea").hidden=false;$("hideCodes").hidden=false;$("showCodes").hidden=true;$("backupDisplay").hidden=false;note("Recovery codes are ready. Copy or download them before continuing.");log("TEST recovery codes: "+backupCodes.join(", "));}catch(e){error(e);}}
$("makeBackups").onclick=makeBackups;$("regenerate").onclick=makeBackups;
$("copyCodes").onclick=()=>copy(backupCodes.join("\\n"),"Recovery codes copied.");
$("downloadCodes").onclick=()=>{const a=document.createElement("a");const url=URL.createObjectURL(new Blob([backupCodes.join("\\n")],{type:"text/plain"}));a.href=url;a.download="harbour-bank-recovery-codes.txt";a.click();setTimeout(()=>URL.revokeObjectURL(url),0);note("Your recovery-code file was downloaded.");};
$("hideCodes").onclick=()=>{$("codesArea").hidden=true;$("hideCodes").hidden=true;$("showCodes").hidden=false;note("Recovery codes hidden. You can show them again when needed.");};
$("showCodes").onclick=()=>{$("codesArea").hidden=false;$("hideCodes").hidden=false;$("showCodes").hidden=true;note("Recovery codes shown again.");};
$("finish").onclick=async()=>{if(!$("savedCodes").checked){note("Please tick the box after you have saved the codes.",false);return;}try{await api("/api/backup/confirm",{});backupCodes=[];secret="";note("Setup complete. Your extra protection is on.");show("success");}catch(e){error(e);}};
$("testRecovery").onclick=async()=>{try{await api("/api/recovery/verify",{code:$("recoveryTest").value.toUpperCase()});note("That recovery code worked and cannot be used again.");$("recoveryTest").value="";}catch(e){error(e);}};
async function logout(){try{await api("/api/logout",{});csrf="";note("You are signed out.");show("sign-in");}catch(e){error(e);}}
document.querySelectorAll('a[href="#logout"]').forEach(a=>a.onclick=e=>{e.preventDefault();logout();});
$("logoutSuccess").onclick=logout;
document.querySelectorAll('a[href="#help"]').forEach(a=>a.onclick=e=>{e.preventDefault();viewBeforeHelp=current;show("help");});
$("back").onclick=()=>show(viewBeforeHelp);
boot();
})();
</script>
</body></html>`;
}

const server = Bun.serve({
  port: 3000,
  hostname: "0.0.0.0",
  tls: { cert: certFile, key: keyFile },
  async fetch(request) {
    const url = new URL(request.url);
    const nonce = opaque(16);

    try {
      if (url.protocol !== "https:") {
        return new Response("Secure connection required.", { status: 426, headers: headersFor(request, nonce) });
      }

      if (request.method === "OPTIONS") {
        if (!allowedOrigin(request)) return new Response(null, { status: 403, headers: headersFor(request, nonce) });
        return new Response(null, {
          status: 204,
          headers: {
            ...headersFor(request, nonce),
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
          },
        });
      }

      if (url.pathname === "/" && request.method === "GET") {
        return new Response(page(nonce), {
          headers: { ...headersFor(request, nonce), "Content-Type": "text/html; charset=utf-8" },
        });
      }

      if (url.pathname === "/api/bootstrap" && request.method === "GET") {
        let session = getSession(request);
        if (!session) {
          session = freshSession();
          return json(request, { signedIn: false, csrf: session.csrf }, 200, { "Set-Cookie": sessionCookie(session.id) });
        }
        return json(request, session.userId ? authSummary(session) : { signedIn: false, csrf: session.csrf });
      }

      if (url.pathname === "/api/signin" && request.method === "POST") {
        const old = getSession(request);
        const input = await body(request);
        if (!old || !input || !allowedOrigin(request) || request.headers.get("x-csrf-token") !== old.csrf) {
          return json(request, { error: "Your security check expired. Refresh and try again." }, 403);
        }

        const genericError = "We could not sign you in with those details. Check them and try again.";
        const email = typeof input.email === "string" ? input.email.toLowerCase() : "";
        const account = email === "marcus@example.test" ? accounts.get("marcus-001") : undefined;
        const sessionFailures = old.signInFailures ||= { attempts: 0 };
        const accountFailures = account?.signInFailures ||= { attempts: 0 };

        if (isLocked(sessionFailures) || isLocked(accountFailures)) {
          return json(request, { error: "Please wait 15 minutes before trying to sign in again." }, 429);
        }

        const valid = validEmail(input.email) &&
          typeof input.password === "string" &&
          input.password.length <= 128 &&
          email === "marcus@example.test" &&
          input.password === "CorrectHorse1!";

        if (!valid) {
          failedAttempt(sessionFailures);
          if (accountFailures) failedAttempt(accountFailures);
          return json(request, { error: genericError }, 401);
        }

        clearFailures(sessionFailures);
        clearFailures(accountFailures);
        sessions.delete(old.id);
        const session = freshSession("marcus-001");
        return json(request, authSummary(session), 200, { "Set-Cookie": sessionCookie(session.id) });
      }

      if (url.pathname === "/api/state" && request.method === "GET") {
        const auth = requireSession(request);
        if (auth.error) return auth.error;
        return json(request, authSummary(auth.session!));
      }

      if (url.pathname === "/api/identity/request" && request.method === "POST") {
        const auth = requireSession(request, true);
        if (auth.error) return auth.error;
        const input = await body(request);
        if (!input || !["email", "phone"].includes(String(input.method))) {
          return json(request, { error: "Choose email or phone, then try again." }, 400);
        }
        if (auth.session!.stage !== "identity") return json(request, { error: "Please follow the setup steps in order." }, 409);

        const now = Date.now();
        const identity = auth.session!.identity ||= { attempts: 0, used: false, requestTimes: [] };

        /* Preserve failed attempt/lock state across re-requests. */
        if (identity.lockedUntil && now < identity.lockedUntil) {
          return json(request, { error: retryMessage() }, 429);
        }
        identity.requestTimes = identity.requestTimes.filter(time => now - time < IDENTITY_REQUEST_WINDOW_MS);
        if (identity.requestTimes.length >= MAX_IDENTITY_REQUESTS) {
          return json(request, { error: "You have asked for several codes. Please wait 15 minutes before asking again." }, 429);
        }

        const code = String(randomBytes(4).readUInt32BE(0) % 1_000_000).padStart(6, "0");
        identity.codeHash = hash(code);
        identity.expiresAt = now + CODE_LIFETIME_MS;
        identity.used = false;
        identity.requestTimes.push(now);
        return json(request, { csrf: auth.session!.csrf, testCode: code, message: "Code sent." });
      }

      if (url.pathname === "/api/identity/verify" && request.method === "POST") {
        const auth = requireSession(request, true);
        if (auth.error) return auth.error;
        const input = await body(request);
        const check = auth.session!.identity;
        if (!input || !validOtp(input.code)) return json(request, { error: "Enter the 6-number code. Example: 123456." }, 400);
        if (!check || !check.codeHash || check.used || !check.expiresAt || Date.now() > check.expiresAt) {
          return json(request, { error: "That code is no longer available. Send a new code and try again." }, 400);
        }
        if (check.lockedUntil && Date.now() < check.lockedUntil) return json(request, { error: retryMessage() }, 429);
        if (hash(String(input.code)) !== check.codeHash) {
          failedAttempt(check);
          return json(request, { error: check.lockedUntil ? retryMessage() : "That code did not match. Check the 6 numbers or send a new code." }, check.lockedUntil ? 429 : 400);
        }
        check.used = true;
        clearFailures(check);
        auth.session!.stage = "setup";
        return json(request, { csrf: auth.session!.csrf });
      }

      if (url.pathname === "/api/authenticator/start" && request.method === "POST") {
        const auth = requireSession(request, true);
        if (auth.error) return auth.error;
        if (auth.session!.stage !== "setup") return json(request, { error: "Please complete the earlier step first." }, 409);
        if (isLocked(auth.session!.authenticatorFailures)) return json(request, { error: retryMessage() }, 429);

        const secret = base32(randomBytes(20));
        const code = otpFor(secret);
        auth.session!.pendingSecret = protect(secret);
        auth.session!.pendingOtpHash = hash(code);
        auth.session!.pendingOtpExpires = Date.now() + CODE_LIFETIME_MS;
        const provisioningUri = `otpauth://totp/Harbour%20Bank:marcus?secret=${secret}&issuer=Harbour%20Bank`;
        return json(request, { csrf: auth.session!.csrf, secret, provisioningUri, testCode: code });
      }

      if (url.pathname === "/api/authenticator/verify" && request.method === "POST") {
        const auth = requireSession(request, true);
        if (auth.error) return auth.error;
        const input = await body(request);
        const failures = auth.session!.authenticatorFailures ||= { attempts: 0 };

        if (isLocked(failures)) return json(request, { error: retryMessage() }, 429);
        if (!input || !validOtp(input.code)) return json(request, { error: "Enter the 6-number code from your authenticator." }, 400);
        if (!auth.session!.pendingSecret || !auth.session!.pendingOtpHash || !auth.session!.pendingOtpExpires || Date.now() > auth.session!.pendingOtpExpires) {
          return json(request, { error: "Please show setup options again and enter the new code." }, 400);
        }

        const expectedNow = otpFor(reveal(auth.session!.pendingSecret));
        if (hash(String(input.code)) !== auth.session!.pendingOtpHash && String(input.code) !== expectedNow) {
          failedAttempt(failures);
          return json(request, { error: failures.lockedUntil ? retryMessage() : "That code did not match. Check your authenticator and try again." }, failures.lockedUntil ? 429 : 400);
        }

        clearFailures(failures);
        auth.account!.authenticatorSecret = auth.session!.pendingSecret;
        auth.session!.pendingSecret = undefined;
        auth.session!.pendingOtpHash = undefined;
        auth.session!.pendingOtpExpires = undefined;
        auth.session!.stage = "backup";
        return json(request, { csrf: auth.session!.csrf });
      }

      if (url.pathname === "/api/backup/generate" && request.method === "POST") {
        const auth = requireSession(request, true);
        if (auth.error) return auth.error;
        if (!["backup", "success"].includes(auth.session!.stage)) return json(request, { error: "Please confirm your authenticator first." }, 409);
        const codes = recoveryCodes();
        auth.account!.backupCodes = new Map(codes.map(code => [hash(code), false]));
        auth.session!.stage = "backup";
        return json(request, { csrf: auth.session!.csrf, codes });
      }

      if (url.pathname === "/api/backup/confirm" && request.method === "POST") {
        const auth = requireSession(request, true);
        if (auth.error) return auth.error;
        if (auth.session!.stage !== "backup" || auth.account!.backupCodes.size === 0) {
          return json(request, { error: "Show and save recovery codes before continuing." }, 409);
        }
        auth.session!.stage = "success";
        return json(request, { csrf: auth.session!.csrf });
      }

      if (url.pathname === "/api/recovery/verify" && request.method === "POST") {
        const auth = requireSession(request, true);
        if (auth.error) return auth.error;
        const input = await body(request);
        const failures = auth.account!.recoveryFailures ||= { attempts: 0 };

        /* Account-bound recovery-code failure control survives session changes. */
        if (isLocked(failures)) return json(request, { error: retryMessage() }, 429);
        if (!input || !validRecovery(input.code)) return json(request, { error: "Enter a recovery code in this format: ABC12-DEF34." }, 400);

        const key = hash(String(input.code));
        const used = auth.account!.backupCodes.get(key);
        if (used !== false) {
          failedAttempt(failures);
          return json(request, { error: failures.lockedUntil ? retryMessage() : "That recovery code cannot be used. Try a different saved code." }, failures.lockedUntil ? 429 : 400);
        }

        auth.account!.backupCodes.set(key, true);
        clearFailures(failures);
        return json(request, { csrf: auth.session!.csrf });
      }

      if (url.pathname === "/api/logout" && request.method === "POST") {
        const session = getSession(request);
        if (!session || !allowedOrigin(request) || request.headers.get("x-csrf-token") !== session.csrf) {
          return json(request, { error: "Your security check expired. Refresh and try again." }, 403);
        }
        sessions.delete(session.id);
        return json(request, { ok: true }, 200, { "Set-Cookie": clearCookie() });
      }

      return new Response("Not found.", { status: 404, headers: headersFor(request, nonce) });
    } catch {
      return json(request, { error: "Something went wrong. Please refresh and try again." }, 500);
    }
  },
});

console.log(`MFA server ready on https://localhost:${server.port}`);
