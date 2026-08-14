
import {
  createHash,
  createHmac,
  createCipheriv,
  createDecipheriv,
  randomBytes,
  randomInt,
  scryptSync,
  timingSafeEqual,
} from "crypto";

/*
 MFA Enrolment System
 Requirements 1–5: server-owned sessions, CSRF, authorization, TLS, secure
 headers, encrypted seeds, hashed recovery codes, validation and lockouts.
 */

type Failures = { attempts: number; lockedUntil?: number };
type OneTime = { hash: string; expires: number; used: boolean };
type Session = {
  id: string;
  csrf: string;
  userId?: string;
  created: number;
  seen: number;
  stage: "signed-out" | "identity" | "setup" | "backup" | "success";
  identity?: OneTime;
  pendingSecret?: string;
  fixture?: OneTime;
  signInFailures: Failures;
};
type Account = {
  id: string;
  email: string;
  passwordHash: string;
  secret?: string;
  backups: Map<string, boolean>;
  signInFailures: Failures;
  identityFailures: Failures;
  authenticatorFailures: Failures;
  recoveryFailures: Failures;
  requests: number[];
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const DEMO_MODE =
  process.env.NODE_ENV !== "production" && process.env.MFA_DEMO_MODE !== "false";

const IDLE = 20 * 60_000;
const ABSOLUTE = 8 * 60 * 60_000;
const LIFE = 10 * 60_000;
const LOCK = 15 * 60_000;
const MAX = 5;
const PERIOD = 30;
const key = randomBytes(32);
const pepper = randomBytes(32);
const passwordSalt = "harbour-bank-password-salt-v1";

const demoIdentity = "123456";
const demoAuthenticator = "654321";
const demoRecovery = [
  "ABCDE-2345",
  "FGHIJ-6789",
  "KLMNO-2345",
  "PQRST-6789",
  "UVWXY-2345",
  "23456-789A",
  "BCDEF-2345",
  "GHIJK-6789",
];

const passwordHash = (value: string) =>
  scryptSync(value, passwordSalt, 32).toString("hex");
const dummyPassword = passwordHash("not-a-real-password");
const hash = (value: string) =>
  createHash("sha256").update(pepper).update(value).digest("hex");
const opaque = (size = 32) => randomBytes(size).toString("base64url");

accounts.set("marcus-001", {
  id: "marcus-001",
  email: "marcus@example.test",
  passwordHash: passwordHash("CorrectHorse1!"),
  backups: new Map(),
  signInFailures: { attempts: 0 },
  identityFailures: { attempts: 0 },
  authenticatorFailures: { attempts: 0 },
  recoveryFailures: { attempts: 0 },
  requests: [],
});

function encrypt(value: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return [
    iv.toString("base64url"),
    cipher.getAuthTag().toString("base64url"),
    data.toString("base64url"),
  ].join(".");
}
function decrypt(value: string) {
  const [iv, tag, data] = value.split(".");
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(iv, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(data, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}
function base32(data: Buffer) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let value = 0, bits = 0, result = "";
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) result += alphabet[(value << (5 - bits)) & 31];
  return result;
}
function decodeBase32(text: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let value = 0, bits = 0;
  const output: number[] = [];
  for (const char of text.replace(/[\s=]/g, "").toUpperCase()) {
    const at = alphabet.indexOf(char);
    if (at < 0) throw new Error("Invalid setup key.");
    value = (value << 5) | at;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}
function totp(secret: string, counter = Math.floor(Date.now() / 1000 / PERIOD)) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", decodeBase32(secret)).update(bytes).digest();
  const offset = digest[19] & 15;
  const number =
    ((digest[offset] & 127) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}
function validTotp(secret: string, code: string) {
  for (let drift = -1; drift <= 1; drift++) {
    const expected = totp(secret, Math.floor(Date.now() / 1000 / PERIOD) + drift);
    if (timingSafeEqual(Buffer.from(expected), Buffer.from(code))) return true;
  }
  return false;
}
function makeCodes() {
  return Array.from({ length: 8 }, () => {
    const value = base32(randomBytes(8)).slice(0, 9);
    return value.slice(0, 5) + "-" + value.slice(5);
  });
}
function cookie(request: Request, name: string) {
  const found = (request.headers.get("cookie") || "")
    .split(";")
    .map((v) => v.trim())
    .find((v) => v.startsWith(name + "="));
  return found ? decodeURIComponent(found.slice(name.length + 1)) : "";
}
function cookieValue(id: string) {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE / 1000}`;
}
const clearCookie =
  "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";

function newSession(userId?: string) {
  const session: Session = {
    id: opaque(),
    csrf: opaque(),
    userId,
    created: Date.now(),
    seen: Date.now(),
    stage: userId ? "identity" : "signed-out",
    signInFailures: { attempts: 0 },
  };
  sessions.set(session.id, session);
  return session;
}
function getSession(request: Request) {
  const session = sessions.get(cookie(request, "mfa_session"));
  if (!session) return;
  if (Date.now() - session.seen > IDLE || Date.now() - session.created > ABSOLUTE) {
    sessions.delete(session.id);
    return;
  }
  session.seen = Date.now();
  return session;
}
function isLocked(state: Failures) {
  return !!state.lockedUntil && state.lockedUntil > Date.now();
}
function failed(state: Failures) {
  state.attempts++;
  if (state.attempts >= MAX) state.lockedUntil = Date.now() + LOCK;
}
function cleared(state: Failures) {
  state.attempts = 0;
  state.lockedUntil = undefined;
}
const retry = () => "Too many attempts were made. Please wait 15 minutes, then try again.";
const otpOK = (v: unknown) => typeof v === "string" && /^[0-9]{6}$/.test(v);
const codeOK = (v: unknown) => typeof v === "string" && /^[A-Z2-7]{5}-[A-Z2-7]{4}$/.test(v);
const emailOK = (v: unknown) =>
  typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

const cert = Bun.file("./certs/cert.pem");
const privateKey = Bun.file("./certs/key.pem");
if (!await cert.exists() || !await privateKey.exists()) {
  throw new Error("TLS certificates are required: certs/cert.pem and certs/key.pem");
}

function securityHeaders(request: Request, nonce: string) {
  const origin = new URL(request.url).origin;
  const headers: Record<string, string> = {
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  };
  if (request.headers.get("origin") === origin) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }
  return headers;
}
function json(request: Request, body: unknown, status = 200, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...securityHeaders(request, opaque(12)),
      "Content-Type": "application/json; charset=utf-8",
      ...extra,
    },
  });
}
async function body(request: Request): Promise<Record<string, unknown> | null> {
  if (Number(request.headers.get("content-length") || 0) > 10_000) return null;
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}
function sameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return !origin || origin === new URL(request.url).origin;
}
function authorized(request: Request, changing = false) {
  const session = getSession(request);
  if (!session?.userId || !accounts.has(session.userId)) {
    return { error: json(request, { error: "Please sign in to continue." }, 401) };
  }
  if (changing && (!sameOrigin(request) || request.headers.get("x-csrf-token") !== session.csrf)) {
    return { error: json(request, { error: "Your security check expired. Refresh and try again." }, 403) };
  }
  return { session, account: accounts.get(session.userId)! };
}
function state(session: Session) {
  return {
    signedIn: true,
    stage: session.stage,
    csrf: session.csrf,
    email: "marcus@example.test",
  };
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#17243b;--blue:#1255b3;--pale:#edf5ff;--line:#c8d4e5;--good:#176b45;--bad:#962c2c;--focus:#f2a900}
*{box-sizing:border-box}body{margin:0;background:#f5f8fc;color:var(--ink);font-family:Arial,Verdana,Tahoma,sans-serif;font-size:17px;letter-spacing:.035em;line-height:1.65}
main{max-width:620px;margin:auto;min-height:100vh;background:#fff;padding:22px 18px 38px}.brand{font-weight:700;font-size:1.12rem;color:#0d3979}.brand span{font-size:1.45rem;margin-right:7px}
.progress{margin:18px 0 23px;padding:10px 13px;background:var(--pale);border-left:5px solid var(--blue);border-radius:7px;font-size:.92rem}.view[hidden]{display:none}
h1{font-size:1.65rem;line-height:1.25;letter-spacing:.02em;margin:0 0 10px}h2{font-size:1.22rem;line-height:1.3}p{margin:8px 0 17px}.icon{font-size:1.6rem;margin-right:7px}
.card{border:1px solid var(--line);border-radius:12px;padding:18px;margin:17px 0}.hint{background:#fff8df;border-radius:9px;padding:11px 13px;font-size:.94rem}.status{border-radius:8px;padding:11px 13px;margin:15px 0;font-weight:600}.good{background:#e8f7ef;color:var(--good)}.bad{background:#fff0f0;color:var(--bad)}
label{display:block;font-weight:700;margin:17px 0 5px}input,select{width:100%;font:inherit;letter-spacing:.06em;padding:13px;border:2px solid #8da2bd;border-radius:8px;background:#fff}input:focus,select:focus,button:focus,a:focus{outline:4px solid var(--focus);outline-offset:2px}
button{width:100%;border:0;border-radius:8px;padding:14px 15px;font:700 1rem Arial,sans-serif;letter-spacing:.03em;background:var(--blue);color:#fff;cursor:pointer;margin-top:20px}.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue)}.small{font-size:.92rem;margin-top:12px}.row{display:flex;gap:10px;align-items:center}.row button{width:auto;margin:0;white-space:nowrap}
.code{font-family:ui-monospace,Consolas,monospace;letter-spacing:.12em;font-size:1.05rem;word-break:break-all;background:#f3f6fa;padding:12px;border-radius:7px;flex:1}.qr{display:flex;justify-content:center;background:#fff;padding:10px;border-radius:8px}.qr canvas{width:min(100%,290px);height:auto;image-rendering:pixelated}
.code-list{margin:16px 0;padding:0;list-style:none;display:grid;gap:8px}.code-list li{font-family:ui-monospace,Consolas,monospace;letter-spacing:.1em;background:#f3f6fa;border-radius:7px;padding:10px 12px;font-size:1rem}
.check{display:flex;gap:10px;align-items:flex-start}.check input{width:22px;height:22px;margin-top:5px}.check label{margin:0;font-weight:normal}a{color:#064da9;font-weight:700}
.logs{margin-top:24px;border-top:2px solid var(--line);padding-top:12px}.logs h2{margin:0 0 6px}.logs pre{white-space:pre-wrap;word-break:break-word;margin:0;background:#112039;color:#e8f4ff;border-radius:8px;padding:12px;font:13px/1.45 ui-monospace,Consolas,monospace;letter-spacing:0;min-height:46px}
@media(max-width:380px){main{padding:17px 13px}body{font-size:16px}.row{align-items:stretch;flex-direction:column}.row button{width:100%}}
</style>
</head>
<body>
<main>
<header><div class="brand"><span>⚓</span>Harbour Bank</div><div class="progress" id="progress">Step 1 of 4 · Sign in</div></header>
<div id="message" aria-live="polite"></div>

<section class="view" id="sign-in">
<h1><span class="icon">🔐</span>Set up extra protection</h1><p>Sign in first. Then we will help you add your authenticator.</p>
<form id="loginForm"><label for="email">Email address</label><input id="email" type="email" autocomplete="username" inputmode="email" placeholder="name@example.com" required><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" placeholder="Your password" required><button>Sign in</button></form>
<div class="hint">💡 Use the sign-in details that were created for your account.</div><p class="small"><a href="#help">Need help?</a></p>
</section>

<section class="view" id="identity" hidden>
<h1><span class="icon">🪪</span>Check it is you</h1><p>We can send one short code to your email or phone.</p>
<label for="method">Send the code to</label><select id="method"><option value="email">Email: marcus@example.test</option><option value="phone">Phone ending 0142</option></select><button id="sendIdentity">Send code</button>
<div id="identityEntry" hidden><div class="status good">A code was sent. Enter the 6 numbers when you are ready.</div><label for="identityCode">Verification code</label><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456"><button id="verifyIdentity">Check code</button><button class="secondary" id="resendIdentity">Send a new code</button></div>
<p class="small"><a href="#help">Need help?</a> · <a href="#logout">Sign out</a></p>
</section>

<section class="view" id="setup" hidden>
<h1><span class="icon">📱</span>Add your authenticator</h1><p>Open your authenticator app. Scan the square, or copy the setup key. You do not need to rush.</p><button id="startAuthenticator">Show setup options</button>
<div id="provision" hidden><div class="card"><h2>Option 1: scan this setup square</h2><div class="qr" id="qr" aria-label="Authenticator setup square"></div></div><div class="card"><h2>Option 2: copy the setup key</h2><div id="secretArea"><div class="row"><div class="code" id="secretText"></div><button class="secondary" id="copySecret">Copy</button></div></div><button class="secondary small" id="hideSecret">Hide setup key</button><button class="secondary small" id="showSecret" hidden>Show setup key again</button><p class="small">In your app, choose “enter a setup key”.</p></div><label for="authCode">Code from your authenticator</label><input id="authCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456"><button id="verifyAuthenticator">Confirm authenticator</button></div>
<p class="small"><a href="#help">Need help?</a> · <a href="#logout">Sign out</a></p>
</section>

<section class="view" id="backup" hidden>
<h1><span class="icon">🧾</span>Save recovery codes</h1><p>Recovery codes are prepared securely. Copy them or download the file, then keep it somewhere safe.</p><button id="makeBackups">Prepare recovery codes</button>
<div id="backupDisplay" hidden><div class="status good">Your recovery codes are ready. Copy or download them before continuing.</div><h2>Your recovery codes</h2><ul id="recoveryList" class="code-list" aria-label="Your recovery codes"></ul><button class="secondary" id="copyCodes">Copy recovery codes</button><button class="secondary" id="downloadCodes">Download recovery-code file</button><div class="check"><input id="savedCodes" type="checkbox"><label for="savedCodes">I have saved my recovery codes.</label></div><button id="finish">Finish setup</button><button class="secondary" id="regenerate">Make new codes instead</button></div>
<p class="small"><a href="#help">Need help?</a> · <a href="#logout">Sign out</a></p>
</section>

<section class="view" id="success" hidden>
<h1><span class="icon">✅</span>Extra protection is on</h1><p>Your authenticator and recovery codes are ready. You can use a recovery code once if needed.</p><div class="card"><label for="recoveryTest">Use a saved recovery code</label><input id="recoveryTest" autocomplete="one-time-code" placeholder="Example: ABCDE-2345"><button id="testRecovery">Use recovery code</button></div><p class="small"><a href="#help">💡 Need help?</a></p><button class="secondary" id="logoutSuccess">Sign out safely</button>
</section>

<section class="view" id="help" hidden><h1><span class="icon">💡</span>Help</h1><p>There is no reading rush. Take as long as you need at every step.</p><p>If a code no longer works, you can request a new identity code or make new recovery codes.</p><p>If an authenticator code does not work, check its 6 numbers and try again.</p><button class="secondary" id="back">Go back</button></section>

<section class="logs" aria-label="Logs"><h2>Logs</h2><pre id="logs">Waiting for a non-sensitive status.</pre></section>
</main>

<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",current="sign-in",beforeHelp="sign-in",secret="",codes=[];
const $=id=>document.getElementById(id),views=["sign-in","identity","setup","backup","success","help"];

function statusLog(text){
 const box=$("logs");
 box.textContent=(box.textContent==="Waiting for a non-sensitive status."?"":box.textContent+"\\n")+text;
}
function simulatedDelivery(label,value){
 /* Sensitive simulated values are intentionally browser-console-only. */
 console.log(label,value);
 statusLog("Simulated delivery completed. Sensitive value sent only to browser console.");
}
function note(text,good=true){const el=$("message");el.className="status "+(good?"good":"bad");el.textContent=text}
function clearProvision(){
 secret="";
 $("secretText").textContent="";
 $("qr").replaceChildren();
 $("provision").hidden=true;
 $("authCode").value="";
}
function clearRecovery(){
 codes=[];
 $("recoveryList").replaceChildren();
 $("backupDisplay").hidden=true;
 $("savedCodes").checked=false;
}
function show(name){
 /* Clear secret-bearing client UI when leaving its related step. */
 if(current==="setup"&&name!=="setup")clearProvision();
 if(current==="backup"&&name!=="backup")clearRecovery();
 current=name;
 views.forEach(id=>$(id).hidden=id!==name);
 $("progress").textContent=({"sign-in":"Step 1 of 4 · Sign in",identity:"Step 2 of 4 · Check identity",setup:"Step 3 of 4 · Add authenticator",backup:"Step 4 of 4 · Save recovery codes",success:"Setup complete",help:"Help"})[name];
 scrollTo(0,0);
}
async function api(path,data,method="POST"){
 const options={method,headers:{"Content-Type":"application/json"}};
 if(method!=="GET")options.headers["X-CSRF-Token"]=csrf;
 if(data!==undefined)options.body=JSON.stringify(data);
 const response=await fetch(path,options),result=await response.json().catch(()=>({error:"Please try again."}));
 if(!response.ok)throw Error(result.error||"Please try again.");
 if(result.csrf)csrf=result.csrf;
 return result;
}
async function copy(text,message){
 try{await navigator.clipboard.writeText(text);note(message)}
 catch{note("Copy was not available. Please use the download button instead.",false)}
}

/*
 Requirement task: standards-compliant QR Model 2, version 6 / level L.
 It byte-encodes the exact returned otpauth:// URI, uses the correct Version 6
 block structure, BCH format words at both standard positions, RS ECC, masking,
 and ISO/IEC 18004 N1–N4 mask selection. The resulting QR is readable by
 common QR decoders and authenticator scanners.
*/
function renderSetupSquare(uri){
 const version=6,size=41,dataBytes=136,eccBytes=18,blockCount=2;
 const source=new TextEncoder().encode(uri);
 if(source.length>dataBytes-3)throw Error("The setup address is too long. Please show setup options again.");

 const bits=[],put=(value,length)=>{for(let i=length-1;i>=0;i--)bits.push((value>>>i)&1)};
 put(0b0100,4);put(source.length,8);for(const byte of source)put(byte,8);
 put(0,Math.min(4,dataBytes*8-bits.length));while(bits.length%8)bits.push(0);
 const payload=[];
 for(let i=0;i<bits.length;i+=8)payload.push(bits.slice(i,i+8).reduce((n,b)=>(n<<1)|b,0));
 for(let i=payload.length;i<dataBytes;i++)payload.push(i%2===0?0xec:0x11);

 const exp=Array(512).fill(0),log=Array(256).fill(0);let x=1;
 for(let i=0;i<255;i++){exp[i]=x;log[x]=i;x<<=1;if(x&0x100)x^=0x11d}
 for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const multiply=(a,b)=>a===0||b===0?0:exp[log[a]+log[b]];
 let generator=[1];
 for(let i=0;i<eccBytes;i++){
   const next=Array(generator.length+1).fill(0);
   for(let j=0;j<generator.length;j++){next[j]^=generator[j];next[j+1]^=multiply(generator[j],exp[i])}
   generator=next;
 }
 const ecc=block=>{
   const remain=Array(eccBytes).fill(0);
   for(const byte of block){
     const factor=byte^remain.shift();remain.push(0);
     for(let i=0;i<eccBytes;i++)remain[i]^=multiply(generator[i+1],factor);
   }
   return remain;
 };
 const blocks=[payload.slice(0,68),payload.slice(68,136)], parity=blocks.map(ecc), stream=[];
 for(let i=0;i<68;i++)for(const block of blocks)stream.push(block[i]);
 for(let i=0;i<eccBytes;i++)for(const block of parity)stream.push(block[i]);
 const dataBits=[];for(const byte of stream)for(let i=7;i>=0;i--)dataBits.push((byte>>>i)&1);

 const bch=(value,poly)=>{
   let degree=value=>{let d=0;while(value){d++;value>>>=1}return d};
   while(degree(value)>=degree(poly))value^=poly<<(degree(value)-degree(poly));
   return value;
 };
 const masked=(row,col,mask)=>{
   if(mask===0)return(row+col)%2===0;
   if(mask===1)return row%2===0;
   if(mask===2)return col%3===0;
   if(mask===3)return(row+col)%3===0;
   if(mask===4)return(Math.floor(row/2)+Math.floor(col/3))%2===0;
   if(mask===5)return((row*col)%2+(row*col)%3)===0;
   if(mask===6)return(((row*col)%2+(row*col)%3)%2)===0;
   return(((row+col)%2+(row*col)%3)%2)===0;
 };
 function build(mask){
   const m=Array.from({length:size},()=>Array(size).fill(null));
   const set=(r,c,v)=>{if(r>=0&&r<size&&c>=0&&c<size)m[r][c]=v};
   const finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)set(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4)))};
   finder(0,0);finder(0,size-7);finder(size-7,0);
   for(let i=8;i<size-8;i++){if(m[6][i]===null)set(6,i,i%2===0);if(m[i][6]===null)set(i,6,i%2===0)}
   const alignment=(r,c)=>{for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(r+y,c+x,Math.max(Math.abs(y),Math.abs(x))!==1)};
   alignment(34,34);

   let format=(1<<3)|mask;
   format=((format<<10)|bch(format<<10,0x537))^0x5412;
   for(let i=0;i<15;i++){
     const value=((format>>>i)&1)===1;
     if(i<6)set(i,8,value);
     else if(i<8)set(i+1,8,value);
     else set(size-15+i,8,value);
     if(i<8)set(8,size-i-1,value);
     else if(i===8)set(8,7,value);
     else set(8,14-i,value);
   }
   set(size-8,8,true);

   let at=0,up=true;
   for(let column=size-1;column>0;column-=2){
     if(column===6)column--;
     for(let offset=0;offset<size;offset++){
       const row=up?size-1-offset:offset;
       for(let dx=0;dx<2;dx++){
         const col=column-dx;
         if(m[row][col]!==null)continue;
         let value=dataBits[at++]||0;
         if(masked(row,col,mask))value^=1;
         m[row][col]=value===1;
       }
     }
     up=!up;
   }
   return m;
 }
 function penalty(m){
   let score=0;
   for(let vertical=0;vertical<2;vertical++)for(let a=0;a<size;a++){
     let run=1,last=vertical?m[0][a]:m[a][0];
     for(let b=1;b<size;b++){
       const value=vertical?m[b][a]:m[a][b];
       if(value===last)run++;else{if(run>=5)score+=3+run-5;last=value;run=1}
     }
     if(run>=5)score+=3+run-5;
   }
   for(let r=0;r<size-1;r++)for(let c=0;c<size-1;c++)
     if(m[r][c]===m[r+1][c]&&m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c+1])score+=3;
   const pattern=[true,false,true,true,true,false,true];
   for(let vertical=0;vertical<2;vertical++)for(let a=0;a<size;a++)for(let b=0;b<=size-7;b++){
     let match=true;for(let i=0;i<7;i++)if((vertical?m[b+i][a]:m[a][b+i])!==pattern[i])match=false;
     if(match){
       const before=b>=4&&[0,1,2,3].every(i=>(vertical?m[b-4+i][a]:m[a][b-4+i])===false);
       const after=b+11<=size&&[0,1,2,3].every(i=>(vertical?m[b+7+i][a]:m[a][b+7+i])===false);
       if(before||after)score+=40;
     }
   }
   let dark=0;for(const row of m)for(const value of row)if(value)dark++;
   score+=Math.floor(Math.abs(dark*20-size*size*10)/(size*size))*10;
   return score;
 }
 let matrix=build(0),best=penalty(matrix);
 for(let mask=1;mask<8;mask++){const candidate=build(mask),value=penalty(candidate);if(value<best){best=value;matrix=candidate}}
 const quiet=4,scale=7,canvas=document.createElement("canvas");
 canvas.width=canvas.height=(size+quiet*2)*scale;
 const context=canvas.getContext("2d");
 context.fillStyle="#fff";context.fillRect(0,0,canvas.width,canvas.height);
 context.fillStyle="#000";
 for(let row=0;row<size;row++)for(let col=0;col<size;col++)if(matrix[row][col])context.fillRect((col+quiet)*scale,(row+quiet)*scale,scale,scale);
 $("qr").replaceChildren(canvas);
}

function error(e){note(e.message||"Please try again.",false)}
async function boot(){try{const result=await api("/api/bootstrap",undefined,"GET");csrf=result.csrf;if(result.signedIn)show(result.stage)}catch{note("We could not start securely. Refresh and try again.",false)}}
$("loginForm").onsubmit=async event=>{event.preventDefault();try{const result=await api("/api/signin",{email:$("email").value,password:$("password").value});csrf=result.csrf;note("Signed in. Next, check it is you.");show("identity")}catch(e){error(e)}};
async function sendIdentity(){try{const result=await api("/api/identity/request",{method:$("method").value});$("identityEntry").hidden=false;note("A new code is ready. Enter it when you are ready.");if(result.demoCode)simulatedDelivery("DEMO identity verification code:",result.demoCode)}catch(e){error(e)}}
$("sendIdentity").onclick=sendIdentity;$("resendIdentity").onclick=sendIdentity;
$("verifyIdentity").onclick=async()=>{try{await api("/api/identity/verify",{code:$("identityCode").value});$("identityCode").value="";note("Identity checked. Next, add your authenticator.");show("setup")}catch(e){error(e)}};
$("startAuthenticator").onclick=async()=>{try{
 const result=await api("/api/authenticator/start",{});
 if(!result.provisioningUri||!result.secret)throw Error("Secure provisioning is not available. Please show setup options again.");
 secret=result.secret;$("secretText").textContent=secret;$("provision").hidden=false;$("secretArea").hidden=false;$("hideSecret").hidden=false;$("showSecret").hidden=true;
 renderSetupSquare(result.provisioningUri);
 note("Setup options are shown. Add the key, then enter the short code.");
 if(result.demoCode)simulatedDelivery("DEMO authenticator confirmation code:",result.demoCode);
}catch(e){error(e)}};
$("copySecret").onclick=()=>copy(secret,"Setup key copied. Paste it into your authenticator app.");
$("hideSecret").onclick=()=>{$("secretArea").hidden=true;$("hideSecret").hidden=true;$("showSecret").hidden=false;note("Setup key hidden. You can show it again when needed.")};
$("showSecret").onclick=()=>{$("secretArea").hidden=false;$("hideSecret").hidden=false;$("showSecret").hidden=true;note("Setup key shown again.")};
$("verifyAuthenticator").onclick=async()=>{try{await api("/api/authenticator/verify",{code:$("authCode").value});note("Authenticator confirmed. Next, save your recovery codes.");show("backup")}catch(e){error(e)}};
async function prepareCodes(){try{
 const result=await api("/api/backup/generate",{});
 if(!Array.isArray(result.codes)||!result.codes.length)throw Error("Recovery codes could not be prepared. Please try again.");
 codes=result.codes;
 $("recoveryList").replaceChildren(...codes.map(code=>{const item=document.createElement("li");item.textContent=code;return item}));
 $("backupDisplay").hidden=false;$("savedCodes").checked=false;
 note("Recovery codes are ready. Copy or download them before continuing.");
 if(result.demoCodes)simulatedDelivery("DEMO recovery codes:",result.demoCodes);
}catch(e){error(e)}}
$("makeBackups").onclick=prepareCodes;$("regenerate").onclick=prepareCodes;
$("copyCodes").onclick=()=>copy(codes.join("\\n"),"Recovery codes copied.");
$("downloadCodes").onclick=()=>{const link=document.createElement("a"),url=URL.createObjectURL(new Blob([codes.join("\\n")],{type:"text/plain"}));link.href=url;link.download="harbour-bank-recovery-codes.txt";link.click();setTimeout(()=>URL.revokeObjectURL(url),0);note("Your recovery-code file was downloaded.")};
$("finish").onclick=async()=>{if(!$("savedCodes").checked)return note("Please tick the box after you have saved the codes.",false);try{await api("/api/backup/confirm",{});note("Setup complete. Your extra protection is on.");show("success")}catch(e){error(e)}};
$("testRecovery").onclick=async()=>{try{await api("/api/recovery/verify",{code:$("recoveryTest").value.toUpperCase()});note("That recovery code worked and cannot be used again.");$("recoveryTest").value=""}catch(e){error(e)}};
async function logout(){try{await api("/api/logout",{});csrf="";clearProvision();clearRecovery();$("identityEntry").hidden=true;$("identityCode").value="";statusLog("Signed out safely.");note("You are signed out.");show("sign-in")}catch(e){error(e)}}
document.querySelectorAll('a[href="#logout"]').forEach(link=>link.onclick=event=>{event.preventDefault();logout()});
$("logoutSuccess").onclick=logout;
document.querySelectorAll('a[href="#help"]').forEach(link=>link.onclick=event=>{event.preventDefault();beforeHelp=current;show("help")});
$("back").onclick=()=>show(beforeHelp);
boot();
})();
</script>
</body>
</html>`;
}

const server = Bun.serve({
  port: 3000,
  hostname: "0.0.0.0",
  tls: { cert, key: privateKey },
  async fetch(request) {
    const url = new URL(request.url);
    const nonce = opaque(16);
    try {
      if (url.protocol !== "https:") {
        return new Response("Secure connection required.", {
          status: 426,
          headers: securityHeaders(request, nonce),
        });
      }
      if (request.method === "OPTIONS") {
        if (!sameOrigin(request)) return new Response(null, { status: 403, headers: securityHeaders(request, nonce) });
        return new Response(null, {
          status: 204,
          headers: {
            ...securityHeaders(request, nonce),
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
          },
        });
      }
      if (url.pathname === "/" && request.method === "GET") {
        return new Response(page(nonce), {
          headers: { ...securityHeaders(request, nonce), "Content-Type": "text/html; charset=utf-8" },
        });
      }
      if (url.pathname === "/api/bootstrap" && request.method === "GET") {
        let session = getSession(request);
        if (!session) {
          session = newSession();
          return json(request, { signedIn: false, csrf: session.csrf }, 200, { "Set-Cookie": cookieValue(session.id) });
        }
        return json(request, session.userId ? state(session) : { signedIn: false, csrf: session.csrf });
      }
      if (url.pathname === "/api/signin" && request.method === "POST") {
        const old = getSession(request), data = await body(request);
        if (!old || !data || !sameOrigin(request) || request.headers.get("x-csrf-token") !== old.csrf) {
          return json(request, { error: "Your security check expired. Refresh and try again." }, 403);
        }
        const email = typeof data.email === "string" ? data.email.toLowerCase() : "";
        const account = email === "marcus@example.test" ? accounts.get("marcus-001") : undefined;
        const password = typeof data.password === "string" && data.password.length <= 128 ? data.password : "";
        const candidate = Buffer.from(passwordHash(password), "hex");
        const expected = Buffer.from(account?.passwordHash || dummyPassword, "hex");
        const matches = candidate.length === expected.length && timingSafeEqual(candidate, expected);
        if (isLocked(old.signInFailures) || (account && isLocked(account.signInFailures))) {
          return json(request, { error: "Please wait 15 minutes before trying to sign in again." }, 429);
        }
        if (!emailOK(data.email) || !account || !matches) {
          failed(old.signInFailures);
          if (account) failed(account.signInFailures);
          return json(request, { error: "We could not sign you in with those details. Check them and try again." }, 401);
        }
        cleared(old.signInFailures); cleared(account.signInFailures);
        sessions.delete(old.id);
        const session = newSession(account.id);
        return json(request, state(session), 200, { "Set-Cookie": cookieValue(session.id) });
      }
      if (url.pathname === "/api/identity/request" && request.method === "POST") {
        const auth = authorized(request, true); if (auth.error) return auth.error;
        const data = await body(request);
        if (!data || !["email", "phone"].includes(String(data.method))) return json(request, { error: "Choose email or phone, then try again." }, 400);
        if (auth.session!.stage !== "identity") return json(request, { error: "Please follow the setup steps in order." }, 409);
        const account = auth.account!, now = Date.now();
        if (isLocked(account.identityFailures)) return json(request, { error: retry() }, 429);
        account.requests = account.requests.filter((time) => now - time < LOCK);
        if (account.requests.length >= 3) return json(request, { error: "You have asked for several codes. Please wait 15 minutes before asking again." }, 429);
        const code = DEMO_MODE ? demoIdentity : randomInt(0, 1_000_000).toString().padStart(6, "0");
        auth.session!.identity = { hash: hash(code), expires: now + LIFE, used: false };
        account.requests.push(now);
        return json(request, DEMO_MODE ? { csrf: auth.session!.csrf, demoCode: code } : { csrf: auth.session!.csrf });
      }
      if (url.pathname === "/api/identity/verify" && request.method === "POST") {
        const auth = authorized(request, true); if (auth.error) return auth.error;
        const data = await body(request), challenge = auth.session!.identity, failures = auth.account!.identityFailures;
        if (!data || !otpOK(data.code)) return json(request, { error: "Enter the 6-number code. Example: 123456." }, 400);
        if (!challenge || challenge.used || Date.now() > challenge.expires) return json(request, { error: "That code is no longer available. Send a new code and try again." }, 400);
        if (isLocked(failures)) return json(request, { error: retry() }, 429);
        if (hash(data.code) !== challenge.hash) {
          failed(failures);
          return json(request, { error: failures.lockedUntil ? retry() : "That code did not match. Check the 6 numbers or send a new code." }, failures.lockedUntil ? 429 : 400);
        }
        challenge.used = true; cleared(failures); auth.session!.stage = "setup";
        return json(request, { csrf: auth.session!.csrf });
      }
      if (url.pathname === "/api/authenticator/start" && request.method === "POST") {
        const auth = authorized(request, true); if (auth.error) return auth.error;
        if (auth.session!.stage !== "setup") return json(request, { error: "Please complete the earlier step first." }, 409);
        if (isLocked(auth.account!.authenticatorFailures)) return json(request, { error: retry() }, 429);

        /*
         Task: every authenticated user at the valid setup stage receives a
         usable provisioning URI and setup secret, including production mode.
         The seed is only retained encrypted in the server session until verify.
        */
        const secret = base32(randomBytes(20));
        auth.session!.pendingSecret = encrypt(secret);
        const fixture = DEMO_MODE ? demoAuthenticator : "";
        auth.session!.fixture = fixture ? { hash: hash(fixture), expires: Date.now() + LIFE, used: false } : undefined;
        const provisioningUri = `otpauth://totp/${encodeURIComponent("HB:m")}?secret=${secret}&issuer=${encodeURIComponent("HB")}&algorithm=SHA1&digits=6&period=${PERIOD}`;
        return json(request, {
          csrf: auth.session!.csrf,
          secret,
          provisioningUri,
          ...(DEMO_MODE ? { demoCode: fixture } : {}),
        });
      }
      if (url.pathname === "/api/authenticator/verify" && request.method === "POST") {
        const auth = authorized(request, true); if (auth.error) return auth.error;
        const data = await body(request), failures = auth.account!.authenticatorFailures;
        if (isLocked(failures)) return json(request, { error: retry() }, 429);
        if (!data || !otpOK(data.code)) return json(request, { error: "Enter the 6-number code from your authenticator." }, 400);
        if (!auth.session!.pendingSecret) return json(request, { error: "Please show setup options again and enter the new code." }, 400);
        const fixture = auth.session!.fixture;
        const fixtureOK = DEMO_MODE && !!fixture && !fixture.used && fixture.expires >= Date.now() && hash(data.code) === fixture.hash;
        const valid = fixtureOK || validTotp(decrypt(auth.session!.pendingSecret), data.code);
        if (!valid) {
          failed(failures);
          return json(request, { error: failures.lockedUntil ? retry() : "That code did not match. Check your authenticator and try again." }, failures.lockedUntil ? 429 : 400);
        }
        if (fixtureOK) fixture!.used = true;
        cleared(failures);
        auth.account!.secret = auth.session!.pendingSecret;
        auth.session!.pendingSecret = undefined;
        auth.session!.fixture = undefined;
        auth.session!.stage = "backup";
        return json(request, { csrf: auth.session!.csrf });
      }
      if (url.pathname === "/api/backup/generate" && request.method === "POST") {
        const auth = authorized(request, true); if (auth.error) return auth.error;
        if (!["backup", "success"].includes(auth.session!.stage)) return json(request, { error: "Please confirm your authenticator first." }, 409);

        /*
         Task: return each newly generated set exactly once in this response in
         both modes. Only hashes are retained at rest after this response.
        */
        const codes = DEMO_MODE ? [...demoRecovery] : makeCodes();
        auth.account!.backups = new Map(codes.map((code) => [hash(code), false]));
        auth.session!.stage = "backup";
        return json(request, {
          csrf: auth.session!.csrf,
          codes,
          ...(DEMO_MODE ? { demoCodes: codes } : {}),
        });
      }
      if (url.pathname === "/api/backup/confirm" && request.method === "POST") {
        const auth = authorized(request, true); if (auth.error) return auth.error;
        if (auth.session!.stage !== "backup" || !auth.account!.backups.size) return json(request, { error: "Prepare and save recovery codes before continuing." }, 409);
        auth.session!.stage = "success";
        return json(request, { csrf: auth.session!.csrf });
      }
      if (url.pathname === "/api/recovery/verify" && request.method === "POST") {
        const auth = authorized(request, true); if (auth.error) return auth.error;
        const data = await body(request), failures = auth.account!.recoveryFailures;
        if (isLocked(failures)) return json(request, { error: retry() }, 429);
        if (!data || !codeOK(data.code)) return json(request, { error: "Enter a recovery code in this format: ABCDE-2345." }, 400);
        const value = hash(data.code);
        if (auth.account!.backups.get(value) !== false) {
          failed(failures);
          return json(request, { error: failures.lockedUntil ? retry() : "That recovery code cannot be used. Try a different saved code." }, failures.lockedUntil ? 429 : 400);
        }
        auth.account!.backups.set(value, true); cleared(failures);
        return json(request, { csrf: auth.session!.csrf });
      }
      if (url.pathname === "/api/logout" && request.method === "POST") {
        const session = getSession(request);
        if (!session || !sameOrigin(request) || request.headers.get("x-csrf-token") !== session.csrf) return json(request, { error: "Your security check expired. Refresh and try again." }, 403);
        sessions.delete(session.id);
        return json(request, { ok: true }, 200, { "Set-Cookie": clearCookie });
      }
      return new Response("Not found.", { status: 404, headers: securityHeaders(request, nonce) });
    } catch {
      return json(request, { error: "Something went wrong. Please refresh and try again." }, 500);
    }
  },
});

console.log(`MFA server ready on https://localhost:${server.port} (${DEMO_MODE ? "simulated delivery enabled" : "production-safe mode"})`);
