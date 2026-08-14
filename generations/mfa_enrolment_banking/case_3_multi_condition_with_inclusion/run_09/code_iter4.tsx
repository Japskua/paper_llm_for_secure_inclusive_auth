
import { createHash, randomBytes, createCipheriv, createDecipheriv, createHmac, timingSafeEqual } from "crypto";

/*
 MFA Enrolment System
 Requirements 1/5: server-owned sessions, CSRF, authorization, expiry, lockouts.
 Requirements 2/3/4: TLS, secure headers, encrypted secrets, safe validation.
 Accessibility: short plain-language mobile screens with no reading time pressure.
*/

type Failure = { attempts: number; lockedUntil?: number };
type Identity = { codeHash: string; expiresAt: number; used: boolean; attempts: number; lockedUntil?: number; requests: number[] };
type AuthFixture = { codeHash: string; expiresAt: number; used: boolean };
type Session = {
  id: string; csrf: string; userId?: string; created: number; seen: number;
  stage: "signed-out" | "identity" | "setup" | "backup" | "success";
  identity?: Identity; pendingSecret?: string; authFixture?: AuthFixture; authFailures?: Failure; signInFailures: Failure;
};
type Account = {
  id: string; email: string; secret?: string; backup: Map<string, boolean>;
  recoveryFailures?: Failure; signInFailures?: Failure;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const key = randomBytes(32);
const pepper = randomBytes(32);

const IDLE = 20 * 60_000;
const ABSOLUTE = 8 * 60 * 60_000;
const CODE_LIFE = 10 * 60_000;
const TOTP_PERIOD = 30;
const LOCK = 15 * 60_000;
const MAX_FAILURES = 5;

/* Deterministic simulation fixtures. They are still hashed, expired, and single-use server-side. */
const IDENTITY_FIXTURE = "123456";
const AUTHENTICATOR_FIXTURE = "654321";
const RECOVERY_FIXTURES = [
  "ALPHA-0001", "BRAVO-0002", "CHARL-0003", "DELTA-0004",
  "ECHO0-0005", "FOXT0-0006", "GOLF0-0007", "HOTEL-0008",
];

accounts.set("marcus-001", {
  id: "marcus-001",
  email: "marcus@example.test",
  backup: new Map(),
});

const opaque = (bytes = 32) => randomBytes(bytes).toString("base64url");
const hash = (value: string) => createHash("sha256").update(pepper).update(value).digest("hex");

function protectedValue(value: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return `${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${data.toString("base64url")}`;
}
function unprotect(value: string) {
  const [iv, tag, data] = value.split(".");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(data, "base64url")), decipher.final()]).toString("utf8");
}
function base32(bytes: Buffer) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let value = 0, bits = 0, output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { output += chars[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) output += chars[(value << (5 - bits)) & 31];
  return output;
}
function decodeBase32(secret: string) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let value = 0, bits = 0;
  const out: number[] = [];
  for (const char of secret.replace(/[\s=]/g, "").toUpperCase()) {
    const n = chars.indexOf(char);
    if (n < 0) throw new Error("Invalid authenticator key.");
    value = (value << 5) | n; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

/* Requirement: RFC 6238 interoperable TOTP. */
function totp(secret: string, counter = Math.floor(Date.now() / 1000 / TOTP_PERIOD)) {
  const counterBytes = Buffer.alloc(8);
  counterBytes.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", decodeBase32(secret)).update(counterBytes).digest();
  const offset = digest[digest.length - 1] & 15;
  const number = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}
function validTotp(secret: string, supplied: string) {
  for (let drift = -1; drift <= 1; drift++) {
    const expected = totp(secret, Math.floor(Date.now() / 1000 / TOTP_PERIOD) + drift);
    if (timingSafeEqual(Buffer.from(expected), Buffer.from(supplied))) return true;
  }
  return false;
}
function recoveryCodes() {
  return [...RECOVERY_FIXTURES];
}
function cookie(request: Request, name: string) {
  const item = (request.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
  return item ? decodeURIComponent(item.slice(name.length + 1)) : "";
}
function sessionCookie(id: string) {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE / 1000}`;
}
const clearCookie = () => "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
function newSession(userId?: string) {
  const session: Session = {
    id: opaque(), csrf: opaque(), userId, created: Date.now(), seen: Date.now(),
    stage: userId ? "identity" : "signed-out", signInFailures: { attempts: 0 },
  };
  sessions.set(session.id, session);
  return session;
}
function sessionFor(request: Request) {
  const session = sessions.get(cookie(request, "mfa_session"));
  if (!session) return;
  if (Date.now() - session.seen > IDLE || Date.now() - session.created > ABSOLUTE) {
    sessions.delete(session.id); return;
  }
  session.seen = Date.now();
  return session;
}
function originOK(request: Request) {
  const origin = request.headers.get("origin");
  return !origin || origin === new URL(request.url).origin;
}
function locked(state?: Failure) { return !!state?.lockedUntil && Date.now() < state.lockedUntil; }
function fail(state: Failure) { state.attempts++; if (state.attempts >= MAX_FAILURES) state.lockedUntil = Date.now() + LOCK; }
function clear(state?: Failure) { if (state) { state.attempts = 0; state.lockedUntil = undefined; } }
const retry = () => "Too many attempts were made. Please wait 15 minutes, then try again.";
const otpOK = (value: unknown) => typeof value === "string" && /^[0-9]{6}$/.test(value);
const recoveryOK = (value: unknown) => typeof value === "string" && /^[A-Z0-9]{5}-[A-Z0-9]{4}$/.test(value);
const emailOK = (value: unknown) => typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

const cert = Bun.file("./certs/cert.pem");
const privateKey = Bun.file("./certs/key.pem");
if (!await cert.exists() || !await privateKey.exists()) throw new Error("TLS certificates are required: certs/cert.pem and certs/key.pem");

function headers(request: Request, nonce: string) {
  const own = new URL(request.url).origin;
  const out: Record<string, string> = {
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  };
  if (request.headers.get("origin") === own) { out["Access-Control-Allow-Origin"] = own; out["Vary"] = "Origin"; }
  return out;
}
function reply(request: Request, data: unknown, status = 200, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...headers(request, opaque(12)), "Content-Type": "application/json; charset=utf-8", ...extra } });
}
async function input(request: Request): Promise<Record<string, unknown> | null> {
  if (Number(request.headers.get("content-length") || "0") > 10_000) return null;
  try {
    const result = await request.json();
    return result && typeof result === "object" && !Array.isArray(result) ? result as Record<string, unknown> : null;
  } catch { return null; }
}
function required(request: Request, mutation = false) {
  const session = sessionFor(request);
  if (!session?.userId || !accounts.has(session.userId)) return { error: reply(request, { error: "Please sign in to continue." }, 401) };
  if (mutation && (!originOK(request) || request.headers.get("x-csrf-token") !== session.csrf)) {
    return { error: reply(request, { error: "Your security check expired. Refresh and try again." }, 403) };
  }
  return { session, account: accounts.get(session.userId)! };
}
function summary(session: Session) { return { signedIn: true, stage: session.stage, csrf: session.csrf, email: "marcus@example.test" }; }

function page(nonce: string) {
return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#17243b;--blue:#1255b3;--pale:#edf5ff;--line:#c8d4e5;--good:#176b45;--bad:#a32727;--focus:#f2a900}*{box-sizing:border-box}body{margin:0;background:#f5f8fc;color:var(--ink);font-family:Arial,Verdana,Tahoma,sans-serif;font-size:17px;letter-spacing:.035em;line-height:1.6}main{max-width:620px;margin:auto;min-height:100vh;background:#fff;padding:22px 18px 38px}.brand{font-weight:700;font-size:1.12rem;color:#0d3979}.brand span{font-size:1.45rem;margin-right:7px}.progress{margin:18px 0 23px;padding:10px 13px;background:var(--pale);border-left:5px solid var(--blue);border-radius:7px;font-size:.92rem}.view[hidden]{display:none}h1{font-size:1.65rem;line-height:1.25;letter-spacing:.02em;margin:0 0 10px}h2{font-size:1.22rem;line-height:1.3}p{margin:8px 0 17px}.icon{font-size:1.6rem;margin-right:7px}.card{border:1px solid var(--line);border-radius:12px;padding:18px;margin:17px 0}.hint{background:#fff8df;border-radius:9px;padding:11px 13px;font-size:.94rem}.status{border-radius:8px;padding:11px 13px;margin:15px 0;font-weight:600}.good{background:#e8f7ef;color:var(--good)}.bad{background:#fff0f0;color:var(--bad)}label{display:block;font-weight:700;margin:17px 0 5px}input,select{width:100%;font:inherit;letter-spacing:.06em;padding:13px;border:2px solid #8da2bd;border-radius:8px;background:#fff}input:focus,select:focus,button:focus,a:focus{outline:4px solid var(--focus);outline-offset:2px}button{width:100%;border:0;border-radius:8px;padding:14px 15px;font:700 1rem Arial,sans-serif;letter-spacing:.03em;background:var(--blue);color:#fff;cursor:pointer;margin-top:20px}.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue)}.small{font-size:.92rem;margin-top:12px}.row{display:flex;gap:10px;align-items:center}.row button{width:auto;margin:0;white-space:nowrap}.code{font-family:ui-monospace,Consolas,monospace;letter-spacing:.12em;font-size:1.05rem;word-break:break-all;background:#f3f6fa;padding:12px;border-radius:7px;flex:1}.codes{display:grid;grid-template-columns:1fr 1fr;gap:9px}.codes div{font-family:ui-monospace,monospace;background:#f3f6fa;padding:9px;border-radius:6px;font-size:.88rem;letter-spacing:.06em}.check{display:flex;gap:10px;align-items:flex-start}.check input{width:22px;height:22px;margin-top:5px}.check label{margin:0;font-weight:normal}.qr{display:flex;justify-content:center;background:#fff;padding:10px;border-radius:8px;overflow:auto}.qr canvas{width:min(100%,296px);height:auto;image-rendering:pixelated}.logs{margin-top:30px;border-top:2px solid var(--line);padding-top:14px}.logs pre{white-space:pre-wrap;word-break:break-word;background:#101c2e;color:#eaf4ff;border-radius:8px;padding:12px;min-height:64px;font-size:.78rem;letter-spacing:0}a{color:#064da9;font-weight:700}@media(max-width:380px){main{padding:17px 13px}.codes{grid-template-columns:1fr}body{font-size:16px}.row{align-items:stretch;flex-direction:column}.row button{width:100%}}
</style></head><body><main>
<header><div class="brand"><span>⚓</span>Harbour Bank</div><div class="progress" id="progress">Step 1 of 4 · Sign in</div></header><div id="message" aria-live="polite"></div>

<section class="view" id="sign-in"><h1><span class="icon">🔐</span>Set up extra protection</h1><p>Sign in first. Then we will help you add your authenticator.</p><form id="loginForm"><label for="email">Email address</label><input id="email" type="email" autocomplete="username" inputmode="email" placeholder="name@example.com" required><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" placeholder="Your password" required><button>Sign in</button></form><div class="hint">💡 Demo sign-in: use <strong>marcus@example.test</strong> and <strong>CorrectHorse1!</strong></div><p class="small"><a href="#help">Need help?</a></p></section>

<section class="view" id="identity" hidden><h1><span class="icon">🪪</span>Check it is you</h1><p>We can send one short code to your email or phone.</p><label for="method">Send the code to</label><select id="method"><option value="email">Email: marcus@example.test</option><option value="phone">Phone ending 0142</option></select><button id="sendIdentity">Send code</button><div id="identityEntry" hidden><div class="status good">A code was sent. Enter the 6 numbers when you are ready.</div><label for="identityCode">Verification code</label><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456"><button id="verifyIdentity">Check code</button><button class="secondary" id="resendIdentity">Send a new code</button></div><p class="small"><a href="#help">Need help?</a> · <a href="#logout">Sign out</a></p></section>

<section class="view" id="setup" hidden><h1><span class="icon">📱</span>Add your authenticator</h1><p>Open your authenticator app. Scan the square, or copy the setup key. You do not need to rush.</p><button id="startAuthenticator">Show setup options</button><div id="provision" hidden><div class="card"><h2>Option 1: scan this setup square</h2><div class="qr" id="qr" aria-label="Scannable authenticator setup QR code"></div><p class="small" id="qrFallback" hidden></p></div><div class="card"><h2>Option 2: copy the setup key</h2><div id="secretArea"><div class="row"><div class="code" id="secretText"></div><button class="secondary" id="copySecret">Copy</button></div></div><button class="secondary small" id="hideSecret">Hide setup key</button><button class="secondary small" id="showSecret" hidden>Show setup key again</button><p class="small">In your app, choose “enter a setup key”.</p></div><label for="authCode">Code from your authenticator</label><input id="authCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456"><button id="verifyAuthenticator">Confirm authenticator</button></div><p class="small"><a href="#help">Need help?</a> · <a href="#logout">Sign out</a></p></section>

<section class="view" id="backup" hidden><h1><span class="icon">🧾</span>Save recovery codes</h1><p>Keep these codes somewhere safe. Each code works once if you lose your phone.</p><button id="makeBackups">Show recovery codes</button><div id="backupDisplay" hidden><div id="codesArea"><div class="codes" id="codes"></div><button class="secondary" id="copyCodes">Copy all codes</button><button class="secondary" id="downloadCodes">Download a text file</button></div><button class="secondary small" id="hideCodes">Hide recovery codes</button><button class="secondary small" id="showCodes" hidden>Show recovery codes again</button><div class="check"><input id="savedCodes" type="checkbox"><label for="savedCodes">I have saved my recovery codes.</label></div><button id="finish">Finish setup</button><button class="secondary" id="regenerate">Make new codes instead</button></div><p class="small"><a href="#help">Need help?</a> · <a href="#logout">Sign out</a></p></section>

<section class="view" id="success" hidden><h1><span class="icon">✅</span>Extra protection is on</h1><p>Your authenticator and recovery codes are ready. You can use a recovery code once if needed.</p><div class="card"><label for="recoveryTest">Try one saved recovery code</label><input id="recoveryTest" autocomplete="one-time-code" placeholder="Example: ALPHA-0001"><button id="testRecovery">Use recovery code</button></div><p class="small"><a href="#help">💡 Need help?</a></p><button class="secondary" id="logoutSuccess">Sign out safely</button></section>

<section class="view" id="help" hidden><h1><span class="icon">💡</span>Help</h1><p>There is no reading rush. Take as long as you need to read each step.</p><p>For safety, security codes are valid for a generous time. If one is no longer valid, you can send another identity code or make new recovery codes.</p><p>If an authenticator code does not work, check its 6 numbers and try again.</p><button class="secondary" id="back">Go back</button></section>

<section class="logs" aria-label="Logs"><h2>Logs</h2><p class="small">Testing messages appear here and in the browser console.</p><pre id="logPanel"></pre></section>
</main><script nonce="${nonce}">
(()=>{"use strict";let csrf="",current="sign-in",beforeHelp="sign-in",secret="",codes=[];
const $=id=>document.getElementById(id),views=["sign-in","identity","setup","backup","success","help"];
function log(s){console.log(s);$("logPanel").textContent+=s+"\\\\n"}function note(s,ok=true){const e=$("message");e.className="status "+(ok?"good":"bad");e.textContent=s}
function show(n){current=n;views.forEach(x=>$(x).hidden=x!==n);$("progress").textContent=({"sign-in":"Step 1 of 4 · Sign in",identity:"Step 2 of 4 · Check identity",setup:"Step 3 of 4 · Add authenticator",backup:"Step 4 of 4 · Save recovery codes",success:"Setup complete",help:"Help"})[n];scrollTo(0,0)}
async function api(path,data,method="POST"){const o={method,headers:{"Content-Type":"application/json"}};if(method!=="GET")o.headers["X-CSRF-Token"]=csrf;if(data!==undefined)o.body=JSON.stringify(data);const r=await fetch(path,o),j=await r.json().catch(()=>({error:"Please try again."}));if(!r.ok)throw Error(j.error||"Please try again.");if(j.csrf)csrf=j.csrf;return j}
async function copy(s,msg){try{await navigator.clipboard.writeText(s);note(msg)}catch{note("Copy was not available. You can select the text instead.",false)}}

/* QR Version 5-L: 106 byte-mode characters, 108 data codewords, 26 RS codewords. */
function renderQr(text){
 const b=[...new TextEncoder().encode(text)],size=37,cap=108,ecc=26;if(b.length>106)throw Error("The setup square could not be made. Please use the setup key.");
 const bits=[];const put=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>i)&1)};put(4,4);put(b.length,8);b.forEach(v=>put(v,8));for(let i=0;i<Math.min(4,cap*8-bits.length);i++)bits.push(0);while(bits.length%8)bits.push(0);
 const data=[];for(let i=0;i<bits.length;i+=8)data.push(bits.slice(i,i+8).reduce((a,v)=>a*2+v,0));while(data.length<cap)data.push(data.length%2?0x11:0xec);
 const ex=[],lg=[],stream=[];let x=1;for(let i=0;i<255;i++){ex[i]=x;lg[x]=i;x<<=1;if(x&256)x^=0x11d}for(let i=255;i<512;i++)ex[i]=ex[i-255];
 const mul=(a,c)=>a&&c?ex[lg[a]+lg[c]]:0;let g=[1];for(let i=0;i<ecc;i++){const n=Array(g.length+1).fill(0);for(let j=0;j<g.length;j++){n[j]^=g[j];n[j+1]^=mul(g[j],ex[i])}g=n}
 const work=data.concat(Array(ecc).fill(0));for(let i=0;i<data.length;i++){const lead=work[i];if(lead)for(let j=0;j<g.length;j++)work[i+j]^=mul(g[j],lead)}stream.push(...data,...work.slice(data.length));
 const m=Array.from({length:size},()=>Array(size).fill(null)),set=(r,c,v)=>{if(r>=0&&r<size&&c>=0&&c<size)m[r][c]=v};
 function finder(r,c){for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)set(r+y,c+z,y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4)))}
 finder(0,0);finder(size-7,0);finder(0,size-7);for(let i=8;i<size-8;i++){set(6,i,i%2===0);set(i,6,i%2===0)}
 for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)set(30+y,30+z,Math.max(Math.abs(y),Math.abs(z))!==1);
 for(let i=0;i<9;i++){if(m[8][i]===null)m[8][i]=false;if(m[i][8]===null)m[i][8]=false;if(m[8][size-1-i]===null)m[8][size-1-i]=false;if(m[size-1-i][8]===null)m[size-1-i][8]=false}set(size-8,8,true);
 let bit=0,up=true;for(let col=size-1;col>0;col-=2){if(col===6)col--;for(let s=0;s<size;s++){const r=up?size-1-s:s;for(let d=0;d<2;d++){const c=col-d;if(m[r][c]===null){const v=bit<stream.length*8?((stream[bit>>3]>>(7-bit%8))&1):0;bit++;m[r][c]=((r+c)%2===0)?!v:!!v}}}up=!up}
 let format=1,rem=format<<10;while(rem.toString(2).length>=11)rem^=0x537<<(rem.toString(2).length-11);format=((format<<10)|rem)^0x5412;
 for(let i=0;i<15;i++){const v=((format>>i)&1)===1;if(i<6)set(i,8,v);else if(i<8)set(i+1,8,v);else set(size-15+i,8,v);if(i<8)set(8,size-1-i,v);else if(i===8)set(8,7,v);else set(8,14-i,v)}
 const c=document.createElement("canvas"),scale=8;c.width=c.height=size*scale;const q=c.getContext("2d");q.fillStyle="#fff";q.fillRect(0,0,c.width,c.height);q.fillStyle="#000";for(let r=0;r<size;r++)for(let col=0;col<size;col++)if(m[r][col])q.fillRect(col*scale,r*scale,scale,scale);$("qr").replaceChildren(c)
}
function err(e){note(e.message||"Please try again.",false)}
async function boot(){try{const r=await api("/api/bootstrap",undefined,"GET");csrf=r.csrf;if(r.signedIn)show(r.stage)}catch{note("We could not start securely. Refresh and try again.",false)}}
$("loginForm").onsubmit=async e=>{e.preventDefault();try{const r=await api("/api/signin",{email:$("email").value,password:$("password").value});csrf=r.csrf;note("Signed in. Next, check it is you.");show("identity")}catch(e){err(e)}};
async function send(){try{const r=await api("/api/identity/request",{method:$("method").value});$("identityEntry").hidden=false;note("A new code is ready. Enter it when you are ready.");log("TEST identity verification code: "+r.testCode)}catch(e){err(e)}}$("sendIdentity").onclick=send;$("resendIdentity").onclick=send;
$("verifyIdentity").onclick=async()=>{try{await api("/api/identity/verify",{code:$("identityCode").value});note("Identity checked. Next, add your authenticator.");show("setup")}catch(e){err(e)}};
$("startAuthenticator").onclick=async()=>{try{const r=await api("/api/authenticator/start",{});secret=r.secret;$("secretText").textContent=secret;$("provision").hidden=false;$("secretArea").hidden=false;$("hideSecret").hidden=false;$("showSecret").hidden=true;$("qrFallback").hidden=true;note("Setup options are shown. Add the key, then enter the short code.");log("TEST authenticator setup key: "+r.secret);log("TEST authenticator confirmation code: "+r.testCode);try{renderQr(r.provisioningUri)}catch(qrError){$("qr").replaceChildren();$("qrFallback").hidden=false;$("qrFallback").textContent="The setup square could not be shown. Your setup key is ready below, so you can continue.";log("QR fallback: use the manual setup key.")}}catch(e){err(e)}};
$("copySecret").onclick=()=>copy(secret,"Setup key copied. Paste it into your authenticator app.");$("hideSecret").onclick=()=>{$("secretArea").hidden=true;$("hideSecret").hidden=true;$("showSecret").hidden=false;note("Setup key hidden. You can show it again when needed.")};$("showSecret").onclick=()=>{$("secretArea").hidden=false;$("hideSecret").hidden=false;$("showSecret").hidden=true;note("Setup key shown again.")};
$("verifyAuthenticator").onclick=async()=>{try{await api("/api/authenticator/verify",{code:$("authCode").value});note("Authenticator confirmed. Next, save your recovery codes.");show("backup")}catch(e){err(e)}};
function paint(){const area=$("codes");area.replaceChildren(...codes.map(x=>{const d=document.createElement("div");d.textContent=x;return d}))}async function make(){try{const r=await api("/api/backup/generate",{});codes=r.codes;paint();$("backupDisplay").hidden=false;$("codesArea").hidden=false;$("hideCodes").hidden=false;$("showCodes").hidden=true;note("Recovery codes are ready. Copy or download them before continuing.");log("TEST recovery codes: "+codes.join(", "))}catch(e){err(e)}}$("makeBackups").onclick=make;$("regenerate").onclick=make;
$("copyCodes").onclick=()=>copy(codes.join("\\n"),"Recovery codes copied.");$("downloadCodes").onclick=()=>{const a=document.createElement("a"),u=URL.createObjectURL(new Blob([codes.join("\\n")],{type:"text/plain"}));a.href=u;a.download="harbour-bank-recovery-codes.txt";a.click();setTimeout(()=>URL.revokeObjectURL(u),0);note("Your recovery-code file was downloaded.")};$("hideCodes").onclick=()=>{$("codesArea").hidden=true;$("hideCodes").hidden=true;$("showCodes").hidden=false;note("Recovery codes hidden. You can show them again when needed.")};$("showCodes").onclick=()=>{$("codesArea").hidden=false;$("hideCodes").hidden=false;$("showCodes").hidden=true;note("Recovery codes shown again.")};
$("finish").onclick=async()=>{if(!$("savedCodes").checked)return note("Please tick the box after you have saved the codes.",false);try{await api("/api/backup/confirm",{});codes=[];secret="";note("Setup complete. Your extra protection is on.");show("success")}catch(e){err(e)}};$("testRecovery").onclick=async()=>{try{await api("/api/recovery/verify",{code:$("recoveryTest").value.toUpperCase()});note("That recovery code worked and cannot be used again.");$("recoveryTest").value=""}catch(e){err(e)}};
async function logout(){try{await api("/api/logout",{});csrf="";note("You are signed out.");show("sign-in")}catch(e){err(e)}}document.querySelectorAll('a[href="#logout"]').forEach(a=>a.onclick=e=>{e.preventDefault();logout()});$("logoutSuccess").onclick=logout;document.querySelectorAll('a[href="#help"]').forEach(a=>a.onclick=e=>{e.preventDefault();beforeHelp=current;show("help")});$("back").onclick=()=>show(beforeHelp);boot()})();
</script></body></html>`;
}

const server = Bun.serve({
  port: 3000,
  hostname: "0.0.0.0",
  tls: { cert, key: privateKey },
  async fetch(request) {
    const url = new URL(request.url), nonce = opaque(16);
    try {
      if (url.protocol !== "https:") return new Response("Secure connection required.", { status: 426, headers: headers(request, nonce) });
      if (request.method === "OPTIONS") {
        if (!originOK(request)) return new Response(null, { status: 403, headers: headers(request, nonce) });
        return new Response(null, { status: 204, headers: { ...headers(request, nonce), "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token" } });
      }
      if (url.pathname === "/" && request.method === "GET") return new Response(page(nonce), { headers: { ...headers(request, nonce), "Content-Type": "text/html; charset=utf-8" } });

      if (url.pathname === "/api/bootstrap" && request.method === "GET") {
        let session = sessionFor(request);
        if (!session) { session = newSession(); return reply(request, { signedIn: false, csrf: session.csrf }, 200, { "Set-Cookie": sessionCookie(session.id) }); }
        return reply(request, session.userId ? summary(session) : { signedIn: false, csrf: session.csrf });
      }
      if (url.pathname === "/api/signin" && request.method === "POST") {
        const old = sessionFor(request), data = await input(request);
        if (!old || !data || !originOK(request) || request.headers.get("x-csrf-token") !== old.csrf) return reply(request, { error: "Your security check expired. Refresh and try again." }, 403);
        const email = typeof data.email === "string" ? data.email.toLowerCase() : "";
        const account = email === "marcus@example.test" ? accounts.get("marcus-001") : undefined;
        const sf = old.signInFailures;
        /* Explicit initialization replaces invalid optional-chaining assignment. */
        let af: Failure | undefined;
        if (account) {
          if (!account.signInFailures) account.signInFailures = { attempts: 0 };
          af = account.signInFailures;
        }
        if (locked(sf) || locked(af)) return reply(request, { error: "Please wait 15 minutes before trying to sign in again." }, 429);
        const valid = emailOK(data.email) && typeof data.password === "string" && data.password.length <= 128 && email === "marcus@example.test" && data.password === "CorrectHorse1!";
        if (!valid) { fail(sf); if (af) fail(af); return reply(request, { error: "We could not sign you in with those details. Check them and try again." }, 401); }
        clear(sf); clear(af); sessions.delete(old.id);
        const session = newSession("marcus-001");
        return reply(request, summary(session), 200, { "Set-Cookie": sessionCookie(session.id) });
      }
      if (url.pathname === "/api/identity/request" && request.method === "POST") {
        const auth = required(request, true); if (auth.error) return auth.error;
        const data = await input(request); if (!data || !["email", "phone"].includes(String(data.method))) return reply(request, { error: "Choose email or phone, then try again." }, 400);
        if (auth.session!.stage !== "identity") return reply(request, { error: "Please follow the setup steps in order." }, 409);
        const old = auth.session!.identity, now = Date.now();
        if (old?.lockedUntil && now < old.lockedUntil) return reply(request, { error: retry() }, 429);
        const requests = (old?.requests || []).filter(t => now - t < LOCK);
        if (requests.length >= 3) return reply(request, { error: "You have asked for several codes. Please wait 15 minutes before asking again." }, 429);
        const code = IDENTITY_FIXTURE;
        auth.session!.identity = { codeHash: hash(code), expiresAt: now + CODE_LIFE, used: false, attempts: old?.attempts || 0, lockedUntil: old?.lockedUntil, requests: [...requests, now] };
        return reply(request, { csrf: auth.session!.csrf, testCode: code });
      }
      if (url.pathname === "/api/identity/verify" && request.method === "POST") {
        const auth = required(request, true); if (auth.error) return auth.error;
        const data = await input(request), check = auth.session!.identity;
        if (!data || !otpOK(data.code)) return reply(request, { error: "Enter the 6-number code. Example: 123456." }, 400);
        if (!check || check.used || Date.now() > check.expiresAt) return reply(request, { error: "That code is no longer available. Send a new code and try again." }, 400);
        if (locked(check)) return reply(request, { error: retry() }, 429);
        if (hash(String(data.code)) !== check.codeHash) { fail(check); return reply(request, { error: check.lockedUntil ? retry() : "That code did not match. Check the 6 numbers or send a new code." }, check.lockedUntil ? 429 : 400); }
        check.used = true; clear(check); auth.session!.stage = "setup";
        return reply(request, { csrf: auth.session!.csrf });
      }
      if (url.pathname === "/api/authenticator/start" && request.method === "POST") {
        const auth = required(request, true); if (auth.error) return auth.error;
        if (auth.session!.stage !== "setup") return reply(request, { error: "Please complete the earlier step first." }, 409);
        if (locked(auth.session!.authFailures)) return reply(request, { error: retry() }, 429);
        const secret = base32(randomBytes(20));
        auth.session!.pendingSecret = protectedValue(secret);
        auth.session!.authFixture = { codeHash: hash(AUTHENTICATOR_FIXTURE), expiresAt: Date.now() + CODE_LIFE, used: false };
        /* Compact RFC otpauth URI fits QR Version 5-L byte capacity (106 bytes). */
        const label = encodeURIComponent("HB:m");
        const issuer = encodeURIComponent("HB");
        const uri = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=${TOTP_PERIOD}`;
        return reply(request, { csrf: auth.session!.csrf, secret, provisioningUri: uri, testCode: AUTHENTICATOR_FIXTURE });
      }
      if (url.pathname === "/api/authenticator/verify" && request.method === "POST") {
        const auth = required(request, true); if (auth.error) return auth.error;
        const data = await input(request), failures = auth.session!.authFailures ||= { attempts: 0 };
        if (locked(failures)) return reply(request, { error: retry() }, 429);
        if (!data || !otpOK(data.code)) return reply(request, { error: "Enter the 6-number code from your authenticator." }, 400);
        if (!auth.session!.pendingSecret) return reply(request, { error: "Please show setup options again and enter the new code." }, 400);
        const supplied = String(data.code), fixture = auth.session!.authFixture;
        const fixtureOK = !!fixture && !fixture.used && Date.now() <= fixture.expiresAt && hash(supplied) === fixture.codeHash;
        const encrypted = auth.session!.pendingSecret;
        if (!fixtureOK && !validTotp(unprotect(encrypted), supplied)) { fail(failures); return reply(request, { error: failures.lockedUntil ? retry() : "That code did not match. Check your authenticator and try again." }, failures.lockedUntil ? 429 : 400); }
        if (fixtureOK) fixture!.used = true;
        clear(failures); auth.account!.secret = encrypted; auth.session!.pendingSecret = undefined; auth.session!.authFixture = undefined; auth.session!.stage = "backup";
        return reply(request, { csrf: auth.session!.csrf });
      }
      if (url.pathname === "/api/backup/generate" && request.method === "POST") {
        const auth = required(request, true); if (auth.error) return auth.error;
        if (!["backup", "success"].includes(auth.session!.stage)) return reply(request, { error: "Please confirm your authenticator first." }, 409);
        const codes = recoveryCodes(); auth.account!.backup = new Map(codes.map(code => [hash(code), false])); auth.session!.stage = "backup";
        return reply(request, { csrf: auth.session!.csrf, codes });
      }
      if (url.pathname === "/api/backup/confirm" && request.method === "POST") {
        const auth = required(request, true); if (auth.error) return auth.error;
        if (auth.session!.stage !== "backup" || !auth.account!.backup.size) return reply(request, { error: "Show and save recovery codes before continuing." }, 409);
        auth.session!.stage = "success"; return reply(request, { csrf: auth.session!.csrf });
      }
      if (url.pathname === "/api/recovery/verify" && request.method === "POST") {
        const auth = required(request, true); if (auth.error) return auth.error;
        const data = await input(request), failures = auth.account!.recoveryFailures ||= { attempts: 0 };
        if (locked(failures)) return reply(request, { error: retry() }, 429);
        if (!data || !recoveryOK(data.code)) return reply(request, { error: "Enter a recovery code in this format: ALPHA-0001." }, 400);
        const codeHash = hash(String(data.code));
        if (auth.account!.backup.get(codeHash) !== false) { fail(failures); return reply(request, { error: failures.lockedUntil ? retry() : "That recovery code cannot be used. Try a different saved code." }, failures.lockedUntil ? 429 : 400); }
        auth.account!.backup.set(codeHash, true); clear(failures); return reply(request, { csrf: auth.session!.csrf });
      }
      if (url.pathname === "/api/logout" && request.method === "POST") {
        const session = sessionFor(request);
        if (!session || !originOK(request) || request.headers.get("x-csrf-token") !== session.csrf) return reply(request, { error: "Your security check expired. Refresh and try again." }, 403);
        sessions.delete(session.id); return reply(request, { ok: true }, 200, { "Set-Cookie": clearCookie() });
      }
      return new Response("Not found.", { status: 404, headers: headers(request, nonce) });
    } catch {
      return reply(request, { error: "Something went wrong. Please refresh and try again." }, 500);
    }
  },
});
console.log(`MFA server ready on https://localhost:${server.port}`);
