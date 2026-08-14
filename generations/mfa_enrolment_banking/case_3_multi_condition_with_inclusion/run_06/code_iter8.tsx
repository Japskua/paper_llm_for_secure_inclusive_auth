
import { serve, file } from "bun";

/*
 MFA Enrolment System — Requirements 1–5
 Server-side ownership and CSRF checks protect every state change. Sessions use
 Secure, HttpOnly, SameSite cookies; OTP seeds are encrypted and recovery codes
 are hashed at rest. TLS, CSP, HSTS, input validation, rate limits, expiry, and
 single-use verification are enforced server-side.

 Academic testing note: deterministic mock identity codes, setup secrets,
 authenticator test codes, and recovery codes are returned only to the active
 browser page. They are intentionally shown in the browser-only testing UI and
 logged only by browser JavaScript (never server logs, URLs, persistent browser
 storage, cookies, server errors, or console output from this Bun server).
*/
const PORT = 3000;
const IDLE = 20 * 60_000;
const ABSOLUTE = 8 * 60 * 60_000;
const CODE_LIFE = 10 * 60_000;
const LOCK = 5 * 60_000;
const MAX_FAILURES = 5;

const TEST_IDENTITY_OTP = "123456";
const TEST_SETUP_SECRET = "JBSWY3DPEHPK3PXP";
const TEST_AUTHENTICATOR_CODE = "654321";
const TEST_RECOVERY_CODES = [
  "ALFA-BETA-GAMA", "DELT-ECHO-FOXT", "GOLF-HOTL-INDI", "JULI-KILO-LIMA",
  "MIKE-NOVE-OSCA", "PAPA-QUEB-ROME", "SIER-TANG-UNIF", "VICT-WHIS-XRAY"
];

const origins = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`
]);

type Challenge = { hash: string; expires: number; used: boolean };
type Session = {
  id: string; csrf: string; created: number; lastSeen: number; userId?: string;
  identityVerified: boolean; identityChallenge?: Challenge; authenticatorChallenge?: Challenge;
};
type Account = {
  id: string; email: string; encryptedOtpSecret?: { iv: string; data: string };
  recoveryHashes: Set<string>; recoveryExpires?: number; recoveryFailures: number;
  recoveryLockedUntil: number; recoveryGenerated: boolean; recoveryConfirmed: boolean;
  mfaEnabled: boolean; authenticatorSetupStarted: boolean;
  identityFailures: number; identityLockedUntil: number;
  authenticatorFailures: number; authenticatorLockedUntil: number;
};
type Failure = { failures: number; lockedUntil: number };

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const loginFailures = new Map<string, Failure>();
const encryptionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
const pepper = randomText(32);

accounts.set("marcus-account", {
  id: "marcus-account", email: "marcus@example.com", recoveryHashes: new Set(),
  recoveryFailures: 0, recoveryLockedUntil: 0, recoveryGenerated: false,
  recoveryConfirmed: false, mfaEnabled: false, authenticatorSetupStarted: false,
  identityFailures: 0, identityLockedUntil: 0, authenticatorFailures: 0,
  authenticatorLockedUntil: 0
});

function randomText(length = 24) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, x => x.toString(16).padStart(2, "0")).join("");
}
function b64(value: Uint8Array) { return Buffer.from(value).toString("base64"); }
function unb64(value: string) { return new Uint8Array(Buffer.from(value, "base64")); }
async function hash(value: string) {
  return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${pepper}:${value}`))));
}
function same(a: string, b: string) {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b);
  if (x.length !== y.length) return false;
  let difference = 0;
  for (let i = 0; i < x.length; i++) difference |= x[i] ^ y[i];
  return difference === 0;
}
async function encrypt(value: string) {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, new TextEncoder().encode(value));
  return { iv: b64(iv), data: b64(new Uint8Array(data)) };
}
function cookie(req: Request, name: string) {
  for (const part of (req.headers.get("cookie") || "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
}
function makeSession(): Session {
  const now = Date.now();
  return { id: randomText(32), csrf: randomText(32), created: now, lastSeen: now, identityVerified: false };
}
function sessionCookie(id: string) {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE / 1000)}`;
}
function current(req: Request) {
  const id = cookie(req, "mfa_session");
  const session = id && sessions.get(id);
  if (!session) return;
  if (Date.now() - session.lastSeen > IDLE || Date.now() - session.created > ABSOLUTE) {
    sessions.delete(session.id);
    return;
  }
  session.lastSeen = Date.now();
  return session;
}
function headers(nonce?: string) {
  const h = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Resource-Policy": "same-origin"
  });
  h.set("Content-Security-Policy", nonce
    ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    : "default-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  return h;
}
function json(body: unknown, status = 200, h = headers()) { return new Response(JSON.stringify(body), { status, headers: h }); }
function fail(message = "We could not complete that step. Please try again.", status = 400) { return json({ ok: false, message }, status); }
function validEmail(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(value.trim()) && value.length < 255;
}
function six(value: unknown): value is string { return typeof value === "string" && /^\d{6}$/.test(value); }
function recovery(value: unknown): value is string { return typeof value === "string" && /^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$/.test(value); }
async function body(req: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await req.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch { return null; }
}
function csrf(req: Request, session: Session) {
  const token = req.headers.get("x-csrf-token");
  return !!token && same(token, session.csrf);
}
function owner(req: Request): { s: Session; a: Account } | Response {
  const s = current(req);
  if (!s?.userId) return fail("Please sign in again to continue.", 401);
  const a = accounts.get(s.userId);
  return a ? { s, a } : fail("Please sign in again to continue.", 401);
}
function verified(req: Request): { s: Session; a: Account } | Response {
  const result = owner(req);
  return result instanceof Response || result.s.identityVerified ? result : fail("Please finish identity check before changing MFA settings.", 403);
}
function stateFor(s: Session, a?: Account) {
  return {
    ok: true, csrf: s.csrf, loggedIn: !!s.userId, identityVerified: s.identityVerified,
    mfaEnabled: !!a?.mfaEnabled, authenticatorSetupStarted: !!a?.authenticatorSetupStarted,
    recoveryGenerated: !!a?.recoveryGenerated, recoveryConfirmed: !!a?.recoveryConfirmed
  };
}

function page(nonce: string) {
return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172334;--muted:#526174;--blue:#075fc6;--blue2:#034d9f;--pale:#edf6ff;--line:#cbd6e2;--good:#146c43;--error:#a12828}*{box-sizing:border-box}body{margin:0;background:#f2f5f8;color:var(--ink);font-family:Verdana,"Trebuchet MS",Arial,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.025em}main{width:min(100%,560px);margin:auto;min-height:100vh;padding:18px 16px 38px}header{display:flex;align-items:center;gap:11px;margin:5px 0 18px}.logo{display:grid;place-items:center;background:var(--blue);color:#fff;border-radius:50%;width:40px;height:40px;font-weight:bold}h1{font-size:1.45rem;line-height:1.25;margin:0}h2{font-size:1.3rem;line-height:1.35;margin:0 0 9px}p{margin:8px 0 14px}.card,.logs{background:#fff;border:1px solid var(--line);border-radius:14px;padding:21px 18px;box-shadow:0 1px 2px #13223a10}.steps{font-size:.86rem;color:var(--muted);margin:0 2px 12px}.step-now{color:var(--blue2);font-weight:bold}.icon{font-size:1.65rem;margin-right:7px}label{display:block;font-weight:bold;margin:17px 0 5px}input{width:100%;min-height:51px;border:2px solid #91a5b9;border-radius:9px;padding:10px 12px;color:var(--ink);font:inherit;letter-spacing:.045em}input:focus{outline:3px solid #8ac5ff;outline-offset:2px;border-color:var(--blue)}button{font:inherit;letter-spacing:.02em;border-radius:9px;cursor:pointer;min-height:50px;padding:10px 16px}.primary{width:100%;border:2px solid var(--blue);background:var(--blue);color:#fff;font-weight:bold;margin-top:18px}.primary:hover{background:var(--blue2)}.secondary{border:1px solid #62768b;background:#fff;color:#163e68;min-height:43px;margin-top:10px}.hint{color:var(--muted);font-size:.9rem;margin:4px 0 12px}.notice{border-left:5px solid var(--blue);background:var(--pale);padding:10px 12px;border-radius:5px;margin:15px 0}.error{border-left-color:var(--error);background:#fff0f0;color:#721b1b}.success{border-left-color:var(--good);background:#effaf3;color:#145535}.action-row{display:flex;gap:9px;flex-wrap:wrap;margin-top:8px}.secretbox{padding:10px;background:#f5f7f9;border:1px solid var(--line);border-radius:8px}.secret,code,.codes li,#loglines{font-family:ui-monospace,"Courier New",monospace;word-break:break-all}.qr{width:246px;height:246px;display:block;margin:17px auto;border:8px solid white;outline:1px solid var(--line);image-rendering:pixelated}.codes{list-style:none;padding:0;margin:10px 0;display:grid;grid-template-columns:1fr 1fr;gap:8px}.codes li{background:#f5f7f9;padding:8px;border:1px solid var(--line);border-radius:7px;text-align:center;font-size:.84rem}.footer{display:flex;justify-content:space-between;gap:12px;margin:17px 3px;font-size:.9rem}.link{color:#145897;text-decoration:underline;border:0;background:transparent;padding:3px;min-height:auto}details{margin-top:17px;border-top:1px solid var(--line);padding-top:11px}summary{cursor:pointer;color:#174f88;font-weight:bold}.logs{margin-top:16px;padding:14px 16px}.logs h2{font-size:1rem}.logs p{font-size:.78rem;margin:0 0 6px;color:var(--muted)}#loglines{font-size:.75rem;line-height:1.45;white-space:pre-wrap;max-height:180px;overflow:auto}[hidden]{display:none!important}@media(max-width:360px){body{font-size:16px}.card{padding:18px 14px}.codes{grid-template-columns:1fr}.qr{width:220px;height:220px}}
</style></head><body><main><header><div class="logo">HB</div><div><h1>Harbour Bank</h1><div class="hint">MFA enrolment</div></div></header><div id="app" aria-live="polite">Loading your secure setup…</div><section class="logs" aria-live="polite"><h2>Logs</h2><p>Testing-only mock-sensitive values are shown in this browser-only panel and logged in this browser's console. They are never sent to server logs, URLs, persistent storage, cookies, or server error output.</p><div id="loglines"></div></section></main>
<script nonce="${nonce}">(()=>{"use strict";
let csrf="",state=null,view="signin",identityCode=null,lastSetup=null,backupCodes=null,visible=true;
const app=document.getElementById("app"),logs=document.getElementById("loglines");
function log(message){console.log(message);const line=document.createElement("div");line.textContent=message;logs.appendChild(line)}
function text(el,value){el.textContent=value}
async function api(path,method="GET",data){const options={method,headers:{}};if(method!=="GET"){options.headers["Content-Type"]="application/json";options.headers["X-CSRF-Token"]=csrf;options.body=JSON.stringify(data||{})}let response;try{response=await fetch(path,options)}catch{throw Error("Connection problem. Check the secure page and try again.")}let result;try{result=await response.json()}catch{throw Error("We could not complete that step. Please try again.")}if(result.csrf)csrf=result.csrf;if(!response.ok||!result.ok)throw Error(result.message||"We could not complete that step. Please try again.");return result}
async function refresh(){state=await api("/api/state")}
function showError(message){const box=document.getElementById("message");if(box){text(box,message);box.className="notice error";box.hidden=false}}
function shell(step,title,icon,description,content){app.innerHTML='<div class="steps">Step <span class="step-now">'+step+'</span> of 5</div><section class="card"><h2><span class="icon">'+icon+'</span>'+title+'</h2><p>'+description+'</p><div id="message" class="notice error" hidden></div>'+content+'<details><summary>Need help?</summary><p>Take your time. You can retry a code or request a new code without penalty.</p></details></section><nav class="footer"><button class="link" id="help">Help</button><button class="link" id="logout">Log out</button></nav>';document.getElementById("help").onclick=()=>{view="help";render()};document.getElementById("logout").onclick=logout}
function render(){({signin,identity,setup,authenticatorConfirm,backup,recoveryManage,recover,success,help}[view]||help)()}
function signin(){shell("1","Sign in","🔐","Use the email for your new bank account.",'<div class="notice">For this practice setup, use <code>marcus@example.com</code> and password <code>bank-demo</code>.</div><form id="f"><label>Email address<input id="email" type="email" autocomplete="username" placeholder="marcus@example.com" required></label><div class="hint">Example: name@example.com</div><label>Password<input id="password" type="password" autocomplete="current-password" required></label><button class="primary">Continue</button></form>');f.onsubmit=async e=>{e.preventDefault();try{await api("/api/login","POST",{email:email.value,password:password.value});await refresh();log("SIMULATION: Sign-in accepted. Identity check is ready.");view=route();render()}catch(x){showError(x.message)}}}
function identity(){shell("2","Check it is you","✉️","We will send a short practice code to your account email.",'<div class="notice">There is no rush. The code has 6 numbers, like <code>123456</code>.</div><button class="primary" id="send">Send my code</button>');send.onclick=async()=>{try{const d=await api("/api/identity/send","POST");identityCode=d.testCode;log("TESTING ONLY — displayed identity OTP: "+identityCode);identityEntry()}catch(x){showError(x.message)}}}
function identityEntry(){shell("2","Enter the email code","✉️","Enter the short practice code below. It is shown only in this browser.",'<div class="notice success">Practice email code: <code id="practiceCode"></code></div><form id="f"><label>Email code<input id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required></label><div class="hint">Example: 123456</div><button class="primary">Check code</button></form><button class="secondary" id="again">Send a new code</button>');text(practiceCode,identityCode||"Request a new code");f.onsubmit=async e=>{e.preventDefault();try{await api("/api/identity/verify","POST",{code:code.value});identityCode=null;await refresh();log("SIMULATION: Identity check completed.");view=route();render()}catch(x){showError(x.message)}};again.onclick=identity}
function setup(){shell("3","Set up your authenticator","📱","Use an authenticator app on this phone. You can scan a code or copy a setup key.",'<div class="notice">Choose one easy way: scan the code, or copy the setup key.</div><button class="primary" id="make">Show setup options</button>');make.onclick=async()=>{try{lastSetup=await api("/api/authenticator/setup","POST");await refresh();log("TESTING ONLY — provisioning secret: "+lastSetup.secret);log("TESTING ONLY — provisioning URI: "+lastSetup.uri);log("TESTING ONLY — authenticator verification code: "+lastSetup.testCode);setupOptions()}catch(x){showError(x.message)}}}

/* Task: local standards-compliant QR Version 5-L byte-mode encoder.
   It bit-packs the exact otpauth URI returned by the server, creates Reed-
   Solomon error correction, applies a valid mask, and emits no network asset. */
function qrSvg(value){
 const size=37,bytes=Array.from(new TextEncoder().encode(value));if(bytes.length>106)throw Error("Setup code is too long.");
 const bits=[];const push=(n,count)=>{for(let i=count-1;i>=0;i--)bits.push((n>>>i)&1)};push(4,4);push(bytes.length,8);bytes.forEach(b=>push(b,8));push(0,Math.min(4,108*8-bits.length));while(bits.length%8)bits.push(0);
 const data=[];for(let i=0;i<bits.length;i+=8)data.push(bits.slice(i,i+8).reduce((n,b)=>n*2+b,0));for(let i=0;data.length<108;i++)data.push(i%2?17:236);
 const exp=[],log=[];let v=1;for(let i=0;i<255;i++){exp[i]=v;log[v]=i;v<<=1;if(v&256)v^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;
 let gen=[1];for(let i=0;i<26;i++){const next=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=mul(gen[j],exp[i])}gen=next}
 const rem=Array(26).fill(0);for(const byte of data){const factor=byte^rem.shift();rem.push(0);for(let j=0;j<26;j++)rem[j]^=mul(gen[j+1],factor)}const stream=[];data.concat(rem).forEach(byte=>pushTo(stream,byte,8));
 function pushTo(out,n,count){for(let i=count-1;i>=0;i--)out.push((n>>>i)&1)}
 function matrix(mask){
  const m=Array.from({length:size},()=>Array(size).fill(null));
  const set=(r,c,x)=>{if(r>=0&&r<size&&c>=0&&c<size)m[r][c]=x};
  const finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)set(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4)))};
  finder(0,0);finder(0,size-7);finder(size-7,0);
  for(let i=8;i<size-8;i++){set(6,i,i%2===0);set(i,6,i%2===0)}
  for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(30+y,30+x,Math.max(Math.abs(x),Math.abs(y))!==1);
  for(let i=0;i<9;i++){if(m[i][8]===null)set(i,8,false);if(m[8][i]===null)set(8,i,false)}for(let i=0;i<8;i++){set(size-1-i,8,false);set(8,size-1-i,false)}set(size-8,8,true);
  let bit=0,up=true;for(let c=size-1;c>0;c-=2){if(c===6)c--;for(let row=0;row<size;row++){const r=up?size-1-row:row;for(let j=0;j<2;j++){const col=c-j;if(m[r][col]===null){let q=stream[bit++]||0;const a=r,b=col;const invert=[(a+b)%2===0,a%2===0,b%3===0,(a+b)%3===0,(Math.floor(a/2)+Math.floor(b/3))%2===0,(a*b)%2+(a*b)%3===0,((a*b)%2+(a*b)%3)%2===0,((a+b)%2+(a*b)%3)%2===0][mask];m[r][col]=invert?!q:q}}}up=!up}
  let format=(1<<3)|mask,work=format<<10;while(work>=1024){let shift=0;for(let q=work;q>=1024;q>>=1)shift++;work^=0x537<<shift}format=((format<<10)|work)^0x5412;const fb=i=>(format>>>i)&1;
  for(let i=0;i<6;i++)m[i][8]=fb(i);m[7][8]=fb(6);m[8][8]=fb(7);m[8][7]=fb(8);for(let i=9;i<15;i++)m[8][14-i]=fb(i);for(let i=0;i<8;i++)m[8][size-1-i]=fb(i);for(let i=8;i<15;i++)m[size-15+i][8]=fb(i);
  return m;
 }
 function score(m){let p=0,dark=0;for(let r=0;r<size;r++)for(let c=0;c<size;c++){dark+=m[r][c]?1:0;if(r<size-1&&c<size-1&&m[r][c]===m[r+1][c]&&m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c+1])p+=3}for(let r=0;r<size;r++)for(let c=0;c<size;c++){let h=1,w=1;while(c+w<size&&m[r][c+w]===m[r][c])w++;while(r+h<size&&m[r+h][c]===m[r][c])h++;if(w>=5)p+=w-2;if(h>=5)p+=h-2}return p+Math.floor(Math.abs(dark*100/(size*size)-50)/5)*10}
 let best=matrix(0),bestScore=score(best);for(let i=1;i<8;i++){const candidate=matrix(i),candidateScore=score(candidate);if(candidateScore<bestScore){best=candidate;bestScore=candidateScore}}let path="";for(let r=0;r<size;r++)for(let c=0;c<size;c++)if(best[r][c])path+="M"+c+" "+r+"h1v1h-1z";return '<svg class="qr" viewBox="-4 -4 45 45" role="img" aria-label="Scannable authenticator setup QR code"><rect x="-4" y="-4" width="45" height="45" fill="white"/><path fill="black" d="'+path+'"/></svg>'
}
function setupOptions(){shell("3","Add this to your app","📱","Scan the square in your authenticator app. Or copy the setup key below.",'<div id="qrPlace"></div><label>Setup key</label><div class="secretbox"><span class="secret" id="key"></span></div><div class="action-row"><button class="secondary" id="copy">Copy setup key</button><button class="secondary" id="hide">Hide key</button></div><div class="hint">Manual option: choose “enter setup key” in your app, then paste it.</div><div class="notice">Practice check code: <code id="testCode"></code></div><button class="primary" id="ready">I added it to my app</button>');qrPlace.innerHTML=qrSvg(lastSetup.uri);text(key,visible?lastSetup.secret:"••••••••••••••••");text(testCode,lastSetup.testCode);copy.onclick=async()=>{try{await navigator.clipboard.writeText(lastSetup.secret);log("SIMULATION: Setup key copied to clipboard.")}catch{showError("Copy did not work. Select the setup key and copy it.")}};hide.onclick=()=>{visible=!visible;setupOptions()};ready.onclick=()=>{view="authenticatorConfirm";render()}}
function authenticatorConfirm(){shell("4","Check your authenticator","✅","Enter the 6-number practice code shown with your setup options.",'<form id="f"><label>Authenticator code<input id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required></label><div class="hint">Example: 123456</div><button class="primary">Check authenticator</button></form><button class="secondary" id="show">Show setup key again</button>');f.onsubmit=async e=>{e.preventDefault();try{await api("/api/authenticator/confirm","POST",{code:code.value});lastSetup=null;await refresh();log("SIMULATION: Authenticator confirmed.");view=route();render()}catch(x){showError(x.message)}};show.onclick=()=>lastSetup?setupOptions():setup()}
function backup(){shell("5","Save backup codes","🧾","Keep these codes somewhere safe. Each one works once if you cannot use your authenticator.",'<div class="notice">You can copy all codes. You will next check one code, so you know where they are.</div><button class="primary" id="create">Show my backup codes</button>');create.onclick=async()=>{try{const d=await api("/api/recovery/generate","POST",{});backupCodes=d.codes;await refresh();log("TESTING ONLY — generated backup recovery codes: "+backupCodes.join(", "));backupList(backupCodes)}catch(x){showError(x.message)}}}
function backupList(codes){shell("5","Your backup codes","🧾","Copy or write down these short codes. Each code can be used once.",'<ul class="codes" id="list"></ul><button class="secondary" id="copy">Copy all codes</button><button class="primary" id="check">I saved them — check one code</button>');for(const value of codes){const li=document.createElement("li");text(li,value);list.appendChild(li)}copy.onclick=async()=>{try{await navigator.clipboard.writeText(codes.join("\\n"));log("SIMULATION: Backup codes copied to clipboard.")}catch{showError("Copy did not work. Select the codes and copy them.")}};check.onclick=()=>{view="recover";render()}}
function recoveryManage(){shell("5","Manage backup codes","🧾","Your backup codes were created, but they have not been checked yet. For safety, codes cannot be shown again after leaving that screen.",'<div class="notice">You can generate a new set. This will permanently invalidate every current backup code.</div><button class="primary" id="regen">Generate replacement codes</button><button class="secondary" id="check">I already saved a code — check it</button>');regen.onclick=async()=>{if(!window.confirm("Generate replacement codes? Your current backup codes will stop working."))return;try{const d=await api("/api/recovery/generate","POST",{confirmRegenerate:true});backupCodes=d.codes;await refresh();log("TESTING ONLY — generated replacement recovery codes: "+backupCodes.join(", "));backupList(backupCodes)}catch(x){showError(x.message)}};check.onclick=()=>{view="recover";render()}}
function recover(){shell("5","Check one backup code","🔎","Enter one unused backup code. This confirms you can recover your account later.",'<form id="f"><label>Backup code<input id="code" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" maxlength="14" placeholder="ABCD-EFGH-IJKL" required></label><div class="hint">Example: ABCD-EFGH-IJKL</div><button class="primary">Check backup code</button></form>'+(backupCodes?'<button class="secondary" id="back">Show my codes again</button>':'<button class="secondary" id="manage">Manage backup codes</button>'));f.onsubmit=async e=>{e.preventDefault();try{await api("/api/recovery/verify","POST",{code:code.value.toUpperCase()});backupCodes=null;await refresh();log("SIMULATION: A backup code was checked and used once.");view=route();render()}catch(x){showError(x.message)}};if(backupCodes)back.onclick=()=>backupList(backupCodes);else manage.onclick=()=>{view="recoveryManage";render()}}
function success(){shell("5","MFA is ready","🎉","Your authenticator is connected and your backup codes are saved.",'<div class="notice success">Setup complete. You are in control of your account security.</div><button class="primary" id="finish">Finish securely</button>');finish.onclick=logout}
function help(){shell("Help","Help with MFA","💡","Use one step at a time. Nothing on this page moves or times your reading.",'<div class="notice">If a code does not work, request a new one or try again. A temporary pause after several incorrect entries protects your account.</div><button class="primary" id="return">Return to setup</button>');document.getElementById("return").onclick=async()=>{try{await refresh();view=route();render()}catch(x){showError(x.message)}}}
function route(){return !state||!state.loggedIn?"signin":!state.identityVerified?"identity":!state.mfaEnabled?(state.authenticatorSetupStarted?"authenticatorConfirm":"setup"):!state.recoveryGenerated?"backup":!state.recoveryConfirmed?(backupCodes?"recover":"recoveryManage"):"success"}
async function logout(){try{await api("/api/logout","POST")}catch(_){}csrf="";state=null;identityCode=null;lastSetup=null;backupCodes=null;visible=true;log("SIMULATION: You have been logged out securely.");boot()}
async function boot(){try{await refresh();view=route();render()}catch{app.textContent="We could not open secure setup. Please refresh this page."}}boot();
})();</script></body></html>`;
}

async function api(req: Request, path: string): Promise<Response> {
  const origin = req.headers.get("origin");
  if (origin && !origins.has(origin)) return fail("This request was not accepted. Please use this page directly.", 403);

  if (path === "/api/state" && req.method === "GET") {
    let s = current(req), setCookie: string | undefined;
    if (!s) { s = makeSession(); sessions.set(s.id, s); setCookie = sessionCookie(s.id); }
    const h = headers();
    if (setCookie) h.set("Set-Cookie", setCookie);
    return json(stateFor(s, s.userId ? accounts.get(s.userId) : undefined), 200, h);
  }

  if (path === "/api/login" && req.method === "POST") {
    const old = current(req);
    if (!old || !csrf(req, old)) return fail("Please refresh the page and try again.", 403);
    const b = await body(req);
    if (!b || !validEmail(b.email) || typeof b.password !== "string" || b.password.length > 256) return fail("We could not sign you in. Check your email and password, then try again.", 401);
    const id = b.email.trim().toLowerCase(), now = Date.now(), prior = loginFailures.get(id);
    if (prior && prior.lockedUntil > now) return fail("Too many sign-in attempts. Please wait a few minutes, then try again.", 429);
    if (id !== "marcus@example.com" || b.password !== "bank-demo") {
      const record = prior && prior.lockedUntil <= now ? { failures: prior.failures, lockedUntil: 0 } : (prior || { failures: 0, lockedUntil: 0 });
      record.failures++;
      if (record.failures >= MAX_FAILURES) { record.failures = 0; record.lockedUntil = now + LOCK; }
      loginFailures.set(id, record);
      return fail(record.lockedUntil > now ? "Too many sign-in attempts. Please wait a few minutes, then try again." : "We could not sign you in. Check your email and password, then try again.", record.lockedUntil > now ? 429 : 401);
    }
    loginFailures.delete(id);
    sessions.delete(old.id);
    const s = makeSession(); s.userId = "marcus-account"; sessions.set(s.id, s);
    const h = headers(); h.set("Set-Cookie", sessionCookie(s.id));
    return json(stateFor(s, accounts.get(s.userId)), 200, h);
  }

  if (path === "/api/logout" && req.method === "POST") {
    const s = current(req);
    if (!s || !csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    sessions.delete(s.id);
    const h = headers(); h.set("Set-Cookie", "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
    return json({ ok: true }, 200, h);
  }

  if (path === "/api/identity/send" && req.method === "POST") {
    const r = owner(req);
    if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    if (r.a.identityLockedUntil > Date.now()) return fail("Too many incorrect codes. Please wait a few minutes, then request a new code.", 429);
    r.s.identityChallenge = { hash: await hash(TEST_IDENTITY_OTP), expires: Date.now() + CODE_LIFE, used: false };
    return json({ ok: true, csrf: r.s.csrf, testCode: TEST_IDENTITY_OTP });
  }

  if (path === "/api/identity/verify" && req.method === "POST") {
    const r = owner(req);
    if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    const b = await body(req), c = r.s.identityChallenge;
    if (!b || !six(b.code)) return fail("Enter all 6 numbers from the email code.");
    if (r.a.identityLockedUntil > Date.now()) return fail("Too many incorrect codes. Please wait a few minutes, then request a new code.", 429);
    if (!c || c.used || Date.now() > c.expires) return fail("That code is no longer available. Send a new code and try again.");
    if (!same(await hash(b.code), c.hash)) {
      if (++r.a.identityFailures >= MAX_FAILURES) { r.a.identityFailures = 0; r.a.identityLockedUntil = Date.now() + LOCK; return fail("Too many incorrect codes. Please wait a few minutes, then request a new code.", 429); }
      return fail("That code does not match. Check the 6 numbers or send a new code.");
    }
    c.used = true; r.a.identityFailures = 0; r.s.identityVerified = true;
    return json(stateFor(r.s, r.a));
  }

  if (path === "/api/authenticator/setup" && req.method === "POST") {
    const r = verified(req);
    if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    if (r.a.authenticatorLockedUntil > Date.now()) return fail("Too many incorrect codes. Please wait a few minutes, then show setup options again.", 429);
    if (!r.a.encryptedOtpSecret) r.a.encryptedOtpSecret = await encrypt(TEST_SETUP_SECRET);
    r.a.authenticatorSetupStarted = true;
    r.s.authenticatorChallenge = { hash: await hash(TEST_AUTHENTICATOR_CODE), expires: Date.now() + CODE_LIFE, used: false };
    const uri = `otpauth://totp/Harbour:marcus?secret=${TEST_SETUP_SECRET}&issuer=Harbour`;
    return json({ ok: true, csrf: r.s.csrf, secret: TEST_SETUP_SECRET, uri, testCode: TEST_AUTHENTICATOR_CODE });
  }

  if (path === "/api/authenticator/confirm" && req.method === "POST") {
    const r = verified(req);
    if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    const b = await body(req), c = r.s.authenticatorChallenge;
    if (!b || !six(b.code)) return fail("Enter the 6-number authenticator code.");
    if (r.a.authenticatorLockedUntil > Date.now()) return fail("Too many incorrect codes. Please wait a few minutes, then show setup options again.", 429);
    if (!c || c.used || Date.now() > c.expires) return fail("Setup time has passed. Show setup options again and try the practice code.");
    if (!same(await hash(b.code), c.hash)) {
      if (++r.a.authenticatorFailures >= MAX_FAILURES) { r.a.authenticatorFailures = 0; r.a.authenticatorLockedUntil = Date.now() + LOCK; return fail("Too many incorrect codes. Please wait a few minutes, then show setup options again.", 429); }
      return fail("That code does not match the practice authenticator code. Check it and try again.");
    }
    c.used = true; r.a.authenticatorFailures = 0; r.a.mfaEnabled = true;
    return json(stateFor(r.s, r.a));
  }

  if (path === "/api/recovery/generate" && req.method === "POST") {
    const r = verified(req);
    if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    const b = await body(req);
    if (!r.a.mfaEnabled) return fail("Finish authenticator setup before creating backup codes.", 403);
    if (r.a.recoveryHashes.size && b?.confirmRegenerate !== true) return fail("Please confirm that you want to replace your current backup codes.");
    r.a.recoveryHashes = new Set(await Promise.all(TEST_RECOVERY_CODES.map(hash)));
    r.a.recoveryExpires = Date.now() + 365 * 24 * 60 * 60_000;
    r.a.recoveryFailures = 0; r.a.recoveryLockedUntil = 0;
    r.a.recoveryGenerated = true; r.a.recoveryConfirmed = false;
    return json({ ok: true, csrf: r.s.csrf, codes: TEST_RECOVERY_CODES });
  }

  if (path === "/api/recovery/verify" && req.method === "POST") {
    const r = verified(req);
    if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    const b = await body(req), a = r.a;
    if (!a.recoveryGenerated) return fail("Create backup codes before checking one.", 403);
    if (!b || !recovery(b.code)) return fail("Enter a backup code in this format: ABCD-EFGH-IJKL.");
    if (a.recoveryLockedUntil > Date.now()) return fail("Too many incorrect backup codes. Please wait a few minutes, then try again.", 429);
    if (!a.recoveryExpires || Date.now() > a.recoveryExpires) return fail("These backup codes have expired. Return to backup codes and generate a new set.");
    const candidate = await hash(b.code); let found: string | undefined;
    for (const saved of a.recoveryHashes) if (same(saved, candidate)) { found = saved; break; }
    if (!found) {
      if (++a.recoveryFailures >= MAX_FAILURES) { a.recoveryFailures = 0; a.recoveryLockedUntil = Date.now() + LOCK; return fail("Too many incorrect backup codes. Please wait a few minutes, then try again.", 429); }
      return fail("That backup code is not available. Check the code and try another saved code.");
    }
    a.recoveryHashes.delete(found); a.recoveryFailures = 0; a.recoveryConfirmed = true;
    return json(stateFor(r.s, a));
  }
  return fail("This secure page is not available.", 404);
}

serve({
  port: PORT,
  tls: { cert: file("certs/cert.pem"), key: file("certs/key.pem") },
  async fetch(req) {
    try {
      const url = new URL(req.url);
      if (url.protocol !== "https:") return fail("Please use the secure HTTPS address.", 403);
      if (url.pathname.startsWith("/api/")) return await api(req, url.pathname);
      if (url.pathname === "/" && req.method === "GET") {
        const nonce = randomText(18), h = headers(nonce);
        h.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers: h });
      }
      return fail("This secure page is not available.", 404);
    } catch {
      return fail("We could not complete that request. Please try again.", 500);
    }
  }
});
