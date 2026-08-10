
const encoder = new TextEncoder();
const PEPPER = bytesToBase64(randomBytes(32));
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt", "decrypt"]
);

type Session = { userId: string; csrf: string; createdAt: number; lastSeen: number };
type Verification = { hash: string; expiresAt: number; used: boolean };
type StoredCipher = { iv: string; data: string };
type UserState = {
  email: string;
  identityVerified: boolean;
  mfaEnabled: boolean;
  encryptedSeed?: StoredCipher;
  identityCheck?: Verification;
  identityFailures: number;
  identityLockedUntil: number;
  identityLastSent: number;
  authenticatorFailures: number;
  authenticatorLockedUntil: number;
  provisioningLastSent: number;
  usedTotpSteps: Set<number>;
  backupHashes: Set<string>;
};

const sessions = new Map<string, Session>();
const user: UserState = {
  email: "marcus@example.test",
  identityVerified: false,
  mfaEnabled: false,
  identityFailures: 0,
  identityLockedUntil: 0,
  identityLastSent: 0,
  authenticatorFailures: 0,
  authenticatorLockedUntil: 0,
  provisioningLastSent: 0,
  usedTotpSteps: new Set(),
  backupHashes: new Set(),
};

const IDLE_MS = 30 * 60 * 1000;
const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const VERIFY_MS = 30 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const ISSUE_MS = 20 * 1000;
const MAX_FAILURES = 5;
const DEMO_IDENTITY_CODE = "123456";
/* Deterministic test seed. It is still encrypted before server-side storage. */
const DEMO_SEED = "JBSWY3DPEHPK3PXP";

function randomBytes(length: number): Uint8Array {
  const values = new Uint8Array(length);
  crypto.getRandomValues(values);
  return values;
}
function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}
function base64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}
function randomToken(bytes = 32): string {
  return bytesToBase64(randomBytes(bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function randomBase32(length = 10): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const raw = randomBytes(length);
  return Array.from(raw, (v) => alphabet[v % alphabet.length]).join("");
}
function randomRecoveryCode(): string {
  const value = randomBase32(10);
  return value.slice(0, 5) + "-" + value.slice(5);
}
async function digest(value: string): Promise<string> {
  const output = await crypto.subtle.digest("SHA-256", encoder.encode(value + ":" + PEPPER));
  return bytesToBase64(new Uint8Array(output));
}
async function encryptSecret(secret: string): Promise<StoredCipher> {
  const iv = randomBytes(12);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, encoder.encode(secret));
  return { iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(data)) };
}
async function decryptSecret(stored: StoredCipher): Promise<string> {
  const data = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(stored.iv) },
    encryptionKey,
    base64ToBytes(stored.data)
  );
  return new TextDecoder().decode(data);
}
function base32Bytes(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let buffer = 0, bits = 0;
  const result: number[] = [];
  for (const character of value.replace(/=|\s/g, "").toUpperCase()) {
    const n = alphabet.indexOf(character);
    if (n < 0) throw new Error("invalid seed");
    buffer = (buffer << 5) | n;
    bits += 5;
    if (bits >= 8) {
      result.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(result);
}
/* Cryptographic failures / TOTP: RFC 6238 HMAC-SHA-1, 30 second time steps. */
async function totp(secret: string, step: number): Promise<string> {
  const counter = new Uint8Array(8);
  let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(n & 255n); n >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = mac[mac.length - 1] & 15;
  const number = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(number % 1000000).padStart(6, "0");
}
function cookieValue(request: Request, name: string): string | undefined {
  for (const item of (request.headers.get("cookie") || "").split(";")) {
    const part = item.trim();
    if (part.startsWith(name + "=")) return part.slice(name.length + 1);
  }
}
function sessionCookie(id: string): string {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE_MS / 1000)}`;
}
function expiredCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}
function baseHeaders(nonce?: string): Headers {
  const csp = nonce
    ? `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    : "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
  return new Headers({
    "Content-Security-Policy": csp,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  });
}
function responseJson(data: unknown, status = 200): Response {
  const headers = baseHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers });
}
function genericError(status = 400, message = "We could not complete that request. Please try again."): Response {
  return responseJson({ ok: false, message }, status);
}
function trustedOrigin(origin: string | null): boolean {
  if (!origin) return false;
  try {
    const u = new URL(origin);
    return u.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(u.hostname);
  } catch { return false; }
}
function addCors(request: Request, response: Response): Response {
  const origin = request.headers.get("origin");
  if (trustedOrigin(origin)) response.headers.set("Access-Control-Allow-Origin", origin!);
  response.headers.set("Vary", "Origin");
  response.headers.set("Access-Control-Allow-Credentials", "true");
  response.headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
  response.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  return response;
}
function authenticated(request: Request): Session | undefined {
  const id = cookieValue(request, "mfa_session");
  const session = id ? sessions.get(id) : undefined;
  const now = Date.now();
  if (!session || session.userId !== "account-owner" || now - session.lastSeen > IDLE_MS || now - session.createdAt > ABSOLUTE_MS) {
    if (id) sessions.delete(id);
    return;
  }
  session.lastSeen = now;
  return session;
}
function csrfOK(request: Request, session: Session): boolean {
  return trustedOrigin(request.headers.get("origin")) && request.headers.get("x-csrf-token") === session.csrf;
}
async function bodyJSON(request: Request): Promise<Record<string, unknown> | undefined> {
  if (!(request.headers.get("content-type") || "").includes("application/json")) return;
  const text = await request.text();
  if (text.length > 3000) return;
  try {
    const v = JSON.parse(text);
    return v && typeof v === "object" && !Array.isArray(v) ? v : undefined;
  } catch { return; }
}
function validEmail(v: unknown): v is string { return typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function validCode(v: unknown): v is string { return typeof v === "string" && /^\d{6}$/.test(v); }
function validRecovery(v: unknown): v is string { return typeof v === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(v); }
async function newVerification(code: string): Promise<Verification> {
  return { hash: await digest(code), expiresAt: Date.now() + VERIFY_MS, used: false };
}
async function createRecoveryCodes(): Promise<string[]> {
  const codes = Array.from({ length: 8 }, randomRecoveryCode);
  user.backupHashes = new Set(await Promise.all(codes.map(digest)));
  return codes;
}
function locked(until: number): boolean { return Date.now() < until; }
function failureMessage(kind: "identity" | "auth"): string {
  return kind === "identity"
    ? "Too many tries. Please wait 10 minutes before trying again."
    : "Too many authenticator tries. Please wait 10 minutes before trying again.";
}

/* Single-file client page. The nonce is inserted only in the response generated for this request. */
const page = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank · Security setup</title>
<style nonce="__NONCE__">
:root{--ink:#17243a;--muted:#536276;--blue:#075fc8;--line:#cbd6e3;--bad:#b42318;--good:#126b43}*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:var(--ink);font:17px/1.65 Arial,Verdana,Tahoma,sans-serif;letter-spacing:.025em}main{width:min(100%,620px);margin:auto;padding:18px 15px 42px}.brand{font-weight:bold;color:#064b9e;margin:5px 5px 18px}h1{font-size:1.55rem;line-height:1.3;margin:0 0 9px}p{margin:0 0 14px}.card{background:#fff;border:1px solid var(--line);border-radius:15px;padding:23px 19px;box-shadow:0 2px 8px #1935540d}.step{color:var(--blue);font-weight:bold;margin:0 0 12px}.icon{font-size:1.55rem;margin-right:8px}label{display:block;font-weight:bold;margin:18px 0 6px}input{width:100%;min-height:52px;border:2px solid #8ba0b8;border-radius:10px;padding:13px;font:inherit;letter-spacing:.05em}input:focus{outline:3px solid #8bc5ff;outline-offset:2px;border-color:var(--blue)}button{width:100%;min-height:53px;margin-top:16px;border:0;border-radius:10px;background:var(--blue);color:white;font:bold 1rem Arial,sans-serif;padding:12px;cursor:pointer}button.secondary{background:#fff;color:#064b9e;border:2px solid #1e70c7}button.small{width:auto;min-height:42px;margin:8px 8px 0 0;padding:7px 12px}.hint,details{color:var(--muted);font-size:.94rem}.notice{margin-top:16px;padding:12px;border-radius:9px;font-weight:bold}.error{background:#fff0ef;color:var(--bad);border-left:5px solid var(--bad)}.ok{background:#eaf8f0;color:var(--good);border-left:5px solid var(--good)}.secret{overflow-wrap:anywhere;background:#f5f8fc;border:1px dashed #7891ae;padding:12px;border-radius:8px;font-family:monospace;font-weight:bold}.qr{display:block;width:min(100%,280px);height:auto;margin:16px auto;border:7px solid white;image-rendering:pixelated}.code-list{list-style:none;padding:0}.code-list li{margin:8px 0;padding:8px 10px;background:#f5f8fc;font-family:monospace;font-weight:bold;border-radius:7px}.checkline{display:flex;gap:10px;align-items:flex-start}.checkline input{width:23px;min-height:23px;margin-top:5px}.status{padding:10px;background:#eef6ff;border-radius:9px}.log-panel{margin-top:22px;background:#14223a;color:#eaf4ff;border-radius:13px;padding:14px}.log-panel h2{font-size:1rem;margin:0 0 7px}#logs{margin:0;white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.55 monospace;max-height:180px;overflow:auto}summary{color:var(--blue);font-weight:bold;cursor:pointer}@media(max-width:370px){body{font-size:16px}.card{padding:18px 14px}}
</style></head><body><main><header><div class="brand">◆ Harbour Bank</div></header><section id="app" aria-live="polite"></section><section class="log-panel" aria-label="Mock delivery logs"><h2>Logs</h2><pre id="logs">Ready. Mock delivery messages will appear here.</pre></section></main>
<script nonce="__NONCE__">
(()=>{"use strict";
const app=document.querySelector("#app"),logs=document.querySelector("#logs");
const state={csrf:"",screen:"signin",identityCode:"",otp:"",secret:"",uri:"",codes:[],message:"",error:""};
const esc=v=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function log(m){console.log(m);logs.textContent=m+"\\n"+logs.textContent}
function msg(m,e=""){state.message=m;state.error=e}
function note(){return state.error?'<div class="notice error">'+esc(state.error)+"</div>":state.message?'<div class="notice ok">'+esc(state.message)+"</div>":""}
function help(t){return "<details><summary>Need help?</summary><p>"+esc(t)+"</p></details>"}
function shell(step,title,icon,text,inside,h){return '<article class="card"><p class="step">'+step+'</p><h1><span class="icon">'+icon+"</span>"+title+"</h1><p>"+text+"</p>"+inside+note()+help(h)+"</article>"}
async function api(path,data){let r;try{r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":state.csrf},body:JSON.stringify(data||{})})}catch{throw Error("Connection problem. Please try again.")}const j=await r.json().catch(()=>({message:"We could not complete that request."}));if(r.status===401){state.csrf="";state.screen="signin";render()}if(!r.ok)throw Error(j.message||"We could not complete that request.");return j}
async function copy(t,done){try{await navigator.clipboard.writeText(t);msg(done);render()}catch{msg("Copy was not available. You can select the text and copy it.");render()}}
/* Standards-compatible QR Code Model 2, version 5-L. Encodes the otpauth provisioning URI in byte mode. */
function qrSvg(text){
 const N=37,a=Array.from({length:N},()=>Array(N).fill(null)),set=(r,c,v)=>{if(r>=0&&c>=0&&r<N&&c<N)a[r][c]=v};
 function finder(r,c){for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)set(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(x==0||x==6||y==0||y==6||(x>=2&&x<=4&&y>=2&&y<=4)))}
 finder(0,0);finder(0,N-7);finder(N-7,0);
 for(let i=8;i<N-8;i++){set(6,i,i%2==0);set(i,6,i%2==0)}
 for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(30+y,30+x,Math.max(Math.abs(x),Math.abs(y))!=1);
 for(let i=0;i<9;i++){if(a[8][i]===null)set(8,i,false);if(a[i][8]===null)set(i,8,false);if(a[8][N-1-i]===null)set(8,N-1-i,false);if(a[N-1-i][8]===null)set(N-1-i,8,false)}set(N-8,8,true);
 const bytes=[...new TextEncoder().encode(text)];let bits=[0,1,0,0];for(let i=7;i>=0;i--)bits.push((bytes.length>>i)&1);bytes.forEach(b=>{for(let i=7;i>=0;i--)bits.push((b>>i)&1)});while(bits.length%8)bits.push(0);
 let data=[];for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8).join(""),2));for(let p=0;data.length<108;p++)data.push(p%2?0x11:0xec);
 const exp=[1],log=[0];for(let i=1;i<256;i++){exp[i]=exp[i-1]<<1;if(exp[i]&256)exp[i]^=285}for(let i=0;i<255;i++)log[exp[i]]=i;for(let i=255;i<512;i++)exp[i]=exp[i-255];
 let gen=[1];for(let i=0;i<26;i++){let g=Array(gen.length+1).fill(0);gen.forEach((v,j)=>{g[j]^=v;g[j+1]^=v?exp[log[v]+i]:0});gen=g}
 let rem=Array(26).fill(0);data.forEach(v=>{let f=v^rem.shift();rem.push(0);if(f)for(let j=0;j<26;j++)rem[j]^=exp[log[f]+log[gen[j+1]]]});let stream=data.concat(rem),k=0,up=true;
 for(let c=N-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<N;q++){let r=up?N-1-q:q;for(const x of [c,c-1])if(a[r][x]===null)a[r][x]=stream[k>>3]!==undefined?!!(stream[k>>3]&(1<<(7-(k&7)))):false,k++}up=!up}
 let best=null,score=1e9;
 for(let mask=0;mask<8;mask++){let m=a.map(row=>row.slice());for(let r=0;r<N;r++)for(let c=0;c<N;c++)if(a[r][c]!==null&&!(r<9&&c<9)&&!(r<9&&c>N-9)&&!(r>N-9&&c<9)&&r!==6&&c!==6&&!(r>=28&&c>=28)){let z=[(r+c)%2==0,r%2==0,c%3==0,(r+c)%3==0,(Math.floor(r/2)+Math.floor(c/3))%2==0,(r*c)%2+(r*c)%3==0,((r*c)%2+(r*c)%3)%2==0,((r+c)%2+(r*c)%3)%2==0][mask];if(z)m[r][c]=!m[r][c]}
 let d=(1<<3)|mask;let v=d<<10;while(v.toString(2).length>=11)v^=0x537<<(v.toString(2).length-11);let fmt=((d<<10)|v)^0x5412;
 for(let i=0;i<15;i++){let bit=!!(fmt>>i&1);if(i<6)m[i][8]=bit;else if(i<8)m[i+1][8]=bit;else m[N-15+i][8]=bit;if(i<8)m[8][N-i-1]=bit;else if(i<9)m[8][15-i]=bit;else m[8][15-i-1]=bit}
 let s=0;for(let r=0;r<N;r++)for(let c=0;c<N;c++){if(c&&c<N-1&&m[r][c]===m[r][c-1]&&m[r][c]===m[r][c+1])s++;if(r&&r<N-1&&m[r][c]===m[r-1][c]&&m[r][c]===m[r+1][c])s++}if(s<score){score=s;best=m}}
 let cells="";best.forEach((row,y)=>row.forEach((on,x)=>{if(on)cells+='<rect x="'+x+'" y="'+y+'" width="1" height="1"/>'}));return '<svg class="qr" viewBox="0 0 37 37" role="img" aria-label="QR code for authenticator setup" xmlns="http://www.w3.org/2000/svg"><rect width="37" height="37" fill="white"/><g fill="#17243a">'+cells+"</g></svg>"
}
function render(){let html="";
 if(state.screen==="signin")html=shell("Step 1 of 5","Sign in to start","👋","Use the email for your bank account.",'<form id="sign"><label>Email address<input id="email" type="email" autocomplete="username email" placeholder="name@example.com" required></label><p class="hint">Example: marcus@example.com</p><button>Continue</button></form>',"This demo accepts any correctly written email.");
 if(state.screen==="identity")html=shell("Step 2 of 5","Check it is you","✉️","We sent a 6-digit check code in this safe demo.",'<form id="ident"><label>Check code<input id="identity" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456" required></label><button>Check code</button></form><button class="secondary" id="fillI">Use demo code</button><button class="secondary" id="resend">Send a new code</button>',"Use the demo code to avoid typing. There is plenty of time.");
 if(state.screen==="setup")html=shell("Step 3 of 5","Add your authenticator","📱","Scan this QR code in your authenticator app. You can also copy the setup details.",qrSvg(state.uri)+'<p class="hint">Manual setup URI</p><div class="secret" id="uri"></div><button class="small secondary" id="copyUri">Copy setup URI</button><p class="hint">Manual secret</p><div class="secret" id="secret"></div><button class="small secondary" id="copySecret">Copy secret</button><button id="toOtp">I added the authenticator</button>',"The QR code, setup URI, and secret all set up the same authenticator.");
 if(state.screen==="otp")html=shell("Step 4 of 5","Confirm your authenticator","🔐","Enter the 6-digit code from your authenticator app.",'<form id="otpform"><label>Authenticator code<input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456" required></label><button>Confirm authenticator</button></form><button class="secondary" id="fillO">Use demo code</button><button class="secondary" id="restart">Request setup again</button>',"The demo code is shown in Logs. You can retry without penalty unless the safety limit is reached.");
 if(state.screen==="backup")html=shell("Step 5 of 5","Save your recovery codes","🧾","Keep these codes somewhere safe. Each works once if you lose your phone.",'<ul class="code-list">'+state.codes.map(x=>"<li>"+esc(x)+"</li>").join("")+'</ul><button class="small secondary" id="copyCodes">Copy all codes</button><label class="checkline"><input id="saved" type="checkbox"><span>I have saved my recovery codes.</span></label><button id="finish">Finish security setup</button>',"Copy the codes rather than typing them.");
 if(state.screen==="settings")html=shell("Security settings","MFA is ready","✅","Your authenticator and recovery codes are active.",'<div class="status">🛡️ <strong>Authenticator:</strong>&nbsp; active</div><label>Test a recovery code<input id="recovery" autocapitalize="characters" placeholder="Example: ABCDE-FGHIJ"></label><button id="test">Test recovery code</button><button class="secondary" id="regen">Make new recovery codes</button><button class="secondary" id="logout">Sign out</button>',"New recovery codes replace old ones.");
 app.innerHTML=html;if(state.screen==="setup"){document.querySelector("#uri").textContent=state.uri;document.querySelector("#secret").textContent=state.secret}bind()}
 async function provision(){const r=await api("/api/authenticator/provision");state.secret=r.secret;state.uri=r.uri;state.otp=r.mockCode;log("[Mock delivery] Authenticator test code: "+r.mockCode)}
 function bind(){const $=x=>document.querySelector(x);
 if(state.screen==="signin")$("#sign").onsubmit=async e=>{e.preventDefault();try{let r=await api("/api/signin",{email:$("#email").value});state.csrf=r.csrf;state.identityCode=r.mockCode;state.screen="identity";log("[Mock delivery] Identity check code: "+r.mockCode);render()}catch(e){msg("",e.message);render()}};
 if(state.screen==="identity"){$("#ident").onsubmit=async e=>{e.preventDefault();try{await api("/api/identity/verify",{code:$("#identity").value});await provision();state.screen="setup";render()}catch(e){msg("",e.message);render()}};$("#fillI").onclick=()=>{$("#identity").value=state.identityCode};$("#resend").onclick=async()=>{try{let r=await api("/api/identity/send");state.identityCode=r.mockCode;log("[Mock delivery] Identity check code: "+r.mockCode);msg("A demo code is ready in Logs.");render()}catch(e){msg("",e.message);render()}}}
 if(state.screen==="setup"){$("#copyUri").onclick=()=>copy(state.uri,"Setup URI copied.");$("#copySecret").onclick=()=>copy(state.secret,"Secret copied.");$("#toOtp").onclick=()=>{state.screen="otp";msg("Your next step is to confirm the 6-digit code.");render()}}
 if(state.screen==="otp"){$("#otpform").onsubmit=async e=>{e.preventDefault();try{let r=await api("/api/authenticator/verify",{code:$("#otp").value});state.codes=r.codes;log("[Mock delivery] Recovery codes: "+r.codes.join(", "));state.screen="backup";render()}catch(e){msg("",e.message);render()}};$("#fillO").onclick=()=>{$("#otp").value=state.otp};$("#restart").onclick=async()=>{try{await provision();state.screen="setup";render()}catch(e){msg("",e.message);render()}}}
 if(state.screen==="backup"){$("#copyCodes").onclick=()=>copy(state.codes.join("\\n"),"Recovery codes copied.");$("#finish").onclick=async()=>{if(!$("#saved").checked){msg("Please tick the box after you have saved the codes.");render();return}try{await api("/api/backup/confirm");state.codes=[];state.screen="settings";msg("Security setup is complete.");render()}catch(e){msg("",e.message);render()}}}
 if(state.screen==="settings"){$("#test").onclick=async()=>{try{await api("/api/recovery/verify",{code:$("#recovery").value.toUpperCase()});msg("That recovery code worked and is now used.");render()}catch(e){msg("",e.message);render()}};$("#regen").onclick=async()=>{try{let r=await api("/api/recovery/regenerate");state.codes=r.codes;log("[Mock delivery] New recovery codes: "+r.codes.join(", "));state.screen="backup";render()}catch(e){msg("",e.message);render()}};$("#logout").onclick=async()=>{await api("/api/logout");state.csrf="";state.screen="signin";msg("You have signed out.");render()}}}
 render()
})()
</script></body></html>`;

function htmlResponse(): Response {
  const nonce = randomToken(18);
  const headers = baseHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(page.replaceAll("__NONCE__", nonce), { headers });
}
function authResponse(request: Request, response: Response): Response { return addCors(request, response); }

async function route(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (request.method === "OPTIONS") {
    if (!trustedOrigin(request.headers.get("origin"))) return genericError(403, "Request not allowed.");
    return addCors(request, new Response(null, { status: 204, headers: baseHeaders() }));
  }
  if (url.pathname === "/" && request.method === "GET") return htmlResponse();
  if (!url.pathname.startsWith("/api/")) return genericError(404, "Page not found.");

  if (url.pathname === "/api/signin" && request.method === "POST") {
    const data = await bodyJSON(request);
    if (!data || !validEmail(data.email) || !trustedOrigin(request.headers.get("origin"))) return genericError(400, "Please enter an email address in the example format.");
    if (locked(user.identityLockedUntil)) return genericError(429, failureMessage("identity"));
    for (const [id, session] of sessions) if (session.userId === "account-owner") sessions.delete(id);
    const id = randomToken(), csrf = randomToken();
    sessions.set(id, { userId: "account-owner", csrf, createdAt: Date.now(), lastSeen: Date.now() });
    user.identityVerified = false;
    user.identityCheck = await newVerification(DEMO_IDENTITY_CODE);
    user.identityLastSent = Date.now();
    const response = responseJson({ ok: true, csrf, mockCode: DEMO_IDENTITY_CODE });
    response.headers.set("Set-Cookie", sessionCookie(id));
    return authResponse(request, response);
  }

  const session = authenticated(request);
  if (!session) {
    const response = genericError(401, "Please sign in again to continue.");
    response.headers.set("Set-Cookie", expiredCookie());
    return authResponse(request, response);
  }
  if (request.method !== "GET" && !csrfOK(request, session)) return authResponse(request, genericError(403, "Your secure form check did not match. Refresh and try again."));

  /* Identity failures and lockout persist independently from newly issued deterministic codes. */
  if (url.pathname === "/api/identity/send" && request.method === "POST") {
    if (locked(user.identityLockedUntil)) return authResponse(request, genericError(429, failureMessage("identity")));
    if (Date.now() - user.identityLastSent < ISSUE_MS) return authResponse(request, genericError(429, "Please wait a short moment before requesting another code."));
    user.identityCheck = await newVerification(DEMO_IDENTITY_CODE);
    user.identityLastSent = Date.now();
    return authResponse(request, responseJson({ ok: true, mockCode: DEMO_IDENTITY_CODE }));
  }
  if (url.pathname === "/api/identity/verify" && request.method === "POST") {
    const data = await bodyJSON(request);
    if (!data || !validCode(data.code)) return authResponse(request, genericError(400, "Enter exactly 6 numbers, for example 123456."));
    if (locked(user.identityLockedUntil)) return authResponse(request, genericError(429, failureMessage("identity")));
    const check = user.identityCheck;
    if (!check || check.used || Date.now() > check.expiresAt) return authResponse(request, genericError(400, "That code is no longer available. Request a new code and try again."));
    if ((await digest(data.code)) !== check.hash) {
      user.identityFailures++;
      if (user.identityFailures >= MAX_FAILURES) { user.identityLockedUntil = Date.now() + LOCK_MS; user.identityFailures = 0; }
      return authResponse(request, genericError(400, locked(user.identityLockedUntil) ? failureMessage("identity") : "That code does not match. Check the 6 numbers and try again."));
    }
    check.used = true;
    user.identityVerified = true;
    user.identityFailures = 0;
    return authResponse(request, responseJson({ ok: true }));
  }

  /* TOTP is verified server-side after decrypting the stored seed. Provisioning cannot clear failed-attempt protection. */
  if (url.pathname === "/api/authenticator/provision" && request.method === "POST") {
    if (!user.identityVerified) return authResponse(request, genericError(403, "Complete the identity check before setting up an authenticator."));
    if (locked(user.authenticatorLockedUntil)) return authResponse(request, genericError(429, failureMessage("auth")));
    if (user.encryptedSeed && Date.now() - user.provisioningLastSent < ISSUE_MS) return authResponse(request, genericError(429, "Please wait a short moment before requesting setup again."));
    user.encryptedSeed = await encryptSecret(DEMO_SEED);
    user.provisioningLastSent = Date.now();
    user.usedTotpSteps.clear();
    const step = Math.floor(Date.now() / 30000);
    const code = await totp(DEMO_SEED, step);
    const uri = "otpauth://totp/Harbour:Marcus?secret=" + DEMO_SEED + "&issuer=Harbour";
    return authResponse(request, responseJson({ ok: true, secret: DEMO_SEED, uri, mockCode: code }));
  }
  if (url.pathname === "/api/authenticator/verify" && request.method === "POST") {
    const data = await bodyJSON(request);
    if (!data || !validCode(data.code)) return authResponse(request, genericError(400, "Enter exactly 6 numbers, for example 123456."));
    if (locked(user.authenticatorLockedUntil)) return authResponse(request, genericError(429, failureMessage("auth")));
    if (!user.encryptedSeed) return authResponse(request, genericError(400, "Request authenticator setup before entering a code."));
    const secret = await decryptSecret(user.encryptedSeed);
    const current = Math.floor(Date.now() / 30000);
    let matched: number | undefined;
    for (const step of [current - 1, current, current + 1]) {
      if (!user.usedTotpSteps.has(step) && data.code === await totp(secret, step)) { matched = step; break; }
    }
    if (matched === undefined) {
      user.authenticatorFailures++;
      if (user.authenticatorFailures >= MAX_FAILURES) { user.authenticatorLockedUntil = Date.now() + LOCK_MS; user.authenticatorFailures = 0; }
      return authResponse(request, genericError(400, locked(user.authenticatorLockedUntil) ? failureMessage("auth") : "That code does not match. Check the 6 numbers and try again."));
    }
    user.usedTotpSteps.add(matched);
    user.authenticatorFailures = 0;
    user.mfaEnabled = true;
    const codes = await createRecoveryCodes();
    return authResponse(request, responseJson({ ok: true, codes }));
  }
  if (url.pathname === "/api/backup/confirm" && request.method === "POST") {
    if (!user.mfaEnabled) return authResponse(request, genericError(403, "Set up an authenticator first."));
    return authResponse(request, responseJson({ ok: true }));
  }
  if (url.pathname === "/api/recovery/regenerate" && request.method === "POST") {
    if (!user.mfaEnabled) return authResponse(request, genericError(403, "Set up an authenticator first."));
    return authResponse(request, responseJson({ ok: true, codes: await createRecoveryCodes() }));
  }
  if (url.pathname === "/api/recovery/verify" && request.method === "POST") {
    if (!user.mfaEnabled) return authResponse(request, genericError(403, "Set up an authenticator first."));
    const data = await bodyJSON(request);
    if (!data || !validRecovery(data.code)) return authResponse(request, genericError(400, "Enter a recovery code like ABCDE-FGHIJ."));
    const hashed = await digest(data.code);
    if (!user.backupHashes.has(hashed)) return authResponse(request, genericError(400, "That recovery code is not available. Check it or use another saved code."));
    user.backupHashes.delete(hashed);
    return authResponse(request, responseJson({ ok: true }));
  }
  if (url.pathname === "/api/logout" && request.method === "POST") {
    const id = cookieValue(request, "mfa_session");
    if (id) sessions.delete(id);
    const response = responseJson({ ok: true });
    response.headers.set("Set-Cookie", expiredCookie());
    return authResponse(request, response);
  }
  return authResponse(request, genericError(404, "Page not found."));
}

/* Security misconfiguration requirement: TLS uses supplied mkcert files. */
Bun.serve({
  port: 3000,
  hostname: "0.0.0.0",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try { return await route(request); }
    catch { return genericError(500, "We could not complete that request. Please try again."); }
  },
});
console.log("MFA enrolment server ready at https://localhost:3000");
