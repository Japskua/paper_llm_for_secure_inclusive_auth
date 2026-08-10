
/*
 MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.
 Run with: bun app.ts
 TLS certificates: certs/cert.pem and certs/key.pem
*/
const encoder = new TextEncoder();
const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();

const SESSION_IDLE = 30 * 60_000;
const SESSION_ABSOLUTE = 8 * 60 * 60_000;
const MAX_FAILURES = 5;
const LOCKOUT = 5 * 60_000;
const TOTP_PERIOD = 30;
const TOTP_SKEW = 1;

const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const recoveryKey = crypto.getRandomValues(new Uint8Array(32));

type Encrypted = { iv: string; ciphertext: string };
type Session = { userId: string; csrf: string; createdAt: number; lastSeenAt: number };
type Account = {
  id: string; email: string; passwordHash: string; mfaEnabled: boolean;
  encryptedSecret?: Encrypted; pendingEncryptedSecret?: Encrypted;
  pendingUsedCounters: number[]; usedCounters: number[];
  reenrolmentStarted: boolean; otpFailures: number; otpLockedUntil: number;
  recoveryFailures: number; recoveryLockedUntil: number; backupCodeHashes: string[];
};

function sha256(value: string) { return Bun.CryptoHasher.hash("sha256", value, "hex"); }
function randomToken(bytes = 32) { return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url"); }
function equal(a: string, b: string) {
  const aa = encoder.encode(a), bb = encoder.encode(b);
  let d = aa.length ^ bb.length, n = Math.max(aa.length, bb.length);
  for (let i = 0; i < n; i++) d |= (aa[i % (aa.length || 1)] || 0) ^ (bb[i % (bb.length || 1)] || 0);
  return d === 0;
}
async function keyedHash(value: string, key: Uint8Array) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return Buffer.from(await crypto.subtle.sign("HMAC", k, encoder.encode(value))).toString("hex");
}
async function encrypt(value: string): Promise<Encrypted> {
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const text = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return { iv: Buffer.from(iv).toString("base64url"), ciphertext: Buffer.from(text).toString("base64url") };
}
async function decrypt(value: Encrypted) {
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
  const text = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(value.iv, "base64url") }, key, Buffer.from(value.ciphertext, "base64url"));
  return new TextDecoder().decode(text);
}
function makeSecret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "";
  while (result.length < 32) for (const b of crypto.getRandomValues(new Uint8Array(32))) {
    if (b < 248) result += alphabet[b % 32];
    if (result.length === 32) return result;
  }
  return result;
}
function makeRecoveryCodes() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", codes = new Set<string>();
  while (codes.size < 10) {
    let code = "";
    while (code.length < 10) for (const b of crypto.getRandomValues(new Uint8Array(24))) {
      if (b < 252) code += alphabet[b % 36];
      if (code.length === 10) break;
    }
    codes.add(code.slice(0, 5) + "-" + code.slice(5));
  }
  return [...codes];
}

/* RFC 6238 TOTP: Base32 secret, HMAC-SHA1, six digits, 30-second moving factor. */
function base32Bytes(secret: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = secret.toUpperCase().replace(/=|\s/g, "");
  let bits = 0, count = 0; const output: number[] = [];
  for (const char of clean) {
    const value = alphabet.indexOf(char);
    if (value < 0) throw new Error("Invalid Base32");
    bits = (bits << 5) | value; count += 5;
    while (count >= 8) { count -= 8; output.push((bits >>> count) & 255); }
  }
  return new Uint8Array(output);
}
async function totp(secret: string, counter: number) {
  const data = new Uint8Array(8);
  let n = BigInt(counter);
  for (let i = 7; i >= 0; i--) { data[i] = Number(n & 255n); n >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  const offset = digest[19] & 15;
  const value = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
function currentCounter(now = Date.now()) { return Math.floor(now / 1000 / TOTP_PERIOD); }

accounts.set("marcus-account-001", {
  id: "marcus-account-001", email: "marcus@example.com", passwordHash: sha256("BankDemo!42"),
  mfaEnabled: false, pendingUsedCounters: [], usedCounters: [], reenrolmentStarted: false,
  otpFailures: 0, otpLockedUntil: 0, recoveryFailures: 0, recoveryLockedUntil: 0, backupCodeHashes: [],
});
const dummyPasswordHash = sha256("not-a-real-account-password");

function parseCookies(request: Request) {
  const out: Record<string, string> = {};
  for (const item of (request.headers.get("cookie") || "").split(";")) {
    const i = item.indexOf("="); if (i > 0) out[item.slice(0, i).trim()] = item.slice(i + 1).trim();
  }
  return out;
}
function trustedHost(host: string) { return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]"; }
function sameSecureOrigin(request: Request) {
  const url = new URL(request.url);
  return url.protocol === "https:" && trustedHost(url.hostname) && request.headers.get("origin") === url.origin;
}
/* Security misconfiguration requirements: restrictive CSP, HSTS, no framing, no sniffing, same-origin CORS. */
function secureHeaders(request: Request, nonce = "") {
  const h = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Cache-Control": "no-store",
  });
  const url = new URL(request.url), origin = request.headers.get("origin");
  if (origin === url.origin && trustedHost(url.hostname)) {
    h.set("Access-Control-Allow-Origin", origin); h.set("Access-Control-Allow-Credentials", "true"); h.set("Vary", "Origin");
  }
  return h;
}
function respond(request: Request, body: unknown, status = 200, extra?: HeadersInit) {
  const h = secureHeaders(request); h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((v, k) => h.set(k, v));
  return new Response(JSON.stringify(body), { status, headers: h });
}
async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  if (!(request.headers.get("content-type") || "").includes("application/json")) return null;
  try { const v = await request.json(); return v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : null; } catch { return null; }
}
function getSession(request: Request): { id: string; session: Session; account: Account } | null {
  const id = parseCookies(request).mfa_session, now = Date.now();
  if (!id || !/^[A-Za-z0-9_-]{30,}$/.test(id)) return null;
  const session = sessions.get(id);
  if (!session || now - session.lastSeenAt > SESSION_IDLE || now - session.createdAt > SESSION_ABSOLUTE) { sessions.delete(id); return null; }
  const account = accounts.get(session.userId);
  if (!account) { sessions.delete(id); return null; }
  session.lastSeenAt = now; return { id, session, account };
}
function requireOwner(request: Request): { id: string; session: Session; account: Account } | Response {
  return getSession(request) || respond(request, { ok: false, message: "Please sign in again to continue." }, 401);
}
function validCsrf(request: Request, session: Session) { return sameSecureOrigin(request) && request.headers.get("x-csrf-token") === session.csrf; }
function newSession(userId: string) {
  const id = randomToken(), session = { userId, csrf: randomToken(24), createdAt: Date.now(), lastSeenAt: Date.now() };
  sessions.set(id, session); return { id, session };
}
function sessionCookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE / 1000}`; }
function validEmail(v: unknown): v is string { return typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function validPassword(v: unknown): v is string { return typeof v === "string" && v.length >= 8 && v.length <= 128; }
function validOtp(v: unknown): v is string { return typeof v === "string" && /^\d{6}$/.test(v); }
function validRecovery(v: unknown): v is string { return typeof v === "string" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/i.test(v); }
function lockedMessage() { return "Too many attempts were made. Please wait a few minutes, then try again."; }

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank · Security setup</title><style nonce="${nonce}">
:root{--ink:#172331;--muted:#526273;--blue:#1259b5;--line:#cbd8e6;--soft:#edf5ff;--good:#156d43;--bad:#992b2b}*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:16px;line-height:1.65;letter-spacing:.025em}main{width:min(100%,620px);min-height:100vh;margin:auto;padding:18px 16px 38px}header{display:flex;align-items:center;gap:11px;margin:4px 0 18px}.mark{width:40px;height:40px;display:grid;place-items:center;border-radius:12px;background:var(--blue);color:white;font-size:22px}h1,h2,h3{line-height:1.3;margin:0 0 12px}h1{font-size:1.38rem}h2{font-size:1.34rem}h3{font-size:1rem}p{margin:0 0 15px}.sub,.example{color:var(--muted);font-size:.87rem}.sub{margin:0}.lead{font-size:1.05rem}.steps{display:flex;gap:5px;margin:18px 0}.step{flex:1;padding:6px 2px;text-align:center;border-bottom:4px solid var(--line);font-size:.72rem;color:#607080}.step.active{color:#083d82;border-color:var(--blue);font-weight:bold}.card{background:white;border:1px solid var(--line);border-radius:16px;padding:22px 18px;box-shadow:0 2px 7px #193c5c0b}label{display:block;margin:16px 0 6px;font-weight:bold}input{width:100%;min-height:52px;padding:11px 13px;border:2px solid #9eafc0;border-radius:10px;font:inherit;letter-spacing:.06em}input:focus,button:focus,summary:focus{outline:3px solid #e3a927;outline-offset:2px}button{width:100%;min-height:53px;padding:11px 15px;border:0;border-radius:10px;cursor:pointer;font:700 1rem/1.35 Verdana,Arial,sans-serif}button:disabled{opacity:.55}.primary{margin-top:22px;background:var(--blue);color:white}.secondary{margin-top:11px;background:white;color:#083d82;border:2px solid var(--blue)}.small{width:auto;min-height:42px;padding:7px 12px;font-size:.88rem}.notice{margin:15px 0;padding:12px 13px;border-radius:10px;font-weight:bold}.good{color:#0e5533;background:#e5f6eb;border-left:5px solid var(--good)}.bad{color:#782222;background:#fff0f0;border-left:5px solid var(--bad)}.info{color:#164a84;background:var(--soft);border-left:5px solid var(--blue)}.secret{overflow-wrap:anywhere;padding:12px;border:1px solid var(--line);border-radius:9px;background:#f4f8fc;font-family:ui-monospace,Consolas,monospace;letter-spacing:.06em;line-height:1.8}.row{display:flex;flex-wrap:wrap;gap:9px;margin-top:10px}.row button{flex:1;min-width:130px}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:14px 0}.code{padding:9px 6px;border-radius:7px;background:#f4f8fc;text-align:center;font-family:ui-monospace,Consolas,monospace;font-weight:bold}.hidden{padding:16px;border-radius:8px;background:#f4f8fc;color:var(--muted);text-align:center}.qr{width:250px;height:250px;margin:16px auto;padding:8px;border:1px solid var(--line);border-radius:8px;background:white}.qr svg{display:block;width:100%;height:100%;image-rendering:pixelated}.feedback{min-height:1.7em;margin-top:12px;color:#164a84;font-weight:bold}details{margin-top:17px;padding-top:12px;border-top:1px solid var(--line)}summary{cursor:pointer;color:#083d82;font-weight:bold}.footer{margin-top:18px;text-align:center;color:var(--muted);font-size:.82rem}@media(max-width:390px){main{padding:12px 11px 28px}.card{padding:18px 14px}.step{font-size:.65rem}.codes{grid-template-columns:1fr}}
</style></head><body><main><header><div class="mark" aria-hidden="true">✦</div><div><h1>Northstar Bank</h1><p class="sub">Security setup</p></div></header><nav class="steps" aria-label="Setup progress"><div class="step" data-step="1">1. Confirm</div><div class="step" data-step="2">2. App</div><div class="step" data-step="3">3. Check</div><div class="step" data-step="4">4. Save</div></nav><section id="app" class="card" aria-live="polite">Loading secure setup…</section><footer class="footer">Take your time. There is no reading timer.</footer></main>
<script nonce="${nonce}">"use strict";
const appEl=document.getElementById("app");let csrfToken="",setupSecret="",setupUri="",recoveryCodes=[],secretsVisible=true,codesVisible=true;
function byId(id){return document.getElementById(id)}function escapeHtml(v){const e=document.createElement("span");e.textContent=String(v);return e.innerHTML}function setStep(n){document.querySelectorAll("[data-step]").forEach(e=>e.classList.toggle("active",Number(e.dataset.step)===n))}function notice(t,c){return '<div class="notice '+c+'">'+escapeHtml(t)+'</div>'}function help(){return '<details><summary>Help with this step</summary><p>You can pause and return later. You can retry safely. There is no reading timer.</p></details>'}function message(t){const e=byId("feedback");if(e)e.textContent=t}
async function api(path,data){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify(data||{})}),d=await r.json().catch(()=>({ok:false,message:"Something went wrong. Please try again."}));if(r.status===401){csrfToken="";signInPage("Your secure session ended. Please sign in again.")}return{response:r,result:d}}
async function copyText(value,label){try{await navigator.clipboard.writeText(value);message(label+" copied. Next, save it somewhere safe.")}catch{message(label+" could not be copied. Select it on this secure page and try again.")}}
/* Standards-compliant QR Version 10-L encoder. It encodes the exact otpauth URI in byte mode. */
function qr(uri){const v=10,n=57,data=[],bytes=new TextEncoder().encode(uri);if(bytes.length>271)return;function bits(x,c){for(let i=c-1;i>=0;i--)data.push((x>>>i)&1)}bits(4,4);bits(bytes.length,16);bytes.forEach(x=>bits(x,8));for(let i=0;i<Math.min(4,2192-data.length);i++)data.push(0);while(data.length%8)data.push(0);let raw=[];for(let i=0;i<data.length;i+=8)raw.push(data.slice(i,i+8).reduce((a,b)=>a*2+b,0));for(let p=0;raw.length<274;p++)raw.push(p%2?17:236);
const exp=[1],log=Array(256).fill(0);for(let i=1,x=1;i<256;i++){exp[i]=x;log[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;let gen=[1];for(let i=0;i<18;i++){let g=Array(gen.length+1).fill(0);gen.forEach((x,j)=>{g[j]^=x;g[j+1]^=mul(x,exp[i])});gen=g}function ecc(block){let r=Array(18).fill(0);block.forEach(x=>{let f=x^r.shift();r.push(0);gen.slice(1).forEach((g,i)=>r[i]^=mul(g,f))});return r}const blocks=[raw.slice(0,68),raw.slice(68,137),raw.slice(137,206),raw.slice(206)],ec=blocks.map(ecc),stream=[];for(let i=0;i<69;i++)blocks.forEach(b=>{if(i<b.length)stream.push(b[i])});for(let i=0;i<18;i++)ec.forEach(b=>stream.push(b[i]));const m=Array.from({length:n},()=>Array(n).fill(0)),used=Array.from({length:n},()=>Array(n).fill(false));const put=(x,y,z)=>{m[y][x]=z;used[y][x]=true};function finder(x,y){for(let j=-1;j<=7;j++)for(let i=-1;i<=7;i++)if(x+i>=0&&y+j>=0&&x+i<n&&y+j<n)put(x+i,y+j,i>=0&&i<=6&&j>=0&&j<=6&&(i===0||i===6||j===0||j===6||(i>=2&&i<=4&&j>=2&&j<=4))?1:0)}finder(0,0);finder(n-7,0);finder(0,n-7);for(let i=8;i<n-8;i++){if(!used[6][i])put(i,6,i%2===0);if(!used[i][6])put(6,i,i%2===0)}[6,28,50].forEach(y=>[6,28,50].forEach(x=>{if(used[y][x])return;for(let j=-2;j<=2;j++)for(let i=-2;i<=2;i++)put(x+i,y+j,Math.max(Math.abs(i),Math.abs(j))!==1?1:0)}));put(8,n-8,1);for(let i=0;i<9;i++){if(!used[8][i])put(i,8,0);if(!used[i][8])put(8,i,0)}for(let i=0;i<8;i++){put(n-1-i,8,0);put(8,n-1-i,0)}for(let i=0;i<6;i++)for(let j=0;j<3;j++){put(n-11+j,i,0);put(i,n-11+j,0)}let rem=v<<12;for(let i=17;i>=12;i--)if(rem&(1<<i))rem^=0x1f25;let ver=(v<<12)|rem;for(let i=0;i<18;i++){let z=(ver>>>i)&1,a=n-11+i%3,b=Math.floor(i/3);put(a,b,z);put(b,a,z)}let bi=0,up=true;for(let x=n-1;x>0;x-=2){if(x===6)x--;for(let q=0;q<n;q++){let y=up?n-1-q:q;for(let dx=0;dx<2;dx++)if(!used[y][x-dx]){let z=bi<stream.length?((stream[bi>>>3]>>>(7-(bi&7)))&1):0;bi++;if((x-dx+y)%2===0)z^=1;put(x-dx,y,z)}}up=!up}let f=1<<3;for(let i=0;i<10;i++)if(f&(1<<i))f^=0x537;f=((1<<3)|f)^0x5412;for(let i=0;i<=5;i++)put(8,i,(f>>>i)&1);put(8,7,(f>>>6)&1);put(8,8,(f>>>7)&1);put(7,8,(f>>>8)&1);for(let i=9;i<15;i++)put(14-i,8,(f>>>i)&1);for(let i=0;i<8;i++)put(n-1-i,8,(f>>>i)&1);for(let i=8;i<15;i++)put(8,n-15+i,(f>>>i)&1);let path="";for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(m[y][x])path+="M"+x+" "+y+"h1v1h-1z";const box=byId("qrCode");box.innerHTML='<svg viewBox="0 0 '+n+" "+n+'" role="img" aria-label="QR code for your authenticator app"><rect width="100%" height="100%" fill="white"/><path d="'+path+'" fill="black"/></svg>'}
function signInPage(info){setStep(1);appEl.innerHTML='<h2>Confirm your account</h2><p class="lead">Use your bank email and password.</p>'+notice("Demo sign-in: marcus@example.com · password: BankDemo!42","info")+(info?notice(info,"info"):"")+'<label for="emailInput">Email address</label><input id="emailInput" type="email" autocomplete="email" placeholder="marcus@example.com"><p class="example">Example: marcus@example.com</p><label for="passwordInput">Password</label><input id="passwordInput" type="password" autocomplete="current-password"><button class="primary" id="signInButton">Continue</button>'+help();byId("signInButton").onclick=async()=>{const b=byId("signInButton"),r=await fetch("/api/signin",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:byId("emailInput").value,password:byId("passwordInput").value})}),d=await r.json().catch(()=>({ok:false,message:"Please try again."}));if(!r.ok||!d.ok){appEl.insertAdjacentHTML("afterbegin",notice(d.message,"bad"));return}csrfToken=d.csrf;d.mfaEnabled?accountPage("You are signed in. Your authenticator is connected."):setupPage("Your identity is confirmed. Next, add your authenticator app.")}}
function setupPage(info){setStep(2);appEl.innerHTML='<h2>Add your authenticator app</h2><p class="lead">Open an authenticator app. You can scan a setup image or copy a secret.</p>'+(info?notice(info,"good"):"")+'<button class="primary" id="showSetupButton">Show secure setup</button>'+help();byId("showSetupButton").onclick=()=>requestProvision()}
async function requestProvision(){const a=await api("/api/provision",{});if(!a.response.ok){appEl.insertAdjacentHTML("afterbegin",notice(a.result.message,"bad"));return}setupSecret=a.result.secret;setupUri=a.result.uri;console.log("Mock TOTP test value:",a.result.verificationCode);provisionPage(a.result.message)}
function provisionPage(info){setStep(2);appEl.innerHTML='<h2>Your setup is ready</h2>'+notice(info,"good")+'<p>Scan this QR code in your authenticator app. If scanning is difficult, use the secret below.</p><div class="qr" id="qrCode"></div><h3>Manual secret</h3><div class="secret" id="secretText">'+escapeHtml(setupSecret)+'</div><div class="row"><button class="secondary small" id="copySecretButton">Copy secret</button><button class="secondary small" id="hideSecretButton">Hide secret</button></div><details><summary>Show full setup link</summary><p class="example">This is the same secure setup information as the QR code.</p><div class="secret" id="uriText">'+escapeHtml(setupUri)+'</div><button class="secondary small" id="copyUriButton">Copy setup link</button></details><button class="primary" id="verifyPageButton">I added it to my app</button><button class="secondary" id="newSetupButton">Request a new setup</button><div id="feedback" class="feedback" role="status"></div>'+help();qr(setupUri);byId("copySecretButton").onclick=()=>copyText(setupSecret,"Authenticator secret");byId("copyUriButton").onclick=()=>copyText(setupUri,"Setup link");byId("hideSecretButton").onclick=()=>{secretsVisible=!secretsVisible;byId("secretText").textContent=secretsVisible?setupSecret:"Secret hidden";byId("hideSecretButton").textContent=secretsVisible?"Hide secret":"Show secret"};byId("verifyPageButton").onclick=()=>verifyPage("");byId("newSetupButton").onclick=()=>requestProvision()}
function verifyPage(info){setStep(3);appEl.innerHTML='<h2>Check your app</h2><p class="lead">Enter the six numbers shown in your authenticator app.</p>'+(info?notice(info,"info"):"")+'<label for="otpInput">Six-digit code</label><input id="otpInput" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><p class="example">Example: 123456. You have plenty of time.</p><button class="primary" id="verifyButton">Verify code</button><button class="secondary" id="backSetupButton">Go back to setup</button>'+help();byId("verifyButton").onclick=async()=>{const a=await api("/api/verify-otp",{otp:byId("otpInput").value.trim()});if(!a.response.ok){appEl.insertAdjacentHTML("afterbegin",notice(a.result.message,"bad"));return}recoveryCodes=a.result.codes;console.log("Mock recovery codes:",recoveryCodes);codesPage("Your authenticator is now connected.")};byId("backSetupButton").onclick=()=>provisionPage("You can view setup details again.")}
function renderedCodes(){return codesVisible?'<div class="codes">'+recoveryCodes.map(c=>'<div class="code">'+escapeHtml(c)+'</div>').join("")+'</div>':'<div class="hidden">Recovery codes are hidden.</div>'}
function codesPage(info){setStep(4);appEl.innerHTML='<h2>Save your recovery codes</h2>'+notice(info,"good")+'<p class="lead">These codes help if you lose your phone. Store them somewhere safe. Each code works once.</p><div id="codesArea">'+renderedCodes()+'</div><div class="row"><button class="secondary small" id="toggleCodesButton">'+(codesVisible?"Hide recovery codes":"Show recovery codes")+'</button><button class="secondary small" id="copyCodesButton">Copy all recovery codes</button></div><div id="feedback" class="feedback" role="status"></div><button class="primary" id="finishButton">I saved my codes</button>'+help();byId("toggleCodesButton").onclick=()=>{codesVisible=!codesVisible;byId("codesArea").innerHTML=renderedCodes();byId("toggleCodesButton").textContent=codesVisible?"Hide recovery codes":"Show recovery codes"};byId("copyCodesButton").onclick=()=>copyText(recoveryCodes.join("\\n"),"Recovery codes");byId("finishButton").onclick=()=>accountPage("Your recovery codes are saved.")}
function accountPage(info){setStep(4);appEl.innerHTML='<h2>Security setup</h2>'+notice(info,"good")+'<p class="lead">Your authenticator is active.</p><button class="primary" id="replaceButton">Replace authenticator</button><button class="secondary" id="recoveryButton">Use a recovery code</button><button class="secondary" id="regenerateButton">Generate new recovery codes</button><button class="secondary" id="logoutButton">Sign out</button>'+help();byId("replaceButton").onclick=async()=>{const a=await api("/api/begin-reenrolment",{});a.response.ok?setupPage("Replacement started. Your current authenticator remains active until the replacement is verified."):appEl.insertAdjacentHTML("afterbegin",notice(a.result.message,"bad"))};byId("recoveryButton").onclick=()=>recoveryPage("");byId("regenerateButton").onclick=regenerateCodes;byId("logoutButton").onclick=signOut}
function recoveryPage(info){setStep(4);appEl.innerHTML='<h2>Use a recovery code</h2><p class="lead">Use one saved code if you cannot use your authenticator app.</p>'+(info?notice(info,"info"):"")+'<label for="recoveryInput">Recovery code</label><input id="recoveryInput" type="text" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" maxlength="11" placeholder="ABCDE-12345"><p class="example">Example: ABCDE-12345. Each code works once.</p><button class="primary" id="verifyRecoveryButton">Verify recovery code</button><button class="secondary" id="backAccountButton">Back to security setup</button>'+help();byId("verifyRecoveryButton").onclick=async()=>{const a=await api("/api/verify-recovery-code",{recoveryCode:byId("recoveryInput").value.trim().toUpperCase()});a.response.ok?accountPage("Recovery code accepted. That code has now been used and cannot be used again."):appEl.insertAdjacentHTML("afterbegin",notice(a.result.message,"bad"))};byId("backAccountButton").onclick=()=>accountPage("")}
async function regenerateCodes(){const a=await api("/api/regenerate-backup-codes",{});if(!a.response.ok){appEl.insertAdjacentHTML("afterbegin",notice(a.result.message,"bad"));return}recoveryCodes=a.result.codes;codesVisible=true;console.log("Mock recovery codes:",recoveryCodes);codesPage("New recovery codes have replaced the old ones.")}
async function signOut(){await api("/api/logout",{});csrfToken="";setupSecret="";setupUri="";recoveryCodes=[];signInPage("You have signed out safely.")}signInPage("");
</script></body></html>`;
}

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.protocol !== "https:" || !trustedHost(url.hostname)) return new Response("Not found", { status: 404, headers: secureHeaders(request) });
  if (request.method === "GET" && url.pathname === "/") {
    const nonce = randomToken(18), h = secureHeaders(request, nonce); h.set("Content-Type", "text/html; charset=utf-8");
    return new Response(page(nonce), { headers: h });
  }
  if (request.method === "OPTIONS") {
    if (!sameSecureOrigin(request)) return new Response(null, { status: 403, headers: secureHeaders(request) });
    const h = secureHeaders(request); h.set("Access-Control-Allow-Methods", "POST"); h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return new Response(null, { status: 204, headers: h });
  }
  if (request.method === "POST" && url.pathname === "/api/signin") {
    if (!sameSecureOrigin(request)) return respond(request, { ok: false, message: "Please use the secure sign-in page." }, 403);
    const data = await readBody(request), email = typeof data?.email === "string" ? data.email.toLowerCase().trim() : "", password = data?.password;
    const account = [...accounts.values()].find(a => a.email === email);
    const match = equal(sha256(typeof password === "string" ? password : ""), account ? account.passwordHash : dummyPasswordHash);
    if (!data || !validEmail(email) || !validPassword(password) || !account || !match) return respond(request, { ok: false, message: "Sign-in could not be completed. Check your email and password, then try again." }, 401);
    for (const [id, s] of sessions) if (s.userId === account.id) sessions.delete(id);
    const created = newSession(account.id);
    return respond(request, { ok: true, csrf: created.session.csrf, mfaEnabled: account.mfaEnabled }, 200, { "Set-Cookie": sessionCookie(created.id) });
  }
  if (request.method === "POST" && url.pathname === "/api/logout") {
    const owner = requireOwner(request); if (owner instanceof Response) return owner;
    if (!validCsrf(request, owner.session)) return respond(request, { ok: false, message: "Please refresh the secure page and try again." }, 403);
    sessions.delete(owner.id); return respond(request, { ok: true }, 200, { "Set-Cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }
  const owner = requireOwner(request);
  if (owner instanceof Response) return owner;
  if (request.method !== "POST" || !validCsrf(request, owner.session)) return respond(request, { ok: false, message: "Please refresh the secure page and try again." }, 403);
  const account = owner.account;
  if (url.pathname === "/api/begin-reenrolment") {
    if (!account.mfaEnabled || !account.encryptedSecret) return respond(request, { ok: false, message: "Finish authenticator setup before replacing it." }, 400);
    account.reenrolmentStarted = true; return respond(request, { ok: true });
  }
  if (url.pathname === "/api/provision") {
    if (account.mfaEnabled && !account.reenrolmentStarted) return respond(request, { ok: false, message: "Choose “Replace authenticator” first. Your current authenticator stays active until the new one is checked." }, 400);
    const secret = makeSecret();
    account.pendingEncryptedSecret = await encrypt(secret); account.pendingUsedCounters = [];
    const uri = "otpauth://totp/" + encodeURIComponent("Northstar Bank:" + account.email) + "?secret=" + secret + "&issuer=Northstar%20Bank&algorithm=SHA1&digits=6&period=30";
    /* Mock-only response permits browser console testing; it is never displayed in page logs. */
    return respond(request, { ok: true, secret, uri, verificationCode: await totp(secret, currentCounter()), message: account.mfaEnabled ? "Your replacement setup is ready. Your current authenticator still works until this new one is verified." : "Authenticator setup is ready. Add the secret, then enter the six-digit code." });
  }
  if (url.pathname === "/api/verify-otp") {
    const data = await readBody(request), now = Date.now();
    if (account.otpLockedUntil && account.otpLockedUntil <= now) { account.otpLockedUntil = 0; account.otpFailures = 0; }
    if (!data || !validOtp(data.otp)) return respond(request, { ok: false, message: "Enter exactly six numbers, for example 123456." }, 400);
    if (account.otpLockedUntil > now) return respond(request, { ok: false, message: lockedMessage() }, 429);
    if (!account.pendingEncryptedSecret) return respond(request, { ok: false, message: "Request a new setup and try again." }, 400);
    const secret = await decrypt(account.pendingEncryptedSecret), base = currentCounter(now);
    let accepted = -1;
    for (let c = base - TOTP_SKEW; c <= base + TOTP_SKEW; c++) {
      if (c >= 0 && !account.pendingUsedCounters.includes(c) && equal(await totp(secret, c), data.otp)) { accepted = c; break; }
    }
    if (accepted < 0) {
      account.otpFailures++; if (account.otpFailures >= MAX_FAILURES) account.otpLockedUntil = now + LOCKOUT;
      return respond(request, { ok: false, message: account.otpFailures >= MAX_FAILURES ? lockedMessage() : "That code did not match, has already been used, or is no longer current. Check your authenticator app and try again." }, 400);
    }
    /* Replay protection: accepted RFC 6238 moving factor is retained and cannot be reused. */
    account.pendingUsedCounters.push(accepted);
    account.encryptedSecret = account.pendingEncryptedSecret; account.usedCounters = [...account.pendingUsedCounters];
    account.pendingEncryptedSecret = undefined; account.pendingUsedCounters = []; account.reenrolmentStarted = false;
    account.mfaEnabled = true; account.otpFailures = 0; account.otpLockedUntil = 0;
    const codes = makeRecoveryCodes(); account.backupCodeHashes = await Promise.all(codes.map(c => keyedHash(c, recoveryKey)));
    account.recoveryFailures = 0; account.recoveryLockedUntil = 0; return respond(request, { ok: true, codes });
  }
  if (url.pathname === "/api/verify-recovery-code") {
    const data = await readBody(request), now = Date.now(), submitted = typeof data?.recoveryCode === "string" ? data.recoveryCode.toUpperCase() : "";
    if (account.recoveryLockedUntil && account.recoveryLockedUntil <= now) { account.recoveryLockedUntil = 0; account.recoveryFailures = 0; }
    if (!data || !validRecovery(submitted)) return respond(request, { ok: false, message: "Enter a recovery code in this format: ABCDE-12345." }, 400);
    if (!account.mfaEnabled) return respond(request, { ok: false, message: "Finish authenticator setup before using a recovery code." }, 400);
    if (account.recoveryLockedUntil > now) return respond(request, { ok: false, message: lockedMessage() }, 429);
    const hash = await keyedHash(submitted, recoveryKey); let index = -1;
    for (let i = 0; i < account.backupCodeHashes.length; i++) if (equal(hash, account.backupCodeHashes[i]) && index < 0) index = i;
    if (index < 0) { account.recoveryFailures++; if (account.recoveryFailures >= MAX_FAILURES) account.recoveryLockedUntil = now + LOCKOUT; return respond(request, { ok: false, message: account.recoveryFailures >= MAX_FAILURES ? lockedMessage() : "That recovery code was not recognised. Check the code and try again, or use another saved code." }, 400); }
    account.backupCodeHashes.splice(index, 1); account.recoveryFailures = 0; account.recoveryLockedUntil = 0; return respond(request, { ok: true });
  }
  if (url.pathname === "/api/regenerate-backup-codes") {
    if (!account.mfaEnabled) return respond(request, { ok: false, message: "Finish authenticator setup before making recovery codes." }, 400);
    const codes = makeRecoveryCodes(); account.backupCodeHashes = await Promise.all(codes.map(c => keyedHash(c, recoveryKey)));
    account.recoveryFailures = 0; account.recoveryLockedUntil = 0; return respond(request, { ok: true, codes });
  }
  return new Response("Not found", { status: 404, headers: secureHeaders(request) });
}

Bun.serve({
  port: Number(Bun.env.PORT || 3000), hostname: "localhost",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) { try { return await handle(request); } catch { return new Response("Something went wrong. Please try again.", { status: 500, headers: secureHeaders(request) }); } },
});
console.log("MFA HTTPS server running at https://localhost:" + (Bun.env.PORT || 3000));
