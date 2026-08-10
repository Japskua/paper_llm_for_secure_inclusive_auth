
/*
  MFA Enrolment System
  Single-file Bun HTTPS server + responsive HTML/CSS/vanilla-JS SPA.
  Run with: bun app.ts
  TLS certificates are expected at certs/cert.pem and certs/key.pem.
*/

const encoder = new TextEncoder();
const sessions = new Map<string, Session>();
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;
const MAX_FAILURES = 5;
const encryptionKeyBytes = crypto.getRandomValues(new Uint8Array(32));
const recoveryVerifierKey = crypto.getRandomValues(new Uint8Array(32));
const DUMMY_PASSWORD_HASH = Bun.CryptoHasher.hash("sha256", "fixed-dummy-password-value-not-an-account", "hex");

type Session = { userId: string; csrf: string; createdAt: number; lastSeenAt: number };
type Account = {
  id: string; email: string; passwordHash: string; mfaEnabled: boolean;
  encryptedSecret?: { iv: string; ciphertext: string };
  usedTotpCounters: number[]; otpFailedAttempts: number; otpLockedUntil: number;
  recoveryFailedAttempts: number; recoveryLockedUntil: number; backupCodeHashes: string[];
};

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}
function sha256(value: string): string { return Bun.CryptoHasher.hash("sha256", value, "hex"); }
function constantTimeEqualText(a: string, b: string): boolean {
  const aa = encoder.encode(a), bb = encoder.encode(b);
  let difference = aa.length ^ bb.length, length = Math.max(aa.length, bb.length);
  for (let i = 0; i < length; i++) difference |= (aa[i % (aa.length || 1)] || 0) ^ (bb[i % (bb.length || 1)] || 0);
  return difference === 0;
}

/* Security requirement 3: recovery codes are retained only as keyed HMAC verifiers. */
async function hmacSha256Hex(value: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", recoveryVerifierKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return Buffer.from(await crypto.subtle.sign("HMAC", key, encoder.encode(value))).toString("hex");
}
function generateSecret(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "";
  while (result.length < 32) for (const byte of crypto.getRandomValues(new Uint8Array(32))) {
    if (byte < 248) result += alphabet[byte % 32];
    if (result.length === 32) break;
  }
  return result;
}
function generateBackupCodes(): string[] {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", codes = new Set<string>();
  while (codes.size < 10) {
    let raw = "";
    while (raw.length < 10) for (const byte of crypto.getRandomValues(new Uint8Array(16))) {
      if (byte < 252) raw += alphabet[byte % 36];
      if (raw.length === 10) break;
    }
    codes.add(raw.slice(0, 5) + "-" + raw.slice(5));
  }
  return [...codes];
}
function base32Decode(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, count = 0; const output: number[] = [];
  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("Invalid secret");
    bits = (bits << 5) | index; count += 5;
    while (count >= 8) { count -= 8; output.push((bits >> count) & 255); }
  }
  return new Uint8Array(output);
}
async function totpForCounter(secret: string, counter: number): Promise<string> {
  const message = new Uint8Array(8); let value = BigInt(counter);
  for (let i = 7; i >= 0; i--) { message[i] = Number(value & 255n); value >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = signature[signature.length - 1] & 15;
  const binary = ((signature[offset] & 127) << 24) | (signature[offset + 1] << 16) | (signature[offset + 2] << 8) | signature[offset + 3];
  return String(binary % 1_000_000).padStart(6, "0");
}
async function encryptSecret(secret: string): Promise<{ iv: string; ciphertext: string }> {
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret));
  return { iv: Buffer.from(iv).toString("base64url"), ciphertext: Buffer.from(encrypted).toString("base64url") };
}
async function decryptSecret(stored: { iv: string; ciphertext: string }): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(stored.iv, "base64url") }, key, Buffer.from(stored.ciphertext, "base64url"));
  return new TextDecoder().decode(clear);
}

const accounts = new Map<string, Account>([["marcus-account-001", {
  id: "marcus-account-001", email: "marcus@example.com", passwordHash: sha256("BankDemo!42"), mfaEnabled: false,
  usedTotpCounters: [], otpFailedAttempts: 0, otpLockedUntil: 0, recoveryFailedAttempts: 0, recoveryLockedUntil: 0, backupCodeHashes: [],
}]]);

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  for (const item of (request.headers.get("cookie") || "").split(";")) {
    const index = item.indexOf("=");
    if (index > 0) result[item.slice(0, index).trim()] = item.slice(index + 1).trim();
  }
  return result;
}
function cookieHeader(id: string): string { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`; }
function expiredCookie(): string { return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }
function isTrustedHost(host: string): boolean { return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]"; }

/* Security requirement 2: restrictive headers, TLS-only origin policy, and no-store responses. */
function securityHeaders(request: Request, nonce?: string): Headers {
  const script = nonce ? `'nonce-${nonce}'` : "'none'";
  const headers = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src ${script}; style-src ${script}; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Cache-Control": "no-store",
  });
  const origin = request.headers.get("origin"), url = new URL(request.url);
  if (origin === url.origin && isTrustedHost(url.hostname)) {
    headers.set("Access-Control-Allow-Origin", origin); headers.set("Access-Control-Allow-Credentials", "true"); headers.set("Vary", "Origin");
  }
  return headers;
}
function json(request: Request, body: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = securityHeaders(request); headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((value, key) => headers.set(key, value));
  return new Response(JSON.stringify(body), { status, headers });
}
function originIsSafe(request: Request): boolean {
  const url = new URL(request.url);
  return request.headers.get("origin") === url.origin && url.protocol === "https:" && isTrustedHost(url.hostname);
}
function getSession(request: Request): { id: string; session: Session; account: Account } | null {
  const id = parseCookies(request).mfa_session;
  if (!id || !/^[A-Za-z0-9_-]{30,}$/.test(id)) return null;
  const session = sessions.get(id), now = Date.now();
  if (!session || now - session.lastSeenAt > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) { sessions.delete(id); return null; }
  const account = accounts.get(session.userId);
  if (!account) { sessions.delete(id); return null; }
  session.lastSeenAt = now;
  return { id, session, account };
}
function requireSession(request: Request): { id: string; session: Session; account: Account } | Response {
  return getSession(request) || json(request, { ok: false, message: "Please sign in again to continue." }, 401);
}
function csrfValid(request: Request, session: Session): boolean { return originIsSafe(request) && request.headers.get("x-csrf-token") === session.csrf; }
async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  if (!(request.headers.get("content-type") || "").includes("application/json")) return null;
  try { const body = await request.json(); return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null; } catch { return null; }
}
function validEmail(value: unknown): value is string { return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value); }
function validPassword(value: unknown): value is string { return typeof value === "string" && value.length >= 8 && value.length <= 128; }
function validOtp(value: unknown): value is string { return typeof value === "string" && /^\d{6}$/.test(value); }
function validRecoveryCode(value: unknown): value is string { return typeof value === "string" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/i.test(value); }
function createSession(userId: string): { id: string; session: Session } {
  const id = randomToken(32), session = { userId, csrf: randomToken(24), createdAt: Date.now(), lastSeenAt: Date.now() };
  sessions.set(id, session); return { id, session };
}
function lockMessage(): string { return "Too many attempts were made. Please wait a few minutes, then try again. You can return safely later."; }
function resetExpiredOtpLock(account: Account, now: number): void { if (account.otpLockedUntil && account.otpLockedUntil <= now) { account.otpLockedUntil = 0; account.otpFailedAttempts = 0; } }
function resetExpiredRecoveryLock(account: Account, now: number): void { if (account.recoveryLockedUntil && account.recoveryLockedUntil <= now) { account.recoveryLockedUntil = 0; account.recoveryFailedAttempts = 0; } }

async function provision(request: Request, account: Account): Promise<Response> {
  const secret = generateSecret();
  account.encryptedSecret = await encryptSecret(secret); account.usedTotpCounters = []; account.otpFailedAttempts = 0; account.otpLockedUntil = 0;
  const label = encodeURIComponent("Northstar Bank:" + account.email);
  const uri = `otpauth://totp/${label}?secret=${secret}&issuer=Northstar%20Bank&algorithm=SHA1&digits=6&period=30`;
  const mockOtp = await totpForCounter(secret, Math.floor(Date.now() / 30000));
  return json(request, { ok: true, secret, uri, mockOtp, message: "Authenticator setup is ready. Add the secret, then enter the six-digit code." });
}

function pageHtml(nonce: string): string {
return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#172331;--muted:#536271;--blue:#1259b5;--soft:#edf5ff;--line:#cbd8e6;--good:#156d43;--bad:#a12c2c}
*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:16px;line-height:1.65;letter-spacing:.025em}
main{width:min(100%,620px);min-height:100vh;margin:auto;padding:18px 16px 38px}header{display:flex;gap:11px;align-items:center;margin:4px 0 18px}.mark{width:40px;height:40px;display:grid;place-items:center;background:var(--blue);color:#fff;border-radius:12px;font-size:22px}
h1,h2,h3{line-height:1.3;letter-spacing:.01em;margin:0 0 12px}h1{font-size:1.38rem}h2{font-size:1.35rem}h3{font-size:1rem}.sub,.example{color:var(--muted);font-size:.86rem}.sub{margin:0}
.steps{display:flex;margin:18px 0;gap:5px}.step{flex:1;text-align:center;padding:6px 2px;border-bottom:4px solid var(--line);color:#607080;font-size:.72rem}.step.active{color:#083d82;font-weight:700;border-color:var(--blue)}
.card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:22px 18px;box-shadow:0 2px 7px #193c5c0b}p{margin:0 0 15px}.lead{font-size:1.05rem}
label{display:block;margin:16px 0 6px;font-weight:700}input{width:100%;min-height:52px;border:2px solid #9eafc0;border-radius:10px;padding:11px 13px;font:inherit;letter-spacing:.06em}input:focus,button:focus,summary:focus{outline:3px solid #e3a927;outline-offset:2px}
button{width:100%;min-height:53px;border:0;border-radius:10px;padding:11px 15px;cursor:pointer;font:700 1rem/1.35 Verdana,Arial,sans-serif}button.primary{background:var(--blue);color:#fff;margin-top:22px}button.secondary{background:#fff;color:#083d82;border:2px solid var(--blue);margin-top:11px}button.small{width:auto;min-height:42px;font-size:.88rem;padding:7px 12px}button:disabled{opacity:.55}
.notice{padding:12px 13px;border-radius:10px;margin:15px 0;font-weight:700}.good{color:#0e5533;background:#e5f6eb;border-left:5px solid var(--good)}.bad{color:#782222;background:#fff0f0;border-left:5px solid var(--bad)}.info{color:#164a84;background:var(--soft);border-left:5px solid var(--blue)}
.secret{overflow-wrap:anywhere;padding:12px;background:#f4f8fc;border:1px solid var(--line);border-radius:9px;font-family:ui-monospace,Consolas,monospace;letter-spacing:.09em;line-height:1.8}.row{display:flex;flex-wrap:wrap;gap:9px;margin-top:10px}.row button{flex:1;min-width:130px}
.qr{width:236px;height:236px;margin:16px auto;padding:8px;background:#fff;border:1px solid var(--line);border-radius:8px}.qr canvas{display:block;width:100%;height:100%;image-rendering:pixelated}
.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:14px 0}.code{padding:9px 6px;background:#f4f8fc;border-radius:7px;text-align:center;font-family:ui-monospace,Consolas,monospace;font-weight:700;letter-spacing:.04em}.hiddenCodes{padding:16px;background:#f4f8fc;border-radius:8px;color:var(--muted);text-align:center}
.clip-feedback{min-height:1.7em;margin-top:12px;padding:0 2px;color:#164a84;font-weight:700}
details{margin-top:17px;border-top:1px solid var(--line);padding-top:12px}summary{cursor:pointer;color:#083d82;font-weight:700}.footer{text-align:center;margin-top:18px;color:var(--muted);font-size:.82rem}
@media(max-width:390px){main{padding:12px 11px 28px}.card{padding:18px 14px}.step{font-size:.65rem}.codes{grid-template-columns:1fr}}
</style></head><body><main>
<header><div class="mark" aria-hidden="true">✦</div><div><h1>Northstar Bank</h1><p class="sub">Security setup</p></div></header>
<nav class="steps" aria-label="Setup progress"><div class="step" id="s1">1. Confirm</div><div class="step" id="s2">2. App</div><div class="step" id="s3">3. Check</div><div class="step" id="s4">4. Save</div></nav>
<section id="app" class="card" aria-live="polite">Loading secure setup…</section>
<footer class="footer">Take your time. There is no reading timer.</footer></main>
<script nonce="${nonce}">
const app=document.getElementById("app");
let csrf="",setupSecret="",setupUri="",mockOtp="",visibleSecret=true,currentCodes=[],codesVisible=true;
function esc(value){const e=document.createElement("span");e.textContent=String(value);return e.innerHTML}
function setSteps(number){document.querySelectorAll(".step").forEach((step,index)=>step.classList.toggle("active",index+1===number))}
function notice(message,type){return '<div class="notice '+type+'">'+esc(message)+'</div>'}
function help(){return '<details><summary>Help with this step</summary><p>You can pause and return later. You can retry safely. There is no reading timer.</p></details>'}
function safeConsole(message,...values){console.log(message,...values)}
function clipboardFeedback(message){const panel=document.getElementById("clipFeedback");if(panel)panel.textContent=message}

/* Requirement: browser-generated QR code. This encoder creates a QR version 10-L symbol
   directly from the returned otpauth URI; it uses no network request or external library. */
const QR_EXP=[],QR_LOG=[];(function(){let x=1;for(let i=0;i<256;i++){QR_EXP[i]=x;QR_LOG[x]=i;x<<=1;if(x&256)x^=285}for(let i=256;i<512;i++)QR_EXP[i]=QR_EXP[i-256]})()
function qrMul(a,b){return !a||!b?0:QR_EXP[QR_LOG[a]+QR_LOG[b]]}
function qrPoly(n){let p=[1];for(let i=0;i<n;i++){let q=new Array(p.length+1).fill(0);for(let j=0;j<p.length;j++){q[j]^=p[j];q[j+1]^=qrMul(p[j],QR_EXP[i])}p=q}return p}
function qrRemainder(data,n){const gen=qrPoly(n),r=new Array(n).fill(0);for(const d of data){const f=d^r.shift();r.push(0);for(let j=0;j<n;j++)r[j]^=qrMul(gen[j+1],f)}return r}
function qrBits(v,n,a){for(let i=n-1;i>=0;i--)a.push((v>>>i)&1)}
function qrData(text){
 const bytes=Array.from(new TextEncoder().encode(text));if(bytes.length>274)throw new Error("Setup code is too long");
 const bits=[];qrBits(4,4,bits);qrBits(bytes.length,16,bits);bytes.forEach(b=>qrBits(b,8,bits));qrBits(0,Math.min(4,274*8-bits.length),bits);
 while(bits.length%8)bits.push(0);const raw=[];for(let i=0;i<bits.length;i+=8)raw.push(bits.slice(i,i+8).reduce((v,b)=>v*2+b,0));
 for(let i=0;raw.length<274;i++)raw.push(i%2?17:236);
 const lengths=[68,68,69,69],blocks=[],at=0;for(const len of lengths){const d=raw.slice(at,at+len);at+=len;blocks.push({d,e:qrRemainder(d,18)})}
 const out=[];for(let i=0;i<69;i++)blocks.forEach(b=>{if(i<b.d.length)out.push(b.d[i])});for(let i=0;i<18;i++)blocks.forEach(b=>out.push(b.e[i]));return out
}
function qrBch(v,poly){let d=v;while((d.toString(2).length)>=poly.toString(2).length)d^=poly<<(d.toString(2).length-poly.toString(2).length);return d}
function qrMask(mask,i,j){return [((i+j)%2)==0,i%2==0,j%3==0,(i+j)%3==0,(Math.floor(i/2)+Math.floor(j/3))%2==0,(i*j)%2+(i*j)%3==0,((i*j)%2+(i*j)%3)%2==0,((i*j)%3+(i+j)%2)%2==0][mask]}
function qrMatrix(data,mask){
 const n=57,m=Array.from({length:n},()=>Array(n).fill(null)),put=(r,c,v)=>{if(r>=0&&r<n&&c>=0&&c<n)m[r][c]=v};
 function finder(r,c){for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)put(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(y==0||y==6||x==0||x==6||(y>=2&&y<=4&&x>=2&&x<=4)))}
 finder(0,0);finder(n-7,0);finder(0,n-7);
 [6,22,38,50].forEach(r=>[6,22,38,50].forEach(c=>{if(m[r][c]!==null)return;for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)put(r+y,c+x,Math.abs(x)==2||Math.abs(y)==2||(x==0&&y==0))}));
 for(let i=8;i<n-8;i++){if(m[i][6]===null)put(i,6,i%2==0);if(m[6][i]===null)put(6,i,i%2==0)}
 let type=((1<<3)|mask);type=(type<<10|qrBch(type<<10,1335))^21522;
 for(let i=0;i<15;i++){const v=((type>>>i)&1)===1;if(i<6)put(i,8,v);else if(i<8)put(i+1,8,v);else put(n-15+i,8,v);if(i<8)put(8,n-i-1,v);else if(i<9)put(8,15-i,v);else put(8,15-i-1,v)}put(n-8,8,true);
 const bits=[];data.forEach(v=>qrBits(v,8,bits));let bit=0,row=n-1,dir=-1;
 for(let col=n-1;col>0;col-=2){if(col==6)col--;while(true){for(let k=0;k<2;k++){const c=col-k;if(m[row][c]===null){let v=bit<bits.length?bits[bit++]:0;if(qrMask(mask,row,c))v^=1;m[row][c]=!!v}}row+=dir;if(row<0||row>=n){row-=dir;dir=-dir;break}}}
 return m
}
function qrPenalty(m){const n=m.length;let p=0;for(let r=0;r<n;r++)for(let c=0;c<n;c++){let same=0,v=m[r][c];for(let y=-1;y<=1;y++)for(let x=-1;x<=1;x++)if(x||y){const rr=r+y,cc=c+x;if(rr>=0&&rr<n&&cc>=0&&cc<n&&m[rr][cc]===v)same++}if(same>5)p+=3+same-5}for(let r=0;r<n-1;r++)for(let c=0;c<n-1;c++)if(m[r][c]===m[r+1][c]&&m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c+1])p+=3;let dark=0;m.forEach(r=>r.forEach(v=>dark+=v?1:0));return p+Math.abs(100*dark/n/n-50)/5}
function drawQr(uri){
 const holder=document.getElementById("qrCode");if(!holder)return;let data,m,best=null,score=Infinity;try{data=qrData(uri);for(let i=0;i<8;i++){m=qrMatrix(data,i);let s=qrPenalty(m);if(s<score){score=s;best=m}}}catch{return}
 const canvas=document.createElement("canvas"),size=best.length,scale=4;canvas.width=canvas.height=size*scale;const ctx=canvas.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle="#000";best.forEach((row,y)=>row.forEach((v,x)=>{if(v)ctx.fillRect(x*scale,y*scale,scale,scale)}));holder.replaceChildren(canvas)
}
async function api(path,body){
 const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body||{})});
 const data=await response.json().catch(()=>({ok:false,message:"Something went wrong. Please try again."}));
 if(response.status===401){csrf="";showSignIn("Your secure session ended. Please sign in again.")}
 return {response,data};
}
function showSignIn(message=""){
 setSteps(1);app.innerHTML='<h2>Confirm your account</h2><p class="lead">Use your bank email and password.</p>'+notice("Demo sign-in: marcus@example.com · password: BankDemo!42","info")+(message?notice(message,"info"):"")+'<label for="email">Email address</label><input id="email" type="email" autocomplete="email" inputmode="email" placeholder="marcus@example.com"><p class="example">Example: marcus@example.com</p><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" placeholder="Your password"><button class="primary" id="signin">Continue</button>'+help();document.getElementById("signin").onclick=signIn
}
async function signIn(){
 const button=document.getElementById("signin");button.disabled=true;
 const response=await fetch("/api/signin",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:document.getElementById("email").value,password:document.getElementById("password").value})});
 const data=await response.json().catch(()=>({ok:false,message:"Sign-in could not be completed. Try again."}));
 if(!response.ok||!data.ok){button.disabled=false;app.insertAdjacentHTML("afterbegin",notice(data.message||"Sign-in could not be completed. Try again.","bad"));return}csrf=data.csrf;if(data.mfaEnabled)showComplete("You are signed in. Your authenticator is already connected.");else showSetup("Your identity is confirmed. Next, add your authenticator app.")
}
function showSetup(message=""){setSteps(2);app.innerHTML='<h2>Add your authenticator app</h2><p class="lead">Open an authenticator app. You can scan a QR code or copy a short secret.</p>'+(message?notice(message,"good"):"")+'<button class="primary" id="getSetup">Show secure setup</button>'+help();document.getElementById("getSetup").onclick=getSetup}
async function getSetup(){
 const button=document.getElementById("getSetup");button.disabled=true;const result=await api("/api/provision",{});
 if(!result.response.ok||!result.data.ok){button.disabled=false;app.insertAdjacentHTML("afterbegin",notice(result.data.message||"We could not prepare setup. Try again.","bad"));return}
 setupSecret=result.data.secret;setupUri=result.data.uri;mockOtp=result.data.mockOtp;visibleSecret=true;safeConsole("Mock authenticator setup delivered. Secret: "+setupSecret);safeConsole("Mock OTP for testing: "+mockOtp);showProvisioning(result.data.message)
}
function showProvisioning(message){
 setSteps(2);app.innerHTML='<h2>Your setup QR code is ready</h2>'+notice(message,"good")+'<p>Scan this QR code in your authenticator app. If scanning is difficult, use the secret below.</p><div class="qr" id="qrCode" role="img" aria-label="Scannable QR code for Northstar Bank authenticator setup"></div><h3>Manual secret</h3><div class="secret" id="secretText">'+esc(setupSecret)+'</div><div class="row"><button class="secondary small" id="copySecret">Copy secret</button><button class="secondary small" id="hideSecret">Hide secret</button></div><div id="clipFeedback" class="clip-feedback" role="status" aria-live="polite" aria-atomic="true"></div><button class="primary" id="goVerify">I added it to my app</button><button class="secondary" id="newSetup">Request a new setup</button>'+help();
 drawQr(setupUri);document.getElementById("copySecret").onclick=()=>copyText(setupSecret,"secret");document.getElementById("hideSecret").onclick=toggleSecret;document.getElementById("goVerify").onclick=showVerify;document.getElementById("newSetup").onclick=getSetup
}
function toggleSecret(){visibleSecret=!visibleSecret;document.getElementById("secretText").textContent=visibleSecret?setupSecret:"Secret hidden";document.getElementById("hideSecret").textContent=visibleSecret?"Hide secret":"Show secret"}
async function copyText(text,kind){
 const label=kind==="secret"?"Authenticator secret":"Recovery codes";
 try{await navigator.clipboard.writeText(text);safeConsole(label+" copied.");clipboardFeedback(label+" copied. Next, add it to your authenticator app or save the codes somewhere safe.")}catch{safeConsole("Copy was not available. The value remains on the secure page.");clipboardFeedback(label+" could not be copied. Select it on this secure page and try again.")}
}
function showVerify(message=""){
 setSteps(3);app.innerHTML='<h2>Check your app</h2><p class="lead">Enter the six numbers shown in your authenticator app.</p>'+(message?notice(message,"info"):"")+'<label for="otp">Six-digit code</label><input id="otp" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><p class="example">Example: 123456. You have plenty of time.</p><button class="primary" id="verify">Verify code</button><button class="secondary" id="backSetup">Go back to setup</button>'+help();document.getElementById("verify").onclick=verifyOtp;document.getElementById("backSetup").onclick=()=>showProvisioning("You can view setup details again.")
}
async function verifyOtp(){
 const button=document.getElementById("verify");button.disabled=true;const result=await api("/api/verify-otp",{otp:document.getElementById("otp").value.trim()});
 if(!result.response.ok||!result.data.ok){button.disabled=false;app.insertAdjacentHTML("afterbegin",notice(result.data.message||"That code could not be checked. Try again.","bad"));return}currentCodes=result.data.codes;codesVisible=true;safeConsole("Generated recovery codes for testing:",currentCodes);showCodes("Your authenticator is now connected.")
}
function renderCodes(){return codesVisible?'<div class="codes">'+currentCodes.map(code=>'<div class="code">'+esc(code)+'</div>').join("")+'</div>':'<div class="hiddenCodes">Recovery codes are hidden.</div>'}
function showCodes(message){
 setSteps(4);app.innerHTML='<h2>Save your recovery codes</h2>'+notice(message,"good")+'<p class="lead">These codes help if you lose your phone. Store them somewhere safe. Each code works once.</p><div id="codesArea">'+renderCodes()+'</div><div class="row"><button class="secondary small" id="toggleCodes">'+(codesVisible?"Hide recovery codes":"Show recovery codes")+'</button><button class="secondary small" id="copyCodes">Copy all recovery codes</button></div><div id="clipFeedback" class="clip-feedback" role="status" aria-live="polite" aria-atomic="true"></div><button class="primary" id="finish">I saved my codes</button>'+help();
 document.getElementById("copyCodes").onclick=()=>copyText(currentCodes.join("\\n"),"codes");document.getElementById("toggleCodes").onclick=toggleCodes;document.getElementById("finish").onclick=()=>showComplete()
}
function toggleCodes(){codesVisible=!codesVisible;document.getElementById("codesArea").innerHTML=renderCodes();document.getElementById("toggleCodes").textContent=codesVisible?"Hide recovery codes":"Show recovery codes";clipboardFeedback(codesVisible?"Recovery codes are shown again. Save them somewhere safe.":"Recovery codes are hidden. You can show the same codes again whenever you need them.")}
function showComplete(message=""){
 setSteps(4);currentCodes=[];setupSecret="";setupUri="";mockOtp="";app.innerHTML='<h2>Setup complete ✓</h2>'+notice(message||"Multi-factor authentication is on for your account.","good")+'<p class="lead">You will use your authenticator when a payment needs extra protection.</p><button class="primary" id="recovery">Use a recovery code</button><button class="secondary" id="regenerate">Generate new recovery codes</button><button class="secondary" id="logout">Sign out</button>'+help();document.getElementById("recovery").onclick=showRecovery;document.getElementById("regenerate").onclick=regenerate;document.getElementById("logout").onclick=logout
}
function showRecovery(message=""){
 setSteps(4);app.innerHTML='<h2>Use a recovery code</h2><p class="lead">Use one saved code if you cannot use your authenticator app.</p>'+(message?notice(message,"info"):"")+'<label for="recoveryCode">Recovery code</label><input id="recoveryCode" type="text" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" maxlength="11" placeholder="ABCDE-12345"><p class="example">Example: ABCDE-12345. Each code works once.</p><button class="primary" id="verifyRecovery">Verify recovery code</button><button class="secondary" id="backAccount">Back to security setup</button>'+help();document.getElementById("verifyRecovery").onclick=verifyRecovery;document.getElementById("backAccount").onclick=()=>showComplete("You can use a saved recovery code whenever you need it.")
}
async function verifyRecovery(){
 const button=document.getElementById("verifyRecovery");button.disabled=true;const result=await api("/api/verify-recovery-code",{recoveryCode:document.getElementById("recoveryCode").value.trim().toUpperCase()});
 if(!result.response.ok||!result.data.ok){button.disabled=false;app.insertAdjacentHTML("afterbegin",notice(result.data.message||"That recovery code could not be checked. Try again.","bad"));return}safeConsole("Recovery code verification succeeded in the mock flow.");showComplete("Recovery code accepted. That code has now been used and cannot be used again.")
}
async function regenerate(){
 const result=await api("/api/regenerate-backup-codes",{});if(!result.response.ok||!result.data.ok){app.insertAdjacentHTML("afterbegin",notice(result.data.message||"New codes could not be made. Try again.","bad"));return}currentCodes=result.data.codes;codesVisible=true;safeConsole("New recovery codes generated for testing:",currentCodes);showCodes("New recovery codes have replaced the old ones.")
}
async function logout(){await api("/api/logout",{});csrf="";setupSecret="";currentCodes=[];safeConsole("Signed out safely.");showSignIn("You have signed out safely.")}
showSignIn();
</script></body></html>`;
}

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.protocol !== "https:" || !isTrustedHost(url.hostname)) return new Response("Not found", { status: 404, headers: securityHeaders(request) });
  if (request.method === "OPTIONS") {
    if (!originIsSafe(request)) return new Response(null, { status: 403, headers: securityHeaders(request) });
    const headers = securityHeaders(request); headers.set("Access-Control-Allow-Methods", "POST"); headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return new Response(null, { status: 204, headers });
  }
  if (request.method === "GET" && url.pathname === "/") {
    const nonce = randomToken(18), headers = securityHeaders(request, nonce); headers.set("Content-Type", "text/html; charset=utf-8");
    return new Response(pageHtml(nonce), { headers });
  }
  if (request.method === "POST" && url.pathname === "/api/signin") {
    if (!originIsSafe(request)) return json(request, { ok: false, message: "Please use the secure sign-in page." }, 403);
    const body = await readJson(request), email = typeof body?.email === "string" ? body.email.toLowerCase().trim() : "", password = body?.password;
    const account = [...accounts.values()].find(candidate => candidate.email === email);
    const matches = constantTimeEqualText(sha256(typeof password === "string" ? password : ""), account ? account.passwordHash : DUMMY_PASSWORD_HASH);
    if (!body || !validEmail(email) || !validPassword(password) || !account || !matches) return json(request, { ok: false, message: "Sign-in could not be completed. Check your email and password, then try again." }, 401);
    for (const [id, session] of sessions) if (session.userId === account.id) sessions.delete(id);
    const made = createSession(account.id);
    return json(request, { ok: true, csrf: made.session.csrf, mfaEnabled: account.mfaEnabled }, 200, { "Set-Cookie": cookieHeader(made.id) });
  }
  if (request.method === "POST" && url.pathname === "/api/logout") {
    const auth = requireSession(request); if (auth instanceof Response) return auth;
    if (!csrfValid(request, auth.session)) return json(request, { ok: false, message: "Please refresh the secure page and try again." }, 403);
    sessions.delete(auth.id); return json(request, { ok: true }, 200, { "Set-Cookie": expiredCookie() });
  }

  /* Requirement 1: account ownership is always derived exclusively from the authenticated session. */
  const auth = requireSession(request);
  if (auth instanceof Response) return auth;
  if (request.method !== "POST" || !csrfValid(request, auth.session)) return json(request, { ok: false, message: "Please refresh the secure page and try again." }, 403);
  if (url.pathname === "/api/provision") return provision(request, auth.account);

  if (url.pathname === "/api/verify-otp") {
    const account = auth.account, now = Date.now(); resetExpiredOtpLock(account, now);
    const body = await readJson(request);
    if (!body || !validOtp(body.otp)) return json(request, { ok: false, message: "Enter exactly six numbers, for example 123456." }, 400);
    if (account.otpLockedUntil > now) return json(request, { ok: false, message: lockMessage() }, 429);
    if (!account.encryptedSecret) return json(request, { ok: false, message: "Request a new setup and try again." }, 400);
    let secret: string; try { secret = await decryptSecret(account.encryptedSecret); } catch { return json(request, { ok: false, message: "Request a new setup and try again." }, 400); }
    let acceptedCounter = -1;
    for (const counter of [Math.floor(now / 30000) - 1, Math.floor(now / 30000), Math.floor(now / 30000) + 1]) if (constantTimeEqualText(body.otp, await totpForCounter(secret, counter))) acceptedCounter = counter;
    if (acceptedCounter < 0 || account.usedTotpCounters.includes(acceptedCounter)) {
      account.otpFailedAttempts++; if (account.otpFailedAttempts >= MAX_FAILURES) account.otpLockedUntil = now + LOCKOUT_MS;
      return json(request, { ok: false, message: account.otpFailedAttempts >= MAX_FAILURES ? lockMessage() : "That code did not match, or it was already used. Check your authenticator app and try again." }, 400);
    }
    account.usedTotpCounters = [...account.usedTotpCounters, acceptedCounter].slice(-8); account.mfaEnabled = true; account.otpFailedAttempts = 0; account.otpLockedUntil = 0;
    const codes = generateBackupCodes(); account.backupCodeHashes = await Promise.all(codes.map(hmacSha256Hex)); account.recoveryFailedAttempts = 0; account.recoveryLockedUntil = 0;
    return json(request, { ok: true, codes });
  }

  /* Requirements 1, 3, and 5: authenticated CSRF-protected, HMAC-verified single-use recovery code. */
  if (url.pathname === "/api/verify-recovery-code") {
    const account = auth.account, now = Date.now(); resetExpiredRecoveryLock(account, now);
    const body = await readJson(request), submitted = typeof body?.recoveryCode === "string" ? body.recoveryCode.toUpperCase() : "";
    if (!body || !validRecoveryCode(submitted)) return json(request, { ok: false, message: "Enter a recovery code in this format: ABCDE-12345." }, 400);
    if (!account.mfaEnabled) return json(request, { ok: false, message: "Finish authenticator setup before using a recovery code." }, 400);
    if (account.recoveryLockedUntil > now) return json(request, { ok: false, message: lockMessage() }, 429);
    const submittedVerifier = await hmacSha256Hex(submitted); let matchingIndex = -1;
    for (let index = 0; index < account.backupCodeHashes.length; index++) { const matches = constantTimeEqualText(submittedVerifier, account.backupCodeHashes[index]); if (matches && matchingIndex === -1) matchingIndex = index; }
    if (matchingIndex === -1) {
      account.recoveryFailedAttempts++; if (account.recoveryFailedAttempts >= MAX_FAILURES) account.recoveryLockedUntil = now + LOCKOUT_MS;
      return json(request, { ok: false, message: account.recoveryFailedAttempts >= MAX_FAILURES ? lockMessage() : "That recovery code was not recognised. Check the code and try again, or use another saved code." }, 400);
    }
    account.backupCodeHashes.splice(matchingIndex, 1); account.recoveryFailedAttempts = 0; account.recoveryLockedUntil = 0;
    return json(request, { ok: true, message: "Recovery code accepted." });
  }
  if (url.pathname === "/api/regenerate-backup-codes") {
    if (!auth.account.mfaEnabled) return json(request, { ok: false, message: "Finish authenticator setup before making recovery codes." }, 400);
    const codes = generateBackupCodes(); auth.account.backupCodeHashes = await Promise.all(codes.map(hmacSha256Hex)); auth.account.recoveryFailedAttempts = 0; auth.account.recoveryLockedUntil = 0;
    return json(request, { ok: true, codes });
  }
  return new Response("Not found", { status: 404, headers: securityHeaders(request) });
}

Bun.serve({
  port: Number(Bun.env.PORT || 3000), hostname: "localhost",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try { return await handle(request); }
    catch { return new Response("Something went wrong. Please try again.", { status: 500, headers: securityHeaders(request) }); }
  },
});
console.log("MFA HTTPS server running at https://localhost:" + (Bun.env.PORT || 3000));
