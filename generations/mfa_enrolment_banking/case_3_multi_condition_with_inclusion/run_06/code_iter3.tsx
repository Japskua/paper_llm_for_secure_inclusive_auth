
import { serve, file } from "bun";

/*
 MFA Enrolment System
 Requirements 1–5: ownership authorization, CSRF, secure TLS cookies/headers,
 encrypted TOTP secrets, hashed recovery codes, validation, expiry, and rate limits.
*/
const PORT = 3000;
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 10 * 60 * 1000;
const RECOVERY_LIFETIME_MS = 365 * 24 * 60 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;
const MAX_FAILURES = 5;
const TOTP_PERIOD = 30;
const trustedOrigins = new Set([`https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`]);

type Challenge = { hash: string; expires: number; used: boolean; failures: number; lockedUntil: number };
type Session = {
  id: string; csrf: string; created: number; lastSeen: number; userId?: string;
  identityVerified: boolean; loginFailures: number; loginLockedUntil: number;
  identityChallenge?: Challenge; authenticatorChallenge?: Challenge;
};
type Account = {
  id: string; email: string; encryptedOtpSecret?: { iv: string; data: string };
  recoveryHashes: Set<string>; recoveryExpires?: number; recoveryFailures: number;
  recoveryLockedUntil: number; recoveryGenerated: boolean; recoveryConfirmed: boolean;
  mfaEnabled: boolean; usedTotpCounters: Set<number>;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();

/* Requirement 3: AES-GCM encryption key remains only in server memory. */
const encryptionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
const hashPepper = randomText(32);

accounts.set("marcus-account", {
  id: "marcus-account", email: "marcus@example.com", recoveryHashes: new Set(),
  recoveryFailures: 0, recoveryLockedUntil: 0, recoveryGenerated: false,
  recoveryConfirmed: false, mfaEnabled: false, usedTotpCounters: new Set(),
});

function randomText(bytes = 24) {
  const a = new Uint8Array(bytes); crypto.getRandomValues(a);
  return Array.from(a, x => x.toString(16).padStart(2, "0")).join("");
}
function randomBase32(bytes = 20) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", a = new Uint8Array(bytes);
  crypto.getRandomValues(a); let bits = 0, value = 0, out = "";
  for (const byte of a) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
function randomSixCode() {
  const a = new Uint32Array(1);
  crypto.getRandomValues(a);
  return String((a[0] % 900000) + 100000);
}
function toBase64(a: Uint8Array) { return Buffer.from(a).toString("base64"); }
function fromBase64(s: string) { return new Uint8Array(Buffer.from(s, "base64")); }

/* Requirement 3: TOTP seeds are encrypted at rest and recovery values are hashed. */
async function encryptSecret(secret: string) {
  const iv = new Uint8Array(12); crypto.getRandomValues(iv);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, new TextEncoder().encode(secret));
  return { iv: toBase64(iv), data: toBase64(new Uint8Array(data)) };
}
async function decryptSecret(record: { iv: string; data: string }) {
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64(record.iv) }, encryptionKey, fromBase64(record.data));
  return new TextDecoder().decode(plain);
}
async function protectedHash(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(hashPepper + ":" + value));
  return toBase64(new Uint8Array(digest));
}
function sameText(a: string, b: string) {
  const aa = new TextEncoder().encode(a), bb = new TextEncoder().encode(b);
  if (aa.length !== bb.length) return false;
  let n = 0; for (let i = 0; i < aa.length; i++) n |= aa[i] ^ bb[i];
  return n === 0;
}
function base32Bytes(s: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, value = 0; const out: number[] = [];
  for (const ch of s.replace(/=/g, "").toUpperCase()) {
    const n = alphabet.indexOf(ch); if (n < 0) throw new Error("bad base32");
    value = (value << 5) | n; bits += 8;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
/* Requirement 3: RFC 6238 TOTP using SHA-1, 30-second period, six digits. */
async function totp(secret: string, counter = Math.floor(Date.now() / 1000 / TOTP_PERIOD)) {
  const msg = new Uint8Array(8); let c = counter;
  for (let i = 7; i >= 0; i--) { msg[i] = c & 255; c = Math.floor(c / 256); }
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
  const offset = mac[19] & 15;
  const value = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(value % 1000000).padStart(6, "0");
}

function cookieValue(req: Request, name: string) {
  for (const item of (req.headers.get("cookie") || "").split(";")) {
    const [k, ...v] = item.trim().split("="); if (k === name) return decodeURIComponent(v.join("="));
  }
}
function makeSession(): Session {
  const now = Date.now();
  return { id: randomText(32), csrf: randomText(32), created: now, lastSeen: now, identityVerified: false, loginFailures: 0, loginLockedUntil: 0 };
}
/* Requirement 2: session cookie is Secure, HttpOnly, Strict SameSite. */
function sessionCookie(id: string) {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}
/* Requirement 5: idle and absolute session expiry are enforced on every access. */
function currentSession(req: Request) {
  const id = cookieValue(req, "mfa_session"), s = id && sessions.get(id);
  if (!s) return undefined;
  if (Date.now() - s.lastSeen > SESSION_IDLE_MS || Date.now() - s.created > SESSION_ABSOLUTE_MS) { sessions.delete(s.id); return undefined; }
  s.lastSeen = Date.now(); return s;
}
/* Requirement 2: CSP, HSTS, anti-clickjacking, no-store and related hardening headers. */
function headers(nonce?: string) {
  const h = new Headers({
    "Content-Type": "application/json; charset=utf-8", "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Cache-Control": "no-store", "Cross-Origin-Resource-Policy": "same-origin",
  });
  h.set("Content-Security-Policy", nonce
    ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    : "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  return h;
}
function json(body: unknown, status = 200, h = headers()) { h.set("Content-Type", "application/json; charset=utf-8"); return new Response(JSON.stringify(body), { status, headers: h }); }
function reject(message = "We could not complete that step. Please try again.", status = 400) { return json({ ok: false, message }, status); }

/* Requirement 4: strict allow-list validation before any security-sensitive use. */
function validEmail(x: unknown): x is string { return typeof x === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(x) && x.length <= 254; }
function validCode(x: unknown): x is string { return typeof x === "string" && /^\d{6}$/.test(x); }
function validRecovery(x: unknown): x is string { return typeof x === "string" && /^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$/.test(x); }
async function readBody(req: Request): Promise<Record<string, unknown> | null> {
  try { const x = await req.json(); return x && typeof x === "object" && !Array.isArray(x) ? x as Record<string, unknown> : null; } catch { return null; }
}
/* Requirement 1: every state-changing endpoint requires this per-session CSRF token. */
function csrfOK(req: Request, s: Session) { const x = req.headers.get("x-csrf-token"); return !!x && sameText(x, s.csrf); }
function originOK(req: Request) { const o = req.headers.get("origin"); return !o || trustedOrigins.has(o); }
/* Requirement 1: account is resolved exclusively from the authenticated session, never client IDs. */
function owner(req: Request): { session: Session; account: Account } | Response {
  const session = currentSession(req); if (!session?.userId) return reject("Please sign in again to continue.", 401);
  const account = accounts.get(session.userId); if (!account) return reject("Please sign in again to continue.", 401);
  return { session, account };
}
function verifiedOwner(req: Request): { session: Session; account: Account } | Response {
  const r = owner(req); if (r instanceof Response) return r;
  return r.session.identityVerified ? r : reject("Please finish identity check before changing MFA settings.", 403);
}
/* Requirement 5: challenges are single-use, expiring, and lock after repeated failures. */
async function challengeMatches(ch: Challenge | undefined, code: string) {
  if (!ch || ch.used || Date.now() > ch.expires) return "expired";
  if (ch.lockedUntil > Date.now()) return "locked";
  if (!sameText(await protectedHash(code), ch.hash)) {
    if (++ch.failures >= MAX_FAILURES) { ch.failures = 0; ch.lockedUntil = Date.now() + LOCKOUT_MS; }
    return "wrong";
  }
  ch.used = true; return "ok";
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank · MFA setup</title><style nonce="${nonce}">
:root{--ink:#172334;--muted:#526174;--blue:#075fc6;--blue2:#034d9f;--pale:#edf6ff;--line:#cbd6e2;--good:#146c43;--error:#a12828}*{box-sizing:border-box}body{margin:0;background:#f2f5f8;color:var(--ink);font-family:Verdana,"Trebuchet MS",Arial,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.025em}main{width:min(100%,560px);margin:auto;min-height:100vh;padding:18px 16px 38px}header{display:flex;align-items:center;gap:11px;margin:5px 0 18px}.logo{display:grid;place-items:center;background:var(--blue);color:white;border-radius:50%;width:40px;height:40px;font-weight:bold}h1{font-size:1.45rem;line-height:1.25;margin:0}h2{font-size:1.3rem;line-height:1.35;margin:0 0 9px}p{margin:8px 0 14px}.card,.logs{background:white;border:1px solid var(--line);border-radius:14px;padding:21px 18px;box-shadow:0 1px 2px #13223a10}.steps{font-size:.86rem;color:var(--muted);margin:0 2px 12px}.step-now{color:var(--blue2);font-weight:bold}.icon{font-size:1.65rem;margin-right:7px}label{display:block;font-weight:bold;margin:17px 0 5px}input{width:100%;min-height:51px;border:2px solid #91a5b9;border-radius:9px;padding:10px 12px;color:var(--ink);font:inherit;letter-spacing:.045em}input:focus{outline:3px solid #8ac5ff;outline-offset:2px;border-color:var(--blue)}button{font:inherit;letter-spacing:.02em;border-radius:9px;cursor:pointer;min-height:50px;padding:10px 16px}.primary{width:100%;border:2px solid var(--blue);background:var(--blue);color:white;font-weight:bold;margin-top:18px}.primary:hover{background:var(--blue2)}.secondary{border:1px solid #62768b;background:white;color:#163e68;min-height:43px;margin-top:10px}.hint{color:var(--muted);font-size:.9rem;margin:4px 0 12px}.notice{border-left:5px solid var(--blue);background:var(--pale);padding:10px 12px;border-radius:5px;margin:15px 0}.error{border-left-color:var(--error);background:#fff0f0;color:#721b1b}.success{border-left-color:var(--good);background:#effaf3;color:#145535}.action-row{display:flex;gap:9px;flex-wrap:wrap;margin-top:8px}.secretbox{padding:10px;background:#f5f7f9;border:1px solid var(--line);border-radius:8px}.secret,code,.codes li,#loglines{font-family:ui-monospace,"Courier New",monospace;word-break:break-all}.qr{width:218px;height:218px;margin:15px auto;border:8px solid white;outline:1px solid var(--line);display:block;image-rendering:pixelated}.codes{list-style:none;padding:0;margin:10px 0;display:grid;grid-template-columns:1fr 1fr;gap:8px}.codes li{background:#f5f7f9;padding:8px;border:1px solid var(--line);border-radius:7px;text-align:center;font-size:.84rem}.footer{display:flex;justify-content:space-between;gap:12px;margin:17px 3px;font-size:.9rem}.link{color:#145897;text-decoration:underline;border:0;background:transparent;padding:3px;min-height:auto}details{margin-top:17px;border-top:1px solid var(--line);padding-top:11px}summary{cursor:pointer;color:#174f88;font-weight:bold}.logs{margin-top:16px;padding:14px 16px}.logs h2{font-size:1rem}.logs p{font-size:.78rem;margin:0 0 6px;color:var(--muted)}#loglines{font-size:.75rem;line-height:1.45;white-space:pre-wrap;max-height:180px;overflow:auto}[hidden]{display:none!important}@media(max-width:360px){body{font-size:16px}.card{padding:18px 14px}.codes{grid-template-columns:1fr}}
</style></head><body><main><header><div class="logo">HB</div><div><h1>Harbour Bank</h1><div class="hint">MFA enrolment</div></div></header><div id="app" aria-live="polite">Loading your secure setup…</div><section class="logs" aria-live="polite"><h2>Logs</h2><p>Simulation messages appear here and in the browser console.</p><div id="loglines"></div></section></main>
<script nonce="${nonce}">(()=>{"use strict";
let csrf="",view="signin",state=null,lastSetup=null,visibleSecret=true,backupCodes=null;
const app=document.getElementById("app"),loglines=document.getElementById("loglines");
function log(s){console.log(s);const line=document.createElement("div");line.textContent=s;loglines.appendChild(line)}
function text(e,v){e.textContent=v}
async function api(path,method="GET",body){const o={method,headers:{}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(body||{})}let r;try{r=await fetch(path,o)}catch{throw Error("Connection problem. Check the secure page and try again.")}let d;try{d=await r.json()}catch{throw Error("We could not complete that step. Please try again.")}if(d.csrf)csrf=d.csrf;if(!r.ok||!d.ok)throw Error(d.message||"We could not complete that step. Please try again.");return d}
function err(m){const e=document.getElementById("message");if(e){text(e,m);e.className="notice error";e.hidden=false}}
function shell(step,title,icon,desc,body){app.innerHTML='<div class="steps">Step <span class="step-now">'+step+'</span> of 5</div><section class="card"><h2><span class="icon">'+icon+'</span>'+title+'</h2><p>'+desc+'</p><div id="message" class="notice error" hidden></div>'+body+'<details><summary>Need help?</summary><p>Take your time. You can retry a code or request a new one without penalty.</p></details></section><nav class="footer"><button class="link" id="help">Help</button><button class="link" id="logout">Log out</button></nav>';document.getElementById("help").onclick=()=>{view="help";render()};document.getElementById("logout").onclick=logout}
function render(){({signin,identity,setup,confirm,backup,recover,success,help}[view]||help)()}
function signin(){shell("1","Sign in","🔐","Use the email for your new bank account.",'<form id="f"><label>Email address<input id="email" type="email" autocomplete="username" placeholder="marcus@example.com" required></label><div class="hint">Example: name@example.com</div><label>Password<input id="password" type="password" autocomplete="current-password" required></label><button class="primary">Continue</button></form>');document.getElementById("f").onsubmit=async e=>{e.preventDefault();try{state=await api("/api/login","POST",{email:email.value,password:password.value});csrf=state.csrf;log("SIMULATION: Sign-in accepted. Identity check is ready.");view="identity";render()}catch(x){err(x.message)}}}
function identity(){shell("2","Check it is you","✉️","We will send a short practice code to your account email.",'<div class="notice">There is no rush. The code has 6 numbers, like <code>123456</code>.</div><button class="primary" id="send">Send my code</button>');send.onclick=async()=>{try{const d=await api("/api/identity/send","POST");log("SIMULATION identity code: "+d.testCode);identityEntry()}catch(x){err(x.message)}}}
function identityEntry(){shell("2","Enter the email code","✉️","Enter the 6-number code shown in your browser console for this simulation.",'<form id="f"><label>Email code<input id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required></label><div class="hint">Example: 123456</div><button class="primary">Check code</button></form><button class="secondary" id="again">Send a new code</button>');f.onsubmit=async e=>{e.preventDefault();try{await api("/api/identity/verify","POST",{code:code.value});log("SIMULATION: Identity check completed.");view="setup";render()}catch(x){err(x.message)}};again.onclick=identity}

/* Standards-compliant QR Model 2 Version 10-L encoder.
   Version 10 is selected because its 271 byte-mode character capacity exceeds the
   complete otpauth URI. It uses ISO/IEC 18004 placement, two block groups,
   Reed-Solomon ECC/interleaving, mask scoring, format and version information. */
function qrMarkup(){return '<svg id="qr" class="qr" role="img" aria-label="Scannable QR code for authenticator setup"></svg>'}
function drawQR(uri){
 const bytes=Array.from(new TextEncoder().encode(uri)),V=10,N=17+4*V,ECC=18;
 if(bytes.length>271)throw Error("The setup link is too long for the QR code.");
 const exp=Array(512).fill(0),lg=Array(256).fill(0);let q=1;
 for(let i=0;i<255;i++){exp[i]=q;lg[q]=i;q<<=1;if(q&256)q^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const mul=(a,b)=>a&&b?exp[lg[a]+lg[b]]:0;
 let gen=[1];for(let i=0;i<ECC;i++){const g=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){g[j]^=gen[j];g[j+1]^=mul(gen[j],exp[i])}gen=g}
 const bits=[];const put=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push(v>>>i&1)};put(4,4);put(bytes.length,16);for(const b of bytes)put(b,8);
 while(bits.length%8)bits.push(0);const raw=[];for(let i=0;i<bits.length;i+=8)raw.push(bits.slice(i,i+8).reduce((a,b)=>a*2+b,0));
 const cap=274;let pad=0;while(raw.length<cap)raw.push((pad++&1)?17:236);
 const blockLens=[68,68,69,69],blocks=[],ec=[];
 let p=0;for(const len of blockLens){const d=raw.slice(p,p+len);p+=len;blocks.push(d);const rem=Array(ECC).fill(0);for(const b of d){const f=b^rem.shift();rem.push(0);for(let j=0;j<ECC;j++)rem[j]^=mul(gen[j+1],f)}ec.push(rem)}
 const words=[];for(let i=0;i<69;i++)for(const b of blocks)if(i<b.length)words.push(b[i]);for(let i=0;i<ECC;i++)for(const e of ec)words.push(e[i]);
 const stream=[];for(const b of words)putStream(b,8);function putStream(v,n){for(let i=n-1;i>=0;i--)stream.push(v>>>i&1)}
 function base(){
  const m=Array.from({length:N},()=>Array(N).fill(-1)),set=(r,c,v)=>{if(r>=0&&c>=0&&r<N&&c<N)m[r][c]=v};
  const finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)set(r+y,c+x,x>=0&&x<=6&&y>=0&&y<=6&&(x===0||x===6||y===0||y===6||(x>=2&&x<=4&&y>=2&&y<=4))?1:0)};
  finder(0,0);finder(0,N-7);finder(N-7,0);
  for(let i=8;i<N-8;i++){set(6,i,i%2===0?1:0);set(i,6,i%2===0?1:0)}
  for(const r of [6,28,50])for(const c of [6,28,50])if(m[r][c]===-1)for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(r+y,c+x,Math.max(Math.abs(x),Math.abs(y))===2||(!x&&!y)?1:0);
  set(N-8,8,1);
  for(let i=0;i<9;i++){if(m[8][i]===-1)set(8,i,0);if(m[i][8]===-1)set(i,8,0)}
  for(let i=N-8;i<N;i++){if(m[8][i]===-1)set(8,i,0);if(m[i][8]===-1)set(i,8,0)}
  for(let i=0;i<6;i++)for(let j=0;j<3;j++){set(i,N-11+j,0);set(N-11+j,i,0)}
  return m;
 }
 function format(m,mask){
  let v=(1<<3|mask)<<10;for(let i=14;i>=10;i--)if(v>>>i&1)v^=0x537<<(i-10);v=((1<<3|mask)<<10|v)^0x5412;
  for(let i=0;i<15;i++){const b=v>>>i&1;if(i<6)m[i][8]=b;else if(i<8)m[i+1][8]=b;else m[N-15+i][8]=b;if(i<8)m[8][N-i-1]=b;else if(i<9)m[8][15-i]=b;else m[8][14-i]=b}
  let vv=V<<12;for(let i=17;i>=12;i--)if(vv>>>i&1)vv^=0x1f25<<(i-12);vv|=V<<12;
  for(let i=0;i<18;i++){const b=vv>>>i&1;m[Math.floor(i/3)][N-11+i%3]=b;m[N-11+i%3][Math.floor(i/3)]=b}
 }
 const maskBit=(mask,r,c)=>[ (r+c)%2===0,r%2===0,c%3===0,(r+c)%3===0,(Math.floor(r/2)+Math.floor(c/3))%2===0,(r*c)%2+(r*c)%3===0,((r*c)%2+(r*c)%3)%2===0,((r+c)%2+(r*c)%3)%2===0 ][mask];
 function make(mask){const m=base();let k=0,up=true;for(let c=N-1;c>0;c-=2){if(c===6)c--;for(let z=0;z<N;z++){const r=up?N-1-z:z;for(let x=0;x<2;x++){const cc=c-x;if(m[r][cc]===-1){let b=k<stream.length?stream[k++]:0;if(maskBit(mask,r,cc))b^=1;m[r][cc]=b}}}up=!up}format(m,mask);return m}
 function penalty(m){let s=0;for(let r=0;r<N;r++)for(let c=0;c<N;c++){let n=0,v=m[r][c];for(let y=-1;y<=1;y++)for(let x=-1;x<=1;x++)if((x||y)&&r+y>=0&&r+y<N&&c+x>=0&&c+x<N&&m[r+y][c+x]===v)n++;if(n>5)s+=3+n-5}for(let r=0;r<N-1;r++)for(let c=0;c<N-1;c++)if(m[r][c]===m[r+1][c]&&m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c+1])s+=3;for(let r=0;r<N;r++)for(let c=0;c<N-6;c++)if(m[r].slice(c,c+7).join("")==="1011101")s+=40;for(let c=0;c<N;c++)for(let r=0;r<N-6;r++){let z="";for(let i=0;i<7;i++)z+=m[r+i][c];if(z==="1011101")s+=40}let dark=0;for(const row of m)for(const b of row)dark+=b;return s+Math.floor(Math.abs(dark*100/N/N-50)/5)*10}
 let best=make(0),score=penalty(best);for(let i=1;i<8;i++){const m=make(i),v=penalty(m);if(v<score){best=m;score=v}}
 const svg=document.getElementById("qr");svg.setAttribute("viewBox","0 0 "+N+" "+N);let path="";for(let r=0;r<N;r++)for(let c=0;c<N;c++)if(best[r][c])path+="M"+c+" "+r+"h1v1h-1z";svg.innerHTML='<rect width="'+N+'" height="'+N+'" fill="white"/><path d="'+path+'" fill="#172334"/>';
}
function setup(){shell("3","Set up your authenticator","📱","Use an authenticator app on this phone. You can scan a code or copy a setup key.",'<div class="notice">Choose one easy way: scan the code, or copy the setup key.</div><button class="primary" id="make">Show setup options</button>');make.onclick=async()=>{try{lastSetup=await api("/api/authenticator/setup","POST");log("SIMULATION authenticator setup key: "+lastSetup.secret);log("SIMULATION authenticator code: "+lastSetup.testCode);setupOptions()}catch(x){err(x.message)}}}
function setupOptions(){shell("3","Add this to your app","📱","Scan the square in your authenticator app. Or copy the setup key below.",qrMarkup()+'<label>Setup key</label><div class="secretbox"><span class="secret" id="key"></span></div><div class="action-row"><button class="secondary" id="copy">Copy setup key</button><button class="secondary" id="hide">Hide key</button></div><div class="hint">Manual option: choose “enter setup key” in your app, then paste it.</div><button class="primary" id="ready">I added it to my app</button>');drawQR(lastSetup.uri);text(key,visibleSecret?lastSetup.secret:"••••••••••••••••");copy.onclick=async()=>{try{await navigator.clipboard.writeText(lastSetup.secret);log("SIMULATION: Setup key copied to clipboard.")}catch{err("Copy did not work. Select the setup key and copy it.")}};hide.onclick=()=>{visibleSecret=!visibleSecret;setupOptions()};ready.onclick=()=>{view="confirm";render()}}
function confirm(){shell("4","Check your authenticator","✅","Open your authenticator app and enter its 6-number code.",'<form id="f"><label>Authenticator code<input id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required></label><div class="hint">Example: 123456</div><button class="primary">Check authenticator</button></form><button class="secondary" id="show">Show setup key again</button>');f.onsubmit=async e=>{e.preventDefault();try{await api("/api/authenticator/confirm","POST",{code:code.value});log("SIMULATION: Authenticator confirmed.");view="backup";render()}catch(x){err(x.message)}};show.onclick=setupOptions}
function backup(){const action=backupCodes?"Show my codes again":"Show my backup codes";shell("5","Save backup codes","🧾","Keep these codes somewhere safe. Each one works once if you cannot use your authenticator.",'<div class="notice">You can copy all codes. You will next check one code, so you know where they are.</div><button class="primary" id="create">'+action+'</button>'+(backupCodes?'<button class="secondary" id="regen">Regenerate and invalidate these codes</button>':''));create.onclick=async()=>{if(backupCodes)return backupList(backupCodes);try{const d=await api("/api/recovery/generate","POST",{});backupCodes=d.codes;log("SIMULATION backup codes: "+d.codes.join(", "));backupList(backupCodes)}catch(x){err(x.message)}};if(backupCodes)regen.onclick=async()=>{if(!confirm("Regenerate backup codes? Your current codes will stop working."))return;try{const d=await api("/api/recovery/generate","POST",{confirmRegenerate:true});backupCodes=d.codes;log("SIMULATION replacement backup codes: "+d.codes.join(", "));backupList(backupCodes)}catch(x){err(x.message)}}}
function backupList(codes){shell("5","Your backup codes","🧾","Copy or write down these short codes. Each code can be used once.",'<ul class="codes" id="list"></ul><button class="secondary" id="copy">Copy all codes</button><button class="primary" id="check">I saved them — check one code</button>');for(const c of codes){const li=document.createElement("li");text(li,c);list.appendChild(li)}copy.onclick=async()=>{try{await navigator.clipboard.writeText(codes.join("\\n"));log("SIMULATION: Backup codes copied to clipboard.")}catch{err("Copy did not work. Select the codes and copy them.")}};check.onclick=()=>{view="recover";render()}}
function recover(){shell("5","Check one backup code","🔎","Enter one unused backup code. This confirms you can recover your account later.",'<form id="f"><label>Backup code<input id="code" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" maxlength="14" placeholder="ABCD-EFGH-IJKL" required></label><div class="hint">Example: ABCD-EFGH-IJKL</div><button class="primary">Check backup code</button></form>'+(backupCodes?'<button class="secondary" id="back">Show my codes again</button>':''));f.onsubmit=async e=>{e.preventDefault();try{await api("/api/recovery/verify","POST",{code:code.value.toUpperCase()});log("SIMULATION: A backup code was checked and used once.");view="success";render()}catch(x){err(x.message)}};if(backupCodes)back.onclick=()=>backupList(backupCodes)}
function success(){shell("5","MFA is ready","🎉","Your authenticator is connected and your backup codes are saved.",'<div class="notice success">Setup complete. You are in control of your account security.</div><button class="primary" id="finish">Finish securely</button>');finish.onclick=logout}
function help(){shell("Help","Help with MFA","💡","Use one step at a time. Nothing on this page moves or times your reading.",'<div class="notice">If a code does not work, request a new one or try again. A temporary pause after several incorrect entries protects your account.</div><button class="primary" id="return">Return to setup</button>');document.getElementById("return").onclick=()=>{view=route();render()}}
function route(){return !state||!state.loggedIn?"signin":!state.identityVerified?"identity":!state.mfaEnabled?"setup":!state.recoveryGenerated?"backup":!state.recoveryConfirmed?"recover":"success"}
async function logout(){try{await api("/api/logout","POST")}catch(_){}csrf="";state=null;lastSetup=null;backupCodes=null;visibleSecret=true;log("SIMULATION: You have been logged out securely.");boot()}
async function boot(){try{state=await api("/api/state");view=route();render()}catch{app.textContent="We could not open secure setup. Please refresh this page."}}boot()})();</script></body></html>`;
}

async function handleApi(req: Request, path: string): Promise<Response> {
  if (!originOK(req)) return reject("This request was not accepted. Please use this page directly.", 403);

  if (path === "/api/state" && req.method === "GET") {
    let s = currentSession(req), cookie: string | undefined;
    if (!s) { s = makeSession(); sessions.set(s.id, s); cookie = sessionCookie(s.id); }
    const a = s.userId ? accounts.get(s.userId) : undefined, h = headers(); if (cookie) h.set("Set-Cookie", cookie);
    return json({
      ok: true, csrf: s.csrf, loggedIn: !!s.userId, identityVerified: s.identityVerified,
      mfaEnabled: !!a?.mfaEnabled, recoveryGenerated: !!a?.recoveryGenerated,
      recoveryConfirmed: !!a?.recoveryConfirmed,
    }, 200, h);
  }

  if (path === "/api/login" && req.method === "POST") {
    const old = currentSession(req); if (!old || !csrfOK(req, old)) return reject("Please refresh the page and try again.", 403);
    const b = await readBody(req);
    if (!b || !validEmail(b.email) || typeof b.password !== "string" || b.password.length > 256) return reject("We could not sign you in. Check your email and password, then try again.", 401);
    if (old.loginLockedUntil > Date.now()) return reject("Too many sign-in attempts. Please wait a few minutes, then try again.", 429);
    if (b.email.toLowerCase() !== "marcus@example.com" || b.password !== "bank-demo") {
      if (++old.loginFailures >= MAX_FAILURES) { old.loginFailures = 0; old.loginLockedUntil = Date.now() + LOCKOUT_MS; }
      return reject("We could not sign you in. Check your email and password, then try again.", 401);
    }
    /* Requirement 5: successful authentication rotates the session ID. */
    sessions.delete(old.id); const s = makeSession(); s.userId = "marcus-account"; sessions.set(s.id, s);
    const h = headers(); h.set("Set-Cookie", sessionCookie(s.id)); return json({ ok: true, csrf: s.csrf, loggedIn: true }, 200, h);
  }

  if (path === "/api/logout" && req.method === "POST") {
    const s = currentSession(req); if (!s || !csrfOK(req, s)) return reject("Please refresh the page and try again.", 403);
    sessions.delete(s.id); const h = headers(); h.set("Set-Cookie", "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"); return json({ ok: true }, 200, h);
  }

  if (path === "/api/identity/send" && req.method === "POST") {
    const r = owner(req); if (r instanceof Response) return r;
    if (!csrfOK(req, r.session)) return reject("Please refresh the page and try again.", 403);
    /* Requirement 5: an active lock is never bypassed by requesting another challenge. */
    if (r.session.identityChallenge?.lockedUntil && r.session.identityChallenge.lockedUntil > Date.now()) {
      return reject("Too many incorrect codes. Please wait a few minutes, then request a new code.", 429);
    }
    /* Every permitted re-request replaces and invalidates the prior challenge. */
    const code = randomSixCode();
    r.session.identityChallenge = { hash: await protectedHash(code), expires: Date.now() + CODE_LIFETIME_MS, used: false, failures: 0, lockedUntil: 0 };
    return json({ ok: true, csrf: r.session.csrf, testCode: code });
  }

  if (path === "/api/identity/verify" && req.method === "POST") {
    const r = owner(req); if (r instanceof Response) return r; if (!csrfOK(req, r.session)) return reject("Please refresh the page and try again.", 403);
    const b = await readBody(req); if (!b || !validCode(b.code)) return reject("Enter all 6 numbers from the email code.");
    const o = await challengeMatches(r.session.identityChallenge, b.code);
    if (o === "ok") { r.session.identityVerified = true; return json({ ok: true, csrf: r.session.csrf }); }
    return o === "locked" ? reject("Too many incorrect codes. Please wait a few minutes, then request a new code.", 429) : o === "expired" ? reject("That code is no longer available. Send a new code and try again.") : reject("That code does not match. Check the 6 numbers or send a new code.");
  }

  if (path === "/api/authenticator/setup" && req.method === "POST") {
    const r = verifiedOwner(req); if (r instanceof Response) return r; if (!csrfOK(req, r.session)) return reject("Please refresh the page and try again.", 403);
    const secret = r.account.encryptedOtpSecret ? await decryptSecret(r.account.encryptedOtpSecret) : randomBase32(20);
    if (!r.account.encryptedOtpSecret) r.account.encryptedOtpSecret = await encryptSecret(secret);
    if (!r.session.authenticatorChallenge || Date.now() > r.session.authenticatorChallenge.expires) r.session.authenticatorChallenge = { hash: "", expires: Date.now() + CODE_LIFETIME_MS, used: false, failures: 0, lockedUntil: 0 };
    const uri = `otpauth://totp/Harbour%20Bank:marcus%40example.com?secret=${secret}&issuer=Harbour%20Bank&algorithm=SHA1&digits=6&period=30`;
    return json({ ok: true, csrf: r.session.csrf, secret, uri, testCode: await totp(secret) });
  }

  if (path === "/api/authenticator/confirm" && req.method === "POST") {
    const r = verifiedOwner(req); if (r instanceof Response) return r; if (!csrfOK(req, r.session)) return reject("Please refresh the page and try again.", 403);
    const b = await readBody(req), ch = r.session.authenticatorChallenge;
    if (!b || !validCode(b.code)) return reject("Enter the 6-number authenticator code.");
    if (!ch || Date.now() > ch.expires) return reject("Setup time has passed. Show setup options again and try the current app code.");
    if (ch.lockedUntil > Date.now()) return reject("Too many incorrect codes. Please wait a few minutes, then show setup options again.", 429);
    const secret = r.account.encryptedOtpSecret && await decryptSecret(r.account.encryptedOtpSecret), now = Math.floor(Date.now() / 1000 / TOTP_PERIOD);
    let matched: number | undefined;
    if (secret) for (let offset = -1; offset <= 1; offset++) if (sameText(await totp(secret, now + offset), b.code)) { matched = now + offset; break; }
    if (matched === undefined || r.account.usedTotpCounters.has(matched)) {
      if (++ch.failures >= MAX_FAILURES) { ch.failures = 0; ch.lockedUntil = Date.now() + LOCKOUT_MS; return reject("Too many incorrect codes. Please wait a few minutes, then show setup options again.", 429); }
      return reject("That code does not match the current code in your authenticator app. Wait for its next code, then try again.");
    }
    r.account.usedTotpCounters.add(matched); ch.used = true; r.account.mfaEnabled = true; return json({ ok: true, csrf: r.session.csrf });
  }

  if (path === "/api/recovery/generate" && req.method === "POST") {
    const r = verifiedOwner(req); if (r instanceof Response) return r; if (!csrfOK(req, r.session)) return reject("Please refresh the page and try again.", 403);
    const b = await readBody(req); if (!r.account.mfaEnabled) return reject("Finish authenticator setup before creating backup codes.", 403);
    if (r.account.recoveryHashes.size && b?.confirmRegenerate !== true) return reject("Please confirm that you want to replace your current backup codes.");
    const codes = Array.from({ length: 8 }, () => { const s = randomBase32(8).slice(0, 12); return s.slice(0, 4) + "-" + s.slice(4, 8) + "-" + s.slice(8, 12); });
    r.account.recoveryHashes = new Set(await Promise.all(codes.map(protectedHash)));
    r.account.recoveryExpires = Date.now() + RECOVERY_LIFETIME_MS;
    r.account.recoveryFailures = 0; r.account.recoveryLockedUntil = 0;
    /* Recovery enrolment progresses only after a later successful verification. */
    r.account.recoveryGenerated = true; r.account.recoveryConfirmed = false;
    return json({ ok: true, csrf: r.session.csrf, codes });
  }

  if (path === "/api/recovery/verify" && req.method === "POST") {
    const r = verifiedOwner(req); if (r instanceof Response) return r; if (!csrfOK(req, r.session)) return reject("Please refresh the page and try again.", 403);
    const a = r.account, b = await readBody(req);
    if (!a.recoveryGenerated) return reject("Create backup codes before checking one.", 403);
    if (!b || !validRecovery(b.code)) return reject("Enter a backup code in this format: ABCD-EFGH-IJKL.");
    if (a.recoveryLockedUntil > Date.now()) return reject("Too many incorrect backup codes. Please wait a few minutes, then try again.", 429);
    if (!a.recoveryExpires || Date.now() > a.recoveryExpires) return reject("These backup codes have expired. Return to backup codes and generate a new set.");
    const h = await protectedHash(b.code); let found: string | undefined;
    for (const saved of a.recoveryHashes) if (sameText(saved, h)) { found = saved; break; }
    if (!found) {
      if (++a.recoveryFailures >= MAX_FAILURES) { a.recoveryFailures = 0; a.recoveryLockedUntil = Date.now() + LOCKOUT_MS; return reject("Too many incorrect backup codes. Please wait a few minutes, then try again.", 429); }
      return reject("That backup code is not available. Check the code and try another saved code.");
    }
    a.recoveryHashes.delete(found); a.recoveryFailures = 0;
    /* Server-side recovery completion is only set after a valid single-use code succeeds. */
    a.recoveryConfirmed = true;
    return json({ ok: true, csrf: r.session.csrf });
  }

  return reject("This secure page is not available.", 404);
}

serve({
  port: PORT,
  tls: { cert: file("certs/cert.pem"), key: file("certs/key.pem") },
  async fetch(req) {
    try {
      const url = new URL(req.url);
      if (url.protocol !== "https:") return reject("Please use the secure HTTPS address.", 403);
      if (url.pathname.startsWith("/api/")) return await handleApi(req, url.pathname);
      if (url.pathname === "/" && req.method === "GET") {
        const nonce = randomText(18), h = headers(nonce);
        h.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers: h });
      }
      return reject("This secure page is not available.", 404);
    } catch {
      return reject("We could not complete that request. Please try again.", 500);
    }
  },
});
