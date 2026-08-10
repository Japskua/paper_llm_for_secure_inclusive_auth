
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const USER = { id: "acct_marcus_01", email: "marcus@example.test" };
const PORT = 3000;
const STORE_FILE = "mfa-store.json";
const SESSION_IDLE_MS = 20 * 60_000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60_000;
const CODE_LIFE_MS = 10 * 60_000;
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60_000;
const MAX_JSON_BODY_BYTES = 4096;
const allowedOrigins = new Set([`https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`]);

type Challenge = { accountId: string; value: string; expires: number; used: boolean };
type Attempt = { count: number; lockedUntil: number };
type Session = {
  id: string; csrf: string; createdAt: number; lastSeen: number;
  signInEmail?: string; userId?: string; identityVerified: boolean; mfaVerified: boolean;
  ownerChallenge?: Challenge; identityChallenge?: Challenge;
};
type MfaState = {
  encryptedSecret?: string; enrolled: boolean; acceptedSteps: number[]; recoveryHashes: string[];
  attempts: Record<"owner" | "identity" | "totp" | "recovery", Attempt>;
};
type StoredMfa = { accounts: Record<string, MfaState> };

function bytes(n: number) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
function b64(b: Uint8Array) { let s = ""; for (const x of b) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); }
function unb64(s: string) { return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), x => x.charCodeAt(0)); }
function token(n = 32) { return b64(bytes(n)); }

const production = Bun.env.MFA_ENV === "production";
let masterMaterial = Bun.env.MFA_MASTER_KEY;
let pepper = Bun.env.MFA_HASH_PEPPER;
if (production && (!masterMaterial || masterMaterial.length < 32 || !pepper || pepper.length < 32)) {
  console.error("MFA service cannot start: production requires MFA_MASTER_KEY and MFA_HASH_PEPPER.");
  process.exit(1);
}
if (!production) {
  masterMaterial ||= token(48);
  pepper ||= token(48);
  console.warn("MFA development mode uses process-local cryptographic keys.");
}
const keyRaw = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(masterMaterial!)));
const masterKey = await crypto.subtle.importKey("raw", keyRaw, "AES-GCM", false, ["encrypt", "decrypt"]);

function emptyState(): MfaState {
  return {
    enrolled: false, acceptedSteps: [], recoveryHashes: [],
    attempts: {
      owner: { count: 0, lockedUntil: 0 }, identity: { count: 0, lockedUntil: 0 },
      totp: { count: 0, lockedUntil: 0 }, recovery: { count: 0, lockedUntil: 0 },
    },
  };
}
async function loadStore(): Promise<StoredMfa> {
  const f = Bun.file(STORE_FILE);
  if (!(await f.exists())) return { accounts: {} };
  const raw = await f.text();
  const data = JSON.parse(raw) as StoredMfa;
  if (!data || typeof data !== "object" || !data.accounts || typeof data.accounts !== "object") throw new Error("Invalid MFA state.");
  for (const id of Object.keys(data.accounts)) {
    const s = data.accounts[id];
    if (!s || typeof s !== "object") throw new Error("Invalid MFA account state.");
    s.enrolled = s.enrolled === true;
    s.acceptedSteps = Array.isArray(s.acceptedSteps) ? s.acceptedSteps.filter(Number.isSafeInteger) : [];
    s.recoveryHashes = Array.isArray(s.recoveryHashes) ? s.recoveryHashes.filter(x => typeof x === "string") : [];
    s.attempts ||= emptyState().attempts;
    for (const k of ["owner", "identity", "totp", "recovery"] as const) s.attempts[k] ||= { count: 0, lockedUntil: 0 };
  }
  return data;
}
const stored = await loadStore();
let saveChain = Promise.resolve();
function saveStore() {
  saveChain = saveChain.then(() => Bun.write(STORE_FILE, JSON.stringify(stored))).catch(() => console.error("MFA state persistence failed."));
  return saveChain;
}
function stateFor(id: string) {
  if (!stored.accounts[id]) { stored.accounts[id] = emptyState(); void saveStore(); }
  return stored.accounts[id];
}
async function hash(v: string) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(`${pepper}:${v}`)))); }
async function encrypt(v: string) {
  const iv = bytes(12), out = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(v)));
  const packed = new Uint8Array(iv.length + out.length); packed.set(iv); packed.set(out, iv.length); return b64(packed);
}
async function decrypt(v: string) {
  const p = unb64(v);
  return decoder.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: p.slice(0, 12) }, masterKey, p.slice(12)));
}
function base32Secret() {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", src = bytes(20); let bits = 0, val = 0, out = "";
  for (const x of src) { val = (val << 8) | x; bits += 8; while (bits >= 5) { out += a[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  return bits ? out + a[(val << (5 - bits)) & 31] : out;
}
function b32(v: string) {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, n = 0; const out: number[] = [];
  for (const c of v.replace(/[=\s]/g, "").toUpperCase()) { const x = a.indexOf(c); if (x < 0) throw new Error("Invalid secret"); n = (n << 5) | x; bits += 5; if (bits >= 8) { out.push((n >>> (bits - 8)) & 255); bits -= 8; } }
  return new Uint8Array(out);
}
async function totp(secret: string, step: number) {
  const c = new Uint8Array(8); let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { c[i] = Number(n & 255n); n >>= 8n; }
  const k = await crypto.subtle.importKey("raw", b32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const d = new Uint8Array(await crypto.subtle.sign("HMAC", k, c)), o = d[19] & 15;
  const x = ((d[o] & 127) << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3];
  return String(x % 1_000_000).padStart(6, "0");
}
function six() { const x = new Uint32Array(1); crypto.getRandomValues(x); return String(x[0] % 1_000_000).padStart(6, "0"); }
function newChallenge(): Challenge { return { accountId: USER.id, value: six(), expires: Date.now() + CODE_LIFE_MS, used: false }; }
function recoveryCode() { const a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", s = Array.from(bytes(8), x => a[x % a.length]).join(""); return `${s.slice(0, 4)}-${s.slice(4)}`; }
async function generateRecovery(s: MfaState) { const codes = Array.from({ length: 8 }, recoveryCode); s.recoveryHashes = await Promise.all(codes.map(hash)); await saveStore(); return codes; }

const sessions = new Map<string, Session>();
function headers(nonce = token(16), origin?: string | null) {
  const h = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
  });
  if (origin && allowedOrigins.has(origin)) { h.set("Access-Control-Allow-Origin", origin); h.set("Access-Control-Allow-Credentials", "true"); h.set("Vary", "Origin"); }
  return h;
}
function reply(x: unknown, status = 200, req?: Request) { return new Response(JSON.stringify(x), { status, headers: headers(token(16), req?.headers.get("origin")) }); }
function cookie(req: Request, name: string) { const x = (req.headers.get("cookie") || "").split(";").map(v => v.trim()).find(v => v.startsWith(name + "=")); return x ? x.slice(name.length + 1) : ""; }
function originOK(req: Request) { const o = req.headers.get("origin"); return o === null || allowedOrigins.has(o); }
function makeSession(email?: string, user?: string) { const now = Date.now(), s: Session = { id: token(), csrf: token(), createdAt: now, lastSeen: now, signInEmail: email, userId: user, identityVerified: false, mfaVerified: false }; sessions.set(s.id, s); return s; }
function sessionCookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`; }
function auth(req: Request): Session | null {
  const s = sessions.get(cookie(req, "mfa_session")), now = Date.now();
  if (!s || now - s.lastSeen > SESSION_IDLE_MS || now - s.createdAt > SESSION_ABSOLUTE_MS) { if (s) sessions.delete(s.id); return null; }
  s.lastSeen = now; return s;
}
function validCsrf(req: Request, s: Session) { return req.headers.get("x-csrf-token") === s.csrf; }
function safeEmail(x: unknown) { return typeof x === "string" && x.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x); }
function safeOtp(x: unknown) { return typeof x === "string" && /^\d{6}$/.test(x); }
function safeRecovery(x: unknown) { return typeof x === "string" && /^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(x); }
function attempt(s: MfaState, k: keyof MfaState["attempts"]) { const a = s.attempts[k]; if (a.lockedUntil && a.lockedUntil <= Date.now()) { a.count = 0; a.lockedUntil = 0; void saveStore(); } return a; }
function fail(s: MfaState, k: keyof MfaState["attempts"]) { const a = attempt(s, k); a.count++; if (a.count >= MAX_FAILURES) a.lockedUntil = Date.now() + LOCK_MS; void saveStore(); return a.lockedUntil > Date.now(); }
function pass(s: MfaState, k: keyof MfaState["attempts"]) { s.attempts[k] = { count: 0, lockedUntil: 0 }; void saveStore(); }
function lock(k: string) { return `Too many ${k} tries. Please wait 15 minutes, then try again.`; }
async function body(req: Request): Promise<Record<string, unknown> | null> {
  if (!/^application\/json(?:\s*;|$)/i.test(req.headers.get("content-type") || "")) return null;
  const len = req.headers.get("content-length"); if (len && (!/^\d+$/.test(len) || Number(len) > MAX_JSON_BODY_BYTES)) return null;
  try { const t = await req.text(); if (t.length > MAX_JSON_BODY_BYTES) return null; const x = JSON.parse(t); return x && typeof x === "object" && !Array.isArray(x) ? x : null; } catch { return null; }
}
async function delay() { await new Promise(r => setTimeout(r, 180)); }

/* Requirements: mobile UI, inclusive wording, browser-visible mock logs, and standards QR encoder. */
function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Example Bank — security set-up</title><style nonce="${nonce}">
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#edf3f7;color:#172535;font:18px/1.68 Arial,Verdana,sans-serif;letter-spacing:.035em}.shell{max-width:580px;min-height:100vh;margin:auto;background:#fff;padding:22px 20px 42px}.brand{font-weight:700;color:#063f7c;margin:0 0 25px}.step{color:#4d6172;font-size:.92rem;margin:0 0 8px}h1{font-size:1.65rem;line-height:1.3;margin:0 0 14px}p{margin:10px 0 16px}.notice,.error,.success{border-radius:10px;padding:14px;margin:16px 0}.notice{background:#edf6ff}.error{background:#fff0f1;color:#851622}.success{background:#edf9f1;color:#12633d}.hint{margin:16px 0;border:1px solid #c7d7e5;border-radius:9px;padding:7px 13px}.hint summary{cursor:pointer;font-weight:700}label{display:block;font-weight:700;margin-top:16px}input{width:100%;border:2px solid #72889b;border-radius:8px;padding:12px;margin-top:6px;min-height:53px;font:inherit;letter-spacing:.06em}button{width:100%;min-height:53px;margin-top:17px;padding:11px;border:0;border-radius:8px;background:#075bb8;color:#fff;font:700 1rem Arial,Verdana,sans-serif;letter-spacing:.03em;cursor:pointer}button.secondary{background:#e4edf5;color:#123954}button.warn{background:#a64022}button:disabled{opacity:.5;cursor:not-allowed}.row{display:flex;gap:10px}.row button{margin-top:12px}.codes,.logbox{white-space:pre-wrap;background:#142737;color:#f3fbff;border-radius:8px;padding:14px;line-height:1.8;font:16px/1.65 monospace;letter-spacing:.04em;overflow-wrap:anywhere}.qr{display:block;width:280px;height:280px;max-width:100%;margin:18px auto;border:10px solid #fff;image-rendering:pixelated}footer{margin-top:30px;border-top:1px solid #c7d7e5;padding-top:15px}footer h2{font-size:1rem;margin:0 0 8px}
</style></head><body><div class="shell"><header><p class="brand">◈ Example Bank security set-up</p></header><main id="app" aria-live="polite"></main><footer aria-label="Demo logs"><h2>Logs</h2><div id="logs" class="logbox">No demo codes have been sent yet.</div></footer></div>
<script nonce="${nonce}">(()=>{"use strict";
const app=document.querySelector("#app"),logs=document.querySelector("#logs");let csrf="",visibleCodes=[],codesHidden=false,provisionSecret="",provisionUri="",logLines=[];
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const msg=(t,k)=>t?'<div class="'+k+'">'+esc(t)+"</div>":"";
const help=(a,b)=>'<details class="hint"><summary>ⓘ Help and example</summary><p>'+esc(a)+"</p><p>"+esc(b)+"</p></details>";
function demoLog(t){console.log(t);logLines.push(t);logs.textContent=logLines.join("\\n")}
async function api(path,data={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});let d;try{d=await r.json()}catch{throw Error("Please try again.")}if(!r.ok)throw Error(d.error||"Please try again.");return d}
async function copy(t,n){try{await navigator.clipboard.writeText(t);alert(n)}catch{alert("Copy was not available. You can select the text and copy it.")}}

/* Standards-compliant QR Code Model 2, Version 10, error correction level L.
   It byte-encodes the otpauth URI, applies Reed-Solomon ECC, format/version bits,
   data placement, and chooses the lowest-penalty mask. */
function qr(uri){
 const V=10,N=57,DATA=274,ECC=18,A=[6,28,50],M=Array.from({length:N},()=>Array(N).fill(null));
 const put=(x,y,v)=>{if(x>=0&&y>=0&&x<N&&y<N)M[y][x]=v}, finder=(x,y)=>{for(let j=-1;j<8;j++)for(let i=-1;i<8;i++)put(x+i,y+j,i>=0&&i<=6&&j>=0&&j<=6&&(i==0||i==6||j==0||j==6||(i>=2&&i<=4&&j>=2&&j<=4))?1:0)};
 finder(0,0);finder(N-7,0);finder(0,N-7);
 for(let i=8;i<N-8;i++){put(i,6,i%2?0:1);put(6,i,i%2?0:1)}
 for(const y of A)for(const x of A){if(M[y][x]===null)for(let j=-2;j<=2;j++)for(let i=-2;i<=2;i++)put(x+i,y+j,Math.max(Math.abs(i),Math.abs(j))!=1?1:0)}
 put(8,N-8,1);
 const reserve=()=>{for(let i=0;i<9;i++){if(M[8][i]===null)put(8,i,0);if(M[i][8]===null)put(i,8,0)}for(let i=0;i<8;i++){put(N-1-i,8,0);put(8,N-1-i,0)}for(let i=0;i<18;i++){put(N-11+i,0,0);put(0,N-11+i,0)}};reserve();
 const utf=new TextEncoder().encode(uri);if(utf.length>271)throw Error("Setup link is too long for this QR code.");
 let bits=[0,1,0,0];for(let i=15;i>=0;i--)bits.push((utf.length>>i)&1);for(const z of utf)for(let i=7;i>=0;i--)bits.push((z>>i)&1);for(let i=0;i<Math.min(4,DATA*8-bits.length);i++)bits.push(0);while(bits.length%8)bits.push(0);
 let dat=[];for(let i=0;i<bits.length;i+=8)dat.push(parseInt(bits.slice(i,i+8).join(""),2));for(let p=0;dat.length<DATA;p++)dat.push(p%2?0x11:0xec);
 const mul=(a,b)=>{let r=0;while(b){if(b&1)r^=a;b>>=1;a=(a<<1)^((a&128)?285:0)}return r}, pow=(a,n)=>{let r=1;while(n--)r=mul(r,a);return r};
 let gen=[1];for(let i=0;i<ECC;i++){let q=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){q[j]^=gen[j];q[j+1]^=mul(gen[j],pow(2,i))}gen=q}
 const rs=d=>{let r=Array(ECC).fill(0);for(const z of d){let f=z^r.shift();r.push(0);for(let i=0;i<ECC;i++)r[i]^=mul(gen[i+1],f)}return r};
 const blocks=[dat.slice(0,68),dat.slice(68,136),dat.slice(136,205),dat.slice(205)], ec=blocks.map(rs), stream=[];for(let i=0;i<69;i++)for(const b of blocks)if(i<b.length)stream.push(b[i]);for(let i=0;i<ECC;i++)for(const e of ec)stream.push(e[i]);
 let db=[];for(const z of stream)for(let i=7;i>=0;i--)db.push((z>>i)&1);let k=0,up=true;
 for(let x=N-1;x>0;x-=2){if(x==6)x--;for(let q=0;q<N;q++){let y=up?N-1-q:q;for(let dx=0;dx<2;dx++)if(M[y][x-dx]===null)M[y][x-dx]=db[k++]||0}up=!up}
 const base=M.map(r=>r.slice()), fmt=(mask)=>{let d=(1<<3)|mask,v=d<<10;for(let i=14;i>=10;i--)if((v>>i)&1)v^=0x537<<(i-10);return ((d<<10)|v)^0x5412}, version=()=>{let v=V<<12;for(let i=17;i>=12;i--)if((v>>i)&1)v^=0x1f25<<(i-12);return(V<<12)|v};
 const apply=(mask)=>{let z=base.map(r=>r.slice());for(let y=0;y<N;y++)for(let x=0;x<N;x++)if(base[y][x]!==null){let functional=(x<=8&&y<=8)||(x>=N-8&&y<=8)||(x<=8&&y>=N-8)||x==6||y==6||(x>=A[1]-2&&x<=A[1]+2&&y>=A[1]-2&&y<=A[1]+2)||(x>=A[2]-2&&y>=A[1]-2)||(x>=A[1]-2&&y>=A[2]-2);if(!functional){let m=[(x+y)%2==0,y%2==0,x%3==0,(x+y)%3==0,(Math.floor(y/2)+Math.floor(x/3))%2==0,(x*y)%2+(x*y)%3==0,((x*y)%2+(x*y)%3)%2==0,((x+y)%2+(x*y)%3)%2==0][mask];if(m)z[y][x]^=1}}let f=fmt(mask);for(let i=0;i<15;i++){let b=(f>>i)&1;if(i<6)z[i][8]=b;else if(i<8)z[i+1][8]=b;else z[N-15+i][8]=b;if(i<8)z[8][N-i-1]=b;else if(i<9)z[8][15-i]=b;else z[8][15-i-1]=b}let vv=version();for(let i=0;i<18;i++){let b=(vv>>i)&1;z[Math.floor(i/3)][N-11+i%3]=b;z[N-11+i%3][Math.floor(i/3)]=b}return z};
 const score=z=>{let p=0;for(let y=0;y<N;y++)for(let x=0;x<N;x++){let c=z[y][x],run=1;while(x+run<N&&z[y][x+run]===c)run++;if(run>=5)p+=run-2;run=1;while(y+run<N&&z[y+run][x]===c)run++;if(run>=5)p+=run-2;if(x<N-1&&y<N-1&&c===z[y][x+1]&&c===z[y+1][x]&&c===z[y+1][x+1])p+=3}for(let y=0;y<N;y++)for(let x=0;x<N-6;x++){let s="";for(let i=0;i<7;i++)s+=z[y][x+i];if(s=="1011101")p+=40}for(let x=0;x<N;x++)for(let y=0;y<N-6;y++){let s="";for(let i=0;i<7;i++)s+=z[y+i][x];if(s=="1011101")p+=40}let dark=z.flat().filter(Boolean).length;p+=Math.floor(Math.abs(dark*20-N*N*10)/(N*N))*10;return p};
 let best=apply(0),bp=score(best);for(let i=1;i<8;i++){let z=apply(i),p=score(z);if(p<bp){best=z;bp=p}}return best;
}
function renderQr(uri){const c=document.querySelector("#qr"),m=qr(uri),scale=5;c.width=c.height=m.length*scale;const x=c.getContext("2d");x.fillStyle="#fff";x.fillRect(0,0,c.width,c.height);x.fillStyle="#000";m.forEach((r,y)=>r.forEach((v,x1)=>{if(v)x.fillRect(x1*scale,y*scale,scale,scale)}))}
function signIn(note="",kind="error"){visibleCodes=[];app.innerHTML='<p class="step">Step 1 of 4</p><h1>Start security set-up</h1>'+msg(note,kind)+'<p>Enter the email for your bank account.</p>'+help("Example: marcus@example.test","You can try again as often as you need.")+'<form id="f"><label>Email address<input id="email" type="email" autocomplete="email" placeholder="name@example.com" required></label><button>Continue</button></form>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{let d=await api("/api/auth/signin",{email:document.querySelector("#email").value});csrf=d.csrf;owner()}catch(x){signIn(x.message)}}}
function owner(note="",kind="success"){app.innerHTML='<p class="step">Step 1 of 4</p><h1>Confirm your sign-in</h1>'+msg(note,kind)+'<p>We will send a six-number owner approval code to the account email.</p>'+help("Example: 123456","This demo shows the sent code in Logs. In a bank app, it would arrive in your private email.")+'<button id="send" type="button">Send owner approval code</button>';document.querySelector("#send").onclick=async()=>{try{let d=await api("/api/auth/owner");demoLog("[Demo] Owner approval code: "+d.testCode);ownerVerify("An owner approval code was sent. Enter it below.")}catch(x){owner(x.message,"error")}}}
function ownerVerify(note="",kind="success"){app.innerHTML='<p class="step">Step 1 of 4</p><h1>Enter owner approval code</h1>'+msg(note,kind)+'<p>Enter the six numbers from your owner approval message.</p>'+help("Example: 123456","You may request a new code without penalty.")+'<form id="f"><label>Owner approval code<input id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Example: 123456" required></label><button>Confirm and send identity code</button></form>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{let d=await api("/api/auth/owner/verify",{code:document.querySelector("#code").value});csrf=d.csrf;demoLog("[Demo] Identity verification code: "+d.testCode);identity("A six-number identity code was sent.")}catch(x){ownerVerify(x.message,"error")}}}
function identity(note="",kind="success"){app.innerHTML='<p class="step">Step 2 of 4</p><h1>Check it is you</h1>'+msg(note,kind)+'<p>Enter the six-number code from your email.</p>'+help("Example: 123456","The code has six numbers. You may ask for a new code without penalty.")+'<form id="f"><label>Email code<input id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Example: 123456" required></label><button>Verify code</button></form><button class="secondary" id="resend" type="button">Send a new code</button>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{let d=await api("/api/identity/verify",{code:document.querySelector("#code").value});d.enrolled?existing("Identity confirmed. This account already has MFA.") : setup("Identity confirmed. Add your authenticator next.")}catch(x){identity(x.message,"error")}};document.querySelector("#resend").onclick=async()=>{try{let d=await api("/api/identity/resend");demoLog("[Demo] Replacement identity code: "+d.testCode);identity("A new code was sent. The earlier code no longer works.")}catch(x){identity(x.message,"error")}}}
function setup(note="",kind="success"){app.innerHTML='<p class="step">Step 3 of 4</p><h1>Add your authenticator</h1>'+msg(note,kind)+'<p>Scan the working QR code below with an authenticator app. Or copy the setup key.</p>'+help("Authenticator code example: 123456","If scanning is difficult, copy the setup key. You have plenty of time.")+'<canvas id="qr" class="qr" role="img" aria-label="Scannable QR code for authenticator setup"></canvas><label>Setup key<input id="secret" readonly autocomplete="off"></label><button class="secondary" id="copy" type="button">Copy setup key</button><button class="secondary" id="demo" type="button">Reveal demo authenticator code</button><form id="f"><label>Authenticator code<input id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Example: 123456" required></label><button>Verify authenticator</button></form>';document.querySelector("#copy").onclick=()=>copy(provisionSecret,"Setup key copied.");document.querySelector("#demo").onclick=async()=>{let code=await demoTotp(provisionSecret);demoLog("[Demo] Current authenticator code: "+code);document.querySelector("#code").value=code;alert("The current demo code was placed in the box.")};document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{await api("/api/mfa/totp/verify",{code:document.querySelector("#code").value});recovery("Authenticator confirmed. Save recovery codes next.")}catch(x){setup(x.message,"error")}};api("/api/mfa/provision").then(d=>{provisionSecret=d.secret;provisionUri=d.uri;document.querySelector("#secret").value=d.secret;try{renderQr(provisionUri)}catch{setup("The QR picture could not be made. Copy the setup key instead.","error")}}).catch(x=>setup(x.message,"error"))}
function clientB32(s){const a="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";let b=0,v=0,o=[];for(const c of s){v=v<<5|a.indexOf(c);b+=5;if(b>=8){o.push(v>>>(b-8)&255);b-=8}}return new Uint8Array(o)}
async function demoTotp(s){let c=new Uint8Array(8),n=BigInt(Math.floor(Date.now()/30000));for(let i=7;i>=0;i--){c[i]=Number(n&255n);n>>=8n}let k=await crypto.subtle.importKey("raw",clientB32(s),{name:"HMAC",hash:"SHA-1"},false,["sign"]),d=new Uint8Array(await crypto.subtle.sign("HMAC",k,c)),o=d[19]&15,v=((d[o]&127)<<24)|(d[o+1]<<16)|(d[o+2]<<8)|d[o+3];return String(v%1000000).padStart(6,"0")}
function existing(note="",kind="success"){app.innerHTML='<p class="step">Existing MFA account</p><h1>Verify your authenticator</h1>'+msg(note,kind)+'<p>This account already has MFA. Verify an authenticator code or one recovery code to manage recovery codes.</p>'+help("Authenticator example: 123456. Recovery example: ABCD-EFGH.","Use whichever saved method is easier. There is no reading timer.")+'<button id="auth" type="button">Use authenticator code</button><button class="secondary" id="rec" type="button">Use recovery code</button>';document.querySelector("#auth").onclick=existingTotp;document.querySelector("#rec").onclick=existingRecovery}
function existingTotp(note="",kind="success"){app.innerHTML='<p class="step">Existing MFA account</p><h1>Enter authenticator code</h1>'+msg(note,kind)+'<form id="f"><label>Authenticator code<input id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Example: 123456" required></label><button>Verify authenticator</button></form>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{await api("/api/mfa/totp/verify",{code:document.querySelector("#code").value});recoveryStatus("Authenticator confirmed.")}catch(x){existingTotp(x.message,"error")}}}
function existingRecovery(note="",kind="success"){app.innerHTML='<p class="step">Existing MFA account</p><h1>Enter recovery code</h1>'+msg(note,kind)+'<form id="f"><label>Recovery code<input id="code" autocapitalize="characters" spellcheck="false" maxlength="9" autocomplete="one-time-code" placeholder="Example: ABCD-EFGH" required></label><button>Verify recovery code</button></form>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{await api("/api/mfa/recovery/verify",{code:document.querySelector("#code").value.trim().toUpperCase()});recoveryStatus("Recovery code accepted and removed.")}catch(x){existingRecovery(x.message,"error")}}}
function recovery(note="",kind="success"){app.innerHTML='<p class="step">Step 4 of 4</p><h1>Save recovery codes</h1>'+msg(note,kind)+'<p>Recovery codes are for when you cannot use your authenticator. Each code works once.</p>'+help("Example: ABCD-EFGH","Keep these somewhere safe. You can make a replacement set later.")+'<button id="show" type="button">Show recovery codes</button>';document.querySelector("#show").onclick=async()=>{try{let d=await api("/api/mfa/recovery/generate");visibleCodes=d.codes;demoLog("[Demo] Recovery codes: "+visibleCodes.join(", "));codesView("Your recovery codes are ready.")}catch(x){recovery(x.message,"error")}}}
function recoveryStatus(note="",kind="success"){api("/api/mfa/recovery/status").then(d=>{app.innerHTML='<p class="step">Recovery code status</p><h1>Your recovery codes</h1>'+msg(note,kind)+'<p>You have <strong>'+esc(d.remaining)+'</strong> recovery codes left.</p>'+help("Example: ABCD-EFGH","Replacement makes every old recovery code stop working immediately.")+'<button class="warn" id="replace" type="button">Replace recovery codes</button>';document.querySelector("#replace").onclick=replaceCodes}).catch(x=>existing(x.message,"error"))}
function codesView(note="",kind="success"){const shown=!codesHidden&&visibleCodes.length,text=shown?visibleCodes.map(esc).join("\\n"):"Codes hidden. Reveal codes only when you are somewhere private.";app.innerHTML='<p class="step">Step 4 of 4</p><h1>Your recovery codes</h1>'+msg(note,kind)+'<p>Save these now. They stay only in this page memory until you leave this flow.</p><pre class="codes">'+text+'</pre><div class="row"><button class="secondary" id="hide" type="button" '+(!shown?"disabled":"")+'>Hide codes</button><button class="secondary" id="copy" type="button" '+(!shown?"disabled":"")+'>Copy all</button></div>'+(!shown?'<button id="reveal" type="button">Reveal codes</button>':"")+'<button class="warn" id="replace" type="button">Replace recovery codes</button>';document.querySelector("#hide").onclick=()=>{codesHidden=true;codesView("Codes are hidden.")};document.querySelector("#copy").onclick=()=>copy(visibleCodes.join("\\n"),"Recovery codes copied.");let r=document.querySelector("#reveal");if(r)r.onclick=()=>{codesHidden=false;codesView("Your saved codes are shown again.")};document.querySelector("#replace").onclick=replaceCodes}
function replaceCodes(note="",kind="error"){app.innerHTML='<p class="step">Recovery code replacement</p><h1>Replace your codes?</h1>'+msg(note,kind)+'<div class="notice">Your current recovery codes will stop working immediately. Save the new set before leaving.</div><button class="warn" id="yes" type="button">Yes, replace my codes</button><button class="secondary" id="no" type="button">Cancel</button>';document.querySelector("#yes").onclick=async()=>{try{let d=await api("/api/mfa/recovery/regenerate",{confirm:true});visibleCodes=d.codes;codesHidden=false;demoLog("[Demo] Replacement recovery codes: "+visibleCodes.join(", "));codesView("Old codes were replaced. Save this new set now.")}catch(x){replaceCodes(x.message,"error")}};document.querySelector("#no").onclick=()=>recoveryStatus("Your existing codes were kept.")}
signIn()})();</script></body></html>`;
}
function html() { const n = token(16), r = new Response(page(n), { headers: headers(n) }); r.headers.set("Content-Type", "text/html; charset=utf-8"); return r; }

async function handle(req: Request): Promise<Response> {
 try {
  const url = new URL(req.url);
  if (!originOK(req)) return reply({ error: "Request not allowed." }, 403, req);
  if (req.method === "GET" && url.pathname === "/") return html();
  if (req.method !== "POST") return reply({ error: "Not found." }, 404, req);
  const input = await body(req); if (!input) return reply({ error: "Please check the form and try again." }, 400, req);

  if (url.pathname === "/api/auth/signin") {
   await delay(); const email = typeof input.email === "string" ? input.email.trim().toLowerCase() : "";
   if (!safeEmail(email) || email !== USER.email) return reply({ error: "We could not start sign-in. Check the email address and try again." }, 401, req);
   const old = cookie(req, "mfa_session"); if (old) sessions.delete(old);
   const s = makeSession(email), r = reply({ csrf: s.csrf }, 200, req); r.headers.set("Set-Cookie", sessionCookie(s.id)); return r;
  }
  const s = auth(req); if (!s) return reply({ error: "Please sign in again." }, 401, req);
  if (!validCsrf(req, s)) return reply({ error: "This request could not be confirmed. Refresh and try again." }, 403, req);

  if (url.pathname === "/api/auth/owner") {
   if (s.signInEmail !== USER.email) return reply({ error: "Please start sign-in again." }, 403, req);
   const st = stateFor(USER.id), a = attempt(st, "owner"); if (a.lockedUntil > Date.now()) return reply({ error: lock("sign-in") }, 429, req);
   s.ownerChallenge = newChallenge(); return reply({ testCode: s.ownerChallenge.value }, 200, req);
  }
  if (url.pathname === "/api/auth/owner/verify") {
   const st = stateFor(USER.id), a = attempt(st, "owner"), c = s.ownerChallenge;
   if (!safeOtp(input.code) || a.lockedUntil > Date.now() || !c || c.used || c.expires < Date.now() || c.value !== input.code) {
    const locked = a.lockedUntil > Date.now() || fail(st, "owner"); return reply({ error: locked ? lock("sign-in") : "That owner approval code does not match. Send a new code and try again." }, locked ? 429 : 400, req);
   }
   c.used = true; pass(st, "owner"); sessions.delete(s.id); const x = makeSession(undefined, USER.id); x.identityChallenge = newChallenge();
   const r = reply({ csrf: x.csrf, testCode: x.identityChallenge.value }, 200, req); r.headers.set("Set-Cookie", sessionCookie(x.id)); return r;
  }
  if (!s.userId || s.userId !== USER.id) return reply({ error: "Please sign in again." }, 401, req);
  const st = stateFor(s.userId);

  if (url.pathname === "/api/identity/resend") { const a = attempt(st, "identity"); if (a.lockedUntil > Date.now()) return reply({ error: lock("identity check") }, 429, req); s.identityChallenge = newChallenge(); return reply({ testCode: s.identityChallenge.value }, 200, req); }
  if (url.pathname === "/api/identity/verify") {
   const a = attempt(st, "identity"), c = s.identityChallenge;
   if (!safeOtp(input.code) || a.lockedUntil > Date.now() || !c || c.used || c.expires < Date.now() || c.value !== input.code) { const locked = a.lockedUntil > Date.now() || fail(st, "identity"); return reply({ error: locked ? lock("identity check") : "That code does not match. Check the six numbers or send a new code." }, locked ? 429 : 400, req); }
   c.used = true; s.identityVerified = true; pass(st, "identity"); return reply({ enrolled: st.enrolled }, 200, req);
  }
  if (!s.identityVerified) return reply({ error: "Complete the identity check before changing MFA settings." }, 403, req);

  if (url.pathname === "/api/mfa/provision") {
   if (st.enrolled) return reply({ error: "An authenticator is already enrolled for this account." }, 409, req);
   if (!st.encryptedSecret) { st.encryptedSecret = await encrypt(base32Secret()); await saveStore(); }
   const secret = await decrypt(st.encryptedSecret), label = encodeURIComponent(`Example Bank:${USER.email}`);
   return reply({ secret, uri: `otpauth://totp/${label}?secret=${secret}&issuer=Example%20Bank&algorithm=SHA1&digits=6&period=30` }, 200, req);
  }
  if (url.pathname === "/api/mfa/totp/verify") {
   const a = attempt(st, "totp"); if (!safeOtp(input.code) || a.lockedUntil > Date.now() || !st.encryptedSecret) return reply({ error: a.lockedUntil > Date.now() ? lock("authenticator") : "Enter the six numbers from your authenticator." }, a.lockedUntil > Date.now() ? 429 : 400, req);
   const secret = await decrypt(st.encryptedSecret), base = Math.floor(Date.now() / 30_000); let accepted = -1;
   for (const step of [base - 1, base, base + 1]) if (!st.acceptedSteps.includes(step) && await totp(secret, step) === input.code) { accepted = step; break; }
   if (accepted < 0) { const locked = fail(st, "totp"); return reply({ error: locked ? lock("authenticator") : "That authenticator code cannot be used. Check it and try again." }, locked ? 429 : 400, req); }
   st.acceptedSteps = [...st.acceptedSteps, accepted].slice(-100); st.enrolled = true; s.mfaVerified = true; pass(st, "totp"); await saveStore(); return reply({ ok: true }, 200, req);
  }
  if (url.pathname === "/api/mfa/recovery/status") {
   if (!s.mfaVerified || !st.enrolled) return reply({ error: "Verify your authenticator or a recovery code first." }, 403, req);
   return reply({ remaining: st.recoveryHashes.length }, 200, req);
  }

  /* Exact route matching: generation and regeneration are distinct endpoints. */
  if (url.pathname === "/api/mfa/recovery/generate") {
   if (!s.mfaVerified || !st.enrolled) return reply({ error: "Verify your authenticator or a recovery code first, then create recovery codes." }, 403, req);
   if (st.recoveryHashes.length) return reply({ error: "Recovery codes already exist. Use replacement only if you need a new set." }, 409, req);
   return reply({ codes: await generateRecovery(st) }, 200, req);
  }
  if (url.pathname === "/api/mfa/recovery/regenerate") {
   if (!s.mfaVerified || !st.enrolled) return reply({ error: "Verify your authenticator or a recovery code first, then replace recovery codes." }, 403, req);
   if (input.confirm !== true) return reply({ error: "Confirm that you want to replace the old codes." }, 400, req);
   return reply({ codes: await generateRecovery(st) }, 200, req);
  }
  if (url.pathname === "/api/mfa/recovery/verify") {
   if (!st.enrolled) return reply({ error: "MFA has not been enrolled for this account." }, 403, req);
   const a = attempt(st, "recovery"); if (a.lockedUntil > Date.now()) return reply({ error: lock("recovery code") }, 429, req);
   const code = typeof input.code === "string" ? input.code.trim().toUpperCase() : "", digest = safeRecovery(code) ? await hash(code) : "", i = st.recoveryHashes.indexOf(digest);
   if (i < 0) { const locked = fail(st, "recovery"); return reply({ error: locked ? lock("recovery code") : "That recovery code cannot be used. Check the format ABCD-EFGH and try another saved code." }, locked ? 429 : 400, req); }
   st.recoveryHashes.splice(i, 1); s.mfaVerified = true; pass(st, "recovery"); await saveStore(); return reply({ ok: true }, 200, req);
  }
  if (url.pathname === "/api/auth/logout") { sessions.delete(s.id); const r = reply({ ok: true }, 200, req); r.headers.set("Set-Cookie", "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"); return r; }
  return reply({ error: "Not found." }, 404, req);
 } catch { return reply({ error: "Something went wrong. Please try again." }, 500, req); }
}

/* Requirement 2/3: local mkcert TLS certificates protect the Bun server. */
Bun.serve({ hostname: "0.0.0.0", port: PORT, tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") }, fetch: handle });
