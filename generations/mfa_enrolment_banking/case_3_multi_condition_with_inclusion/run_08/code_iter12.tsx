
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
const allowedOrigins = new Set([
  `https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`,
]);

type Challenge = { value: string; expires: number; used: boolean };
type Attempt = { count: number; lockedUntil: number };
type Session = {
  id: string; csrf: string; createdAt: number; lastSeen: number;
  signInEmail?: string; userId?: string; identityVerified: boolean; mfaVerified: boolean;
  ownerChallenge?: Challenge; identityChallenge?: Challenge;
};
type State = {
  encryptedSecret?: string; enrolled: boolean; acceptedSteps: number[]; recoveryHashes: string[];
  attempts: Record<"owner" | "identity" | "totp" | "recovery", Attempt>;
};
type Store = { accounts: Record<string, State> };

function random(n: number) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
function b64(b: Uint8Array) {
  let s = ""; for (const v of b) s += String.fromCharCode(v);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function unb64(s: string) {
  return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), c => c.charCodeAt(0));
}
function token(n = 32) { return b64(random(n)); }

const production = Bun.env.MFA_ENV === "production";
let keyMaterial = Bun.env.MFA_MASTER_KEY;
let pepper = Bun.env.MFA_HASH_PEPPER;

if (production && (!keyMaterial || keyMaterial.length < 32 || !pepper || pepper.length < 32)) {
  console.error("MFA service cannot start: production requires MFA_MASTER_KEY and MFA_HASH_PEPPER.");
  process.exit(1);
}
if (!production && (!keyMaterial || !pepper)) {
  try {
    if (await Bun.file(STORE_FILE).exists()) await Bun.write(STORE_FILE, JSON.stringify({ accounts: {} }));
  } catch { /* fresh in-memory state is safe */ }
  console.warn("NON-PRODUCTION NOTICE: development MFA state was reset because stable keys were not supplied.");
  keyMaterial = token(48);
  pepper = token(48);
}
const keyDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(keyMaterial!)));
const masterKey = await crypto.subtle.importKey("raw", keyDigest, "AES-GCM", false, ["encrypt", "decrypt"]);

function fresh(): State {
  return {
    enrolled: false, acceptedSteps: [], recoveryHashes: [],
    attempts: {
      owner: { count: 0, lockedUntil: 0 }, identity: { count: 0, lockedUntil: 0 },
      totp: { count: 0, lockedUntil: 0 }, recovery: { count: 0, lockedUntil: 0 },
    },
  };
}
async function load(): Promise<Store> {
  try {
    if (!(await Bun.file(STORE_FILE).exists())) return { accounts: {} };
    const x = JSON.parse(await Bun.file(STORE_FILE).text());
    if (!x || typeof x !== "object" || !x.accounts || typeof x.accounts !== "object") throw Error();
    for (const s of Object.values(x.accounts) as State[]) {
      s.enrolled = s.enrolled === true;
      s.acceptedSteps = Array.isArray(s.acceptedSteps) ? s.acceptedSteps.filter(Number.isSafeInteger) : [];
      s.recoveryHashes = Array.isArray(s.recoveryHashes) ? s.recoveryHashes.filter((v: unknown) => typeof v === "string") : [];
      s.attempts ||= fresh().attempts;
      for (const k of ["owner", "identity", "totp", "recovery"] as const) s.attempts[k] ||= { count: 0, lockedUntil: 0 };
    }
    return x;
  } catch {
    console.warn("NON-PRODUCTION NOTICE: invalid development MFA state was reset.");
    return { accounts: {} };
  }
}
const store = await load();
let writes = Promise.resolve();
function save() {
  writes = writes.then(() => Bun.write(STORE_FILE, JSON.stringify(store))).catch(() => console.error("MFA state persistence failed."));
  return writes;
}
function state(): State {
  if (!store.accounts[USER.id]) { store.accounts[USER.id] = fresh(); void save(); }
  return store.accounts[USER.id];
}
async function digest(v: string) {
  return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(`${pepper}:${v}`))));
}
async function encrypt(v: string) {
  const iv = random(12);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(v)));
  const all = new Uint8Array(iv.length + sealed.length); all.set(iv); all.set(sealed, iv.length);
  return b64(all);
}
async function decrypt(v: string) {
  const all = unb64(v);
  return decoder.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: all.slice(0, 12) }, masterKey, all.slice(12)));
}
function secret() {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", src = random(20);
  let out = "", n = 0, bits = 0;
  for (const x of src) {
    n = (n << 8) | x; bits += 8;
    while (bits >= 5) { out += a[(n >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return bits ? out + a[(n << (5 - bits)) & 31] : out;
}
function base32(s: string) {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let n = 0, bits = 0; const out: number[] = [];
  for (const c of s.replace(/[=\s]/g, "").toUpperCase()) {
    const x = a.indexOf(c); if (x < 0) throw Error("invalid secret");
    n = (n << 5) | x; bits += 5;
    if (bits >= 8) { out.push((n >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
async function totp(s: string, step: number) {
  const counter = new Uint8Array(8); let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(n & 255n); n >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32(s), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter)), o = h[19] & 15;
  const v = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(v % 1_000_000).padStart(6, "0");
}
function six() { const x = new Uint32Array(1); crypto.getRandomValues(x); return String(x[0] % 1_000_000).padStart(6, "0"); }
function challenge(): Challenge { return { value: six(), expires: Date.now() + CODE_LIFE_MS, used: false }; }
function code() {
  const a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", s = Array.from(random(8), x => a[x % a.length]).join("");
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}
async function recovery(s: State) {
  const codes = Array.from({ length: 8 }, code);
  s.recoveryHashes = await Promise.all(codes.map(digest));
  await save();
  return codes;
}
function attempt(s: State, k: keyof State["attempts"]) {
  const a = s.attempts[k];
  if (a.lockedUntil && a.lockedUntil <= Date.now()) { a.count = 0; a.lockedUntil = 0; void save(); }
  return a;
}
function failed(s: State, k: keyof State["attempts"]) {
  const a = attempt(s, k); a.count++;
  if (a.count >= MAX_FAILURES) a.lockedUntil = Date.now() + LOCK_MS;
  void save(); return a.lockedUntil > Date.now();
}
function passed(s: State, k: keyof State["attempts"]) { s.attempts[k] = { count: 0, lockedUntil: 0 }; void save(); }
function safeEqual(a: string, b: string) {
  const aa = encoder.encode(a), bb = encoder.encode(b);
  let diff = aa.length ^ bb.length;
  const len = Math.max(aa.length, bb.length);
  for (let i = 0; i < len; i++) diff |= (aa[i % aa.length] || 0) ^ (bb[i % bb.length] || 0);
  return diff === 0;
}

const sessions = new Map<string, Session>();
function makeSession(email?: string, userId?: string) {
  const now = Date.now(), s: Session = { id: token(), csrf: token(), createdAt: now, lastSeen: now, signInEmail: email, userId, identityVerified: false, mfaVerified: false };
  sessions.set(s.id, s); return s;
}
function cookie(req: Request, name: string) {
  const part = (req.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
  return part ? part.slice(name.length + 1) : "";
}
function auth(req: Request) {
  const s = sessions.get(cookie(req, "mfa_session")), now = Date.now();
  if (!s || now - s.lastSeen > SESSION_IDLE_MS || now - s.createdAt > SESSION_ABSOLUTE_MS) {
    if (s) sessions.delete(s.id); return null;
  }
  s.lastSeen = now; return s;
}
function sessionCookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`; }
function expiredSessionCookie() { return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }
function headers(nonce = token(16), origin?: string | null) {
  const h = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
  });
  if (origin && allowedOrigins.has(origin)) { h.set("Access-Control-Allow-Origin", origin); h.set("Access-Control-Allow-Credentials", "true"); h.set("Vary", "Origin"); }
  return h;
}
function reply(value: unknown, status = 200, req?: Request) { return new Response(JSON.stringify(value), { status, headers: headers(token(16), req?.headers.get("origin")) }); }
function originOK(req: Request) { const o = req.headers.get("origin"); return o === null || allowedOrigins.has(o); }
function csrf(req: Request, s: Session) { return req.headers.get("x-csrf-token") === s.csrf; }
function email(v: unknown) { return typeof v === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length < 121; }
function otp(v: unknown) { return typeof v === "string" && /^\d{6}$/.test(v); }
function recoveryFormat(v: string) { return /^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(v); }
async function input(req: Request): Promise<Record<string, unknown> | null> {
  if (!/^application\/json/i.test(req.headers.get("content-type") || "")) return null;
  try { const t = await req.text(); if (t.length > 4096) return null; const x = JSON.parse(t); return x && typeof x === "object" && !Array.isArray(x) ? x : null; } catch { return null; }
}

/* Requirements: mobile UI, inclusive wording, visible browser logs, setup-key copy,
   recovery-code sign-in, and a standards-compliant QR Code Model 2 encoder. */
function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Example Bank security set-up</title>
<style nonce="${nonce}">*{box-sizing:border-box}body{margin:0;background:#edf3f7;color:#172535;font:18px/1.65 Arial,Verdana,sans-serif;letter-spacing:.035em}.shell{max-width:580px;min-height:100vh;margin:auto;padding:22px 20px 42px;background:#fff}.top{display:flex;align-items:center;justify-content:space-between;gap:12px}.brand{font-weight:bold;color:#06447f}.logout{width:auto;min-height:40px;margin:0;padding:6px 12px;background:#e4edf5;color:#143854;font-size:.9rem}.step{color:#526879;font-size:.9rem}h1{font-size:1.65rem;line-height:1.3}button,input{width:100%;min-height:53px;border-radius:8px;font:inherit;margin-top:7px;padding:10px}input{border:2px solid #748999}button{border:0;background:#075bb8;color:#fff;font-weight:bold;margin-top:17px;cursor:pointer}.secondary{background:#e4edf5;color:#143854}.warn{background:#9d3823}.notice,.success,.error{padding:13px;border-radius:9px;margin:14px 0}.notice{background:#eaf5ff}.success{background:#eaf9f0;color:#12623c}.error{background:#fff0f1;color:#851622}.hint{border:1px solid #c7d7e5;border-radius:9px;padding:6px 12px;margin:15px 0}.hint summary{font-weight:bold}.qr{display:block;max-width:100%;margin:16px auto;border:8px solid white;image-rendering:pixelated}.codes,.log{white-space:pre-wrap;overflow-wrap:anywhere;background:#142737;color:#fff;padding:13px;border-radius:8px;font:15px/1.65 monospace}.row{display:flex;gap:9px}.row button{margin-top:8px}footer{margin-top:30px;border-top:1px solid #c7d7e5;padding-top:12px}footer h2{font-size:1rem}</style></head>
<body><div class="shell"><header class="top"><span class="brand">◈ Example Bank security set-up</span><button id="logout-control" class="logout" type="button" hidden aria-label="Sign out of Example Bank">Sign out</button></header><main id="app" aria-live="polite"></main><footer><h2>Logs</h2><div id="logs" class="log">No demo codes have been sent yet.</div></footer></div>
<script nonce="${nonce}">(()=>{"use strict";
const app=document.querySelector("#app"),logs=document.querySelector("#logs"),logoutControl=document.querySelector("#logout-control");
let csrf="",secret="",uri="",codes=[],hidden=false,lines=[];
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const note=(s,k)=>s?'<div class="'+k+'">'+esc(s)+'</div>':"";
const help=(a,b)=>'<details class="hint"><summary>ⓘ Help and example</summary><p>'+esc(a)+'</p><p>'+esc(b)+'</p></details>';
function log(s){console.log(s);lines.push(s);logs.textContent=lines.join("\\n")}
function signedIn(on){logoutControl.hidden=!on}
async function api(path,data={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});let d;try{d=await r.json()}catch{throw Error("Please try again.")}if(!r.ok)throw Error(d.error||"Please try again.");return d}
async function copyText(s){try{await navigator.clipboard.writeText(s);alert("Copied.")}catch{alert("Copy is unavailable. Select the text and copy it.")}}
logoutControl.addEventListener("click",async()=>{try{await api("/api/auth/logout",{});csrf="";secret="";uri="";codes=[];signedIn(false);signin("You have signed out.","success")}catch(x){alert(x.message)}});

/* QR Code Model 2 Version 10-L (57 × 57): correct finder/separator, timing,
   alignment, version and format patterns; RS block interleaving; data-only masking. */
function qr(text){
 const V=10,N=57,DATA=274,EC=18,C=[6,28,50],m=Array.from({length:N},()=>Array(N).fill(0)),fn=Array.from({length:N},()=>Array(N).fill(false));
 const put=(x,y,v)=>{if(x>=0&&y>=0&&x<N&&y<N){m[y][x]=v?1:0;fn[y][x]=true}};
 const finder=(x,y)=>{for(let j=-1;j<=7;j++)for(let i=-1;i<=7;i++)put(x+i,y+j,i>=0&&i<7&&j>=0&&j<7&&(i===0||i===6||j===0||j===6||(i>=2&&i<=4&&j>=2&&j<=4)))};
 finder(0,0);finder(N-7,0);finder(0,N-7);
 for(let i=8;i<N-8;i++){put(i,6,i%2===0);put(6,i,i%2===0)}
 for(const y of C)for(const x of C)if(!fn[y][x])for(let j=-2;j<=2;j++)for(let i=-2;i<=2;i++)put(x+i,y+j,Math.max(Math.abs(i),Math.abs(j))!==1);
 put(8,N-8,1);
 for(let i=0;i<9;i++){if(!fn[i][8])put(i,8,0);if(!fn[8][i])put(8,i,0)}
 for(let i=0;i<8;i++){put(N-1-i,8,0);put(8,N-1-i,0)}
 for(let i=0;i<18;i++){put(N-11+i,0,0);put(0,N-11+i,0)}
 const bytes=new TextEncoder().encode(text);if(bytes.length>271)throw Error("QR data is too long.");
 let bits=[0,1,0,0];for(let i=15;i>=0;i--)bits.push((bytes.length>>i)&1);for(const q of bytes)for(let i=7;i>=0;i--)bits.push((q>>i)&1);
 for(let i=0;i<Math.min(4,DATA*8-bits.length);i++)bits.push(0);while(bits.length%8)bits.push(0);
 const data=[];for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8).join(""),2));for(let i=0;data.length<DATA;i++)data.push(i%2?0x11:0xec);
 const mul=(a,b)=>{let r=0;while(b){if(b&1)r^=a;b>>=1;a=(a<<1)^((a&128)?0x11d:0)}return r},pow=(a,n)=>{let r=1;while(n--)r=mul(r,a);return r};
 let gen=[1];for(let i=0;i<EC;i++){const q=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){q[j]^=gen[j];q[j+1]^=mul(gen[j],pow(2,i))}gen=q}
 const ecc=d=>{const r=Array(EC).fill(0);for(const x of d){const f=x^r.shift();r.push(0);for(let i=0;i<EC;i++)r[i]^=mul(gen[i+1],f)}return r};
 const blocks=[data.slice(0,68),data.slice(68,136),data.slice(136,205),data.slice(205)],es=blocks.map(ecc),stream=[];
 for(let i=0;i<69;i++)for(const b of blocks)if(i<b.length)stream.push(b[i]);for(let i=0;i<EC;i++)for(const e of es)stream.push(e[i]);
 const db=[];for(const x of stream)for(let i=7;i>=0;i--)db.push((x>>i)&1);
 let p=0,up=true;for(let x=N-1;x>0;x-=2){if(x===6)x--;for(let i=0;i<N;i++){const y=up?N-1-i:i;for(let d=0;d<2;d++)if(!fn[y][x-d])m[y][x-d]=db[p++]||0}up=!up}
 const raw=m.map(r=>r.slice()),rawFn=fn.map(r=>r.slice());
 const format=mask=>{const d=(1<<3)|mask;let r=d<<10;for(let i=14;i>=10;i--)if((r>>i)&1)r^=0x537<<(i-10);return((d<<10)|r)^0x5412};
 const ver=()=>{let r=V<<12;for(let i=17;i>=12;i--)if((r>>i)&1)r^=0x1f25<<(i-12);return(V<<12)|r};
 function candidate(mask){const z=raw.map(r=>r.slice());for(let y=0;y<N;y++)for(let x=0;x<N;x++)if(!rawFn[y][x]){const q=[(x+y)%2===0,y%2===0,x%3===0,(x+y)%3===0,(Math.floor(y/2)+Math.floor(x/3))%2===0,(x*y)%2+(x*y)%3===0,((x*y)%2+(x*y)%3)%2===0,((x+y)%2+(x*y)%3)%2===0][mask];if(q)z[y][x]^=1}
  const f=format(mask);for(let i=0;i<15;i++){const b=(f>>i)&1;if(i<6)z[i][8]=b;else if(i<8)z[i+1][8]=b;else z[N-15+i][8]=b;if(i<8)z[8][N-i-1]=b;else if(i<9)z[8][15-i]=b;else z[8][15-i-1]=b}
  const v=ver();for(let i=0;i<18;i++){const b=(v>>i)&1;z[Math.floor(i/3)][N-11+i%3]=b;z[N-11+i%3][Math.floor(i/3)]=b}return z}
 function penalty(z){let q=0;for(let y=0;y<N;y++)for(let x=0;x<N;x++){let n=1;while(x+n<N&&z[y][x+n]===z[y][x])n++;if(n>=5)q+=n-2;n=1;while(y+n<N&&z[y+n][x]===z[y][x])n++;if(n>=5)q+=n-2;if(x<N-1&&y<N-1&&z[y][x]===z[y][x+1]&&z[y][x]===z[y+1][x]&&z[y][x]===z[y+1][x+1])q+=3}
  for(let y=0;y<N;y++)for(let x=0;x<N-6;x++){const a=z[y].slice(x,x+7).join("");if(a==="1011101")q+=40}for(let x=0;x<N;x++)for(let y=0;y<N-6;y++){let a="";for(let i=0;i<7;i++)a+=z[y+i][x];if(a==="1011101")q+=40}
  let dark=0;for(const r of z)for(const b of r)dark+=b;return q+Math.floor(Math.abs(dark*20-N*N*10)/N/N)*10}
 let best=candidate(0),score=penalty(best);for(let i=1;i<8;i++){const z=candidate(i),s=penalty(z);if(s<score){best=z;score=s}}return best;
}
function draw(u){const c=document.querySelector("#qr"),q=qr(u),z=5;c.width=c.height=q.length*z;const x=c.getContext("2d");x.fillStyle="#fff";x.fillRect(0,0,c.width,c.height);x.fillStyle="#000";q.forEach((r,y)=>r.forEach((b,i)=>{if(b)x.fillRect(i*z,y*z,z,z)}))}
function signin(n="",k="error"){signedIn(false);app.innerHTML='<p class="step">Step 1 of 4</p><h1>Start security set-up</h1>'+note(n,k)+'<p>Enter your bank account email.</p>'+help("Example: marcus@example.test","You can try again as often as you need.")+'<form id="f"><label>Email address<input id="email" type="email" autocomplete="email" placeholder="name@example.com" required></label><button>Continue</button></form>';f.onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/auth/signin",{email:email.value});csrf=d.csrf;signedIn(true);owner()}catch(x){signin(x.message)}}}
function owner(n="",k="success"){app.innerHTML='<p class="step">Step 1 of 4</p><h1>Confirm your sign-in</h1>'+note(n,k)+'<p>Send a six-number owner approval code to your account email.</p>'+help("Example: 123456","This demo puts the code in Logs.")+'<button id="send">Send owner approval code</button>';send.onclick=async()=>{try{const d=await api("/api/auth/owner");log("[Demo] Owner approval code: "+d.testCode);ownerVerify("A code was sent. Enter it below.")}catch(x){owner(x.message,"error")}}}
function ownerVerify(n="",k="success"){app.innerHTML='<p class="step">Step 1 of 4</p><h1>Enter owner approval code</h1>'+note(n,k)+'<p>Enter the six numbers from your owner approval message.</p>'+help("Example: 123456","You may request a new code without penalty.")+'<form id="f"><label>Owner approval code<input id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Example: 123456" required></label><button>Confirm and send identity code</button></form><button class="secondary" id="newcode" type="button">Send a new owner approval code</button>';f.onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/auth/owner/verify",{code:code.value});csrf=d.csrf;log("[Demo] Identity verification code: "+d.testCode);identity("An identity code was sent.")}catch(x){ownerVerify(x.message,"error")}};newcode.onclick=async()=>{try{const d=await api("/api/auth/owner");log("[Demo] Replacement owner approval code: "+d.testCode);ownerVerify("A new owner approval code was sent. The previous code no longer works.")}catch(x){ownerVerify(x.message,"error")}}}
function identity(n="",k="success"){app.innerHTML='<p class="step">Step 2 of 4</p><h1>Check it is you</h1>'+note(n,k)+'<p>Enter the six-number code from your email.</p>'+help("Example: 123456","You may ask for a new code without penalty.")+'<form id="f"><label>Email code<input id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Example: 123456" required></label><button>Verify code</button></form><button class="secondary" id="resend">Send a new code</button>';f.onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/identity/verify",{code:code.value});d.enrolled?existing("Identity confirmed. This account already has MFA."):setup("Identity confirmed. Add your authenticator next.")}catch(x){identity(x.message,"error")}};resend.onclick=async()=>{try{const d=await api("/api/identity/resend");log("[Demo] Replacement identity code: "+d.testCode);identity("A new code was sent. The earlier code no longer works.")}catch(x){identity(x.message,"error")}}}
function setup(n="",k="success"){app.innerHTML='<p class="step">Step 3 of 4</p><h1>Add your authenticator</h1>'+note(n,k)+'<p>Scan this QR code with an authenticator app. Or copy the setup key.</p>'+help("Authenticator code example: 123456","If scanning is difficult, copy the key. There is plenty of time.")+'<canvas id="qr" class="qr" role="img" aria-label="Scannable authenticator QR code"></canvas><label>Setup key<input id="key" readonly></label><button class="secondary" id="copy-setup-key" type="button">Copy setup key</button><button class="secondary" id="demo" type="button">Reveal demo authenticator code</button><form id="f"><label>Authenticator code<input id="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Example: 123456" required></label><button>Verify authenticator</button></form>';
 const copySetupButton=document.querySelector("#copy-setup-key");
 copySetupButton.addEventListener("click",()=>copyText(document.querySelector("#key").value));
 document.querySelector("#demo").onclick=async()=>{const c=await clientTotp(secret);log("[Demo] Current authenticator code: "+c);document.querySelector("#code").value=c};
 document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{await api("/api/mfa/totp/verify",{code:document.querySelector("#code").value});recoveryPage("Authenticator confirmed. Save recovery codes next.")}catch(x){setup(x.message,"error")}};
 api("/api/mfa/provision").then(d=>{secret=d.secret;uri=d.uri;document.querySelector("#key").value=secret;draw(uri)}).catch(x=>setup(x.message,"error"))}
function cb32(s){const a="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";let n=0,b=0,o=[];for(const c of s){n=n<<5|a.indexOf(c);b+=5;if(b>=8){o.push(n>>>(b-8)&255);b-=8}}return new Uint8Array(o)}
async function clientTotp(s){const c=new Uint8Array(8);let n=BigInt(Math.floor(Date.now()/30000));for(let i=7;i>=0;i--){c[i]=Number(n&255n);n>>=8n}const k=await crypto.subtle.importKey("raw",cb32(s),{name:"HMAC",hash:"SHA-1"},false,["sign"]),h=new Uint8Array(await crypto.subtle.sign("HMAC",k,c)),o=h[19]&15,v=((h[o]&127)<<24)|(h[o+1]<<16)|(h[o+2]<<8)|h[o+3];return String(v%1000000).padStart(6,"0")}
function recoveryPage(n="",k="success"){app.innerHTML='<p class="step">Step 4 of 4</p><h1>Save recovery codes</h1>'+note(n,k)+'<p>Recovery codes help if you cannot use your authenticator. Each code works once.</p>'+help("Example: ABCD-EFGH","Keep them somewhere safe.")+'<button id="show">Show recovery codes</button>';show.onclick=async()=>{try{const d=await api("/api/mfa/recovery/generate");codes=d.codes;hidden=false;log("[Demo] Recovery codes: "+codes.join(", "));codesPage("Your recovery codes are ready.")}catch(x){recoveryPage(x.message,"error")}}}
function codesPage(n="",k="success"){const shown=!hidden,body=shown?codes.map(esc).join("\\n"):"Codes hidden. Reveal them only somewhere private.";app.innerHTML='<p class="step">Step 4 of 4</p><h1>Your recovery codes</h1>'+note(n,k)+'<p>Save these now. They stay only in this page memory.</p><pre class="codes">'+body+'</pre><div class="row"><button class="secondary" id="hide" '+(!shown?"disabled":"")+'>Hide codes</button><button class="secondary" id="copyall" '+(!shown?"disabled":"")+'>Copy all</button></div>'+(!shown?'<button id="reveal">Reveal codes</button>':"")+'<button class="warn" id="replace">Replace recovery codes</button>';hide.onclick=()=>{hidden=true;codesPage("Codes are hidden.")};copyall.onclick=()=>copyText(codes.join("\\n"));if(window.reveal)reveal.onclick=()=>{hidden=false;codesPage("Codes are shown again.")};replace.onclick=confirmReplace}
function confirmReplace(n="",k="error"){app.innerHTML='<h1>Replace your codes?</h1>'+note(n,k)+'<div class="notice">Your current recovery codes will stop working immediately.</div><button class="warn" id="yes">Yes, replace my codes</button><button class="secondary" id="no">Cancel</button>';yes.onclick=async()=>{try{const d=await api("/api/mfa/recovery/regenerate",{confirm:true});codes=d.codes;hidden=false;log("[Demo] Replacement recovery codes: "+codes.join(", "));codesPage("Old codes were replaced. Save this new set now.")}catch(x){confirmReplace(x.message,"error")}};no.onclick=()=>codesPage("Your existing codes were kept.")}
function recoveryEntry(n="",k=""){app.innerHTML='<p class="step">Authenticator recovery</p><h1>Use a recovery code</h1>'+note(n,k)+'<p>Enter one saved recovery code. It works once.</p>'+help("Example: ABCD-EFGH","Use this only when you cannot use your authenticator.")+'<form id="f"><label>Recovery code<input id="recovery-code" autocapitalize="characters" autocomplete="one-time-code" maxlength="9" placeholder="Example: ABCD-EFGH" required></label><button>Use recovery code</button></form><button class="secondary" id="back" type="button">Back to authenticator</button>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{await api("/api/mfa/recovery/verify",{code:document.querySelector("#recovery-code").value});recoveryPage("Recovery code accepted. Your authenticator is confirmed. You can manage recovery codes next.")}catch(x){recoveryEntry(x.message,"error")}};document.querySelector("#back").onclick=()=>existing()}
function existing(n="",k="success"){app.innerHTML='<h1>Verify your authenticator</h1>'+note(n,k)+'<p>This account already has MFA. Enter an authenticator code.</p>'+help("Example: 123456","If you cannot use your authenticator, use a saved recovery code.")+'<form id="f"><label>Authenticator code<input id="code" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="Example: 123456" required></label><button>Verify authenticator</button></form><button id="use-recovery" class="secondary" type="button">Use a recovery code instead</button>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();try{await api("/api/mfa/totp/verify",{code:document.querySelector("#code").value});recoveryPage("Authenticator confirmed.")}catch(x){existing(x.message,"error")}};document.querySelector("#use-recovery").onclick=()=>recoveryEntry()}
signin()})();</script></body></html>`;
}
function html() {
  const nonce = token(16), r = new Response(page(nonce), { headers: headers(nonce) });
  r.headers.set("Content-Type", "text/html; charset=utf-8"); return r;
}

async function handle(req: Request): Promise<Response> {
  try {
    const url = new URL(req.url);
    if (!originOK(req)) return reply({ error: "Request not allowed." }, 403, req);
    if (req.method === "GET" && url.pathname === "/") return html();
    if (req.method !== "POST") return reply({ error: "Not found." }, 404, req);
    const data = await input(req); if (!data) return reply({ error: "Please check the form and try again." }, 400, req);

    if (url.pathname === "/api/auth/signin") {
      const v = typeof data.email === "string" ? data.email.trim().toLowerCase() : "";
      if (!email(v) || v !== USER.email) return reply({ error: "We could not start sign-in. Check the email address and try again." }, 401, req);
      const old = cookie(req, "mfa_session"); if (old) sessions.delete(old);
      const s = makeSession(v), r = reply({ csrf: s.csrf }, 200, req); r.headers.set("Set-Cookie", sessionCookie(s.id)); return r;
    }

    const s = auth(req); if (!s) return reply({ error: "Please sign in again." }, 401, req);
    if (!csrf(req, s)) return reply({ error: "This request could not be confirmed. Refresh and try again." }, 403, req);

    /* Requirement 1/5: CSRF-protected logout invalidates the server-side session. */
    if (url.pathname === "/api/auth/logout") {
      sessions.delete(s.id);
      const r = reply({ ok: true }, 200, req);
      r.headers.set("Set-Cookie", expiredSessionCookie());
      return r;
    }

    if (url.pathname === "/api/auth/owner") {
      if (s.signInEmail !== USER.email) return reply({ error: "Please start sign-in again." }, 403, req);
      const st = state(), a = attempt(st, "owner");
      if (a.lockedUntil > Date.now()) return reply({ error: "Too many sign-in tries. Please wait 15 minutes." }, 429, req);
      s.ownerChallenge = challenge();
      return reply({ testCode: s.ownerChallenge.value }, 200, req);
    }
    if (url.pathname === "/api/auth/owner/verify") {
      const st = state(), a = attempt(st, "owner"), c = s.ownerChallenge;
      if (!otp(data.code) || a.lockedUntil > Date.now() || !c || c.used || c.expires < Date.now() || c.value !== data.code) {
        const locked = a.lockedUntil > Date.now() || failed(st, "owner");
        return reply({ error: locked ? "Too many sign-in tries. Please wait 15 minutes." : "That owner approval code does not match. Send a new code and try again." }, locked ? 429 : 400, req);
      }
      c.used = true; passed(st, "owner"); sessions.delete(s.id);
      const next = makeSession(undefined, USER.id); next.identityChallenge = challenge();
      const r = reply({ csrf: next.csrf, testCode: next.identityChallenge.value }, 200, req); r.headers.set("Set-Cookie", sessionCookie(next.id)); return r;
    }

    if (s.userId !== USER.id) return reply({ error: "Please sign in again." }, 401, req);
    const st = state();
    if (url.pathname === "/api/identity/resend") {
      s.identityChallenge = challenge(); return reply({ testCode: s.identityChallenge.value }, 200, req);
    }
    if (url.pathname === "/api/identity/verify") {
      const a = attempt(st, "identity"), c = s.identityChallenge;
      if (!otp(data.code) || a.lockedUntil > Date.now() || !c || c.used || c.expires < Date.now() || c.value !== data.code) {
        const locked = a.lockedUntil > Date.now() || failed(st, "identity");
        return reply({ error: locked ? "Too many identity check tries. Please wait 15 minutes." : "That code does not match. Check the six numbers or send a new code." }, locked ? 429 : 400, req);
      }
      c.used = true; s.identityVerified = true; passed(st, "identity"); return reply({ enrolled: st.enrolled }, 200, req);
    }
    if (!s.identityVerified) return reply({ error: "Complete the identity check before changing MFA settings." }, 403, req);

    if (url.pathname === "/api/mfa/provision") {
      if (st.enrolled) return reply({ error: "An authenticator is already enrolled for this account." }, 409, req);
      if (!st.encryptedSecret) { st.encryptedSecret = await encrypt(secret()); await save(); }
      const plain = await decrypt(st.encryptedSecret), label = encodeURIComponent(`Example Bank:${USER.email}`);
      return reply({ secret: plain, uri: `otpauth://totp/${label}?secret=${plain}&issuer=Example%20Bank&algorithm=SHA1&digits=6&period=30` }, 200, req);
    }
    if (url.pathname === "/api/mfa/totp/verify") {
      const a = attempt(st, "totp");
      if (!otp(data.code) || a.lockedUntil > Date.now() || !st.encryptedSecret) return reply({ error: a.lockedUntil > Date.now() ? "Too many authenticator tries. Please wait 15 minutes." : "Enter the six numbers from your authenticator." }, a.lockedUntil > Date.now() ? 429 : 400, req);
      const plain = await decrypt(st.encryptedSecret), now = Math.floor(Date.now() / 30_000); let accepted = -1;
      for (const step of [now - 1, now, now + 1]) if (!st.acceptedSteps.includes(step) && await totp(plain, step) === data.code) { accepted = step; break; }
      if (accepted < 0) {
        const locked = failed(st, "totp");
        return reply({ error: locked ? "Too many authenticator tries. Please wait 15 minutes." : "That authenticator code cannot be used. Check it and try again." }, locked ? 429 : 400, req);
      }
      st.acceptedSteps = [...st.acceptedSteps, accepted].slice(-100); st.enrolled = true; s.mfaVerified = true; passed(st, "totp"); await save(); return reply({ ok: true }, 200, req);
    }

    /* Requirement 1/5: account-owned, CSRF-protected, single-use recovery verification. */
    if (url.pathname === "/api/mfa/recovery/verify") {
      const a = attempt(st, "recovery");
      const entered = typeof data.code === "string" ? data.code.trim().toUpperCase() : "";
      if (a.lockedUntil > Date.now()) return reply({ error: "Too many recovery code tries. Please wait 15 minutes." }, 429, req);
      if (!recoveryFormat(entered)) {
        const locked = failed(st, "recovery");
        return reply({ error: locked ? "Too many recovery code tries. Please wait 15 minutes." : "Enter a saved recovery code in the format ABCD-EFGH." }, locked ? 429 : 400, req);
      }
      const candidate = await digest(entered);
      let match = -1;
      for (let i = 0; i < st.recoveryHashes.length; i++) {
        const equal = safeEqual(st.recoveryHashes[i], candidate);
        if (equal && match < 0) match = i;
      }
      if (match < 0) {
        const locked = failed(st, "recovery");
        return reply({ error: locked ? "Too many recovery code tries. Please wait 15 minutes." : "That recovery code cannot be used. Check the code or try another saved code." }, locked ? 429 : 400, req);
      }
      st.recoveryHashes.splice(match, 1);
      s.mfaVerified = true;
      passed(st, "recovery");
      await save();
      return reply({ ok: true, remaining: st.recoveryHashes.length }, 200, req);
    }

    if (url.pathname === "/api/mfa/recovery/generate") {
      if (!s.mfaVerified || !st.enrolled) return reply({ error: "Verify your authenticator first." }, 403, req);
      if (st.recoveryHashes.length) return reply({ error: "Recovery codes already exist. Use replacement if needed." }, 409, req);
      return reply({ codes: await recovery(st) }, 200, req);
    }
    if (url.pathname === "/api/mfa/recovery/regenerate") {
      if (!s.mfaVerified || !st.enrolled || data.confirm !== true) return reply({ error: "Confirm replacement after verifying your authenticator." }, 403, req);
      return reply({ codes: await recovery(st) }, 200, req);
    }
    return reply({ error: "Not found." }, 404, req);
  } catch {
    return reply({ error: "Something went wrong. Please try again." }, 500, req);
  }
}

/* Requirement 2/3: Bun serves local mkcert TLS and uses secure HttpOnly cookies. */
Bun.serve({
  hostname: "0.0.0.0",
  port: PORT,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  fetch: handle,
});
