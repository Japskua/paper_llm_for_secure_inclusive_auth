
/*
 MFA Enrolment System — single Bun HTTPS server and mobile web client.
 Run: bun app.ts
 TLS certificates are expected at certs/cert.pem and certs/key.pem.
*/
const PORT = 3000;
const IDLE_MS = 20 * 60 * 1000, ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_PERIOD = 300000, MAX_ATTEMPTS = 5, LOCK_MS = 300000, IDENTITY_MS = 10 * 60 * 1000;
const enc = new TextEncoder(), dec = new TextDecoder();

type Cipher = { nonce: string; cipher: string };
type Recovery = { salt: string; hash: string; used: boolean };
type Session = {
  userId: string; csrf: string; created: number; seen: number; identity: boolean;
  identitySalt?: string; identityHash?: string; identityExpiry?: number;
};
type Account = {
  id: string; email: string; password: string; pending?: Cipher; active?: Cipher;
  usedSlots: Set<number>; otpFailures: number; otpLocked: number;
  recovery: Recovery[]; recoveryFailures: number; recoveryLocked: number;
  identityFailures: number; identityLocked: number;
  provisionExpiry?: number; provisionHash?: string; provisionSalt?: string;
};

const sessions = new Map<string, Session>();
const account: Account = {
  id: "account-marcus-001", email: "marcus@example.com", password: "River!47",
  usedSlots: new Set(), otpFailures: 0, otpLocked: 0, recovery: [],
  recoveryFailures: 0, recoveryLocked: 0, identityFailures: 0, identityLocked: 0
};
const origins = new Set(["https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000"]);
const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

/* Requirements 1, 3, 4 and 5: protected session state, CSRF, validation, encryption and rate limits. */
function randomBytes(n: number) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
function b64(data: Uint8Array | ArrayBuffer) {
  let s = ""; for (const x of (data instanceof ArrayBuffer ? new Uint8Array(data) : data)) s += String.fromCharCode(x);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function unb64(s: string) {
  s = s.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((s.length + 3) % 4);
  return Uint8Array.from(atob(s), x => x.charCodeAt(0));
}
function token(n = 32) { return b64(randomBytes(n)); }
function b32(data: Uint8Array) {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let out = "", v = 0, bits = 0;
  for (const x of data) { v = (v << 8) | x; bits += 8; while (bits >= 5) { out += a[(v >>> (bits - 5)) & 31]; bits -= 5; } }
  return bits ? out + a[(v << (5 - bits)) & 31] : out;
}
function fromB32(s: string) {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let v = 0, bits = 0, out: number[] = [];
  for (const c of s.replace(/\s|=/g, "").toUpperCase()) {
    const n = a.indexOf(c); if (n < 0) throw Error("invalid");
    v = (v << 5) | n; bits += 5;
    if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
function cookies(r: Request) {
  const out: Record<string, string> = {};
  for (const p of (r.headers.get("cookie") || "").split(";")) {
    const i = p.indexOf("="); if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return out;
}
function trusted(r: Request) { return !!r.headers.get("origin") && origins.has(r.headers.get("origin")!); }
function headers(nonce?: string, r?: Request) {
  const h = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store"
  });
  if (r && trusted(r)) {
    h.set("Access-Control-Allow-Origin", r.headers.get("origin")!);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Vary", "Origin");
  }
  return h;
}
function reply(value: unknown, status = 200, r?: Request, extra?: HeadersInit) {
  const h = headers(undefined, r);
  if (extra) for (const [k, v] of new Headers(extra)) h.set(k, v);
  return new Response(JSON.stringify(value), { status, headers: h });
}
function fail(status: number, r?: Request) {
  return reply({ ok: false, message: "We could not complete that request. Please try again." }, status, r);
}
function cookie(value: string, max?: number) {
  return `mfa_session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict${max === undefined ? "" : `; Max-Age=${max}`}`;
}
function session(r: Request): { id: string; s: Session } | null {
  const id = cookies(r).mfa_session, s = id && sessions.get(id);
  if (!id || !s) return null;
  const now = Date.now();
  if (now - s.seen > IDLE_MS || now - s.created > ABSOLUTE_MS) { sessions.delete(id); return null; }
  s.seen = now; return { id, s };
}
function auth(r: Request): { id: string; s: Session } | Response {
  const a = session(r);
  return !a || a.s.userId !== account.id ? reply({ ok: false, message: "Please sign in to continue." }, 401, r) : a;
}
function csrf(r: Request): { id: string; s: Session } | Response {
  const a = auth(r);
  return a instanceof Response ? a : (!trusted(r) || r.headers.get("x-csrf-token") !== a.s.csrf
    ? reply({ ok: false, message: "This page needs to be refreshed before continuing." }, 403, r) : a);
}
async function input(r: Request): Promise<Record<string, unknown> | null> {
  try { const x = await r.json(); return x && typeof x === "object" && !Array.isArray(x) ? x as Record<string, unknown> : null; } catch { return null; }
}
function str(v: unknown, max: number) { return typeof v === "string" && v.length <= max ? v.trim() : null; }
function equal(a: Uint8Array, b: Uint8Array) {
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a[i] || 0) ^ (b[i] || 0);
  return d === 0;
}
async function hash(value: string, salt: string) {
  return b64(await crypto.subtle.digest("SHA-256", enc.encode(salt + "\0" + value)));
}
async function encrypt(secret: string): Promise<Cipher> {
  const nonce = randomBytes(12);
  return { nonce: b64(nonce), cipher: b64(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, enc.encode(secret))) };
}
async function decrypt(value: Cipher) {
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(value.nonce) }, aesKey, unb64(value.cipher)));
}

/* Testing mock values are intentionally deterministic. Server still stores hashes, expiry and one-use state. */
const MOCK_IDENTITY_CODE = "246810";
const MOCK_SECRET = "JBSWY3DPEHPK3PXP";
const MOCK_AUTHENTICATOR_OTP = "135790";
const MOCK_RECOVERY_CODES = [
  "ALPHA-23456", "BRAVO-34567", "CHARL-45678", "DELTA-56789",
  "ECHOX-67892", "FOXTN-78923", "GOLDF-89234", "HOTEL-92345"
];
async function issueIdentity(s: Session) {
  const salt = token(18);
  s.identity = false; s.identitySalt = salt; s.identityHash = await hash(MOCK_IDENTITY_CODE, salt);
  s.identityExpiry = Date.now() + IDENTITY_MS;
  return MOCK_IDENTITY_CODE;
}
async function recoveryHash(code: string, salt: string) { return hash(code, salt); }
async function makeRecoveries() {
  const stored: Recovery[] = [];
  for (const code of MOCK_RECOVERY_CODES) {
    const salt = token(16);
    stored.push({ salt, hash: await recoveryHash(code, salt), used: false });
  }
  account.recovery = stored;
  return [...MOCK_RECOVERY_CODES];
}
const credentialSalt = token(16);
async function credential(email: string, password: string) {
  const key = await crypto.subtle.importKey("raw", enc.encode(email + "\0" + password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(credentialSalt), iterations: 100000 }, key, 256));
}
const validCredential = await credential(account.email, account.password);

function html(nonce: string) { return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172331;--muted:#526273;--blue:#075ca8;--blue2:#03457f;--paper:#fff;--wash:#edf5fa;--line:#cbd8e3;--good:#126b43;--bad:#a32727}
*{box-sizing:border-box}body{margin:0;background:var(--wash);color:var(--ink);font-family:Verdana,Arial,sans-serif;letter-spacing:.035em;line-height:1.65;font-size:16px}
main{max-width:560px;min-height:100vh;margin:auto;background:var(--paper);padding:22px 20px 38px}header{border-bottom:2px solid var(--line);padding-bottom:15px;margin-bottom:24px}
.brand{font-weight:700;color:var(--blue);font-size:1.07rem}.step{color:var(--muted);font-size:.9rem;margin-top:9px}h1{font-size:1.65rem;line-height:1.28;letter-spacing:.02em;margin:0 0 15px}
h2{font-size:1.16rem;line-height:1.35;margin:23px 0 9px}p{margin:0 0 15px}.card{border:1px solid var(--line);border-radius:12px;padding:18px;margin:16px 0}
.notice{background:#eef8f2;border-left:5px solid var(--good);padding:13px 14px;margin:15px 0}.error{background:#fff0f0;border-left:5px solid var(--bad);padding:13px 14px;margin:15px 0}
.test{background:#fff9e9;border-left:5px solid #9a6800;padding:14px;margin:16px 0}.hint{background:#f4f8fb;padding:13px;border-radius:8px;color:#33495e;font-size:.94rem}
label{display:block;font-weight:700;margin:18px 0 6px}input{width:100%;min-height:51px;border:2px solid #8da1b4;border-radius:8px;padding:10px 12px;font:inherit;letter-spacing:.07em;color:var(--ink)}
input:focus,button:focus{outline:3px solid #8bc7ec;outline-offset:2px;border-color:var(--blue)}button{width:100%;min-height:53px;border:0;border-radius:8px;background:var(--blue);color:#fff;font:700 1rem Verdana,Arial,sans-serif;letter-spacing:.035em;padding:12px 14px;cursor:pointer;margin-top:21px}
button:hover{background:var(--blue2)}button.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue);margin-top:12px}.smalllink{background:none;border:0;color:var(--blue);text-decoration:underline;width:auto;min-height:auto;padding:4px;margin:12px 0 0;font:inherit;cursor:pointer}
.copyrow{display:flex;gap:14px;align-items:center;flex-wrap:wrap}.copyrow button{width:auto;margin:3px 0}.code,.codes{font-family:ui-monospace,Consolas,monospace;letter-spacing:.08em;word-break:break-all;background:#f4f8fb;border:1px solid var(--line);border-radius:8px;padding:12px;margin:10px 0}.codes{line-height:2;white-space:pre-wrap}
.qr{display:block;width:min(100%,328px);height:auto;image-rendering:pixelated;margin:14px auto;border:10px solid white}.logs{border-top:2px solid var(--line);margin-top:28px;padding-top:12px;font-size:.86rem;color:#33495e}.logline{margin:6px 0}
@media(max-width:380px){main{padding:18px 15px}body{font-size:15px}h1{font-size:1.45rem}}
</style></head><body><main id="app" aria-live="polite">Loading securely…</main><script nonce="${nonce}">(()=>{"use strict";
const app=document.getElementById("app");let csrfToken="",provision=null,recoveryCodes=null,logs=[];
const E=(tag,p={},kids=[])=>{const n=document.createElement(tag);for(const[k,v]of Object.entries(p)){if(k==="className")n.className=v;else if(k==="text")n.textContent=v;else if(k.startsWith("on")&&typeof v==="function")n.addEventListener(k.slice(2).toLowerCase(),v);else n.setAttribute(k,String(v));}for(const x of kids)n.append(x);return n;};
const say=(text,kind="notice")=>E("div",{className:kind,text,role:"status"});
function log(text){console.log(text);logs.push(text);if(logs.length>7)logs.shift();}
function finish(){const b=E("section",{className:"logs","aria-label":"Logs"},[E("strong",{text:"Logs"})]);logs.forEach(x=>b.append(E("div",{className:"logline",text:"• "+x})));app.append(b);}
function page(step,title){app.replaceChildren(E("header",{},[E("div",{className:"brand",text:"Northstar Bank"}),E("div",{className:"step",text:"MFA set-up · Step "+step+" of 4"})]),E("h1",{text:title}));}
function help(){return E("div",{className:"hint"},[E("strong",{text:"Need help? "}),document.createTextNode("You can pause here. Nothing will disappear while you read.")]);}
function primary(text,fn){return E("button",{type:"button",text,onClick:fn});}
function copy(value,b){navigator.clipboard?.writeText(value).then(()=>b.textContent="Copied").catch(()=>b.textContent="Select the value to copy");}
async function api(path,method="GET",data){const o={method,headers:{}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrfToken;o.body=JSON.stringify(data||{});}try{const r=await fetch(path,o),v=await r.json().catch(()=>({ok:false,message:"We could not complete that request."}));if(r.status===401&&path!=="/api/signin"){csrfToken="";provision=null;recoveryCodes=null;signin("Your secure session has expired. Please sign in again.");return null;}return v;}catch{return{ok:false,message:"Connection problem. Please try again."};}}

/* Requirement task: standards-compliant QR Model 2 byte encoder.
   It selects QR version 1–10 Low EC capacity, performs RS correction,
   block interleaving, all eight masks and ISO/IEC penalty selection. */
function qr(uri){
 const bytes=new TextEncoder().encode(uri);
 const byteCap=[0,17,32,53,78,106,134,154,192,230,271];
 const dataWords=[0,19,34,55,80,108,136,156,194,232,274];
 const ecWords=[0,7,10,15,20,26,18,20,24,30,18];
 const blocks=[0,1,1,1,1,1,2,2,2,2,4];
 let ver=1;while(ver<=10&&bytes.length>byteCap[ver])ver++;
 if(ver>10)throw Error("Setup link is too long for this QR encoder.");
 const N=17+4*ver,align=[[],[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50]][ver];
 const gfExp=Array(512).fill(0),gfLog=Array(256).fill(0);let z=1;
 for(let i=0;i<255;i++){gfExp[i]=z;gfLog[z]=i;z<<=1;if(z&256)z^=285;}for(let i=255;i<512;i++)gfExp[i]=gfExp[i-255];
 const mul=(a,b)=>a&&b?gfExp[gfLog[a]+gfLog[b]]:0;
 const generator=n=>{let p=[1];for(let i=0;i<n;i++){const q=Array(p.length+1).fill(0);for(let j=0;j<p.length;j++){q[j]^=p[j];q[j+1]^=mul(p[j],gfExp[i]);}p=q;}return p;};
 const rs=(d,n)=>{const g=generator(n),r=Array(n).fill(0);for(const x of d){const f=x^r.shift();r.push(0);for(let i=0;i<n;i++)r[i]^=mul(g[i+1],f);}return r;};
 const bits=[],push=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>>i)&1);};
 push(4,4);push(bytes.length,ver<10?8:16);for(const x of bytes)push(x,8);push(0,Math.min(4,dataWords[ver]*8-bits.length));while(bits.length%8)bits.push(0);
 const raw=[];for(let i=0;i<bits.length;i+=8)raw.push(bits.slice(i,i+8).reduce((a,b)=>(a<<1)|b,0));for(let p=0;raw.length<dataWords[ver];p++)raw.push(p%2?17:236);
 const bc=blocks[ver],each=dataWords[ver]/bc,groups=[];for(let i=0;i<bc;i++)groups.push(raw.slice(i*each,(i+1)*each));
 const parity=groups.map(g=>rs(g,ecWords[ver])),words=[];
 for(let i=0;i<each;i++)for(const g of groups)words.push(g[i]);for(let i=0;i<ecWords[ver];i++)for(const g of parity)words.push(g[i]);
 const stream=[];for(const w of words)for(let i=7;i>=0;i--)stream.push((w>>>i)&1);
 const base=Array.from({length:N},()=>Array(N).fill(null)),put=(x,y,v)=>{if(x>=0&&y>=0&&x<N&&y<N)base[y][x]=!!v;};
 const finder=(x,y)=>{for(let j=-1;j<=7;j++)for(let i=-1;i<=7;i++)put(x+i,y+j,i>=0&&i<=6&&j>=0&&j<=6&&(i===0||i===6||j===0||j===6||(i>=2&&i<=4&&j>=2&&j<=4)));};
 finder(0,0);finder(N-7,0);finder(0,N-7);
 for(let i=8;i<N-8;i++){put(i,6,i%2===0);put(6,i,i%2===0);}
 for(const y of align)for(const x of align){if(base[y][x]!==null)continue;for(let j=-2;j<=2;j++)for(let i=-2;i<=2;i++)put(x+i,y+j,Math.max(Math.abs(i),Math.abs(j))!==1);}
 const bch=(v,poly,shift)=>{let x=v<<shift;while(x.toString(2).length>shift)x^=poly<<(x.toString(2).length-(shift+1));return(v<<shift)|x;};
 if(ver>=7){const vb=bch(ver,0x1f25,12);for(let i=0;i<18;i++){const bit=(vb>>>i)&1;put(N-11+i%3,Math.floor(i/3),bit);put(Math.floor(i/3),N-11+i%3,bit);}}
 const reserveFormat=()=>{for(let i=0;i<15;i++){put(8,i<6?i:i<8?i+1:N-15+i,false);put(i<8?N-i-1:i<9?15-i:14-i,8,false);}put(8,N-8,true);};reserveFormat();
 const maskBit=(m,x,y)=>[ (x+y)%2===0,y%2===0,x%3===0,(x+y)%3===0,(Math.floor(y/2)+Math.floor(x/3))%2===0,(x*y)%2+(x*y)%3===0,((x*y)%2+(x*y)%3)%2===0,((x+y)%2+(x*y)%3)%2===0 ][m];
 const format=(mask)=>bch((1<<3)|mask,0x537,10)^0x5412;
 const build=mask=>{const a=base.map(r=>r.slice());let k=0,up=true;for(let x=N-1;x>0;x-=2){if(x===6)x--;for(let q=0;q<N;q++){const y=up?N-1-q:q;for(const xx of[x,x-1])if(a[y][xx]===null){let v=stream[k++]||0;if(maskBit(mask,xx,y))v^=1;a[y][xx]=!!v;}}up=!up;}const f=format(mask);for(let i=0;i<15;i++){const bit=(f>>>i)&1;a[i<6?i:i<8?i+1:N-15+i][8]=!!bit;a[8][i<8?N-i-1:i<9?15-i:14-i]=!!bit;}a[N-8][8]=true;return a;};
 const score=a=>{let s=0;for(let y=0;y<N;y++)for(let x=0;x<N;x++){let same=0;for(let j=-1;j<=1;j++)for(let i=-1;i<=1;i++)if(i||j){const yy=y+j,xx=x+i;if(yy>=0&&xx>=0&&yy<N&&xx<N&&a[yy][xx]===a[y][x])same++;}if(same>5)s+=3+same-5;}for(let y=0;y<N-1;y++)for(let x=0;x<N-1;x++)if(a[y][x]===a[y+1][x]&&a[y][x]===a[y][x+1]&&a[y][x]===a[y+1][x+1])s+=3;const line=v=>{for(let i=0;i<=N-7;i++)if(v.slice(i,i+7).join("")==="1011101")s+=40;};for(let i=0;i<N;i++){line(a[i]);line(a.map(r=>r[i]));}let dark=0;for(const r of a)for(const x of r)dark+=x?1:0;s+=Math.floor(Math.abs(dark*100/(N*N)-50)/5)*10;return s;};
 let best=build(0),bestScore=score(best);for(let m=1;m<8;m++){const a=build(m),v=score(a);if(v<bestScore){best=a;bestScore=v;}}
 const c=document.createElement("canvas");c.width=c.height=N;const g=c.getContext("2d");for(let y=0;y<N;y++)for(let x=0;x<N;x++){g.fillStyle=best[y][x]?"#000":"#fff";g.fillRect(x,y,1,1);}c.className="qr";c.setAttribute("role","img");c.setAttribute("aria-label","Scannable QR code for authenticator setup");return c;
}
function signin(error){page("1","Sign in");app.append(E("p",{text:"Use your bank sign-in details. This demo keeps your sign-in private."}));if(error)app.append(say(error,"error"));const form=E("form"),email=E("input",{type:"email",autocomplete:"username",inputmode:"email",placeholder:"name@example.com"}),password=E("input",{type:"password",autocomplete:"current-password",placeholder:"Your password"});const send=async e=>{e.preventDefault();const r=await api("/api/signin","POST",{email:email.value,password:password.value});if(!r.ok)return signin(r.message);csrfToken=r.csrf;console.log("Testing-only identity check code:",r.testCode);log("Mock sign-in completed. Identity code issued in browser console.");identity();};form.addEventListener("submit",send);form.append(E("label",{text:"Email"}),email,E("p",{className:"hint",text:"Example: marcus@example.com"}),E("label",{text:"Password"}),password,primary("Sign in",send));app.append(form,E("p",{className:"hint",text:"Demo sign-in: marcus@example.com and River!47"}),help());finish();}
function identity(error,msg){page("2","Check it is you");app.append(E("p",{text:"We need one quick identity check before MFA set-up."}));if(error)app.append(say(error,"error"));if(msg)app.append(say(msg));const code=E("input",{inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"246810"});app.append(E("label",{text:"Identity check code"}),code,E("p",{className:"hint",text:"Example: 246810"}),primary("Confirm identity",async()=>{const r=await api("/api/identity","POST",{code:code.value});if(!r)return;if(!r.ok)return identity(r.message);log("Mock identity check completed.");setup();}),E("button",{className:"secondary",type:"button",text:"Send a new identity check code",onClick:async()=>{const r=await api("/api/identity/request","POST",{});if(!r)return;if(!r.ok)return identity(r.message);console.log("Testing-only replacement identity check code:",r.testCode);log("New identity code issued in browser console.");identity(null,"A new code was requested. Nothing has been penalised.");}}),help());finish();}
function setup(error){page("3","Set up your authenticator");app.append(E("p",{text:"Open your authenticator app. You can scan a code or copy a setup value."}));if(error)app.append(say(error,"error"));app.append(E("div",{className:"card",text:"📱 Choose “add account” in your authenticator app."}),primary("Show setup options",async()=>{const r=await api("/api/mfa/provision","POST",{});if(!r)return;if(!r.ok)return setup(r.message);provision=r;console.log("Testing-only authenticator secret:",r.secret);console.log("Testing-only authenticator OTP:",r.testOtp);log("Authenticator setup material is ready.");provisionScreen();}),help());finish();}
function provisionScreen(message){page("3","Add this account");app.append(E("p",{text:"Scan the QR code. If that is not convenient, reveal and copy a setup value instead. You do not need to type it."}));if(message)app.append(say(message));app.append(qr(provision.uri),E("h2",{text:"Manual setup value"}));const secret=E("div",{className:"code",text:"Hidden for privacy"}),show=E("button",{className:"secondary",type:"button",text:"Show manual setup value",onClick:()=>{const open=show.textContent.startsWith("Hide");show.textContent=open?"Show manual setup value":"Hide manual setup value";secret.textContent=open?"Hidden for privacy":provision.secret;}}),cp=E("button",{className:"smalllink",type:"button",text:"Copy manual setup value",onClick:()=>copy(provision.secret,cp)}),cu=E("button",{className:"smalllink",type:"button",text:"Copy setup link",onClick:()=>copy(provision.uri,cu)});app.append(secret,E("div",{className:"copyrow"},[show,cp,cu]),E("div",{className:"test"},[E("strong",{text:"Testing only"}),E("div",{className:"code",text:"Mock authenticator OTP: "+provision.testOtp})]),primary("I have added it",verify),E("button",{className:"secondary",type:"button",text:"Create replacement setup material",onClick:async()=>{const r=await api("/api/mfa/provision","POST",{});if(!r)return;if(!r.ok)return setup(r.message);provision=r;console.log("Testing-only replacement authenticator secret:",r.secret);console.log("Testing-only replacement authenticator OTP:",r.testOtp);log("Replacement setup material was created.");provisionScreen("Replacement setup material is ready. The earlier setup value no longer works.");}}),help());finish();}
function verify(error){page("4","Enter the 6-digit code");app.append(E("p",{text:"Your authenticator app now shows a 6-digit code. Take your time."}));if(error)app.append(say(error,"error"));const code=E("input",{inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"135790"});app.append(E("label",{text:"Authenticator code"}),code,E("p",{className:"hint",text:"Example: 135790"}),primary("Verify code",async()=>{const r=await api("/api/mfa/verify","POST",{otp:code.value});if(!r)return;if(!r.ok)return verify(r.message);recoveryCodes=r.codes;console.log("Testing-only backup recovery codes:",r.codes);log("Authenticator was verified.");backups();}),E("button",{className:"smalllink",type:"button",text:"Show setup options again",onClick:provisionScreen}),help());finish();}
function backups(message){page("4","Save your backup codes");const all=recoveryCodes.join("\\n");app.append(say(message||"Authenticator set up. Save these backup codes somewhere safe. Each one works once."));const list=E("div",{className:"codes",text:"Hidden for privacy"}),show=E("button",{className:"secondary",type:"button",text:"Show backup recovery codes",onClick:()=>{const open=show.textContent.startsWith("Hide");show.textContent=open?"Show backup recovery codes":"Hide backup recovery codes";list.textContent=open?"Hidden for privacy":all;}}),cp=E("button",{className:"secondary",type:"button",text:"Copy all backup codes",onClick:()=>copy(all,cp)});app.append(list,show,cp,primary("I saved my codes",settings),help());finish();}
function settings(message){page("4","MFA is ready");app.append(E("p",{text:"Your authenticator is active. Backup codes are available if you lose your device."}));if(message)app.append(say(message,message.startsWith("That backup")?"notice":"error"));const code=E("input",{autocomplete:"one-time-code",placeholder:"ALPHA-23456",maxlength:"11"});app.append(E("h2",{text:"Try a backup code"}),E("label",{text:"Recovery code"}),code,E("p",{className:"hint",text:"Example: ALPHA-23456"}),primary("Use recovery code",async()=>{const r=await api("/api/recovery/verify","POST",{code:code.value});if(!r)return;settings(r.ok?"That backup code worked and cannot be used again.":r.message);}),E("button",{className:"secondary",type:"button",text:"Make new backup codes",onClick:async()=>{const r=await api("/api/backup/regenerate","POST",{});if(!r)return;if(!r.ok)return settings(r.message);recoveryCodes=r.codes;console.log("Testing-only replacement recovery codes:",r.codes);log("Replacement backup codes were created.");backups("New backup codes are ready. The earlier backup codes no longer work.");}}),E("button",{className:"smalllink",type:"button",text:"Sign out",onClick:async()=>{const r=await api("/api/logout","POST",{});if(!r)return;csrfToken="";provision=null;recoveryCodes=null;log("Mock sign-out completed. Server session invalidated.");signin();}}),help());finish();}
async function boot(){const r=await api("/api/status");if(!r)return;if(r.ok){csrfToken=r.csrf;r.mfaActive?settings():r.identityVerified?setup():identity();}else signin();}boot();})();</script></body></html>`; }

async function route(r: Request): Promise<Response> {
  const url = new URL(r.url);
  if (r.method === "OPTIONS") {
    if (!trusted(r)) return fail(403, r);
    const h = headers(undefined, r);
    h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return new Response(null, { status: 204, headers: h });
  }
  if (url.pathname === "/" && r.method === "GET") {
    const nonce = token(18), h = headers(nonce, r);
    h.set("Content-Type", "text/html; charset=utf-8");
    return new Response(html(nonce), { headers: h });
  }
  if (url.pathname === "/api/signin" && r.method === "POST") {
    if (!trusted(r)) return fail(403, r);
    const x = await input(r), email = str(x?.email, 254), password = str(x?.password, 128);
    const valid = !!email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    const normalizedEmail = valid ? email!.toLowerCase() : "invalid@example.invalid", normalizedPassword = password || "invalid-password-value";
    const matched = equal(await credential(normalizedEmail, normalizedPassword), validCredential) && normalizedEmail === account.email && !!password && valid;
    if (!matched) return reply({ ok: false, message: "Those sign-in details did not match. Check both fields and try again." }, 401, r);
    const id = token(), now = Date.now(), s: Session = { userId: account.id, csrf: token(), created: now, seen: now, identity: false };
    sessions.set(id, s);
    return reply({ ok: true, csrf: s.csrf, testCode: await issueIdentity(s) }, 200, r, { "Set-Cookie": cookie(id) });
  }
  if (url.pathname === "/api/status" && r.method === "GET") {
    const a = auth(r); if (a instanceof Response) return a;
    return reply({ ok: true, csrf: a.s.csrf, identityVerified: a.s.identity, mfaActive: !!account.active }, 200, r);
  }
  if (url.pathname === "/api/identity/request" && r.method === "POST") {
    const a = csrf(r); if (a instanceof Response) return a;
    if (Date.now() < account.identityLocked) return reply({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, r);
    return reply({ ok: true, testCode: await issueIdentity(a.s) }, 200, r);
  }
  if (url.pathname === "/api/identity" && r.method === "POST") {
    const a = csrf(r); if (a instanceof Response) return a;
    if (Date.now() < account.identityLocked) return reply({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, r);
    const code = str((await input(r))?.code, 6);
    const valid = !!code && /^\d{6}$/.test(code) && !!a.s.identityHash && !!a.s.identitySalt && !!a.s.identityExpiry && Date.now() <= a.s.identityExpiry && equal(enc.encode(await hash(code, a.s.identitySalt)), enc.encode(a.s.identityHash));
    if (!valid) {
      if (++account.identityFailures >= MAX_ATTEMPTS) { account.identityFailures = 0; account.identityLocked = Date.now() + LOCK_MS; return reply({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, r); }
      return reply({ ok: false, message: !a.s.identityExpiry || Date.now() > a.s.identityExpiry ? "That identity code has expired. Send a new code and try again." : "That identity code did not work. Check the 6 numbers and try again." }, 400, r);
    }
    account.identityFailures = 0; a.s.identity = true; delete a.s.identityHash; delete a.s.identitySalt; delete a.s.identityExpiry;
    return reply({ ok: true }, 200, r);
  }
  if (url.pathname === "/api/mfa/provision" && r.method === "POST") {
    const a = csrf(r); if (a instanceof Response) return a;
    if (!a.s.identity) return reply({ ok: false, message: "Complete the identity check before setting up MFA." }, 403, r);
    account.pending = await encrypt(MOCK_SECRET);
    account.usedSlots.clear(); account.otpFailures = 0; account.otpLocked = 0;
    account.provisionSalt = token(16); account.provisionHash = await hash(MOCK_AUTHENTICATOR_OTP, account.provisionSalt); account.provisionExpiry = Date.now() + OTP_PERIOD;
    const uri = "otpauth://totp/" + encodeURIComponent("Northstar:" + account.email) + "?secret=" + MOCK_SECRET + "&issuer=Northstar&algorithm=SHA1&digits=6&period=300";
    return reply({ ok: true, secret: MOCK_SECRET, uri, testOtp: MOCK_AUTHENTICATOR_OTP }, 200, r);
  }
  if (url.pathname === "/api/mfa/verify" && r.method === "POST") {
    const a = csrf(r); if (a instanceof Response) return a;
    if (!a.s.identity) return reply({ ok: false, message: "Complete the identity check before setting up MFA." }, 403, r);
    const value = str((await input(r))?.otp, 6);
    if (!value || !/^\d{6}$/.test(value)) return reply({ ok: false, message: "Enter all 6 numbers from your authenticator app." }, 400, r);
    if (!account.pending || !account.provisionHash || !account.provisionSalt || !account.provisionExpiry) return reply({ ok: false, message: "Choose setup options first, then enter the code." }, 400, r);
    if (Date.now() < account.otpLocked) return reply({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, r);
    const valid = Date.now() <= account.provisionExpiry && equal(enc.encode(await hash(value, account.provisionSalt)), enc.encode(account.provisionHash));
    if (!valid) {
      if (++account.otpFailures >= MAX_ATTEMPTS) { account.otpFailures = 0; account.otpLocked = Date.now() + LOCK_MS; return reply({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, r); }
      return reply({ ok: false, message: Date.now() > account.provisionExpiry ? "That authenticator code has expired. Show setup options again and try the new code." : "That code did not work. Check the 6 numbers and try again." }, 400, r);
    }
    account.otpFailures = 0; account.active = account.pending; account.pending = undefined; delete account.provisionHash; delete account.provisionSalt; delete account.provisionExpiry;
    return reply({ ok: true, codes: await makeRecoveries() }, 200, r);
  }
  if (url.pathname === "/api/recovery/verify" && r.method === "POST") {
    const a = csrf(r); if (a instanceof Response) return a;
    const code = str((await input(r))?.code, 11)?.toUpperCase();
    if (!code || !/^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/.test(code)) return reply({ ok: false, message: "Enter a backup code in the format ABCDE-12345." }, 400, r);
    if (Date.now() < account.recoveryLocked) return reply({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, r);
    for (const item of account.recovery) {
      if (!item.used && equal(enc.encode(await recoveryHash(code, item.salt)), enc.encode(item.hash))) {
        item.used = true; account.recoveryFailures = 0; return reply({ ok: true }, 200, r);
      }
    }
    if (++account.recoveryFailures >= MAX_ATTEMPTS) { account.recoveryFailures = 0; account.recoveryLocked = Date.now() + LOCK_MS; return reply({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, r); }
    return reply({ ok: false, message: "That backup code did not work. Check the saved code and try another one." }, 400, r);
  }
  if (url.pathname === "/api/backup/regenerate" && r.method === "POST") {
    const a = csrf(r); if (a instanceof Response) return a;
    if (!account.active) return reply({ ok: false, message: "Set up an authenticator before making backup codes." }, 400, r);
    return reply({ ok: true, codes: await makeRecoveries() }, 200, r);
  }
  if (url.pathname === "/api/logout" && r.method === "POST") {
    const a = csrf(r); if (a instanceof Response) return a;
    sessions.delete(a.id);
    return reply({ ok: true }, 200, r, { "Set-Cookie": cookie("", 0) });
  }
  return fail(404, r);
}

Bun.serve({
  port: PORT,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) { try { return await route(request); } catch { return fail(500, request); } }
});
console.log("MFA demo listening securely at https://localhost:" + PORT);
