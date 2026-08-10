
const enc = new TextEncoder(), dec = new TextDecoder();
const pepper = b64(rand(32));
const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

type Cipher = { iv: string; data: string };
type Check = { hash: string; expires: number; used: boolean };
type Attempts = { count: number; lockedUntil: number; last: number };
type Account = {
  id: string; email: string; credentialHash: string; identityVerified: boolean;
  identity?: Check; identityFails: number; identityLocked: number; lastIdentitySent: number;
  seed?: Cipher; provisionExpires: number; mfaEnabled: boolean; totpFails: number; totpLocked: number; usedTotps: Set<string>;
  backups: Set<string>; backupCodesConfirmed: boolean; recoveryFails: number; recoveryLocked: number; signIn: Attempts;
};
type Session = { userId: string; csrf: string; made: number; seen: number };

const accounts = new Map<string, Account>(), sessions = new Map<string, Session>(), anonymousAttempts = new Map<string, Attempts>();
const DEMO_EMAIL = "marcus@example.test", DEMO_CREDENTIAL = "Harbour-demo-54";
const IDLE = 30 * 60e3, ABS = 8 * 60 * 60e3, VERIFY = 30 * 60e3, LOCK = 10 * 60e3, MAX = 5, ISSUE = 20e3;

function rand(n: number) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
function b64(b: Uint8Array) { return btoa(String.fromCharCode(...b)); }
function ub64(s: string) { return Uint8Array.from(atob(s), x => x.charCodeAt(0)); }
function token(n = 32) { return b64(rand(n)).replace(/[+/]/g, x => x === "+" ? "-" : "_").replace(/=+$/g, ""); }
function base32(n: number) { const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; return [...rand(n)].map(x => a[x & 31]).join(""); }
function recovery() { const x = base32(10); return x.slice(0, 5) + "-" + x.slice(5); }
function numberCode() {
  const limit = 0x100000000 - 0x100000000 % 1000000; let n = 0;
  do n = crypto.getRandomValues(new Uint32Array(1))[0]; while (n >= limit);
  return String(n % 1000000).padStart(6, "0");
}
async function hash(s: string) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s + ":" + pepper)))); }
async function crypt(s: string): Promise<Cipher> {
  const iv = rand(12), data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(s));
  return { iv: b64(iv), data: b64(new Uint8Array(data)) };
}
async function uncrypt(c: Cipher) { return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: ub64(c.iv) }, aesKey, ub64(c.data))); }
async function hmac(key: Uint8Array, message: Uint8Array) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, message));
}
async function totp(secret: string, step = Math.floor(Date.now() / 30000)) {
  const raw: number[] = []; let value = 0, bits = 0;
  for (const ch of secret) {
    const x = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(ch); value = (value << 5) | x; bits += 5;
    if (bits >= 8) { raw.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  const msg = new Uint8Array(8); let count = BigInt(step);
  for (let i = 7; i >= 0; i--) { msg[i] = Number(count & 255n); count >>= 8n; }
  const d = await hmac(new Uint8Array(raw), msg), o = d[19] & 15;
  return String((((d[o] & 127) << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) % 1000000).padStart(6, "0");
}
function uri(secret: string) { return `otpauth://totp/Harbour%20Bank:${encodeURIComponent(DEMO_EMAIL)}?secret=${secret}&issuer=Harbour%20Bank&algorithm=SHA1&digits=6&period=30`; }

const credentialHash = await hash(DEMO_CREDENTIAL);
const dummyCredentialHash = await hash("fixed-non-account-dummy-credential");
accounts.set("marcus-account", {
  id: "marcus-account", email: DEMO_EMAIL, credentialHash, identityVerified: false, identityFails: 0, identityLocked: 0,
  lastIdentitySent: 0, provisionExpires: 0, mfaEnabled: false, totpFails: 0, totpLocked: 0, usedTotps: new Set(),
  backups: new Set(), backupCodesConfirmed: false, recoveryFails: 0, recoveryLocked: 0,
  signIn: { count: 0, lockedUntil: 0, last: 0 }
});

/* Security requirements: CSP, HSTS, clickjacking protection, restricted CORS, and secure cookies. */
function headers(nonce = "") {
  return new Headers({
    "Content-Security-Policy": nonce ? `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` : "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains", "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
  });
}
function json(x: unknown, status = 200) { const h = headers(); h.set("Content-Type", "application/json; charset=utf-8"); return new Response(JSON.stringify(x), { status, headers: h }); }
function fail(status: number, message: string, identityRequired = false) { return json({ ok: false, message, identityRequired }, status); }
const origins = new Set(["https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000"]);
function cors(r: Request, res: Response) {
  const o = r.headers.get("origin");
  if (o && origins.has(o)) { res.headers.set("Access-Control-Allow-Origin", o); res.headers.set("Access-Control-Allow-Credentials", "true"); }
  res.headers.set("Vary", "Origin"); res.headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token"); res.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  return res;
}
function cookie(r: Request, name: string) { return (r.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(name + "="))?.slice(name.length + 1); }
function session(r: Request) {
  const id = cookie(r, "mfa_session"), s = id && sessions.get(id), now = Date.now(), a = s && accounts.get(s.userId);
  if (!s || !a || now - s.seen > IDLE || now - s.made > ABS) { if (id) sessions.delete(id); return; }
  s.seen = now; return { s, a };
}
function csrf(r: Request, s: Session) { return origins.has(r.headers.get("origin") || "") && r.headers.get("x-csrf-token") === s.csrf; }
async function body(r: Request): Promise<Record<string, unknown> | undefined> {
  if (!(r.headers.get("content-type") || "").includes("application/json")) return;
  const t = await r.text(); if (t.length > 3000) return;
  try { const x = JSON.parse(t); return x && typeof x === "object" && !Array.isArray(x) ? x : undefined; } catch { return; }
}
const emailOK = (x: unknown): x is string => typeof x === "string" && x.length < 255 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x);
const credentialOK = (x: unknown): x is string => typeof x === "string" && x.length >= 8 && x.length <= 128;
const codeOK = (x: unknown): x is string => typeof x === "string" && /^\d{6}$/.test(x);
const recoveryOK = (x: unknown): x is string => typeof x === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(x);
const locked = (n: number) => Date.now() < n;
async function makeCheck(code: string): Promise<Check> { return { hash: await hash(code), expires: Date.now() + VERIFY, used: false }; }
async function makeCodes(a: Account) {
  const codes = Array.from({ length: 8 }, recovery);
  a.backups = new Set(await Promise.all(codes.map(hash))); a.backupCodesConfirmed = false; a.recoveryFails = a.recoveryLocked = 0;
  return codes;
}
function authCookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABS / 1000)}`; }
function deadCookie() { return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }
function recordFailure(a: Attempts) { a.last = Date.now(); if (++a.count >= MAX) { a.count = MAX; a.lockedUntil = Date.now() + LOCK; } }
const signMessage = "We could not sign in with those details. Check the email and credential and try again.";

const page = String.raw`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank · Security setup</title><style nonce="__NONCE__">
:root{--ink:#17243a;--muted:#526277;--blue:#075fc8;--line:#c8d4e1;--bad:#a92319;--good:#126b43}*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:var(--ink);font:17px/1.7 Arial,Verdana,Tahoma,sans-serif;letter-spacing:.025em}main{max-width:620px;margin:auto;padding:18px 15px 40px}.brand{font-weight:bold;color:#064b9e;margin:4px 5px 18px}h1{font-size:1.55rem;line-height:1.3;margin:0 0 9px}p{margin:0 0 14px}.card{background:#fff;border:1px solid var(--line);border-radius:15px;padding:22px 18px;box-shadow:0 2px 8px #1935540d}.step{color:var(--blue);font-weight:bold}.icon{font-size:1.45rem;margin-right:8px}label{display:block;font-weight:bold;margin:16px 0 6px}input{width:100%;min-height:52px;border:2px solid #8ba0b8;border-radius:10px;padding:11px;font:inherit;letter-spacing:.05em}input:focus{outline:3px solid #8bc5ff;outline-offset:2px;border-color:var(--blue)}button{width:100%;min-height:52px;margin-top:15px;border:0;border-radius:10px;background:var(--blue);color:#fff;font:bold 1rem Arial,sans-serif;padding:10px;cursor:pointer}.secondary{background:#fff;color:#064b9e;border:2px solid #1e70c7}.small{width:auto;min-height:40px;margin:7px 7px 0 0;padding:7px 11px}.hint,details{color:var(--muted);font-size:.94rem}.notice{margin-top:15px;padding:12px;border-radius:9px;font-weight:bold}.error{background:#fff0ef;color:var(--bad);border-left:5px solid var(--bad)}.ok{background:#eaf8f0;color:var(--good);border-left:5px solid var(--good)}.secret{overflow-wrap:anywhere;background:#f5f8fc;border:1px dashed #7891ae;padding:11px;border-radius:8px;font-family:monospace;font-weight:bold}.qr{display:block;width:min(100%,280px);height:auto;margin:15px auto;padding:10px;background:#fff;border:1px solid var(--line);border-radius:10px}.qr-label{text-align:center;font-weight:bold;margin-top:16px}.code-list{list-style:none;padding:0}.code-list li{margin:8px 0;padding:8px 10px;background:#f5f8fc;font-family:monospace;font-weight:bold;border-radius:7px}.checkline{display:flex;gap:10px;align-items:flex-start}.checkline input{width:23px;min-height:23px;margin-top:5px}.status{padding:11px;background:#eef6ff;border-radius:9px}.logs{margin-top:18px;background:#17243a;color:#eff6ff;border-radius:12px;padding:14px}.logs h2{font-size:1rem;margin:0 0 6px}.logs p,.logs ul{font-size:.85rem;line-height:1.5;margin:5px 0}.logs ul{padding-left:20px}@media(max-width:370px){body{font-size:16px}.card{padding:18px 14px}}
</style></head><body><main><header><div class="brand">◆ Harbour Bank</div></header><section id="app" aria-live="polite"></section><aside class="logs"><h2>Logs</h2><p>Safe mock activity is shown here. Test secrets are in the browser console.</p><ul id="logs"><li>Ready to begin.</li></ul></aside></main>
<script nonce="__NONCE__">(()=>{"use strict";
const app=document.querySelector("#app"),box=document.querySelector("#logs");
const s={csrf:"",screen:"signin",identityCode:"",otp:"",secret:"",uri:"",codes:[],message:"",error:"",show:false,expired:false,logs:["Ready to begin."]};
const esc=v=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function browserLog(secret,safe){console.log(secret);s.logs.push(safe);if(s.logs.length>8)s.logs.shift();box.innerHTML=s.logs.map(x=>"<li>"+esc(x)+"</li>").join("")}
function say(m,e=""){s.message=m;s.error=e}function note(){return s.error?'<div class="notice error">'+esc(s.error)+"</div>":s.message?'<div class="notice ok">'+esc(s.message)+"</div>":""}
function shell(step,title,icon,text,inside,hint){return '<article class="card"><p class="step">'+step+'</p><h1><span class="icon">'+icon+"</span>"+title+"</h1><p>"+text+"</p>"+inside+note()+'<details><summary>Need help?</summary><p>'+esc(hint)+"</p></details></article>"}

/* Requirement: local standards-compliant QR Model 2 Version 10-L encoder. */
function qrSvg(text){
 const size=57,cap=274,bytes=[...new TextEncoder().encode(text)],exp=[],log=[];let x=1;
 for(let i=0;i<255;i++){exp[i]=x;log[x]=i;x<<=1;if(x&256)x^=0x11d}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;
 const gen=n=>{let p=[1];for(let i=0;i<n;i++){let q=Array(p.length+1).fill(0);for(let j=0;j<p.length;j++){q[j]^=p[j];q[j+1]^=mul(p[j],exp[i])}p=q}return p};
 let bits="0100"+bytes.length.toString(2).padStart(16,"0")+bytes.map(v=>v.toString(2).padStart(8,"0")).join("");
 bits+="0".repeat(Math.min(4,cap*8-bits.length));while(bits.length%8)bits+="0";
 const data=[];for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8),2));for(let i=0;data.length<cap;i++)data.push(i%2?0x11:0xec);
 const blocks=[],lengths=[68,68,69,69];let p=0;for(const n of lengths)blocks.push(data.slice(p,p+=n));
 const g=gen(18),ecc=blocks.map(b=>{let r=b.concat(Array(18).fill(0));for(let i=0;i<b.length;i++){let f=r[i];if(f)for(let j=0;j<g.length;j++)r[i+j]^=mul(g[j],f)}return r.slice(-18)});
 const stream=[];for(let i=0;i<69;i++)for(const b of blocks)if(i<b.length)stream.push(b[i]);for(let i=0;i<18;i++)for(const b of ecc)stream.push(b[i]);
 const base=()=>Array.from({length:size},()=>Array(size).fill(-1)),set=(m,r,c,v)=>{if(r>=0&&c>=0&&r<size&&c<size)m[r][c]=v?1:0};
 const m=base(),finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)set(m,r+y,c+z,y>=0&&y<7&&z>=0&&z<7&&(y==0||y==6||z==0||z==6||(y>=2&&y<=4&&z>=2&&z<=4)))};
 finder(0,0);finder(0,size-7);finder(size-7,0);
 const align=(r,c)=>{for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)set(m,r+y,c+z,Math.max(Math.abs(y),Math.abs(z))!=1)};
 [6,28,50].forEach(r=>[6,28,50].forEach(c=>{if(m[r][c]<0)align(r,c)}));
 for(let i=8;i<size-8;i++){if(m[6][i]<0)set(m,6,i,i%2==0);if(m[i][6]<0)set(m,i,6,i%2==0)}set(m,size-8,8,1);
 for(let i=0;i<9;i++){if(m[8][i]<0)set(m,8,i,0);if(m[i][8]<0)set(m,i,8,0);if(m[8][size-1-i]<0)set(m,8,size-1-i,0);if(m[size-1-i][8]<0)set(m,size-1-i,8,0)}
 for(let i=0;i<18;i++){set(m,Math.floor(i/3),size-11+i%3,0);set(m,size-11+i%3,Math.floor(i/3),0)}
 const bch=(v,poly)=>{let d=v;while(d.toString(2).length>=poly.toString(2).length)d^=poly<<(d.toString(2).length-poly.toString(2).length);return d};
 const mask=(k,r,c)=>[ (r+c)%2==0,r%2==0,c%3==0,(r+c)%3==0,(Math.floor(r/2)+Math.floor(c/3))%2==0,(r*c)%2+(r*c)%3==0,((r*c)%2+(r*c)%3)%2==0,((r+c)%2+(r*c)%3)%2==0 ][k];
 const place=k=>{const q=m.map(a=>a.slice());let bit=0,up=true;for(let c=size-1;c>0;c-=2){if(c==6)c--;for(let z=0;z<size;z++){let r=up?size-1-z:z;for(let d=0;d<2;d++){let cc=c-d;if(q[r][cc]<0){let v=bit<stream.length*8?((stream[bit>>>3]>>>(7-(bit&7)))&1):0;bit++;q[r][cc]=v^(mask(k,r,cc)?1:0)}}up=!up}return q};
 const format=(q,k)=>{let d=(1<<3)|k,f=((d<<10)|bch(d<<10,0x537))^0x5412;for(let i=0;i<15;i++){let v=(f>>>i)&1;if(i<6)set(q,i,8,v);else if(i<8)set(q,i+1,8,v);else set(q,size-15+i,8,v);if(i<8)set(q,8,size-1-i,v);else set(q,8,15-i,v)}set(q,size-8,8,1);let vd=(10<<12)|bch(10<<12,0x1f25);for(let i=0;i<18;i++){let v=(vd>>>i)&1;set(q,Math.floor(i/3),size-11+i%3,v);set(q,size-11+i%3,Math.floor(i/3),v)}};
 const score=q=>{let n=0;for(let r=0;r<size;r++)for(let c=0;c<size;c++){let v=q[r][c],run=1;while(c+run<size&&q[r][c+run]==v)run++;if(run>=5)n+=run-2;run=1;while(r+run<size&&q[r+run][c]==v)run++;if(run>=5)n+=run-2;if(r<size-1&&c<size-1&&v==q[r+1][c]&&v==q[r][c+1]&&v==q[r+1][c+1])n+=3}for(let r=0;r<size;r++)for(let c=0;c<size-6;c++){let a=q[r].slice(c,c+7).join("");if(a=="1011101")n+=40}for(let c=0;c<size;c++)for(let r=0;r<size-6;r++){let a="";for(let i=0;i<7;i++)a+=q[r+i][c];if(a=="1011101")n+=40}let dark=q.flat().filter(Boolean).length;n+=Math.floor(Math.abs(dark*20-size*size*10)/(size*size))*10;return n};
 let best,bs=Infinity;for(let k=0;k<8;k++){let q=place(k);format(q,k);let z=score(q);if(z<bs){bs=z;best=q}}let rect="";for(let r=0;r<size;r++)for(let c=0;c<size;c++)if(best[r][c])rect+='<rect x="'+(c+4)+'" y="'+(r+4)+'" width="1" height="1"/>';
 return '<svg class="qr" viewBox="0 0 '+(size+8)+' '+(size+8)+'" role="img" aria-label="Scannable QR code for authenticator setup" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="white"/><g fill="black">'+rect+"</g></svg>";
}
async function request(path,data,method="POST"){let r;try{r=await fetch(path,{method,credentials:"same-origin",headers:method==="POST"?{"Content-Type":"application/json","X-CSRF-Token":s.csrf}:{},body:method==="POST"?JSON.stringify(data||{}):undefined})}catch{throw Error("Connection problem. Please try again.")}const x=await r.json().catch(()=>({message:"We could not complete that request."}));if(r.status===401){s.csrf="";s.screen="signin"}if(!r.ok)throw Error(x.message||"We could not complete that request.");return x}
async function copy(v,m){try{await navigator.clipboard.writeText(v);say(m)}catch{say("Copy was not available. You can select the text and copy it.")}render()}
async function provision(refresh=false){const r=await request("/api/authenticator/provision",{refresh});s.secret=r.secret;s.uri=r.uri;s.otp=r.mockCode;s.expired=false;s.show=false;browserLog("Mock authenticator TOTP: "+r.mockCode,"Authenticator setup details are ready.")}
async function status(){const r=await request("/api/mfa/status",null,"GET");s.csrf=r.csrf||s.csrf;if(!r.identityVerified)s.screen="identity";else if(r.mfaEnabled)s.screen=r.backupCodesConfirmed?"settings":"backup";else{ s.screen="setup";s.expired=r.provisionState==="expired";if(!s.expired)await provision(false) }return r}
function render(){let h="";
if(s.screen==="signin")h=shell("Step 1 of 5","Sign in to start","👋","Use your bank email and demo credential.",'<form id="sign"><label>Email address<input id="email" type="email" autocomplete="username email" placeholder="marcus@example.test" required></label><p class="hint">Example: marcus@example.test</p><label>Demo credential<input id="credential" type="password" autocomplete="current-password" placeholder="Example: Harbour-demo-54" required></label><button>Continue</button></form>',"Enter both details.");
if(s.screen==="identity")h=shell("Step 2 of 5","Check it is you","✉️","Use the 6-digit check code in this safe demo.",'<form id="ident"><label>Check code<input id="identity" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456" required></label><button>Check code</button></form><button class="secondary" id="fillI">Use demo code</button><button class="secondary" id="resend">Send a new code</button>',"Use the demo-code button. There is plenty of time.");
if(s.screen==="setup"){let inside=s.expired?'<div class="status">Your earlier setup details have expired. Request a fresh set when you are ready.</div><button id="fresh">Request fresh setup details</button>':'<p class="status">Your setup details are ready but hidden for privacy.</p><button id="show">Reveal setup details</button>';if(!s.expired&&s.show)inside+='<p class="qr-label">Scan QR code</p>'+qrSvg(s.uri)+'<p class="hint">Or use one of these options instead of typing.</p><p class="hint">Manual secret</p><div class="secret">'+esc(s.secret)+'</div><button class="small secondary" id="copyS">Copy secret</button><p class="hint">Provisioning URI</p><div class="secret">'+esc(s.uri)+'</div><button class="small secondary" id="copyU">Copy provisioning URI</button><button class="small secondary" id="hide">Hide setup details</button><button id="toOtp">I added the authenticator</button>';h=shell("Step 3 of 5","Add your authenticator","📱","Reveal the QR code only when you are ready to scan or copy it.",inside,"Setup details stay hidden until you choose to reveal them. No reading time limit applies.")}
if(s.screen==="otp")h=shell("Step 4 of 5","Confirm your authenticator","🔐","Enter the 6-digit code from your authenticator app.",'<form id="otpform"><label>Authenticator code<input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456" required></label><button>Confirm authenticator</button></form><button class="secondary" id="fillO">Use current demo code</button><button class="secondary" id="restart">Show fresh setup details</button>',"Codes change every 30 seconds. There is no limit on reading time.");
if(s.screen==="backup")h=shell("Step 5 of 5","Save your recovery codes","🧾","Your authenticator is active. Save and confirm this recovery-code set to finish.",s.codes.length?'<ul class="code-list">'+s.codes.map(x=>"<li>"+esc(x)+"</li>").join("")+'</ul><button class="small secondary" id="copyC">Copy all codes</button><label class="checkline"><input id="saved" type="checkbox"><span>I have saved my recovery codes.</span></label><button id="finish">Finish security setup</button><button class="secondary" id="regen">Make a new recovery-code set</button>':'<div class="status">Your codes were created earlier. Make a new set to view them again.</div><button id="regen">Make a new recovery-code set</button>',"Make a new set if you need to see the codes again.");
if(s.screen==="settings")h=shell("Security settings","MFA is ready","✅","Your authenticator and recovery codes are active.",'<div class="status">🛡️ <strong>Authenticator:</strong> active<br>🧾 <strong>Recovery codes:</strong> confirmed</div><label>Test a recovery code<input id="recovery" autocapitalize="characters" placeholder="Example: ABCDE-FGHIJ"></label><button id="test">Test recovery code</button><button class="secondary" id="regen">Make new recovery codes</button><button class="secondary" id="logout">Sign out</button>',"New recovery codes replace old ones and need confirmation.");
app.innerHTML=h;bind()}
function bind(){const $=x=>document.querySelector(x);
if(s.screen==="signin")$("#sign").onsubmit=async e=>{e.preventDefault();try{const r=await request("/api/signin",{email:$("#email").value,credential:$("#credential").value});s.csrf=r.csrf;s.identityCode=r.mockCode;browserLog("Mock identity code: "+r.mockCode,"A demo identity check code is ready.");await status();render()}catch(x){say("",x.message);render()}};
if(s.screen==="identity"){$("#ident").onsubmit=async e=>{e.preventDefault();try{await request("/api/identity/verify",{code:$("#identity").value});await status();say("Identity check complete. Add your authenticator next.");render()}catch(x){say("",x.message);render()}};$("#fillI").onclick=()=>$("#identity").value=s.identityCode;$("#resend").onclick=async()=>{try{const r=await request("/api/identity/send");s.identityCode=r.mockCode;browserLog("Mock identity code: "+r.mockCode,"A new demo identity check code is ready.");say("A new demo code is ready.");render()}catch(x){say("",x.message);render()}}}
if(s.screen==="setup"){if($("#fresh"))$("#fresh").onclick=async()=>{try{await provision(true);say("Fresh setup details are ready. Reveal them when ready.");render()}catch(x){say("",x.message);render()}};if($("#show"))$("#show").onclick=()=>{s.show=true;render()};if($("#hide"))$("#hide").onclick=()=>{s.show=false;render()};if($("#copyS"))$("#copyS").onclick=()=>copy(s.secret,"Secret copied.");if($("#copyU"))$("#copyU").onclick=()=>copy(s.uri,"Provisioning URI copied.");if($("#toOtp"))$("#toOtp").onclick=()=>{s.screen="otp";say("Your next step is to confirm the 6-digit code.");render()}}
if(s.screen==="otp"){$("#otpform").onsubmit=async e=>{e.preventDefault();try{const r=await request("/api/authenticator/verify",{code:$("#otp").value});s.codes=r.codes;browserLog("Mock recovery codes: "+r.codes.join(", "),"Recovery codes have been generated.");s.screen="backup";render()}catch(x){say("",x.message);render()}};$("#fillO").onclick=()=>$("#otp").value=s.otp;$("#restart").onclick=async()=>{try{await provision(true);s.screen="setup";say("Fresh setup details are ready. Reveal them when ready.");render()}catch(x){say("",x.message);render()}}}
if(s.screen==="backup"){if($("#copyC"))$("#copyC").onclick=()=>copy(s.codes.join("\n"),"Recovery codes copied.");if($("#finish"))$("#finish").onclick=async()=>{if(!$("#saved").checked){say("Please tick the box after you have saved the codes.");render();return}try{await request("/api/backup/confirm");s.codes=[];s.screen="settings";say("Security setup is complete.");render()}catch(x){say("",x.message);render()}};$("#regen").onclick=async()=>{try{const r=await request("/api/recovery/regenerate");s.codes=r.codes;browserLog("New mock recovery codes: "+r.codes.join(", "),"New recovery codes have been generated.");say("Save this new set, then confirm it.");render()}catch(x){say("",x.message);render()}}}
if(s.screen==="settings"){$("#test").onclick=async()=>{try{await request("/api/recovery/verify",{code:$("#recovery").value.toUpperCase()});say("That recovery code worked and is now used.");render()}catch(x){say("",x.message);render()}};$("#regen").onclick=async()=>{try{const r=await request("/api/recovery/regenerate");s.codes=r.codes;browserLog("New mock recovery codes: "+r.codes.join(", "),"New recovery codes have been generated.");s.screen="backup";say("Save this new set, then confirm it.");render()}catch(x){say("",x.message);render()}};$("#logout").onclick=async()=>{try{await request("/api/logout");s.csrf="";s.screen="signin";say("You have signed out.");render()}catch(x){say("",x.message);render()}}}}
(async()=>{try{await status();render()}catch{render()}})()})()</script></body></html>`;

function html() { const nonce = token(18), h = headers(nonce); h.set("Content-Type", "text/html; charset=utf-8"); return new Response(page.replaceAll("__NONCE__", nonce), { headers: h }); }

async function route(r: Request): Promise<Response> {
  const u = new URL(r.url);
  if (r.method === "OPTIONS") return origins.has(r.headers.get("origin") || "") ? cors(r, new Response(null, { status: 204, headers: headers() })) : fail(403, "Request not allowed.");
  if (u.pathname === "/" && r.method === "GET") return html();
  if (!u.pathname.startsWith("/api/")) return fail(404, "Page not found.");

  if (u.pathname === "/api/signin" && r.method === "POST") {
    const d = await body(r), email = d && typeof d.email === "string" ? d.email : "", credential = d && typeof d.credential === "string" ? d.credential : "";
    const syntacticallyValid = emailOK(email) && credentialOK(credential);
    const account = emailOK(email) ? [...accounts.values()].find(a => a.email.toLowerCase() === email.toLowerCase()) : undefined;
    const key = ("local:" + email.toLowerCase()).slice(0, 320);
    let state = account?.signIn;
    if (!state) { state = anonymousAttempts.get(key) || { count: 0, lockedUntil: 0, last: 0 }; anonymousAttempts.set(key, state); }
    let valid = false;
    if (syntacticallyValid) { const suppliedHash = await hash(credential); valid = suppliedHash === (account?.credentialHash || dummyCredentialHash); }
    if (!origins.has(r.headers.get("origin") || "") || locked(state.lockedUntil) || !valid || !account) {
      if ((!valid || !account) && !locked(state.lockedUntil)) recordFailure(state);
      return cors(r, fail(401, signMessage));
    }
    account.signIn = { count: 0, lockedUntil: 0, last: Date.now() };
    for (const [id, s] of sessions) if (s.userId === account.id) sessions.delete(id);
    const id = token(), csrfToken = token(), code = numberCode();
    sessions.set(id, { userId: account.id, csrf: csrfToken, made: Date.now(), seen: Date.now() });
    if (!account.identityVerified) { account.identity = await makeCheck(code); account.lastIdentitySent = Date.now(); }
    const out = json({ ok: true, csrf: csrfToken, mockCode: code }); out.headers.set("Set-Cookie", authCookie(id)); return cors(r, out);
  }

  const active = session(r);
  if (!active) { const out = fail(401, "Please sign in again to continue."); out.headers.set("Set-Cookie", deadCookie()); return cors(r, out); }
  const { s, a } = active;
  if (r.method !== "GET" && !csrf(r, s)) return cors(r, fail(403, "Your secure form check did not match. Refresh and try again."));

  if (u.pathname === "/api/mfa/status" && r.method === "GET") {
    const provisionState = !a.identityVerified || a.mfaEnabled ? "none" : a.seed && Date.now() > a.provisionExpires ? "expired" : "valid";
    return cors(r, json({ ok: true, csrf: s.csrf, identityVerified: a.identityVerified, mfaEnabled: a.mfaEnabled, backupCodesConfirmed: a.backupCodesConfirmed, provisionState }));
  }
  if (u.pathname === "/api/identity/send" && r.method === "POST") {
    if (locked(a.identityLocked)) return cors(r, fail(429, "Too many tries. Please wait 10 minutes before trying again."));
    if (Date.now() - a.lastIdentitySent < ISSUE) return cors(r, fail(429, "Please wait a short moment before requesting another code."));
    const code = numberCode(); a.identity = await makeCheck(code); a.lastIdentitySent = Date.now();
    return cors(r, json({ ok: true, mockCode: code }));
  }
  if (u.pathname === "/api/identity/verify" && r.method === "POST") {
    const d = await body(r); if (!d || !codeOK(d.code)) return cors(r, fail(400, "Enter exactly 6 numbers, for example 123456."));
    if (locked(a.identityLocked)) return cors(r, fail(429, "Too many tries. Please wait 10 minutes before trying again."));
    const c = a.identity; if (!c || c.used || Date.now() > c.expires) return cors(r, fail(400, "That code is no longer available. Request a new code and try again."));
    if (await hash(d.code) !== c.hash) { if (++a.identityFails >= MAX) { a.identityFails = 0; a.identityLocked = Date.now() + LOCK; } return cors(r, fail(400, "That code does not match. Check the 6 numbers and try again.")); }
    c.used = true; a.identityVerified = true; a.identityFails = 0; return cors(r, json({ ok: true }));
  }
  if (u.pathname === "/api/authenticator/provision" && r.method === "POST") {
    if (!a.identityVerified) return cors(r, fail(403, "Complete the identity check before MFA settings can change.", true));
    if (a.mfaEnabled) return cors(r, fail(403, "Your authenticator is already active."));
    const d = await body(r), refresh = d?.refresh === true, expired = !!a.seed && Date.now() > a.provisionExpires;
    if (expired && !refresh) return cors(r, fail(400, "Your setup details have expired. Request fresh setup details."));
    if (!a.seed || refresh) { a.seed = await crypt(base32(32)); a.provisionExpires = Date.now() + VERIFY; a.usedTotps.clear(); }
    const seed = await uncrypt(a.seed);
    return cors(r, json({ ok: true, secret: seed, uri: uri(seed), mockCode: await totp(seed) }));
  }
  if (u.pathname === "/api/authenticator/verify" && r.method === "POST") {
    if (!a.identityVerified) return cors(r, fail(403, "Complete the identity check before MFA settings can change.", true));
    const d = await body(r); if (!d || !codeOK(d.code)) return cors(r, fail(400, "Enter exactly 6 numbers, for example 123456."));
    if (locked(a.totpLocked)) return cors(r, fail(429, "Too many authenticator tries. Please wait 10 minutes before trying again."));
    if (!a.seed || Date.now() > a.provisionExpires) return cors(r, fail(400, "Show fresh setup details before entering a code."));
    const seed = await uncrypt(a.seed), used = await hash(d.code), step = Math.floor(Date.now() / 30000);
    const valid = [await totp(seed, step), await totp(seed, step - 1), await totp(seed, step + 1)].includes(d.code) && !a.usedTotps.has(used);
    if (!valid) { if (++a.totpFails >= MAX) { a.totpFails = 0; a.totpLocked = Date.now() + LOCK; } return cors(r, fail(400, "That code does not match a current authenticator code. Check the app and try again.")); }
    a.usedTotps.add(used); a.totpFails = 0; a.mfaEnabled = true;
    return cors(r, json({ ok: true, codes: await makeCodes(a) }));
  }
  if (u.pathname === "/api/backup/confirm" && r.method === "POST") {
    if (!a.identityVerified || !a.mfaEnabled) return cors(r, fail(403, "Set up an authenticator first."));
    if (!a.backups.size) return cors(r, fail(400, "Make a new recovery-code set before confirming it."));
    a.backupCodesConfirmed = true; return cors(r, json({ ok: true }));
  }
  if (u.pathname === "/api/recovery/regenerate" && r.method === "POST") {
    if (!a.identityVerified || !a.mfaEnabled) return cors(r, fail(403, "Set up an authenticator first."));
    return cors(r, json({ ok: true, codes: await makeCodes(a) }));
  }
  if (u.pathname === "/api/recovery/verify" && r.method === "POST") {
    if (!a.identityVerified || !a.mfaEnabled) return cors(r, fail(403, "Set up an authenticator first."));
    const d = await body(r); if (!d || !recoveryOK(d.code)) return cors(r, fail(400, "Enter a recovery code like ABCDE-FGHIJ."));
    if (locked(a.recoveryLocked)) return cors(r, fail(429, "Too many recovery-code tries. Please wait 10 minutes before trying again."));
    const h = await hash(d.code);
    if (!a.backups.has(h)) { if (++a.recoveryFails >= MAX) { a.recoveryFails = 0; a.recoveryLocked = Date.now() + LOCK; } return cors(r, fail(400, "That recovery code is not available. Check it or use another saved code.")); }
    a.backups.delete(h); a.recoveryFails = 0; return cors(r, json({ ok: true }));
  }
  if (u.pathname === "/api/logout" && r.method === "POST") {
    const id = cookie(r, "mfa_session"); if (id) sessions.delete(id);
    const out = json({ ok: true }); out.headers.set("Set-Cookie", deadCookie()); return cors(r, out);
  }
  return cors(r, fail(404, "Page not found."));
}

/* TLS requirement: supplied mkcert certificates enforce HTTPS. */
Bun.serve({
  port: 3000, hostname: "0.0.0.0",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(r) { try { return await route(r); } catch { return fail(500, "We could not complete that request. Please try again."); } }
});
console.log("MFA enrolment server ready at https://localhost:3000");
