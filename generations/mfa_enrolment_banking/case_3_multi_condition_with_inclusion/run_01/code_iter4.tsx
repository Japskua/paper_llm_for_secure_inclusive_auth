
const enc = new TextEncoder(), dec = new TextDecoder();
const pepper = b64(rand(32));
const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

type Check = { hash: string; expires: number; used: boolean };
type Cipher = { iv: string; data: string };
type Account = {
  id: string; email: string; identityVerified: boolean; identity?: Check;
  identityFails: number; identityLocked: number; lastIdentitySent: number;
  seed?: Cipher; mfaEnabled: boolean; totpFails: number; totpLocked: number;
  usedSteps: Set<number>; backups: Set<string>; recoveryFails: number;
  recoveryStart: number; recoveryLocked: number;
};
type Session = { userId: string; csrf: string; made: number; seen: number };

const accounts = new Map<string, Account>();
const sessions = new Map<string, Session>();
accounts.set("marcus-account", {
  id: "marcus-account", email: "marcus@example.test", identityVerified: false,
  identityFails: 0, identityLocked: 0, lastIdentitySent: 0, mfaEnabled: false,
  totpFails: 0, totpLocked: 0, usedSteps: new Set(), backups: new Set(),
  recoveryFails: 0, recoveryStart: 0, recoveryLocked: 0
});

const IDLE = 30 * 60e3, ABS = 8 * 60 * 60e3, VERIFY = 30 * 60e3, LOCK = 10 * 60e3;
const MAX = 5, ISSUE = 20e3, DEMO = "123456";
const origins = new Set(["https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000"]);

/* Security requirements: cryptographically secure generation and encrypted/hash-only storage. */
function rand(n: number) { const x = new Uint8Array(n); crypto.getRandomValues(x); return x; }
function b64(x: Uint8Array) { return btoa(String.fromCharCode(...x)); }
function ub64(s: string) { return Uint8Array.from(atob(s), x => x.charCodeAt(0)); }
function token(n = 32) { return b64(rand(n)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); }
function base32(n: number) { const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", x = rand(n); return [...x].map(v => a[v % 32]).join(""); }
function recovery() { const x = base32(10); return x.slice(0, 5) + "-" + x.slice(5); }
async function hash(x: string) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(x + ":" + pepper)))); }
async function crypt(x: string): Promise<Cipher> {
  const iv = rand(12), d = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(x));
  return { iv: b64(iv), data: b64(new Uint8Array(d)) };
}
async function uncrypt(x: Cipher) {
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: ub64(x.iv) }, key, ub64(x.data)));
}
function seedBytes(s: string) {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let v = 0, bits = 0; const out: number[] = [];
  for (const c of s) { const n = a.indexOf(c); if (n < 0) throw Error("seed"); v = (v << 5) | n; bits += 5; if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8; } }
  return new Uint8Array(out);
}
/* RFC 6238 TOTP. Accepted counter values are recorded to make codes single-use. */
async function totp(seed: string, step: number) {
  const c = new Uint8Array(8); let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { c[i] = Number(n & 255n); n >>= 8n; }
  const k = await crypto.subtle.importKey("raw", seedBytes(seed), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", k, c)), off = mac[19] & 15;
  const x = ((mac[off] & 127) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(x % 1e6).padStart(6, "0");
}
function cookie(r: Request, n: string) {
  return (r.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(n + "="))?.slice(n.length + 1);
}
function headers(nonce?: string) {
  return new Headers({
    "Content-Security-Policy": nonce ? `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` : "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
  });
}
function json(x: unknown, status = 200) { const h = headers(); h.set("Content-Type", "application/json; charset=utf-8"); return new Response(JSON.stringify(x), { status, headers: h }); }
function fail(status: number, message: string, identityRequired = false) { return json({ ok: false, message, identityRequired }, status); }
function cors(r: Request, res: Response) {
  const o = r.headers.get("origin"); if (o && origins.has(o)) { res.headers.set("Access-Control-Allow-Origin", o); res.headers.set("Access-Control-Allow-Credentials", "true"); }
  res.headers.set("Vary", "Origin"); res.headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token"); res.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); return res;
}
function session(r: Request) {
  const id = cookie(r, "mfa_session"), s = id && sessions.get(id), now = Date.now(), a = s && accounts.get(s.userId);
  if (!s || !a || now - s.seen > IDLE || now - s.made > ABS) { if (id) sessions.delete(id); return; }
  s.seen = now; return { s, a };
}
function csrf(r: Request, s: Session) { return origins.has(r.headers.get("origin") || "") && r.headers.get("x-csrf-token") === s.csrf; }
async function body(r: Request): Promise<Record<string, unknown> | undefined> {
  if (!(r.headers.get("content-type") || "").includes("application/json")) return;
  const text = await r.text(); if (text.length > 3000) return;
  try { const x = JSON.parse(text); return x && typeof x === "object" && !Array.isArray(x) ? x : undefined; } catch { return; }
}
const emailOK = (x: unknown): x is string => typeof x === "string" && x.length < 255 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x);
const codeOK = (x: unknown): x is string => typeof x === "string" && /^\d{6}$/.test(x);
const recoveryOK = (x: unknown): x is string => typeof x === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(x);
const locked = (x: number) => Date.now() < x;
async function check(code: string): Promise<Check> { return { hash: await hash(code), expires: Date.now() + VERIFY, used: false }; }
async function codes(a: Account) {
  const c = Array.from({ length: 8 }, recovery); a.backups = new Set(await Promise.all(c.map(hash)));
  a.recoveryFails = a.recoveryStart = a.recoveryLocked = 0; return c;
}
function identityNeeded() { return fail(403, "Complete the identity check before MFA or recovery-code settings can change.", true); }

const page = String.raw`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Harbour Bank · Security setup</title>
<style nonce="__NONCE__">
:root{--ink:#17243a;--muted:#536276;--blue:#075fc8;--line:#cbd6e3;--bad:#b42318;--good:#126b43}*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:var(--ink);font:17px/1.7 Arial,Verdana,Tahoma,sans-serif;letter-spacing:.025em}main{width:min(100%,620px);margin:auto;padding:18px 15px 40px}.brand{font-weight:bold;color:#064b9e;margin:5px 5px 18px}h1{font-size:1.55rem;line-height:1.3;margin:0 0 9px}p{margin:0 0 14px}.card,.logs{background:#fff;border:1px solid var(--line);border-radius:15px;padding:22px 18px;box-shadow:0 2px 8px #1935540d}.logs{margin-top:16px}.step{color:var(--blue);font-weight:bold;margin:0 0 12px}.icon{font-size:1.5rem;margin-right:8px}label{display:block;font-weight:bold;margin:16px 0 6px}input{width:100%;min-height:52px;border:2px solid #8ba0b8;border-radius:10px;padding:12px;font:inherit;letter-spacing:.05em}input:focus{outline:3px solid #8bc5ff;outline-offset:2px;border-color:var(--blue)}button{width:100%;min-height:52px;margin-top:15px;border:0;border-radius:10px;background:var(--blue);color:#fff;font:bold 1rem Arial,sans-serif;padding:11px;cursor:pointer}.secondary{background:#fff;color:#064b9e;border:2px solid #1e70c7}.small{width:auto;min-height:40px;margin:7px 7px 0 0;padding:7px 11px}.hint,details{color:var(--muted);font-size:.94rem}.notice{margin-top:15px;padding:12px;border-radius:9px;font-weight:bold}.error{background:#fff0ef;color:var(--bad);border-left:5px solid var(--bad)}.ok{background:#eaf8f0;color:var(--good);border-left:5px solid var(--good)}.secret{overflow-wrap:anywhere;background:#f5f8fc;border:1px dashed #7891ae;padding:11px;border-radius:8px;font-family:monospace;font-weight:bold}.hidden{color:#536276;letter-spacing:.1em}.qr{display:block;width:min(100%,270px);height:auto;margin:15px auto;border:7px solid #fff;image-rendering:pixelated}.code-list{list-style:none;padding:0}.code-list li{margin:8px 0;padding:8px 10px;background:#f5f8fc;font-family:monospace;font-weight:bold;border-radius:7px}.checkline{display:flex;gap:10px;align-items:flex-start}.checkline input{width:23px;min-height:23px;margin-top:5px}.status{padding:10px;background:#eef6ff;border-radius:9px}summary{color:var(--blue);font-weight:bold;cursor:pointer}#log{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.5 monospace;max-height:170px;overflow:auto}@media(max-width:370px){body{font-size:16px}.card{padding:18px 14px}}
</style></head><body><main><header><div class="brand">◆ Harbour Bank</div></header><section id="app" aria-live="polite"></section><section class="logs" aria-label="Logs"><strong>Logs</strong><div id="log">Demo messages will appear here.</div></section></main>
<script nonce="__NONCE__">(()=>{"use strict";
const app=document.querySelector("#app"),logBox=document.querySelector("#log");
const s={csrf:"",screen:"signin",identityCode:"",otp:"",secret:"",uri:"",codes:[],message:"",error:"",showUri:false,showSecret:false};
const esc=v=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function log(x){console.log(x);logBox.textContent=(logBox.textContent==="Demo messages will appear here."?"":logBox.textContent+"\\n")+x}
function say(m,e=""){s.message=m;s.error=e}function note(){return s.error?'<div class="notice error">'+esc(s.error)+"</div>":s.message?'<div class="notice ok">'+esc(s.message)+"</div>":""}
function shell(step,title,icon,text,inside,hint){return '<article class="card"><p class="step">'+step+'</p><h1><span class="icon">'+icon+"</span>"+title+"</h1><p>"+text+"</p>"+inside+note()+'<details><summary>Need help?</summary><p>'+esc(hint)+"</p></details></article>"}
async function api(path,data){let r;try{r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":s.csrf},body:JSON.stringify(data||{})})}catch{throw Error("Connection problem. Please try again.")}const j=await r.json().catch(()=>({message:"We could not complete that request."}));if(j.identityRequired){s.screen="identity";say("The identity check must be completed before MFA or recovery-code settings can change.",j.message);render()}if(r.status===401){s.csrf="";s.screen="signin";render()}if(!r.ok)throw Error(j.message||"We could not complete that request.");return j}
async function copy(x,m){try{await navigator.clipboard.writeText(x);say(m);render()}catch{say("Copy was not available. You can select the text and copy it.");render()}}
/* Real QR Code: Version 5-L byte-mode encoder. It encodes exactly the supplied otpauth URI. */
function qr(uri){const bytes=[...new TextEncoder().encode(uri)],N=37;if(bytes.length>106)return"";let d=[64|bytes.length,...bytes];while(d.length<108)d.push(d.length===bytes.length+1?0:0);let bits=[];d.forEach(x=>{for(let i=7;i>=0;i--)bits.push(x>>i&1)});bits=bits.slice(0,864);while(bits.length<864)bits.push(0);let raw=[];for(let i=0;i<108;i++){let x=0;for(let j=0;j<8;j++)x=x*2+bits[i*8+j];raw.push(x)}for(let i=bytes.length+2;i<108;i++)raw[i]=(i-(bytes.length+2))%2?17:236;let exp=[1],log=Array(256);for(let i=1;i<512;i++){exp[i]=exp[i-1]*2; if(exp[i]&256)exp[i]^=285}for(let i=0;i<255;i++)log[exp[i]]=i;let gen=[1];for(let i=0;i<26;i++){let q=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){q[j]^=gen[j];q[j+1]^=exp[(log[gen[j]]+i)%255]}gen=q}let ecc=Array(26).fill(0);for(const x of raw){let f=x^ecc.shift();ecc.push(0);for(let j=0;j<26;j++)if(gen[j+1]&&f)ecc[j]^=exp[(log[gen[j+1]]+log[f])%255]}let stream=[...raw,...ecc].flatMap(x=>Array.from({length:8},(_,i)=>(x>>(7-i))&1));let m=Array.from({length:N},()=>Array(N).fill(null)),set=(r,c,v)=>{if(r>=0&&c>=0&&r<N&&c<N)m[r][c]=v};function finder(r,c){for(let y=-1;y<8;y++)for(let x=-1;x<8;x++)set(r+y,c+x,y>=0&&y<7&&x>=0&&x<7&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4))?1:0)}finder(0,0);finder(0,N-7);finder(N-7,0);for(let i=8;i<N-8;i++){set(6,i,i%2===0?1:0);set(i,6,i%2===0?1:0)}for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(30+y,30+x,Math.max(Math.abs(x),Math.abs(y))!==1?1:0);set(N-8,8,1);for(let i=0;i<9;i++){if(m[8][i]===null)set(8,i,0);if(m[i][8]===null)set(i,8,0);if(m[8][N-1-i]===null)set(8,N-1-i,0);if(m[N-1-i][8]===null)set(N-1-i,8,0)}let k=0,up=true;for(let c=N-1;c>0;c-=2){if(c===6)c--;for(let z=0;z<N;z++){let r=up?N-1-z:z;for(let x=0;x<2;x++)if(m[r][c-x]===null){let v=stream[k++]||0;m[r][c-x]=v^((r+c-x)%2===0?1:0)}}up=!up}let f=8;for(let i=0;i<10;i++)f=(f<<1)^(((f>>>9)&1)?0x537:0);f=(8<<10|f)^0x5412;for(let i=0;i<15;i++){let v=(f>>i)&1;if(i<6)set(i,8,v);else if(i<8)set(i+1,8,v);else set(N-15+i,8,v);if(i<8)set(8,N-i-1,v);else if(i<9)set(8,15-i,v);else set(8,15-i-1,v)}let cells="";for(let r=0;r<N;r++)for(let c=0;c<N;c++)if(m[r][c])cells+='<rect x="'+c+'" y="'+r+'" width="1" height="1"/>';return '<svg class="qr" viewBox="0 0 '+N+" "+N+'" role="img" aria-label="QR code containing your authenticator setup URI" xmlns="http://www.w3.org/2000/svg"><rect width="100%" height="100%" fill="white"/><g fill="#17243a">'+cells+"</g></svg>"}
function render(){let h="";if(s.screen==="signin")h=shell("Step 1 of 5","Sign in to start","👋","Use the email for your bank account.",'<form id="sign"><label>Email address<input id="email" type="email" autocomplete="username email" placeholder="marcus@example.test" required></label><p class="hint">Example: marcus@example.test</p><button>Continue</button></form>',"Use the demo account email shown in the example.");
if(s.screen==="identity")h=shell("Step 2 of 5","Check it is you","✉️","We sent a 6-digit check code in this safe demo.",'<form id="ident"><label>Check code<input id="identity" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456" required></label><button>Check code</button></form><button class="secondary" id="fillI">Use demo code</button><button class="secondary" id="resend">Send a new code</button>',"The demo code is in the Logs panel. There is plenty of time.");
if(s.screen==="setup"){let u=s.showUri?esc(s.uri):'<span class="hidden">Hidden for privacy</span>',x=s.showSecret?esc(s.secret):'<span class="hidden">Hidden for privacy</span>';h=shell("Step 3 of 5","Add your authenticator","📱","This QR code genuinely contains your setup URI. Scan it with your authenticator app.",qr(s.uri)+'<p class="hint">The QR code encodes the same setup URI shown below. You can reveal and copy it instead.</p><p class="hint">Manual setup URI</p><div class="secret">'+u+'</div><button class="small secondary" id="tu">'+(s.showUri?"Hide setup URI":"Reveal setup URI")+'</button><button class="small secondary" id="cu">Copy setup URI</button><p class="hint">Manual secret</p><div class="secret">'+x+'</div><button class="small secondary" id="ts">'+(s.showSecret?"Hide secret":"Reveal secret")+'</button><button class="small secondary" id="cs">Copy secret</button><button id="toOtp">I added the authenticator</button>',"The QR code, setup URI, and secret set up the same authenticator.");
}
if(s.screen==="otp")h=shell("Step 4 of 5","Confirm your authenticator","🔐","Enter the 6-digit code from your authenticator app.",'<form id="otpform"><label>Authenticator code<input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456" required></label><button>Confirm authenticator</button></form><button class="secondary" id="fillO">Use demo code</button><button class="secondary" id="restart">Show setup details again</button>',"The demo code is in the Logs panel. You can retry.");
if(s.screen==="backup")h=shell("Step 5 of 5","Save your recovery codes","🧾","Keep these codes somewhere safe. Each works once if you lose your phone.",'<ul class="code-list">'+s.codes.map(x=>"<li>"+esc(x)+"</li>").join("")+'</ul><button class="small secondary" id="copyCodes">Copy all codes</button><label class="checkline"><input id="saved" type="checkbox"><span>I have saved my recovery codes.</span></label><button id="finish">Finish security setup</button>',"Copy the codes rather than typing them.");
if(s.screen==="settings")h=shell("Security settings","MFA is ready","✅","Your authenticator and recovery codes are active.",'<div class="status">🛡️ <strong>Authenticator:</strong> active</div><label>Test a recovery code<input id="recovery" autocapitalize="characters" placeholder="Example: ABCDE-FGHIJ"></label><button id="test">Test recovery code</button><button class="secondary" id="regen">Make new recovery codes</button><button class="secondary" id="logout">Sign out</button>',"New recovery codes replace old ones.");app.innerHTML=h;bind()}
async function provision(){let r=await api("/api/authenticator/provision");s.secret=r.secret;s.uri=r.uri;s.otp=r.mockCode;s.showUri=s.showSecret=false;log("[Mock delivery] Authenticator test code: "+r.mockCode)}
function bind(){let $=x=>document.querySelector(x);if(s.screen==="signin")$("#sign").onsubmit=async e=>{e.preventDefault();try{let r=await api("/api/signin",{email:$("#email").value});s.csrf=r.csrf;s.identityCode=r.mockCode;s.screen="identity";log("[Mock delivery] Identity check code: "+r.mockCode);render()}catch(x){say("",x.message);render()}};
if(s.screen==="identity"){$("#ident").onsubmit=async e=>{e.preventDefault();try{await api("/api/identity/verify",{code:$("#identity").value});await provision();s.screen="setup";say("Identity check complete. Add your authenticator next.");render()}catch(x){say("",x.message);render()}};$("#fillI").onclick=()=>$("#identity").value=s.identityCode;$("#resend").onclick=async()=>{try{let r=await api("/api/identity/send");s.identityCode=r.mockCode;log("[Mock delivery] Identity check code: "+r.mockCode);say("A new demo code is in the Logs panel.");render()}catch(x){say("",x.message);render()}}}
if(s.screen==="setup"){$("#tu").onclick=()=>{s.showUri=!s.showUri;render()};$("#ts").onclick=()=>{s.showSecret=!s.showSecret;render()};$("#cu").onclick=()=>copy(s.uri,"Setup URI copied.");$("#cs").onclick=()=>copy(s.secret,"Secret copied.");$("#toOtp").onclick=()=>{s.screen="otp";say("Your next step is to confirm the 6-digit code.");render()}}
if(s.screen==="otp"){$("#otpform").onsubmit=async e=>{e.preventDefault();try{let r=await api("/api/authenticator/verify",{code:$("#otp").value});s.codes=r.codes;log("[Mock delivery] Recovery codes: "+r.codes.join(", "));s.screen="backup";render()}catch(x){say("",x.message);render()}};$("#fillO").onclick=()=>$("#otp").value=s.otp;$("#restart").onclick=()=>{s.screen="setup";render()}}
if(s.screen==="backup"){$("#copyCodes").onclick=()=>copy(s.codes.join("\\n"),"Recovery codes copied.");$("#finish").onclick=async()=>{if(!$("#saved").checked){say("Please tick the box after you have saved the codes.");render();return}try{await api("/api/backup/confirm");s.codes=[];s.screen="settings";say("Security setup is complete.");render()}catch(x){say("",x.message);render()}}}
if(s.screen==="settings"){$("#test").onclick=async()=>{try{await api("/api/recovery/verify",{code:$("#recovery").value.toUpperCase()});say("That recovery code worked and is now used.");render()}catch(x){say("",x.message);render()}};$("#regen").onclick=async()=>{try{let r=await api("/api/recovery/regenerate");s.codes=r.codes;log("[Mock delivery] New recovery codes: "+r.codes.join(", "));s.screen="backup";render()}catch(x){say("",x.message);render()}};$("#logout").onclick=async()=>{try{await api("/api/logout");s.csrf="";s.screen="signin";say("You have signed out.");render()}catch(x){say("",x.message);render()}}}}render()})()</script></body></html>`;

function html() { const n = token(18), h = headers(n); h.set("Content-Type", "text/html; charset=utf-8"); return new Response(page.replaceAll("__NONCE__", n), { headers: h }); }
function authCookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABS / 1000)}`; }
function deadCookie() { return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }

async function route(r: Request): Promise<Response> {
  const u = new URL(r.url);
  if (r.method === "OPTIONS") return origins.has(r.headers.get("origin") || "") ? cors(r, new Response(null, { status: 204, headers: headers() })) : fail(403, "Request not allowed.");
  if (u.pathname === "/" && r.method === "GET") return html();
  if (!u.pathname.startsWith("/api/")) return fail(404, "Page not found.");

  /* Authentication rotates session IDs and binds all operations to session.account only. */
  if (u.pathname === "/api/signin" && r.method === "POST") {
    const d = await body(r);
    if (!d || !emailOK(d.email) || !origins.has(r.headers.get("origin") || "")) return fail(400, "Please enter an email address in the example format.");
    const a = [...accounts.values()].find(x => x.email.toLowerCase() === d.email.toLowerCase());
    if (!a) return fail(401, "We could not sign in with those details. Check the account email and try again.");
    if (locked(a.identityLocked)) return fail(429, "Too many tries. Please wait 10 minutes before trying again.");
    for (const [id, x] of sessions) if (x.userId === a.id) sessions.delete(id);
    const id = token(), c = token(); sessions.set(id, { userId: a.id, csrf: c, made: Date.now(), seen: Date.now() });
    a.identityVerified = false; a.identity = await check(DEMO); a.lastIdentitySent = Date.now();
    const out = json({ ok: true, csrf: c, mockCode: DEMO }); out.headers.set("Set-Cookie", authCookie(id)); return cors(r, out);
  }

  const x = session(r);
  if (!x) { const out = fail(401, "Please sign in again to continue."); out.headers.set("Set-Cookie", deadCookie()); return cors(r, out); }
  const { s, a } = x;
  if (r.method !== "GET" && !csrf(r, s)) return cors(r, fail(403, "Your secure form check did not match. Refresh and try again."));

  if (u.pathname === "/api/identity/send" && r.method === "POST") {
    if (locked(a.identityLocked)) return cors(r, fail(429, "Too many tries. Please wait 10 minutes before trying again."));
    if (Date.now() - a.lastIdentitySent < ISSUE) return cors(r, fail(429, "Please wait a short moment before requesting another code."));
    a.identity = await check(DEMO); a.lastIdentitySent = Date.now(); return cors(r, json({ ok: true, mockCode: DEMO }));
  }
  if (u.pathname === "/api/identity/verify" && r.method === "POST") {
    const d = await body(r); if (!d || !codeOK(d.code)) return cors(r, fail(400, "Enter exactly 6 numbers, for example 123456."));
    if (locked(a.identityLocked)) return cors(r, fail(429, "Too many tries. Please wait 10 minutes before trying again."));
    const c = a.identity;
    if (!c || c.used || Date.now() > c.expires) return cors(r, fail(400, "That code is no longer available. Request a new code and try again."));
    if (await hash(d.code) !== c.hash) { if (++a.identityFails >= MAX) { a.identityFails = 0; a.identityLocked = Date.now() + LOCK; } return cors(r, fail(locked(a.identityLocked) ? 429 : 400, locked(a.identityLocked) ? "Too many tries. Please wait 10 minutes before trying again." : "That code does not match. Check the 6 numbers and try again.")); }
    c.used = true; a.identityVerified = true; a.identityFails = 0; return cors(r, json({ ok: true }));
  }
  if (u.pathname === "/api/authenticator/provision" && r.method === "POST") {
    if (!a.identityVerified) return cors(r, identityNeeded());
    if (a.mfaEnabled) return cors(r, fail(403, "Your authenticator is already active."));
    const seed = a.seed ? await uncrypt(a.seed) : base32(32); if (!a.seed) a.seed = await crypt(seed);
    const mockCode = await totp(seed, Math.floor(Date.now() / 30000));
    return cors(r, json({ ok: true, secret: seed, uri: "otpauth://totp/Harbour:Marcus?secret=" + encodeURIComponent(seed) + "&issuer=Harbour", mockCode }));
  }
  if (u.pathname === "/api/authenticator/verify" && r.method === "POST") {
    /* Required: identity check is enforced before accepting TOTP or enabling MFA. */
    if (!a.identityVerified) return cors(r, identityNeeded());
    const d = await body(r); if (!d || !codeOK(d.code)) return cors(r, fail(400, "Enter exactly 6 numbers, for example 123456."));
    if (locked(a.totpLocked)) return cors(r, fail(429, "Too many authenticator tries. Please wait 10 minutes before trying again."));
    if (!a.seed) return cors(r, fail(400, "Request authenticator setup before entering a code."));
    const seed = await uncrypt(a.seed), now = Math.floor(Date.now() / 30000); let match: number | undefined;
    for (const q of [now - 1, now, now + 1]) if (!a.usedSteps.has(q) && d.code === await totp(seed, q)) { match = q; break; }
    if (match === undefined) { if (++a.totpFails >= MAX) { a.totpFails = 0; a.totpLocked = Date.now() + LOCK; } return cors(r, fail(locked(a.totpLocked) ? 429 : 400, locked(a.totpLocked) ? "Too many authenticator tries. Please wait 10 minutes before trying again." : "That code does not match. Check the 6 numbers and try again.")); }
    a.usedSteps.add(match); a.totpFails = 0; a.mfaEnabled = true; return cors(r, json({ ok: true, codes: await codes(a) }));
  }
  /* Required: recovery settings require the currently authorized, identity-verified session. */
  if (u.pathname === "/api/backup/confirm" && r.method === "POST") {
    if (!a.identityVerified) return cors(r, identityNeeded()); if (!a.mfaEnabled) return cors(r, fail(403, "Set up an authenticator first.")); return cors(r, json({ ok: true }));
  }
  if (u.pathname === "/api/recovery/regenerate" && r.method === "POST") {
    if (!a.identityVerified) return cors(r, identityNeeded()); if (!a.mfaEnabled) return cors(r, fail(403, "Set up an authenticator first.")); return cors(r, json({ ok: true, codes: await codes(a) }));
  }
  if (u.pathname === "/api/recovery/verify" && r.method === "POST") {
    if (!a.identityVerified) return cors(r, identityNeeded()); if (!a.mfaEnabled) return cors(r, fail(403, "Set up an authenticator first."));
    if (locked(a.recoveryLocked)) return cors(r, fail(429, "Too many recovery-code tries. Please wait 10 minutes before trying again."));
    const d = await body(r); if (!d || !recoveryOK(d.code)) return cors(r, fail(400, "Enter a recovery code like ABCDE-FGHIJ."));
    const h = await hash(d.code);
    if (!a.backups.has(h)) { const now = Date.now(); if (!a.recoveryStart || now - a.recoveryStart > 600e3) { a.recoveryStart = now; a.recoveryFails = 0; } if (++a.recoveryFails >= MAX) { a.recoveryFails = 0; a.recoveryStart = 0; a.recoveryLocked = now + LOCK; return cors(r, fail(429, "Too many recovery-code tries. Please wait 10 minutes before trying again.")); } return cors(r, fail(400, "That recovery code is not available. Check it or use another saved code.")); }
    a.backups.delete(h); a.recoveryFails = a.recoveryStart = 0; return cors(r, json({ ok: true }));
  }
  if (u.pathname === "/api/logout" && r.method === "POST") { const id = cookie(r, "mfa_session"); if (id) sessions.delete(id); const out = json({ ok: true }); out.headers.set("Set-Cookie", deadCookie()); return cors(r, out); }
  return cors(r, fail(404, "Page not found."));
}

/* Requirements: supplied mkcert TLS files enforce HTTPS. */
Bun.serve({
  port: 3000, hostname: "0.0.0.0",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) { try { return await route(request); } catch { return fail(500, "We could not complete that request. Please try again."); } }
});
console.log("MFA enrolment server ready at https://localhost:3000");
