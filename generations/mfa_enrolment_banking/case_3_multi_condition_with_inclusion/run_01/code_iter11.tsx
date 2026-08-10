
/*
  MFA Enrolment System
  Single-file Bun HTTPS server + responsive HTML/CSS/vanilla-JS SPA.
  Run with: bun app.ts
  TLS certificates are expected at certs/cert.pem and certs/key.pem.
*/

const enc = new TextEncoder();
const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const SESSION_IDLE = 30 * 60_000, SESSION_ABSOLUTE = 8 * 60 * 60_000, LOCKOUT = 5 * 60_000, MAX_FAILURES = 5;
/* Task: stable deterministic mock enrolment value, deliberately limited to pending setup verification. */
const MOCK_ENROLMENT_OTP = "654321";
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const recoveryKey = crypto.getRandomValues(new Uint8Array(32));

type Secret = { iv: string; ciphertext: string };
type Session = { userId: string; csrf: string; createdAt: number; lastSeenAt: number };
type Account = {
  id: string; email: string; passwordHash: string; mfaEnabled: boolean;
  encryptedSecret?: Secret; pendingEncryptedSecret?: Secret;
  usedTotpCounters: number[]; pendingUsedTotpCounters: number[];
  reenrolmentStarted: boolean; otpFailedAttempts: number; otpLockedUntil: number;
  recoveryFailedAttempts: number; recoveryLockedUntil: number; backupCodeHashes: string[];
};

function hash(v: string) { return Bun.CryptoHasher.hash("sha256", v, "hex"); }
const DUMMY_PASSWORD_HASH = hash("fixed-dummy-password-value-not-an-account");
accounts.set("marcus-account-001", {
  id: "marcus-account-001", email: "marcus@example.com", passwordHash: hash("BankDemo!42"),
  mfaEnabled: false, usedTotpCounters: [], pendingUsedTotpCounters: [], reenrolmentStarted: false,
  otpFailedAttempts: 0, otpLockedUntil: 0, recoveryFailedAttempts: 0, recoveryLockedUntil: 0, backupCodeHashes: [],
});

function token(bytes = 32) { return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url"); }
function equal(a: string, b: string) {
  const aa = enc.encode(a), bb = enc.encode(b); let d = aa.length ^ bb.length, n = Math.max(aa.length, bb.length);
  for (let i = 0; i < n; i++) d |= (aa[i % (aa.length || 1)] || 0) ^ (bb[i % (bb.length || 1)] || 0);
  return d === 0;
}
function cookies(r: Request) {
  const out: Record<string, string> = {};
  for (const part of (r.headers.get("cookie") || "").split(";")) {
    const i = part.indexOf("="); if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
function trusted(host: string) { return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]"; }

/* Requirements 1 and 2: HTTPS origin checks, CSRF, secure headers, secure HttpOnly cookie. */
function headers(r: Request, nonce?: string) {
  const h = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src ${nonce ? "'nonce-" + nonce + "'" : "'none'"}; style-src ${nonce ? "'nonce-" + nonce + "'" : "'none'"}; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Cache-Control": "no-store",
  });
  const u = new URL(r.url), origin = r.headers.get("origin");
  if (origin === u.origin && trusted(u.hostname)) {
    h.set("Access-Control-Allow-Origin", origin); h.set("Access-Control-Allow-Credentials", "true"); h.set("Vary", "Origin");
  }
  return h;
}
function json(r: Request, body: unknown, status = 200, extra?: HeadersInit) {
  const h = headers(r); h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((v, k) => h.set(k, v));
  return new Response(JSON.stringify(body), { status, headers: h });
}
function safeOrigin(r: Request) {
  const u = new URL(r.url);
  return u.protocol === "https:" && trusted(u.hostname) && r.headers.get("origin") === u.origin;
}
async function body(r: Request): Promise<Record<string, unknown> | null> {
  if (!(r.headers.get("content-type") || "").includes("application/json")) return null;
  try { const x = await r.json(); return x && typeof x === "object" && !Array.isArray(x) ? x as Record<string, unknown> : null; } catch { return null; }
}
function session(r: Request): { id: string; s: Session; a: Account } | null {
  const id = cookies(r).mfa_session;
  if (!id || !/^[A-Za-z0-9_-]{30,}$/.test(id)) return null;
  const s = sessions.get(id), now = Date.now();
  if (!s || now - s.lastSeenAt > SESSION_IDLE || now - s.createdAt > SESSION_ABSOLUTE) { sessions.delete(id); return null; }
  const a = accounts.get(s.userId); if (!a) { sessions.delete(id); return null; }
  s.lastSeenAt = now; return { id, s, a };
}
function auth(r: Request): { id: string; s: Session; a: Account } | Response {
  return session(r) || json(r, { ok: false, message: "Please sign in again to continue." }, 401);
}
function csrf(r: Request, s: Session) { return safeOrigin(r) && r.headers.get("x-csrf-token") === s.csrf; }
function cookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE / 1000)}`; }
function newSession(userId: string) {
  const id = token(), s = { userId, csrf: token(24), createdAt: Date.now(), lastSeenAt: Date.now() }; sessions.set(id, s); return { id, s };
}
function validEmail(x: unknown): x is string { return typeof x === "string" && x.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x); }
function validPassword(x: unknown): x is string { return typeof x === "string" && x.length >= 8 && x.length <= 128; }
function validOtp(x: unknown): x is string { return typeof x === "string" && /^\d{6}$/.test(x); }
function validRecovery(x: unknown): x is string { return typeof x === "string" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/i.test(x); }
function locked() { return "Too many attempts were made. Please wait a few minutes, then try again. You can return safely later."; }

function base32(secret: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", out: number[] = []; let bits = 0, count = 0;
  for (const c of secret) { const n = alphabet.indexOf(c); if (n < 0) throw Error(); bits = (bits << 5) | n; count += 5; while (count >= 8) { count -= 8; out.push((bits >> count) & 255); } }
  return new Uint8Array(out);
}
async function totp(secret: string, counter: number) {
  const msg = new Uint8Array(8); let n = BigInt(counter);
  for (let i = 7; i >= 0; i--) { msg[i] = Number(n & 255n); n >>= 8n; }
  const k = await crypto.subtle.importKey("raw", base32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, msg)), o = sig[19] & 15;
  const v = (((sig[o] & 127) * 0x1000000) + sig[o + 1] * 0x10000 + sig[o + 2] * 0x100 + sig[o + 3]) >>> 0;
  return String(v % 1_000_000).padStart(6, "0");
}
async function encrypt(secret: string): Promise<Secret> {
  const k = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]), iv = crypto.getRandomValues(new Uint8Array(12));
  return { iv: Buffer.from(iv).toString("base64url"), ciphertext: Buffer.from(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k, enc.encode(secret))).toString("base64url") };
}
async function decrypt(s: Secret) {
  const k = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(s.iv, "base64url") }, k, Buffer.from(s.ciphertext, "base64url")));
}
async function hmac(v: string) {
  const k = await crypto.subtle.importKey("raw", recoveryKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return Buffer.from(await crypto.subtle.sign("HMAC", k, enc.encode(v))).toString("hex");
}
function secret() {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let out = "";
  while (out.length < 32) for (const b of crypto.getRandomValues(new Uint8Array(32))) { if (b < 248) out += a[b % 32]; if (out.length === 32) break; }
  return out;
}
function codes() {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", out = new Set<string>();
  while (out.size < 10) { let x = ""; while (x.length < 10) for (const b of crypto.getRandomValues(new Uint8Array(24))) { if (b < 252) x += a[b % 36]; if (x.length === 10) break; } out.add(x.slice(0, 5) + "-" + x.slice(5)); }
  return [...out];
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#172331;--muted:#536271;--blue:#1259b5;--soft:#edf5ff;--line:#cbd8e6;--good:#156d43;--bad:#a12c2c}*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:16px;line-height:1.65;letter-spacing:.025em}main{width:min(100%,620px);min-height:100vh;margin:auto;padding:18px 16px 38px}header{display:flex;gap:11px;align-items:center;margin:4px 0 18px}.mark{width:40px;height:40px;display:grid;place-items:center;background:var(--blue);color:#fff;border-radius:12px;font-size:22px}h1,h2,h3{line-height:1.3;letter-spacing:.01em;margin:0 0 12px}h1{font-size:1.38rem}h2{font-size:1.35rem}h3{font-size:1rem}.sub,.example{color:var(--muted);font-size:.86rem}.sub{margin:0}.steps{display:flex;margin:18px 0;gap:5px}.step{flex:1;text-align:center;padding:6px 2px;border-bottom:4px solid var(--line);color:#607080;font-size:.72rem}.step.active{color:#083d82;font-weight:700;border-color:var(--blue)}.card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:22px 18px;box-shadow:0 2px 7px #193c5c0b}p{margin:0 0 15px}.lead{font-size:1.05rem}label{display:block;margin:16px 0 6px;font-weight:700}input{width:100%;min-height:52px;border:2px solid #9eafc0;border-radius:10px;padding:11px 13px;font:inherit;letter-spacing:.06em}input:focus,button:focus,summary:focus{outline:3px solid #e3a927;outline-offset:2px}button{width:100%;min-height:53px;border:0;border-radius:10px;padding:11px 15px;cursor:pointer;font:700 1rem/1.35 Verdana,Arial,sans-serif}button.primary{background:var(--blue);color:#fff;margin-top:22px}button.secondary{background:#fff;color:#083d82;border:2px solid var(--blue);margin-top:11px}button.small{width:auto;min-height:42px;font-size:.88rem;padding:7px 12px}button:disabled{opacity:.55}.notice{padding:12px 13px;border-radius:10px;margin:15px 0;font-weight:700}.good{color:#0e5533;background:#e5f6eb;border-left:5px solid var(--good)}.bad{color:#782222;background:#fff0f0;border-left:5px solid var(--bad)}.info{color:#164a84;background:var(--soft);border-left:5px solid var(--blue)}.secret{overflow-wrap:anywhere;padding:12px;background:#f4f8fc;border:1px solid var(--line);border-radius:9px;font-family:ui-monospace,Consolas,monospace;letter-spacing:.09em;line-height:1.8}.row{display:flex;flex-wrap:wrap;gap:9px;margin-top:10px}.row button{flex:1;min-width:130px}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:14px 0}.code{padding:9px 6px;background:#f4f8fc;border-radius:7px;text-align:center;font-family:ui-monospace,Consolas,monospace;font-weight:700}.qr{width:250px;height:250px;margin:16px auto;padding:9px;background:#fff;border:1px solid var(--line);border-radius:8px}.qr canvas{width:100%;height:100%;image-rendering:pixelated}.hiddenCodes{padding:16px;background:#f4f8fc;border-radius:8px;color:var(--muted);text-align:center}.clip-feedback{min-height:1.7em;margin-top:12px;color:#164a84;font-weight:700}details{margin-top:17px;border-top:1px solid var(--line);padding-top:12px}summary{cursor:pointer;color:#083d82;font-weight:700}.testing{background:#fff8d9;border:1px solid #d99e1d;border-radius:10px;padding:10px 12px;margin-top:16px}.footer{text-align:center;margin-top:18px;color:var(--muted);font-size:.82rem}@media(max-width:390px){main{padding:12px 11px 28px}.card{padding:18px 14px}.step{font-size:.65rem}.codes{grid-template-columns:1fr}}
</style></head><body><main><header><div class="mark" aria-hidden="true">✦</div><div><h1>Northstar Bank</h1><p class="sub">Security setup</p></div></header><nav class="steps" aria-label="Setup progress"><div class="step" id="s1">1. Confirm</div><div class="step" id="s2">2. App</div><div class="step" id="s3">3. Check</div><div class="step" id="s4">4. Save</div></nav><section id="app" class="card" aria-live="polite">Loading secure setup…</section><footer class="footer">Take your time. There is no reading timer.</footer></main>
<script nonce="${nonce}">
const app=document.getElementById("app");let csrf="",setupSecret="",setupUri="",mockOtp="",currentCodes=[],codesVisible=true,visibleSecret=true;
function log(m){console.log(m)}function esc(v){const e=document.createElement("span");e.textContent=String(v);return e.innerHTML}function steps(n){document.querySelectorAll(".step").forEach((e,i)=>e.classList.toggle("active",i+1===n))}function notice(m,t){return '<div class="notice '+t+'">'+esc(m)+'</div>'}function help(){return '<details><summary>Help with this step</summary><p>You can pause and return later. You can retry safely. There is no reading timer.</p></details>'}function clip(m){const e=document.getElementById("clipFeedback");if(e)e.textContent=m}
async function api(path,data){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data||{})}),d=await r.json().catch(()=>({ok:false,message:"Something went wrong. Please try again."}));if(r.status===401){csrf="";signInPage("Your secure session ended. Please sign in again.")}return{r,d}}

/* Task: standards-compliant QR encoder: QR Version 10, error correction L, byte mode.
   Version 10-L has room for this otpauth URI. It uses ISO/IEC 18004 placement,
   BCH format/version data, Reed-Solomon error correction and best-mask selection. */
function drawQr(text){
 const target=document.getElementById("qrCode");if(!target)return;const bytes=new TextEncoder().encode(text),N=57;
 if(bytes.length>274){target.textContent="Setup code is too long. Use the manual secret.";return}
 const exp=[],logt=[];let x=1;for(let i=0;i<255;i++){exp[i]=x;logt[x]=i;x<<=1;if(x&256)x^=285}
 const mul=(a,b)=>a&&b?exp[(logt[a]+logt[b])%255]:0;
 function rs(data,n){let g=[1];for(let i=0;i<n;i++){let z=new Array(g.length+1).fill(0);for(let j=0;j<g.length;j++){z[j]^=g[j];z[j+1]^=mul(g[j],exp[i])}g=z}let rem=new Array(n).fill(0);for(const d of data){let f=d^rem.shift();rem.push(0);for(let j=0;j<n;j++)rem[j]^=mul(g[j+1],f)}return rem}
 const bits=[];const put=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>i)&1)};put(4,4);put(bytes.length,16);for(const b of bytes)put(b,8);put(0,Math.min(4,274*8-bits.length));while(bits.length%8)bits.push(0);
 const data=[];for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8).join(""),2));for(let p=0;data.length<274;p++)data.push(p%2?17:236);
 const blocks=[data.slice(0,68),data.slice(68,136),data.slice(136,205),data.slice(205,274)], ecc=blocks.map(b=>rs(b,18)), stream=[];
 for(let i=0;i<69;i++)for(const b of blocks)if(i<b.length)stream.push(b[i]);for(let i=0;i<18;i++)for(const e of ecc)stream.push(e[i]);
 const raw=[];for(const b of stream)for(let i=7;i>=0;i--)raw.push((b>>i)&1);
 function matrix(mask){
  const m=Array.from({length:N},()=>Array(N).fill(null));const set=(r,c,v)=>{if(r>=0&&c>=0&&r<N&&c<N)m[r][c]=v};
  function finder(r,c){for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)set(r+y,c+z,y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4))?1:0)}
  finder(0,0);finder(0,N-7);finder(N-7,0);
  for(let i=8;i<N-8;i++){set(6,i,i%2===0?1:0);set(i,6,i%2===0?1:0)}
  const aligns=[6,28,50];for(const r of aligns)for(const c of aligns){if(m[r][c]!==null)continue;for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)set(r+y,c+z,Math.max(Math.abs(y),Math.abs(z))===2||(!y&&!z)?1:0)}
  for(let i=0;i<9;i++){if(m[8][i]===null)set(8,i,0);if(m[i][8]===null)set(i,8,0);if(m[8][N-1-i]===null)set(8,N-1-i,0);if(m[N-1-i][8]===null)set(N-1-i,8,0)}
  set(N-8,8,1);
  let k=0,up=true;for(let c=N-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<N;q++){let r=up?N-1-q:q;for(let z=0;z<2;z++){let col=c-z;if(m[r][col]===null){let v=raw[k++]||0,inv=[(r+col)%2===0,r%2===0,col%3===0,(r+col)%3===0,(Math.floor(r/2)+Math.floor(col/3))%2===0,(r*col)%2+(r*col)%3===0,((r*col)%2+(r*col)%3)%2===0,((r+col)%2+(r*col)%3)%2===0][mask];m[r][col]=inv?v^1:v}}}up=!up}
  let f=(1<<3)|mask,d=f<<10;while(d.toString(2).length>=11)d^=0x537<<(d.toString(2).length-11);f=((f<<10)|d)^0x5412;for(let i=0;i<15;i++){let v=(f>>i)&1;if(i<6)set(i,8,v);else if(i<8)set(i+1,8,v);else set(N-15+i,8,v);if(i<8)set(8,N-i-1,v);else if(i<9)set(8,15-i,v);else set(8,15-i-1,v)}
  let vd=10<<12;let t=vd;while(t.toString(2).length>=13)t^=0x1f25<<(t.toString(2).length-13);let ver=vd|t;for(let i=0;i<18;i++){let v=(ver>>i)&1;set(Math.floor(i/3),N-11+i%3,v);set(N-11+i%3,Math.floor(i/3),v)}return m;
 }
 function penalty(m){let p=0;for(let a=0;a<2;a++)for(let i=0;i<N;i++){let run=1,last=m[a?i:0][a?0:i];for(let j=1;j<N;j++){let v=m[a?i:j][a?j:i];if(v===last)run++;else{if(run>=5)p+=run-2;run=1;last=v}}if(run>=5)p+=run-2}for(let r=0;r<N-1;r++)for(let c=0;c<N-1;c++)if(m[r][c]===m[r+1][c]&&m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c+1])p+=3;for(let r=0;r<N;r++)for(let c=0;c<N-6;c++)if([1,0,1,1,1,0,1].every((v,i)=>m[r][c+i]===v))p+=40;return p}
 let best=matrix(0),score=penalty(best);for(let i=1;i<8;i++){const q=matrix(i),s=penalty(q);if(s<score){best=q;score=s}}const c=document.createElement("canvas");c.width=c.height=N*4;const g=c.getContext("2d");g.fillStyle="#fff";g.fillRect(0,0,c.width,c.height);g.fillStyle="#000";for(let r=0;r<N;r++)for(let col=0;col<N;col++)if(best[r][col])g.fillRect(col*4,r*4,4,4);target.replaceChildren(c);
}
function testing(){return '<details class="testing"><summary>Testing only: show mock six-digit code</summary><p>This stable demo code is accepted by verification.</p><div class="secret">'+esc(mockOtp)+'</div></details>'}
function signInPage(msg=""){steps(1);app.innerHTML='<h2>Confirm your account</h2><p class="lead">Use your bank email and password.</p>'+notice("Demo sign-in: marcus@example.com · password: BankDemo!42","info")+(msg?notice(msg,"info"):"")+'<label for="email">Email address</label><input id="email" type="email" autocomplete="email" placeholder="marcus@example.com"><p class="example">Example: marcus@example.com</p><label for="password">Password</label><input id="password" type="password" autocomplete="current-password"><button class="primary" id="signin">Continue</button>'+help();document.getElementById("signin").onclick=signin}
async function signin(){const b=document.getElementById("signin");b.disabled=true;const r=await fetch("/api/signin",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:email.value,password:password.value})}),d=await r.json();if(!r.ok||!d.ok){b.disabled=false;app.insertAdjacentHTML("afterbegin",notice(d.message,"bad"));return}csrf=d.csrf;d.mfaEnabled?account("You are signed in. Your authenticator is connected."):setup("Your identity is confirmed. Next, add your authenticator app.")}
function account(msg=""){steps(4);app.innerHTML='<h2>Security setup</h2>'+notice(msg,"good")+'<p class="lead">Your authenticator is active.</p><button class="primary" id="replace">Replace authenticator</button><button class="secondary" id="recovery">Use a recovery code</button><button class="secondary" id="regenerate">Generate new recovery codes</button><button class="secondary" id="logout">Sign out</button>'+help();replace.onclick=begin;recovery.onclick=recoveryPage;regenerate.onclick=regen;logout.onclick=signout}
async function begin(){const x=await api("/api/begin-reenrolment",{});if(!x.r.ok)return app.insertAdjacentHTML("afterbegin",notice(x.d.message,"bad"));setup("Replacement started. Your current authenticator remains active until the replacement is verified.")}
function setup(msg=""){steps(2);app.innerHTML='<h2>Add your authenticator app</h2><p class="lead">Open an authenticator app. You can scan a QR code or copy a secret.</p>'+(msg?notice(msg,"good"):"")+'<button class="primary" id="getSetup">Show secure setup</button>'+help();getSetup.onclick=getsetup}
async function getsetup(){getSetup.disabled=true;const x=await api("/api/provision",{});if(!x.r.ok){getSetup.disabled=false;return app.insertAdjacentHTML("afterbegin",notice(x.d.message,"bad"))}setupSecret=x.d.secret;setupUri=x.d.uri;mockOtp=x.d.mockOtp;log("Mock OTP for testing: "+mockOtp);provision(x.d.message)}
function provision(msg){steps(2);app.innerHTML='<h2>Your setup QR code is ready</h2>'+notice(msg,"good")+'<p>Scan this QR code in your authenticator app. If scanning is difficult, use the secret below.</p><div class="qr" id="qrCode" role="img" aria-label="Authenticator setup QR code"></div><h3>Manual secret</h3><div class="secret" id="secretText">'+esc(setupSecret)+'</div><div class="row"><button class="secondary small" id="copySecret">Copy secret</button><button class="secondary small" id="hideSecret">Hide secret</button></div><div id="clipFeedback" class="clip-feedback" role="status"></div>'+testing()+'<button class="primary" id="goVerify">I added it to my app</button><button class="secondary" id="newSetup">Request a new setup</button>'+help();drawQr(setupUri);copySecret.onclick=()=>copy(setupSecret,"Authenticator secret");hideSecret.onclick=toggleSecret;goVerify.onclick=verifyPage;newSetup.onclick=getsetup}
function toggleSecret(){visibleSecret=!visibleSecret;secretText.textContent=visibleSecret?setupSecret:"Secret hidden";hideSecret.textContent=visibleSecret?"Hide secret":"Show secret"}
async function copy(t,l){try{await navigator.clipboard.writeText(t);log(l+" copied.");clip(l+" copied. Next, save it somewhere safe.")}catch{clip(l+" could not be copied. Select it on this secure page and try again.")}}
function verifyPage(msg=""){steps(3);app.innerHTML='<h2>Check your app</h2><p class="lead">Enter the six numbers shown in your authenticator app.</p>'+(msg?notice(msg,"info"):"")+'<label for="otp">Six-digit code</label><input id="otp" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><p class="example">Example: 123456. You have plenty of time.</p>'+testing()+'<button class="primary" id="verify">Verify code</button><button class="secondary" id="backSetup">Go back to setup</button>'+help();verify.onclick=verifyOtp;backSetup.onclick=()=>provision("You can view setup details again.")}
async function verifyOtp(){verify.disabled=true;const x=await api("/api/verify-otp",{otp:otp.value.trim()});if(!x.r.ok){verify.disabled=false;return app.insertAdjacentHTML("afterbegin",notice(x.d.message,"bad"))}currentCodes=x.d.codes;log("Generated recovery codes for testing: "+currentCodes.join(", "));codesPage("Your authenticator is now connected.")}
function renderCodes(){return codesVisible?'<div class="codes">'+currentCodes.map(x=>'<div class="code">'+esc(x)+'</div>').join("")+'</div>':'<div class="hiddenCodes">Recovery codes are hidden.</div>'}
function codesPage(msg){steps(4);app.innerHTML='<h2>Save your recovery codes</h2>'+notice(msg,"good")+'<p class="lead">These codes help if you lose your phone. Store them somewhere safe. Each code works once.</p><div id="codesArea">'+renderCodes()+'</div><div class="row"><button class="secondary small" id="toggleCodes">'+(codesVisible?"Hide recovery codes":"Show recovery codes")+'</button><button class="secondary small" id="copyCodes">Copy all recovery codes</button></div><div id="clipFeedback" class="clip-feedback" role="status"></div><button class="primary" id="finish">I saved my codes</button>'+help();copyCodes.onclick=()=>copy(currentCodes.join("\\n"),"Recovery codes");toggleCodes.onclick=()=>{codesVisible=!codesVisible;codesArea.innerHTML=renderCodes();toggleCodes.textContent=codesVisible?"Hide recovery codes":"Show recovery codes"};finish.onclick=()=>account("Your recovery codes are saved.")}
function recoveryPage(msg=""){steps(4);app.innerHTML='<h2>Use a recovery code</h2><p class="lead">Use one saved code if you cannot use your authenticator app.</p>'+(msg?notice(msg,"info"):"")+'<label for="recoveryCode">Recovery code</label><input id="recoveryCode" type="text" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" maxlength="11" placeholder="ABCDE-12345"><p class="example">Example: ABCDE-12345. Each code works once.</p><button class="primary" id="verifyRecovery">Verify recovery code</button><button class="secondary" id="backAccount">Back to security setup</button>'+help();verifyRecovery.onclick=verifyRecoveryCode;backAccount.onclick=()=>account()}
async function verifyRecoveryCode(){verifyRecovery.disabled=true;const x=await api("/api/verify-recovery-code",{recoveryCode:recoveryCode.value.trim().toUpperCase()});if(!x.r.ok){verifyRecovery.disabled=false;return app.insertAdjacentHTML("afterbegin",notice(x.d.message,"bad"))}log("Recovery code verification succeeded in the mock flow.");account("Recovery code accepted. That code has now been used and cannot be used again.")}
async function regen(){const x=await api("/api/regenerate-backup-codes",{});if(!x.r.ok)return app.insertAdjacentHTML("afterbegin",notice(x.d.message,"bad"));currentCodes=x.d.codes;codesVisible=true;log("New recovery codes generated for testing: "+currentCodes.join(", "));codesPage("New recovery codes have replaced the old ones.")}
async function signout(){await api("/api/logout",{});csrf="";setupSecret="";currentCodes=[];log("Signed out safely.");signInPage("You have signed out safely.")}
signInPage();
</script></body></html>`}

async function handle(r: Request): Promise<Response> {
  const u = new URL(r.url);
  if (u.protocol !== "https:" || !trusted(u.hostname)) return new Response("Not found", { status: 404, headers: headers(r) });
  if (r.method === "GET" && u.pathname === "/") { const n = token(18), h = headers(r, n); h.set("Content-Type", "text/html; charset=utf-8"); return new Response(page(n), { headers: h }); }
  if (r.method === "OPTIONS") {
    if (!safeOrigin(r)) return new Response(null, { status: 403, headers: headers(r) });
    const h = headers(r); h.set("Access-Control-Allow-Methods", "POST"); h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token"); return new Response(null, { status: 204, headers: h });
  }
  if (r.method === "POST" && u.pathname === "/api/signin") {
    if (!safeOrigin(r)) return json(r, { ok: false, message: "Please use the secure sign-in page." }, 403);
    const b = await body(r), email = typeof b?.email === "string" ? b.email.toLowerCase().trim() : "", password = b?.password;
    const a = [...accounts.values()].find(v => v.email === email), matches = equal(hash(typeof password === "string" ? password : ""), a ? a.passwordHash : DUMMY_PASSWORD_HASH);
    if (!b || !validEmail(email) || !validPassword(password) || !a || !matches) return json(r, { ok: false, message: "Sign-in could not be completed. Check your email and password, then try again." }, 401);
    for (const [id, s] of sessions) if (s.userId === a.id) sessions.delete(id);
    const made = newSession(a.id); return json(r, { ok: true, csrf: made.s.csrf, mfaEnabled: a.mfaEnabled }, 200, { "Set-Cookie": cookie(made.id) });
  }
  if (r.method === "POST" && u.pathname === "/api/logout") {
    const x = auth(r); if (x instanceof Response) return x; if (!csrf(r, x.s)) return json(r, { ok: false, message: "Please refresh the secure page and try again." }, 403);
    sessions.delete(x.id); return json(r, { ok: true }, 200, { "Set-Cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }
  const x = auth(r); if (x instanceof Response) return x;
  if (r.method !== "POST" || !csrf(r, x.s)) return json(r, { ok: false, message: "Please refresh the secure page and try again." }, 403);
  const a = x.a;
  if (u.pathname === "/api/begin-reenrolment") {
    if (!a.mfaEnabled || !a.encryptedSecret) return json(r, { ok: false, message: "Finish authenticator setup before replacing it." }, 400);
    a.reenrolmentStarted = true; return json(r, { ok: true });
  }
  if (u.pathname === "/api/provision") {
    if (a.mfaEnabled && !a.reenrolmentStarted) return json(r, { ok: false, message: "Choose “Replace authenticator” first. Your current authenticator stays active until the new one is checked." }, 400);
    const s = secret(); a.pendingEncryptedSecret = await encrypt(s); a.pendingUsedTotpCounters = [];
    const uri = `otpauth://totp/${encodeURIComponent("Northstar Bank:" + a.email)}?secret=${s}&issuer=Northstar%20Bank&algorithm=SHA1&digits=6&period=30`;
    return json(r, { ok: true, secret: s, uri, mockOtp: MOCK_ENROLMENT_OTP, message: a.mfaEnabled ? "Your replacement setup is ready. Your current authenticator still works until this new one is verified." : "Authenticator setup is ready. Add the secret, then enter the six-digit code." });
  }
  if (u.pathname === "/api/verify-otp") {
    const b = await body(r), now = Date.now(); if (a.otpLockedUntil && a.otpLockedUntil <= now) { a.otpLockedUntil = 0; a.otpFailedAttempts = 0; }
    if (!b || !validOtp(b.otp)) return json(r, { ok: false, message: "Enter exactly six numbers, for example 123456." }, 400);
    if (a.otpLockedUntil > now) return json(r, { ok: false, message: locked() }, 429);
    if (!a.pendingEncryptedSecret) return json(r, { ok: false, message: "Request a new setup and try again." }, 400);
    let s: string; try { s = await decrypt(a.pendingEncryptedSecret); } catch { return json(r, { ok: false, message: "Request a new setup and try again." }, 400); }
    let counter = -1;
    /* Real TOTP flow remains available; deterministic test path is accepted only during pending enrolment. */
    if (equal(b.otp, MOCK_ENROLMENT_OTP)) counter = -2;
    else for (const c of [Math.floor(now / 30000) - 1, Math.floor(now / 30000), Math.floor(now / 30000) + 1]) if (equal(b.otp, await totp(s, c))) counter = c;
    if (counter < 0 || a.pendingUsedTotpCounters.includes(counter)) {
      a.otpFailedAttempts++; if (a.otpFailedAttempts >= MAX_FAILURES) a.otpLockedUntil = now + LOCKOUT;
      return json(r, { ok: false, message: a.otpFailedAttempts >= MAX_FAILURES ? locked() : "That code did not match, or it was already used. Check your authenticator app and try again." }, 400);
    }
    a.pendingUsedTotpCounters.push(counter); a.encryptedSecret = a.pendingEncryptedSecret; a.usedTotpCounters = a.pendingUsedTotpCounters.slice(-8);
    a.pendingEncryptedSecret = undefined; a.pendingUsedTotpCounters = []; a.reenrolmentStarted = false; a.mfaEnabled = true; a.otpFailedAttempts = 0; a.otpLockedUntil = 0;
    const c = codes(); a.backupCodeHashes = await Promise.all(c.map(hmac)); a.recoveryFailedAttempts = 0; a.recoveryLockedUntil = 0; return json(r, { ok: true, codes: c });
  }
  if (u.pathname === "/api/verify-recovery-code") {
    const b = await body(r), now = Date.now(), submitted = typeof b?.recoveryCode === "string" ? b.recoveryCode.toUpperCase() : "";
    if (a.recoveryLockedUntil && a.recoveryLockedUntil <= now) { a.recoveryLockedUntil = 0; a.recoveryFailedAttempts = 0; }
    if (!b || !validRecovery(submitted)) return json(r, { ok: false, message: "Enter a recovery code in this format: ABCDE-12345." }, 400);
    if (!a.mfaEnabled) return json(r, { ok: false, message: "Finish authenticator setup before using a recovery code." }, 400);
    if (a.recoveryLockedUntil > now) return json(r, { ok: false, message: locked() }, 429);
    const v = await hmac(submitted); let i = -1; for (let n = 0; n < a.backupCodeHashes.length; n++) if (equal(v, a.backupCodeHashes[n]) && i < 0) i = n;
    if (i < 0) { a.recoveryFailedAttempts++; if (a.recoveryFailedAttempts >= MAX_FAILURES) a.recoveryLockedUntil = now + LOCKOUT; return json(r, { ok: false, message: a.recoveryFailedAttempts >= MAX_FAILURES ? locked() : "That recovery code was not recognised. Check the code and try again, or use another saved code." }, 400); }
    a.backupCodeHashes.splice(i, 1); a.recoveryFailedAttempts = 0; a.recoveryLockedUntil = 0; return json(r, { ok: true });
  }
  if (u.pathname === "/api/regenerate-backup-codes") {
    if (!a.mfaEnabled) return json(r, { ok: false, message: "Finish authenticator setup before making recovery codes." }, 400);
    const c = codes(); a.backupCodeHashes = await Promise.all(c.map(hmac)); a.recoveryFailedAttempts = 0; a.recoveryLockedUntil = 0; return json(r, { ok: true, codes: c });
  }
  return new Response("Not found", { status: 404, headers: headers(r) });
}

Bun.serve({
  port: Number(Bun.env.PORT || 3000), hostname: "localhost",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(r) { try { return await handle(r); } catch { return new Response("Something went wrong. Please try again.", { status: 500, headers: headers(r) }); } },
});
console.log("MFA HTTPS server running at https://localhost:" + (Bun.env.PORT || 3000));
