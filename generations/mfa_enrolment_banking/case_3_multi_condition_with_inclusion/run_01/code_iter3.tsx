
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
const cspNonce = randomToken(18);
const encryptionKeyBytes = crypto.getRandomValues(new Uint8Array(32));
/* Requirement: server-only HMAC key for recovery-code verifiers. */
const recoveryVerifierKey = crypto.getRandomValues(new Uint8Array(32));
const DUMMY_PASSWORD_HASH = Bun.CryptoHasher.hash("sha256", "fixed-dummy-password-value-not-an-account", "hex");

type Session = { userId: string; csrf: string; createdAt: number; lastSeenAt: number };
type Account = {
  id: string;
  email: string;
  passwordHash: string;
  mfaEnabled: boolean;
  encryptedSecret?: { iv: string; ciphertext: string };
  usedTotpCounters: number[];
  otpFailedAttempts: number;
  otpLockedUntil: number;
  recoveryFailedAttempts: number;
  recoveryLockedUntil: number;
  backupCodeHashes: string[];
};

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}
function sha256(value: string): string {
  return Bun.CryptoHasher.hash("sha256", value, "hex");
}
function constantTimeEqualText(a: string, b: string): boolean {
  const aa = encoder.encode(a), bb = encoder.encode(b);
  let diff = aa.length ^ bb.length;
  const length = Math.max(aa.length, bb.length);
  for (let i = 0; i < length; i++) diff |= (aa[i % (aa.length || 1)] || 0) ^ (bb[i % (bb.length || 1)] || 0);
  return diff === 0;
}
async function hmacSha256Hex(value: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", recoveryVerifierKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return Buffer.from(signature).toString("hex");
}
function generateSecret(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "";
  while (result.length < 32) {
    const values = crypto.getRandomValues(new Uint8Array(32));
    for (const value of values) {
      if (value < 248) result += alphabet[value % 32];
      if (result.length === 32) break;
    }
  }
  return result;
}
/* Requirement: recovery codes are cryptographically random and exactly ABCDE-12345. */
function generateBackupCodes(): string[] {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const codes = new Set<string>();
  while (codes.size < 10) {
    let raw = "";
    while (raw.length < 10) {
      const values = crypto.getRandomValues(new Uint8Array(16));
      for (const value of values) {
        if (value < 252) raw += alphabet[value % 36];
        if (raw.length === 10) break;
      }
    }
    codes.add(raw.slice(0, 5) + "-" + raw.slice(5));
  }
  return [...codes];
}
function base32Decode(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, count = 0;
  const output: number[] = [];
  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("Invalid secret");
    bits = (bits << 5) | index;
    count += 5;
    while (count >= 8) {
      count -= 8;
      output.push((bits >> count) & 255);
    }
  }
  return new Uint8Array(output);
}
/* Task: RFC 6238 TOTP: HMAC-SHA-1, 30-second period, six digits. */
async function totpForCounter(secret: string, counter: number): Promise<string> {
  const message = new Uint8Array(8);
  let value = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    message[i] = Number(value & 255n);
    value >>= 8n;
  }
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = signature[signature.length - 1] & 15;
  const binary = ((signature[offset] & 127) << 24) | (signature[offset + 1] << 16) | (signature[offset + 2] << 8) | signature[offset + 3];
  return String(binary % 1_000_000).padStart(6, "0");
}
async function encryptSecret(secret: string): Promise<{ iv: string; ciphertext: string }> {
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret));
  return { iv: Buffer.from(iv).toString("base64url"), ciphertext: Buffer.from(ciphertext).toString("base64url") };
}
async function decryptSecret(stored: { iv: string; ciphertext: string }): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(stored.iv, "base64url") },
    key,
    Buffer.from(stored.ciphertext, "base64url")
  );
  return new TextDecoder().decode(clear);
}

/* Requirement 1/5: established server-side mock account, never replaced by submitted identity. */
const accounts = new Map<string, Account>([[
  "marcus-account-001",
  {
    id: "marcus-account-001",
    email: "marcus@example.com",
    passwordHash: sha256("BankDemo!42"),
    mfaEnabled: false,
    usedTotpCounters: [],
    otpFailedAttempts: 0,
    otpLockedUntil: 0,
    recoveryFailedAttempts: 0,
    recoveryLockedUntil: 0,
    backupCodeHashes: [],
  },
]]);

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  for (const item of (request.headers.get("cookie") || "").split(";")) {
    const index = item.indexOf("=");
    if (index > 0) result[item.slice(0, index).trim()] = item.slice(index + 1).trim();
  }
  return result;
}
function cookieHeader(id: string): string {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}
function expiredCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}
function isTrustedHost(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
}
function securityHeaders(request: Request): Headers {
  const headers = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${cspNonce}'; style-src 'nonce-${cspNonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  const origin = request.headers.get("origin"), url = new URL(request.url);
  if (origin === url.origin && isTrustedHost(url.hostname)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}
function json(request: Request, body: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = securityHeaders(request);
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((v, k) => headers.set(k, v));
  return new Response(JSON.stringify(body), { status, headers });
}
function originIsSafe(request: Request): boolean {
  const url = new URL(request.url);
  return request.headers.get("origin") === url.origin && url.protocol === "https:" && isTrustedHost(url.hostname);
}
function getSession(request: Request): { id: string; session: Session; account: Account } | null {
  const id = parseCookies(request).mfa_session;
  if (!id || !/^[A-Za-z0-9_-]{30,}$/.test(id)) return null;
  const session = sessions.get(id);
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeenAt > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  const account = accounts.get(session.userId);
  if (!account) { sessions.delete(id); return null; }
  session.lastSeenAt = now;
  return { id, session, account };
}
function requireSession(request: Request): { id: string; session: Session; account: Account } | Response {
  return getSession(request) || json(request, { ok: false, message: "Please sign in again to continue." }, 401);
}
function csrfValid(request: Request, session: Session): boolean {
  return originIsSafe(request) && request.headers.get("x-csrf-token") === session.csrf;
}
async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  if (!(request.headers.get("content-type") || "").includes("application/json")) return null;
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch { return null; }
}
function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function validPassword(value: unknown): value is string {
  return typeof value === "string" && value.length >= 8 && value.length <= 128;
}
function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function validRecoveryCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/i.test(value);
}
function createSession(userId: string): { id: string; session: Session } {
  const id = randomToken(32);
  const session = { userId, csrf: randomToken(24), createdAt: Date.now(), lastSeenAt: Date.now() };
  sessions.set(id, session);
  return { id, session };
}
function lockMessage(): string {
  return "Too many attempts were made. Please wait a few minutes, then try again. You can return safely later.";
}
async function provision(request: Request, account: Account): Promise<Response> {
  const secret = generateSecret();
  account.encryptedSecret = await encryptSecret(secret);
  account.usedTotpCounters = [];
  account.otpFailedAttempts = 0;
  account.otpLockedUntil = 0;
  const label = encodeURIComponent("Northstar Bank:" + account.email);
  const issuer = encodeURIComponent("Northstar Bank");
  const uri = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
  /* Returned test TOTP is derived from the exact encrypted-at-rest secret. */
  const testTotp = await totpForCounter(secret, Math.floor(Date.now() / 30000));
  console.log("Authenticator provisioning issued for authenticated account.");
  return json(request, {
    ok: true, secret, uri, testTotp,
    message: "Authenticator setup is ready. Add the secret, then enter the six-digit code."
  });
}

function pageHtml(): string {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Bank · Security setup</title>
<style nonce="${cspNonce}">
:root{--ink:#172331;--muted:#536271;--blue:#1259b5;--soft:#edf5ff;--line:#cbd8e6;--good:#156d43;--bad:#a12c2c}*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:16px;line-height:1.65;letter-spacing:.025em}main{width:min(100%,620px);min-height:100vh;margin:auto;padding:18px 16px 38px}header{display:flex;gap:11px;align-items:center;margin:4px 0 18px}.mark{width:40px;height:40px;display:grid;place-items:center;background:var(--blue);color:#fff;border-radius:12px;font-size:22px}h1,h2,h3{line-height:1.3;letter-spacing:.01em;margin:0 0 12px}h1{font-size:1.38rem}h2{font-size:1.35rem}h3{font-size:1rem}.sub,.example{color:var(--muted);font-size:.86rem}.steps{display:flex;margin:18px 0;gap:5px}.step{flex:1;text-align:center;padding:6px 2px;border-bottom:4px solid var(--line);color:#607080;font-size:.72rem}.step.active{color:#083d82;font-weight:700;border-color:var(--blue)}.card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:22px 18px;box-shadow:0 2px 7px #193c5c0b}p{margin:0 0 15px}.lead{font-size:1.05rem}label{display:block;margin:16px 0 6px;font-weight:700}input{width:100%;min-height:52px;border:2px solid #9eafc0;border-radius:10px;padding:11px 13px;font:inherit;letter-spacing:.04em}input:focus,button:focus,summary:focus{outline:3px solid #e3a927;outline-offset:2px}button{width:100%;min-height:53px;border:0;border-radius:10px;padding:11px 15px;cursor:pointer;font:700 1rem/1.35 Verdana,Arial,sans-serif}button.primary{background:var(--blue);color:#fff;margin-top:22px}button.secondary{background:#fff;color:#083d82;border:2px solid var(--blue);margin-top:11px}button.small{width:auto;min-height:42px;font-size:.88rem;padding:7px 12px}button:disabled{opacity:.55}.notice{padding:12px 13px;border-radius:10px;margin:15px 0;font-weight:700}.good{color:#0e5533;background:#e5f6eb;border-left:5px solid var(--good)}.bad{color:#782222;background:#fff0f0;border-left:5px solid var(--bad)}.info{color:#164a84;background:var(--soft);border-left:5px solid var(--blue)}.secret{overflow-wrap:anywhere;padding:12px;background:#f4f8fc;border:1px solid var(--line);border-radius:9px;font-family:ui-monospace,Consolas,monospace;letter-spacing:.09em;line-height:1.8}.row{display:flex;flex-wrap:wrap;gap:9px;margin-top:10px}.row button{flex:1;min-width:130px}.qr{display:block;width:220px;height:220px;background:#fff;border:9px solid #fff;box-shadow:0 0 0 1px var(--line);margin:16px auto;image-rendering:pixelated}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:14px 0}.code{padding:9px 6px;background:#f4f8fc;border-radius:7px;text-align:center;font-family:ui-monospace,Consolas,monospace;font-weight:700;letter-spacing:.04em}details{margin-top:17px;border-top:1px solid var(--line);padding-top:12px}summary{cursor:pointer;color:#083d82;font-weight:700}.logs{margin-top:22px;background:#14202b;color:#dbeefc;border-radius:12px;padding:13px}.logs h2{font-size:1rem}#logList{margin:0;padding-left:19px;font:.77rem/1.55 ui-monospace,Consolas,monospace;max-height:160px;overflow:auto}.footer{text-align:center;margin-top:18px;color:var(--muted);font-size:.82rem}@media(max-width:390px){main{padding:12px 11px 28px}.card{padding:18px 14px}.step{font-size:.65rem}.codes{grid-template-columns:1fr}}
</style></head><body><main>
<header><div class="mark" aria-hidden="true">✦</div><div><h1>Northstar Bank</h1><p class="sub">Security setup</p></div></header>
<nav class="steps" aria-label="Setup progress"><div class="step" id="s1">1. Confirm</div><div class="step" id="s2">2. App</div><div class="step" id="s3">3. Check</div><div class="step" id="s4">4. Save</div></nav>
<section id="app" class="card" aria-live="polite">Loading secure setup…</section>
<section class="logs" aria-label="Logs"><h2>Logs</h2><ul id="logList"><li>Secure setup page ready.</li></ul></section><footer class="footer">Take your time. There is no reading timer.</footer>
</main><script nonce="${cspNonce}">
const app=document.getElementById("app"),logList=document.getElementById("logList");let csrf="",setupSecret="",setupUri="",visibleSecret=true,currentCodes=[];
function log(m){console.log(m);const x=document.createElement("li");x.textContent=m;logList.appendChild(x);logList.scrollTop=logList.scrollHeight}
function esc(v){const x=document.createElement("span");x.textContent=String(v);return x.innerHTML}
function setSteps(n){document.querySelectorAll(".step").forEach((x,i)=>x.classList.toggle("active",i+1===n))}
function notice(m,t){return '<div class="notice '+t+'">'+esc(m)+"</div>"}function help(){return '<details><summary>Help with this step</summary><p>You can pause and return later. You can retry safely. There is no reading timer.</p></details>'}
async function api(path,body){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body||{})});const d=await r.json().catch(()=>({ok:false,message:"Something went wrong. Please try again."}));if(r.status===401){csrf="";showSignIn("Your secure session ended. Please sign in again.")}return{response:r,data:d}}
function showSignIn(m=""){setSteps(1);app.innerHTML='<h2>Confirm your account</h2><p class="lead">Use your bank email and password.</p>'+notice("Demo sign-in: marcus@example.com · password: BankDemo!42","info")+(m?notice(m,"info"):"")+'<label for="email">Email address</label><input id="email" type="email" autocomplete="email" inputmode="email" placeholder="marcus@example.com"><p class="example">Example: marcus@example.com</p><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" placeholder="Your password"><button class="primary" id="signin">Continue</button>'+help();document.getElementById("signin").onclick=signIn}
async function signIn(){const b=document.getElementById("signin");b.disabled=true;const r=await fetch("/api/signin",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:document.getElementById("email").value,password:document.getElementById("password").value})}),d=await r.json().catch(()=>({ok:false,message:"Sign-in could not be completed. Try again."}));if(!r.ok||!d.ok){b.disabled=false;app.insertAdjacentHTML("afterbegin",notice(d.message||"Sign-in could not be completed. Try again.","bad"));return}csrf=d.csrf;log("Identity confirmed. Starting authenticator setup.");showSetup()}
function showSetup(m=""){setSteps(2);app.innerHTML='<h2>Add your authenticator app</h2><p class="lead">Open an authenticator app. You can scan a QR code or copy a short secret.</p>'+(m?notice(m,"good"):"")+'<button class="primary" id="getSetup">Show secure setup</button>'+help();document.getElementById("getSetup").onclick=getSetup}
async function getSetup(){const b=document.getElementById("getSetup");b.disabled=true;const{response,data}=await api("/api/provision",{});if(!response.ok||!data.ok){b.disabled=false;app.insertAdjacentHTML("afterbegin",notice(data.message||"We could not prepare setup. Try again.","bad"));return}setupSecret=data.secret;setupUri=data.uri;console.log("[TEST ONLY] Authenticator secret:",data.secret);console.log("[TEST ONLY] RFC 6238 test TOTP:",data.testTotp);log("Mock authenticator setup delivered. A test code is ready.");showProvisioning(data.message)}
/*
  Standards-compliant QR Code Model 2 encoder.
  Version 8, error correction level L, byte mode, mask 0:
  - reserves finder, separator, timing, alignment, format, version and dark modules
  - uses QR Reed-Solomon interleaving (2 blocks, 97 data + 24 ECC each)
  - encodes the exact otpauth URI returned by the server
*/
function qrSvg(text){
 const version=8,n=49,cap=194,eccLen=24,bytes=new TextEncoder().encode(text);
 if(bytes.length>cap)return '<p class="notice bad">The QR code could not be prepared. Please copy the secret instead.</p>';
 const a=Array.from({length:n},()=>Array(n).fill(null));
 const set=(x,y,v)=>{if(x>=0&&y>=0&&x<n&&y<n)a[y][x]=!!v};
 const finder=(x,y)=>{for(let j=-1;j<=7;j++)for(let i=-1;i<=7;i++)set(x+i,y+j,i>=0&&i<=6&&j>=0&&j<=6&&(i===0||i===6||j===0||j===6||(i>=2&&i<=4&&j>=2&&j<=4)))};
 finder(0,0);finder(n-7,0);finder(0,n-7);
 for(let i=8;i<n-8;i++){if(a[6][i]===null)set(i,6,i%2===0);if(a[i][6]===null)set(6,i,i%2===0)}
 const centers=[6,24,42];
 for(const cy of centers)for(const cx of centers){if(a[cy][cx]!==null)continue;for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(cx+x,cy+y,Math.abs(x)===2||Math.abs(y)===2||(x===0&&y===0))}
 set(8,n-8,true);
 const formatPositions=[];
 for(let i=0;i<=5;i++)formatPositions.push([8,i]);
 formatPositions.push([8,7],[8,8],[7,8]);for(let i=9;i<=14;i++)formatPositions.push([14-i,8]);
 for(let i=0;i<8;i++)formatPositions.push([n-1-i,8]);for(let i=8;i<15;i++)formatPositions.push([8,n-15+i]);
 formatPositions.forEach(p=>set(p[0],p[1],false));
 const versionPositions=[];for(let i=0;i<18;i++){versionPositions.push([n-11+i%3,Math.floor(i/3)],[Math.floor(i/3),n-11+i%3])}versionPositions.forEach(p=>set(p[0],p[1],false));
 let bits=[0,1,0,0];for(let i=7;i>=0;i--)bits.push((bytes.length>>i)&1);for(const b of bytes)for(let i=7;i>=0;i--)bits.push((b>>i)&1);
 while(bits.length%8)bits.push(0);const data=[];for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8).join(""),2));for(let i=0;data.length<cap;i++)data.push(i%2?0x11:0xec);
 const exp=[],lg=[];let z=1;for(let i=0;i<255;i++){exp[i]=z;lg[z]=i;z<<=1;if(z&256)z^=0x11d}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const mul=(x,y)=>x&&y?exp[lg[x]+lg[y]]:0;let gen=[1];for(let i=0;i<eccLen;i++){const q=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){q[j]^=gen[j];q[j+1]^=mul(gen[j],exp[i])}gen=q}
 const remainder=block=>{const r=Array(eccLen).fill(0);for(const value of block){const f=value^r.shift();r.push(0);for(let i=0;i<eccLen;i++)r[i]^=mul(gen[i+1],f)}return r};
 const b1=data.slice(0,97),b2=data.slice(97),e1=remainder(b1),e2=remainder(b2),stream=[];
 for(let i=0;i<97;i++)stream.push(b1[i],b2[i]);for(let i=0;i<eccLen;i++)stream.push(e1[i],e2[i]);
 let k=0,up=true;for(let x=n-1;x>0;x-=2){if(x===6)x--;for(let q=0;q<n;q++){const y=up?n-1-q:q;for(let dx=0;dx<2;dx++){const xx=x-dx;if(a[y][xx]===null){const bit=k<stream.length*8?((stream[Math.floor(k/8)]>>(7-k%8))&1):0;set(xx,y,bit^((xx+y)%2===0));k++}}}up=!up}
 const bch=(value,poly)=>{let v=value;const top=()=>Math.floor(Math.log2(v));while(v&&top(v)>=top(poly))v^=poly<<(top(v)-top(poly));return v};
 const format=((1<<3)|0)<<10;const formatWord=(format|bch(format,0x537))^0x5412;
 formatPositions.forEach((p,i)=>set(p[0],p[1],(formatWord>>i)&1));
 const versionWord=(version<<12)|bch(version<<12,0x1f25);versionPositions.forEach((p,i)=>set(p[0],p[1],(versionWord>>Math.floor(i/2))&1));
 let p="";for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(a[y][x])p+="<rect x='"+x+"' y='"+y+"' width='1' height='1'/>";
 return "<svg class='qr' role='img' aria-label='QR code for authenticator setup' viewBox='0 0 "+n+" "+n+"' xmlns='http://www.w3.org/2000/svg'><title>Authenticator setup QR code</title><rect width='100%' height='100%' fill='white'/><g fill='#102438'>"+p+"</g></svg>";
}
function showProvisioning(m){setSteps(2);app.innerHTML='<h2>Your setup QR code is ready</h2>'+notice(m,"good")+'<p>Scan this QR code in your authenticator app. If scanning is difficult, use the secret below.</p>'+qrSvg(setupUri)+'<h3>Manual secret</h3><div class="secret" id="secretText">'+esc(setupSecret)+'</div><div class="row"><button class="secondary small" id="copySecret">Copy secret</button><button class="secondary small" id="hideSecret">Hide secret</button></div><button class="primary" id="goVerify">I added it to my app</button><button class="secondary" id="newSetup">Request a new setup</button>'+help();document.getElementById("copySecret").onclick=()=>copyText(setupSecret,"Secret copied. Paste it into your authenticator app.");document.getElementById("hideSecret").onclick=toggleSecret;document.getElementById("goVerify").onclick=showVerify;document.getElementById("newSetup").onclick=getSetup}
function toggleSecret(){visibleSecret=!visibleSecret;document.getElementById("secretText").textContent=visibleSecret?setupSecret:"Secret hidden";document.getElementById("hideSecret").textContent=visibleSecret?"Hide secret":"Show secret"}
async function copyText(t,m){try{await navigator.clipboard.writeText(t);log(m)}catch{log("Copy was not available. You can select the text shown above.")}}
function showVerify(m=""){setSteps(3);app.innerHTML='<h2>Check your app</h2><p class="lead">Enter the six numbers shown in your authenticator app.</p>'+(m?notice(m,"info"):"")+'<label for="otp">Six-digit code</label><input id="otp" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><p class="example">Example: 123456. You have plenty of time.</p><button class="primary" id="verify">Verify code</button><button class="secondary" id="backSetup">Go back to setup</button>'+help();document.getElementById("verify").onclick=verifyOtp;document.getElementById("backSetup").onclick=()=>showProvisioning("You can view setup details again.")}
async function verifyOtp(){const b=document.getElementById("verify");b.disabled=true;const{response,data}=await api("/api/verify-otp",{otp:document.getElementById("otp").value.trim()});if(!response.ok||!data.ok){b.disabled=false;app.insertAdjacentHTML("afterbegin",notice(data.message||"That code could not be checked. Try again.","bad"));return}currentCodes=data.codes;console.log("[TEST ONLY] Backup recovery codes:",data.codes);log("Authenticator verified. Recovery codes are ready to save.");showCodes("Your authenticator is now connected.")}
function showCodes(m){setSteps(4);app.innerHTML='<h2>Save your recovery codes</h2>'+notice(m,"good")+'<p class="lead">These codes help if you lose your phone. Store them somewhere safe. Each code works once.</p><div class="codes">'+currentCodes.map(c=>'<div class="code">'+esc(c)+"</div>").join("")+'</div><button class="primary" id="copyCodes">Copy all recovery codes</button><button class="secondary" id="finish">I saved my codes</button>'+help();document.getElementById("copyCodes").onclick=()=>copyText(currentCodes.join("\\n"),"Recovery codes copied. Keep them private.");document.getElementById("finish").onclick=showComplete}
function showComplete(){setSteps(4);currentCodes=[];setupSecret="";setupUri="";app.innerHTML='<h2>Setup complete ✓</h2>'+notice("Multi-factor authentication is on for your account.","good")+'<p class="lead">You will use your authenticator when a payment needs extra protection.</p><button class="primary" id="regenerate">Generate new recovery codes</button><button class="secondary" id="logout">Sign out</button>'+help();document.getElementById("regenerate").onclick=regenerate;document.getElementById("logout").onclick=logout}
async function regenerate(){const{response,data}=await api("/api/regenerate-backup-codes",{});if(!response.ok||!data.ok){app.insertAdjacentHTML("afterbegin",notice(data.message||"New codes could not be made. Try again.","bad"));return}currentCodes=data.codes;console.log("[TEST ONLY] New backup recovery codes:",data.codes);log("New recovery codes were generated. The old codes no longer work.");showCodes("New recovery codes have replaced the old ones.")}
async function logout(){await api("/api/logout",{});csrf="";setupSecret="";currentCodes=[];log("You signed out. This device no longer has an active session.");showSignIn("You have signed out safely.")}
showSignIn();
</script></body></html>`;
}

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.protocol !== "https:" || !isTrustedHost(url.hostname)) return new Response("Not found", { status: 404, headers: securityHeaders(request) });

  if (request.method === "OPTIONS") {
    if (!originIsSafe(request)) return new Response(null, { status: 403, headers: securityHeaders(request) });
    const headers = securityHeaders(request);
    headers.set("Access-Control-Allow-Methods", "POST");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return new Response(null, { status: 204, headers });
  }
  if (request.method === "GET" && url.pathname === "/") {
    const headers = securityHeaders(request);
    headers.set("Content-Type", "text/html; charset=utf-8");
    return new Response(pageHtml(), { headers });
  }

  if (request.method === "POST" && url.pathname === "/api/signin") {
    if (!originIsSafe(request)) return json(request, { ok: false, message: "Please use the secure sign-in page." }, 403);
    const body = await readJson(request);
    const email = typeof body?.email === "string" ? body.email.toLowerCase().trim() : "";
    const password = body?.password;
    const account = [...accounts.values()].find(a => a.email === email);
    /*
      Task: hash and constant-time compare on every sign-in, including nonexistent
      accounts, against a fixed dummy hash. The response remains generic.
    */
    const submittedHash = sha256(typeof password === "string" ? password : "");
    const expectedHash = account ? account.passwordHash : DUMMY_PASSWORD_HASH;
    const passwordMatches = constantTimeEqualText(submittedHash, expectedHash);
    if (!body || !validEmail(email) || !validPassword(password) || !account || !passwordMatches) {
      return json(request, { ok: false, message: "Sign-in could not be completed. Check your email and password, then try again." }, 401);
    }
    account.recoveryFailedAttempts = 0;
    account.recoveryLockedUntil = 0;
    for (const [id, session] of sessions) if (session.userId === account.id) sessions.delete(id);
    const created = createSession(account.id);
    console.log("Secure authenticated session created.");
    return json(request, { ok: true, csrf: created.session.csrf }, 200, { "Set-Cookie": cookieHeader(created.id) });
  }

  if (request.method === "POST" && url.pathname === "/api/logout") {
    const auth = requireSession(request);
    if (auth instanceof Response) return auth;
    if (!csrfValid(request, auth.session)) return json(request, { ok: false, message: "Please refresh the secure page and try again." }, 403);
    sessions.delete(auth.id);
    return json(request, { ok: true }, 200, { "Set-Cookie": expiredCookie() });
  }

  const auth = requireSession(request);
  if (auth instanceof Response) return auth;
  if (request.method !== "POST" || !csrfValid(request, auth.session)) return json(request, { ok: false, message: "Please refresh the secure page and try again." }, 403);

  if (url.pathname === "/api/provision") return provision(request, auth.account);

  if (url.pathname === "/api/verify-otp") {
    const body = await readJson(request), account = auth.account, now = Date.now();
    if (!body || !validOtp(body.otp)) return json(request, { ok: false, message: "Enter exactly six numbers, for example 123456." }, 400);
    if (account.otpLockedUntil > now) return json(request, { ok: false, message: lockMessage() }, 429);
    if (!account.encryptedSecret) return json(request, { ok: false, message: "Request a new setup and try again." }, 400);

    let secret: string;
    try { secret = await decryptSecret(account.encryptedSecret); }
    catch { return json(request, { ok: false, message: "Request a new setup and try again." }, 400); }

    /* RFC 6238 short clock-skew window: current 30-second period plus either neighbour. */
    const currentCounter = Math.floor(now / 30000);
    const validCounters = [currentCounter - 1, currentCounter, currentCounter + 1];
    let acceptedCounter = -1;
    for (const counter of validCounters) {
      const candidate = await totpForCounter(secret, counter);
      if (constantTimeEqualText(body.otp, candidate)) acceptedCounter = counter;
    }
    if (acceptedCounter < 0 || account.usedTotpCounters.includes(acceptedCounter)) {
      account.otpFailedAttempts++;
      if (account.otpFailedAttempts >= MAX_FAILURES) account.otpLockedUntil = now + LOCKOUT_MS;
      return json(request, {
        ok: false,
        message: account.otpFailedAttempts >= MAX_FAILURES ? lockMessage() : "That code did not match, or it was already used. Check your authenticator app and try again."
      }, 400);
    }

    /* Single-use TOTP counter state is retained server-side. */
    account.usedTotpCounters = [...account.usedTotpCounters, acceptedCounter].slice(-8);
    account.mfaEnabled = true;
    account.otpFailedAttempts = 0;
    account.otpLockedUntil = 0;
    const codes = generateBackupCodes();
    account.backupCodeHashes = await Promise.all(codes.map(code => hmacSha256Hex(code)));
    console.log("MFA enabled for authenticated account.");
    return json(request, { ok: true, codes });
  }

  if (url.pathname === "/api/regenerate-backup-codes") {
    if (!auth.account.mfaEnabled) return json(request, { ok: false, message: "Finish authenticator setup before making recovery codes." }, 400);
    const codes = generateBackupCodes();
    auth.account.backupCodeHashes = await Promise.all(codes.map(code => hmacSha256Hex(code)));
    auth.account.recoveryFailedAttempts = 0;
    auth.account.recoveryLockedUntil = 0;
    console.log("Recovery codes regenerated for authenticated account.");
    return json(request, { ok: true, codes });
  }

  if (url.pathname === "/api/recovery/verify") {
    const body = await readJson(request), account = auth.account, now = Date.now();
    if (!body || !validRecoveryCode(body.code)) return json(request, { ok: false, message: "Enter a recovery code in the format ABCDE-12345." }, 400);
    if (account.recoveryLockedUntil > now) return json(request, { ok: false, message: lockMessage() }, 429);

    /* Task: keyed HMAC verifier and constant-time comparison for every stored code. */
    const verifier = await hmacSha256Hex(body.code.toUpperCase());
    let index = -1;
    for (let i = 0; i < account.backupCodeHashes.length; i++) {
      const matches = constantTimeEqualText(verifier, account.backupCodeHashes[i]);
      if (matches && index === -1) index = i;
    }
    if (index < 0) {
      account.recoveryFailedAttempts++;
      if (account.recoveryFailedAttempts >= MAX_FAILURES) account.recoveryLockedUntil = now + LOCKOUT_MS;
      return json(request, { ok: false, message: account.recoveryFailedAttempts >= MAX_FAILURES ? lockMessage() : "That recovery code could not be used. Check the code and try again." }, 400);
    }
    account.backupCodeHashes.splice(index, 1);
    account.recoveryFailedAttempts = 0;
    account.recoveryLockedUntil = 0;
    console.log("Recovery code accepted for authenticated account.");
    return json(request, { ok: true, message: "Recovery code accepted." });
  }
  return new Response("Not found", { status: 404, headers: securityHeaders(request) });
}

Bun.serve({
  port: Number(Bun.env.PORT || 3000),
  hostname: "localhost",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try { return await handle(request); }
    catch { return new Response("Something went wrong. Please try again.", { status: 500, headers: securityHeaders(request) }); }
  },
});
console.log("MFA HTTPS server running at https://localhost:" + (Bun.env.PORT || 3000));
