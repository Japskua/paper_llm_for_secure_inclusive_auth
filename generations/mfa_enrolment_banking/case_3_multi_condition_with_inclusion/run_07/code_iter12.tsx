
import { Buffer } from "buffer";

/*
 MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.
 Security §1/§5: server-side session ownership, CSRF, rate limiting, single-use values.
 Security §2: TLS, CSP, HSTS, secure cookies, generic production errors.
 Security §3: encrypted TOTP secret and hashed recovery codes.
 Security §4: validated input and contextual output encoding.
*/

type Session = { accountId: string; csrf: string; created: number; seen: number };
type State = {
  identity: boolean;
  verified: boolean;
  encryptedSecret?: string;
  usedSteps: Set<number>;
  backupHashes: Set<string>;
  recoveryChecked: boolean;
  failures: number;
  lockedUntil: number;
  mockChallenge?: string;
  mockExpires?: number;
  mockUsed?: boolean;
  complete: boolean;
};

const PIN = process.env.MFA_DEMO_PIN;
if (!PIN || !/^\d{4,12}$/.test(PIN)) {
  console.error("Configuration error.");
  process.exit(1);
}

const ACCOUNT = { id: "account-marcus-demo", email: "marcus@example.test", phone: "07700900123" };
const IDLE = 20 * 60_000, LIFE = 8 * 60 * 60_000, LOCK = 5 * 60_000, MAX = 5;
const sessions = new Map<string, Session>();
const states = new Map<string, State>();
const loginFailures = new Map<string, { count: number; until: number }>();
const encBytes = crypto.getRandomValues(new Uint8Array(32));
const encKey = await crypto.subtle.importKey("raw", encBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
const pepper = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");

const random = (n = 32) => Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url");
const text = new TextEncoder();
const b64 = (v: ArrayBuffer | Uint8Array) => Buffer.from(v).toString("base64url");
const equal = (a: string, b: string) => {
  const x = text.encode(a), y = text.encode(b);
  if (x.length !== y.length) return false;
  let n = 0; for (let i = 0; i < x.length; i++) n |= x[i] ^ y[i];
  return n === 0;
};
async function digest(value: string) {
  return b64(await crypto.subtle.digest("SHA-256", text.encode(value)));
}
async function encrypt(value: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encKey, text.encode(value));
  return b64(iv) + "." + b64(data);
}
async function decrypt(value: string) {
  const [iv, data] = value.split(".");
  if (!iv || !data) throw Error("invalid encrypted value");
  return new TextDecoder().decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(iv, "base64url") },
    encKey, Buffer.from(data, "base64url")
  ));
}
function state() {
  let s = states.get(ACCOUNT.id);
  if (!s) {
    s = { identity: false, verified: false, usedSteps: new Set(), backupHashes: new Set(), recoveryChecked: false, failures: 0, lockedUntil: 0, complete: false };
    states.set(ACCOUNT.id, s);
  }
  return s;
}
function secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  return Array.from(crypto.getRandomValues(new Uint8Array(20)), n => alphabet[n % alphabet.length]).join("");
}
function backupCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const x = Array.from(crypto.getRandomValues(new Uint8Array(10)), n => alphabet[n % alphabet.length]).join("");
  return x.slice(0, 5) + "-" + x.slice(5);
}
function base32(v: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", out: number[] = [];
  let bits = 0, cur = 0;
  for (const c of v) {
    const n = alphabet.indexOf(c); if (n < 0) throw Error("invalid base32");
    cur = (cur << 5) | n; bits += 5;
    if (bits >= 8) { out.push((cur >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
async function hmac(key: Uint8Array, input: Uint8Array) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, input));
}
async function totp(key: string, step: number) {
  const msg = new Uint8Array(8); let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { msg[i] = Number(n & 255n); n >>= 8n; }
  const d = await hmac(base32(key), msg), o = d[19] & 15;
  return String(((((d[o] & 127) << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) % 1_000_000)).padStart(6, "0");
}
async function validTotp(key: string, value: string) {
  const now = Math.floor(Date.now() / 30_000);
  for (let d = -1; d <= 1; d++) if (equal(value, await totp(key, now + d))) return now + d;
  return null;
}
async function mockCode(s: State) {
  const d = await hmac(base32(await decrypt(s.encryptedSecret!)), text.encode("mock:" + s.mockChallenge));
  return String((((d[0] & 127) << 16) | (d[1] << 8) | d[2]) % 1_000_000).padStart(6, "0");
}

function headers(nonce?: string) {
  return new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
  });
}
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: headers() });
function cookies(r: Request) {
  const out: Record<string, string> = {};
  for (const p of (r.headers.get("cookie") || "").split(";")) {
    const i = p.indexOf("="); if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return out;
}
function originOK(r: Request) {
  const origin = r.headers.get("origin"), host = r.headers.get("host");
  if (!origin || !host) return false;
  try {
    const u = new URL(origin), name = u.hostname.replace(/^\[|\]$/g, "");
    return u.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(name) && u.origin === new URL("https://" + host).origin;
  } catch { return false; }
}
function current(r: Request) {
  const id = cookies(r).mfa_session, s = id && sessions.get(id);
  if (!s || s.accountId !== ACCOUNT.id || Date.now() - s.seen > IDLE || Date.now() - s.created > LIFE) {
    if (id) sessions.delete(id); return null;
  }
  s.seen = Date.now(); return s;
}
async function body(r: Request) {
  if (Number(r.headers.get("content-length") || "0") > 5000) return null;
  try { const x = await r.json(); return x && typeof x === "object" && !Array.isArray(x) ? x as Record<string, unknown> : null; } catch { return null; }
}
const email = (x: unknown) => typeof x === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x.trim()) && x.length < 121 ? x.trim().toLowerCase() : null;
const phone = (x: unknown) => typeof x === "string" && /^\+?[\d ()-]{7,24}$/.test(x) ? x : null;
const otp = (x: unknown): x is string => typeof x === "string" && /^\d{6}$/.test(x);
const recovery = (x: unknown): x is string => typeof x === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(x);
function fail(s: State, recoveryMessage = false) {
  if (++s.failures >= MAX) { s.failures = 0; s.lockedUntil = Date.now() + LOCK; return json({ ok: false, message: "Too many tries. Please wait a few minutes, then try again." }, 429); }
  return json({ ok: false, message: recoveryMessage ? "That backup code did not match. Copy one unused saved code and try again." : "That code did not match. Check the six numbers and try again." }, 400);
}

async function api(r: Request, path: string) {
  if (path === "/api/authenticate" && r.method === "POST") {
    if (!originOK(r)) return json({ ok: false, message: "Please use this secure page to continue." }, 403);
    const peer = server.requestIP(r)?.address || "unknown", a = loginFailures.get(peer) || { count: 0, until: 0 };
    const v = await body(r), ok = !!v && email(v.email) === ACCOUNT.email && typeof v.credential === "string" && /^\d{4,12}$/.test(v.credential) && equal(await digest("pin:" + v.credential), await digest("pin:" + PIN));
    if (a.until > Date.now() || !ok) {
      if (!ok && ++a.count >= MAX) { a.count = 0; a.until = Date.now() + LOCK; } loginFailures.set(peer, a);
      return json({ ok: false, message: "We could not sign you in with those details. Please try again." }, 400);
    }
    loginFailures.delete(peer);
    const old = cookies(r).mfa_session; if (old) sessions.delete(old);
    const id = random(), s = { accountId: ACCOUNT.id, csrf: random(), created: Date.now(), seen: Date.now() };
    sessions.set(id, s);
    const response = json({ ok: true, csrf: s.csrf, message: "You are signed in. Next, confirm your identity." });
    response.headers.set("Set-Cookie", `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(LIFE / 1000)}`);
    return response;
  }

  const session = current(r);
  if (!session) return json({ ok: false, message: "Please sign in again to continue." }, 401);
  if (path === "/api/me" && r.method === "GET") return json({ ok: true, csrf: session.csrf });
  if (r.method !== "POST") return json({ ok: false, message: "That secure action is not available." }, 404);
  if (!originOK(r) || !equal(r.headers.get("x-csrf-token") || "", session.csrf)) return json({ ok: false, message: "Your safety check expired. Please sign in again." }, 403);

  if (path === "/api/logout") {
    for (const [id, x] of sessions) if (x === session) sessions.delete(id);
    const response = json({ ok: true, message: "You have signed out." });
    response.headers.set("Set-Cookie", "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
    return response;
  }

  const input = await body(r);
  if (!input || "accountId" in input || "userId" in input || "sessionId" in input) return json({ ok: false, message: "Please check your entry and try again." }, 400);
  const s = state();
  if (s.lockedUntil > Date.now() && ["/api/otp", "/api/recovery/verify", "/api/test/mock/verify"].includes(path)) return json({ ok: false, message: "Too many tries. Please wait a few minutes, then try again." }, 429);

  if (path === "/api/identity") {
    const e = email(input.email), p = phone(input.phone);
    if (!e || !p) return json({ ok: false, message: "Enter an email like name@example.com and a phone number." }, 400);
    if (e !== ACCOUNT.email || p.replace(/\D/g, "") !== ACCOUNT.phone) return json({ ok: false, message: "Those details did not match. Check both entries and try again." }, 400);
    s.identity = true; return json({ ok: true, message: "Identity confirmed. Next, create your authenticator setup key." });
  }
  if (path === "/api/setup") {
    if (!s.identity) return json({ ok: false, message: "Confirm your identity before setting up an authenticator." }, 403);
    const key = secret();
    s.encryptedSecret = await encrypt(key); s.verified = false; s.usedSteps = new Set(); s.backupHashes = new Set(); s.recoveryChecked = false; s.complete = false; s.failures = 0;
    s.mockChallenge = random(); s.mockExpires = Date.now() + 10 * 60_000; s.mockUsed = false;
    // Task: omit default digits=6 and period=30 so this UTF-8 URI fits Version 5-L.
    const uri = `otpauth://totp/OnlineBank:Marcus?secret=${key}&issuer=OnlineBank`;
    return json({ ok: true, secret: key, uri, message: "Setup key created. Copy the manual key into your authenticator app." });
  }
  if (path === "/api/otp") {
    if (!otp(input.code)) return json({ ok: false, message: "Enter six numbers, for example 123456." }, 400);
    if (!s.encryptedSecret) return json({ ok: false, message: "Set up your authenticator first." }, 400);
    const n = await validTotp(await decrypt(s.encryptedSecret), input.code);
    if (n === null) return fail(s);
    if (s.usedSteps.has(n)) return json({ ok: false, message: "That code was already used. Wait for a fresh code, then try again." }, 400);
    s.usedSteps.add(n); s.verified = true; s.failures = 0;
    return json({ ok: true, message: "Authenticator confirmed. Next, generate and save backup codes." });
  }
  if (path === "/api/test/mock/reveal" || path === "/api/test/mock/rerequest") {
    if (!s.encryptedSecret) return json({ ok: false, message: "Set up your authenticator first." }, 400);
    if (path.endsWith("rerequest")) { s.mockChallenge = random(); s.mockExpires = Date.now() + 10 * 60_000; s.mockUsed = false; }
    if (!s.mockChallenge || !s.mockExpires || s.mockExpires < Date.now() || s.mockUsed) return json({ ok: false, message: "That practice code is no longer available. Request a new one." }, 400);
    return json({ ok: true, code: await mockCode(s), message: "Practice code sent to the browser console for this academic test." });
  }
  if (path === "/api/test/mock/verify") {
    if (!otp(input.code) || !s.mockChallenge || !s.mockExpires || s.mockExpires < Date.now() || s.mockUsed) return json({ ok: false, message: "This practice code is not available. Request a new one." }, 400);
    if (!equal(input.code, await mockCode(s))) return fail(s);
    s.mockUsed = true; s.verified = true; s.failures = 0; return json({ ok: true, message: "Authenticator confirmed. Next, generate and save backup codes." });
  }
  if (path === "/api/backups") {
    if (!s.verified) return json({ ok: false, message: "Verify your authenticator code first, then generate backup codes." }, 403);
    const codes = Array.from({ length: 8 }, backupCode);
    s.backupHashes = new Set(await Promise.all(codes.map(x => digest("recovery:" + pepper + ":" + x))));
    s.recoveryChecked = false;
    return json({ ok: true, codes, message: "Your fresh backup codes are ready. Earlier backup codes no longer work." });
  }
  if (path === "/api/recovery/verify") {
    if (!recovery(input.code)) return json({ ok: false, message: "Enter a backup code like ABCDE-FGHIJ." }, 400);
    const h = await digest("recovery:" + pepper + ":" + input.code);
    if (!s.backupHashes.has(h)) return fail(s, true);
    s.backupHashes.delete(h); s.recoveryChecked = true; s.failures = 0;
    return json({ ok: true, message: "Backup code accepted. It cannot be used again. You can now finish enrolment." });
  }
  if (path === "/api/complete") {
    if (!s.verified || !s.encryptedSecret || !s.recoveryChecked || !s.backupHashes.size) return json({ ok: false, message: "Save backup codes and check one backup code before finishing." }, 400);
    s.complete = true; return json({ ok: true, message: "MFA enrolment is complete." });
  }
  return json({ ok: false, message: "That secure action is not available." }, 404);
}

function page(nonce: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Online Bank · MFA enrolment</title>
<style nonce="${nonce}">
:root{--ink:#172335;--blue:#075cc8;--line:#cbd6e2;--pale:#edf5ff;--bad:#9e2020}*{box-sizing:border-box}body{margin:0;background:#f5f8fb;color:var(--ink);font-family:"Atkinson Hyperlegible","Comic Sans MS",Verdana,sans-serif;font-size:17px;line-height:1.7;letter-spacing:.035em}main{width:min(100%,600px);margin:auto;padding:20px 16px 44px}.brand{font-weight:700;color:#093b78;margin-bottom:18px}.card,.logs{background:#fff;border:1px solid var(--line);border-radius:16px;padding:24px}.logs{margin-top:16px}.progress{color:#526174;margin:0 0 10px}.progress b{color:var(--blue)}h1{font-size:1.65rem;line-height:1.3;margin:0 0 15px}h2{font-size:1rem;margin:0 0 8px}p{margin:0 0 16px}.hint,.status{padding:13px 14px;border-radius:10px;margin:17px 0}.hint{background:var(--pale)}.status{background:#edf9f1;border-left:5px solid #087443}.error{background:#fff0f0;color:#841d1d;border-left-color:var(--bad)}.hide{display:none}label{display:block;font-weight:700;margin:16px 0 6px}input{width:100%;min-height:52px;border:2px solid #93a5b8;border-radius:10px;padding:10px 13px;font:inherit}button{width:100%;min-height:52px;border:0;border-radius:11px;padding:10px 14px;margin-top:17px;background:var(--blue);color:#fff;font:700 1rem inherit;cursor:pointer}.secondary{background:#fff;color:#114d91;border:2px solid #86a5c7;margin-top:10px}.text{width:auto;min-height:36px;background:transparent;color:#075cc8;text-decoration:underline;padding:5px 2px;margin:10px 15px 0 0}.secret,.codes li{word-break:break-all;background:#f2f5f8;padding:11px;border-radius:8px;font-family:monospace}.codes{list-style:none;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:9px}.qr{width:250px;max-width:100%;margin:18px auto;padding:8px;background:#fff}.qr canvas{display:block;width:100%;height:auto;image-rendering:pixelated}.log-list{padding-left:20px;font-family:monospace;font-size:.82rem;word-break:break-word}@media(max-width:380px){body{font-size:16px}.card,.logs{padding:19px}.codes{grid-template-columns:1fr}}@media print{button,.progress,.brand,#status,.logs{display:none}.card{border:0}}
</style></head><body><main><header class="brand">● Online Bank</header><section class="card"><p class="progress" id="progress"></p><h1 id="title"></h1><div id="status" class="status hide" role="status" aria-live="polite"></div><div id="screen"></div></section><section class="logs"><h2>Logs</h2><small>Delivery and verification messages appear here. Academic test values appear only in the browser console.</small><ol id="logs" class="log-list" aria-live="polite"></ol></section></main>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",step="start",key="",uri="",codes=[],hidden=false,recoveryOK=false,mock="";
const $=s=>document.querySelector(s),screen=$("#screen"),title=$("#title"),progress=$("#progress"),status=$("#status"),logs=$("#logs");
const steps={start:["1 of 6","Start"],identity:["2 of 6","Check identity"],setup:["3 of 6","Add authenticator"],otp:["4 of 6","Confirm code"],backup:["5 of 6","Save backup codes"],recovery:["6 of 6","Check a backup code"],done:["Complete","Finished"]};
const esc=v=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function note(v,b=false){status.textContent=v;status.className="status"+(b?" error":"")}
function log(v){console.log(v);const x=document.createElement("li");x.textContent=v;logs.append(x)}
function testLog(label,value){console.log(label,value);const x=document.createElement("li");x.textContent=label+" Value shown in browser console for the academic test.";logs.append(x)}
async function call(path,data={},method="POST"){try{const r=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:method==="GET"?undefined:JSON.stringify(data)}),v=await r.json();if(!r.ok||!v.ok)throw Error(v.message||"Please try again.");return v}catch(e){note(e.message||"Something went wrong. Please try again.",true);return null}}
async function copy(v,message){try{await navigator.clipboard.writeText(v);note(message)}catch{note("Copy was not available. Select the text and copy it.",true)}}
const help=()=>note("Help: take your time. Use copy buttons instead of typing long details. You can retry without a penalty.");
const common=()=>'<div><button class="text" data-help type="button">ⓘ Need help?</button></div>';
function set(s){step=s;progress.innerHTML="Step <b>"+steps[s][0]+"</b> · "+steps[s][1];render()}
function wire(){screen.querySelectorAll("[data-help]").forEach(b=>b.onclick=help);screen.querySelectorAll("[data-back]").forEach(b=>b.onclick=()=>set(({identity:"start",setup:"identity",otp:"setup",backup:"otp",recovery:"backup"})[step]||step))}

/* Version 5-L QR encoder. URI is byte encoded with Reed-Solomon correction. */
function qrMatrix(value){
 const size=37,db=108,ec=26,bytes=new TextEncoder().encode(value);if(bytes.length>106)throw Error("URI exceeds Version 5-L byte capacity");
 const exp=Array(512),lg=Array(256);let z=1;for(let i=0;i<255;i++){exp[i]=z;lg[z]=i;z<<=1;if(z&256)z^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const mul=(a,b)=>a&&b?exp[lg[a]+lg[b]]:0,pm=(a,b)=>{const o=Array(a.length+b.length-1).fill(0);for(let i=0;i<a.length;i++)for(let j=0;j<b.length;j++)o[i+j]^=mul(a[i],b[j]);return o};let gen=[1];for(let i=0;i<ec;i++)gen=pm(gen,[1,exp[i]]);
 const bits=[],put=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push(v>>>i&1)};put(4,4);put(bytes.length,8);for(const b of bytes)put(b,8);for(let i=0;i<4&&bits.length<db*8;i++)bits.push(0);while(bits.length%8)bits.push(0);
 const data=[];for(let i=0;i<bits.length;i+=8){let n=0;for(let j=0;j<8;j++)n=n<<1|bits[i+j];data.push(n)}for(let i=0;data.length<db;i++)data.push(i%2?17:236);
 const rem=data.concat(Array(ec).fill(0));for(let i=0;i<data.length;i++){const f=rem[i];if(f)for(let j=0;j<gen.length;j++)rem[i+j]^=mul(gen[j],f)}const words=data.concat(rem.slice(data.length));
 const make=mask=>{const m=Array.from({length:size},()=>Array(size).fill(null)),set=(r,c,v)=>{if(r>=0&&c>=0&&r<size&&c<size)m[r][c]=v?1:0},finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)set(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4)))};finder(0,0);finder(30,0);finder(0,30);for(let i=8;i<29;i++){set(6,i,i%2===0);set(i,6,i%2===0)}for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(30+y,30+x,Math.max(Math.abs(y),Math.abs(x))!==1);set(29,8,1);
 let f=(1<<3|mask)<<10,q=f;while(q>=1024)q^=0x537<<(Math.floor(Math.log2(q))-10);f=(f|q)^0x5412;for(let i=0;i<15;i++){let b=f>>>i&1;if(i<6)set(i,8,b);else if(i<8)set(i+1,8,b);else set(22+i,8,b);if(i<8)set(8,36-i,b);else if(i<9)set(8,15-i,b);else set(8,14-i,b)}
 let stream=[];for(const w of words)for(let i=7;i>=0;i--)stream.push(w>>>i&1);let at=0,up=true,masked=(r,c)=>[(r+c)%2===0,r%2===0,c%3===0,(r+c)%3===0,(Math.floor(r/2)+Math.floor(c/3))%2===0,(r*c)%2+(r*c)%3===0,((r*c)%2+(r*c)%3)%2===0,((r+c)%2+(r*c)%3)%2===0][mask];
 for(let c=36;c>0;c-=2){if(c===6)c--;for(let t=0;t<size;t++){let r=up?36-t:t;for(let k=0;k<2;k++){let col=c-k;if(m[r][col]===null){let b=at<stream.length?stream[at++]:0;if(masked(r,col))b^=1;m[r][col]=b}}}up=!up}return m};
 const penalty=m=>{let p=0;for(let r=0;r<size;r++)for(let c=0;c<size;c++){let n=0;for(let y=-1;y<=1;y++)for(let x=-1;x<=1;x++)if(x||y){let a=r+y,b=c+x;if(a>=0&&b>=0&&a<size&&b<size&&m[a][b]===m[r][c])n++}if(n>5)p+=n-2}for(let r=0;r<36;r++)for(let c=0;c<36;c++)if(m[r][c]===m[r+1][c]&&m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c+1])p+=3;return p};let best=make(0),score=penalty(best);for(let i=1;i<8;i++){const n=make(i),p=penalty(n);if(p<score){best=n;score=p}}return best;
}
function qrCanvas(value){
 const m=qrMatrix(value),quiet=4,scale=6,c=document.createElement("canvas");c.width=c.height=(m.length+quiet*2)*scale;c.setAttribute("role","img");c.setAttribute("aria-label","Scannable QR code for adding this Online Bank authenticator account.");const x=c.getContext("2d");x.fillStyle="#fff";x.fillRect(0,0,c.width,c.height);x.fillStyle="#000";m.forEach((row,y)=>row.forEach((v,x0)=>{if(v)x.fillRect((x0+quiet)*scale,(y+quiet)*scale,scale,scale)}));return c;
}
function assertAndDisplayQR(exactUri){
 const host=$("#qr"),canvas=qrCanvas(exactUri);
 const valid=exactUri===uri&&exactUri.startsWith("otpauth://totp/")&&canvas instanceof HTMLCanvasElement&&canvas.width===canvas.height&&canvas.width>200;
 console.assert(valid,"Exact otpauth URI must render as a scannable Version 5-L QR canvas.");
 if(!valid)throw Error("QR assertion failed");
 host.replaceChildren(canvas);
 if(host.querySelector("canvas")!==canvas)throw Error("QR canvas display assertion failed");
}

function render(){
 if(step==="start"){title.textContent="Set up extra security";screen.innerHTML='<p>🔐 Sign in to begin this short setup.</p><label>Email address<input id="email" autocomplete="username email" inputmode="email" placeholder="name@example.com"></label><small>Example: name@example.com</small><label>Account PIN<input id="pin" type="password" autocomplete="current-password" inputmode="numeric" maxlength="12" placeholder="Your account PIN"></label><button id="go">Sign in and start</button>'+common();$("#go").onclick=async()=>{const r=await call("/api/authenticate",{email:$("#email").value,credential:$("#pin").value});$("#pin").value="";if(r){csrf=r.csrf;note(r.message);set("identity")}}}
 else if(step==="identity"){title.textContent="Check it is you";screen.innerHTML='<p>👤 Confirm the contact details on your account.</p><label>Email address<input id="email" autocomplete="email" value="marcus@example.test"></label><small>Example: name@example.com</small><label>Mobile number<input id="phone" autocomplete="tel" value="07700900123"></label><small>Example: 07700 900123</small><button id="go">Confirm my details</button><button class="text" data-back>← Back</button>'+common();$("#go").onclick=async()=>{const r=await call("/api/identity",{email:$("#email").value,phone:$("#phone").value});if(r){note(r.message);set("setup")}}}
 else if(step==="setup"){title.textContent="Add your authenticator";if(!key){screen.innerHTML='<p>📱 Create a private setup key for your authenticator app.</p><div class="hint">You can scan a QR code or copy a manual key. You do not need to type a long secret.</div><button id="make">Create my setup key</button><button class="text" data-back>← Back</button>'+common();$("#make").onclick=async()=>{const r=await call("/api/setup");if(r){key=r.secret;uri=r.uri;note(r.message);render()}}}else{screen.innerHTML='<p>📱 Scan this QR code with your authenticator app. Or use either copy option below.</p><div id="qr" class="qr"></div><button class="secondary" id="copyuri">Copy setup link</button><p class="hint">Manual Base32 key: <span class="secret">'+esc(key)+'</span></p><button class="secondary" id="copykey">Copy manual key</button><button class="secondary" id="hidekey">Hide setup key</button><button id="ready">I added it to my app</button>'+common();assertAndDisplayQR(uri);$("#copyuri").onclick=()=>copy(uri,"Setup link copied.");$("#copykey").onclick=()=>copy(key,"Manual key copied.");$("#hidekey").onclick=()=>{key="";uri="";note("Setup key hidden and removed from this page.");render()};$("#ready").onclick=()=>set("otp")}}
 else if(step==="otp"){title.textContent="Confirm your code";screen.innerHTML='<p>✅ Enter the six-number code from your authenticator. There is no reading timer.</p><label>Six-number code<input id="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6" placeholder="Example: 123456"></label><button id="verify">Confirm code</button><div class="hint"><b>Academic test option</b><br><small>A practice code is sent only to your browser console.</small><button class="secondary" id="mock">Send practice code to console</button><button class="text" id="usemock">Use practice code</button><button class="text" id="newmock">Request a fresh practice code</button></div><button class="text" data-back>← Back</button>'+common();$("#verify").onclick=async()=>{const r=await call("/api/otp",{code:$("#otp").value.trim()});if(r){log("Authenticator code verified.");note(r.message);set("backup")}};$("#mock").onclick=async()=>{const r=await call("/api/test/mock/reveal");if(r){mock=r.code;testLog("Mock OTP for academic test:",r.code);note(r.message)}};$("#newmock").onclick=async()=>{const r=await call("/api/test/mock/rerequest");if(r){mock=r.code;testLog("Fresh mock OTP for academic test:",r.code);note(r.message)}};$("#usemock").onclick=async()=>{if(!mock)return note("Request a practice code first. It will appear in your browser console.",true);const r=await call("/api/test/mock/verify",{code:mock});mock="";if(r){log("Practice authenticator code verified.");note(r.message);set("backup")}}}
 else if(step==="backup"){title.textContent="Save your backup codes";if(!codes.length&&!hidden){screen.innerHTML='<p>🗝️ Backup codes help if you cannot use your authenticator.</p><div class="hint">Generate them once, then save them somewhere private.</div><button id="make">Generate backup codes</button>'+common();$("#make").onclick=async()=>{const r=await call("/api/backups");if(r){codes=r.codes;testLog("MFA backup recovery codes:",r.codes);note(r.message);render()}}}else if(hidden){screen.innerHTML='<p>🗝️ Your backup codes are hidden and removed from this page.</p><div class="hint">Use the private copy you saved. Next, check one backup code works.</div><button class="secondary" id="replace">Generate fresh replacement codes</button><button id="continue">Continue to backup code check</button>'+common();$("#replace").onclick=async()=>{const r=await call("/api/backups");if(r){codes=r.codes;hidden=false;testLog("Replacement MFA backup recovery codes:",r.codes);note(r.message);render()}};$("#continue").onclick=()=>set("recovery")}else{screen.innerHTML='<p>🗝️ Keep these codes somewhere private. Each code works once.</p><ul class="codes">'+codes.map(x=>"<li>"+esc(x)+"</li>").join("")+'</ul><button class="secondary" id="copy">Copy all backup codes</button><button class="secondary" id="print">Print this page</button><button class="secondary" id="hide">Hide backup codes</button><button id="continue">Continue to backup code check</button>'+common();$("#copy").onclick=()=>copy(codes.join("\\n"),"Backup codes copied.");$("#print").onclick=()=>print();$("#hide").onclick=()=>{codes=[];hidden=true;note("Backup codes hidden and removed from this page.");render()};$("#continue").onclick=()=>set("recovery")}}
 else if(step==="recovery"){if(recoveryOK){title.textContent="Backup code confirmed";screen.innerHTML='<p>✅ Your backup code worked and is now used.</p><div class="hint">Your authenticator is confirmed. Finish when you are ready.</div><button id="finish">Finish MFA enrolment</button>'+common();$("#finish").onclick=async()=>{const r=await call("/api/complete");if(r){log("MFA enrolment completed.");note(r.message);set("done")}}}else{title.textContent="Check a backup code";screen.innerHTML='<p>🧪 Copy one code from your saved list and enter it here.</p><label>Backup code<input id="recovery" autocomplete="one-time-code" autocapitalize="characters" placeholder="Example: ABCDE-FGHIJ"></label><button id="check">Check backup code</button><button class="text" data-back>← Back</button>'+common();$("#check").onclick=async()=>{const r=await call("/api/recovery/verify",{code:$("#recovery").value.trim().toUpperCase()});if(r){recoveryOK=true;log("Backup recovery code verified and marked used.");note(r.message);render()}}}}
 else{title.textContent="MFA is ready";screen.innerHTML='<p>🎉 Your authenticator and backup codes are set up.</p><div class="hint">For future payments, use your authenticator when asked.</div><button id="logout">Finish and sign out</button>'+common();$("#logout").onclick=async()=>{const r=await call("/api/logout");if(r){csrf="";key="";uri="";codes=[];hidden=false;recoveryOK=false;mock="";log("Signed out.");note(r.message);set("start")}}}
 wire()}
set("start")})();
</script></body></html>`;
}

const server = Bun.serve({
  port: Number(process.env.PORT || 3000),
  hostname: "::",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = random(), response = new Response(page(nonce), { headers: headers(nonce) });
        response.headers.set("Content-Type", "text/html; charset=utf-8");
        return response;
      }
      return new Response("Not found", { status: 404, headers: headers() });
    } catch {
      return json({ ok: false, message: "Something went wrong. Please try again." }, 500);
    }
  }
});

console.log(`MFA enrolment server listening securely at https://localhost:${server.port}`);
