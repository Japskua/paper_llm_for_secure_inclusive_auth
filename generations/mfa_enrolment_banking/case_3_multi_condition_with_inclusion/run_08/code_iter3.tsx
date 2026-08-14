
import { readFileSync } from "fs";

/*
 MFA Enrolment System
 Requirements 1–5: authenticated server-side state, CSRF, HTTPS, secure
 response headers, input validation, encryption/hashing, and rate limiting.
*/

const enc = new TextEncoder();
const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const masterKey = crypto.getRandomValues(new Uint8Array(32));
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const recoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const SESSION_IDLE = 30 * 60_000, SESSION_MAX = 8 * 60 * 60_000;
const CODE_LIFE = 15 * 60_000, LOCKOUT = 10 * 60_000, TOTP_STEP = 30_000;
const trusted = new Set(["https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000"]);

type Challenge = { hash: string; expires: number; used: boolean; failures: number; lockedUntil: number };
type Encrypted = { iv: string; data: string };
type Account = {
  id: string; email: string; identityChallenge?: Challenge; authenticatorSecret?: Encrypted;
  authenticatorFailures: number; authenticatorLockedUntil: number; authenticatorUsedSteps: Set<number>;
  mfaEnabled: boolean; recoveryCodes: { salt: string; hash: string; used: boolean }[];
  recoveryFailures: number; recoveryLockedUntil: number;
};
type Session = { id: string; accountId: string; csrf: string; created: number; lastSeen: number; identityVerified: boolean };

const marcus: Account = {
  id: "acct_marcus_demo", email: "marcus@example.com", authenticatorFailures: 0,
  authenticatorLockedUntil: 0, authenticatorUsedSteps: new Set(), mfaEnabled: false,
  recoveryCodes: [], recoveryFailures: 0, recoveryLockedUntil: 0,
};
accounts.set(marcus.id, marcus);

const bytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const b64 = (v: Uint8Array) => Buffer.from(v).toString("base64url");
const token = (n = 32) => b64(bytes(n));
const sha = (v: string) => new Bun.CryptoHasher("sha256").update(v).digest("hex");
function equal(a: string, b: string) {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
function randomBase32(length = 32) {
  /* Task: cryptographically random Base32 authenticator seed. */
  const raw = bytes(length);
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[raw[i] & 31];
  return out;
}
function randomRecoveryCode() {
  /* Task: cryptographically random recovery code. */
  const raw = bytes(10);
  let value = "";
  for (const n of raw) value += recoveryAlphabet[n & 31];
  return value.slice(0, 5) + "-" + value.slice(5);
}
const grouped = (s: string) => s.match(/.{1,4}/g)!.join("-");
function challenge(code: string): Challenge {
  const salt = token(24);
  return { hash: salt + ":" + sha(salt + code), expires: Date.now() + CODE_LIFE, used: false, failures: 0, lockedUntil: 0 };
}
function deterministicIdentityCode(sessionId: string) {
  return String(parseInt(sha("demo-identity|" + sessionId).slice(0, 12), 16) % 1_000_000).padStart(6, "0");
}
function checkChallenge(c: Challenge | undefined, code: string) {
  if (!c) return "Request a new code, then try again.";
  if (c.used) return "That code was already used. Request a new code.";
  if (Date.now() > c.expires) return "That code has expired. Request a new code.";
  if (Date.now() < c.lockedUntil) return "Too many attempts. Please wait a few minutes, then request a new code.";
  const [salt, stored] = c.hash.split(":");
  if (!equal(sha(salt + code), stored)) {
    c.failures++;
    if (c.failures >= 5) { c.failures = 0; c.lockedUntil = Date.now() + LOCKOUT; return "Too many attempts. Please wait a few minutes before trying again."; }
    return "That code does not match. Check the six digits, or request a new code.";
  }
  c.used = true; return "";
}
async function encrypt(value: string): Promise<Encrypted> {
  const iv = bytes(12), key = await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["encrypt"]);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(value));
  return { iv: b64(iv), data: b64(new Uint8Array(data)) };
}
async function decrypt(value: Encrypted) {
  const key = await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["decrypt"]);
  const data = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(value.iv, "base64url") }, key, Buffer.from(value.data, "base64url"));
  return new TextDecoder().decode(data);
}
function base32Decode(s: string) {
  let bits = 0, count = 0; const out: number[] = [];
  for (const char of s.replaceAll("-", "")) {
    const n = alphabet.indexOf(char); if (n < 0) throw new Error("bad seed");
    bits = (bits << 5) | n; count += 5;
    if (count >= 8) { out.push((bits >>> (count - 8)) & 255); count -= 8; }
  }
  return new Uint8Array(out);
}
async function totp(secret: string, step: number) {
  const counter = new Uint8Array(8); let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(n & 255n); n >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter)), off = h[19] & 15;
  const value = ((h[off] & 127) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(value % 1_000_000).padStart(6, "0");
}

function cookies(req: Request) {
  return Object.fromEntries((req.headers.get("cookie") || "").split(";").map(v => {
    const i = v.indexOf("="); return i < 0 ? ["", ""] : [v.slice(0, i).trim(), decodeURIComponent(v.slice(i + 1))];
  }));
}
function sessionCookie(v: string, age?: number) {
  return `mfa_session=${encodeURIComponent(v)}; Path=/; HttpOnly; Secure; SameSite=Strict${age !== undefined ? `; Max-Age=${age}` : ""}`;
}
function getSession(req: Request) {
  const s = sessions.get(cookies(req).mfa_session || ""); if (!s) return null;
  if (Date.now() - s.lastSeen > SESSION_IDLE || Date.now() - s.created > SESSION_MAX) { sessions.delete(s.id); return null; }
  s.lastSeen = Date.now(); return s;
}
function createSession(accountId: string) {
  const s: Session = { id: token(), accountId, csrf: token(), created: Date.now(), lastSeen: Date.now(), identityVerified: false };
  sessions.set(s.id, s); return s;
}
function headers(nonce: string) {
  return {
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data: blob:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", "Vary": "Origin",
  };
}
function reply(data: unknown, status = 200, nonce = "") { return Response.json(data, { status, headers: headers(nonce) }); }
function fail(message = "We could not complete that request. Please try again.", status = 400, nonce = "") { return reply({ ok: false, message }, status, nonce); }
async function body(req: Request) {
  const x = await req.json().catch(() => null);
  return x && typeof x === "object" && !Array.isArray(x) ? x as Record<string, unknown> : null;
}
function auth(req: Request, nonce: string) {
  const session = getSession(req), account = session && accounts.get(session.accountId);
  return session && account ? { session, account } : { error: fail("Please sign in again to continue.", 401, nonce) };
}
function csrf(req: Request, session: Session, nonce: string) {
  const value = req.headers.get("x-csrf-token") || "";
  return value && equal(value, session.csrf) ? null : fail("Your secure page has changed. Refresh the page and try again.", 403, nonce);
}
const clean = (d: Record<string, unknown>) => !["userId", "accountId", "emailId"].some(k => k in d);
const six = (v: unknown) => typeof v === "string" && /^\d{6}$/.test(v);

async function api(req: Request, path: string, nonce: string): Promise<Response> {
  if (path === "/api/signin" && req.method === "POST") {
    const d = await body(req), generic = "We could not sign you in. Check your email and password, then try again.";
    if (!d || typeof d.email !== "string" || typeof d.password !== "string" || d.email.length > 120 || d.password.length > 200 ||
      !equal(d.email.toLowerCase(), marcus.email) || !equal(d.password, "MarcusDemo!2025")) return fail(generic, 401, nonce);
    for (const [id, s] of sessions) if (s.accountId === marcus.id) sessions.delete(id);
    const s = createSession(marcus.id), r = reply({ ok: true, next: "#identity" }, 200, nonce);
    r.headers.set("Set-Cookie", sessionCookie(s.id)); return r;
  }
  if (path === "/api/session" && req.method === "GET") {
    const a = auth(req, nonce); if ("error" in a) return a.error;
    return reply({ ok: true, csrf: a.session.csrf, identityVerified: a.session.identityVerified, mfaEnabled: a.account.mfaEnabled, provisioned: !!a.account.authenticatorSecret, recoveryCount: a.account.recoveryCodes.length }, 200, nonce);
  }
  const a = auth(req, nonce); if ("error" in a) return a.error;
  const { session, account } = a;
  if (path === "/api/logout" && req.method === "POST") {
    const x = csrf(req, session, nonce); if (x) return x;
    sessions.delete(session.id); const r = reply({ ok: true }, 200, nonce); r.headers.set("Set-Cookie", sessionCookie("", 0)); return r;
  }
  if (path === "/api/identity/request" && req.method === "POST") {
    const d = await body(req); if (!d || !clean(d)) return fail(undefined, 400, nonce);
    const x = csrf(req, session, nonce); if (x) return x;
    const code = deterministicIdentityCode(session.id); account.identityChallenge = challenge(code);
    return reply({ ok: true, mockCode: code }, 200, nonce);
  }
  if (path === "/api/identity/verify" && req.method === "POST") {
    const d = await body(req); if (!d || !clean(d) || !six(d.code)) return fail("Enter six digits, for example 123456.", 400, nonce);
    const x = csrf(req, session, nonce); if (x) return x;
    const message = checkChallenge(account.identityChallenge, d.code as string); if (message) return fail(message, 400, nonce);
    session.identityVerified = true; return reply({ ok: true, next: account.mfaEnabled ? "#settings" : "#setup" }, 200, nonce);
  }
  if (!session.identityVerified) return fail("Please complete the identity check before changing MFA settings.", 403, nonce);
  if (path === "/api/authenticator/provision" && req.method === "POST") {
    const d = await body(req); if (!d || !clean(d)) return fail("We could not prepare setup.", 400, nonce);
    const x = csrf(req, session, nonce); if (x) return x;
    /* Task: a fresh secure seed is created for every provisioning request. */
    const secret = randomBase32(32);
    account.authenticatorSecret = await encrypt(secret);
    account.authenticatorFailures = 0; account.authenticatorLockedUntil = 0; account.authenticatorUsedSteps.clear();
    const mockCode = await totp(secret, Math.floor(Date.now() / TOTP_STEP));
    const uri = `otpauth://totp/Local%20Bank:${encodeURIComponent(account.email)}?secret=${secret}&issuer=Local%20Bank&algorithm=SHA1&digits=6&period=30`;
    return reply({ ok: true, secret: grouped(secret), uri, mockCode }, 200, nonce);
  }
  if (path === "/api/authenticator/confirm" && req.method === "POST") {
    const d = await body(req); if (!d || !clean(d) || !six(d.code)) return fail("Enter six digits, for example 123456.", 400, nonce);
    const x = csrf(req, session, nonce); if (x) return x;
    if (!account.authenticatorSecret) return fail("Show a setup code before confirming your authenticator.", 400, nonce);
    if (Date.now() < account.authenticatorLockedUntil) return fail("Too many attempts. Please wait a few minutes, then try again.", 429, nonce);
    const secret = await decrypt(account.authenticatorSecret), now = Math.floor(Date.now() / TOTP_STEP);
    let step = -1; for (const candidate of [now - 1, now, now + 1]) if (equal(await totp(secret, candidate), d.code as string)) { step = candidate; break; }
    if (step < 0 || account.authenticatorUsedSteps.has(step)) {
      if (++account.authenticatorFailures >= 5) { account.authenticatorFailures = 0; account.authenticatorLockedUntil = Date.now() + LOCKOUT; return fail("Too many attempts. Please wait a few minutes before trying again.", 429, nonce); }
      return fail(step >= 0 ? "That authenticator code was already used. Wait for a new code, then try again." : "That code does not match your authenticator. Check the six digits and try again.", 400, nonce);
    }
    account.authenticatorUsedSteps.add(step); account.authenticatorFailures = 0; account.mfaEnabled = true;
    return reply({ ok: true, next: "#recovery" }, 200, nonce);
  }
  if (path === "/api/recovery/generate" && req.method === "POST") {
    const d = await body(req); if (!d || !clean(d)) return fail("We could not create recovery codes.", 400, nonce);
    const x = csrf(req, session, nonce); if (x) return x;
    if (!account.mfaEnabled) return fail("Connect your authenticator before creating recovery codes.", 403, nonce);
    /* Task: generated codes and salts are random; only salted hashes remain in state. */
    const codes = Array.from({ length: 8 }, randomRecoveryCode);
    account.recoveryCodes = codes.map(code => { const salt = token(24); return { salt, hash: sha(salt + code), used: false }; });
    account.recoveryFailures = 0; return reply({ ok: true, codes }, 200, nonce);
  }
  if (path === "/api/recovery/use" && req.method === "POST") {
    const d = await body(req), code = d?.code;
    if (!d || !clean(d) || typeof code !== "string" || !/^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(code)) return fail("Enter a recovery code like ABCDE-23456.", 400, nonce);
    const x = csrf(req, session, nonce); if (x) return x;
    if (Date.now() < account.recoveryLockedUntil) return fail("Too many attempts. Please wait a few minutes, then try another code.", 429, nonce);
    const found = account.recoveryCodes.find(v => !v.used && equal(v.hash, sha(v.salt + code)));
    if (!found) {
      if (++account.recoveryFailures >= 5) { account.recoveryFailures = 0; account.recoveryLockedUntil = Date.now() + LOCKOUT; return fail("Too many attempts. Please wait a few minutes before trying again.", 429, nonce); }
      return fail("That recovery code is not available. Check it, or use another unused code.", 400, nonce);
    }
    found.used = true; account.recoveryFailures = 0; return reply({ ok: true, message: "Recovery code accepted. It cannot be used again." }, 200, nonce);
  }
  if (path === "/api/settings" && req.method === "GET") return reply({ ok: true, enabled: account.mfaEnabled, remaining: account.recoveryCodes.filter(v => !v.used).length, email: account.email }, 200, nonce);
  return fail("That page is not available.", 404, nonce);
}

const page = (nonce: string) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Local Bank security setup</title>
<style nonce="${nonce}">
:root{--b:#075e9e;--i:#18212b;--m:#53616e;--l:#c8d5df;--p:#eef7fc;--e:#8d2424}*{box-sizing:border-box}body{margin:0;background:#f4f7f9;color:var(--i);font:17px/1.65 Arial,Verdana,sans-serif;letter-spacing:.025em}.shell{max-width:620px;min-height:100vh;margin:auto;padding:20px;background:white}.top{display:flex;justify-content:space-between;border-bottom:2px solid var(--l);padding-bottom:12px}.brand{font-weight:bold;color:#034a7c}.logout,.link{border:0;background:none;color:var(--b);text-decoration:underline;font:inherit}.progress{display:flex;gap:6px;margin:19px 0}.progress i{height:8px;flex:1;background:#d8e1e6;border-radius:9px}.progress i.on{background:var(--b)}h1{font-size:1.7rem;line-height:1.25}h2{font-size:1.2rem}.lead,.example{color:var(--m)}.hint,.success,.error{padding:12px 14px;margin:15px 0;border-radius:7px;background:var(--p);border-left:5px solid #2184bd}.success{background:#eef9f2;border-color:#156c43}.error{background:#fff1f1;border-color:var(--e);color:#702020}label{display:block;font-weight:bold;margin-top:15px}input{width:100%;min-height:51px;border:2px solid #8497a5;border-radius:8px;padding:10px;font:inherit}input:focus{outline:3px solid #82c9ee}.primary,.secondary{width:100%;min-height:53px;border-radius:9px;padding:9px;margin-top:18px;font:inherit;font-weight:bold}.primary{border:0;background:var(--b);color:white}.secondary{border:2px solid var(--b);background:white;color:var(--b)}.code{font-family:ui-monospace,Consolas,monospace;letter-spacing:.12em}.secret{padding:12px;background:#f3f6f8;overflow-wrap:anywhere}.qr{display:block;width:240px;height:240px;margin:15px auto;image-rendering:pixelated}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:0;list-style:none}.codes li{padding:8px;background:#f1f5f7;font-family:ui-monospace,monospace}.logs{margin-top:28px;padding-top:12px;border-top:2px solid var(--l)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#17222c;color:#d9f2ff;padding:10px;border-radius:8px}.hide{display:none!important}@media(max-width:390px){.shell{padding:16px}.codes{grid-template-columns:1fr}}
</style></head><body><main class="shell"><header class="top"><span class="brand">🏦 Local Bank</span><button class="logout hide" id="logout">Log out</button></header><nav class="progress"><i id="p1"></i><i id="p2"></i><i id="p3"></i><i id="p4"></i></nav><section id="app" aria-live="polite"></section><section class="logs"><h2>🔎 Demo logs</h2><p class="example">Test values appear here and in the browser console.</p><pre id="logs">Ready.</pre></section></main>
<script nonce="${nonce}">(()=>{"use strict";
const app=document.querySelector("#app"),logs=document.querySelector("#logs"),logout=document.querySelector("#logout");let csrf="",provision,codes=[];
const routes=new Set(["#signin","#identity","#setup","#confirm","#recovery","#saved","#settings","#use"]);
function log(x){console.log(x);logs.textContent+=(logs.textContent==="Ready."?"\\n":"\\n")+x}function go(x){location.hash=routes.has(x)?x:"#signin"}function prog(n){for(let i=1;i<5;i++)document.querySelector("#p"+i).classList.toggle("on",i<=n)}
function err(x){let e=document.querySelector("#form-error");if(e){e.className="error";e.textContent=x;e.focus()}}function help(){return '<button class="link" data-help>Need help?</button>'}function attach(){document.querySelectorAll("[data-help]").forEach(x=>x.onclick=()=>alert("Take your time. You can retry safely. Demo test values are in Demo logs."))}
async function api(path,method="GET",data){let o={method,headers:{Accept:"application/json"}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(data||{})}try{let r=await fetch(path,o),j=await r.json();if(r.status===401){csrf="";logout.classList.add("hide")}return j}catch{return{ok:false,message:"We could not connect securely. Please try again."}}}
async function signed(){let s=await api("/api/session");if(s.ok){csrf=s.csrf;logout.classList.remove("hide");return s}return null}

/* Correct self-contained QR Model 2 encoder: byte mode, versions 1–10, L ECC,
   capacity selection, interleaving, Reed–Solomon ECC, all masks and BCH format bits. */
function qr(text){
 const raw=new TextEncoder().encode(text), specs=[[1,19,1,19],[2,34,1,34],[3,55,1,55],[4,80,1,80],[5,108,1,108],[6,136,2,68],[7,156,2,78],[8,194,2,97],[9,232,2,116],[10,274,4,68]];
 let spec=specs.find(s=>raw.length+(s[0]<10?2:3)<=s[1]);if(!spec)return null;let [ver,cap,blocks,per]=spec,size=17+4*ver;
 let bits=[],put=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push(v>>>i&1)};put(4,4);put(raw.length,ver<10?8:16);raw.forEach(x=>put(x,8));put(0,Math.min(4,cap*8-bits.length));while(bits.length%8)bits.push(0);
 let data=[];for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8).join(""),2));for(let p=0;data.length<cap;p++)data.push(p%2?17:236);
 let exp=[],lg=[],x=1;for(let i=0;i<255;i++){exp[i]=x;lg[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 let ecc=Math.round((ver===10?4*86:blocks*(per+(ver===10?0:0)))-cap);if(ver<=5)ecc=[7,10,15,20,26][ver-1];else if(ver===6)ecc=36;else if(ver===7)ecc=40;else if(ver===8)ecc=48;else if(ver===9)ecc=52;else ecc=72;
 let ecPer=ecc/blocks,gen=[1];for(let i=0;i<ecPer;i++){let z=Array(gen.length+1).fill(0);gen.forEach((g,j)=>{z[j]^=g;z[j+1]^=exp[lg[g]+i]});gen=z}
 let ds=[],es=[];for(let b=0;b<blocks;b++){let d=data.slice(b*per,(b+1)*per),r=Array(ecPer).fill(0);for(let q of d){let f=q^r.shift();r.push(0);for(let j=0;j<ecPer;j++)r[j]^=f?exp[lg[gen[j+1]]+lg[f]]:0}ds.push(d);es.push(r)}
 let stream=[];for(let i=0;i<per;i++)ds.forEach(d=>stream.push(d[i]));for(let i=0;i<ecPer;i++)es.forEach(e=>stream.push(e[i]));let db=[];stream.forEach(q=>put=0);for(const q of stream)for(let i=7;i>=0;i--)db.push(q>>>i&1);
 const aligns=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50]][ver-1];
 function matrix(mask){let m=Array.from({length:size},()=>Array(size).fill(null)),set=(r,c,v)=>{if(r>=0&&c>=0&&r<size&&c<size)m[r][c]=v};
  function finder(r,c){for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)set(r+y,c+z,y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4))?1:0)}finder(0,0);finder(size-7,0);finder(0,size-7);
  aligns.forEach(r=>aligns.forEach(c=>{if(m[r][c]!==null)return;for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)set(r+y,c+z,Math.max(Math.abs(y),Math.abs(z))!==1?1:0)}));
  for(let i=8;i<size-8;i++){set(6,i,+(i%2===0));set(i,6,+(i%2===0))}for(let i=0;i<9;i++){if(m[i][8]===null)set(i,8,0);if(m[8][i]===null)set(8,i,0);if(m[size-1-i][8]===null)set(size-1-i,8,0);if(m[8][size-1-i]===null)set(8,size-1-i,0)}set(size-8,8,1);
  let k=0,up=true;for(let c=size-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<size;q++){let r=up?size-1-q:q;for(let cc of[c,c-1])if(m[r][cc]===null){let flip=[(r+cc)%2===0,r%2===0,cc%3===0,(r+cc)%3===0,(Math.floor(r/2)+Math.floor(cc/3))%2===0,(r*cc)%2+(r*cc)%3===0,((r*cc)%2+(r*cc)%3)%2===0,((r*cc)%3+(r+cc)%2)%2===0][mask];m[r][cc]=(db[k++]||0)^(flip?1:0)}}up=!up}
  let v=(1<<3|mask)<<10,g=0x537;while(v.toString(2).length>=g.toString(2).length)v^=g<<(v.toString(2).length-g.toString(2).length);v=(((1<<3|mask)<<10)|v)^0x5412;
  for(let i=0;i<15;i++){let b=v>>>i&1;if(i<6)set(i,8,b);else if(i<8)set(i+1,8,b);else set(size-15+i,8,b);if(i<8)set(8,size-i-1,b);else if(i<9)set(8,15-i,b);else set(8,14-i,b)}return m}
 function score(m){let z=0;for(let r=0;r<size;r++)for(let c=0;c<size;c++){let n=0,v=m[r][c];for(let y=-1;y<2;y++)for(let x=-1;x<2;x++)if((y||x)&&m[r+y]?.[c+x]===v)n++;if(n>5)z+=3+n-5}return z}
 let best=matrix(0),s=score(best);for(let i=1;i<8;i++){let q=matrix(i),n=score(q);if(n<s){best=q;s=n}}let svg='<svg class="qr" viewBox="0 0 '+size+' '+size+'" role="img" aria-label="Authenticator setup QR code" xmlns="http://www.w3.org/2000/svg"><rect width="100%" height="100%" fill="white"/>';best.forEach((r,y)=>r.forEach((v,x)=>{if(v)svg+='<rect x="'+x+'" y="'+y+'" width="1" height="1"/>'}));return svg+"</svg>"
}
function signin(){prog(0);app.innerHTML='<h1>🔐 Sign in</h1><p class="lead">Start your security setup.</p><div class="hint">Demo email: <b>marcus@example.com</b><br>Demo password: <b>MarcusDemo!2025</b></div><form id="f"><div id="form-error" tabindex="-1"></div><label>Email address</label><input name="email" type="email" autocomplete="username" required><label>Password</label><input name="password" type="password" autocomplete="current-password" required><button class="primary">Sign in</button></form>'+help();document.querySelector("#f").onsubmit=async e=>{e.preventDefault();let f=new FormData(e.target),r=await api("/api/signin","POST",{email:f.get("email"),password:f.get("password")});if(!r.ok)return err(r.message);log("Sign-in complete. Secure session created.");go(r.next)};attach()}
function identity(){prog(1);app.innerHTML='<h1>🪪 Check it is you</h1><p class="lead">Get a six-digit identity code for this demo.</p><div class="hint">There is no reading timer. Take as long as you need.</div><div id="form-error" tabindex="-1"></div><button id="get" class="primary">Get identity code</button>'+help();document.querySelector("#get").onclick=async()=>{let r=await api("/api/identity/request","POST",{});if(!r.ok)return err(r.message);log("Demo identity code: "+r.mockCode);app.innerHTML='<h1>🪪 Enter your identity code</h1><form id="f"><div id="form-error" tabindex="-1"></div><label>Six-digit code</label><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required><button class="primary">Check code</button></form>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();let r=await api("/api/identity/verify","POST",{code:new FormData(e.target).get("code")});if(!r.ok)return err(r.message);go(r.next)}};attach()}
function setup(){prog(2);app.innerHTML='<h1>📱 Set up your authenticator</h1><p class="lead">Scan a code, or copy a setup key. You do not need to write it down.</p><div id="form-error" tabindex="-1"></div><button id="go" class="primary">Show setup code</button>'+help();document.querySelector("#go").onclick=async()=>{let r=await api("/api/authenticator/provision","POST",{});if(!r.ok)return err(r.message);provision=r;log("Authenticator setup secret (demo): "+r.secret);log("Current TOTP test code (demo): "+r.mockCode);showProvision()};attach()}
function showProvision(){let image=qr(provision.uri),notice=image?"":"<div class=error>QR code is too large to encode. Use the copyable manual setup key below.</div>";app.innerHTML='<h1>📱 Add this to your app</h1><p class="lead">Scan the square, or copy the setup key.</p>'+notice+(image||"")+'<div id="key" class="secret code"></div><button id="copy" class="secondary">Copy setup key</button><button id="next" class="primary">I added it — continue</button><button id="new" class="link">Show a new setup code</button>';document.querySelector("#key").textContent=provision.secret;document.querySelector("#copy").onclick=async()=>{try{await navigator.clipboard.writeText(provision.secret);alert("Setup key copied.")}catch{alert("Select the setup key and copy it.")}};document.querySelector("#next").onclick=()=>go("#confirm");document.querySelector("#new").onclick=()=>go("#setup")}
function confirm(){prog(3);app.innerHTML='<h1>✅ Check your authenticator</h1><p class="lead">Enter the six digits from your app.</p><form id="f"><div id="form-error" tabindex="-1"></div><label>Authenticator code</label><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required><button class="primary">Confirm authenticator</button></form><button id="retry" class="secondary">Show setup code again</button>'+help();document.querySelector("#f").onsubmit=async e=>{e.preventDefault();let r=await api("/api/authenticator/confirm","POST",{code:new FormData(e.target).get("code")});if(!r.ok)return err(r.message);log("Authenticator confirmed.");go(r.next)};document.querySelector("#retry").onclick=()=>go("#setup");attach()}
function recovery(){prog(4);app.innerHTML='<h1>🧾 Save recovery codes</h1><p class="lead">These help if you cannot use your authenticator.</p><div class="hint">Save them somewhere private. Each code works once.</div><div id="form-error" tabindex="-1"></div><button id="create" class="primary">Create recovery codes</button>';document.querySelector("#create").onclick=async()=>{let r=await api("/api/recovery/generate","POST",{});if(!r.ok)return err(r.message);codes=r.codes;log("Recovery codes (demo): "+codes.join(", "));app.innerHTML='<h1>🧾 Your recovery codes</h1><ul class="codes" id="list"></ul><button id="copy" class="secondary">Copy all codes</button><button id="done" class="primary">I saved my codes</button>';let l=document.querySelector("#list");codes.forEach(c=>{let x=document.createElement("li");x.textContent=c;l.appendChild(x)});document.querySelector("#copy").onclick=()=>navigator.clipboard.writeText(codes.join("\\n")).then(()=>alert("Recovery codes copied.")).catch(()=>alert("Select the codes and copy them."));document.querySelector("#done").onclick=()=>go("#saved")}}
async function settings(){prog(4);let r=await api("/api/settings");if(!r.ok)return;app.innerHTML='<h1>⚙️ Security settings</h1><div class="success">MFA is on for <b id="email"></b>.</div><p id="remain"></p><button id="newcodes" class="primary">Create new recovery codes</button><button id="use" class="secondary">Use a recovery code</button>';document.querySelector("#email").textContent=r.email;document.querySelector("#remain").textContent=r.remaining+" unused code(s) remain.";document.querySelector("#newcodes").onclick=()=>go("#recovery");document.querySelector("#use").onclick=()=>go("#use")}
function use(){prog(4);app.innerHTML='<h1>🔑 Use a recovery code</h1><form id="f"><div id="form-error" tabindex="-1"></div><label>Recovery code</label><input class="code" name="code" autocomplete="one-time-code" placeholder="ABCDE-23456" maxlength="11" required><button class="primary">Use recovery code</button></form>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();let r=await api("/api/recovery/use","POST",{code:String(new FormData(e.target).get("code")).toUpperCase().trim()});if(!r.ok)return err(r.message);app.innerHTML='<h1>✓ Recovery code accepted</h1><div class="success">'+r.message+'</div><button id="back" class="primary">Back to settings</button>';document.querySelector("#back").onclick=()=>go("#settings")}}
function saved(){prog(4);app.innerHTML='<h1>🎉 Security setup complete</h1><div class="success">Your authenticator is connected and your recovery codes are saved.</div><button id="go" class="primary">View security settings</button>';document.querySelector("#go").onclick=()=>go("#settings")}
async function render(){let route=routes.has(location.hash)?location.hash:"#signin";if(route==="#signin"){signin();return}let s=await signed();if(!s){go("#signin");return}if(!s.identityVerified&&route!=="#identity"){go("#identity");return}if(!s.mfaEnabled&&!["#identity","#setup","#confirm"].includes(route)){go(s.provisioned?"#confirm":"#setup");return}if(s.mfaEnabled&&s.recoveryCount===0&&["#settings","#saved","#use"].includes(route)){go("#recovery");return}if(route==="#identity")identity();else if(route==="#setup")setup();else if(route==="#confirm")confirm();else if(route==="#recovery")recovery();else if(route==="#saved")saved();else if(route==="#settings")settings();else use()}
logout.onclick=async()=>{let r=await api("/api/logout","POST",{});if(r.ok){csrf="";provision=null;codes=[];log("Secure session ended.");go("#signin")}};addEventListener("hashchange",render);render()})();</script></body></html>`;

const cert = readFileSync("certs/cert.pem"), key = readFileSync("certs/key.pem");
Bun.serve({
  port: 3000, tls: { cert, key },
  fetch: async req => {
    const nonce = token(18);
    try {
      const url = new URL(req.url), origin = req.headers.get("origin");
      if (req.headers.get("x-forwarded-proto") === "http") return new Response("Secure connection required.", { status: 426, headers: headers(nonce) });
      if (origin && !trusted.has(origin)) return new Response("Not allowed.", { status: 403, headers: headers(nonce) });
      const cors = origin && trusted.has(origin) ? { "Access-Control-Allow-Origin": origin } : {};
      if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...headers(nonce), ...cors, "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token" } });
      if (url.pathname.startsWith("/api/")) { const r = await api(req, url.pathname, nonce); for (const [k, v] of Object.entries(cors)) r.headers.set(k, v); return r; }
      if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) return new Response(page(nonce), { headers: { ...headers(nonce), ...cors, "Content-Type": "text/html; charset=utf-8" } });
      return new Response("Page not found.", { status: 404, headers: headers(nonce) });
    } catch { return new Response("We could not complete that request. Please try again.", { status: 500, headers: headers(nonce) }); }
  },
});
