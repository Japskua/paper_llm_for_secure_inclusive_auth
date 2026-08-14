
import { serve } from "bun";
import { timingSafeEqual } from "node:crypto";

/* Requirements 1–5: TLS, secure in-memory mock state, authorization, CSRF. */
const cert = await Bun.file("certs/cert.pem").text();
const key = await Bun.file("certs/key.pem").text();
const TEST_SIMULATION = process.env.TEST_SIMULATION === "true";

const enc = new TextEncoder(), dec = new TextDecoder();
const IDLE = 30 * 60_000, ABSOLUTE = 8 * 60 * 60_000, CODE_LIFE = 15 * 60_000;
const LOCK = 10 * 60_000, MAX = 5, PERIOD = 30, PBKDF2_ITERATIONS = 210_000;
const ORIGIN = /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/;

type Verify = { code: string; expires: number; used: boolean; attempts: number; locked: number };
type Stored = { iv: string; cipher: string };
type RecoveryStored = { salt: string; hash: string; used: boolean };
type Session = { id: string; accountId: string; csrf: string; created: number; seen: number };
type Account = {
  id: string; email: string; identityVerified: boolean; mfaEnabled: boolean;
  identity?: Verify; auth?: Verify; pending?: Stored; secret?: Stored;
  backups: RecoveryStored[]; recoveryAttempts: number; recoveryLocked: number;
};

const accounts = new Map<string, Account>([["acct-marcus", {
  id: "acct-marcus", email: "marcus@example.com", identityVerified: false,
  mfaEnabled: false, backups: [], recoveryAttempts: 0, recoveryLocked: 0
}]]);
const sessions = new Map<string, Session>();
const tickets = new Map<string, number>();
const loginFailures = new Map<string, { attempts: number; locked: number }>();
const encryptionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

function token(n = 32) {
  const bytes = new Uint8Array(n); crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("base64url");
}
function six() {
  const bytes = new Uint32Array(1); crypto.getRandomValues(bytes);
  return String((bytes[0] % 900000) + 100000);
}
function setupSecret() {
  const bytes = new Uint8Array(20), chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  crypto.getRandomValues(bytes);
  return [...bytes].map(x => chars[x % chars.length]).join("");
}
function recovery() {
  const bytes = new Uint8Array(10), chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  crypto.getRandomValues(bytes);
  return [...bytes].map(x => chars[x % chars.length]).join("");
}
function b64(value: ArrayBuffer | Uint8Array) { return Buffer.from(value).toString("base64url"); }
function unb64(value: string) { return new Uint8Array(Buffer.from(value, "base64url")); }

async function crypt(value: string): Promise<Stored> {
  const iv = new Uint8Array(12); crypto.getRandomValues(iv);
  return {
    iv: b64(iv),
    cipher: b64(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, enc.encode(value)))
  };
}
async function decrypt(value: Stored) {
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(value.iv) }, encryptionKey, unb64(value.cipher)));
}
async function recoveryHash(code: string, salt: string) {
  const material = await crypto.subtle.importKey("raw", enc.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2", salt: unb64(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256"
  }, material, 256);
  return b64(bits);
}
function equal(a: string, b: string) {
  const left = Buffer.from(a), right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
async function makeBackups() {
  const plain = Array.from({ length: 8 }, recovery);
  const stored: RecoveryStored[] = [];
  for (const code of plain) {
    const salt = token(16);
    stored.push({ salt, hash: await recoveryHash(code, salt), used: false });
  }
  return { plain, stored };
}
function base32(value: string) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", output: number[] = [];
  let bits = 0, current = 0;
  for (const char of value.replace(/[\s=]/g, "").toUpperCase()) {
    const n = chars.indexOf(char);
    if (n < 0) throw new Error("invalid");
    current = (current << 5) | n; bits += 5;
    if (bits >= 8) { bits -= 8; output.push((current >> bits) & 255); }
  }
  return new Uint8Array(output);
}
async function totp(secret: string, counter: number) {
  const message = new Uint8Array(8); let n = BigInt(counter);
  for (let i = 7; i >= 0; i--) { message[i] = Number(n & 255n); n >>= 8n; }
  const hmacKey = await crypto.subtle.importKey("raw", base32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, message));
  const offset = mac[19] & 15;
  return String(((((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3]) % 1_000_000)).padStart(6, "0");
}

/* Requirement 5: reissues retain active failed-attempt state and locks. */
function verifyNew(previous?: Verify): Verify {
  const now = Date.now();
  const locked = previous?.locked || 0;
  const activeLock = locked > now;
  return {
    code: six(), expires: now + CODE_LIFE, used: false,
    attempts: activeLock ? previous!.attempts : 0,
    locked: activeLock ? locked : 0
  };
}
function resetExpiredLock(verifier: Verify | undefined) {
  if (verifier && verifier.locked && verifier.locked <= Date.now()) {
    verifier.locked = 0;
    verifier.attempts = 0;
  }
}
function lockText() { return "Too many tries were made. Please wait 10 minutes, then try again."; }
function authLockText() { return "Authenticator setup is temporarily locked. Please wait 10 minutes, then try again."; }
function recoveryLockText() { return "Recovery code checking is temporarily locked. Please wait 10 minutes, then try again."; }

function auth(req: Request) {
  const match = (req.headers.get("cookie") || "").match(/(?:^|;\s*)mfa_session=([^;]+)/);
  const session = match ? sessions.get(match[1]) : undefined;
  if (!session) return null;
  const now = Date.now();
  if (now - session.seen > IDLE || now - session.created > ABSOLUTE) { sessions.delete(session.id); return null; }
  const account = accounts.get(session.accountId);
  if (!account) { sessions.delete(session.id); return null; }
  session.seen = now;
  return { session, account };
}

/* Requirement 2: secure headers, trusted CORS, anti-clickjacking, no cache. */
function headers(req: Request, nonce?: string) {
  const h = new Headers({
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'self'; frame-ancestors 'none'; base-uri 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store, max-age=0"
  });
  const origin = req.headers.get("origin");
  if (origin && ORIGIN.test(origin)) {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    h.set("Vary", "Origin");
  }
  return h;
}
function reply(req: Request, data: unknown, status = 200, extra?: HeadersInit) {
  const h = headers(req);
  h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((v, k) => h.set(k, v));
  return new Response(JSON.stringify(data), { status, headers: h });
}
async function body(req: Request) {
  if (!(req.headers.get("content-type") || "").includes("application/json")) return null;
  const raw = await req.text();
  if (raw.length > 4000) return null;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch { return null; }
}
function field(data: Record<string, unknown> | null, key: string, max = 200) {
  const value = data?.[key];
  return typeof value === "string" && value.length <= max ? value.trim() : "";
}
function csrf(req: Request, session: Session, data: Record<string, unknown> | null) {
  const value = req.headers.get("x-csrf-token") || field(data, "csrf");
  return value.length >= 32 && equal(value, session.csrf);
}
function cookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE / 1000)}`;
}
function expiredCookie() { return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }
function safe(req: Request) { const origin = req.headers.get("origin"); return !origin || ORIGIN.test(origin); }
function otpOk(value: string) { return /^\d{6}$/.test(value); }
function recoveryCodeOk(value: string) { return /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{10}$/.test(value); }

function check(verifier: Verify | undefined, code: string) {
  const now = Date.now();
  if (!verifier) return { ok: false, error: "Request a new code, then try again." };
  resetExpiredLock(verifier);
  if (verifier.locked > now) return { ok: false, error: lockText() };
  if (verifier.used || verifier.expires < now) return { ok: false, error: "This code is no longer available. Request a new code and try again." };
  if (!equal(verifier.code, code)) {
    verifier.attempts++;
    if (verifier.attempts >= MAX) verifier.locked = now + LOCK;
    return { ok: false, error: verifier.locked > now ? lockText() : "That code does not match. Check the six digits and try again." };
  }
  verifier.used = true;
  return { ok: true, error: "" };
}

async function api(req: Request, path: string): Promise<Response> {
  if (!safe(req)) return reply(req, { error: "Request not allowed." }, 403);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: headers(req) });

  if (path === "/api/bootstrap" && req.method === "GET") {
    const pageToken = token();
    tickets.set(pageToken, Date.now() + 600_000);
    return reply(req, { csrf: pageToken, simulation: TEST_SIMULATION });
  }

  if (path === "/api/signin" && req.method === "POST") {
    const data = await body(req), pageToken = field(data, "csrf");
    const expires = tickets.get(pageToken);
    tickets.delete(pageToken);
    if (!expires || expires < Date.now()) return reply(req, { error: "Your page check expired. Refresh the page, then try again." }, 403);

    const email = field(data, "email", 120).toLowerCase(), password = field(data, "password");
    const account = accounts.get("acct-marcus")!;
    const failure = loginFailures.get(email);
    if (failure?.locked && failure.locked > Date.now()) return reply(req, { error: "We could not sign you in with those details. Check them and try again." }, 401);

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email !== account.email || password !== "BankPass1!") {
      const failed = failure || { attempts: 0, locked: 0 };
      failed.attempts++;
      if (failed.attempts >= MAX) { failed.attempts = 0; failed.locked = Date.now() + LOCK; }
      loginFailures.set(email, failed);
      return reply(req, { error: "We could not sign you in with those details. Check them and try again." }, 401);
    }

    loginFailures.delete(email);
    const id = token();
    const session: Session = { id, accountId: account.id, csrf: token(), created: Date.now(), seen: Date.now() };
    sessions.set(id, session);
    return reply(req, {
      csrf: session.csrf,
      step: account.identityVerified ? (account.mfaEnabled ? "settings" : "provision") : "identity"
    }, 200, { "Set-Cookie": cookie(id) });
  }

  const who = auth(req);
  if (!who) return reply(req, { error: "Your signed-in session ended. Please sign in again." }, 401);
  const { session, account } = who;
  const data = req.method === "POST" ? await body(req) : null;
  if (req.method === "POST" && !csrf(req, session, data)) {
    return reply(req, { error: "Your page check expired. Refresh the page, then try again." }, 403);
  }

  if (path === "/api/state" && req.method === "GET") {
    return reply(req, { csrf: session.csrf, email: account.email, identityVerified: account.identityVerified, mfaEnabled: account.mfaEnabled });
  }

  if (path === "/api/identity/request" && req.method === "POST") {
    if (account.identity?.locked > Date.now()) return reply(req, { error: lockText() }, 429);
    account.identity = verifyNew(account.identity);
    const out: Record<string, unknown> = { message: "A fresh verification code was sent." };
    if (TEST_SIMULATION) out.testValue = account.identity.code;
    return reply(req, out);
  }

  if (path === "/api/identity/verify" && req.method === "POST") {
    const code = field(data, "code", 6);
    if (!otpOk(code)) return reply(req, { error: "Enter six digits, for example 123456." }, 400);
    const result = check(account.identity, code);
    if (!result.ok) return reply(req, { error: result.error }, 400);
    account.identityVerified = true;
    return reply(req, { message: "Identity confirmed." });
  }

  if (path === "/api/provision" && req.method === "POST") {
    if (!account.identityVerified) return reply(req, { error: "Please confirm your identity before setting up an authenticator." }, 403);
    if (account.auth?.locked > Date.now()) return reply(req, { error: authLockText() }, 429);

    /* Preserve authenticator setup attempts when a user provisions a new key. */
    resetExpiredLock(account.auth);
    const previous = account.auth;
    const secret = setupSecret();
    account.pending = await crypt(secret);
    account.auth = {
      code: "", expires: 0, used: false,
      attempts: previous?.attempts || 0,
      locked: previous?.locked || 0
    };

    const label = encodeURIComponent(`Safe Bank:${account.email}`);
    const uri = `otpauth://totp/${label}?secret=${secret}&issuer=Safe%20Bank&period=30`;
    const out: Record<string, unknown> = { secret, uri, email: account.email };
    if (TEST_SIMULATION) out.testValue = await totp(secret, Math.floor(Date.now() / 1000 / PERIOD));
    return reply(req, out);
  }

  if (path === "/api/authenticator/verify" && req.method === "POST") {
    const code = field(data, "code", 6);
    if (!otpOk(code)) return reply(req, { error: "Enter six digits from your authenticator, for example 123456." }, 400);
    if (!account.pending) return reply(req, { error: "Start authenticator setup again, then enter a code." }, 400);

    resetExpiredLock(account.auth);
    if (account.auth?.locked && account.auth.locked > Date.now()) return reply(req, { error: authLockText() }, 429);

    const secret = await decrypt(account.pending);
    const counter = Math.floor(Date.now() / 1000 / PERIOD);
    const valid = await Promise.all([totp(secret, counter - 1), totp(secret, counter), totp(secret, counter + 1)]);
    if (!valid.some(v => equal(v, code))) {
      const verifier = account.auth!;
      verifier.attempts++;
      if (verifier.attempts >= MAX) verifier.locked = Date.now() + LOCK;
      return reply(req, {
        error: verifier.locked > Date.now()
          ? authLockText()
          : "That code does not match this setup. Check your authenticator and try again."
      }, 400);
    }

    account.secret = account.pending;
    delete account.pending;
    account.mfaEnabled = true;
    const backups = await makeBackups();
    account.backups = backups.stored;
    account.recoveryAttempts = 0;
    account.recoveryLocked = 0;
    const out: Record<string, unknown> = { message: "Authenticator confirmed.", codes: backups.plain };
    if (TEST_SIMULATION) out.testValues = backups.plain;
    return reply(req, out);
  }

  if (path === "/api/recovery/verify" && req.method === "POST") {
    const code = field(data, "code", 10).replace(/[\s-]/g, "").toUpperCase();
    if (!recoveryCodeOk(code)) return reply(req, { error: "Enter one 10-character recovery code, for example AB23CD45EF." }, 400);
    if (account.recoveryLocked > Date.now()) return reply(req, { error: recoveryLockText() }, 429);

    let found = false;
    for (const item of account.backups) {
      if (!item.used && equal(await recoveryHash(code, item.salt), item.hash)) {
        item.used = true;
        found = true;
        break;
      }
    }
    if (!found) {
      account.recoveryAttempts++;
      if (account.recoveryAttempts >= MAX) {
        account.recoveryAttempts = 0;
        account.recoveryLocked = Date.now() + LOCK;
      }
      return reply(req, {
        error: account.recoveryLocked > Date.now()
          ? recoveryLockText()
          : "That recovery code is not available. Check it or use a different unused code."
      }, 400);
    }
    account.recoveryAttempts = 0;
    return reply(req, { message: "Recovery code checked. It has now been used." });
  }

  if (path === "/api/recovery/regenerate" && req.method === "POST") {
    if (!account.mfaEnabled) return reply(req, { error: "Set up an authenticator before making recovery codes." }, 403);
    const backups = await makeBackups();
    account.backups = backups.stored;
    account.recoveryAttempts = 0;
    account.recoveryLocked = 0;
    const out: Record<string, unknown> = {
      message: "New recovery codes are ready. Your old codes no longer work.",
      codes: backups.plain
    };
    if (TEST_SIMULATION) out.testValues = backups.plain;
    return reply(req, out);
  }

  if (path === "/api/logout" && req.method === "POST") {
    sessions.delete(session.id);
    return reply(req, { message: "You have signed out." }, 200, { "Set-Cookie": expiredCookie() });
  }

  return reply(req, { error: "That page is not available." }, 404);
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Safe Bank MFA</title>
<style nonce="${nonce}">
:root{color-scheme:light;--ink:#172638;--blue:#075bb8;--pale:#edf6ff;--line:#b9c9d8;--bad:#a91d2f;--good:#086b43}
*{box-sizing:border-box}
body{margin:0;background:#f4f7fa;color:var(--ink);font-family:Arial,"Trebuchet MS",sans-serif;font-size:17px;line-height:1.65;letter-spacing:.025em}
.shell{width:min(100%,620px);margin:auto;min-height:100vh;background:#fff;padding:22px 20px 45px}
header{border-bottom:3px solid var(--blue);margin-bottom:25px}
h1{font-size:1.55rem;line-height:1.25;margin:0 0 14px}
h2{font-size:1.38rem;line-height:1.3;margin:0 0 12px}
.brand{color:var(--blue);font-weight:bold;margin:0}
.card{border:1px solid var(--line);border-radius:12px;padding:20px;margin:18px 0;background:#fff}
.hint{background:var(--pale);border-left:5px solid var(--blue);padding:12px 14px;margin:16px 0}
.message{padding:12px 14px;border-radius:9px;margin:15px 0;font-weight:bold}
.message.error{background:#fff0f1;color:var(--bad)}
.message.good{background:#e9f8ef;color:var(--good)}
label{display:block;font-weight:bold;margin:17px 0 6px}
input{width:100%;font:inherit;letter-spacing:.07em;padding:13px;border:2px solid #71859a;border-radius:8px;color:var(--ink)}
input:focus{outline:3px solid #85c5ff;outline-offset:2px}
button{font:inherit;font-weight:bold;letter-spacing:.02em;padding:13px 16px;border:2px solid var(--blue);border-radius:8px;background:var(--blue);color:#fff;cursor:pointer;margin:12px 0;width:100%;min-height:52px}
button.secondary{background:#fff;color:var(--blue)}
.code{font-family:monospace;letter-spacing:.13em;word-break:break-all;background:#f3f6f8;padding:12px;border-radius:7px}
.codes{list-style:none;padding:0;margin:12px 0}
.codes li{font-family:monospace;font-size:1.12rem;letter-spacing:.12em;padding:8px;border-bottom:1px solid var(--line)}
details{margin:17px 0}
summary{font-weight:bold;color:var(--blue);cursor:pointer}
.log{background:#101c29;color:#e8f4ff;border-radius:9px;padding:12px;min-height:80px;white-space:pre-wrap;word-break:break-word;font:13px/1.5 monospace}
.qr-wrap{display:inline-block;background:#fff;padding:12px;border:1px solid var(--line);border-radius:8px}
.qr{display:block;width:min(100%,315px);height:auto;image-rendering:pixelated}
.quiet{color:#486071;font-size:.94rem}
@media(max-width:380px){.shell{padding:16px 14px}.card{padding:16px}body{font-size:16px}}
</style>
</head>
<body>
<main class="shell">
<header><p class="brand">🔐 Safe Bank</p><h1>Multi-factor authentication</h1></header>
<section id="app" aria-live="polite"></section>
<section class="card"><details><summary>Help with this page</summary><p>Take your time. There is no reading timer. You can retry, request a new code, or copy a code when you need to.</p></details></section>
<section class="card"><details><summary>Logs for this practice app</summary><pre id="logs" class="log">Ready.</pre></details></section>
</main>
<script nonce="${nonce}">
(()=>{"use strict";
const app=document.getElementById("app"),logs=document.getElementById("logs");
let csrf="",simulation=false,shownCodes=[],setup={secret:"",uri:""};

const log=m=>{logs.textContent+="\\n"+m;console.log(m)};
const el=(tag,text)=>{const x=document.createElement(tag);if(text!==undefined)x.textContent=text;return x};
async function api(path,data,method="POST"){
  try{
    const r=await fetch(path,{method,credentials:"same-origin",
      headers:method==="POST"?{"Content-Type":"application/json","X-CSRF-Token":csrf}:undefined,
      body:method==="POST"?JSON.stringify(data||{}):undefined});
    const j=await r.json();
    if(r.status===401){csrf="";showSign(j.error)}
    return j;
  }catch{return{error:"Something went wrong. Please try again."}}
}
function clear(){app.replaceChildren()}
function note(text,bad=false){const x=el("p",text);x.className="message "+(bad?"error":"good");app.append(x)}
function button(text,fn,secondary=false){const b=el("button",text);if(secondary)b.className="secondary";b.onclick=fn;return b}
function input(label,type,example,autocomplete){
  const l=el("label",label),i=document.createElement("input");
  i.type=type;i.autocomplete=autocomplete||"off";i.placeholder=example;i.setAttribute("aria-label",label);
  app.append(l,i);return i;
}
function step(n,title,text){clear();app.append(el("p","Step "+n),el("h2",title),el("p",text))}
function copy(value,label){
  navigator.clipboard?.writeText(value).then(()=>note(label+" copied."))
    .catch(()=>note("Copy is not available here. You can select the text instead.",true));
}

/* Valid QR Code, Version 7-L, byte mode. It encodes the exact otpauth URI. */
function qrCanvas(text){
  const version=7,size=45,dataCapacity=156,ecLength=20,blocks=2;
  const source=new TextEncoder().encode(text);
  if(source.length>154)throw new Error("Setup link is too long.");
  const bits=[];
  const push=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>>i)&1)};
  push(4,4);push(source.length,8);for(const b of source)push(b,8);
  push(0,Math.min(4,dataCapacity*8-bits.length));
  while(bits.length%8)bits.push(0);
  const data=[];
  for(let i=0;i<bits.length;i+=8)data.push(bits.slice(i,i+8).reduce((a,b)=>a*2+b,0));
  for(let pad=0;data.length<dataCapacity;pad++)data.push(pad%2?0x11:0xec);

  const exp=new Array(512),logt=new Array(256);let x=1;
  for(let i=0;i<255;i++){exp[i]=x;logt[x]=i;x<<=1;if(x&256)x^=0x11d}
  for(let i=255;i<512;i++)exp[i]=exp[i-255];
  const mul=(a,b)=>a&&b?exp[logt[a]+logt[b]]:0;
  let divisor=[1];
  for(let i=0;i<ecLength;i++){
    const next=new Array(divisor.length+1).fill(0);
    for(let j=0;j<divisor.length;j++){next[j]^=divisor[j];next[j+1]^=mul(divisor[j],exp[i])}
    divisor=next;
  }
  const remainder=part=>{
    const rem=new Array(ecLength).fill(0);
    for(const value of part){
      const factor=value^rem.shift();rem.push(0);
      for(let j=0;j<ecLength;j++)rem[j]^=mul(divisor[j+1],factor);
    }
    return rem;
  };
  const chunks=[data.slice(0,78),data.slice(78,156)], ecc=chunks.map(remainder),words=[];
  for(let i=0;i<78;i++)for(const chunk of chunks)words.push(chunk[i]);
  for(let i=0;i<ecLength;i++)for(const part of ecc)words.push(part[i]);

  const matrix=Array.from({length:size},()=>Array(size));
  const set=(r,c,v)=>{if(r>=0&&c>=0&&r<size&&c<size)matrix[r][c]=v};
  const finder=(r,c)=>{
    for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++){
      const border=y>=0&&y<=6&&z>=0&&z<=6;
      set(r+y,c+z,border&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4)));
    }
  };
  finder(0,0);finder(0,size-7);finder(size-7,0);
  const centers=[6,22,38];
  for(const r of centers)for(const c of centers){
    if(matrix[r][c]!==undefined)continue;
    for(let y=-2;y<=2;y++)for(let z=-2;z<=2)set(r+y,c+z,Math.max(Math.abs(y),Math.abs(z))!==1);
  }
  for(let i=8;i<size-8;i++){if(matrix[6][i]===undefined)set(6,i,i%2===0);if(matrix[i][6]===undefined)set(i,6,i%2===0)}
  for(let i=0;i<6;i++){set(i,8,false);set(8,i,false)}
  set(7,8,false);set(8,7,false);set(8,8,false);
  for(let i=0;i<7;i++){set(size-1-i,8,false);set(8,size-1-i,false)}
  for(let i=0;i<6;i++)for(let j=0;j<3;j++){set(i,size-11+j,false);set(size-11+j,i,false)}
  set(size-8,8,true);

  let bit=0,up=true;
  for(let right=size-1;right>0;right-=2){
    if(right===6)right--;
    for(let n=0;n<size;n++){
      const r=up?size-1-n:n;
      for(let c=right;c>=right-1;c--)if(matrix[r][c]===undefined){
        const value=bit<words.length*8?((words[bit>>>3]>>>(7-(bit&7)))&1):0;
        matrix[r][c]=Boolean(value^((r+c)%2===0));bit++;
      }
    }
    up=!up;
  }
  const bch=(value,poly)=>{
    let v=value;
    const degree=n=>32-Math.clz32(n);
    while(degree(v)>=degree(poly))v^=poly<<(degree(v)-degree(poly));
    return v;
  };
  const format=((8<<10)|bch(8<<10,0x537))^0x5412;
  const fbit=i=>Boolean((format>>>i)&1);
  for(let i=0;i<=5;i++)set(i,8,fbit(i));
  set(7,8,fbit(6));set(8,8,fbit(7));set(8,7,fbit(8));
  for(let i=9;i<15;i++)set(8,14-i,fbit(i));
  for(let i=0;i<8;i++)set(8,size-1-i,fbit(i));
  for(let i=8;i<15;i++)set(size-15+i,8,fbit(i));
  const vbits=(version<<12)|bch(version<<12,0x1f25);
  for(let i=0;i<18;i++){const v=Boolean((vbits>>>i)&1);set(Math.floor(i/3),size-11+i%3,v);set(size-11+i%3,Math.floor(i/3),v)}

  const canvas=document.createElement("canvas"),scale=7;
  canvas.width=canvas.height=size*scale;canvas.className="qr";
  canvas.setAttribute("role","img");canvas.setAttribute("aria-label","Scan this QR code with your authenticator app.");
  const ctx=canvas.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle="#000";
  for(let r=0;r<size;r++)for(let c=0;c<size;c++)if(matrix[r][c])ctx.fillRect(c*scale,r*scale,scale,scale);
  return canvas;
}

async function boot(){
  const j=await api("/api/bootstrap",null,"GET");
  csrf=j.csrf||"";simulation=!!j.simulation;showSign();
}
function showSign(error){
  clear();
  app.append(el("p","Step 1 of 6"),el("h2","Sign in"),el("p","Use the practice account to begin."));
  if(error)note(error,true);
  const email=input("Email address","email","marcus@example.com","email");
  const pass=input("Password","password","Example: BankPass1!","current-password");
  email.value="marcus@example.com";
  const b=button("Sign in",async()=>{
    const j=await api("/api/signin",{email:email.value,password:pass.value,csrf});
    if(j.error)return note(j.error,true);
    csrf=j.csrf;route(j.step);
  });
  app.append(el("p","Practice password: BankPass1!"),b);
}
function route(s){if(s==="identity")showIdentity();else if(s==="provision")showProvision();else showSettings()}
function showIdentity(){
  step("2 of 6","Confirm it is you","We will send one six-digit identity code. Example: 123456.");
  const request=button("Send identity code",async()=>{
    const j=await api("/api/identity/request",{});
    if(j.error)return note(j.error,true);
    note(j.message);
    if(simulation&&j.testValue)log("TEST SIMULATION identity code: "+j.testValue);
    request.remove();
    const code=input("Identity code","text","123456","one-time-code");code.inputMode="numeric";
    app.append(button("Confirm identity",async()=>{
      const x=await api("/api/identity/verify",{code:code.value});
      if(x.error)return note(x.error,true);
      showIdentitySuccess();
    }),button("Send a new code",showIdentity,true));
  });
  app.append(request);
}
function showIdentitySuccess(){
  step("2 of 6","Identity confirmed","Your identity has been confirmed. You can continue when you are ready.");
  note("Identity confirmed.");
  app.append(button("Continue",showProvision));
}
async function showProvision(){
  step("3 of 6","Set up your authenticator","Open your authenticator app. Scan the setup image, or use the manual key below.");
  const j=await api("/api/provision",{});
  if(j.error)return note(j.error,true);
  setup=j;
  try{
    const wrap=el("div");wrap.className="qr-wrap";wrap.append(qrCanvas(setup.uri));app.append(wrap);
  }catch{note("The setup image could not be made. Use the manual key below.",true)}
  if(simulation&&j.testValue)log("TEST SIMULATION authenticator code: "+j.testValue);
  app.append(el("p","Manual setup key:"));
  const key=el("p",setup.secret);key.className="code";
  app.append(key,button("Copy manual key",()=>copy(setup.secret,"Manual key"),true));
  const uri=el("p",setup.uri);uri.className="code";
  app.append(el("p","Setup link:"),uri,button("Copy setup link",()=>copy(setup.uri,"Setup link"),true));
  app.append(el("p","Then enter the current six-digit code from your authenticator. Example: 123456."));
  const code=input("Authenticator code","text","123456","one-time-code");code.inputMode="numeric";
  app.append(button("Confirm authenticator",async()=>{
    const x=await api("/api/authenticator/verify",{code:code.value});
    if(x.error)return note(x.error,true);
    shownCodes=x.codes||[];
    if(simulation&&x.testValues)log("TEST SIMULATION recovery codes: "+x.testValues.join(", "));
    showRecoveryDisplay("Authenticator confirmed. Save your recovery codes now.");
  }),button("Make a different setup key",showProvision,true));
}
function showRecoveryDisplay(message){
  step("4 of 6","Save recovery codes","Each code works once. Store them somewhere safe. You do not need to memorise them.");
  note(message);
  const list=el("ul");list.className="codes";
  shownCodes.forEach(c=>list.append(el("li",c)));
  app.append(list,button("Copy all recovery codes",()=>copy(shownCodes.join("\\n"),"Recovery codes"),true));
  app.append(button("I have saved my codes",showRecoveryVerify));
}
function showRecoveryVerify(){
  step("5 of 6","Check one recovery code","Enter one code you saved. Example: AB23CD45EF. This check uses that code once.");
  const code=input("Recovery code","text","AB23CD45EF","one-time-code");
  app.append(button("Check recovery code",async()=>{
    const j=await api("/api/recovery/verify",{code:code.value});
    if(j.error)return note(j.error,true);
    showSettings(j.message);
  }),button("Show recovery codes again",()=>showRecoveryDisplay("Here are your saved codes."),true));
}
async function showSettings(message){
  step("6 of 6","MFA is ready","Your authenticator is active for this account.");
  if(message)note(message);
  app.append(el("p","You can make a new set of recovery codes if needed. New codes replace the old ones."));
  app.append(button("Make new recovery codes",async()=>{
    const j=await api("/api/recovery/regenerate",{});
    if(j.error)return note(j.error,true);
    shownCodes=j.codes||[];
    if(simulation&&j.testValues)log("TEST SIMULATION recovery codes: "+j.testValues.join(", "));
    showRecoveryDisplay(j.message);
  }),button("Sign out",async()=>{
    const j=await api("/api/logout",{});
    log(j.message||"Signed out.");csrf="";showSign();
  },true));
}
boot();
})();
</script>
</body>
</html>`;
}

serve({
  port: Number(process.env.PORT || 3000),
  tls: { cert, key },
  async fetch(req) {
    try {
      const url = new URL(req.url);
      if (url.pathname.startsWith("/api/")) return await api(req, url.pathname);
      if (url.pathname === "/" && req.method === "GET") {
        const nonce = token(18), h = headers(req, nonce);
        h.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers: h });
      }
      return new Response("Not found.", { status: 404, headers: headers(req) });
    } catch {
      return new Response("Something went wrong. Please try again.", { status: 500, headers: headers(req) });
    }
  }
});
console.log("Safe Bank MFA running over HTTPS.");
