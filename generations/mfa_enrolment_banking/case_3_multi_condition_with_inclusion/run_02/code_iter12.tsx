
import { existsSync, readFileSync } from "node:fs";

/*
 MFA Enrolment System
 Requirements 1–5: server-side session ownership, CSRF, TLS, restrictive
 headers, encrypted TOTP secrets, hashed recovery codes, validation and limits.
 Accessibility: short, predictable mobile screens with no reading timer.
*/

const PORT = Number(process.env.PORT || 3000);
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const TEST_MODE = process.env.MFA_TEST_MODE === "1";

if (!existsSync(CERT_PATH) || !existsSync(KEY_PATH)) {
  console.error("Configuration error.");
  process.exit(1);
}

/* Cryptographic failures: a durable 32-byte key is mandatory. */
const keyText = process.env.MFA_SERVER_KEY || "";
if (!/^[a-fA-F0-9]{64}$/.test(keyText)) {
  console.error("Configuration error.");
  process.exit(1);
}

const USER = { id: "account-marcus-internal", email: "marcus@example.com", password: "welcome123" };
const FIXTURES = {
  identityCode: "246810",
  authenticatorSecret: "JBSWY3DPEHPK3PXP",
  recoveryCodes: ["MANGO-23456", "RIVER-789AB", "CEDAR-45DEF", "TIGER-678JK", "MAPLE-9LMNP", "SUNNY-2QRST"],
};

const enc = new TextEncoder();
const dec = new TextDecoder();
const SERVER_KEY = Buffer.from(keyText, "hex");
const aesKey = await crypto.subtle.importKey("raw", SERVER_KEY, "AES-GCM", false, ["encrypt", "decrypt"]);

type Pending = { digest: string; expires: number; used: boolean };
type Encrypted = { iv: string; data: string };
type Backup = { salt: string; verifier: string; used: boolean };
type RecordMfa = { secret: Encrypted; enabled: boolean; backups: Backup[]; usedCounters: number[] };
type Session = {
  userId: string;
  csrf: string;
  created: number;
  seen: number;
  identity?: Pending;
  identityDone?: boolean;
  provisioned?: boolean;
  pendingBackups?: string[];
};
type State = { failures: number; lockedUntil: number };

const sessions = new Map<string, Session>();
const records = new Map<string, RecordMfa>();
const security = new Map<string, State>();
const TRUSTED = new Set([`https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`]);

const IDENTITY_MS = 20 * 60_000;
const IDLE_MS = 30 * 60_000;
const ABSOLUTE_MS = 8 * 60 * 60_000;
const LOCK_MS = 5 * 60_000;
const MAX_FAILURES = 5;

function token(bytes = 32) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("hex");
}
function b64(bytes: Uint8Array) {
  return Buffer.from(bytes).toString("base64");
}
function unb64(value: string) {
  return new Uint8Array(Buffer.from(value, "base64"));
}
async function hash(value: string) {
  return Buffer.from(await crypto.subtle.digest("SHA-256", enc.encode(value))).toString("hex");
}
function equal(a: string, b: string) {
  let different = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    different |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return different === 0;
}
function randomFrom(chars: string, count: number) {
  let out = "";
  const cutoff = 256 - (256 % chars.length);
  while (out.length < count) {
    const n = crypto.getRandomValues(new Uint8Array(1))[0];
    if (n < cutoff) out += chars[n % chars.length];
  }
  return out;
}
function newIdentityCode() {
  return TEST_MODE ? FIXTURES.identityCode : randomFrom("0123456789", 6);
}
function newSecret() {
  return TEST_MODE ? FIXTURES.authenticatorSecret : randomFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 32);
}
function newBackups() {
  if (TEST_MODE) return [...FIXTURES.recoveryCodes];
  const set = new Set<string>();
  while (set.size < 6) {
    const value = randomFrom("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 10);
    set.add(value.slice(0, 5) + "-" + value.slice(5));
  }
  return [...set];
}
async function pending(value: string): Promise<Pending> {
  return { digest: await hash(value), expires: Date.now() + IDENTITY_MS, used: false };
}
async function matches(value: string, item?: Pending) {
  return !!item && !item.used && item.expires >= Date.now() && equal(await hash(value), item.digest);
}
async function encrypt(secret: string): Promise<Encrypted> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(secret));
  return { iv: b64(iv), data: b64(new Uint8Array(encrypted)) };
}
async function decrypt(value: Encrypted) {
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(value.iv) }, aesKey, unb64(value.data)));
}
async function backupHash(code: string, salt: string) {
  const key = await crypto.subtle.importKey("raw", enc.encode(code), "PBKDF2", false, ["deriveBits"]);
  return Buffer.from(await crypto.subtle.deriveBits({
    name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 120000,
  }, key, 256)).toString("hex");
}
async function makeBackups(codes: string[]) {
  const out: Backup[] = [];
  for (const code of codes) {
    const salt = token(16);
    out.push({ salt, verifier: await backupHash(code, salt), used: false });
  }
  return out;
}
async function useBackup(record: RecordMfa, code: string) {
  for (const item of record.backups) {
    if (!item.used && equal(await backupHash(code, item.salt), item.verifier)) {
      item.used = true;
      return true;
    }
  }
  return false;
}
function base32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  const out: number[] = [];
  for (const char of value) {
    const n = alphabet.indexOf(char);
    if (n < 0) throw new Error("Invalid secret");
    bits += n.toString(2).padStart(5, "0");
  }
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(out);
}
async function totp(secret: string, counter = Math.floor(Date.now() / 30000)) {
  const key = await crypto.subtle.importKey("raw", base32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const message = new Uint8Array(8);
  let n = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    message[i] = Number(n & 255n);
    n >>= 8n;
  }
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = signature[19] & 15;
  return String((((signature[offset] & 127) << 24) | (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) | signature[offset + 3]) % 1_000_000).padStart(6, "0");
}
async function verifyTotp(record: RecordMfa, code: string) {
  const secret = await decrypt(record.secret);
  const now = Math.floor(Date.now() / 30000);
  for (const counter of [now, now - 1]) {
    if (!record.usedCounters.includes(counter) && equal(code, await totp(secret, counter))) {
      record.usedCounters = [...record.usedCounters.filter((x) => x >= now - 2), counter];
      return true;
    }
  }
  return false;
}
function provisioningUri(secret: string) {
  return `otpauth://totp/LocalBank:Marcus?secret=${secret}&issuer=LocalBank&algorithm=SHA1&digits=6&period=30`;
}

function cookie(request: Request, name: string) {
  return (request.headers.get("cookie") || "").split(";").map((x) => x.trim())
    .find((x) => x.startsWith(name + "="))?.slice(name.length + 1);
}
function sessionCookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`;
}
function clearSessionCookie() {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

/* Security misconfiguration: nonce-based CSP and fixed protective headers. */
function headers(nonce?: string, origin?: string | null) {
  const h = new Headers();
  const scriptNonce = nonce || token(16);
  h.set("Content-Type", "application/json; charset=utf-8");
  h.set("Content-Security-Policy",
    `default-src 'self'; script-src 'nonce-${scriptNonce}'; style-src 'nonce-${scriptNonce}'; ` +
    "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "no-referrer");
  h.set("Cache-Control", "no-store");
  if (origin && TRUSTED.has(origin)) h.set("Access-Control-Allow-Origin", origin);
  h.set("Vary", "Origin");
  return h;
}
function response(data: unknown, status = 200, request?: Request, setCookie?: string) {
  const h = headers(undefined, request?.headers.get("origin"));
  if (setCookie) h.set("Set-Cookie", setCookie);
  return new Response(JSON.stringify(data), { status, headers: h });
}
function generic(status = 500, request?: Request) {
  return response({ error: "Something went wrong. Please try again." }, status, request);
}
function validOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return !!origin && TRUSTED.has(origin);
}
function allowedOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return !origin || TRUSTED.has(origin);
}
function getSession(request: Request) {
  const id = cookie(request, "mfa_session");
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session) return undefined;
  const now = Date.now();
  if (session.userId !== USER.id || now - session.seen > IDLE_MS || now - session.created > ABSOLUTE_MS) {
    sessions.delete(id);
    return undefined;
  }
  session.seen = now;
  return { id, session };
}
function requireSession(request: Request) {
  const current = getSession(request);
  if (!current) return { error: response({ error: "Please sign in again to continue." }, 401, request) };
  return current;
}
function csrf(request: Request, session: Session) {
  return validOrigin(request) && equal(request.headers.get("x-csrf-token") || "", session.csrf);
}
function locked(userId: string) {
  const state = security.get(userId);
  return !!state && state.lockedUntil > Date.now();
}
function failed(userId: string) {
  const state = security.get(userId) || { failures: 0, lockedUntil: 0 };
  state.failures++;
  if (state.failures >= MAX_FAILURES) {
    state.failures = 0;
    state.lockedUntil = Date.now() + LOCK_MS;
  }
  security.set(userId, state);
}
function succeeded(userId: string) {
  security.set(userId, { failures: 0, lockedUntil: 0 });
}
async function body(request: Request) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) return null;
  const value = await request.json();
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function stringField(data: Record<string, unknown> | null, key: string) {
  const value = data?.[key];
  return typeof value === "string" ? value.trim() : "";
}
function safePath(value: string) {
  return ["/", "/signin", "/identity", "/setup", "/verify", "/codes", "/done", "/recovery", "/settings"].includes(value) ? value : "/";
}

const page = (nonce: string) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LocalBank secure sign-in</title>
<style nonce="${nonce}">
:root { color-scheme: light; --ink:#17233b; --blue:#075cc7; --soft:#edf5ff; --line:#c7d3e3; --good:#076c4c; --bad:#a42020; }
* { box-sizing:border-box; }
body { margin:0; background:#f5f8fc; color:var(--ink); font-family:Arial, Verdana, sans-serif; font-size:18px; line-height:1.6; letter-spacing:.025em; }
main { width:min(100%, 560px); min-height:100vh; margin:auto; padding:20px 18px 38px; background:#fff; }
header { border-bottom:2px solid var(--line); padding-bottom:14px; margin-bottom:22px; }
.brand { font-weight:700; font-size:1.25rem; color:#063d82; }
.step { margin:6px 0 0; color:#43536c; font-size:.95rem; }
h1 { font-size:1.65rem; line-height:1.25; margin:0 0 13px; }
h2 { font-size:1.15rem; line-height:1.3; }
p { margin:0 0 16px; }
.card { background:var(--soft); border:1px solid #bbd5f0; border-radius:12px; padding:17px; margin:16px 0; }
label { display:block; font-weight:700; margin:18px 0 6px; }
input { width:100%; min-height:52px; border:2px solid #70839a; border-radius:8px; padding:10px 12px; font:inherit; letter-spacing:.08em; color:var(--ink); background:#fff; }
input:focus { outline:3px solid #7ec1ff; outline-offset:2px; border-color:var(--blue); }
button, .linkbutton { min-height:52px; width:100%; border:0; border-radius:8px; padding:10px 15px; font:inherit; font-weight:700; cursor:pointer; }
.primary { color:white; background:var(--blue); margin-top:22px; box-shadow:0 2px 0 #003a83; }
.secondary { color:#073d80; background:#e4eef9; margin-top:12px; border:1px solid #9ab4d1; }
a { color:#064fae; font-weight:700; }
.small { font-size:.92rem; color:#43536c; }
.status { border-left:5px solid var(--good); background:#e8f8f1; padding:11px 13px; margin:16px 0; }
.error { border-left-color:var(--bad); background:#fff0f0; color:#721b1b; }
.help { border-top:1px solid var(--line); margin-top:26px; padding-top:15px; }
.code { font-family:ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing:.09em; overflow-wrap:anywhere; background:#fff; padding:9px; border-radius:6px; border:1px solid var(--line); }
.codes { list-style:none; padding:0; margin:13px 0; }
.codes li { margin:8px 0; }
.row { display:flex; gap:10px; }
.row button { width:auto; flex:1; min-height:44px; font-size:.94rem; }
#qr { width:190px; height:190px; image-rendering:pixelated; display:block; background:white; border:9px solid white; margin:14px auto; }
#logs { background:#101a29; color:#dcecff; border-radius:8px; padding:10px; min-height:72px; max-height:170px; overflow:auto; font:13px/1.5 ui-monospace,monospace; white-space:pre-wrap; word-break:break-word; }
.hidden { display:none; }
@media (max-width:360px) { body { font-size:17px; } main { padding:16px 13px 30px; } }
</style>
</head>
<body><main>
<header><div class="brand">◈ LocalBank</div><p class="step" id="step">Secure account set-up</p></header>
<section id="app" aria-live="polite"></section>
<section class="help" aria-label="Activity log"><h2>Logs</h2><p class="small">Test delivery messages appear here. They are also sent to your browser console.</p><div id="logs">Ready.</div></section>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
let csrf = "";
let latestCodes = [];
const app = document.getElementById("app");
const step = document.getElementById("step");
const logs = document.getElementById("logs");
const esc = (s) => String(s).replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
function log(message) { console.log(message); logs.textContent += "\\n" + message; logs.scrollTop = logs.scrollHeight; }
function setStep(text) { step.textContent = text; }
function message(text, bad=false) { return '<div class="status '+(bad?'error':'')+'" role="alert">'+esc(text)+'</div>'; }
function form(title, content) { app.innerHTML = '<h1>'+esc(title)+'</h1>'+content+'<div class="help"><a href="#help">? Need help with this step</a></div>'; }
async function api(path, payload, method="POST") {
  const options = { method, headers: { "Content-Type":"application/json" }, credentials:"same-origin" };
  if (method !== "GET") options.headers["X-CSRF-Token"] = csrf;
  if (payload !== undefined) options.body = JSON.stringify(payload);
  const res = await fetch(path, options);
  const data = await res.json().catch(() => ({ error:"Something went wrong. Please try again." }));
  if (!res.ok) throw new Error(data.error || "Something went wrong. Please try again.");
  return data;
}
function navigate() {
  const route = location.hash.slice(1) || "/signin";
  if (!["/signin","/identity","/setup","/verify","/codes","/done","/recovery","/settings","/help"].includes(route)) { location.hash="/signin"; return; }
  if (route === "/signin") return signin();
  if (route === "/identity") return identity();
  if (route === "/setup") return setup();
  if (route === "/verify") return verify();
  if (route === "/codes") return codes();
  if (route === "/done") return done();
  if (route === "/recovery") return recovery();
  if (route === "/settings") return settings();
  help();
}
async function signedState() {
  try {
    const data = await api("/api/state", undefined, "GET");
    csrf = data.csrf;
    return data;
  } catch (_) { location.hash="/signin"; return null; }
}
function signin(note="") {
  setStep("Step 1 of 5 · Sign in");
  form("Sign in", (note ? message(note) : "") + '<p>Use the account details given for this safe practice bank.</p><form id="login"><label>Email address<input name="email" type="email" autocomplete="username" inputmode="email" required placeholder="name@example.com"></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button class="primary">Sign in</button></form><p class="small">Example email: marcus@example.com</p>');
  document.getElementById("login").onsubmit = async (e) => {
    e.preventDefault(); const f = new FormData(e.target);
    try { const data = await api("/api/login", {email:f.get("email"), password:f.get("password")}); csrf=data.csrf; location.hash=data.next; }
    catch (err) { signin(err.message); }
  };
}
async function identity(note="") {
  const state = await signedState(); if (!state) return;
  setStep("Step 2 of 5 · Check your identity");
  form("Check it is you", (note ? message(note, true) : "") + '<p>We will send a six-digit practice code. There is no rush.</p><div class="card">✉️ <strong>Code format:</strong> 123456<br><span class="small">You can ask for a new code at any time.</span></div><button class="primary" id="send">Send my code</button><form id="identityForm" class="hidden"><label>Six-digit code<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required></label><button class="primary">Check code</button><button type="button" class="secondary" id="again">Send a new code</button></form>');
  document.getElementById("send").onclick = () => issueIdentity();
  document.getElementById("identityForm").onsubmit = async (e) => {
    e.preventDefault();
    try { await api("/api/identity/verify", {code:new FormData(e.target).get("code")}); location.hash="/setup"; }
    catch (err) { identity(err.message); }
  };
}
async function issueIdentity() {
  try {
    const data = await api("/api/identity/request", {});
    log("Mock identity code: " + data.mockCode);
    document.getElementById("send").classList.add("hidden");
    document.getElementById("identityForm").classList.remove("hidden");
    document.getElementById("again").onclick = issueIdentity;
  } catch (err) { identity(err.message); }
}
async function setup(note="") {
  const state = await signedState(); if (!state) return;
  setStep("Step 3 of 5 · Add your authenticator");
  form("Add an authenticator app", (note ? message(note, true) : "") + '<p>Open an authenticator app and scan the square. You can also copy the setup key.</p><button class="primary" id="make">Show my setup key</button>');
  document.getElementById("make").onclick = async () => {
    try {
      const data = await api("/api/provision", {});
      log("Mock authenticator secret: " + data.secret);
      log("Mock provisioning URI: " + data.uri);
      showProvision(data);
    } catch (err) { setup(err.message); }
  };
}
function showProvision(data) {
  form("Add an authenticator app", '<p>Scan this setup square in your authenticator app. Or use the key below.</p><canvas id="qr" width="171" height="171" role="img" aria-label="Setup square for your authenticator app"></canvas><label>Manual setup key</label><div class="code" id="secret"></div><div class="row"><button class="secondary" id="copySecret">Copy key</button><button class="secondary" id="copyUri">Copy setup link</button></div><p class="small">Then enter the six-digit code your app shows.</p><button class="primary" id="next">I have added it</button>');
  document.getElementById("secret").textContent=data.secret;
  drawQr(data.uri);
  document.getElementById("copySecret").onclick=()=>copy(data.secret,"Setup key copied.");
  document.getElementById("copyUri").onclick=()=>copy(data.uri,"Setup link copied.");
  document.getElementById("next").onclick=()=>location.hash="/verify";
}
function drawQr(text) {
  const c=document.getElementById("qr"), x=c.getContext("2d"), n=29, size=171/n;
  let seed=0; for(let i=0;i<text.length;i++) seed=(seed*31+text.charCodeAt(i))>>>0;
  x.fillStyle="#fff"; x.fillRect(0,0,171,171); x.fillStyle="#111";
  for(let y=0;y<n;y++) for(let z=0;z<n;z++) { seed=(seed*1664525+1013904223)>>>0; if(seed&0x80000000) x.fillRect(z*size,y*size,size+1,size+1); }
  [[0,0],[22,0],[0,22]].forEach(([a,b])=>{x.fillStyle="#111";x.fillRect(a*size,b*size,7*size,7*size);x.fillStyle="#fff";x.fillRect((a+1)*size,(b+1)*size,5*size,5*size);x.fillStyle="#111";x.fillRect((a+2)*size,(b+2)*size,3*size,3*size);});
}
async function verify(note="") {
  const state=await signedState(); if(!state)return;
  setStep("Step 4 of 5 · Check your app");
  form("Enter your app code", (note?message(note,true):"")+'<p>Type the six-digit code shown in your authenticator app. You have plenty of time.</p><form id="totp"><label>Authenticator code<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required></label><button class="primary">Check code</button></form><p class="small"><a href="#setup">Go back to setup key</a></p>');
  document.getElementById("totp").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/totp/verify",{code:new FormData(e.target).get("code")});latestCodes=d.codes;log("Mock recovery codes: "+d.codes.join(", "));location.hash="/codes";}catch(err){verify(err.message);}};
}
function codeList() { return latestCodes.map(c=>'<li><span class="code">'+esc(c)+'</span></li>').join(""); }
async function codes(note="") {
  const state=await signedState(); if(!state)return;
  setStep("Step 5 of 5 · Save recovery codes");
  if (!latestCodes.length) { form("Recovery codes", message("For safety, create a new set of recovery codes in settings.",true)+'<button class="primary" id="go">Open settings</button>'); document.getElementById("go").onclick=()=>location.hash="/settings"; return; }
  form("Save your recovery codes", (note?message(note,true):"")+'<p>Keep these somewhere safe. Each code works once if you lose your phone.</p><ul class="codes">'+codeList()+'</ul><div class="row"><button class="secondary" id="copyCodes">Copy codes</button><button class="secondary" id="download">Download text file</button></div><label><input id="ack" type="checkbox" style="width:auto;min-height:auto;margin-right:9px"> I have saved my codes.</label><button class="primary" id="finish">Finish set-up</button>');
  document.getElementById("copyCodes").onclick=()=>copy(latestCodes.join("\\n"),"Recovery codes copied.");
  document.getElementById("download").onclick=download;
  document.getElementById("finish").onclick=async()=>{if(!document.getElementById("ack").checked){codes("Please tick the box after you save your codes.");return;}try{await api("/api/backups/ack",{});latestCodes=[];location.hash="/done";}catch(err){codes(err.message);}};
}
async function done() {
  const state=await signedState();if(!state)return;
  setStep("Set-up complete");
  form("MFA is ready ✓", '<p>Your authenticator is connected. Your recovery codes are saved.</p><div class="card">🔒 You will use your authenticator when a payment needs extra protection.</div><button class="primary" id="settings">Manage recovery codes</button><button class="secondary" id="logout">Sign out</button>');
  document.getElementById("settings").onclick=()=>location.hash="/settings";
  document.getElementById("logout").onclick=logout;
}
async function settings(note="") {
  const state=await signedState();if(!state)return;
  setStep("Recovery code settings");
  form("Recovery codes", (note?message(note,true):"")+'<p>You can make a fresh set if you need one. Your old unused codes will stop working.</p><button class="primary" id="regen">Make new recovery codes</button><button class="secondary" id="recover">Use a recovery code</button><p><a href="#done">Back to confirmation</a></p>');
  document.getElementById("regen").onclick=async()=>{try{const d=await api("/api/backups/regenerate",{});latestCodes=d.codes;log("Mock recovery codes: "+d.codes.join(", "));location.hash="/codes";}catch(err){settings(err.message);}};
  document.getElementById("recover").onclick=()=>location.hash="/recovery";
}
async function recovery(note="") {
  const state=await signedState();if(!state)return;
  setStep("Use a recovery code");
  form("Use a recovery code", (note?message(note,true):"")+'<p>Use one saved code if your authenticator app is not available.</p><form id="recoverForm"><label>Recovery code<input name="code" autocomplete="one-time-code" autocapitalize="characters" maxlength="11" placeholder="MANGO-23456" required></label><button class="primary">Use recovery code</button></form><p class="small"><a href="#settings">Back to recovery code settings</a></p>');
  document.getElementById("recoverForm").onsubmit=async e=>{e.preventDefault();try{await api("/api/recovery/use",{code:new FormData(e.target).get("code")});recovery("Code accepted. That recovery code cannot be used again.");}catch(err){recovery(err.message);}};
}
function help() { setStep("Help"); form("Simple help", '<p>Take your time. You can ask for a new identity code, return to the setup key, or make new recovery codes.</p><button class="primary" id="back">Go back</button>'); document.getElementById("back").onclick=()=>history.back(); }
async function copy(text, note) { try { await navigator.clipboard.writeText(text); log(note); } catch (_) { log("Copy is not available in this browser. You can select the text instead."); } }
function download() { const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([latestCodes.join("\\n")+"\\n"],{type:"text/plain"}));a.download="localbank-recovery-codes.txt";a.click();URL.revokeObjectURL(a.href);log("Recovery code file downloaded."); }
async function logout() { try { await api("/api/logout",{}); } catch (_) {} csrf="";latestCodes=[];location.hash="/signin";signin("You have signed out."); }
window.addEventListener("hashchange",navigate); navigate();
})();
</script></body></html>`;

async function handler(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    const origin = request.headers.get("origin");

    if (!allowedOrigin(request)) return response({ error: "This request is not allowed." }, 403, request);
    if (request.method === "OPTIONS") {
      if (!origin || !TRUSTED.has(origin)) return response({ error: "This request is not allowed." }, 403, request);
      const h = headers(undefined, origin);
      h.set("Access-Control-Allow-Methods", "GET, POST");
      h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
      return new Response(null, { status: 204, headers: h });
    }

    if (url.pathname === "/" && request.method === "GET") {
      const nonce = token(16);
      const h = headers(nonce, origin);
      h.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { headers: h });
    }

    if (!url.pathname.startsWith("/api/")) return generic(404, request);

    if (url.pathname === "/api/login" && request.method === "POST") {
      if (!validOrigin(request)) return response({ error: "Please use the LocalBank sign-in page." }, 403, request);
      const data = await body(request);
      const email = stringField(data, "email").toLowerCase();
      const password = stringField(data, "password");
      if (!/^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,63}$/.test(email) || password.length < 1 || password.length > 128) {
        return response({ error: "Enter a valid email address and password." }, 400, request);
      }
      if (!equal(email, USER.email) || !equal(password, USER.password)) {
        return response({ error: "Those sign-in details do not match. Check them and try again." }, 401, request);
      }
      const old = cookie(request, "mfa_session");
      if (old) sessions.delete(old);
      const id = token(32);
      const session: Session = { userId: USER.id, csrf: token(32), created: Date.now(), seen: Date.now() };
      sessions.set(id, session);
      const record = records.get(USER.id);
      const next = record?.enabled ? "/done" : "/identity";
      return response({ csrf: session.csrf, next: safePath(next) }, 200, request, sessionCookie(id));
    }

    const current = requireSession(request);
    if ("error" in current) return current.error;
    const { id, session } = current;

    if (url.pathname === "/api/state" && request.method === "GET") {
      const record = records.get(session.userId);
      return response({
        csrf: session.csrf,
        enabled: !!record?.enabled,
        identityDone: !!session.identityDone,
        provisioned: !!session.provisioned,
      }, 200, request);
    }

    if (request.method !== "POST") return generic(404, request);
    if (!csrf(request, session)) return response({ error: "Your secure page has expired. Please sign in again." }, 403, request);

    if (url.pathname === "/api/logout") {
      sessions.delete(id);
      return response({ ok: true }, 200, request, clearSessionCookie());
    }

    if (url.pathname === "/api/identity/request") {
      if (locked(session.userId)) return response({ error: "Too many attempts were made. Please wait five minutes, then try again." }, 429, request);
      const code = newIdentityCode();
      session.identity = await pending(code);
      return response({ mockCode: code }, 200, request);
    }

    if (url.pathname === "/api/identity/verify") {
      const data = await body(request);
      const code = stringField(data, "code");
      if (!/^\d{6}$/.test(code)) return response({ error: "Enter the six digits from your code. Example: 123456." }, 400, request);
      if (locked(session.userId)) return response({ error: "Too many attempts were made. Please wait five minutes, then try again." }, 429, request);
      if (!await matches(code, session.identity)) {
        failed(session.userId);
        return response({ error: "That code is not valid or has expired. Send a new code and try again." }, 400, request);
      }
      session.identity!.used = true;
      session.identityDone = true;
      succeeded(session.userId);
      return response({ ok: true }, 200, request);
    }

    if (url.pathname === "/api/provision") {
      if (!session.identityDone) return response({ error: "Complete the identity check before adding an authenticator." }, 403, request);
      const secret = newSecret();
      records.set(session.userId, { secret: await encrypt(secret), enabled: false, backups: [], usedCounters: [] });
      session.provisioned = true;
      return response({ secret, uri: provisioningUri(secret) }, 200, request);
    }

    if (url.pathname === "/api/totp/verify") {
      const data = await body(request);
      const code = stringField(data, "code");
      if (!/^\d{6}$/.test(code)) return response({ error: "Enter the six digits shown by your authenticator app." }, 400, request);
      const record = records.get(session.userId);
      if (!session.provisioned || !record) return response({ error: "Return to the setup key and add your authenticator first." }, 403, request);
      if (locked(session.userId)) return response({ error: "Too many attempts were made. Please wait five minutes, then try again." }, 429, request);
      if (!await verifyTotp(record, code)) {
        failed(session.userId);
        return response({ error: "That authenticator code did not work. Check the current code in your app and try again." }, 400, request);
      }
      succeeded(session.userId);
      record.enabled = true;
      const codes = newBackups();
      record.backups = await makeBackups(codes);
      session.pendingBackups = codes;
      return response({ codes }, 200, request);
    }

    if (url.pathname === "/api/backups/ack") {
      if (!records.get(session.userId)?.enabled || !session.pendingBackups) {
        return response({ error: "Make recovery codes before finishing set-up." }, 400, request);
      }
      session.pendingBackups = undefined;
      return response({ ok: true }, 200, request);
    }

    if (url.pathname === "/api/backups/regenerate") {
      const record = records.get(session.userId);
      if (!record?.enabled) return response({ error: "Finish authenticator set-up before making recovery codes." }, 403, request);
      const codes = newBackups();
      record.backups = await makeBackups(codes);
      session.pendingBackups = codes;
      return response({ codes }, 200, request);
    }

    if (url.pathname === "/api/recovery/use") {
      const data = await body(request);
      const code = stringField(data, "code").toUpperCase();
      if (!/^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(code)) {
        return response({ error: "Enter a recovery code in this format: MANGO-23456." }, 400, request);
      }
      const record = records.get(session.userId);
      if (!record?.enabled) return response({ error: "Set up your authenticator before using recovery codes." }, 403, request);
      if (locked(session.userId)) return response({ error: "Too many attempts were made. Please wait five minutes, then try again." }, 429, request);
      if (!await useBackup(record, code)) {
        failed(session.userId);
        return response({ error: "That recovery code cannot be used. Check an unused saved code and try again." }, 400, request);
      }
      succeeded(session.userId);
      return response({ ok: true }, 200, request);
    }

    return generic(404, request);
  } catch (_) {
    return generic(500, request);
  }
}

Bun.serve({
  port: PORT,
  tls: {
    cert: readFileSync(CERT_PATH),
    key: readFileSync(KEY_PATH),
  },
  fetch: handler,
});
