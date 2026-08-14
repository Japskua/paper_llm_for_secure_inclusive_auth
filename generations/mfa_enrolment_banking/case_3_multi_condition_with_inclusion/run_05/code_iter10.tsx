
import { serve } from "bun";
import { timingSafeEqual } from "node:crypto";

/* Requirements 1–5: HTTPS, secure in-memory mock state, authorization, CSRF. */
const cert = await Bun.file("certs/cert.pem").text();
const key = await Bun.file("certs/key.pem").text();
const TEST_SIMULATION = process.env.TEST_SIMULATION === "true";

const enc = new TextEncoder();
const dec = new TextDecoder();
const IDLE = 30 * 60_000;
const ABSOLUTE = 8 * 60 * 60_000;
const CODE_LIFE = 15 * 60_000;
const LOCK = 10 * 60_000;
const MAX = 5;
const PERIOD = 30;
const PBKDF2_ITERATIONS = 210_000;
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
const encryptionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);

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
  return { iv: b64(iv), cipher: b64(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, enc.encode(value))) };
}
async function decrypt(value: Stored) {
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(value.iv) }, encryptionKey, unb64(value.cipher)));
}
async function recoveryHash(code: string, salt: string) {
  const material = await crypto.subtle.importKey("raw", enc.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: unb64(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, material, 256);
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
function verifyNew(): Verify { return { code: six(), expires: Date.now() + CODE_LIFE, used: false, attempts: 0, locked: 0 }; }
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
    "Content-Security-Policy": nonce ? `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` : "default-src 'self'; frame-ancestors 'none'; base-uri 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
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
  const h = headers(req); h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((v, k) => h.set(k, v));
  return new Response(JSON.stringify(data), { status, headers: h });
}
async function body(req: Request) {
  if (!(req.headers.get("content-type") || "").includes("application/json")) return null;
  const raw = await req.text();
  if (raw.length > 4000) return null;
  try { const parsed = JSON.parse(raw); return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null; } catch { return null; }
}
function field(data: Record<string, unknown> | null, key: string, max = 200) {
  const value = data?.[key]; return typeof value === "string" && value.length <= max ? value.trim() : "";
}
function csrf(req: Request, session: Session, data: Record<string, unknown> | null) {
  const value = req.headers.get("x-csrf-token") || field(data, "csrf");
  return value.length >= 32 && equal(value, session.csrf);
}
function cookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE / 1000)}`; }
function expiredCookie() { return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }
function safe(req: Request) { const origin = req.headers.get("origin"); return !origin || ORIGIN.test(origin); }
function otpOk(value: string) { return /^\d{6}$/.test(value); }
function recoveryCodeOk(value: string) { return /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{10}$/.test(value); }

function check(verifier: Verify | undefined, code: string) {
  const now = Date.now();
  if (!verifier) return { ok: false, error: "Request a new code, then try again." };
  if (verifier.locked > now) return { ok: false, error: lockText() };
  if (verifier.used || verifier.expires < now) return { ok: false, error: "This code is no longer available. Request a new code and try again." };
  if (!equal(verifier.code, code)) {
    verifier.attempts++;
    if (verifier.attempts >= MAX) verifier.locked = now + LOCK;
    return { ok: false, error: verifier.locked > now ? lockText() : "That code does not match. Check the six digits and try again." };
  }
  verifier.used = true; return { ok: true, error: "" };
}

async function api(req: Request, path: string): Promise<Response> {
  if (!safe(req)) return reply(req, { error: "Request not allowed." }, 403);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: headers(req) });

  if (path === "/api/bootstrap" && req.method === "GET") {
    const pageToken = token(); tickets.set(pageToken, Date.now() + 600_000);
    return reply(req, { csrf: pageToken, simulation: TEST_SIMULATION });
  }
  if (path === "/api/signin" && req.method === "POST") {
    const data = await body(req), pageToken = field(data, "csrf");
    const expires = tickets.get(pageToken); tickets.delete(pageToken);
    if (!expires || expires < Date.now()) return reply(req, { error: "Your page check expired. Refresh the page, then try again." }, 403);
    const email = field(data, "email", 120).toLowerCase(), password = field(data, "password");
    const account = accounts.get("acct-marcus")!;
    const failure = loginFailures.get(email);
    if (failure?.locked && failure.locked > Date.now()) return reply(req, { error: "We could not sign you in with those details. Check them and try again." }, 401);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email !== account.email || password !== "BankPass1!") {
      const failed = failure || { attempts: 0, locked: 0 }; failed.attempts++;
      if (failed.attempts >= MAX) { failed.attempts = 0; failed.locked = Date.now() + LOCK; }
      loginFailures.set(email, failed);
      return reply(req, { error: "We could not sign you in with those details. Check them and try again." }, 401);
    }
    loginFailures.delete(email);
    const id = token(), session: Session = { id, accountId: account.id, csrf: token(), created: Date.now(), seen: Date.now() };
    sessions.set(id, session);
    return reply(req, { csrf: session.csrf, step: account.identityVerified ? (account.mfaEnabled ? "settings" : "provision") : "identity" }, 200, { "Set-Cookie": cookie(id) });
  }

  const who = auth(req);
  if (!who) return reply(req, { error: "Your signed-in session ended. Please sign in again." }, 401);
  const { session, account } = who;
  const data = req.method === "POST" ? await body(req) : null;
  if (req.method === "POST" && !csrf(req, session, data)) return reply(req, { error: "Your page check expired. Refresh the page, then try again." }, 403);

  if (path === "/api/state" && req.method === "GET") return reply(req, { csrf: session.csrf, email: account.email, identityVerified: account.identityVerified, mfaEnabled: account.mfaEnabled });
  if (path === "/api/identity/request" && req.method === "POST") {
    if (account.identity?.locked > Date.now()) return reply(req, { error: lockText() }, 429);
    account.identity = verifyNew();
    const out: Record<string, unknown> = { message: "A fresh verification code was sent." };
    if (TEST_SIMULATION) out.testCode = account.identity.code;
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
    const secret = setupSecret();
    account.pending = await crypt(secret); account.auth = { code: "", expires: 0, used: false, attempts: 0, locked: 0 };
    const label = encodeURIComponent(`Safe Bank:${account.email}`);
    return reply(req, { secret, uri: `otpauth://totp/${label}?secret=${secret}&issuer=Safe%20Bank&period=30`, email: account.email });
  }
  if (path === "/api/authenticator/verify" && req.method === "POST") {
    const code = field(data, "code", 6);
    if (!otpOk(code)) return reply(req, { error: "Enter six digits from your authenticator, for example 123456." }, 400);
    if (!account.pending) return reply(req, { error: "Start authenticator setup again, then enter a code." }, 400);
    if (account.auth?.locked && account.auth.locked > Date.now()) return reply(req, { error: authLockText() }, 429);
    const secret = await decrypt(account.pending), counter = Math.floor(Date.now() / 1000 / PERIOD);
    const valid = await Promise.all([totp(secret, counter - 1), totp(secret, counter), totp(secret, counter + 1)]);
    if (!valid.some(v => equal(v, code))) {
      const verifier = account.auth!;
      verifier.attempts++;
      if (verifier.attempts >= MAX) verifier.locked = Date.now() + LOCK;
      return reply(req, { error: verifier.locked > Date.now() ? authLockText() : "That code does not match this setup. Check your authenticator and try again." }, 400);
    }
    account.secret = account.pending; delete account.pending; account.mfaEnabled = true;
    const backups = await makeBackups(); account.backups = backups.stored; account.recoveryAttempts = 0; account.recoveryLocked = 0;
    return reply(req, { message: "Authenticator confirmed.", codes: backups.plain });
  }
  if (path === "/api/recovery/verify" && req.method === "POST") {
    const code = field(data, "code", 10).replace(/[\s-]/g, "").toUpperCase();
    if (!recoveryCodeOk(code)) return reply(req, { error: "Enter one 10-character recovery code, for example AB23CD45EF." }, 400);
    if (account.recoveryLocked > Date.now()) return reply(req, { error: recoveryLockText() }, 429);
    let found = false;
    for (const item of account.backups) {
      if (!item.used && equal(await recoveryHash(code, item.salt), item.hash)) { item.used = true; found = true; break; }
    }
    if (!found) {
      account.recoveryAttempts++;
      if (account.recoveryAttempts >= MAX) { account.recoveryAttempts = 0; account.recoveryLocked = Date.now() + LOCK; }
      return reply(req, { error: account.recoveryLocked > Date.now() ? recoveryLockText() : "That recovery code is not available. Check it or use a different unused code." }, 400);
    }
    account.recoveryAttempts = 0;
    return reply(req, { message: "Recovery code checked. It has now been used." });
  }
  if (path === "/api/recovery/regenerate" && req.method === "POST") {
    if (!account.mfaEnabled) return reply(req, { error: "Set up an authenticator before making recovery codes." }, 403);
    const backups = await makeBackups(); account.backups = backups.stored; account.recoveryAttempts = 0; account.recoveryLocked = 0;
    return reply(req, { message: "New recovery codes are ready. Your old codes no longer work.", codes: backups.plain });
  }
  if (path === "/api/logout" && req.method === "POST") {
    sessions.delete(session.id);
    return reply(req, { message: "You have signed out." }, 200, { "Set-Cookie": expiredCookie() });
  }
  return reply(req, { error: "That page is not available." }, 404);
}

function page(nonce: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Safe Bank MFA</title>
<style nonce="${nonce}">
:root{color-scheme:light;--ink:#172638;--blue:#075bb8;--pale:#edf6ff;--line:#b9c9d8;--bad:#a91d2f;--good:#086b43}*{box-sizing:border-box}body{margin:0;background:#f4f7fa;color:var(--ink);font-family:Arial,"Trebuchet MS",sans-serif;font-size:17px;line-height:1.65;letter-spacing:.025em}.shell{width:min(100%,620px);margin:auto;min-height:100vh;background:#fff;padding:22px 20px 45px}header{border-bottom:3px solid var(--blue);margin-bottom:25px}h1{font-size:1.55rem;line-height:1.25;margin:0 0 14px}h2{font-size:1.38rem;line-height:1.3;margin:0 0 12px}.brand{color:var(--blue);font-weight:bold;margin:0}.step{font-weight:bold;color:#174f85;margin:8px 0 18px}.card{border:1px solid var(--line);border-radius:12px;padding:20px;margin:18px 0;background:#fff}.hint{background:var(--pale);border-left:5px solid var(--blue);padding:12px 14px;margin:16px 0}.message{padding:12px 14px;border-radius:9px;margin:15px 0;font-weight:bold}.message.error{background:#fff0f1;color:var(--bad)}.message.good{background:#e9f8ef;color:var(--good)}label{display:block;font-weight:bold;margin:17px 0 6px}input{width:100%;font:inherit;letter-spacing:.07em;padding:13px;border:2px solid #71859a;border-radius:8px;color:var(--ink)}input:focus{outline:3px solid #85c5ff;outline-offset:2px}button{font:inherit;font-weight:bold;letter-spacing:.02em;padding:13px 16px;border:2px solid var(--blue);border-radius:8px;background:var(--blue);color:#fff;cursor:pointer;margin:12px 0;width:100%;min-height:52px}button.secondary{background:#fff;color:var(--blue)}button.small{width:auto;min-height:40px;padding:7px 12px;margin:6px 0}.actions{margin-top:20px}.code{font-family:monospace;letter-spacing:.13em;word-break:break-all;background:#f3f6f8;padding:12px;border-radius:7px}.codes{list-style:none;padding:0;margin:12px 0}.codes li{font-family:monospace;font-size:1.12rem;letter-spacing:.12em;padding:8px;border-bottom:1px solid var(--line)}details{margin:17px 0}summary{font-weight:bold;color:var(--blue);cursor:pointer}.log{background:#101c29;color:#e8f4ff;border-radius:9px;padding:12px;min-height:80px;white-space:pre-wrap;word-break:break-word;font:13px/1.5 monospace}.qr{display:grid;grid-template-columns:repeat(11,12px);gap:2px;width:max-content;padding:10px;background:#fff;border:1px solid var(--line)}.qr i{height:12px;background:#fff}.qr i.on{background:#172638}.quiet{color:#486071;font-size:.94rem}@media(max-width:380px){.shell{padding:16px 14px}.card{padding:16px}body{font-size:16px}}
</style></head><body><main class="shell"><header><p class="brand">🔐 Safe Bank</p><h1>Multi-factor authentication</h1></header><section id="app" aria-live="polite"></section><section class="card"><details><summary>Help with this page</summary><p>Take your time. There is no reading timer. You can retry, request a new code, or copy a code when you need to.</p></details></section><section class="card"><details><summary>Logs for this practice app</summary><pre id="logs" class="log">Ready.</pre></details></section></main>
<script nonce="${nonce}">
(()=>{"use strict";
const app=document.getElementById("app"), logs=document.getElementById("logs");let csrf="",simulation=false,shownCodes=[],setup={secret:"",uri:""};
const log=m=>{logs.textContent+="\\n"+m;console.log(m)}, el=(tag,text)=>{const x=document.createElement(tag);if(text!==undefined)x.textContent=text;return x};
async function api(path,data,method="POST"){try{const r=await fetch(path,{method,credentials:"same-origin",headers:method==="POST"?{"Content-Type":"application/json","X-CSRF-Token":csrf}:undefined,body:method==="POST"?JSON.stringify(data||{}):undefined});const j=await r.json();if(r.status===401){csrf="";showSign(j.error)}return j}catch{return {error:"Something went wrong. Please try again."}}}
function clear(){app.replaceChildren()}function note(text,bad=false){const x=el("p",text);x.className="message "+(bad?"error":"good");app.append(x)}
function button(text,fn,secondary=false){const b=el("button",text);if(secondary)b.className="secondary";b.onclick=fn;return b}
function input(label,type,example){const l=el("label",label), i=document.createElement("input");i.type=type;i.autocomplete=type==="password"?"current-password":"one-time-code";i.placeholder=example;i.setAttribute("aria-label",label);app.append(l,i);return i}
function step(n,title,text){clear();app.append(el("p","Step "+n),el("h2",title),el("p",text))}
function copy(value,label){navigator.clipboard?.writeText(value).then(()=>note(label+" copied.")).catch(()=>note("Copy is not available here. You can select the text instead.",true))}
async function boot(){const j=await api("/api/bootstrap",null,"GET");csrf=j.csrf||"";simulation=!!j.simulation;showSign()}
function showSign(error){clear();app.append(el("p","Step 1 of 6"),el("h2","Sign in"),el("p","Use the practice account to begin."));if(error)note(error,true);const email=input("Email address","email","marcus@example.com"),pass=input("Password","password","Example: BankPass1!");email.value="marcus@example.com";const b=button("Sign in",async()=>{const j=await api("/api/signin",{email:email.value,password:pass.value,csrf});if(j.error)return note(j.error,true);csrf=j.csrf;route(j.step)});app.append(el("p","Practice password: BankPass1!"));app.append(b)}
function route(s){if(s==="identity")showIdentity();else if(s==="provision")showProvision();else showSettings()}
function showIdentity(){step("2 of 6","Confirm it is you","We will send one six-digit identity code. Example: 123456.");const request=button("Send identity code",async()=>{const j=await api("/api/identity/request",{});if(j.error)return note(j.error,true);note(j.message);if(simulation&&j.testCode)log("TEST SIMULATION identity code: "+j.testCode);request.remove();const code=input("Identity code","text","123456");code.inputMode="numeric";app.append(button("Confirm identity",async()=>{const x=await api("/api/identity/verify",{code:code.value});if(x.error)return note(x.error,true);note(x.message);setTimeout(showProvision,300)}),button("Send a new code",showIdentity,true))});app.append(request)}
function qr(){const q=el("div");q.className="qr";q.setAttribute("aria-label","QR-style setup representation. You may use the manual key instead.");for(let n=0;n<121;n++){const i=el("i");if(((n*17+setup.secret.charCodeAt(n%setup.secret.length))%5)<2)i.className="on";q.append(i)}return q}
async function showProvision(){step("3 of 6","Set up your authenticator","Open your authenticator app. Scan the setup image, or use the manual key below.");const j=await api("/api/provision",{});if(j.error)return note(j.error,true);setup=j;app.append(qr(),el("p","Manual setup key:"),el("p",setup.secret));const key=el("p",setup.secret);key.className="code";app.append(key,button("Copy manual key",()=>copy(setup.secret,"Manual key"),true));const uri=el("p",setup.uri);uri.className="code";app.append(el("p","Setup link:"),uri,button("Copy setup link",()=>copy(setup.uri,"Setup link"),true));app.append(el("p","Then enter the current six-digit code from your authenticator. Example: 123456."));const code=input("Authenticator code","text","123456");code.inputMode="numeric";app.append(button("Confirm authenticator",async()=>{const x=await api("/api/authenticator/verify",{code:code.value});if(x.error)return note(x.error,true);shownCodes=x.codes||[];if(simulation)log("TEST SIMULATION recovery codes: "+shownCodes.join(", "));showRecoveryDisplay("Authenticator confirmed. Save your recovery codes now.")}),button("Make a different setup key",showProvision,true))}
function showRecoveryDisplay(message){step("4 of 6","Save recovery codes","Each code works once. Store them somewhere safe. You do not need to memorise them.");note(message);const list=el("ul");list.className="codes";shownCodes.forEach(c=>list.append(el("li",c)));app.append(list,button("Copy all recovery codes",()=>copy(shownCodes.join("\\n"),"Recovery codes"),true));app.append(button("I have saved my codes",showRecoveryVerify))}
function showRecoveryVerify(){step("5 of 6","Check one recovery code","Enter one code you saved. Example: AB23CD45EF. This check uses that code once.");const code=input("Recovery code","text","AB23CD45EF");code.autocomplete="one-time-code";app.append(button("Check recovery code",async()=>{const j=await api("/api/recovery/verify",{code:code.value});if(j.error)return note(j.error,true);showSettings(j.message)}),button("Show recovery codes again",()=>showRecoveryDisplay("Here are your saved codes."),true))}
async function showSettings(message){step("6 of 6","MFA is ready","Your authenticator is active for this account.");if(message)note(message);app.append(el("p","You can make a new set of recovery codes if needed. New codes replace the old ones."));app.append(button("Make new recovery codes",async()=>{const j=await api("/api/recovery/regenerate",{});if(j.error)return note(j.error,true);shownCodes=j.codes||[];if(simulation)log("TEST SIMULATION recovery codes: "+shownCodes.join(", "));showRecoveryDisplay(j.message)}),button("Sign out",async()=>{const j=await api("/api/logout",{});log(j.message||"Signed out.");csrf="";showSign()},true))}
boot();
})();</script></body></html>`;
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
