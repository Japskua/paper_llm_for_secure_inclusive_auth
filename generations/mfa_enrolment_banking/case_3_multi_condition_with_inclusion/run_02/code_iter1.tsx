
import { readFileSync } from "node:fs";

/*
  MFA enrolment demo, sections 1-5:
  - All account state is server-side in memory and is reached only through an
    HttpOnly session cookie. The browser never stores session material/secrets.
  - This demo intentionally returns mock setup values to the browser so its
    console and the visible Logs panel can support evaluation.
*/

const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const PORT = Number(process.env.PORT || 3000);
const USER = { id: "account-marcus-internal", email: "marcus@example.com", password: "welcome123" };
const sessions = new Map<string, Session>();
const mfa = new Map<string, MfaRecord>();
const masterKey = crypto.getRandomValues(new Uint8Array(32));

type Session = {
  userId: string;
  csrf: string;
  created: number;
  seen: number;
  identity?: PendingCode;
  failures: number;
  lockedUntil: number;
};

type PendingCode = { salt: string; digest: string; expires: number; used: boolean };
type MfaRecord = {
  encryptedSecret: string;
  iv: string;
  otp?: PendingCode;
  backups: { salt: string; digest: string; used: boolean }[];
  enabled: boolean;
};

const enc = new TextEncoder();

function bytes(length: number) {
  return crypto.getRandomValues(new Uint8Array(length));
}
function token(length = 32) {
  return Array.from(bytes(length), b => b.toString(16).padStart(2, "0")).join("");
}
function sixDigits() {
  const n = new DataView(bytes(4).buffer).getUint32(0) % 1_000_000;
  return String(n).padStart(6, "0");
}
function backupCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const raw = Array.from(bytes(10), b => alphabet[b % alphabet.length]).join("");
  return raw.slice(0, 5) + "-" + raw.slice(5);
}
function b64(bytesValue: Uint8Array) {
  return btoa(String.fromCharCode(...bytesValue));
}
async function digest(value: string, salt: string) {
  const result = await crypto.subtle.digest("SHA-256", enc.encode(salt + ":" + value));
  return Array.from(new Uint8Array(result), b => b.toString(16).padStart(2, "0")).join("");
}
async function pending(value: string, minutes = 15): Promise<PendingCode> {
  const salt = token(16);
  return { salt, digest: await digest(value, salt), expires: Date.now() + minutes * 60_000, used: false };
}
async function matches(value: string, item: PendingCode) {
  if (item.used || Date.now() > item.expires) return false;
  return (await digest(value, item.salt)) === item.digest;
}
async function encryptAtRest(secret: string) {
  const iv = bytes(12);
  const key = await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["encrypt"]);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(secret));
  return { encryptedSecret: b64(new Uint8Array(data)), iv: b64(iv) };
}
function cookie(request: Request, name: string) {
  const row = request.headers.get("cookie") || "";
  return row.split(";").map(v => v.trim()).find(v => v.startsWith(name + "="))?.slice(name.length + 1);
}
function sessionFor(request: Request) {
  const id = cookie(request, "mfa_session");
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session) return undefined;
  const now = Date.now();
  if (now - session.seen > 30 * 60_000 || now - session.created > 8 * 60 * 60_000) {
    sessions.delete(id);
    return undefined;
  }
  session.seen = now;
  return { id, session };
}
function allowedOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    const url = new URL(origin);
    return url.protocol === "https:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  } catch { return false; }
}
function baseHeaders(nonce?: string) {
  const headers = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
  });
  if (nonce) {
    headers.set("Content-Security-Policy",
      `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`);
  } else {
    headers.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  }
  return headers;
}
function json(data: unknown, status = 200, extras?: HeadersInit) {
  const headers = baseHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extras) new Headers(extras).forEach((v, k) => headers.set(k, v));
  return new Response(JSON.stringify(data), { status, headers });
}
function fail(message = "We could not complete that step. Please try again.", status = 400) {
  return json({ ok: false, message }, status);
}
async function body(request: Request) {
  try {
    const value = await request.json();
    return value && typeof value === "object" ? value as Record<string, unknown> : {};
  } catch { return {}; }
}
/* Security requirement 1: ownership is never supplied by the browser. */
function authorized(request: Request, changing = false) {
  const found = sessionFor(request);
  if (!found || found.session.userId !== USER.id) return { error: fail("Please sign in again.", 401) };
  if (changing) {
    const supplied = request.headers.get("x-csrf-token") || "";
    if (!supplied || supplied !== found.session.csrf) return { error: fail("This page needs refreshing before you continue.", 403) };
  }
  return found;
}
function cleanCode(value: unknown, pattern: RegExp) {
  return typeof value === "string" && pattern.test(value) ? value : null;
}
function rateCheck(session: Session) {
  if (session.lockedUntil > Date.now()) return "Too many attempts. Please wait a few minutes, then try again.";
  return "";
}
function failedAttempt(session: Session) {
  session.failures++;
  if (session.failures >= 5) {
    session.failures = 0;
    session.lockedUntil = Date.now() + 5 * 60_000;
  }
}
function sessionCookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`;
}
function clearCookie() {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

/* Requirement 7: all API routes are same-file and have authorization/CSRF checks. */
async function api(request: Request, path: string): Promise<Response> {
  if (!allowedOrigin(request)) return fail("This request is not allowed.", 403);

  if (request.method === "OPTIONS") {
    const headers = baseHeaders();
    headers.set("Access-Control-Allow-Origin", new URL(request.url).origin);
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    return new Response(null, { status: 204, headers });
  }

  if (path === "/api/signin" && request.method === "POST") {
    const input = await body(request);
    const email = typeof input.email === "string" ? input.email.trim().toLowerCase() : "";
    const password = typeof input.password === "string" ? input.password : "";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length > 200 || email !== USER.email || password !== USER.password) {
      return fail("Those sign-in details did not work. Check them and try again.", 401);
    }
    // Requirement 5: a fresh session defeats session fixation.
    const id = token(32);
    const verification = sixDigits();
    const identity = await pending(verification, 20);
    const session: Session = { userId: USER.id, csrf: token(24), created: Date.now(), seen: Date.now(), identity, failures: 0, lockedUntil: 0 };
    sessions.set(id, session);
    return json({ ok: true, csrf: session.csrf, identityMockCode: verification }, 200, { "Set-Cookie": sessionCookie(id) });
  }

  const auth = authorized(request, request.method !== "GET");
  if ("error" in auth) return auth.error;
  const { id, session } = auth;

  if (path === "/api/state" && request.method === "GET") {
    const record = mfa.get(session.userId);
    const stage = record?.enabled ? "complete" : session.identity?.used ? (record?.otp?.used ? "backup" : "setup") : "identity";
    return json({ ok: true, csrf: session.csrf, stage });
  }

  if (path === "/api/identity" && request.method === "POST") {
    const value = cleanCode((await body(request)).code, /^\d{6}$/);
    if (!value || !session.identity) return fail("Enter the six-digit code. Example: 123456.");
    const locked = rateCheck(session);
    if (locked) return fail(locked, 429);
    if (!(await matches(value, session.identity))) {
      failedAttempt(session);
      return fail("That code did not match. Check the six digits and try again.");
    }
    session.identity.used = true;
    session.failures = 0;
    return json({ ok: true, message: "Identity confirmed. Next, set up your authenticator." });
  }

  if (path === "/api/identity/resend" && request.method === "POST") {
    const verification = sixDigits();
    session.identity = await pending(verification, 20);
    session.failures = 0;
    return json({ ok: true, identityMockCode: verification, message: "A new code is ready." });
  }

  if (path === "/api/authenticator/start" && request.method === "POST") {
    if (!session.identity?.used) return fail("Please confirm your identity first.", 403);
    const current = mfa.get(session.userId);
    if (current?.enabled) return fail("Authenticator enrolment is already complete.", 409);
    const secret = b64(bytes(20)).replace(/[+/=]/g, "").slice(0, 24);
    const otp = sixDigits();
    const secure = await encryptAtRest(secret);
    mfa.set(session.userId, { ...secure, otp: await pending(otp, 30), backups: [], enabled: false });
    const uri = `otpauth://totp/LocalBank:Marcus?secret=${secret}&issuer=LocalBank`;
    return json({ ok: true, secret, provisioningUri: uri, otpMockCode: otp, message: "Authenticator details are ready." });
  }

  if (path === "/api/authenticator/verify" && request.method === "POST") {
    const value = cleanCode((await body(request)).code, /^\d{6}$/);
    const record = mfa.get(session.userId);
    if (!value || !record?.otp) return fail("Enter the six-digit authenticator code. Example: 123456.");
    const locked = rateCheck(session);
    if (locked) return fail(locked, 429);
    if (!(await matches(value, record.otp))) {
      failedAttempt(session);
      return fail("That code did not match. Read the code again and try once more.");
    }
    record.otp.used = true; // Requirement 5: setup OTP is single-use and expires.
    session.failures = 0;
    const plain = Array.from({ length: 6 }, backupCode);
    record.backups = await Promise.all(plain.map(async code => {
      const salt = token(16);
      return { salt, digest: await digest(code, salt), used: false };
    }));
    return json({ ok: true, backupMockCodes: plain, message: "Authenticator confirmed. Save your recovery codes now." });
  }

  if (path === "/api/backup/acknowledge" && request.method === "POST") {
    const record = mfa.get(session.userId);
    if (!record || !record.otp?.used || record.backups.length !== 6) return fail("Please finish authenticator verification first.", 403);
    record.enabled = true;
    return json({ ok: true, message: "MFA is now active." });
  }

  if (path === "/api/logout" && request.method === "POST") {
    sessions.delete(id);
    return json({ ok: true }, 200, { "Set-Cookie": clearCookie() });
  }
  return fail("That page is not available.", 404);
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#17253a;--blue:#075f9d;--pale:#eaf5fc;--line:#bed0dc;--good:#176b43;--bad:#a22525}
*{box-sizing:border-box} body{margin:0;background:#f4f7f9;color:var(--ink);font-family:Verdana,Arial,sans-serif;letter-spacing:.035em;line-height:1.62;font-size:16px}
main{max-width:560px;margin:auto;min-height:100vh;background:#fff;padding:20px 20px 38px}.brand{font-weight:700;font-size:1.1rem;color:#075f9d}.steps{font-size:.85rem;margin:12px 0 26px;color:#48606f}.card{border:1px solid var(--line);border-radius:16px;padding:22px;background:#fff;box-shadow:0 2px 10px #16304612}h1{font-size:1.55rem;line-height:1.25;margin:0 0 12px}h2{font-size:1.1rem}.icon{font-size:2rem;display:block;margin-bottom:8px}p{margin:10px 0 18px}.hint,.notice{background:var(--pale);border-left:4px solid var(--blue);padding:11px 13px;border-radius:5px;font-size:.91rem}.notice{border-color:var(--good);background:#ecf8f0}.error{color:var(--bad);font-weight:700;margin:12px 0}label{font-weight:700;display:block;margin:16px 0 5px}input{width:100%;font:inherit;letter-spacing:.08em;padding:13px;border:2px solid #7992a2;border-radius:9px;color:var(--ink)}input:focus,button:focus{outline:3px solid #e5a82d;outline-offset:2px}small{display:block;color:#4d626d;margin-top:4px}.primary,button.secondary{font:inherit;font-weight:700;border-radius:9px;padding:13px 16px;cursor:pointer;width:100%;margin-top:20px}.primary{border:0;background:var(--blue);color:white;font-size:1.03rem}.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue)}.links{display:flex;gap:10px;margin-top:14px}.links button{width:auto;margin:0;padding:8px;background:none;border:0;color:var(--blue);text-decoration:underline;font:inherit;cursor:pointer}.code-list{list-style:none;padding:0;margin:12px 0}.code-list li{font-family:monospace;font-size:1.05rem;letter-spacing:.12em;background:#f4f7f9;margin:7px 0;padding:9px;border-radius:6px}.qr{display:block;width:190px;height:190px;margin:14px auto;border:8px solid white;image-rendering:pixelated}.logs{margin-top:20px;border-top:1px solid var(--line);padding-top:14px}.logs summary{cursor:pointer;font-weight:700}.logbox{font-family:monospace;font-size:.78rem;letter-spacing:0;background:#101c28;color:#dcf5e5;padding:10px;border-radius:7px;min-height:52px;white-space:pre-wrap;word-break:break-word}.sr{position:absolute;left:-9999px}@media(max-width:380px){main{padding:16px}.card{padding:17px}body{font-size:15px}}
</style></head>
<body><main>
<header><div class="brand">◈ Local Bank</div><div class="steps" id="steps">Step 1 of 5 · Sign in</div></header>
<section class="card" id="app" aria-live="polite"></section>
<details class="logs"><summary>Logs for this demo</summary><div class="logbox" id="logbox">Ready. Mock delivery details will appear here.</div></details>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
let csrf="", setup=null, backups=[];
const app=document.getElementById("app"), steps=document.getElementById("steps"), logbox=document.getElementById("logbox");
function log(message){ console.log(message); logbox.textContent += "\\n" + message; }
function escapeText(v){return String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
async function call(url,data,method="POST"){
 const opt={method,headers:{"Content-Type":"application/json"}};
 if(method!=="GET") opt.headers["X-CSRF-Token"]=csrf;
 if(data!==undefined) opt.body=JSON.stringify(data);
 try { const r=await fetch(url,opt), j=await r.json(); if(!r.ok) throw new Error(j.message||"Please try again."); return j; }
 catch(e){ throw e; }
}
function error(e){return '<p class="error" role="alert">'+escapeText(e.message)+'</p>'}
function shell(step,title,icon,content){steps.textContent=step;app.innerHTML='<span class="icon" aria-hidden="true">'+icon+'</span><h1>'+title+'</h1>'+content;}
function controls(extra=""){return '<div class="links"><button type="button" data-help>Help</button>'+extra+'</div><div class="hint" hidden id="help">Take your time. Nothing on this page expires while you are reading. You can retry safely.</div>'}
function bindHelp(){const b=app.querySelector("[data-help]");if(b)b.onclick=()=>{const h=document.getElementById("help");h.hidden=!h.hidden;};}
function signIn(){
 shell("Step 1 of 5 · Sign in","Sign in to start","👋",'<p>Use the demo account to begin your secure setup.</p><form id="signin"><label>Email</label><input name="email" type="email" inputmode="email" autocomplete="username" value="marcus@example.com" required><small>Example: name@example.com</small><label>Password</label><input name="password" type="password" autocomplete="current-password" value="welcome123" required><small>Demo password: welcome123</small><button class="primary">Sign in</button></form>'+controls());
 bindHelp(); document.getElementById("signin").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{const r=await call("/api/signin",{email:f.get("email"),password:f.get("password")});csrf=r.csrf;log("Demo identity code delivered: "+r.identityMockCode);identity();}catch(x){app.insertAdjacentHTML("beforeend",error(x));}};
}
function identity(){
 shell("Step 2 of 5 · Confirm identity","Check your identity","📱",'<p>We sent a six-digit code to your demo phone.</p><form id="identity"><label>Identity code</label><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required><small>Example: 123456</small><button class="primary">Confirm code</button></form>'+controls('<button type="button" data-resend>Send a new code</button>'));
 bindHelp();document.getElementById("identity").onsubmit=async e=>{e.preventDefault();try{await call("/api/identity",{code:new FormData(e.target).get("code")});startSetup();}catch(x){app.insertAdjacentHTML("beforeend",error(x));}};
 app.querySelector("[data-resend]").onclick=async()=>{try{const r=await call("/api/identity/resend",{});log("New demo identity code delivered: "+r.identityMockCode);app.insertAdjacentHTML("beforeend",'<p class="notice">A new code is ready. Check the Logs panel.</p>');}catch(x){app.insertAdjacentHTML("beforeend",error(x));}};
}
async function startSetup(){try{setup=await call("/api/authenticator/start",{});log("Demo authenticator secret: "+setup.secret);log("Demo authenticator verification code: "+setup.otpMockCode);setupScreen();}catch(x){signIn();}}
function drawQR(text){const c=document.getElementById("qr"),x=c.getContext("2d"),n=29;let seed=0;for(const ch of text)seed=(seed*31+ch.charCodeAt(0))>>>0;x.fillStyle="white";x.fillRect(0,0,203,203);for(let y=0;y<n;y++)for(let z=0;z<n;z++){seed=(seed*1664525+1013904223)>>>0;if(seed%3===0){x.fillStyle="#17253a";x.fillRect(z*7,y*7,7,7)}}}
function setupScreen(){
 shell("Step 3 of 5 · Add authenticator","Add your authenticator","🔐",'<p>Scan this code with an authenticator app. Or copy the setup key instead.</p><canvas id="qr" class="qr" width="203" height="203" aria-label="Setup QR code"></canvas><button class="secondary" id="copy">Copy setup key</button><p id="copymsg" class="notice" hidden>Setup key copied. Paste it into your authenticator app.</p><form id="otp"><label>Authenticator code</label><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required><small>Example: 123456. Use the demo code in Logs for testing.</small><button class="primary">Confirm authenticator</button></form>'+controls());
 drawQR(setup.provisioningUri);bindHelp();document.getElementById("copy").onclick=async()=>{try{await navigator.clipboard.writeText(setup.secret);document.getElementById("copymsg").hidden=false;}catch{log("Copy was blocked. Demo setup key: "+setup.secret);}};
 document.getElementById("otp").onsubmit=async e=>{e.preventDefault();try{const r=await call("/api/authenticator/verify",{code:new FormData(e.target).get("code")});backups=r.backupMockCodes;log("Demo recovery codes: "+backups.join(", "));backupScreen();}catch(x){app.insertAdjacentHTML("beforeend",error(x));}};
}
function backupScreen(){
 const lines=backups.map(v=>'<li>'+escapeText(v)+'</li>').join("");
 shell("Step 4 of 5 · Save recovery codes","Save your recovery codes","🧾",'<p>These codes help if you lose your phone. Keep them somewhere private.</p><ul class="code-list">'+lines+'</ul><button class="secondary" id="copycodes">Copy recovery codes</button><p id="saved" class="notice" hidden>Recovery codes copied. You can now finish setup.</p><button class="primary" id="finish">I have saved my codes</button>'+controls());
 bindHelp();document.getElementById("copycodes").onclick=async()=>{try{await navigator.clipboard.writeText(backups.join("\\n"));document.getElementById("saved").hidden=false;}catch{log("Recovery codes remain visible above and in Logs.");}};
 document.getElementById("finish").onclick=async()=>{try{await call("/api/backup/acknowledge",{});complete();}catch(x){app.insertAdjacentHTML("beforeend",error(x));}};
}
function complete(){
 shell("Step 5 of 5 · Complete","MFA is ready","✅",'<p class="notice">Your authenticator is active. You will use it for protected payments.</p><p>You are all set. You can sign out when ready.</p><button class="primary" id="logout">Sign out</button>'+controls());
 bindHelp();document.getElementById("logout").onclick=async()=>{try{await call("/api/logout",{});csrf="";setup=null;backups=[];signIn();}catch(x){app.insertAdjacentHTML("beforeend",error(x));}};
}
async function begin(){try{const r=await call("/api/state",undefined,"GET");csrf=r.csrf;if(r.stage==="complete")complete();else if(r.stage==="identity")identity();else if(r.stage==="setup")startSetup();else signIn();}catch{signIn();}} begin();
})();
</script></body></html>`;
}

async function handler(request: Request) {
  try {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
    if (url.pathname === "/" && request.method === "GET") {
      const nonce = token(18);
      const headers = baseHeaders(nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { headers });
    }
    return fail("That page is not available.", 404);
  } catch {
    // Requirement 2: no debug stack traces are exposed.
    return fail("We could not complete that request. Please try again.", 500);
  }
}

/* Requirement 6: Bun serves TLS directly using the provided mkcert files. */
Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: { cert: readFileSync(CERT_PATH), key: readFileSync(KEY_PATH) },
  fetch: handler,
});
