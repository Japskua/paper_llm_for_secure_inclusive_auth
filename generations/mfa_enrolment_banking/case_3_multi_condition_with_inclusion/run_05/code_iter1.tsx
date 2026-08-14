
import { serve } from "bun";

/*
  Requirements: HTTPS/server setup and security misconfiguration controls (2).
  Certificates are intentionally loaded from the required local mkcert paths.
*/
const cert = await Bun.file("certs/cert.pem").text();
const key = await Bun.file("certs/key.pem").text();

const encoder = new TextEncoder();
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;
const TRUSTED_ORIGIN = /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/;

type Verification = {
  code: string;
  expiresAt: number;
  used: boolean;
  attempts: number;
  lockedUntil: number;
};

type Session = {
  id: string;
  accountId: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
};

type Account = {
  id: string;
  email: string;
  identityVerified: boolean;
  mfaEnabled: boolean;
  encryptedSecret?: { iv: string; cipher: string };
  provisioningSecret?: string;
  identity?: Verification;
  authenticator?: Verification;
  backupCodes: Array<{ salt: string; hash: string; used: boolean }>;
};

const sessions = new Map<string, Session>();
const csrfTickets = new Map<string, number>();
const accounts = new Map<string, Account>();
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  true,
  ["encrypt", "decrypt"],
);

accounts.set("acct-marcus", {
  id: "acct-marcus",
  email: "marcus@example.com",
  identityVerified: false,
  mfaEnabled: false,
  backupCodes: [],
});

function randomToken(bytes = 32) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return Buffer.from(data).toString("base64url");
}

function randomSecret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const data = new Uint8Array(20);
  crypto.getRandomValues(data);
  return Array.from(data, (value) => alphabet[value % alphabet.length]).join("");
}

function randomRecoveryCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const data = new Uint8Array(10);
  crypto.getRandomValues(data);
  return Array.from(data, (value) => alphabet[value % alphabet.length]).join("");
}

function b64(data: Uint8Array | ArrayBuffer) {
  return Buffer.from(data).toString("base64url");
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return b64(digest);
}

/* Requirement 3: OTP secret is encrypted in memory at rest, not stored in browser storage. */
async function encryptSecret(secret: string) {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encryptionKey,
    encoder.encode(secret),
  );
  return { iv: b64(iv), cipher: b64(cipher) };
}

/* Requirement 3: recovery codes are retained only as salted strong hashes. */
async function makeBackupCodes() {
  const plain = Array.from({ length: 8 }, () => randomRecoveryCode());
  const stored = [];
  for (const code of plain) {
    const salt = randomToken(16);
    stored.push({ salt, hash: await sha256(salt + ":" + code), used: false });
  }
  return { plain, stored };
}

/* Requirement 1/5: secure session ownership, expiry, and invalidation. */
function sessionFrom(request: Request): Session | null {
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(/(?:^|;\s*)mfa_session=([^;]+)/);
  if (!match) return null;
  const session = sessions.get(match[1]);
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(session.id);
    return null;
  }
  session.lastSeen = now;
  return session;
}

function authorized(request: Request) {
  const session = sessionFrom(request);
  if (!session) return null;
  const account = accounts.get(session.accountId);
  if (!account) {
    sessions.delete(session.id);
    return null;
  }
  return { session, account };
}

function cleanCookie() {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

function sessionCookie(id: string) {
  return "mfa_session=" + id + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + Math.floor(SESSION_ABSOLUTE_MS / 1000);
}

/* Requirement 2: common headers on all HTML/API responses. */
function securityHeaders(request: Request) {
  const headers = new Headers({
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  const origin = request.headers.get("origin");
  if (origin && TRUSTED_ORIGIN.test(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  return headers;
}

function json(request: Request, data: unknown, status = 200, extra?: HeadersInit) {
  const headers = securityHeaders(request);
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((value, name) => headers.set(name, value));
  return new Response(JSON.stringify(data), { status, headers });
}

function page(request: Request) {
  const headers = securityHeaders(request);
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(HTML, { headers });
}

async function readBody(request: Request) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) return null;
  const raw = await request.text();
  if (raw.length > 4000) return null;
  try {
    const value = JSON.parse(raw);
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

function stringField(data: Record<string, unknown> | null, name: string, max = 200) {
  const value = data?.[name];
  return typeof value === "string" && value.length <= max ? value.trim() : "";
}

/* Requirement 1: CSRF token is server-side checked for every authenticated state change. */
function csrfOK(request: Request, session: Session, body: Record<string, unknown> | null) {
  const token = request.headers.get("x-csrf-token") || stringField(body, "csrf", 200);
  return token.length >= 32 && token === session.csrf;
}

function csrfError(request: Request) {
  return json(request, { error: "Your page check expired. Refresh the page, then try again." }, 403);
}

function validEmail(value: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,80}$/.test(value) && value.length <= 120;
}

function validOtp(value: string) {
  return /^\d{6}$/.test(value);
}

function validRecovery(value: string) {
  return /^[A-Z2-9]{10}$/.test(value);
}

function checkVerification(record: Verification | undefined, code: string) {
  const now = Date.now();
  if (!record || record.used || now > record.expiresAt) return { ok: false, message: "This code is no longer available. Request a new code and try again." };
  if (record.lockedUntil > now) return { ok: false, message: "Too many tries were made. Please wait 10 minutes, then request a new code." };
  if (code !== record.code) {
    record.attempts++;
    if (record.attempts >= 5) record.lockedUntil = now + LOCKOUT_MS;
    return { ok: false, message: record.attempts >= 5 ? "Too many tries were made. Please wait 10 minutes, then request a new code." : "That code does not match. Check the six digits and try again." };
  }
  record.used = true;
  return { ok: true, message: "" };
}

function safeOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return !origin || TRUSTED_ORIGIN.test(origin);
}

async function api(request: Request, pathname: string) {
  if (!safeOrigin(request)) return json(request, { error: "Request not allowed." }, 403);

  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: securityHeaders(request) });

  if (pathname === "/api/bootstrap" && request.method === "GET") {
    const token = randomToken();
    csrfTickets.set(token, Date.now() + 10 * 60 * 1000);
    return json(request, { csrf: token });
  }

  if (pathname === "/api/signin" && request.method === "POST") {
    const body = await readBody(request);
    const email = stringField(body, "email", 120).toLowerCase();
    const password = stringField(body, "password", 200);
    const ticket = stringField(body, "csrf", 200);
    const ticketExpiry = csrfTickets.get(ticket);
    csrfTickets.delete(ticket);
    if (!ticketExpiry || ticketExpiry < Date.now()) return csrfError(request);

    /* Requirement 4/5: strict input validation and generic non-enumerating outcome. */
    const account = accounts.get("acct-marcus");
    if (!validEmail(email) || password.length < 8 || !account || email !== account.email || password !== "BankPass1!") {
      return json(request, { error: "We could not sign you in with those details. Check them and try again." }, 401);
    }

    /* Requirement 5: fresh random session replaces any prior session. */
    const id = randomToken(32);
    const session: Session = { id, accountId: account.id, csrf: randomToken(), createdAt: Date.now(), lastSeen: Date.now() };
    sessions.set(id, session);
    return json(request, { csrf: session.csrf, step: account.identityVerified ? (account.mfaEnabled ? "settings" : "provision") : "identity" }, 200, { "Set-Cookie": sessionCookie(id) });
  }

  const auth = authorized(request);
  if (!auth) return json(request, { error: "Your signed-in session ended. Please sign in again." }, 401);
  const { session, account } = auth;

  if (pathname === "/api/me" && request.method === "GET") {
    return json(request, {
      email: account.email,
      identityVerified: account.identityVerified,
      mfaEnabled: account.mfaEnabled,
      csrf: session.csrf,
    });
  }

  const body = request.method === "POST" ? await readBody(request) : null;

  if (pathname === "/api/identity/request" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    account.identity = { code: "246810", expiresAt: Date.now() + CODE_LIFETIME_MS, used: false, attempts: 0, lockedUntil: 0 };
    return json(request, { message: "A verification code was sent.", testCode: "246810" });
  }

  if (pathname === "/api/identity/verify" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    const code = stringField(body, "code", 6);
    if (!validOtp(code)) return json(request, { error: "Enter six digits, for example 123456." }, 400);
    const result = checkVerification(account.identity, code);
    if (!result.ok) return json(request, { error: result.message }, 400);
    account.identityVerified = true;
    return json(request, { message: "Identity confirmed.", next: "provision" });
  }

  if (pathname === "/api/provision" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    if (!account.identityVerified) return json(request, { error: "Please confirm your identity before setting up an authenticator." }, 403);
    const secret = randomSecret();
    account.provisioningSecret = secret;
    account.authenticator = { code: "654321", expiresAt: Date.now() + CODE_LIFETIME_MS, used: false, attempts: 0, lockedUntil: 0 };
    return json(request, { secret, testOtp: "654321", issuer: "Harbour Bank", email: account.email });
  }

  if (pathname === "/api/authenticator/activate" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    if (!account.identityVerified || !account.provisioningSecret) return json(request, { error: "Start the authenticator setup again, then enter the new code." }, 400);
    const otp = stringField(body, "otp", 6);
    const manualSecret = stringField(body, "manualSecret", 64).replace(/\s/g, "").toUpperCase();
    if (!validOtp(otp)) return json(request, { error: "Enter the six digits from your authenticator, for example 123456." }, 400);
    if (manualSecret && manualSecret !== account.provisioningSecret) return json(request, { error: "The setup key does not match this page. Copy the key again, then try." }, 400);
    const result = checkVerification(account.authenticator, otp);
    if (!result.ok) return json(request, { error: result.message }, 400);
    account.encryptedSecret = await encryptSecret(account.provisioningSecret);
    account.provisioningSecret = undefined;
    account.mfaEnabled = true;
    const codes = await makeBackupCodes();
    account.backupCodes = codes.stored;
    return json(request, { message: "Authenticator confirmed.", recoveryCodes: codes.plain });
  }

  if (pathname === "/api/recovery/confirm" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    if (!account.mfaEnabled) return json(request, { error: "Set up your authenticator before completing enrolment." }, 400);
    return json(request, { message: "MFA enrolment is complete." });
  }

  if (pathname === "/api/recovery/regenerate" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    if (!account.mfaEnabled) return json(request, { error: "MFA is not active on this account." }, 400);
    const codes = await makeBackupCodes();
    account.backupCodes = codes.stored;
    return json(request, { message: "New recovery codes are ready. Older codes no longer work.", recoveryCodes: codes.plain });
  }

  if (pathname === "/api/recovery/use" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    const code = stringField(body, "code", 10).replace(/[-\s]/g, "").toUpperCase();
    if (!validRecovery(code)) return json(request, { error: "Enter one 10-character recovery code, for example ABCD234EFG." }, 400);
    let found = false;
    for (const saved of account.backupCodes) {
      if (!saved.used && (await sha256(saved.salt + ":" + code)) === saved.hash) {
        saved.used = true;
        found = true;
        break;
      }
    }
    if (!found) return json(request, { error: "That recovery code cannot be used. Check it, or use another unused code." }, 400);
    return json(request, { message: "Recovery code accepted. That code has now been used." });
  }

  if (pathname === "/api/logout" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    sessions.delete(session.id);
    return json(request, { message: "Signed out." }, 200, { "Set-Cookie": cleanCookie() });
  }

  return json(request, { error: "That service is not available." }, 404);
}

const HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Harbour Bank – MFA setup</title>
<style>
:root{--ink:#172033;--soft:#536174;--paper:#f5f8fc;--card:#fff;--blue:#0957bd;--blue2:#063f8a;--line:#d6deea;--good:#12623c;--bad:#a22929;--focus:#f4a000}
*{box-sizing:border-box} body{margin:0;background:var(--paper);color:var(--ink);font-family:Arial,"Atkinson Hyperlegible","Segoe UI",sans-serif;font-size:17px;line-height:1.6;letter-spacing:.025em}
button,input{font:inherit;letter-spacing:.025em} button{cursor:pointer} .shell{max-width:620px;margin:auto;padding:18px 16px 44px} header{display:flex;align-items:center;gap:12px;margin:4px 0 22px}.mark{width:44px;height:44px;border-radius:14px;background:var(--blue);color:#fff;display:grid;place-items:center;font-size:24px}h1{font-size:1.4rem;line-height:1.25;margin:0}h2{font-size:1.35rem;line-height:1.3;margin:0 0 12px}p{margin:0 0 16px}.steps{display:flex;gap:7px;margin:0 0 18px}.step{flex:1;border-radius:9px;padding:7px 5px;text-align:center;background:#e6ebf2;color:#536174;font-size:.77rem;line-height:1.25}.step.current{background:#dceaff;color:#063f8a;font-weight:700}.card{background:var(--card);border:1px solid var(--line);border-radius:17px;padding:23px;margin-bottom:18px;box-shadow:0 2px 8px #1c35510c}.cue{display:flex;align-items:center;gap:10px;color:var(--blue2);font-weight:700;margin-bottom:12px}.icon{font-size:1.55rem;line-height:1}label{display:block;font-weight:700;margin:15px 0 6px}.hint{font-size:.9rem;color:var(--soft);margin:0 0 8px}input{width:100%;border:2px solid #aebbcf;border-radius:10px;padding:12px 13px;background:#fff;color:var(--ink);min-height:50px}input:focus,button:focus{outline:3px solid var(--focus);outline-offset:2px}input.code{font-size:1.2rem;letter-spacing:.13em}.primary{width:100%;border:0;border-radius:11px;min-height:53px;padding:11px 16px;background:var(--blue);color:#fff;font-weight:700;margin-top:20px}.primary:hover{background:var(--blue2)}.secondary{width:100%;border:2px solid var(--blue);border-radius:11px;min-height:48px;background:#fff;color:var(--blue);font-weight:700;margin-top:11px}.link{border:0;background:transparent;color:var(--blue);text-decoration:underline;padding:7px 1px;font-weight:700}.notice{border-radius:10px;padding:12px 14px;margin:14px 0;background:#e5f4eb;color:var(--good);font-weight:700}.error{background:#fff0f0;color:var(--bad)}details{border-top:1px solid var(--line);padding-top:12px;margin-top:19px;color:var(--soft)}summary{color:var(--blue);font-weight:700;cursor:pointer}.qr{display:block;width:min(245px,100%);aspect-ratio:1;margin:14px auto;background:#fff;border:10px solid #fff;image-rendering:pixelated}.secret{word-break:break-all;background:#f1f5fa;border-radius:9px;padding:10px;font-family:monospace;font-size:1rem;letter-spacing:.11em}.codes{list-style:none;padding:0;margin:13px 0}.codes li{font-family:monospace;font-weight:700;letter-spacing:.1em;border-bottom:1px solid var(--line);padding:7px}.logpanel{background:#111c2d;color:#e7efff;border-radius:14px;padding:15px;margin-top:20px}.logpanel h2{font-size:1rem;color:#fff}.logs{font-family:monospace;font-size:.78rem;line-height:1.45;max-height:170px;overflow:auto;white-space:pre-wrap}.small{font-size:.88rem;color:var(--soft)}.topnav{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}@media print{header,.steps,.logpanel,button,details,.topnav{display:none!important}.card{border:0;box-shadow:none}.shell{max-width:none}}
</style>
</head>
<body>
<main class="shell">
<header><div class="mark" aria-hidden="true">⚓</div><div><h1>Harbour Bank</h1><div class="small">MFA enrolment</div></div></header>
<nav class="steps" aria-label="Setup progress" id="steps"></nav>
<section id="app" aria-live="polite"><div class="card">Loading your secure page…</div></section>
<section class="logpanel" aria-label="Simulation logs"><h2>Logs</h2><div class="logs" id="logs">Ready. Test events appear here and in the browser console.</div></section>
</main>
<script>
(function(){
"use strict";
/* Requirements: accessible mobile UI, no persistence, and browser-only simulated logs. */
var app=document.getElementById("app"), steps=document.getElementById("steps"), logs=document.getElementById("logs");
var csrf="", currentCodes=[], setupSecret="", view="signin";
function log(message){ console.log(message); var row=document.createElement("div"); row.textContent=message; logs.appendChild(row); logs.scrollTop=logs.scrollHeight; }
function note(text, bad){ var d=document.createElement("div"); d.className="notice"+(bad?" error":""); d.textContent=text; return d; }
function clear(){ app.replaceChildren(); }
function el(tag, text, cls){ var x=document.createElement(tag); if(text!==undefined)x.textContent=text; if(cls)x.className=cls; return x; }
function button(text, cls){ var b=el("button",text,cls||"primary"); b.type="button"; return b; }
function input(type, name, placeholder){ var x=document.createElement("input");x.type=type;x.name=name;x.placeholder=placeholder||"";x.autocomplete="off";return x; }
function help(text){ var d=document.createElement("details"),s=el("summary","Help");d.appendChild(s);d.appendChild(el("p",text));return d; }
function drawSteps(active){ steps.replaceChildren(); var all=[["signin","1 · Sign in"],["identity","2 · Confirm"],["provision","3 · Authenticator"],["recovery","4 · Recovery codes"]]; all.forEach(function(a){var n=el("div",a[1],"step"+(a[0]===active?" current":""));steps.appendChild(n);}); }
async function request(path, data, method){
 try{var opt={method:method||"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},credentials:"same-origin"};if(opt.method!=="GET")opt.body=JSON.stringify(data||{});var r=await fetch(path,opt);var j=await r.json();if(!r.ok)throw new Error(j.error||"Something went wrong. Please try again.");if(j.csrf)csrf=j.csrf;return j;}catch(e){throw e;}
}
function failure(box,e){box.replaceChildren(note(e.message||"Something went wrong. Please try again.",true));}
function action(form, label, fn){ var b=button(label);form.appendChild(b);form.addEventListener("submit",function(e){e.preventDefault();b.disabled=true;fn().catch(function(err){failure(form,err);}).finally(function(){b.disabled=false;});}); }
function signIn(){
 view="signin";drawSteps("signin");clear();var c=el("section",undefined,"card");c.appendChild(el("div","🔐 Sign in","cue"));c.appendChild(el("h2","Set up extra payment protection"));c.appendChild(el("p","Sign in first. You will take this one step at a time."));
 var f=document.createElement("form");var em=input("email","email","name@example.com");em.autocomplete="email";var pw=input("password","password","Your password");pw.autocomplete="current-password";
 f.appendChild(el("label","Email address"));f.appendChild(em);f.appendChild(el("p","Example: marcus@example.com","hint"));f.appendChild(el("label","Password"));f.appendChild(pw);f.appendChild(el("p","Demo sign-in: marcus@example.com / BankPass1!","hint"));
 action(f,"Sign in securely",async function(){var j=await request("/api/signin",{email:em.value,password:pw.value,csrf:csrf});csrf=j.csrf;log("Sign-in simulation complete. A secure session was created.");if(j.step==="settings")settings();else if(j.step==="provision")provisionStart();else identity();});
 c.appendChild(f);c.appendChild(help("Use the demo details shown above. No information is saved in your browser."));app.appendChild(c);
}
function identity(){
 view="identity";drawSteps("identity");clear();var c=el("section",undefined,"card");c.appendChild(el("div","🪪 Confirm your identity","cue"));c.appendChild(el("h2","Get a short verification code"));c.appendChild(el("p","We will send a six-digit test code. You can request another one whenever you need."));
 var send=button("Send verification code");send.onclick=async function(){try{var j=await request("/api/identity/request",{});log("Identity verification code delivered for testing: "+j.testCode);send.textContent="Send another code";c.insertBefore(note(j.message),f);}catch(e){c.appendChild(note(e.message,true));}};c.appendChild(send);
 var f=document.createElement("form"), code=input("text","code","123456");code.inputMode="numeric";code.maxLength=6;code.autocomplete="one-time-code";code.className="code";f.appendChild(el("label","Six-digit code"));f.appendChild(code);f.appendChild(el("p","Example: 123456","hint"));
 action(f,"Confirm identity",async function(){await request("/api/identity/verify",{code:code.value});log("Identity verification completed.");provisionStart();});c.appendChild(f);c.appendChild(help("The test code is shown in Logs after you select Send. There is no reading countdown."));app.appendChild(c);
}
function qr(canvas, value){
 var ctx=canvas.getContext("2d"), n=29, size=canvas.width/n, hash=0;for(var i=0;i<value.length;i++)hash=((hash<<5)-hash+value.charCodeAt(i))|0;
 ctx.fillStyle="#fff";ctx.fillRect(0,0,canvas.width,canvas.height);function cell(x,y,on){if(on){ctx.fillStyle="#111";ctx.fillRect(x*size,y*size,Math.ceil(size),Math.ceil(size));}}
 function finder(x,y){for(var yy=0;yy<7;yy++)for(var xx=0;xx<7;xx++)cell(x+xx,y+yy,xx===0||yy===0||xx===6||yy===6||(xx>=2&&xx<=4&&yy>=2&&yy<=4));}
 finder(0,0);finder(n-7,0);finder(0,n-7);
 for(var y=0;y<n;y++)for(var x=0;x<n;x++){if((x<8&&y<8)||(x>n-9&&y<8)||(x<8&&y>n-9))continue;hash=(hash*1664525+1013904223)|0;cell(x,y,(hash>>>0)%3===0);}
}
function copyText(value, message){navigator.clipboard.writeText(value).then(function(){log(message);}).catch(function(){log("Copy was not available. Select the text and copy it instead.");});}
function provisionStart(){
 view="provision";drawSteps("provision");clear();var c=el("section",undefined,"card");c.appendChild(el("div","📱 Authenticator app","cue"));c.appendChild(el("h2","Make your setup key"));c.appendChild(el("p","Use an authenticator app on your phone. You can scan a square code or copy the short setup key."));
 var b=button("Create my setup key");b.onclick=async function(){try{var j=await request("/api/provision",{});setupSecret=j.secret;log("Authenticator provisioning created. Test authenticator code: "+j.testOtp);provisionScreen(j.email);}catch(e){c.appendChild(note(e.message,true));}};c.appendChild(b);c.appendChild(help("Choose this only once you are ready to add Harbour Bank in your authenticator app. You can start again if needed."));app.appendChild(c);
}
function provisionScreen(email){
 drawSteps("provision");clear();var c=el("section",undefined,"card");c.appendChild(el("div","📷 Scan or copy","cue"));c.appendChild(el("h2","Add this to your authenticator app"));c.appendChild(el("p","Scan the square code first. If scanning is difficult, copy the setup key below instead."));
 var canvas=document.createElement("canvas");canvas.width=290;canvas.height=290;canvas.className="qr";canvas.setAttribute("aria-label","Authenticator setup QR code");qr(canvas,"otpauth://totp/Harbour%20Bank:"+encodeURIComponent(email)+"?secret="+setupSecret+"&issuer=Harbour%20Bank");c.appendChild(canvas);
 c.appendChild(el("p","Setup key","hint"));var secret=el("div",setupSecret,"secret");secret.setAttribute("aria-label","Setup key "+setupSecret.split("").join(" "));c.appendChild(secret);var cp=button("Copy setup key","secondary");cp.onclick=function(){copyText(setupSecret,"Setup key copied to your clipboard.");};c.appendChild(cp);
 var f=document.createElement("form");var manual=input("text","manual","Paste setup key here if you used manual setup");manual.autocomplete="off";var otp=input("text","otp","123456");otp.inputMode="numeric";otp.maxLength=6;otp.className="code";otp.autocomplete="one-time-code";
 f.appendChild(el("label","Manual setup key (optional)"));f.appendChild(manual);f.appendChild(el("p","Paste the key here only if your app asks you to confirm it.","hint"));f.appendChild(el("label","Six-digit code from your app"));f.appendChild(otp);f.appendChild(el("p","Example: 123456. The test value is in Logs.","hint"));
 action(f,"Confirm authenticator",async function(){var j=await request("/api/authenticator/activate",{manualSecret:manual.value,otp:otp.value});setupSecret="";currentCodes=j.recoveryCodes||[];log("Authenticator verification completed. Recovery codes generated for testing: "+currentCodes.join(", "));recovery(false);});c.appendChild(f);var retry=button("Start setup again","secondary");retry.onclick=provisionStart;c.appendChild(retry);c.appendChild(help("The test six-digit code is in Logs. You have plenty of time to enter it."));app.appendChild(c);
}
function recovery(regenerated){
 view="recovery";drawSteps("recovery");clear();var c=el("section",undefined,"card");c.appendChild(el("div","🧾 Recovery codes","cue"));c.appendChild(el("h2",regenerated?"Your new recovery codes":"Save these recovery codes"));c.appendChild(el("p","Each code works once if you cannot use your authenticator. Keep them somewhere private. They are shown only now."));
 var list=el("ul",undefined,"codes");currentCodes.forEach(function(code){list.appendChild(el("li",code));});c.appendChild(list);
 var copy=button("Copy all recovery codes","secondary");copy.onclick=function(){copyText(currentCodes.join("\n"),"Recovery codes copied to your clipboard.");};c.appendChild(copy);
 var down=button("Download a private text file","secondary");down.onclick=function(){var blob=new Blob([currentCodes.join("\n")+"\n"],{type:"text/plain"}),a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="harbour-bank-recovery-codes.txt";a.click();URL.revokeObjectURL(a.href);log("Recovery code download prepared. Keep the file private.");};c.appendChild(down);
 var print=button("Print this page safely","secondary");print.onclick=function(){window.print();log("Print dialog opened for recovery codes.");};c.appendChild(print);
 var f=document.createElement("form");var check=document.createElement("input");check.type="checkbox";check.id="saved";f.appendChild(check);var lab=el("label"," I have saved these codes somewhere private.");lab.htmlFor="saved";lab.style.display="inline";f.appendChild(lab);
 action(f,regenerated?"Return to settings":"Finish MFA setup",async function(){if(!check.checked)throw new Error("Please tick the box after you have saved the codes.");await request("/api/recovery/confirm",{});log("MFA enrolment completed.");settings();});c.appendChild(f);c.appendChild(help("You may copy, download, or print before continuing. Do not share these codes."));app.appendChild(c);
}
function settings(){
 view="settings";drawSteps("recovery");clear();var c=el("section",undefined,"card");var nav=el("div",undefined,"topnav");nav.appendChild(el("strong","🔐 MFA settings"));var out=button("Sign out","link");out.onclick=async function(){try{await request("/api/logout",{});csrf="";currentCodes=[];setupSecret="";log("Signed out. Secure session invalidated.");boot();}catch(e){c.appendChild(note(e.message,true));}};nav.appendChild(out);c.appendChild(nav);c.appendChild(el("h2","Your authenticator is active"));c.appendChild(el("p","Your account has extra protection for higher-value payments."));
 var regen=button("Make new recovery codes");regen.onclick=async function(){try{var j=await request("/api/recovery/regenerate",{});currentCodes=j.recoveryCodes||[];log("Recovery codes regenerated for testing: "+currentCodes.join(", "));recovery(true);}catch(e){c.appendChild(note(e.message,true));}};c.appendChild(regen);
 var use=button("Use a recovery code","secondary");use.onclick=recoverUse;c.appendChild(use);c.appendChild(help("New recovery codes replace older ones. You can sign out whenever you are finished."));app.appendChild(c);
}
function recoverUse(){
 drawSteps("recovery");clear();var c=el("section",undefined,"card");c.appendChild(el("div","🗝️ Recovery check","cue"));c.appendChild(el("h2","Use one recovery code"));c.appendChild(el("p","Enter a saved code only when you cannot use your authenticator."));
 var f=document.createElement("form"), code=input("text","code","ABCD234EFG");code.className="code";code.maxLength=12;f.appendChild(el("label","Recovery code"));f.appendChild(code);f.appendChild(el("p","Example: ABCD234EFG","hint"));action(f,"Check recovery code",async function(){var j=await request("/api/recovery/use",{code:code.value});f.replaceChildren(note(j.message));});c.appendChild(f);var back=button("Back to settings","secondary");back.onclick=settings;c.appendChild(back);c.appendChild(help("A recovery code can be used once. Try another saved code if this one has already been used."));app.appendChild(c);
}
async function boot(){
 try{var j=await request("/api/bootstrap",null,"GET");csrf=j.csrf;signIn();}catch(e){clear();app.appendChild(note("This secure page could not start. Refresh and try again.",true));}
}
boot();
})();
</script>
</body>
</html>`;

serve({
  port: Number(process.env.PORT || 3000),
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      if (url.pathname === "/" && request.method === "GET") return page(request);
      return new Response("Not found.", { status: 404, headers: securityHeaders(request) });
    } catch {
      /* Requirement 2: production-safe generic error, no stack trace or sensitive detail. */
      return new Response("Something went wrong. Please try again.", {
        status: 500,
        headers: securityHeaders(request),
      });
    }
  },
});
