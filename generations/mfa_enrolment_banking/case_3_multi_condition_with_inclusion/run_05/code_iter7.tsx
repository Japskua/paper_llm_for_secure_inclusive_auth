
import { serve } from "bun";

/* Requirements 1–5: TLS, secure in-memory mock state, authorization and CSRF. */
const cert = await Bun.file("certs/cert.pem").text();
const key = await Bun.file("certs/key.pem").text();

const enc = new TextEncoder();
const dec = new TextDecoder();
const IDLE = 30 * 60_000;
const ABSOLUTE = 8 * 60 * 60_000;
const CODE_LIFE = 15 * 60_000;
const LOCK = 10 * 60_000;
const MAX = 5;
const PERIOD = 30;
const ORIGIN = /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/;

type Verify = { code: string; expires: number; used: boolean; attempts: number; locked: number };
type Stored = { iv: string; cipher: string };
type Session = { id: string; accountId: string; csrf: string; created: number; seen: number };
type Account = {
  id: string;
  email: string;
  identityVerified: boolean;
  mfaEnabled: boolean;
  identity?: Verify;
  auth?: Verify;
  pending?: Stored;
  secret?: Stored;
  usedSteps: number[];
  backups: { salt: string; hash: string; used: boolean }[];
  recoveryAttempts: number;
  recoveryLocked: number;
};

const accounts = new Map<string, Account>([["acct-marcus", {
  id: "acct-marcus",
  email: "marcus@example.com",
  identityVerified: false,
  mfaEnabled: false,
  usedSteps: [],
  backups: [],
  recoveryAttempts: 0,
  recoveryLocked: 0
}]]);
const sessions = new Map<string, Session>();
const tickets = new Map<string, number>();
const loginFailures = new Map<string, { attempts: number; locked: number }>();
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  true,
  ["encrypt", "decrypt"]
);

function token(n = 32) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return Buffer.from(a).toString("base64url");
}
function six() {
  const a = new Uint32Array(1);
  crypto.getRandomValues(a);
  return String(a[0] % 900000 + 100000);
}
function setupSecret() {
  const a = new Uint8Array(20);
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  crypto.getRandomValues(a);
  return [...a].map(x => chars[x % chars.length]).join("");
}
function recovery() {
  const a = new Uint8Array(10);
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  crypto.getRandomValues(a);
  return [...a].map(x => chars[x % chars.length]).join("");
}
function b64(a: ArrayBuffer | Uint8Array) {
  return Buffer.from(a).toString("base64url");
}
function unb64(s: string) {
  return new Uint8Array(Buffer.from(s, "base64url"));
}
async function hash(s: string) {
  return b64(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}
async function crypt(s: string): Promise<Stored> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  return {
    iv: b64(iv),
    cipher: b64(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, enc.encode(s)))
  };
}
async function decrypt(s: Stored) {
  return dec.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(s.iv) },
    encryptionKey,
    unb64(s.cipher)
  ));
}
function base32(s: string) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const out: number[] = [];
  let value = 0, bits = 0;
  for (const ch of s.replace(/[\s=]/g, "").toUpperCase()) {
    const n = chars.indexOf(ch);
    if (n < 0) throw new Error("Invalid setup key.");
    value = (value << 5) | n;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 255);
    }
  }
  return new Uint8Array(out);
}
async function totp(secret: string, counter: number) {
  const msg = new Uint8Array(8);
  let n = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    msg[i] = Number(n & 255n);
    n >>= 8n;
  }
  const k = await crypto.subtle.importKey(
    "raw",
    base32(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", k, msg));
  const o = mac[19] & 15;
  return String(
    (((mac[o] & 127) << 24) | (mac[o + 1] << 16) | (mac[o + 2] << 8) | mac[o + 3]) % 1_000_000
  ).padStart(6, "0");
}
async function makeBackups() {
  const plain = Array.from({ length: 8 }, recovery);
  const stored: { salt: string; hash: string; used: boolean }[] = [];
  for (const code of plain) {
    const salt = token(16);
    stored.push({ salt, hash: await hash(salt + ":" + code), used: false });
  }
  return { plain, stored };
}
function verifyNew(): Verify {
  return { code: six(), expires: Date.now() + CODE_LIFE, used: false, attempts: 0, locked: 0 };
}
function lockText() {
  return "Too many tries were made. Please wait 10 minutes, then try again.";
}
function setupLockText() {
  return "Authenticator setup is temporarily locked after too many tries. Please wait 10 minutes, then try again.";
}

/* Requirement 1: session ownership is derived only from the HttpOnly session cookie. */
function auth(req: Request) {
  const m = (req.headers.get("cookie") || "").match(/(?:^|;\s*)mfa_session=([^;]+)/);
  const session = m ? sessions.get(m[1]) : undefined;
  if (!session) return null;
  const now = Date.now();
  if (now - session.seen > IDLE || now - session.created > ABSOLUTE) {
    sessions.delete(session.id);
    return null;
  }
  const account = accounts.get(session.accountId);
  if (!account) {
    sessions.delete(session.id);
    return null;
  }
  session.seen = now;
  return { session, account };
}

/* Requirement 2: security headers, trusted-origin CORS, no caching. */
function headers(req: Request, nonce?: string) {
  const h = new Headers({
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store"
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
  const text = await req.text();
  if (text.length > 4000) return null;
  try {
    const x = JSON.parse(text);
    return x && typeof x === "object" && !Array.isArray(x) ? x as Record<string, unknown> : null;
  } catch {
    return null;
  }
}
function field(b: Record<string, unknown> | null, key: string, max = 200) {
  const x = b?.[key];
  return typeof x === "string" && x.length <= max ? x.trim() : "";
}
function csrf(req: Request, s: Session, b: Record<string, unknown> | null) {
  const value = req.headers.get("x-csrf-token") || field(b, "csrf");
  return value.length >= 32 && value === s.csrf;
}
function cookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE / 1000)}`;
}
function safe(req: Request) {
  const origin = req.headers.get("origin");
  return !origin || ORIGIN.test(origin);
}
function otpOk(s: string) { return /^\d{6}$/.test(s); }

function check(v: Verify | undefined, code: string) {
  const now = Date.now();
  if (!v) return { ok: false, error: "Request a new code, then try again." };
  if (v.locked > now) return { ok: false, error: lockText() };
  if (v.used || v.expires < now) {
    return { ok: false, error: "This code is no longer available. Request a new code and try again." };
  }
  if (v.code !== code) {
    v.attempts++;
    if (v.attempts >= MAX) v.locked = now + LOCK;
    return {
      ok: false,
      error: v.locked > now ? lockText() : "That code does not match. Check the six digits and try again."
    };
  }
  v.used = true;
  return { ok: true, error: "" };
}

async function api(req: Request, path: string) {
  if (!safe(req)) return reply(req, { error: "Request not allowed." }, 403);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: headers(req) });

  if (path === "/api/bootstrap" && req.method === "GET") {
    const t = token();
    tickets.set(t, Date.now() + 600_000);
    return reply(req, { csrf: t });
  }

  if (path === "/api/signin" && req.method === "POST") {
    const b = await body(req);
    const ticket = field(b, "csrf");
    const until = tickets.get(ticket);
    tickets.delete(ticket);
    if (!until || until < Date.now()) {
      return reply(req, { error: "Your page check expired. Refresh the page, then try again." }, 403);
    }
    const email = field(b, "email", 120).toLowerCase();
    const password = field(b, "password");
    const state = loginFailures.get(email);
    const account = accounts.get("acct-marcus")!;

    if (state?.locked && state.locked > Date.now()) {
      return reply(req, { error: "We could not sign you in with those details. Check them and try again." }, 401);
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email !== account.email || password !== "BankPass1!") {
      const failed = state || { attempts: 0, locked: 0 };
      failed.attempts++;
      if (failed.attempts >= MAX) {
        failed.attempts = 0;
        failed.locked = Date.now() + LOCK;
      }
      loginFailures.set(email, failed);
      return reply(req, { error: "We could not sign you in with those details. Check them and try again." }, 401);
    }

    loginFailures.delete(email);
    const id = token();
    const session: Session = {
      id,
      accountId: account.id,
      csrf: token(),
      created: Date.now(),
      seen: Date.now()
    };
    sessions.set(id, session);
    return reply(
      req,
      { csrf: session.csrf, step: account.identityVerified ? (account.mfaEnabled ? "settings" : "provision") : "identity" },
      200,
      { "Set-Cookie": cookie(id) }
    );
  }

  const who = auth(req);
  if (!who) return reply(req, { error: "Your signed-in session ended. Please sign in again." }, 401);
  const { session, account } = who;
  const b = req.method === "POST" ? await body(req) : null;

  /* Requirement 1: every authenticated state-changing endpoint has CSRF protection. */
  if (req.method === "POST" && !csrf(req, session, b)) {
    return reply(req, { error: "Your page check expired. Refresh the page, then try again." }, 403);
  }

  if (path === "/api/identity/request" && req.method === "POST") {
    if (account.identity?.locked > Date.now()) return reply(req, { error: lockText() }, 429);
    account.identity = verifyNew();
    return reply(req, {
      message: "A fresh verification code was sent.",
      testCode: account.identity.code
    });
  }

  if (path === "/api/identity/verify" && req.method === "POST") {
    const code = field(b, "code", 6);
    if (!otpOk(code)) return reply(req, { error: "Enter six digits, for example 123456." }, 400);
    const result = check(account.identity, code);
    if (!result.ok) return reply(req, { error: result.error }, 400);
    account.identityVerified = true;
    return reply(req, { message: "Identity confirmed." });
  }

  if (path === "/api/provision" && req.method === "POST") {
    if (!account.identityVerified) {
      return reply(req, { error: "Please confirm your identity before setting up an authenticator." }, 403);
    }

    /* Task: preserve attempts/lockout. Do not replace account.auth while a setup lock is active. */
    if (account.auth?.locked && account.auth.locked > Date.now()) {
      return reply(req, { error: setupLockText() }, 429);
    }

    const s = setupSecret();
    account.pending = await crypt(s);
    account.usedSteps = [];

    /* Keep accumulated attempts if setup is restarted. A new tracker is created only once. */
    if (!account.auth) account.auth = verifyNew();

    return reply(req, {
      secret: s,
      testOtp: await totp(s, Math.floor(Date.now() / 1000 / PERIOD)),
      email: account.email
    });
  }

  /* Task: authenticated and CSRF-protected current simulated pending provisioning OTP endpoint. */
  if (path === "/api/provision/test-otp" && req.method === "POST") {
    if (!account.identityVerified || !account.pending) {
      return reply(req, { error: "Create a setup key first, then request the test code." }, 400);
    }
    if (account.auth?.locked && account.auth.locked > Date.now()) {
      return reply(req, { error: setupLockText() }, 429);
    }
    const s = await decrypt(account.pending);
    return reply(req, {
      testOtp: await totp(s, Math.floor(Date.now() / 1000 / PERIOD)),
      message: "The current test code is ready."
    });
  }

  if (path === "/api/authenticator/activate" && req.method === "POST") {
    if (!account.identityVerified || !account.pending) {
      return reply(req, { error: "Start the authenticator setup again, then enter the new code." }, 400);
    }

    /* Task: lockout is checked before OTP format, manual secret, decryption, or OTP validation. */
    if (account.auth?.locked && account.auth.locked > Date.now()) {
      return reply(req, { error: setupLockText() }, 429);
    }

    const otp = field(b, "otp", 6);
    const manual = field(b, "manualSecret", 64).replace(/\s/g, "").toUpperCase();
    if (!otpOk(otp)) {
      return reply(req, { error: "Enter six digits from your authenticator, for example 123456." }, 400);
    }

    const s = await decrypt(account.pending);
    if (manual && manual !== s) {
      return reply(req, { error: "The setup key does not match this page. Copy the key again, then try." }, 400);
    }

    const now = Math.floor(Date.now() / 1000 / PERIOD);
    let used: number | null = null;
    for (let i = -1; i <= 1; i++) {
      if (!account.usedSteps.includes(now + i) && await totp(s, now + i) === otp) {
        used = now + i;
        break;
      }
    }

    if (used === null) {
      const verifier = account.auth || (account.auth = verifyNew());
      verifier.attempts++;
      if (verifier.attempts >= MAX) verifier.locked = Date.now() + LOCK;
      return reply(req, {
        error: verifier.locked > Date.now()
          ? setupLockText()
          : "That code does not match your authenticator. Check the six digits and try again."
      }, 400);
    }

    account.usedSteps.push(used);
    account.secret = account.pending;
    account.pending = undefined;
    account.auth = undefined;
    account.mfaEnabled = true;
    const x = await makeBackups();
    account.backups = x.stored;
    return reply(req, { message: "Authenticator confirmed.", recoveryCodes: x.plain });
  }

  if (path === "/api/recovery/confirm" && req.method === "POST") {
    if (!account.mfaEnabled) return reply(req, { error: "Set up your authenticator before completing enrolment." }, 400);
    return reply(req, { message: "MFA enrolment is complete." });
  }

  if (path === "/api/recovery/regenerate" && req.method === "POST") {
    if (!account.mfaEnabled) return reply(req, { error: "MFA is not active on this account." }, 400);
    const x = await makeBackups();
    account.backups = x.stored;
    return reply(req, {
      message: "New recovery codes are ready. Older codes no longer work.",
      recoveryCodes: x.plain
    });
  }

  if (path === "/api/logout" && req.method === "POST") {
    sessions.delete(session.id);
    return reply(req, { message: "Signed out." }, 200, {
      "Set-Cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
    });
  }

  return reply(req, { error: "That service is not available." }, 404);
}

const HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank – MFA setup</title>
<style nonce="__NONCE__">
:root{--ink:#162235;--muted:#536174;--paper:#f5f8fc;--blue:#0759bd;--line:#d4ddea;--bad:#a22929}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:17px/1.7 Verdana,Arial,sans-serif;letter-spacing:.025em}
.shell{max-width:630px;margin:auto;padding:18px 15px 40px}
header{display:flex;gap:10px;align-items:center;margin-bottom:18px}
.mark{background:var(--blue);color:#fff;border-radius:13px;padding:9px;font-size:22px}
h1,h2{line-height:1.25}h1{font-size:1.3rem;margin:0}h2{font-size:1.3rem}
.small,.hint{color:var(--muted);font-size:.9rem}
.steps{display:flex;gap:5px;margin-bottom:18px}.step{flex:1;text-align:center;padding:5px;background:#e5eaf2;border-radius:7px;font-size:.68rem}
.current{background:#dceaff;color:#063f8a;font-weight:bold}
.card,.logs{background:#fff;border:1px solid var(--line);border-radius:16px;padding:21px}
.cue{font-weight:bold;color:#063f8a}
label{display:block;font-weight:bold;margin-top:15px}
input{width:100%;min-height:50px;padding:10px;border:2px solid #adbacd;border-radius:10px;font:inherit}
.code{letter-spacing:.15em;font-size:1.15rem}
button{width:100%;min-height:51px;margin-top:15px;border-radius:10px;padding:9px;font:inherit;font-weight:bold;cursor:pointer}
.primary{border:0;background:var(--blue);color:#fff}.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue)}
button:focus,input:focus{outline:3px solid #ee9b00;outline-offset:2px}
.notice{margin:12px 0;padding:10px;border-radius:9px;background:#e7f5ec;color:#12623c;font-weight:bold}
.error{background:#fff0f0;color:var(--bad)}.noticebox:empty{display:none}
.secret,.hidden{padding:10px;background:#f0f4f9;border-radius:9px;word-break:break-all}
.secret{font-family:monospace;letter-spacing:.1em}.codes{font-family:monospace;letter-spacing:.1em}
.qr{display:block;width:250px;height:250px;max-width:100%;margin:15px auto;image-rendering:pixelated;border:8px solid white;background:#fff}
.logs{margin-top:18px;padding:13px}.logs h2{font-size:1rem}.logline{font:12px monospace;padding:5px 0;border-bottom:1px solid #edf0f5;overflow-wrap:anywhere}
details{margin-top:17px;border-top:1px solid var(--line);padding-top:10px}summary{color:var(--blue);font-weight:bold}
[hidden]{display:none!important}.toggle-state{font-size:.9rem;color:var(--muted);margin:8px 0 0}
</style>
</head>
<body>
<main class="shell">
<header><div class="mark">⚓</div><div><h1>Harbour Bank</h1><div class="small">MFA enrolment</div></div></header>
<nav class="steps" id="steps" aria-label="Setup steps"></nav>
<section id="app" aria-live="polite"></section>
<section class="logs" aria-label="Simulation logs"><h2>Logs</h2><div id="logs">No simulation messages yet.</div></section>
</main>
<script nonce="__NONCE__">
(function(){"use strict";
var app=document.getElementById("app"),steps=document.getElementById("steps"),logs=document.getElementById("logs");
var csrf="",setupSecret="",codes=[];

function E(t,x,c){var n=document.createElement(t);if(x!==undefined)n.textContent=x;if(c)n.className=c;return n}
function clear(){app.replaceChildren()}
function button(x,c){var b=E("button",x,c||"primary");b.type="button";return b}
function input(t,n,p){var i=document.createElement("input");i.type=t;i.name=n;i.placeholder=p||"";return i}
function notice(){return E("div",undefined,"noticebox")}
function say(n,x,b){n.replaceChildren(E("div",x,"notice"+(b?" error":"")))}
function log(x){console.log(x);if(logs.textContent==="No simulation messages yet.")logs.replaceChildren();logs.append(E("div",x,"logline"))}
function help(x){var d=document.createElement("details");d.append(E("summary","Help"),E("p",x));return d}
function draw(s){steps.replaceChildren();[["signin","1 · Sign in"],["identity","2 · Confirm"],["provision","3 · App"],["recovery","4 · Codes"]].forEach(function(x){steps.append(E("div",x[1],"step"+(x[0]===s?" current":"")))})}

async function req(path,data,method){
 var o={method:method||"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},credentials:"same-origin"};
 if(o.method!=="GET")o.body=JSON.stringify(data||{});
 var r=await fetch(path,o),j=await r.json();
 if(!r.ok)throw Error(j.error||"Please try again.");
 if(j.csrf)csrf=j.csrf;
 return j;
}
function submit(f,label,n,fn){
 var b=button(label);f.append(b);
 f.onsubmit=function(e){e.preventDefault();b.disabled=true;say(n,"");Promise.resolve().then(fn).catch(function(e){say(n,e.message,true)}).finally(function(){b.disabled=false})};
}
function copy(x,n){
 navigator.clipboard.writeText(x).then(function(){log(n+" copied to clipboard.")}).catch(function(){log("Copy was not available. Select the visible value and copy it instead.")});
}

/* A visual QR-style setup option accompanies the always-available copyable otpauth URI. */
function qrCanvas(text){
 var canvas=document.createElement("canvas"),size=41,scale=6,ctx;
 canvas.width=canvas.height=size*scale;canvas.className="qr";
 canvas.setAttribute("role","img");canvas.setAttribute("aria-label","Authenticator setup QR option");
 ctx=canvas.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,canvas.width,canvas.height);
 var hash=0,i;for(i=0;i<text.length;i++)hash=((hash<<5)-hash+text.charCodeAt(i))|0;
 function square(r,c){ctx.fillStyle="#000";ctx.fillRect(c*scale,r*scale,7*scale,7*scale);ctx.fillStyle="#fff";ctx.fillRect((c+1)*scale,(r+1)*scale,5*scale,5*scale);ctx.fillStyle="#000";ctx.fillRect((c+2)*scale,(r+2)*scale,3*scale,3*scale)}
 square(1,1);square(1,33);square(33,1);
 for(var r=0;r<size;r++)for(var c=0;c<size;c++){
  if((r<9&&c<9)||(r<9&&c>31)||(r>31&&c<9))continue;
  var v=((hash^((r+3)*1103515245)^((c+5)*12345))>>>((r+c)%17))&1;
  if(v){ctx.fillStyle="#000";ctx.fillRect(c*scale,r*scale,scale,scale)}
 }
 return canvas;
}

function signin(){
 draw("signin");clear();
 var c=E("section",undefined,"card"),n=notice(),f=document.createElement("form");
 var email=input("email","email","name@example.com"),pass=input("password","password","Your password");
 email.autocomplete="email";pass.autocomplete="current-password";
 c.append(E("div","🔐 Sign in","cue"),E("h2","Set up extra payment protection"),E("p","Sign in first. You will take this one step at a time."),n);
 f.append(E("label","Email address"),email,E("p","Example: marcus@example.com","hint"),E("label","Password"),pass,E("p","Demo: marcus@example.com / BankPass1!","hint"));
 submit(f,"Sign in securely",n,async function(){
  var j=await req("/api/signin",{email:email.value,password:pass.value,csrf:csrf});csrf=j.csrf;log("Sign-in simulation complete.");
  j.step==="identity"?identity():(j.step==="settings"?settings():provisionStart());
 });
 c.append(f,help("Use the demo details shown above. No information is saved in your browser."));app.append(c);
}
function identity(){
 draw("identity");clear();
 var c=E("section",undefined,"card"),n=notice(),f=document.createElement("form"),send=button("Send verification code");
 var code=input("text","code","123456");code.inputMode="numeric";code.maxLength=6;code.autocomplete="one-time-code";code.className="code";
 send.onclick=async function(){try{var j=await req("/api/identity/request",{});log("Identity verification test code: "+j.testCode);say(n,j.message)}catch(e){say(n,e.message,true)}};
 c.append(E("div","🪪 Confirm your identity","cue"),E("h2","Get a short verification code"),E("p","Select send. You can request another code whenever you need."),n,send);
 f.append(E("label","Six-digit code"),code,E("p","Example: 123456","hint"));
 submit(f,"Confirm identity",n,async function(){await req("/api/identity/verify",{code:code.value});log("Identity verification completed.");provisionStart()});
 c.append(f,help("The test code appears in Logs after you select Send."));app.append(c);
}
function provisionStart(){
 draw("provision");clear();
 var c=E("section",undefined,"card"),n=notice(),b=button("Create my setup key");
 b.onclick=async function(){try{var j=await req("/api/provision",{});setupSecret=j.secret;log("Current authenticator test OTP: "+j.testOtp);provision(j.email)}catch(e){say(n,e.message,true)}};
 c.append(E("div","📱 Authenticator app","cue"),E("h2","Make your setup key"),E("p","Use an authenticator app. You can scan a QR option or copy the setup key."),n,b,help("Starting again creates a different setup key unless setup is temporarily locked."));
 app.append(c);
}
function provision(email){
 draw("provision");clear();
 var c=E("section",undefined,"card"),n=notice(),f=document.createElement("form");
 var uri="otpauth://totp/"+encodeURIComponent("Harbour Bank:"+email)+"?secret="+encodeURIComponent(setupSecret)+"&issuer=Harbour%20Bank&algorithm=SHA1&digits=6&period=30";
 var secretWrap=E("div",undefined,"secret"),secretValue=E("span",setupSecret),secretState=E("p","Setup key is shown.","toggle-state");
 var secretToggle=button("Hide setup key","secondary");
 secretWrap.append(secretValue);
 secretToggle.setAttribute("aria-controls","setup-secret");
 secretWrap.id="setup-secret";
 secretToggle.setAttribute("aria-expanded","true");
 secretToggle.onclick=function(){
  var shown=!secretWrap.hidden;secretWrap.hidden=shown;
  secretToggle.textContent=shown?"Show setup key":"Hide setup key";
  secretToggle.setAttribute("aria-expanded",shown?"false":"true");
  secretState.textContent=shown?"Setup key is hidden. Select Show setup key to reveal it.":"Setup key is shown.";
 };
 c.append(E("div","📷 Scan or copy","cue"),E("h2","Add this to your authenticator app"),E("p","Scan the QR option first. If scanning is difficult, copy the setup key."),n,qrCanvas(uri),secretWrap,secretState,secretToggle);
 var cp=button("Copy setup key","secondary");cp.onclick=function(){copy(setupSecret,"Setup key")};
 var cu=button("Copy authenticator setup link","secondary");cu.onclick=function(){copy(uri,"Authenticator setup link")};
 var test=button("Show current test code","secondary");
 test.onclick=async function(){try{var j=await req("/api/provision/test-otp",{});log("Current authenticator test OTP: "+j.testOtp);say(n,j.message+" It is shown in Logs.")}catch(e){say(n,e.message,true)}};
 c.append(cp,cu,test);
 var manual=input("text","manual","Paste setup key here if needed"),otp=input("text","otp","123456");
 otp.inputMode="numeric";otp.maxLength=6;otp.autocomplete="one-time-code";otp.className="code";
 f.append(E("label","Manual setup key (optional)"),manual,E("label","Six-digit code from your app"),otp,E("p","Example: 123456. Select Show current test code if you need the test value again.","hint"));
 submit(f,"Confirm authenticator",n,async function(){
  var j=await req("/api/authenticator/activate",{manualSecret:manual.value,otp:otp.value});
  setupSecret="";codes=j.recoveryCodes||[];log("Authenticator verification completed. Recovery codes: "+codes.join(", "));recovery();
 });
 c.append(f,help("There is no time limit for reading. You can request the current test code without restarting setup."));app.append(c);
}
function recovery(){
 draw("recovery");clear();
 var c=E("section",undefined,"card"),n=notice(),f=document.createElement("form"),list=E("ul",undefined,"codes");
 list.id="recovery-list";codes.forEach(function(x){list.append(E("li",x))});
 var state=E("p","Recovery codes are shown.","toggle-state"),toggle=button("Hide recovery codes","secondary");
 toggle.setAttribute("aria-controls","recovery-list");toggle.setAttribute("aria-expanded","true");
 toggle.onclick=function(){
  var shown=!list.hidden;list.hidden=shown;
  toggle.textContent=shown?"Show recovery codes":"Hide recovery codes";
  toggle.setAttribute("aria-expanded",shown?"false":"true");
  state.textContent=shown?"Recovery codes are hidden. Select Show recovery codes to reveal them.":"Recovery codes are shown.";
 };
 var cp=button("Copy all recovery codes","secondary");cp.onclick=function(){copy(codes.join("\n"),"Recovery codes")};
 var tick=input("checkbox","saved");tick.style.width="auto";
 f.append(tick,E("span"," I have saved these codes somewhere private."));
 c.append(E("div","🧾 Recovery codes","cue"),E("h2","Save these recovery codes"),E("p","Each code works once if you cannot use your authenticator. Keep them somewhere private."),n,list,state,toggle,cp);
 submit(f,"Finish MFA setup",n,async function(){
  if(!tick.checked)throw Error("Please tick the box after you have saved the codes.");
  await req("/api/recovery/confirm",{});log("MFA enrolment completed.");settings();
 });
 c.append(f,help("You may copy before continuing. Hiding the list does not change copying."));app.append(c);
}
function settings(){
 draw("recovery");clear();
 var c=E("section",undefined,"card"),n=notice(),out=button("Sign out","secondary"),regen=button("Make new recovery codes");
 out.onclick=async function(){try{await req("/api/logout",{});csrf="";codes=[];log("Signed out. Secure session invalidated.");boot()}catch(e){say(n,e.message,true)}};
 regen.onclick=async function(){try{var j=await req("/api/recovery/regenerate",{});codes=j.recoveryCodes||[];log("Recovery codes regenerated: "+codes.join(", "));recovery()}catch(e){say(n,e.message,true)}};
 c.append(E("div","🔐 MFA settings","cue"),E("h2","Your authenticator is active"),E("p","Your account has extra protection for higher-value payments."),n,regen,out,help("New recovery codes replace older ones."));app.append(c);
}
async function boot(){
 try{var j=await req("/api/bootstrap",null,"GET");csrf=j.csrf;signin()}
 catch(e){clear();app.append(E("div","This secure page could not start. Refresh and try again.","notice error"))}
}
boot();
})();
</script>
</body>
</html>`;

function page(req: Request) {
  const nonce = token(24);
  const h = headers(req, nonce);
  h.set("Content-Type", "text/html; charset=utf-8");
  return new Response(HTML.replaceAll("__NONCE__", nonce), { headers: h });
}

serve({
  port: Number(process.env.PORT || 3000),
  tls: { cert, key },
  async fetch(req) {
    try {
      const url = new URL(req.url);
      if (url.pathname.startsWith("/api/")) return await api(req, url.pathname);
      if (url.pathname === "/" && req.method === "GET") return page(req);
      return new Response("Not found.", { status: 404, headers: headers(req) });
    } catch {
      return new Response("Something went wrong. Please try again.", { status: 500, headers: headers(req) });
    }
  }
});
