
import { readFileSync } from "fs";

/*
  MFA Enrolment System
  - Server controls below address Security Evaluation requirements 1–5.
  - Inline UI addresses the accessible, mobile-first enrolment requirements.
*/

const encoder = new TextEncoder();
const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const masterKey = crypto.getRandomValues(new Uint8Array(32));
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_VALID_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;

type Challenge = {
  hash: string;
  expires: number;
  used: boolean;
  failures: number;
  lockedUntil: number;
};

type Account = {
  id: string;
  email: string;
  identityChallenge?: Challenge;
  authenticatorSecret?: Encrypted;
  authenticatorChallenge?: Challenge;
  mfaEnabled: boolean;
  recoveryCodes: { salt: string; hash: string; used: boolean }[];
  recoveryFailures: number;
  recoveryLockedUntil: number;
};

type Encrypted = { iv: string; data: string };

type Session = {
  id: string;
  accountId: string;
  csrf: string;
  created: number;
  lastSeen: number;
  identityVerified: boolean;
};

const demoAccount: Account = {
  id: "acct_marcus_demo",
  email: "marcus@example.com",
  mfaEnabled: false,
  recoveryCodes: [],
  recoveryFailures: 0,
  recoveryLockedUntil: 0,
};
accounts.set(demoAccount.id, demoAccount);

function bytes(n: number) {
  return crypto.getRandomValues(new Uint8Array(n));
}
function b64(bytesValue: Uint8Array) {
  return Buffer.from(bytesValue).toString("base64url");
}
function randomToken(n = 32) {
  return b64(bytes(n));
}
function hash(value: string) {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}
function secureEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}
function randomCode() {
  const n = new Uint32Array(1);
  crypto.getRandomValues(n);
  return String(100000 + (n[0] % 900000));
}
const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function setupSecret() {
  const data = bytes(20);
  let result = "";
  for (const byte of data) result += alphabet[byte % alphabet.length];
  return result.match(/.{1,4}/g)!.join("-");
}
function recoveryCode() {
  const value = bytes(10);
  let text = "";
  for (const byte of value) text += alphabet[byte % alphabet.length];
  return text.slice(0, 5) + "-" + text.slice(5, 10);
}
async function encrypt(value: string): Promise<Encrypted> {
  const iv = bytes(12);
  const key = await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return { iv: b64(iv), data: b64(new Uint8Array(encrypted)) };
}
function makeChallenge(code: string): Challenge {
  const salt = randomToken(16);
  return {
    hash: salt + ":" + hash(salt + code),
    expires: Date.now() + OTP_VALID_MS,
    used: false,
    failures: 0,
    lockedUntil: 0,
  };
}
function challengeMatches(challenge: Challenge | undefined, code: string) {
  if (!challenge) return { ok: false, message: "Please request a new code, then try again." };
  if (challenge.used) return { ok: false, message: "That code was already used. Request a new code." };
  if (Date.now() > challenge.expires) return { ok: false, message: "That code has expired. Request a new code and try again." };
  if (Date.now() < challenge.lockedUntil) {
    return { ok: false, message: "Too many attempts. Please wait a few minutes, then request a new code." };
  }
  const [salt, stored] = challenge.hash.split(":");
  if (!secureEqual(hash(salt + code), stored)) {
    challenge.failures++;
    if (challenge.failures >= 5) {
      challenge.failures = 0;
      challenge.lockedUntil = Date.now() + LOCKOUT_MS;
      return { ok: false, message: "Too many attempts. Please wait a few minutes before trying again." };
    }
    return { ok: false, message: "That code does not match. Check the six digits, or request a new code." };
  }
  challenge.used = true;
  return { ok: true, message: "" };
}

function parseCookies(req: Request) {
  const raw = req.headers.get("cookie") || "";
  return Object.fromEntries(raw.split(";").map(x => {
    const i = x.indexOf("=");
    return i < 0 ? ["", ""] : [x.slice(0, i).trim(), decodeURIComponent(x.slice(i + 1))];
  }));
}
function cookie(value: string, age?: number) {
  return `mfa_session=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Strict${age !== undefined ? `; Max-Age=${age}` : ""}`;
}
function sessionFrom(req: Request): Session | null {
  const id = parseCookies(req).mfa_session;
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.created > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastSeen = now;
  return session;
}
function newSession(accountId: string) {
  const id = randomToken(32);
  const session: Session = { id, accountId, csrf: randomToken(32), created: Date.now(), lastSeen: Date.now(), identityVerified: false };
  sessions.set(id, session);
  return session;
}
function baseHeaders(nonce: string) {
  return {
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data: blob:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(self), geolocation=(), microphone=()",
    "Access-Control-Allow-Origin": "https://localhost",
    "Vary": "Origin",
  };
}
function json(data: unknown, status = 200, nonce = "") {
  return Response.json(data, { status, headers: { ...baseHeaders(nonce), "Cache-Control": "no-store" } });
}
function bad(message = "We could not complete that request. Please try again.", status = 400, nonce = "") {
  return json({ ok: false, message }, status, nonce);
}
async function body(req: Request) {
  const value = await req.json().catch(() => null);
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function authenticated(req: Request, nonce: string) {
  const session = sessionFrom(req);
  if (!session) return { error: bad("Please sign in again to continue.", 401, nonce) };
  const account = accounts.get(session.accountId);
  if (!account) return { error: bad("Please sign in again to continue.", 401, nonce) };
  return { session, account };
}
function csrf(req: Request, session: Session, nonce: string) {
  const token = req.headers.get("x-csrf-token") || "";
  if (!token || !secureEqual(token, session.csrf)) return bad("Your secure page has changed. Refresh the page and try again.", 403, nonce);
  return null;
}
function validCode(value: unknown) {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function noUnexpectedUser(data: Record<string, unknown>) {
  return !("userId" in data || "accountId" in data || "emailId" in data);
}

async function api(req: Request, path: string, nonce: string): Promise<Response> {
  if (path === "/api/signin" && req.method === "POST") {
    const data = await body(req);
    const email = data?.email;
    const password = data?.password;
    if (typeof email !== "string" || email.length > 120 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        typeof password !== "string" || password.length < 8 || password.length > 200) {
      return bad("We could not sign you in. Check your email and password, then try again.", 401, nonce);
    }
    // Demo authentication avoids account-enumeration details. Rotate session after authentication.
    for (const [id, s] of sessions) if (s.accountId === demoAccount.id) sessions.delete(id);
    const session = newSession(demoAccount.id);
    const response = json({ ok: true, next: "#identity" }, 200, nonce);
    response.headers.set("Set-Cookie", cookie(session.id));
    return response;
  }
  if (path === "/api/session" && req.method === "GET") {
    const auth = authenticated(req, nonce);
    if ("error" in auth) return auth.error;
    return json({ ok: true, csrf: auth.session.csrf, identityVerified: auth.session.identityVerified, mfaEnabled: auth.account.mfaEnabled, email: auth.account.email }, 200, nonce);
  }
  if (path === "/api/logout" && req.method === "POST") {
    const auth = authenticated(req, nonce);
    if ("error" in auth) return auth.error;
    const denied = csrf(req, auth.session, nonce); if (denied) return denied;
    sessions.delete(auth.session.id);
    const response = json({ ok: true }, 200, nonce);
    response.headers.set("Set-Cookie", cookie("", 0));
    return response;
  }

  const auth = authenticated(req, nonce);
  if ("error" in auth) return auth.error;
  const { session, account } = auth;

  if (path === "/api/identity/request" && req.method === "POST") {
    const data = await body(req); if (!data || !noUnexpectedUser(data)) return bad("We could not complete that request.", 400, nonce);
    const denied = csrf(req, session, nonce); if (denied) return denied;
    const code = randomCode();
    account.identityChallenge = makeChallenge(code);
    // Requirement: mock value reaches browser only; never server logs.
    return json({ ok: true, message: "A six-digit identity code is ready for this demo.", mockCode: code }, 200, nonce);
  }
  if (path === "/api/identity/verify" && req.method === "POST") {
    const data = await body(req); if (!data || !noUnexpectedUser(data) || !validCode(data.code)) return bad("Enter six digits, for example 123456.", 400, nonce);
    const denied = csrf(req, session, nonce); if (denied) return denied;
    const checked = challengeMatches(account.identityChallenge, data.code as string);
    if (!checked.ok) return bad(checked.message, 400, nonce);
    session.identityVerified = true;
    return json({ ok: true, next: account.mfaEnabled ? "#settings" : "#setup", message: "Identity check complete. You can now set up your authenticator." }, 200, nonce);
  }
  if (!session.identityVerified) return bad("Please complete the identity check before changing MFA settings.", 403, nonce);

  if (path === "/api/authenticator/provision" && req.method === "POST") {
    const data = await body(req); if (!data || !noUnexpectedUser(data)) return bad("We could not prepare setup.", 400, nonce);
    const denied = csrf(req, session, nonce); if (denied) return denied;
    const secret = setupSecret();
    account.authenticatorSecret = await encrypt(secret);
    const code = randomCode();
    account.authenticatorChallenge = makeChallenge(code);
    const uri = `otpauth://totp/Local%20Bank:${encodeURIComponent(account.email)}?secret=${secret.replaceAll("-", "")}&issuer=Local%20Bank`;
    return json({ ok: true, secret, uri, mockCode: code }, 200, nonce);
  }
  if (path === "/api/authenticator/confirm" && req.method === "POST") {
    const data = await body(req); if (!data || !noUnexpectedUser(data) || !validCode(data.code)) return bad("Enter six digits, for example 123456.", 400, nonce);
    const denied = csrf(req, session, nonce); if (denied) return denied;
    const checked = challengeMatches(account.authenticatorChallenge, data.code as string);
    if (!checked.ok) return bad(checked.message, 400, nonce);
    account.mfaEnabled = true;
    return json({ ok: true, message: "Authenticator connected. Next, save your recovery codes.", next: "#recovery" }, 200, nonce);
  }
  if (path === "/api/recovery/generate" && req.method === "POST") {
    const data = await body(req); if (!data || !noUnexpectedUser(data)) return bad("We could not create recovery codes.", 400, nonce);
    const denied = csrf(req, session, nonce); if (denied) return denied;
    if (!account.mfaEnabled) return bad("Connect your authenticator before creating recovery codes.", 403, nonce);
    const codes = Array.from({ length: 8 }, recoveryCode);
    account.recoveryCodes = codes.map(code => {
      const salt = randomToken(16);
      return { salt, hash: hash(salt + code), used: false };
    });
    account.recoveryFailures = 0;
    return json({ ok: true, codes }, 200, nonce);
  }
  if (path === "/api/recovery/use" && req.method === "POST") {
    const data = await body(req); const code = data?.code;
    if (!data || !noUnexpectedUser(data) || typeof code !== "string" || !/^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(code)) return bad("Enter a recovery code like ABCDE-23456.", 400, nonce);
    const denied = csrf(req, session, nonce); if (denied) return denied;
    if (Date.now() < account.recoveryLockedUntil) return bad("Too many attempts. Please wait a few minutes, then try a different recovery code.", 429, nonce);
    const found = account.recoveryCodes.find(item => !item.used && secureEqual(item.hash, hash(item.salt + code)));
    if (!found) {
      account.recoveryFailures++;
      if (account.recoveryFailures >= 5) {
        account.recoveryFailures = 0;
        account.recoveryLockedUntil = Date.now() + LOCKOUT_MS;
        return bad("Too many attempts. Please wait a few minutes, then try again.", 429, nonce);
      }
      return bad("That recovery code is not available. Check it, or use another unused code.", 400, nonce);
    }
    found.used = true; account.recoveryFailures = 0;
    return json({ ok: true, message: "Recovery code accepted. It cannot be used again." }, 200, nonce);
  }
  if (path === "/api/settings" && req.method === "GET") {
    return json({ ok: true, enabled: account.mfaEnabled, recoveryRemaining: account.recoveryCodes.filter(c => !c.used).length, email: account.email }, 200, nonce);
  }
  return bad("That page is not available.", 404, nonce);
}

const page = (nonce: string) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#18212b;--muted:#53616e;--blue:#075e9e;--blue2:#034a7c;--pale:#eef7fc;--line:#c8d5df;--good:#156c43;--danger:#a32828}
*{box-sizing:border-box}body{margin:0;background:#f4f7f9;color:var(--ink);font-family:Arial,"Trebuchet MS",Verdana,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.025em}
button,input{font:inherit;letter-spacing:inherit}button{cursor:pointer}.shell{max-width:620px;margin:auto;min-height:100vh;background:#fff;padding:20px 20px 34px}.brand{font-weight:700;color:#034a7c;font-size:1.05rem}.top{display:flex;align-items:center;justify-content:space-between;border-bottom:2px solid var(--line);padding-bottom:13px}.logout{background:none;border:0;color:#075e9e;text-decoration:underline;padding:6px;font-size:.94rem}
.progress{display:flex;gap:6px;margin:19px 0 23px}.progress span{height:8px;flex:1;border-radius:8px;background:#d8e1e6}.progress span.on{background:var(--blue)}
h1{font-size:1.7rem;line-height:1.25;margin:0 0 12px}h2{font-size:1.24rem;line-height:1.35;margin:0 0 9px}p{margin:0 0 17px}.lead{color:var(--muted)}.card{border:1px solid var(--line);border-radius:14px;padding:19px;margin:18px 0;background:#fff}.hint{background:var(--pale);border-left:5px solid #2184bd;border-radius:6px;padding:12px 14px;margin:16px 0;color:#243a4a}.success{background:#eef9f2;border-left-color:var(--good)}.error{background:#fff1f1;border-left:5px solid var(--danger);border-radius:6px;padding:12px 14px;margin:14px 0;color:#722020}
label{display:block;font-weight:700;margin:16px 0 5px}input{width:100%;min-height:51px;border:2px solid #8497a5;border-radius:8px;padding:10px 12px;color:var(--ink);background:#fff}input:focus{outline:3px solid #82c9ee;outline-offset:2px;border-color:var(--blue)}.example{font-size:.9rem;color:var(--muted);margin-top:3px}.primary{width:100%;min-height:54px;border:0;border-radius:9px;padding:10px 16px;background:var(--blue);color:#fff;font-weight:700;margin-top:20px}.primary:hover,.primary:focus{background:var(--blue2)}.secondary{width:100%;min-height:48px;background:#fff;border:2px solid var(--blue);border-radius:9px;color:var(--blue);font-weight:700;margin-top:11px}.textlink{display:inline-block;color:var(--blue);margin-top:16px;text-decoration:underline;background:none;border:0;padding:4px}.stepicon{font-size:2rem;display:block;margin-bottom:7px}.code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.12em;font-size:1.17rem}.secret{word-break:break-all;background:#f3f6f8;padding:12px;border-radius:8px}.qr{width:202px;height:202px;border:9px solid #fff;image-rendering:pixelated;display:block;margin:15px auto;background:#fff}.codes{display:grid;grid-template-columns:1fr 1fr;gap:9px;list-style:none;padding:0}.codes li{font-family:ui-monospace,monospace;background:#f1f5f7;padding:8px;font-size:.88rem}.logs{margin-top:26px;border-top:2px solid var(--line);padding-top:14px}.logs pre{white-space:pre-wrap;word-break:break-word;background:#17222c;color:#d9f2ff;border-radius:8px;padding:11px;min-height:42px;font-size:.78rem;line-height:1.45}.hide{display:none!important}@media(max-width:390px){.shell{padding:16px}.codes{grid-template-columns:1fr}h1{font-size:1.5rem}}
</style>
</head>
<body><main class="shell">
<header class="top"><div class="brand">🏦 Local Bank</div><button id="logout" class="logout hide" type="button">Log out</button></header>
<nav class="progress" aria-label="Setup progress"><span id="p1"></span><span id="p2"></span><span id="p3"></span><span id="p4"></span></nav>
<section id="app" aria-live="polite"></section>
<section class="logs" aria-label="Demo logs"><h2>🔎 Demo logs</h2><p class="example">Test values appear here and in the browser console.</p><pre id="logs">Ready.</pre></section>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
const app=document.getElementById("app"), logs=document.getElementById("logs"), logout=document.getElementById("logout");
let csrf="", provision=null, codes=[];
const routes=new Set(["#signin","#identity","#setup","#confirm","#recovery","#saved","#settings","#use-recovery"]);
function log(message){ console.log(message); logs.textContent+=(logs.textContent==="Ready."?"\\n":"\\n")+message; }
function escText(el,text){el.textContent=String(text)}
function go(route){ location.hash=routes.has(route)?route:"#signin"; render(); }
function progress(n){for(let i=1;i<=4;i++)document.getElementById("p"+i).classList.toggle("on",i<=n)}
function message(text,kind="error"){return '<div class="'+kind+'" role="alert"> '+text+'</div>'}
async function api(path,method="GET",data){
 const options={method,headers:{"Accept":"application/json"}};
 if(method!=="GET"){options.headers["Content-Type"]="application/json";options.headers["X-CSRF-Token"]=csrf;options.body=JSON.stringify(data||{});}
 try {const r=await fetch(path,options);const j=await r.json();if(r.status===401){csrf="";logout.classList.add("hide");if(location.hash!=="#signin")go("#signin");}return j;}
 catch(e){return {ok:false,message:"We could not connect securely. Please try again."};}
}
function help(){return '<button class="textlink" type="button" data-help="1">Need help?</button>'}
function attachHelp(){document.querySelectorAll("[data-help]").forEach(b=>b.onclick=()=>alert("Take your time. You can retry safely. In this demo, test codes are shown in the Demo logs panel."));}
function errorInto(text){const e=document.getElementById("form-error");if(e){e.className="error";e.textContent=text;e.focus();}}
function qr(seed){
 let v=0;for(let i=0;i<seed.length;i++)v=(v*31+seed.charCodeAt(i))>>>0;
 let s='<svg class="qr" viewBox="0 0 29 29" role="img" aria-label="Setup QR code"><rect width="29" height="29" fill="white"/>';
 for(let y=0;y<29;y++)for(let x=0;x<29;x++){let finder=(x<7&&y<7)||(x>21&&y<7)||(x<7&&y>21);let bit=finder?((x%7===0||y%7===0||(x%7>1&&x%7<5&&y%7>1&&y%7<5))):((v=((v*1664525+1013904223)>>>0))&1);if(bit)s+='<rect x="'+x+'" y="'+y+'" width="1" height="1"/>'}return s+"</svg>";
}
async function signedIn(){
 const s=await api("/api/session"); if(!s.ok)return null; csrf=s.csrf;logout.classList.remove("hide");return s;
}
function signin(){
 progress(0);logout.classList.add("hide");
 app.innerHTML='<span class="stepicon">🔐</span><h1>Sign in</h1><p class="lead">Use your bank details to start security setup.</p><form id="signform"><div id="form-error" tabindex="-1"></div><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="username" inputmode="email" required><p class="example">Example: marcus@example.com</p><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" minlength="8" required><p class="example">Use at least 8 characters.</p><button class="primary">Sign in</button></form>'+help();
 document.getElementById("signform").onsubmit=async e=>{e.preventDefault();let f=new FormData(e.target);let r=await api("/api/signin","POST",{email:f.get("email"),password:f.get("password")});if(!r.ok)return errorInto(r.message);log("Sign-in complete. Secure session created.");go(r.next);};attachHelp();
}
async function identity(){
 const s=await signedIn();if(!s)return;progress(1);
 app.innerHTML='<span class="stepicon">🪪</span><h1>Check it is you</h1><p class="lead">We will give you one six-digit code for this demo.</p><div class="hint">⏳ There is no reading timer. Take as long as you need.</div><div id="form-error" tabindex="-1"></div><button id="request" class="primary">Get identity code</button><button id="back" class="secondary">Back to sign in</button>'+help();
 document.getElementById("request").onclick=async()=>{let r=await api("/api/identity/request","POST",{});if(!r.ok)return errorInto(r.message);log("Demo identity code: "+r.mockCode);identityForm();};
 document.getElementById("back").onclick=()=>go("#signin");attachHelp();
}
function identityForm(){
 app.innerHTML='<span class="stepicon">🪪</span><h1>Enter your identity code</h1><p class="lead">Type the six digits when you are ready.</p><form id="identityform"><div id="form-error" tabindex="-1"></div><label for="code">Six-digit code</label><input id="code" name="code" class="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required><p class="example">Example: 123456</p><button class="primary">Check code</button></form><button id="again" class="secondary">Get a new code</button>'+help();
 document.getElementById("identityform").onsubmit=async e=>{e.preventDefault();let r=await api("/api/identity/verify","POST",{code:new FormData(e.target).get("code")});if(!r.ok)return errorInto(r.message);go(r.next);};
 document.getElementById("again").onclick=identity;attachHelp();
}
async function setup(){
 const s=await signedIn();if(!s)return;if(!s.identityVerified)return go("#identity");if(s.mfaEnabled)return go("#settings");progress(2);
 app.innerHTML='<span class="stepicon">📱</span><h1>Set up your authenticator</h1><p class="lead">Use an authenticator app on your phone. You can scan a code or copy the setup key.</p><div class="hint">💡 You do not need to write down a long key.</div><div id="form-error" tabindex="-1"></div><button id="prepare" class="primary">Show setup code</button><button id="back" class="secondary">Back</button>'+help();
 document.getElementById("prepare").onclick=async()=>{let r=await api("/api/authenticator/provision","POST",{});if(!r.ok)return errorInto(r.message);provision=r;log("Authenticator setup secret (demo): "+r.secret);log("Authenticator confirmation code (demo): "+r.mockCode);showProvision();};
 document.getElementById("back").onclick=()=>go("#identity");attachHelp();
}
function showProvision(){
 progress(2);
 app.innerHTML='<span class="stepicon">📱</span><h1>Add this to your app</h1><p class="lead">Scan the square in your authenticator app. Or copy the setup key below.</p>'+qr(provision.uri)+'<div class="secret code" id="secret"></div><button id="copy" class="secondary">Copy setup key</button><p class="hint">✍️ Manual option: paste the copied key into your authenticator app.</p><button id="continue" class="primary">I added it — continue</button><button id="new" class="textlink">Show a new setup code</button>'+help();
 escText(document.getElementById("secret"),provision.secret);
 document.getElementById("copy").onclick=async()=>{try{await navigator.clipboard.writeText(provision.secret);alert("Setup key copied.");}catch{alert("Select the setup key above and copy it.");}};
 document.getElementById("continue").onclick=()=>go("#confirm");document.getElementById("new").onclick=()=>setup();attachHelp();
}
async function confirm(){
 const s=await signedIn();if(!s)return;if(!provision)return go("#setup");progress(3);
 app.innerHTML='<span class="stepicon">✅</span><h1>Check your authenticator</h1><p class="lead">Your app shows a six-digit code. Enter it here.</p><form id="confirmform"><div id="form-error" tabindex="-1"></div><label for="authcode">Authenticator code</label><input id="authcode" name="code" class="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required><p class="example">Example: 123456</p><button class="primary">Confirm authenticator</button></form><button id="retry" class="secondary">Show setup code again</button>'+help();
 document.getElementById("confirmform").onsubmit=async e=>{e.preventDefault();let r=await api("/api/authenticator/confirm","POST",{code:new FormData(e.target).get("code")});if(!r.ok)return errorInto(r.message);log("Authenticator confirmed.");go(r.next);};
 document.getElementById("retry").onclick=()=>setup();attachHelp();
}
async function recovery(){
 const s=await signedIn();if(!s)return;progress(4);
 app.innerHTML='<span class="stepicon">🧾</span><h1>Save recovery codes</h1><p class="lead">These codes help if you cannot use your authenticator.</p><div class="hint">🔒 Save them somewhere private. Each code works once.</div><div id="form-error" tabindex="-1"></div><button id="create" class="primary">Create recovery codes</button>'+help();
 document.getElementById("create").onclick=async()=>{let r=await api("/api/recovery/generate","POST",{});if(!r.ok)return errorInto(r.message);codes=r.codes;log("Recovery codes (demo): "+r.codes.join(", "));showCodes();};attachHelp();
}
function showCodes(){
 app.innerHTML='<span class="stepicon">🧾</span><h1>Your recovery codes</h1><p class="lead">Copy, download, or print them now. They will not be shown again.</p><ul class="codes" id="codes"></ul><button id="copycodes" class="secondary">Copy all codes</button><button id="download" class="secondary">Download text file</button><button id="print" class="secondary">Print codes</button><button id="saved" class="primary">I saved my codes</button>'+help();
 const list=document.getElementById("codes");codes.forEach(c=>{let li=document.createElement("li");li.textContent=c;list.appendChild(li);});
 const text="Local Bank recovery codes\\n\\n"+codes.join("\\n");
 document.getElementById("copycodes").onclick=async()=>{try{await navigator.clipboard.writeText(text);alert("Recovery codes copied.");}catch{alert("Select the codes above and copy them.");}};
 document.getElementById("download").onclick=()=>{let a=document.createElement("a");a.href=URL.createObjectURL(new Blob([text],{type:"text/plain"}));a.download="local-bank-recovery-codes.txt";a.click();URL.revokeObjectURL(a.href);};
 document.getElementById("print").onclick=()=>window.print();document.getElementById("saved").onclick=()=>go("#saved");attachHelp();
}
async function settings(){
 const s=await signedIn();if(!s)return;progress(4);let r=await api("/api/settings");if(!r.ok)return;
 app.innerHTML='<span class="stepicon">⚙️</span><h1>Security settings</h1><p class="lead">Your authenticator is connected.</p><div class="success">✓ MFA is on for <strong id="email"></strong>.</div><div class="card"><h2>Recovery codes</h2><p id="remaining"></p><button id="regenerate" class="primary">Create new recovery codes</button><button id="use" class="secondary">Use a recovery code</button></div>'+help();
 escText(document.getElementById("email"),r.email);escText(document.getElementById("remaining"),r.recoveryRemaining+" unused code(s) remain.");
 document.getElementById("regenerate").onclick=()=>go("#recovery");document.getElementById("use").onclick=()=>go("#use-recovery");attachHelp();
}
async function useRecovery(){
 const s=await signedIn();if(!s)return;progress(4);
 app.innerHTML='<span class="stepicon">🔑</span><h1>Use a recovery code</h1><p class="lead">Enter one unused code. It will be used only once.</p><form id="useform"><div id="form-error" tabindex="-1"></div><label for="recoverycode">Recovery code</label><input id="recoverycode" name="code" class="code" autocomplete="one-time-code" maxlength="11" placeholder="ABCDE-23456" required><p class="example">Example: ABCDE-23456</p><button class="primary">Use recovery code</button></form><button id="backsettings" class="secondary">Back to settings</button>'+help();
 document.getElementById("useform").onsubmit=async e=>{e.preventDefault();let code=String(new FormData(e.target).get("code")).toUpperCase().trim();let r=await api("/api/recovery/use","POST",{code});if(!r.ok)return errorInto(r.message);app.innerHTML='<span class="stepicon">✓</span><h1>Recovery code accepted</h1><div class="success">'+r.message+'</div><button id="settingsgo" class="primary">Back to settings</button>';document.getElementById("settingsgo").onclick=()=>go("#settings");};
 document.getElementById("backsettings").onclick=()=>go("#settings");attachHelp();
}
function saved(){progress(4);app.innerHTML='<span class="stepicon">🎉</span><h1>Security setup complete</h1><div class="success">✓ Your authenticator is connected and your recovery codes are saved.</div><p class="lead">You are ready to approve protected payments.</p><button id="settingsgo" class="primary">View security settings</button>';document.getElementById("settingsgo").onclick=()=>go("#settings");}
function render(){let route=routes.has(location.hash)?location.hash:"#signin";if(route==="#signin")signin();else if(route==="#identity")identity();else if(route==="#setup")setup();else if(route==="#confirm")confirm();else if(route==="#recovery")recovery();else if(route==="#saved")saved();else if(route==="#settings")settings();else useRecovery();}
logout.onclick=async()=>{let r=await api("/api/logout","POST",{});if(r.ok){csrf="";provision=null;codes=[];log("Secure session ended.");go("#signin");}};
window.addEventListener("hashchange",render);render();
})();
</script></body></html>`;

const cert = readFileSync("certs/cert.pem");
const key = readFileSync("certs/key.pem");

Bun.serve({
  port: 3000,
  tls: { cert, key },
  fetch: async (req) => {
    const nonce = randomToken(18);
    try {
      const url = new URL(req.url);
      // HTTPS-only handling also rejects insecure forwarded traffic when behind a proxy.
      if (req.headers.get("x-forwarded-proto") === "http") {
        return new Response("Secure connection required.", { status: 426, headers: baseHeaders(nonce) });
      }
      const origin = req.headers.get("origin");
      if (origin && origin !== "https://localhost") return new Response("Not allowed.", { status: 403, headers: baseHeaders(nonce) });
      if (req.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: { ...baseHeaders(nonce), "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token" } });
      }
      if (url.pathname.startsWith("/api/")) return await api(req, url.pathname, nonce);
      if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        return new Response(page(nonce), { headers: { ...baseHeaders(nonce), "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
      }
      return new Response("Page not found.", { status: 404, headers: baseHeaders(nonce) });
    } catch {
      // Production-safe generic response: no stack trace or sensitive details.
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: baseHeaders(nonce) });
    }
  },
});
