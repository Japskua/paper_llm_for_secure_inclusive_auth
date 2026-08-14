
import { readFileSync } from "fs";

/* Requirements 1–5: owner-bound server sessions, CSRF, TLS, secure headers,
   encrypted authenticator secret, hashed recovery codes, validation and limits. */
const accounts = new Map<string, Account>();
const sessions = new Map<string, Session>();
const loginTokens = new Map<string, number>();
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const encoder = new TextEncoder(), decoder = new TextDecoder();
const base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const recoveryChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const trustedOrigins = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000"
]);

const IDLE_TIMEOUT = 30 * 60_000;
const ABSOLUTE_TIMEOUT = 8 * 60 * 60_000;
const CODE_LIFETIME = 15 * 60_000;
const LOCK_TIME = 10 * 60_000;
const TOTP_STEP = 30_000;

type Challenge = {
  hash: string;
  expires: number;
  used: boolean;
  failures: number;
  lockedUntil: number;
};

type EncryptedSecret = { iv: string; data: string };

type Recovery = { salt: string; hash: string; used: boolean };

type Account = {
  id: string;
  email: string;
  identity?: Challenge;
  secret?: EncryptedSecret;
  mfa: boolean;
  authenticatorFailures: number;
  authenticatorLockedUntil: number;
  usedTotpSteps: Set<number>;
  recoveries: Recovery[];
  recoveryFailures: number;
  recoveryLockedUntil: number;
};

type Session = {
  id: string;
  accountId: string;
  csrf: string;
  created: number;
  seen: number;
  identityVerified: boolean;
};

const marcus: Account = {
  id: "acct_marcus_demo",
  email: "marcus@example.com",
  mfa: false,
  authenticatorFailures: 0,
  authenticatorLockedUntil: 0,
  usedTotpSteps: new Set(),
  recoveries: [],
  recoveryFailures: 0,
  recoveryLockedUntil: 0
};
accounts.set(marcus.id, marcus);

const random = (bytes = 32) =>
  Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");

const sha256 = (value: string) =>
  new Bun.CryptoHasher("sha256").update(value).digest("hex");

function timingSafeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let value = 0;
  for (let i = 0; i < a.length; i++) value |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return value === 0;
}

function cleanObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const forbidden = ["id", "userId", "accountId", "emailId", "redirect", "next"];
  return !forbidden.some((key) => key in (value as Record<string, unknown>));
}

function validEmail(value: unknown) {
  return typeof value === "string" &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPassword(value: unknown) {
  return typeof value === "string" && value.length > 0 && value.length <= 128;
}

function validSixDigits(value: unknown) {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function validRecoveryCode(value: unknown) {
  return typeof value === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(value);
}

function makeSeed() {
  return [...crypto.getRandomValues(new Uint8Array(32))]
    .map((value) => base32[value & 31]).join("");
}

function groupSeed(value: string) {
  return value.match(/.{1,4}/g)!.join("-");
}

function makeRecoveryCode() {
  const value = [...crypto.getRandomValues(new Uint8Array(10))]
    .map((byte) => recoveryChars[byte & 31]).join("");
  return value.slice(0, 5) + "-" + value.slice(5);
}

/* Deterministic mock identity value: usable in the normal demo flow. */
function identityCode(sessionId: string) {
  return String(parseInt(sha256("identity-demo|" + sessionId).slice(0, 12), 16) % 1_000_000)
    .padStart(6, "0");
}

function makeChallenge(code: string): Challenge {
  const salt = random(24);
  return {
    hash: salt + ":" + sha256(salt + code),
    expires: Date.now() + CODE_LIFETIME,
    used: false,
    failures: 0,
    lockedUntil: 0
  };
}

function checkChallenge(challenge: Challenge | undefined, code: string) {
  if (!challenge) return "Request a new code, then try again.";
  if (challenge.used) return "That code was already used. Request a new code.";
  if (Date.now() > challenge.expires) return "That code has expired. Request a new code.";
  if (Date.now() < challenge.lockedUntil) {
    return "Too many attempts. Please wait a few minutes, then request a new code.";
  }

  const [salt, storedHash] = challenge.hash.split(":");
  if (!timingSafeEqual(sha256(salt + code), storedHash)) {
    challenge.failures++;
    if (challenge.failures >= 5) {
      challenge.failures = 0;
      challenge.lockedUntil = Date.now() + LOCK_TIME;
      return "Too many attempts. Please wait a few minutes before trying again.";
    }
    return "That code does not match. Check the six digits, or request a new code.";
  }

  challenge.used = true;
  return "";
}

async function encryptSecret(value: string): Promise<EncryptedSecret> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return {
    iv: Buffer.from(iv).toString("base64url"),
    data: Buffer.from(encrypted).toString("base64url")
  };
}

async function decryptSecret(value: EncryptedSecret) {
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(value.iv, "base64url") },
    key,
    Buffer.from(value.data, "base64url")
  );
  return decoder.decode(decrypted);
}

function decodeBase32(value: string) {
  const out: number[] = [];
  let bits = 0, buffer = 0;
  for (const character of value) {
    const next = base32.indexOf(character);
    buffer = (buffer << 5) | next;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

async function totp(secret: string, step: number) {
  const counter = new Uint8Array(8);
  let number = BigInt(step);
  for (let index = 7; index >= 0; index--) {
    counter[index] = Number(number & 255n);
    number >>= 8n;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = signature[19] & 15;
  const code = ((signature[offset] & 127) << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];
  return String(code % 1_000_000).padStart(6, "0");
}

/* Requirement 2: CSP, HSTS, anti-clickjacking, nosniff, no cache. */
function securityHeaders(nonce: string) {
  return {
    "Content-Security-Policy":
      "default-src 'self'; script-src 'nonce-" + nonce +
      "'; style-src 'nonce-" + nonce +
      "'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Vary": "Origin"
  };
}

function json(data: unknown, status = 200, nonce = "") {
  return Response.json(data, { status, headers: securityHeaders(nonce) });
}

function failure(message = "We could not complete that request. Please try again.", status = 400, nonce = "") {
  return json({ ok: false, message }, status, nonce);
}

function cookies(request: Request) {
  return Object.fromEntries((request.headers.get("cookie") || "").split(";").map((part) => {
    const index = part.indexOf("=");
    return index < 0
      ? ["", ""]
      : [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1))];
  }));
}

function sessionCookie(value: string, age?: number) {
  return "mfa_session=" + encodeURIComponent(value) +
    "; Path=/; HttpOnly; Secure; SameSite=Strict" +
    (age === undefined ? "" : "; Max-Age=" + age);
}

function bootstrapCookie(value: string, age = 600) {
  return "signin_csrf=" + encodeURIComponent(value) +
    "; Path=/; Secure; SameSite=Strict; Max-Age=" + age;
}

function getSession(request: Request) {
  const id = cookies(request).mfa_session || "";
  const session = sessions.get(id);
  if (!session) return null;
  if (Date.now() - session.seen > IDLE_TIMEOUT || Date.now() - session.created > ABSOLUTE_TIMEOUT) {
    sessions.delete(session.id);
    return null;
  }
  session.seen = Date.now();
  return session;
}

function getOwner(request: Request, nonce: string) {
  const session = getSession(request);
  const account = session ? accounts.get(session.accountId) : undefined;
  return session && account
    ? { session, account }
    : { error: failure("Please sign in again to continue.", 401, nonce) };
}

function csrfValid(request: Request, session: Session, nonce: string) {
  const token = request.headers.get("x-csrf-token") || "";
  return timingSafeEqual(token, session.csrf)
    ? null
    : failure("Your secure page has changed. Refresh the page and try again.", 403, nonce);
}

async function requestData(request: Request) {
  const data = await request.json().catch(() => null);
  return cleanObject(data) ? data : null;
}

async function api(request: Request, path: string, nonce: string): Promise<Response> {
  if (path === "/api/csrf-bootstrap" && request.method === "GET") {
    const token = random();
    loginTokens.set(token, Date.now() + 10 * 60_000);
    const response = json({ ok: true, csrf: token }, 200, nonce);
    response.headers.set("Set-Cookie", bootstrapCookie(token));
    return response;
  }

  if (path === "/api/signin" && request.method === "POST") {
    const body = await requestData(request);
    const origin = request.headers.get("origin") || "";
    const token = request.headers.get("x-login-csrf") || "";
    const cookieToken = cookies(request).signin_csrf || "";
    const expires = loginTokens.get(token);
    loginTokens.delete(token);

    if (!trustedOrigins.has(origin) || !expires || expires < Date.now() || !timingSafeEqual(token, cookieToken)) {
      return failure("Please refresh the sign-in page and try again.", 403, nonce);
    }
    if (!body || !validEmail(body.email) || !validPassword(body.password)) {
      return failure("Enter a valid email address and a password of 128 characters or fewer.", 400, nonce);
    }
    if (!timingSafeEqual(String(body.email).toLowerCase(), marcus.email) ||
        !timingSafeEqual(String(body.password), "MarcusDemo!2025")) {
      return failure("We could not sign you in. Check your email and password, then try again.", 401, nonce);
    }

    for (const [id, old] of sessions) if (old.accountId === marcus.id) sessions.delete(id);
    const session: Session = {
      id: random(),
      accountId: marcus.id,
      csrf: random(),
      created: Date.now(),
      seen: Date.now(),
      identityVerified: false
    };
    sessions.set(session.id, session);
    const response = json({ ok: true, next: "#identity" }, 200, nonce);
    response.headers.set("Set-Cookie", sessionCookie(session.id));
    return response;
  }

  const owner = getOwner(request, nonce);
  if ("error" in owner) return owner.error;
  const { session, account } = owner;

  if (path === "/api/session" && request.method === "GET") {
    return json({
      ok: true,
      csrf: session.csrf,
      identityVerified: session.identityVerified,
      mfaEnabled: account.mfa,
      provisioned: !!account.secret,
      recoveryCount: account.recoveries.length
    }, 200, nonce);
  }

  if (path === "/api/settings" && request.method === "GET") {
    if (!session.identityVerified || !account.mfa) {
      return failure("Please complete security setup before viewing settings.", 403, nonce);
    }
    return json({
      ok: true,
      email: account.email,
      remaining: account.recoveries.filter((item) => !item.used).length
    }, 200, nonce);
  }

  if (request.method !== "POST") return failure("That page is not available.", 404, nonce);
  const body = await requestData(request);
  if (!body) return failure(undefined, 400, nonce);
  const csrfError = csrfValid(request, session, nonce);
  if (csrfError) return csrfError;

  if (path === "/api/logout") {
    sessions.delete(session.id);
    const response = json({ ok: true }, 200, nonce);
    response.headers.set("Set-Cookie", sessionCookie("", 0));
    return response;
  }

  if (path === "/api/identity/request") {
    const code = identityCode(session.id);
    account.identity = makeChallenge(code);
    /* Returned only to the authenticated browser's normal simulated demo flow. */
    return json({ ok: true, simulatedCode: code }, 200, nonce);
  }

  if (path === "/api/identity/verify") {
    if (!validSixDigits(body.code)) {
      return failure("Enter exactly six digits, for example 123456.", 400, nonce);
    }
    const message = checkChallenge(account.identity, String(body.code));
    if (message) return failure(message, 400, nonce);
    session.identityVerified = true;
    return json({ ok: true, next: account.mfa ? "#settings" : "#setup" }, 200, nonce);
  }

  if (!session.identityVerified) {
    return failure("Please complete the identity check before changing MFA settings.", 403, nonce);
  }

  if (path === "/api/authenticator/provision") {
    const secret = makeSeed();
    account.secret = await encryptSecret(secret);
    account.authenticatorFailures = 0;
    account.authenticatorLockedUntil = 0;
    account.usedTotpSteps.clear();

    /* Simulated OTP is returned so the browser can console.log it, never to visible logs. */
    const simulatedOtp = await totp(secret, Math.floor(Date.now() / TOTP_STEP));
    return json({
      ok: true,
      secret: groupSeed(secret),
      simulatedOtp
    }, 200, nonce);
  }

  if (path === "/api/authenticator/confirm") {
    if (!validSixDigits(body.code)) {
      return failure("Enter exactly six digits, for example 123456.", 400, nonce);
    }
    if (!account.secret) {
      return failure("Show a setup key before confirming your authenticator.", 400, nonce);
    }
    if (Date.now() < account.authenticatorLockedUntil) {
      return failure("Too many attempts. Please wait a few minutes, then try again.", 429, nonce);
    }

    const secret = await decryptSecret(account.secret);
    const currentStep = Math.floor(Date.now() / TOTP_STEP);
    let matchingStep = -1;
    for (const step of [currentStep - 1, currentStep, currentStep + 1]) {
      if (timingSafeEqual(await totp(secret, step), String(body.code))) {
        matchingStep = step;
        break;
      }
    }

    if (matchingStep < 0 || account.usedTotpSteps.has(matchingStep)) {
      account.authenticatorFailures++;
      if (account.authenticatorFailures >= 5) {
        account.authenticatorFailures = 0;
        account.authenticatorLockedUntil = Date.now() + LOCK_TIME;
        return failure("Too many attempts. Please wait a few minutes before trying again.", 429, nonce);
      }
      return failure(
        matchingStep >= 0
          ? "That authenticator code was already used. Show a new setup code and try again."
          : "That code does not match your authenticator. Check the six digits and try again.",
        400,
        nonce
      );
    }

    account.usedTotpSteps.add(matchingStep);
    account.authenticatorFailures = 0;
    account.mfa = true;
    return json({ ok: true, next: "#recovery" }, 200, nonce);
  }

  if (path === "/api/recovery/generate") {
    if (!account.mfa) {
      return failure("Connect your authenticator before creating recovery codes.", 403, nonce);
    }
    const codes = Array.from({ length: 8 }, makeRecoveryCode);
    account.recoveries = codes.map((code) => {
      const salt = random(24);
      return { salt, hash: sha256(salt + code), used: false };
    });
    return json({ ok: true, codes }, 200, nonce);
  }

  if (path === "/api/recovery/use") {
    if (!validRecoveryCode(body.code)) {
      return failure("Enter a recovery code like ABCDE-23456.", 400, nonce);
    }
    if (Date.now() < account.recoveryLockedUntil) {
      return failure("Too many attempts. Please wait a few minutes, then try another code.", 429, nonce);
    }

    const code = String(body.code);
    const found = account.recoveries.find((item) =>
      !item.used && timingSafeEqual(item.hash, sha256(item.salt + code))
    );
    if (!found) {
      account.recoveryFailures++;
      if (account.recoveryFailures >= 5) {
        account.recoveryFailures = 0;
        account.recoveryLockedUntil = Date.now() + LOCK_TIME;
        return failure("Too many attempts. Please wait a few minutes before trying again.", 429, nonce);
      }
      return failure("That recovery code is not available. Check it, or use another unused code.", 400, nonce);
    }

    found.used = true;
    account.recoveryFailures = 0;
    return json({ ok: true, message: "Recovery code accepted. It cannot be used again." }, 200, nonce);
  }

  return failure("That page is not available.", 404, nonce);
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local Bank security setup</title>
<style nonce="${nonce}">
:root{--blue:#075e9e;--ink:#17212c;--muted:#53616e;--line:#c8d5df;--soft:#eef7fc}
*{box-sizing:border-box}
body{margin:0;background:#f4f7f9;color:var(--ink);font:18px/1.7 Atkinson Hyperlegible,"OpenDyslexic","Segoe UI",Verdana,Arial,sans-serif;letter-spacing:.035em}
.shell{max-width:620px;min-height:100vh;margin:auto;padding:20px;background:#fff}
.top{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid var(--line);padding-bottom:12px}
.brand{font-weight:800;color:#034a7c}
button,input{font:inherit;letter-spacing:inherit}
button{cursor:pointer}
.link{border:0;background:none;color:var(--blue);text-decoration:underline;padding:6px}
.hide{display:none!important}
.progress{display:flex;gap:6px;margin:19px 0}
.progress i{height:8px;flex:1;background:#d8e1e6;border-radius:9px}
.progress .on{background:var(--blue)}
h1{font-size:1.7rem;line-height:1.3;margin:18px 0 8px}
h2{font-size:1.15rem}
.lead,.example{color:var(--muted)}
.hint,.success,.error{padding:13px 14px;margin:16px 0;border-radius:8px;background:var(--soft);border-left:5px solid #2184bd}
.success{background:#eef9f2;border-color:#156c43}
.error{background:#fff1f1;border-color:#8d2424;color:#702020}
label{display:block;font-weight:800;margin-top:16px}
input{width:100%;min-height:53px;border:2px solid #8497a5;border-radius:8px;padding:10px;font-size:1.08rem}
input:focus{outline:3px solid #82c9ee;outline-offset:2px}
.primary,.secondary{width:100%;min-height:54px;border-radius:9px;padding:9px;margin-top:18px;font-weight:800}
.primary{border:0;background:var(--blue);color:#fff}
.secondary{border:2px solid var(--blue);background:#fff;color:var(--blue)}
.code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.12em}
.secret{padding:14px;background:#f3f6f8;overflow-wrap:anywhere;min-height:56px}
.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:0;list-style:none}
.codes li{padding:9px;background:#f1f5f7;font-family:ui-monospace,Consolas,monospace;letter-spacing:.06em}
.logs{margin-top:28px;border-top:2px solid var(--line)}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#17222c;color:#d9f2ff;padding:12px;border-radius:8px;font:14px/1.55 ui-monospace,Consolas,monospace}
.small{font-size:.92rem}
@media(max-width:390px){.shell{padding:16px}.codes{grid-template-columns:1fr}body{font-size:17px}}
</style>
</head>
<body>
<main class="shell">
<header class="top"><span class="brand">🏦 Local Bank</span><button class="link hide" id="logout">Log out</button></header>
<nav class="progress" aria-label="Setup progress"><i id="p1"></i><i id="p2"></i><i id="p3"></i><i id="p4"></i></nav>
<section id="app" aria-live="polite"></section>
<section class="logs" aria-label="Activity logs">
<h2>🔎 Activity logs</h2>
<p class="example">General activity is shown here. Private codes are never shown.</p>
<pre id="logs">Ready.</pre>
</section>
</main>
<script nonce="${nonce}">
(function(){
"use strict";
var app=document.querySelector("#app");
var logs=document.querySelector("#logs");
var logout=document.querySelector("#logout");
var csrf="";
var loginCsrf="";
var provision=null;
var recoveryCodes=[];
var notice="";
var routes=new Set(["#signin","#identity","#setup","#confirm","#recovery","#saved","#settings","#use"]);

function esc(value){
  var node=document.createElement("span");
  node.textContent=String(value);
  return node.innerHTML;
}
function activity(message){
  console.log(message);
  logs.textContent+=(logs.textContent==="Ready."?"\\n":"\\n")+message;
}
function go(route){ location.hash=routes.has(route)?route:"#signin"; }
function progress(step){
  for(var i=1;i<5;i++) document.querySelector("#p"+i).classList.toggle("on",i<=step);
}
function help(){
  return '<p><button class="link" data-help>Need help?</button></p>';
}
function attachHelp(){
  document.querySelectorAll("[data-help]").forEach(function(button){
    button.onclick=function(){
      alert("Take your time. You can retry safely. Use the example beside each box.");
    };
  });
}
function showError(message){
  var box=document.querySelector("#form-error");
  if(box){
    box.className="error";
    box.textContent=message;
    box.focus();
  }
}
function successNotice(){
  var text=notice;
  notice="";
  return text?'<div class="success">'+esc(text)+"</div>":"";
}
async function api(path,method,body){
  method=method||"GET";
  var options={method:method,headers:{Accept:"application/json"}};
  if(method!=="GET"){
    options.headers["Content-Type"]="application/json";
    options.headers["X-CSRF-Token"]=csrf;
    options.body=JSON.stringify(body||{});
  }
  try{
    var response=await fetch(path,options);
    var result=await response.json();
    if(response.status===401){csrf="";logout.classList.add("hide");}
    return result;
  }catch(_error){
    return {ok:false,message:"We could not connect securely. Please try again."};
  }
}
async function bootstrap(){
  var result=await api("/api/csrf-bootstrap");
  if(result.ok) loginCsrf=result.csrf;
  return result;
}
async function signedIn(){
  var result=await api("/api/session");
  if(result.ok){
    csrf=result.csrf;
    logout.classList.remove("hide");
    return result;
  }
  return null;
}

function signIn(){
  progress(0);
  app.innerHTML='<h1>🔐 Sign in</h1><p class="lead">Start your security setup.</p><div class="hint">Demo email: <b>marcus@example.com</b><br>Demo password: <b>MarcusDemo!2025</b></div><form id="signin-form"><div id="form-error" tabindex="-1"></div><label>Email address</label><input name="email" type="email" maxlength="254" autocomplete="username" placeholder="name@example.com" required><label>Password</label><input name="password" type="password" maxlength="128" autocomplete="current-password" required><button class="primary">Sign in</button></form>'+help();
  document.querySelector("#signin-form").onsubmit=async function(event){
    event.preventDefault();
    if(!loginCsrf){
      var boot=await bootstrap();
      if(!boot.ok){showError(boot.message);return;}
    }
    var form=new FormData(event.target);
    try{
      var response=await fetch("/api/signin",{
        method:"POST",
        headers:{Accept:"application/json","Content-Type":"application/json","X-Login-CSRF":loginCsrf},
        body:JSON.stringify({email:form.get("email"),password:form.get("password")})
      });
      var result=await response.json();
      if(!result.ok){showError(result.message);return;}
      activity("Sign-in complete. Secure session created.");
      notice="Signed in successfully. Next: get your identity code.";
      go(result.next);
    }catch(_error){showError("We could not connect securely. Please try again.");}
  };
  attachHelp();
}

function identity(){
  progress(1);
  app.innerHTML='<h1>🪪 Check it is you</h1>'+successNotice()+'<p class="lead">Get a six-digit identity code for this demo.</p><div class="hint">There is no reading timer. Take as long as you need.</div><div id="form-error" tabindex="-1"></div><button id="get-code" class="primary">Get identity code</button>'+help();
  var requestCode=async function(){
    var result=await api("/api/identity/request","POST",{});
    if(!result.ok){showError(result.message);return;}
    /* Task: normal browser console log, never copied into visible activity logs. */
    console.log("Simulated identity code:",result.simulatedCode);
    identityEntry();
  };
  document.querySelector("#get-code").onclick=requestCode;
  attachHelp();

  function identityEntry(){
    app.innerHTML='<h1>🪪 Enter your identity code</h1><div class="success">Your identity code was requested. Next: enter the six digits.</div><form id="identity-form"><div id="form-error" tabindex="-1"></div><label>Six-digit code</label><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" placeholder="123456" required><button class="primary">Check code</button></form><button id="again" class="secondary">Re-request identity code</button>'+help();
    document.querySelector("#identity-form").onsubmit=async function(event){
      event.preventDefault();
      var result=await api("/api/identity/verify","POST",{code:new FormData(event.target).get("code")});
      if(!result.ok){showError(result.message);return;}
      notice="Identity check complete. Next: set up your authenticator.";
      go(result.next);
    };
    document.querySelector("#again").onclick=requestCode;
    attachHelp();
  }
}

async function createProvision(){
  var result=await api("/api/authenticator/provision","POST",{});
  if(!result.ok){showError(result.message);return;}
  provision=result;
  /* Task: browser console only; the visible activity panel remains private-value free. */
  console.log("Simulated authenticator verification OTP:",result.simulatedOtp);
  showProvision();
}

function setup(){
  progress(2);
  app.innerHTML='<h1>📱 Set up your authenticator</h1>'+successNotice()+'<p class="lead">Copy a setup key into your authenticator app. You do not need to write it down.</p><div class="hint">Your authenticator app will give you a six-digit code.</div><div id="form-error" tabindex="-1"></div><button id="show-key" class="primary">Show setup key</button>'+help();
  document.querySelector("#show-key").onclick=createProvision;
  attachHelp();
}

function showProvision(){
  progress(2);
  app.innerHTML='<h1>📱 Add this to your app</h1><div class="success">Setup key created. Next: copy the key into your authenticator app.</div><p class="lead">Copy the setup key. You can hide it whenever you want.</p><div id="private"></div><button id="toggle" class="secondary">Hide setup key</button><button id="copy" class="secondary">Copy setup key</button><button id="next" class="primary">I added it — continue</button><button id="new-key" class="link">Show a new setup key</button>'+help();
  var shown=true;
  var privateBox=document.querySelector("#private");
  function draw(){
    privateBox.innerHTML="";
    if(shown){
      var key=document.createElement("div");
      key.className="secret code";
      key.textContent=provision.secret;
      privateBox.appendChild(key);
    }else{
      privateBox.innerHTML='<div class="hint">Setup key is hidden. Select reveal when you are ready.</div>';
    }
    document.querySelector("#toggle").textContent=shown?"Hide setup key":"Reveal setup key";
  }
  draw();
  document.querySelector("#toggle").onclick=function(){shown=!shown;draw();};
  document.querySelector("#copy").onclick=function(){
    navigator.clipboard.writeText(provision.secret).then(function(){
      alert("Setup key copied.");
    }).catch(function(){
      alert("Select the setup key and copy it.");
    });
  };
  document.querySelector("#next").onclick=function(){go("#confirm");};
  document.querySelector("#new-key").onclick=createProvision;
  attachHelp();
}

function confirmAuthenticator(){
  progress(3);
  app.innerHTML='<h1>✅ Check your authenticator</h1><p class="lead">Enter the six digits from your app.</p><div class="hint">Take your time. If needed, show a new setup key and try again.</div><form id="auth-form"><div id="form-error" tabindex="-1"></div><label>Authenticator code</label><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" placeholder="123456" required><button class="primary">Confirm authenticator</button></form><button id="retry" class="secondary">Show setup key again</button>'+help();
  document.querySelector("#auth-form").onsubmit=async function(event){
    event.preventDefault();
    var result=await api("/api/authenticator/confirm","POST",{code:new FormData(event.target).get("code")});
    if(!result.ok){showError(result.message);return;}
    activity("Authenticator confirmed.");
    notice="Authenticator confirmed. Next: create your recovery codes.";
    go(result.next);
  };
  document.querySelector("#retry").onclick=function(){provision?showProvision():go("#setup");};
  attachHelp();
}

function recovery(){
  progress(4);
  app.innerHTML='<h1>🧾 Save recovery codes</h1>'+successNotice()+'<p class="lead">These help if you cannot use your authenticator.</p><div class="hint">Save them somewhere private. Each code works once.</div><div id="form-error" tabindex="-1"></div><button id="create-codes" class="primary">Create recovery codes</button>'+help();
  document.querySelector("#create-codes").onclick=async function(){
    var result=await api("/api/recovery/generate","POST",{});
    if(!result.ok){showError(result.message);return;}
    recoveryCodes=result.codes;
    /* Task: complete simulated recovery-code set in browser console only. */
    console.log("Simulated recovery-code set:",recoveryCodes);
    showCodes();
  };
  attachHelp();
}

function showCodes(){
  app.innerHTML='<h1>🧾 Your recovery codes</h1><div class="success">Recovery codes created. Next: copy or save them privately.</div><div id="private"></div><button id="toggle" class="secondary">Hide recovery codes</button><button id="copy" class="secondary">Copy all codes</button><button id="done" class="primary">I saved my codes</button>'+help();
  var shown=true;
  var box=document.querySelector("#private");
  function draw(){
    box.innerHTML="";
    if(shown){
      var list=document.createElement("ul");
      list.className="codes";
      recoveryCodes.forEach(function(code){
        var item=document.createElement("li");
        item.textContent=code;
        list.appendChild(item);
      });
      box.appendChild(list);
    }else{
      box.innerHTML='<div class="hint">Recovery codes are hidden. Select reveal when you are ready.</div>';
    }
    document.querySelector("#toggle").textContent=shown?"Hide recovery codes":"Reveal recovery codes";
  }
  draw();
  document.querySelector("#toggle").onclick=function(){shown=!shown;draw();};
  document.querySelector("#copy").onclick=function(){
    navigator.clipboard.writeText(recoveryCodes.join("\\n")).then(function(){
      alert("Recovery codes copied.");
    }).catch(function(){
      alert("Select the codes and copy them.");
    });
  };
  document.querySelector("#done").onclick=function(){go("#saved");};
  attachHelp();
}

async function settings(){
  progress(4);
  var result=await api("/api/settings");
  if(!result.ok){go("#signin");return;}
  app.innerHTML='<h1>⚙️ Security settings</h1><div class="success">MFA is on for <b id="email"></b>.</div><p id="remaining"></p><button id="new-codes" class="primary">Create new recovery codes</button><button id="use-code" class="secondary">Use a recovery code</button>'+help();
  document.querySelector("#email").textContent=result.email;
  document.querySelector("#remaining").textContent=result.remaining+" unused code(s) remain.";
  document.querySelector("#new-codes").onclick=function(){go("#recovery");};
  document.querySelector("#use-code").onclick=function(){go("#use");};
  attachHelp();
}

function useRecovery(){
  progress(4);
  app.innerHTML='<h1>🔑 Use a recovery code</h1><p class="lead">Enter one unused recovery code.</p><form id="use-form"><div id="form-error" tabindex="-1"></div><label>Recovery code</label><input class="code" name="code" autocomplete="one-time-code" placeholder="ABCDE-23456" maxlength="11" pattern="[A-Za-z2-9]{5}-[A-Za-z2-9]{5}" required><button class="primary">Use recovery code</button></form>'+help();
  document.querySelector("#use-form").onsubmit=async function(event){
    event.preventDefault();
    var code=String(new FormData(event.target).get("code")).toUpperCase().trim();
    var result=await api("/api/recovery/use","POST",{code:code});
    if(!result.ok){showError(result.message);return;}
    app.innerHTML='<h1>✓ Recovery code accepted</h1><div class="success"></div><button id="back" class="primary">Back to settings</button>'+help();
    document.querySelector(".success").textContent=result.message;
    document.querySelector("#back").onclick=function(){go("#settings");};
    attachHelp();
  };
  attachHelp();
}

function saved(){
  progress(4);
  app.innerHTML='<h1>🎉 Security setup complete</h1><div class="success">Your authenticator is connected and your recovery codes are saved.</div><button id="view-settings" class="primary">View security settings</button>'+help();
  document.querySelector("#view-settings").onclick=function(){go("#settings");};
  attachHelp();
}

async function render(){
  var route=routes.has(location.hash)?location.hash:"#signin";
  if(route==="#signin"){
    await bootstrap();
    signIn();
    return;
  }
  var state=await signedIn();
  if(!state){go("#signin");return;}
  if(!state.identityVerified && route!=="#identity"){go("#identity");return;}
  if(!state.mfaEnabled && ["#recovery","#saved","#settings","#use"].includes(route)){
    go(state.provisioned?"#confirm":"#setup");
    return;
  }
  if(state.mfaEnabled && state.recoveryCount===0 && ["#saved","#settings","#use"].includes(route)){
    go("#recovery");
    return;
  }
  var screens={
    "#identity":identity,
    "#setup":setup,
    "#confirm":confirmAuthenticator,
    "#recovery":recovery,
    "#saved":saved,
    "#settings":settings,
    "#use":useRecovery
  };
  screens[route]();
}

logout.onclick=async function(){
  var result=await api("/api/logout","POST",{});
  if(result.ok){
    csrf="";
    provision=null;
    recoveryCodes=[];
    activity("Secure session ended.");
    go("#signin");
  }
};
addEventListener("hashchange",render);
render();
})();
</script>
</body>
</html>`;
}

const certificate = readFileSync("certs/cert.pem");
const privateKey = readFileSync("certs/key.pem");

/* Requirement 3: Bun TLS server using supplied localhost mkcert files. */
Bun.serve({
  port: 3000,
  tls: { cert: certificate, key: privateKey },
  fetch: async (request) => {
    const nonce = random(18);
    try {
      const url = new URL(request.url);
      const origin = request.headers.get("origin");

      if (request.headers.get("x-forwarded-proto") === "http") {
        return new Response("Secure connection required.", { status: 426, headers: securityHeaders(nonce) });
      }
      if (origin && !trustedOrigins.has(origin)) {
        return new Response("Not allowed.", { status: 403, headers: securityHeaders(nonce) });
      }

      const cors = origin ? { "Access-Control-Allow-Origin": origin } : {};
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            ...securityHeaders(nonce),
            ...cors,
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token, X-Login-CSRF"
          }
        });
      }

      if (url.pathname.startsWith("/api/")) {
        const response = await api(request, url.pathname, nonce);
        for (const [header, value] of Object.entries(cors)) response.headers.set(header, value);
        return response;
      }

      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        return new Response(page(nonce), {
          headers: {
            ...securityHeaders(nonce),
            ...cors,
            "Content-Type": "text/html; charset=utf-8"
          }
        });
      }

      return new Response("Page not found.", { status: 404, headers: securityHeaders(nonce) });
    } catch {
      return new Response(
        "We could not complete that request. Please try again.",
        { status: 500, headers: securityHeaders(nonce) }
      );
    }
  }
});
