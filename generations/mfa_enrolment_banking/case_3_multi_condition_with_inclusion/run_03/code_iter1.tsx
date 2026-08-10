
import { readFileSync } from "node:fs";

/*
  MFA Enrolment System
  - Single Bun HTTPS server and inline SPA.
  - Security sections: server-side sessions, CSRF, TLS headers, protected mock secrets.
  - All delivery and verification simulations are deliberately logged in the browser only.
*/

const PORT = Number(process.env.PORT || 3000);
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";

const cert = readFileSync(CERT_PATH);
const key = readFileSync(KEY_PATH);

const encoder = new TextEncoder();
const sessions = new Map<string, Session>();
const bootTokens = new Map<string, number>();
const users = new Map<string, User>();
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  true,
  ["encrypt", "decrypt"],
);
const hashPepper = randomToken(32);

type Session = {
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
};

type TimedCode = {
  hash: string;
  expiresAt: number;
  attempts: number;
  lockedUntil: number;
  used: boolean;
};

type User = {
  id: string;
  email: string;
  identity?: TimedCode;
  identityVerified: boolean;
  authenticatorEncrypted?: string;
  setupOtp?: TimedCode;
  mfaEnabled: boolean;
  recoveryHashes: Set<string>;
  recoveryShown: boolean;
};

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 30 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const LOCK_MS = 15 * 60 * 1000;

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function randomDigits(length = 6): string {
  const values = crypto.getRandomValues(new Uint32Array(length));
  return Array.from(values, (value) => String(value % 10)).join("");
}

function recoveryCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const values = crypto.getRandomValues(new Uint8Array(10));
  const raw = Array.from(values, (v) => chars[v % chars.length]).join("");
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}

async function secureHash(value: string): Promise<string> {
  const bytes = encoder.encode(`${hashPepper}:${value}`);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Buffer.from(digest).toString("base64url");
}

async function encrypt(value: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encryptionKey,
    encoder.encode(value),
  );
  return `${Buffer.from(iv).toString("base64url")}.${Buffer.from(encrypted).toString("base64url")}`;
}

function parseCookies(request: Request): Record<string, string> {
  const source = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const part of source.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) result[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  }
  return result;
}

function cookie(name: string, value: string, maxAge?: number): string {
  let output = `${name}=${encodeURIComponent(value)}; Path=/; Secure; HttpOnly; SameSite=Strict`;
  if (maxAge !== undefined) output += `; Max-Age=${maxAge}`;
  return output;
}

function expiredCookie(name: string): string {
  return `${name}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`;
}

function allowedOrigin(request: Request): string | null {
  const origin = request.headers.get("origin");
  if (!origin) return null;
  try {
    const url = new URL(origin);
    const trustedHosts = new Set(["localhost", "127.0.0.1", "[::1]"]);
    return url.protocol === "https:" && trustedHosts.has(url.hostname) ? origin : null;
  } catch {
    return null;
  }
}

/* Security Misconfiguration: common response protection headers. */
function protectedHeaders(request: Request, nonce?: string): Headers {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, private",
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce || "none"}'; style-src 'nonce-${nonce || "none"}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  });
  const origin = allowedOrigin(request);
  if (origin) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  return headers;
}

function json(request: Request, body: unknown, status = 200, setCookie?: string): Response {
  const headers = protectedHeaders(request);
  if (setCookie) headers.append("Set-Cookie", setCookie);
  return new Response(JSON.stringify(body), { status, headers });
}

function fail(request: Request, status: number, message: string): Response {
  return json(request, { ok: false, error: message }, status);
}

function getSession(request: Request): Session | null {
  const token = parseCookies(request).mfa_session;
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;

  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(token);
    return null;
  }
  session.lastSeen = now;
  return session;
}

/* Broken Access Control: user identity is always derived from HttpOnly session, never request input. */
function authorizedUser(request: Request): { session: Session; user: User } | null {
  const session = getSession(request);
  if (!session) return null;
  const user = users.get(session.userId);
  if (!user) return null;
  return { session, user };
}

/* CSRF protection for all state-changing API routes. */
function validCsrf(request: Request, session?: Session): boolean {
  const supplied = request.headers.get("x-csrf-token") || "";
  if (session) return supplied.length > 20 && supplied === session.csrf;
  const boot = parseCookies(request).mfa_boot;
  const expiry = boot ? bootTokens.get(boot) : undefined;
  return !!boot && !!expiry && expiry > Date.now() && supplied === boot;
}

async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPassword(value: unknown): value is string {
  return typeof value === "string" && value.length >= 8 && value.length <= 200;
}

function validSixDigits(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function checkedCode(code: TimedCode | undefined, submittedHash: string): "ok" | "missing" | "expired" | "locked" | "wrong" {
  if (!code || code.used) return "missing";
  if (Date.now() > code.expiresAt) return "expired";
  if (Date.now() < code.lockedUntil) return "locked";
  if (code.hash !== submittedHash) {
    code.attempts++;
    if (code.attempts >= MAX_ATTEMPTS) code.lockedUntil = Date.now() + LOCK_MS;
    return "wrong";
  }
  code.used = true;
  return "ok";
}

async function newTimedCode(value: string): Promise<TimedCode> {
  return {
    hash: await secureHash(value),
    expiresAt: Date.now() + CODE_LIFETIME_MS,
    attempts: 0,
    lockedUntil: 0,
    used: false,
  };
}

function statusFor(user: User, csrf: string) {
  return {
    ok: true,
    csrf,
    state: {
      signedIn: true,
      identityVerified: user.identityVerified,
      authenticatorReady: !!user.authenticatorEncrypted,
      mfaEnabled: user.mfaEnabled,
      recoveryShown: user.recoveryShown,
      email: user.email,
    },
  };
}

async function api(request: Request, path: string): Promise<Response> {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: protectedHeaders(request) });

  if (path === "/api/sign-in" && request.method === "POST") {
    if (!validCsrf(request)) return fail(request, 403, "Please refresh the page, then try signing in again.");
    const body = await readBody(request);
    if (!body || !validEmail(body.email) || !validPassword(body.password)) {
      return fail(request, 400, "Enter an email like name@example.com and a password with at least 8 characters.");
    }

    /* Session fixation prevention: rotate to a fresh random identifier at authentication. */
    const userId = "account-owner-marcus";
    let user = users.get(userId);
    if (!user) {
      user = {
        id: userId,
        email: String(body.email).trim().toLowerCase(),
        identityVerified: false,
        mfaEnabled: false,
        recoveryHashes: new Set(),
        recoveryShown: false,
      };
      users.set(userId, user);
    } else {
      user.email = String(body.email).trim().toLowerCase();
    }

    const old = parseCookies(request).mfa_session;
    if (old) sessions.delete(old);
    const sessionId = randomToken(32);
    const csrf = randomToken(32);
    sessions.set(sessionId, { userId, csrf, createdAt: Date.now(), lastSeen: Date.now() });
    bootTokens.delete(parseCookies(request).mfa_boot || "");
    return json(request, statusFor(user, csrf), 200, cookie("mfa_session", sessionId, SESSION_ABSOLUTE_MS / 1000));
  }

  const owned = authorizedUser(request);
  if (!owned) return fail(request, 401, "Your secure session has ended. Please sign in again.");
  const { session, user } = owned;

  if (path === "/api/status" && request.method === "GET") return json(request, statusFor(user, session.csrf));

  if (request.method !== "POST") return fail(request, 404, "That page is not available.");
  if (!validCsrf(request, session)) return fail(request, 403, "This action could not be confirmed. Refresh the page and try again.");

  if (path === "/api/identity/request") {
    const code = randomDigits(6);
    user.identity = await newTimedCode(code);
    /* Deliberate test mock value returned only for browser-console delivery simulation. */
    return json(request, { ok: true, csrf: session.csrf, testIdentityCode: code, message: "A check code is ready." });
  }

  if (path === "/api/identity/verify") {
    const body = await readBody(request);
    if (!body || !validSixDigits(body.code)) return fail(request, 400, "Enter the 6 digits shown in the check message. Example: 123456.");
    const result = checkedCode(user.identity, await secureHash(body.code));
    if (result === "ok") {
      user.identityVerified = true;
      return json(request, { ok: true, csrf: session.csrf, message: "Identity check complete. Next, set up your authenticator." });
    }
    if (result === "locked") return fail(request, 429, "Too many attempts. Wait 15 minutes, then request a new code.");
    if (result === "expired") return fail(request, 400, "That code is no longer active. Request a new code and enter it here.");
    return fail(request, 400, "That code did not match. Check all 6 digits, or request a new code.");
  }

  if (path === "/api/authenticator/setup") {
    if (!user.identityVerified) return fail(request, 403, "Complete the identity check before setting up an authenticator.");
    const secret = randomToken(20).replace(/[-_]/g, "A").slice(0, 26).toUpperCase();
    const otp = randomDigits(6);
    user.authenticatorEncrypted = await encrypt(secret);
    user.setupOtp = await newTimedCode(otp);
    const issuer = "Northstar Bank";
    const provisioningUri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(user.email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    return json(request, {
      ok: true,
      csrf: session.csrf,
      secret,
      provisioningUri,
      testAuthenticatorCode: otp,
      message: "Authenticator details are ready.",
    });
  }

  if (path === "/api/authenticator/verify") {
    if (!user.authenticatorEncrypted || !user.setupOtp) return fail(request, 400, "Start authenticator setup before confirming a code.");
    const body = await readBody(request);
    if (!body || !validSixDigits(body.code)) return fail(request, 400, "Enter the 6 digits from your authenticator. Example: 123456.");
    const result = checkedCode(user.setupOtp, await secureHash(body.code));
    if (result === "ok") {
      user.mfaEnabled = true;
      const codes = Array.from({ length: 8 }, recoveryCode);
      user.recoveryHashes = new Set(await Promise.all(codes.map(secureHash)));
      user.recoveryShown = false;
      return json(request, {
        ok: true,
        csrf: session.csrf,
        recoveryCodes: codes,
        message: "Authenticator confirmed. Your recovery codes are ready.",
      });
    }
    if (result === "locked") return fail(request, 429, "Too many attempts. Wait 15 minutes, then start setup again.");
    if (result === "expired") return fail(request, 400, "That code is no longer active. Start setup again to get a fresh code.");
    return fail(request, 400, "That code did not match. Check the 6 digits, then try again.");
  }

  if (path === "/api/recovery/acknowledge") {
    if (!user.mfaEnabled) return fail(request, 403, "Set up your authenticator before saving recovery codes.");
    user.recoveryShown = true;
    return json(request, { ok: true, csrf: session.csrf, message: "Recovery codes marked as saved. MFA enrolment is complete." });
  }

  if (path === "/api/recovery/regenerate") {
    if (!user.mfaEnabled) return fail(request, 403, "Set up your authenticator before making recovery codes.");
    const codes = Array.from({ length: 8 }, recoveryCode);
    user.recoveryHashes = new Set(await Promise.all(codes.map(secureHash)));
    user.recoveryShown = false;
    return json(request, {
      ok: true,
      csrf: session.csrf,
      recoveryCodes: codes,
      message: "New recovery codes are ready. Older codes no longer work.",
    });
  }

  if (path === "/api/logout") {
    const token = parseCookies(request).mfa_session;
    if (token) sessions.delete(token);
    return json(request, { ok: true, message: "You have signed out." }, 200, expiredCookie("mfa_session"));
  }

  return fail(request, 404, "That action is not available.");
}

function page(request: Request): Response {
  const nonce = randomToken(18);
  const boot = randomToken(32);
  bootTokens.set(boot, Date.now() + 30 * 60 * 1000);

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Northstar Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#17233b;--muted:#53627a;--blue:#075dcc;--soft:#edf5ff;--line:#cbd6e5;--good:#087443;--warn:#9a3e00;--bad:#b42318;--bg:#f7f9fc}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.025em}button,input{font:inherit;letter-spacing:.025em}button{cursor:pointer}#app{max-width:560px;margin:auto;min-height:100vh;background:#fff;padding:20px 20px 42px}.brand{font-weight:700;color:#064b9b;font-size:1.05rem}.brand span{font-size:1.35rem;margin-right:7px}.step{margin:20px 0 14px;color:#064b9b;font-weight:bold}.stepbar{height:8px;border-radius:8px;background:#dce6f4;overflow:hidden}.stepbar i{display:block;height:100%;background:var(--blue);border-radius:8px;width:20%}h1{font-size:1.75rem;line-height:1.25;margin:25px 0 10px;letter-spacing:.01em}h2{font-size:1.2rem;line-height:1.35;margin:20px 0 8px}p{margin:9px 0 17px}.hint,.notice{border-left:5px solid #2d74ce;background:var(--soft);padding:12px 14px;margin:18px 0;border-radius:5px}.notice.good{border-color:var(--good);background:#ecf9f1}.notice.error{border-color:var(--bad);background:#fff1f0;color:#751a14}.field{margin:18px 0}label{display:block;font-weight:bold;margin-bottom:6px}input{width:100%;padding:13px;border:2px solid #8797ad;border-radius:8px;background:#fff;color:var(--ink)}input:focus{outline:3px solid #9fc9ff;outline-offset:2px;border-color:var(--blue)}.example{display:block;color:var(--muted);font-size:.88rem}.primary{width:100%;border:0;border-radius:9px;background:var(--blue);color:white;font-weight:bold;padding:14px 16px;margin:20px 0 10px;min-height:54px}.primary:hover{background:#034ca7}.secondary{border:2px solid var(--blue);color:#064b9b;background:white;border-radius:8px;padding:10px 12px;margin:7px 5px 7px 0;font-weight:bold}.link{background:none;border:0;color:#064b9b;text-decoration:underline;padding:7px 0;font-weight:bold}.hidden{display:none!important}.code{font-family:monospace;letter-spacing:.12em;font-size:1.06rem;word-break:break-all;background:#f1f4f8;padding:12px;border-radius:7px}.codes{list-style:none;padding:0;margin:14px 0}.codes li{font-family:monospace;font-weight:bold;letter-spacing:.1em;background:#f1f4f8;margin:7px 0;padding:10px;border-radius:6px}.qr{width:204px;height:204px;display:grid;grid-template-columns:repeat(17,1fr);gap:1px;background:#fff;border:8px solid #fff;outline:2px solid var(--ink);margin:16px auto}.qr b{background:#17233b}.logs{margin-top:30px;border-top:2px solid var(--line);padding-top:12px}.logs pre{white-space:pre-wrap;word-break:break-word;background:#121b2b;color:#d9edff;padding:12px;border-radius:7px;font-size:.8rem;line-height:1.45;max-height:190px;overflow:auto}.logout{float:right}@media(max-width:370px){#app{padding:16px}.secondary{width:100%;margin-right:0}h1{font-size:1.5rem}}
</style>
</head>
<body>
<main id="app" aria-live="polite">
<header><div class="brand"><span aria-hidden="true">✦</span>Northstar Bank</div><button class="link logout hidden" id="logout">Sign out</button></header>
<div class="stepbar" aria-hidden="true"><i id="progress"></i></div>
<div class="step" id="step">Step 1 of 5 · Sign in</div>
<section id="screen"></section>
<section class="logs" aria-label="Simulation logs"><h2>Logs</h2><p class="example">Mock delivery and verification messages appear here.</p><pre id="logs">Ready.</pre></section>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
let csrf = ${JSON.stringify(boot)};
let view = "signIn";
let setup = {secret:"", uri:""};
let recovery = [];
const screen=document.getElementById("screen"), step=document.getElementById("step"), progress=document.getElementById("progress"), logs=document.getElementById("logs"), logout=document.getElementById("logout");
function log(message){console.log(message);logs.textContent += "\\n" + message;logs.scrollTop=logs.scrollHeight}
function esc(s){const d=document.createElement("div");d.textContent=String(s);return d.innerHTML}
async function call(path, data, method="POST"){
  try{
    const response=await fetch(path,{method,credentials:"same-origin",headers:method==="POST"?{"Content-Type":"application/json","X-CSRF-Token":csrf}:undefined,body:method==="POST"?JSON.stringify(data||{}):undefined});
    const out=await response.json();
    if(out.csrf) csrf=out.csrf;
    if(!response.ok) throw new Error(out.error||"Something went wrong. Please try again.");
    return out;
  }catch(error){throw error}
}
function message(text, type="good"){return '<div class="notice '+type+'" role="alert">'+esc(text)+'</div>'}
function setStep(number, title){step.textContent="Step "+number+" of 5 · "+title;progress.style.width=(number*20)+"%";logout.classList.toggle("hidden",number===1)}
function help(){return '<button class="link help" type="button">ⓘ Need a hint?</button>'}
function render(){
  if(view==="signIn"){
    setStep(1,"Sign in");
    screen.innerHTML='<h1>Set up extra payment protection</h1><p>Sign in to start. This takes a few short steps.</p><form id="signin"><div class="field"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" inputmode="email" required><span class="example">Example: marcus@example.com</span></div><div class="field"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><span class="example">Use at least 8 characters.</span></div><button class="primary">Sign in and continue</button></form>'+help();
    document.getElementById("signin").onsubmit=async e=>{e.preventDefault();try{const f=new FormData(e.target);await call("/api/sign-in",{email:f.get("email"),password:f.get("password")});log("Sign-in simulation complete. Secure session created.");view="identity";render()}catch(err){screen.insertAdjacentHTML("afterbegin",message(err.message,"error"))}};
  } else if(view==="identity"){
    setStep(2,"Identity check");
    screen.innerHTML='<h1>Check it is you</h1><p>We will show a 6-digit mock check code. There is no rush.</p><div id="identityMessage"></div><button class="primary" id="send">Show my check code</button><div id="verify" class="hidden"><form id="identityForm"><div class="field"><label for="identityCode">Check code</label><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required><span class="example">Example: 123456</span></div><button class="primary">Check code</button></form></div>'+help();
    document.getElementById("send").onclick=async()=>{try{const out=await call("/api/identity/request",{});log("Mock identity code delivered: "+out.testIdentityCode);document.getElementById("identityMessage").innerHTML=message("Your mock check code is "+out.testIdentityCode+". It is also in Logs.","good");document.getElementById("verify").classList.remove("hidden");document.getElementById("send").textContent="Show a new check code"}catch(err){document.getElementById("identityMessage").innerHTML=message(err.message,"error")}};
    document.getElementById("identityForm").onsubmit=async e=>{e.preventDefault();try{await call("/api/identity/verify",{code:document.getElementById("identityCode").value});log("Identity verification simulated successfully.");view="setup";render()}catch(err){document.getElementById("identityMessage").innerHTML=message(err.message,"error")}};
  } else if(view==="setup"){
    setStep(3,"Authenticator");
    screen.innerHTML='<h1>Connect your authenticator</h1><p>Use an authenticator app on this phone. You can scan, copy, or enter the short secret.</p><button class="primary" id="make">Prepare authenticator details</button><div id="setupDetails"></div>'+help();
    document.getElementById("make").onclick=async()=>{try{const out=await call("/api/authenticator/setup",{});setup={secret:out.secret,uri:out.provisioningUri};log("Mock authenticator secret delivered: "+out.secret);log("Mock authenticator confirmation code: "+out.testAuthenticatorCode);document.getElementById("setupDetails").innerHTML='<div class="notice good">Details ready. Scan the QR pattern or use a copy button. Then enter the 6-digit code from your app.</div><h2>Scan option</h2><div class="qr" id="qr" role="img" aria-label="Demo QR-style provisioning pattern"></div><p class="example">If your app cannot scan this demo pattern, use the copy options below.</p><button class="secondary" id="copyUri">Copy setup link</button><h2>Manual option</h2><p class="code" id="secret"></p><button class="secondary" id="copySecret">Copy secret</button><form id="otpForm"><div class="field"><label for="otp">Authenticator code</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required><span class="example">Example: 123456</span></div><button class="primary">Confirm authenticator</button></form>';document.getElementById("secret").textContent=setup.secret;drawQr(setup.secret);document.getElementById("copyUri").onclick=()=>copy(setup.uri,"Setup link copied.");document.getElementById("copySecret").onclick=()=>copy(setup.secret,"Secret copied.");document.getElementById("otpForm").onsubmit=verifyOtp}catch(err){document.getElementById("setupDetails").innerHTML=message(err.message,"error")}};
  } else if(view==="recovery"){
    setStep(4,"Recovery codes");
    screen.innerHTML='<h1>Save your recovery codes</h1><p>These one-use codes help if you lose your authenticator. Keep them somewhere private.</p><div id="recoveryBox"></div><button class="primary" id="saved">I saved these codes</button><button class="secondary" id="newCodes">Make new codes</button>'+help();
    showCodes();document.getElementById("saved").onclick=async()=>{try{await call("/api/recovery/acknowledge",{});log("Recovery codes marked as saved.");view="done";render()}catch(err){document.getElementById("recoveryBox").insertAdjacentHTML("afterbegin",message(err.message,"error"))}};document.getElementById("newCodes").onclick=regenerate;
  } else {
    setStep(5,"Complete");
    screen.innerHTML='<h1>✓ MFA is ready</h1><div class="notice good">Your authenticator and recovery codes are set up.</div><p>For higher-value payments, use the 6-digit code from your authenticator app.</p><button class="primary" id="finish">Finish securely</button>'+help();
    document.getElementById("finish").onclick=()=>{log("MFA enrolment completion confirmed.");screen.innerHTML='<h1>You are all set</h1><p>Your extra payment protection stays active.</p><button class="primary" id="finishLogout">Sign out</button>';document.getElementById("finishLogout").onclick=doLogout};
  }
  document.querySelectorAll(".help").forEach(b=>b.onclick=()=>alert("Hint: Take your time. You can request a new mock code or try again without a penalty."));
}
function drawQr(seed){const el=document.getElementById("qr");el.innerHTML="";let n=0;for(let i=0;i<289;i++){n=(n*31+(seed.charCodeAt(i%seed.length)||0)+i)%101;const cell=document.createElement("span");if(n%3===0||i%17===0||i%17===16)cell.innerHTML="<b></b>";el.appendChild(cell)}}
async function copy(value, notice){try{await navigator.clipboard.writeText(value);log(notice)}catch(_){log("Copy was unavailable. You can select the displayed value instead.")}}
async function verifyOtp(e){e.preventDefault();try{const out=await call("/api/authenticator/verify",{code:document.getElementById("otp").value});recovery=out.recoveryCodes;log("Authenticator verification simulated successfully.");log("Mock recovery codes delivered: "+recovery.join(", "));view="recovery";render()}catch(err){document.getElementById("setupDetails").insertAdjacentHTML("afterbegin",message(err.message,"error"))}}
function showCodes(){const box=document.getElementById("recoveryBox");box.innerHTML='<ul class="codes">'+recovery.map(c=>"<li>"+esc(c)+"</li>").join("")+'</ul><button class="secondary" id="copyCodes">Copy all codes</button><button class="secondary" id="downloadCodes">Download text file</button>';document.getElementById("copyCodes").onclick=()=>copy(recovery.join("\\n"),"Recovery codes copied.");document.getElementById("downloadCodes").onclick=()=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([recovery.join("\\n")],{type:"text/plain"}));a.download="northstar-recovery-codes.txt";a.click();URL.revokeObjectURL(a.href);log("Recovery code text file prepared for download.")}}
async function regenerate(){try{const out=await call("/api/recovery/regenerate",{});recovery=out.recoveryCodes;log("New mock recovery codes delivered: "+recovery.join(", "));showCodes();document.getElementById("recoveryBox").insertAdjacentHTML("afterbegin",message(out.message,"good"))}catch(err){document.getElementById("recoveryBox").insertAdjacentHTML("afterbegin",message(err.message,"error"))}}
async function doLogout(){try{await call("/api/logout",{});csrf="";recovery=[];setup={secret:"",uri:""};log("Secure session invalidated. Signed out.");view="signIn";render()}catch(err){alert(err.message)}}
logout.onclick=doLogout;
render();
})();
</script>
</body>
</html>`;

  const headers = protectedHeaders(request, nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.append("Set-Cookie", cookie("mfa_boot", boot, 30 * 60));
  return new Response(html, { status: 200, headers });
}

Bun.serve({
  port: PORT,
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/" && request.method === "GET") return page(request);
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      return fail(request, 404, "That page is not available.");
    } catch {
      /* Production-safe generic response: no stack traces or sensitive details. */
      return fail(request, 500, "Something went wrong. Please refresh and try again.");
    }
  },
});
