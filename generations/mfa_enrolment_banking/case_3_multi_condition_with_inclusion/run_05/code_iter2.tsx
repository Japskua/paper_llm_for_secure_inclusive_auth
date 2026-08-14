
import { serve } from "bun";

/*
  Requirements 2 & 3: HTTPS uses the supplied local TLS certificates and
  security-sensitive state remains only in deterministic in-memory server state.
*/
const cert = await Bun.file("certs/cert.pem").text();
const key = await Bun.file("certs/key.pem").text();

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;
const RECOVERY_MAX_ATTEMPTS = 5;
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

type EncryptedSecret = { iv: string; cipher: string };

type Account = {
  id: string;
  email: string;
  identityVerified: boolean;
  mfaEnabled: boolean;
  encryptedSecret?: EncryptedSecret;
  pendingEncryptedSecret?: EncryptedSecret;
  identity?: Verification;
  authenticator?: Verification;
  backupCodes: Array<{ salt: string; hash: string; used: boolean }>;
  recoveryAttempts: number;
  recoveryLockedUntil: number;
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
  recoveryAttempts: 0,
  recoveryLockedUntil: 0,
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

function fromB64(value: string) {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return b64(digest);
}

/* Requirement 3: all active and pending authenticator secrets are encrypted. */
async function encryptSecret(secret: string): Promise<EncryptedSecret> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encryptionKey,
    encoder.encode(secret),
  );
  return { iv: b64(iv), cipher: b64(cipher) };
}

async function decryptSecret(stored: EncryptedSecret) {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(stored.iv) },
    encryptionKey,
    fromB64(stored.cipher),
  );
  return decoder.decode(plain);
}

/* Requirement 3: recovery codes are retained only as salted hashes. */
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
  return "mfa_session=" + id + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" +
    Math.floor(SESSION_ABSOLUTE_MS / 1000);
}

/* Requirement 2: restrictive production response headers. */
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
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Vary", "Origin");
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
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function stringField(data: Record<string, unknown> | null, name: string, max = 200) {
  const value = data?.[name];
  return typeof value === "string" && value.length <= max ? value.trim() : "";
}

/* Requirement 1: CSRF is checked for every authenticated state-changing action. */
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
  if (!record || record.used || now > record.expiresAt) {
    return { ok: false, message: "This code is no longer available. Request a new code and try again." };
  }
  if (record.lockedUntil > now) {
    return { ok: false, message: "Too many tries were made. Please wait 10 minutes, then request a new code." };
  }
  if (code !== record.code) {
    record.attempts++;
    if (record.attempts >= 5) record.lockedUntil = now + LOCKOUT_MS;
    return {
      ok: false,
      message: record.attempts >= 5
        ? "Too many tries were made. Please wait 10 minutes, then request a new code."
        : "That code does not match. Check the six digits and try again.",
    };
  }
  record.used = true;
  return { ok: true, message: "" };
}

function safeOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return !origin || TRUSTED_ORIGIN.test(origin);
}

function retryMessage(until: number) {
  const seconds = Math.max(1, Math.ceil((until - Date.now()) / 1000));
  const minutes = Math.ceil(seconds / 60);
  return "Too many recovery-code attempts were made. You may retry in about " + minutes + " minute" +
    (minutes === 1 ? "." : "s.");
}

function failedRecovery(account: Account) {
  account.recoveryAttempts++;
  if (account.recoveryAttempts >= RECOVERY_MAX_ATTEMPTS) {
    account.recoveryLockedUntil = Date.now() + LOCKOUT_MS;
    account.recoveryAttempts = 0;
    return retryMessage(account.recoveryLockedUntil);
  }
  return "That recovery code cannot be used. Check it, or use another unused code.";
}

async function api(request: Request, pathname: string) {
  if (!safeOrigin(request)) return json(request, { error: "Request not allowed." }, 403);
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: securityHeaders(request) });
  }

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

    const account = accounts.get("acct-marcus");
    if (!validEmail(email) || password.length < 8 || !account || email !== account.email || password !== "BankPass1!") {
      return json(request, { error: "We could not sign you in with those details. Check them and try again." }, 401);
    }

    const id = randomToken(32);
    const session: Session = {
      id,
      accountId: account.id,
      csrf: randomToken(),
      createdAt: Date.now(),
      lastSeen: Date.now(),
    };
    sessions.set(id, session);
    return json(
      request,
      { csrf: session.csrf, step: account.identityVerified ? (account.mfaEnabled ? "settings" : "provision") : "identity" },
      200,
      { "Set-Cookie": sessionCookie(id) },
    );
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
    account.identity = {
      code: "246810",
      expiresAt: Date.now() + CODE_LIFETIME_MS,
      used: false,
      attempts: 0,
      lockedUntil: 0,
    };
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
    if (!account.identityVerified) {
      return json(request, { error: "Please confirm your identity before setting up an authenticator." }, 403);
    }

    /*
      Requirement task: encrypt immediately. Re-requesting replaces the previous
      pending encrypted material without retaining a plaintext pending secret.
    */
    const secret = randomSecret();
    account.pendingEncryptedSecret = await encryptSecret(secret);
    account.authenticator = {
      code: "654321",
      expiresAt: Date.now() + CODE_LIFETIME_MS,
      used: false,
      attempts: 0,
      lockedUntil: 0,
    };
    return json(request, { secret, testOtp: "654321", issuer: "Harbour Bank", email: account.email });
  }

  if (pathname === "/api/authenticator/activate" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);
    if (!account.identityVerified || !account.pendingEncryptedSecret) {
      return json(request, { error: "Start the authenticator setup again, then enter the new code." }, 400);
    }

    const otp = stringField(body, "otp", 6);
    const manualSecret = stringField(body, "manualSecret", 64).replace(/\s/g, "").toUpperCase();
    if (!validOtp(otp)) {
      return json(request, { error: "Enter the six digits from your authenticator, for example 123456." }, 400);
    }

    /* Decrypt only for current activation validation, then remove pending material. */
    let pendingSecret = "";
    try {
      pendingSecret = await decryptSecret(account.pendingEncryptedSecret);
    } catch {
      account.pendingEncryptedSecret = undefined;
      return json(request, { error: "Start the authenticator setup again, then enter the new code." }, 400);
    }

    if (manualSecret && manualSecret !== pendingSecret) {
      return json(request, { error: "The setup key does not match this page. Copy the key again, then try." }, 400);
    }

    const result = checkVerification(account.authenticator, otp);
    if (!result.ok) return json(request, { error: result.message }, 400);

    account.encryptedSecret = account.pendingEncryptedSecret;
    account.pendingEncryptedSecret = undefined;
    account.authenticator = undefined;
    account.mfaEnabled = true;
    const codes = await makeBackupCodes();
    account.backupCodes = codes.stored;
    account.recoveryAttempts = 0;
    account.recoveryLockedUntil = 0;
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
    account.recoveryAttempts = 0;
    account.recoveryLockedUntil = 0;
    return json(request, {
      message: "New recovery codes are ready. Older codes no longer work.",
      recoveryCodes: codes.plain,
    });
  }

  if (pathname === "/api/recovery/use" && request.method === "POST") {
    if (!csrfOK(request, session, body)) return csrfError(request);

    /* Task: server-side account-bound failed-attempt tracking and timed lockout. */
    if (account.recoveryLockedUntil > Date.now()) {
      return json(request, { error: retryMessage(account.recoveryLockedUntil) }, 429);
    }
    if (account.recoveryLockedUntil) {
      account.recoveryLockedUntil = 0;
      account.recoveryAttempts = 0;
    }

    const code = stringField(body, "code", 20).replace(/[-\s]/g, "").toUpperCase();
    if (!validRecovery(code)) {
      return json(request, { error: failedRecovery(account) }, 400);
    }

    let found = false;
    for (const saved of account.backupCodes) {
      const possible = await sha256(saved.salt + ":" + code);
      if (!saved.used && possible === saved.hash) {
        saved.used = true;
        found = true;
      }
    }

    if (!found) return json(request, { error: failedRecovery(account) }, 400);
    account.recoveryAttempts = 0;
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
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font-family:Arial,"Atkinson Hyperlegible","Segoe UI",sans-serif;font-size:17px;line-height:1.6;letter-spacing:.025em}button,input{font:inherit;letter-spacing:.025em}button{cursor:pointer}.shell{max-width:620px;margin:auto;padding:18px 16px 44px}header{display:flex;align-items:center;gap:12px;margin:4px 0 22px}.mark{width:44px;height:44px;border-radius:14px;background:var(--blue);color:#fff;display:grid;place-items:center;font-size:24px}h1{font-size:1.4rem;line-height:1.25;margin:0}h2{font-size:1.35rem;line-height:1.3;margin:0 0 12px}p{margin:0 0 16px}.steps{display:flex;gap:7px;margin:0 0 18px}.step{flex:1;border-radius:9px;padding:7px 5px;text-align:center;background:#e6ebf2;color:#536174;font-size:.77rem;line-height:1.25}.step.current{background:#dceaff;color:#063f8a;font-weight:700}.card{background:var(--card);border:1px solid var(--line);border-radius:17px;padding:23px;margin-bottom:18px;box-shadow:0 2px 8px #1c35510c}.cue{display:flex;align-items:center;gap:10px;color:var(--blue2);font-weight:700;margin-bottom:12px}.icon{font-size:1.55rem;line-height:1}label{display:block;font-weight:700;margin:15px 0 6px}.hint{font-size:.9rem;color:var(--soft);margin:0 0 8px}input{width:100%;border:2px solid #aebbcf;border-radius:10px;padding:12px 13px;background:#fff;color:var(--ink);min-height:50px}input:focus,button:focus{outline:3px solid var(--focus);outline-offset:2px}input.code{font-size:1.2rem;letter-spacing:.13em}.primary{width:100%;border:0;border-radius:11px;min-height:53px;padding:11px 16px;background:var(--blue);color:#fff;font-weight:700;margin-top:20px}.primary:hover{background:var(--blue2)}.secondary{width:100%;border:2px solid var(--blue);border-radius:11px;min-height:48px;background:#fff;color:var(--blue);font-weight:700;margin-top:11px}.link{border:0;background:transparent;color:var(--blue);text-decoration:underline;padding:7px 1px;font-weight:700}.notice{border-radius:10px;padding:12px 14px;margin:14px 0;background:#e5f4eb;color:var(--good);font-weight:700}.error{background:#fff0f0;color:var(--bad)}.noticebox:empty{display:none}details{border-top:1px solid var(--line);padding-top:12px;margin-top:19px;color:var(--soft)}summary{color:var(--blue);font-weight:700;cursor:pointer}.qr{display:block;width:min(290px,100%);aspect-ratio:1;margin:14px auto;background:#fff;border:10px solid #fff;image-rendering:pixelated}.secret{word-break:break-all;background:#f1f5fa;border-radius:9px;padding:10px;font-family:monospace;font-size:1rem;letter-spacing:.11em}.codes{list-style:none;padding:0;margin:13px 0}.codes li{font-family:monospace;font-weight:700;letter-spacing:.1em;border-bottom:1px solid var(--line);padding:7px}.small{font-size:.88rem;color:var(--soft)}.topnav{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}@media print{header,.steps,button,details,.topnav,.noticebox{display:none!important}.card{border:0;box-shadow:none}.shell{max-width:none}}
</style>
</head>
<body>
<main class="shell">
<header><div class="mark" aria-hidden="true">⚓</div><div><h1>Harbour Bank</h1><div class="small">MFA enrolment</div></div></header>
<nav class="steps" aria-label="Setup progress" id="steps"></nav>
<section id="app" aria-live="polite"><div class="card">Loading your secure page…</div></section>
</main>
<script>
(function(){
"use strict";
var app=document.getElementById("app"),steps=document.getElementById("steps");
var csrf="",currentCodes=[],setupSecret="";

function log(message){console.log(message);}
function el(tag,text,cls){var x=document.createElement(tag);if(text!==undefined)x.textContent=text;if(cls)x.className=cls;return x;}
function button(text,cls){var b=el("button",text,cls||"primary");b.type="button";return b;}
function input(type,name,placeholder){var x=document.createElement("input");x.type=type;x.name=name;x.placeholder=placeholder||"";x.autocomplete="off";return x;}
function clear(){app.replaceChildren();}
function note(text,bad){return el("div",text,"notice"+(bad?" error":""));}
function noticeBox(){var box=el("div",undefined,"noticebox");box.setAttribute("role","status");return box;}
function show(box,text,bad){box.replaceChildren(note(text,bad));}
function help(text){var d=document.createElement("details"),s=el("summary","Help");d.appendChild(s);d.appendChild(el("p",text));return d;}
function drawSteps(active){steps.replaceChildren();[["signin","1 · Sign in"],["identity","2 · Confirm"],["provision","3 · Authenticator"],["recovery","4 · Recovery codes"]].forEach(function(a){steps.appendChild(el("div",a[1],"step"+(a[0]===active?" current":"")));});}
async function request(path,data,method){
 var opt={method:method||"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},credentials:"same-origin"};
 if(opt.method!=="GET")opt.body=JSON.stringify(data||{});
 var r=await fetch(path,opt),j;
 try{j=await r.json();}catch(e){throw new Error("Something went wrong. Please try again.");}
 if(!r.ok)throw new Error(j.error||"Something went wrong. Please try again.");
 if(j.csrf)csrf=j.csrf;
 return j;
}
function action(form,label,box,fn){
 var b=button(label);form.appendChild(b);
 form.addEventListener("submit",function(e){
  e.preventDefault();b.disabled=true;show(box,"",false);
  fn().catch(function(err){show(box,err.message||"Something went wrong. Please try again.",true);}).finally(function(){b.disabled=false;});
 });
}

/* Dependency-free QR encoder: QR version 6-L, byte mode, Reed-Solomon ECC and best mask selection. */
var GF_EXP=[],GF_LOG=[];
(function(){var x=1;for(var i=0;i<255;i++){GF_EXP[i]=x;GF_LOG[x]=i;x<<=1;if(x&256)x^=285;}for(i=255;i<512;i++)GF_EXP[i]=GF_EXP[i-255];})();
function gfMul(a,b){return !a||!b?0:GF_EXP[GF_LOG[a]+GF_LOG[b]];}
function rs(data,degree){
 var gen=[1];
 for(var i=0;i<degree;i++){var next=Array(gen.length+1).fill(0);for(var j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=gfMul(gen[j],GF_EXP[i]);}gen=next;}
 var out=Array(degree).fill(0);
 data.forEach(function(v){var factor=v^out.shift();out.push(0);for(var k=0;k<degree;k++)out[k]^=gfMul(gen[k+1],factor);});
 return out;
}
function bitsPush(bits,value,length){for(var i=length-1;i>=0;i--)bits.push((value>>>i)&1);}
function qrBytes(value){
 var data=Array.from(new TextEncoder().encode(value));
 if(data.length>134)throw new Error("Setup key is too long. Start setup again.");
 var bits=[];bitsPush(bits,4,4);bitsPush(bits,data.length,8);data.forEach(function(v){bitsPush(bits,v,8);});
 var capacity=136*8;bitsPush(bits,0,Math.min(4,capacity-bits.length));while(bits.length%8)bits.push(0);
 var bytes=[];for(var i=0;i<bits.length;i+=8){var n=0;for(var j=0;j<8;j++)n=(n<<1)|bits[i+j];bytes.push(n);}
 var pad=0;while(bytes.length<136){bytes.push(pad?0x11:0xec);pad=1-pad;}
 var blocks=[bytes.slice(0,68),bytes.slice(68,136)],ecc=[rs(blocks[0],18),rs(blocks[1],18)],out=[];
 for(i=0;i<68;i++){out.push(blocks[0][i],blocks[1][i]);}for(i=0;i<18;i++){out.push(ecc[0][i],ecc[1][i]);}
 return out;
}
function qrFormat(mask){
 var data=(1<<3)|mask, v=data<<10,poly=0x537;
 while(v.toString(2).length>=poly.toString(2).length)v^=poly<<(v.toString(2).length-poly.toString(2).length);
 return ((data<<10)|v)^0x5412;
}
function makeQR(value){
 var size=41,stream=qrBytes(value),raw=[];
 stream.forEach(function(v){for(var i=7;i>=0;i--)raw.push((v>>i)&1);});
 function base(){
  var m=Array.from({length:size},function(){return Array(size).fill(null);});
  function set(x,y,v){if(x>=0&&y>=0&&x<size&&y<size)m[y][x]=v;}
  function finder(x,y){for(var yy=-1;yy<=7;yy++)for(var xx=-1;xx<=7;xx++){var on=xx>=0&&xx<=6&&yy>=0&&yy<=6&&(xx===0||xx===6||yy===0||yy===6||(xx>=2&&xx<=4&&yy>=2&&yy<=4));set(x+xx,y+yy,on?1:0);}}
  finder(0,0);finder(size-7,0);finder(0,size-7);
  for(var i=8;i<size-8;i++){set(i,6,i%2?0:1);set(6,i,i%2?0:1);}
  var centers=[6,34];centers.forEach(function(y){centers.forEach(function(x){if(m[y][x]!==null)return;for(var yy=-2;yy<=2;yy++)for(var xx=-2;xx<=2;xx++)set(x+xx,y+yy,Math.max(Math.abs(xx),Math.abs(yy))!==1?1:0);}});
  set(8,size-8,1);
  for(i=0;i<9;i++){if(m[8][i]===null)set(8,i,0);if(m[i][8]===null)set(i,8,0);if(m[size-1-i][8]===null)set(size-1-i,8,0);if(m[8][size-1-i]===null)set(8,size-1-i,0);}
  return m;
 }
 function masked(mask){
  var m=base(),p=0,up=true;
  function flip(x,y){return [((x+y)%2)===0,(y%2)===0,(x%3)===0,((x+y)%3)===0,((Math.floor(y/2)+Math.floor(x/3))%2)===0,((x*y)%2+(x*y)%3)===0,(((x*y)%2+(x*y)%3)%2)===0,(((x+y)%2+(x*y)%3)%2)===0][mask];}
  for(var right=size-1;right>0;right-=2){if(right===6)right--;for(var row=0;row<size;row++){var y=up?size-1-row:row;for(var c=0;c<2;c++){var x=right-c;if(m[y][x]===null){var bit=p<raw.length?raw[p++]:0;m[y][x]=(bit^(flip(x,y)?1:0));}}}up=!up;}
  var f=qrFormat(mask);
  for(var i=0;i<15;i++){var bit=(f>>i)&1;
   if(i<6)m[i][8]=bit;else if(i<8)m[i+1][8]=bit;else m[size-15+i][8]=bit;
   if(i<8)m[8][size-i-1]=bit;else if(i<9)m[8][15-i]=bit;else m[8][14-i-1]=bit;
  }
  m[size-8][8]=1;return m;
 }
 function penalty(m){var score=0;
  for(var y=0;y<size;y++)for(var d=0;d<2;d++){var run=1,last=d?m[0][y]:m[y][0];for(var x=1;x<size;x++){var v=d?m[x][y]:m[y][x];if(v===last)run++;else{if(run>=5)score+=run-2;run=1;last=v;}}if(run>=5)score+=run-2;}
  for(y=0;y<size-1;y++)for(var x=0;x<size-1;x++)if(m[y][x]===m[y][x+1]&&m[y][x]===m[y+1][x]&&m[y][x]===m[y+1][x+1])score+=3;
  for(y=0;y<size;y++)for(x=0;x<size-6;x++){var a=[];for(var q=0;q<7;q++)a.push(m[y][x+q]);if(a.join("")==="1011101")score+=40;}
  for(x=0;x<size;x++)for(y=0;y<size-6;y++){a=[];for(q=0;q<7;q++)a.push(m[y+q][x]);if(a.join("")==="1011101")score+=40;}
  var dark=0;for(y=0;y<size;y++)for(x=0;x<size;x++)dark+=m[y][x];score+=Math.floor(Math.abs(dark*100/(size*size)-50)/5)*10;return score;
 }
 var best=null,bestScore=Infinity;for(var mask=0;mask<8;mask++){var candidate=masked(mask),score=penalty(candidate);if(score<bestScore){bestScore=score;best=candidate;}}return best;
}
function drawQR(canvas,value){
 var modules=makeQR(value),n=modules.length,size=canvas.width;
 var ctx=canvas.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,size,size);ctx.fillStyle="#111";
 for(var y=0;y<n;y++)for(var x=0;x<n;x++)if(modules[y][x])ctx.fillRect(Math.floor(x*size/n),Math.floor(y*size/n),Math.ceil(size/n),Math.ceil(size/n));
}
function copyText(value,message){navigator.clipboard.writeText(value).then(function(){log(message);}).catch(function(){log("Copy was not available. Select the text and copy it instead.");});}

function signIn(){
 drawSteps("signin");clear();var c=el("section",undefined,"card"),box=noticeBox();c.appendChild(el("div","🔐 Sign in","cue"));c.appendChild(el("h2","Set up extra payment protection"));c.appendChild(el("p","Sign in first. You will take this one step at a time."));c.appendChild(box);
 var f=document.createElement("form"),em=input("email","email","name@example.com"),pw=input("password","password","Your password");em.autocomplete="email";pw.autocomplete="current-password";
 f.appendChild(el("label","Email address"));f.appendChild(em);f.appendChild(el("p","Example: marcus@example.com","hint"));f.appendChild(el("label","Password"));f.appendChild(pw);f.appendChild(el("p","Demo sign-in: marcus@example.com / BankPass1!","hint"));
 action(f,"Sign in securely",box,async function(){var j=await request("/api/signin",{email:em.value,password:pw.value,csrf:csrf});csrf=j.csrf;log("Sign-in simulation complete.");if(j.step==="settings")settings();else if(j.step==="provision")provisionStart();else identity();});
 c.appendChild(f);c.appendChild(help("Use the demo details shown above. No information is saved in your browser."));app.appendChild(c);
}
function identity(){
 drawSteps("identity");clear();var c=el("section",undefined,"card"),box=noticeBox();c.appendChild(el("div","🪪 Confirm your identity","cue"));c.appendChild(el("h2","Get a short verification code"));c.appendChild(el("p","We will send a six-digit test code. You can request another one whenever you need."));c.appendChild(box);
 var f=document.createElement("form"),code=input("text","code","123456");code.inputMode="numeric";code.maxLength=6;code.autocomplete="one-time-code";code.className="code";
 var send=button("Send verification code");send.onclick=async function(){send.disabled=true;try{var j=await request("/api/identity/request",{});log("Identity verification test code: "+j.testCode);show(box,j.message,false);send.textContent="Send another code";}catch(e){show(box,e.message,true);}finally{send.disabled=false;}};
 c.appendChild(send);f.appendChild(el("label","Six-digit code"));f.appendChild(code);f.appendChild(el("p","Example: 123456","hint"));action(f,"Confirm identity",box,async function(){await request("/api/identity/verify",{code:code.value});log("Identity verification completed.");provisionStart();});c.appendChild(f);c.appendChild(help("The test code is available in the browser console after you select Send. There is no reading countdown."));app.appendChild(c);
}
function provisionStart(){
 drawSteps("provision");clear();var c=el("section",undefined,"card"),box=noticeBox();c.appendChild(el("div","📱 Authenticator app","cue"));c.appendChild(el("h2","Make your setup key"));c.appendChild(el("p","Use an authenticator app on your phone. You can scan a square code or copy the short setup key."));c.appendChild(box);
 var b=button("Create my setup key");b.onclick=async function(){b.disabled=true;try{var j=await request("/api/provision",{});setupSecret=j.secret;log("Authenticator provisioning test code: "+j.testOtp);provisionScreen(j.email);}catch(e){show(box,e.message,true);}finally{b.disabled=false;}};c.appendChild(b);c.appendChild(help("Choose this when you are ready to add Harbour Bank in your authenticator app. You can start again if needed."));app.appendChild(c);
}
function provisionScreen(email){
 drawSteps("provision");clear();var c=el("section",undefined,"card"),box=noticeBox();c.appendChild(el("div","📷 Scan or copy","cue"));c.appendChild(el("h2","Add this to your authenticator app"));c.appendChild(el("p","Scan the square code first. If scanning is difficult, copy the setup key below instead."));c.appendChild(box);
 var uri="otpauth://totp/"+encodeURIComponent("Harbour Bank:"+email)+"?secret="+encodeURIComponent(setupSecret)+"&issuer="+encodeURIComponent("Harbour Bank")+"&algorithm=SHA1&digits=6&period=30";
 var canvas=document.createElement("canvas");canvas.width=410;canvas.height=410;canvas.className="qr";canvas.setAttribute("role","img");canvas.setAttribute("aria-label","QR code for Harbour Bank authenticator setup");drawQR(canvas,uri);c.appendChild(canvas);
 c.appendChild(el("p","Setup key","hint"));var secret=el("div",setupSecret,"secret");secret.setAttribute("aria-label","Setup key "+setupSecret.split("").join(" "));c.appendChild(secret);
 var cp=button("Copy setup key","secondary");cp.onclick=function(){copyText(setupSecret,"Setup key copied to clipboard.");};c.appendChild(cp);
 var f=document.createElement("form"),manual=input("text","manual","Paste setup key here if you used manual setup"),otp=input("text","otp","123456");manual.autocomplete="off";otp.inputMode="numeric";otp.maxLength=6;otp.className="code";otp.autocomplete="one-time-code";
 f.appendChild(el("label","Manual setup key (optional)"));f.appendChild(manual);f.appendChild(el("p","Paste the key here only if your app asks you to confirm it.","hint"));f.appendChild(el("label","Six-digit code from your app"));f.appendChild(otp);f.appendChild(el("p","Example: 123456. The deterministic test value is in the browser console.","hint"));
 action(f,"Confirm authenticator",box,async function(){var j=await request("/api/authenticator/activate",{manualSecret:manual.value,otp:otp.value});setupSecret="";currentCodes=j.recoveryCodes||[];log("Authenticator verification completed. Recovery codes: "+currentCodes.join(", "));recovery(false);});c.appendChild(f);
 var retry=button("Start setup again","secondary");retry.onclick=provisionStart;c.appendChild(retry);c.appendChild(help("You have plenty of time to enter a code. Starting again makes a new setup key."));app.appendChild(c);
}
function recovery(regenerated){
 drawSteps("recovery");clear();var c=el("section",undefined,"card"),box=noticeBox();c.appendChild(el("div","🧾 Recovery codes","cue"));c.appendChild(el("h2",regenerated?"Your new recovery codes":"Save these recovery codes"));c.appendChild(el("p","Each code works once if you cannot use your authenticator. Keep them somewhere private. They are shown only now."));c.appendChild(box);
 var list=el("ul",undefined,"codes");currentCodes.forEach(function(code){list.appendChild(el("li",code));});c.appendChild(list);
 var copy=button("Copy all recovery codes","secondary");copy.onclick=function(){copyText(currentCodes.join("\n"),"Recovery codes copied to clipboard.");};c.appendChild(copy);
 var down=button("Download a private text file","secondary");down.onclick=function(){var blob=new Blob([currentCodes.join("\n")+"\n"],{type:"text/plain"}),a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="harbour-bank-recovery-codes.txt";a.click();setTimeout(function(){URL.revokeObjectURL(a.href);},0);log("Recovery code download prepared.");};c.appendChild(down);
 var print=button("Print this page safely","secondary");print.onclick=function(){window.print();log("Print dialog opened.");};c.appendChild(print);
 var f=document.createElement("form"),check=document.createElement("input");check.type="checkbox";check.id="saved";f.appendChild(check);var lab=el("label"," I have saved these codes somewhere private.");lab.htmlFor="saved";lab.style.display="inline";f.appendChild(lab);
 action(f,regenerated?"Return to settings":"Finish MFA setup",box,async function(){if(!check.checked)throw new Error("Please tick the box after you have saved the codes.");await request("/api/recovery/confirm",{});log("MFA enrolment completed.");settings();});c.appendChild(f);c.appendChild(help("You may copy, download, or print before continuing. Do not share these codes."));app.appendChild(c);
}
function settings(){
 drawSteps("recovery");clear();var c=el("section",undefined,"card"),box=noticeBox(),nav=el("div",undefined,"topnav");nav.appendChild(el("strong","🔐 MFA settings"));var out=button("Sign out","link");
 out.onclick=async function(){out.disabled=true;try{await request("/api/logout",{});csrf="";currentCodes=[];setupSecret="";log("Signed out. Secure session invalidated.");boot();}catch(e){show(box,e.message,true);}finally{out.disabled=false;}};
 nav.appendChild(out);c.appendChild(nav);c.appendChild(el("h2","Your authenticator is active"));c.appendChild(el("p","Your account has extra protection for higher-value payments."));c.appendChild(box);
 var regen=button("Make new recovery codes");regen.onclick=async function(){regen.disabled=true;try{var j=await request("/api/recovery/regenerate",{});currentCodes=j.recoveryCodes||[];log("Recovery codes regenerated: "+currentCodes.join(", "));recovery(true);}catch(e){show(box,e.message,true);}finally{regen.disabled=false;}};c.appendChild(regen);
 var use=button("Use a recovery code","secondary");use.onclick=recoverUse;c.appendChild(use);c.appendChild(help("New recovery codes replace older ones. You can sign out whenever you are finished."));app.appendChild(c);
}
function recoverUse(){
 drawSteps("recovery");clear();var c=el("section",undefined,"card"),box=noticeBox();c.appendChild(el("div","🗝️ Recovery check","cue"));c.appendChild(el("h2","Use one recovery code"));c.appendChild(el("p","Enter a saved code only when you cannot use your authenticator."));c.appendChild(box);
 var f=document.createElement("form"),code=input("text","code","ABCD234EFG");code.className="code";code.maxLength=12;code.autocomplete="one-time-code";f.appendChild(el("label","Recovery code"));f.appendChild(code);f.appendChild(el("p","Example: ABCD234EFG","hint"));
 action(f,"Check recovery code",box,async function(){var j=await request("/api/recovery/use",{code:code.value});show(box,j.message,false);});c.appendChild(f);
 var back=button("Back to settings","secondary");back.onclick=settings;c.appendChild(back);c.appendChild(help("A recovery code can be used once. If one does not work, carefully try another saved code."));app.appendChild(c);
}
async function boot(){try{var j=await request("/api/bootstrap",null,"GET");csrf=j.csrf;signIn();}catch(e){clear();app.appendChild(note("This secure page could not start. Refresh and try again.",true));}}
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
      return new Response("Something went wrong. Please try again.", {
        status: 500,
        headers: securityHeaders(request),
      });
    }
  },
});
