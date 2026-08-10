
/*
  MFA Enrolment System
  Single Bun HTTPS server and single-page client.
  Run: bun app.ts
  TLS certificates are expected at certs/cert.pem and certs/key.pem.
*/

const PORT = 3000;
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_PERIOD_SECONDS = 300;
const OTP_WINDOW_MS = OTP_PERIOD_SECONDS * 1000;
const OTP_DIGITS = 6;
const LOCK_MS = 5 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const encoder = new TextEncoder();

type Session = {
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
  identityVerified: boolean;
};

type EncryptedValue = { nonce: string; cipher: string };
type BackupCode = { salt: string; hash: string; used: boolean };

type Account = {
  id: string;
  email: string;
  password: string;
  pendingSecret?: EncryptedValue;
  activeSecret?: EncryptedValue;
  otpUsedSlots: Set<number>;
  otpFailures: number;
  otpLockedUntil: number;
  backupCodes: BackupCode[];
  backupFailures: number;
  backupLockedUntil: number;
  identityFailures: number;
  identityLockedUntil: number;
};

const sessions = new Map<string, Session>();
const trustedOrigins = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

/* Security requirement 3: process-protected AES key encrypts OTP seeds at rest. */
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt", "decrypt"],
);

const account: Account = {
  id: "account-marcus-001",
  email: "marcus@example.com",
  password: "River!47",
  otpUsedSlots: new Set(),
  otpFailures: 0,
  otpLockedUntil: 0,
  backupCodes: [],
  backupFailures: 0,
  backupLockedUntil: 0,
  identityFailures: 0,
  identityLockedUntil: 0,
};

function bytes(length: number): Uint8Array {
  const output = new Uint8Array(length);
  crypto.getRandomValues(output);
  return output;
}

function base64url(data: Uint8Array | ArrayBuffer): string {
  const values = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
  let value = "";
  for (const byte of values) value += String.fromCharCode(byte);
  return btoa(value).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function randomToken(length = 32): string {
  return base64url(bytes(length));
}

function base32(data: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let output = "";
  let value = 0;
  let bits = 0;
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function fromBase64url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") +
    "===".slice((value.length + 3) % 4);
  return Uint8Array.from(atob(padded), char => char.charCodeAt(0));
}

function parseCookies(request: Request): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const split = part.indexOf("=");
    if (split > 0) cookies[part.slice(0, split).trim()] = part.slice(split + 1).trim();
  }
  return cookies;
}

/* Security requirements 1, 2, 5: HttpOnly, Secure and SameSite session cookie. */
function sessionCookie(value: string, maxAge?: number): string {
  return `mfa_session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict${
    maxAge === undefined ? "" : `; Max-Age=${maxAge}`}`;
}

function isTrustedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return origin !== null && trustedOrigins.has(origin);
}

function secureHeaders(nonce?: string, request?: Request): Headers {
  const result = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
  });
  if (request && isTrustedOrigin(request)) {
    result.set("Access-Control-Allow-Origin", request.headers.get("origin")!);
    result.set("Access-Control-Allow-Credentials", "true");
    result.set("Vary", "Origin");
  }
  return result;
}

function json(value: unknown, status = 200, request?: Request, extra?: HeadersInit): Response {
  const headers = secureHeaders(undefined, request);
  if (extra) for (const [key, item] of new Headers(extra)) headers.set(key, item);
  return new Response(JSON.stringify(value), { status, headers });
}

function genericError(status: number, request?: Request): Response {
  return json({ ok: false, message: "We could not complete that request. Please try again." }, status, request);
}

function sessionFor(request: Request): { id: string; session: Session } | null {
  const id = parseCookies(request).mfa_session;
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeenAt > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastSeenAt = now;
  return { id, session };
}

/* Security requirement 1: authorization is enforced on every MFA endpoint. */
function authorized(request: Request): { id: string; session: Session } | Response {
  const found = sessionFor(request);
  if (!found || found.session.userId !== account.id) {
    return json({ ok: false, message: "Please sign in to continue." }, 401, request);
  }
  return found;
}

/* Security requirement 1: mutations require both a trusted Origin and anti-CSRF token. */
function csrfAuthorized(request: Request): { id: string; session: Session } | Response {
  const found = authorized(request);
  if (found instanceof Response) return found;
  if (!isTrustedOrigin(request) || request.headers.get("x-csrf-token") !== found.session.csrf) {
    return json({ ok: false, message: "This page needs to be refreshed before continuing." }, 403, request);
  }
  return found;
}

async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function text(value: unknown, maximum: number): string | null {
  return typeof value === "string" && value.length <= maximum ? value.trim() : null;
}

async function encryptSecret(secret: string): Promise<EncryptedValue> {
  const nonce = bytes(12);
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    encryptionKey,
    encoder.encode(secret),
  );
  return { nonce: base64url(nonce), cipher: base64url(cipher) };
}

async function decryptSecret(value: EncryptedValue): Promise<string> {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64url(value.nonce) },
    encryptionKey,
    fromBase64url(value.cipher),
  );
  return new TextDecoder().decode(plain);
}

function decodeBase32(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = value.toUpperCase().replaceAll("=", "").replaceAll(/\s/g, "");
  let bits = 0;
  let buffer = 0;
  const output: number[] = [];
  for (const character of clean) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("Invalid base32");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

async function otpFor(secret: string, slot: number): Promise<string> {
  const counter = new Uint8Array(8);
  let number = BigInt(Math.max(0, slot));
  for (let position = 7; position >= 0; position--) {
    counter[position] = Number(number & 255n);
    number >>= 8n;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = signature[signature.length - 1] & 15;
  const value = ((signature[offset] & 127) << 24) |
    (signature[offset + 1] << 16) | (signature[offset + 2] << 8) | signature[offset + 3];
  return String(value % (10 ** OTP_DIGITS)).padStart(OTP_DIGITS, "0");
}

async function hashRecovery(code: string, salt: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveBits"]);
  const hash = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: encoder.encode(salt), iterations: 100_000 },
    key,
    256,
  );
  return base64url(hash);
}

/*
  Security requirement 5: every sign-in path does the same PBKDF2 credential
  comparison work. Invalid and unknown credentials use normalized dummy values,
  then receive the exact same status, response shape and message.
*/
const credentialSalt = randomToken(16);
async function credentialDigest(email: string, password: string): Promise<Uint8Array> {
  const material = `${email}\u0000${password}`;
  const key = await crypto.subtle.importKey("raw", encoder.encode(material), "PBKDF2", false, ["deriveBits"]);
  const output = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: encoder.encode(credentialSalt), iterations: 100_000 },
    key,
    256,
  );
  return new Uint8Array(output);
}
function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index++) difference |= (left[index] || 0) ^ (right[index] || 0);
  return difference === 0;
}
const validCredentialDigest = await credentialDigest(account.email, account.password);

function makeRecoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const raw = bytes(10);
  let output = "";
  for (let index = 0; index < 10; index++) {
    if (index === 5) output += "-";
    output += alphabet[raw[index] % alphabet.length];
  }
  return output;
}

async function createBackupCodes(): Promise<string[]> {
  const visible: string[] = [];
  const stored: BackupCode[] = [];
  for (let index = 0; index < 8; index++) {
    const code = makeRecoveryCode();
    const salt = randomToken(16);
    visible.push(code);
    stored.push({ salt, hash: await hashRecovery(code, salt), used: false });
  }
  account.backupCodes = stored;
  return visible;
}

function html(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172331;--muted:#526273;--blue:#075ca8;--blue2:#03457f;--paper:#fff;--wash:#edf5fa;--line:#cbd8e3;--good:#126b43;--bad:#a32727}*{box-sizing:border-box}body{margin:0;background:var(--wash);color:var(--ink);font-family:Verdana,Arial,sans-serif;letter-spacing:.035em;line-height:1.62;font-size:16px}main{max-width:560px;min-height:100vh;margin:auto;background:var(--paper);padding:22px 20px 38px}header{border-bottom:2px solid var(--line);padding-bottom:15px;margin-bottom:24px}.brand{font-weight:700;color:var(--blue);font-size:1.07rem}.step{color:var(--muted);font-size:.9rem;margin-top:9px}h1{font-size:1.65rem;line-height:1.26;letter-spacing:.02em;margin:0 0 15px}h2{font-size:1.16rem;line-height:1.35;margin:23px 0 9px}p{margin:0 0 15px}.card{border:1px solid var(--line);border-radius:12px;padding:18px;margin:16px 0;background:#fff}.notice{background:#eef8f2;border-left:5px solid var(--good);padding:13px 14px;margin:15px 0}.error{background:#fff0f0;border-left:5px solid var(--bad);padding:13px 14px;margin:15px 0}.hint{background:#f4f8fb;padding:13px;border-radius:8px;color:#33495e;font-size:.94rem}label{display:block;font-weight:700;margin:18px 0 6px}input{width:100%;min-height:51px;border:2px solid #8da1b4;border-radius:8px;padding:10px 12px;font:inherit;letter-spacing:.07em;color:var(--ink)}input:focus{outline:3px solid #8bc7ec;outline-offset:2px;border-color:var(--blue)}button{width:100%;min-height:53px;border:0;border-radius:8px;background:var(--blue);color:#fff;font:700 1rem Verdana,Arial,sans-serif;letter-spacing:.035em;padding:12px 14px;cursor:pointer;margin-top:21px}button:hover{background:var(--blue2)}button.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue);margin-top:12px}.smalllink{background:none;border:0;color:var(--blue);text-decoration:underline;width:auto;min-height:auto;padding:4px;margin:12px 0 0;font:inherit;cursor:pointer}.code,.logs{font-family:ui-monospace,Consolas,monospace;letter-spacing:.08em;word-break:break-all;background:#f4f8fb;border:1px solid var(--line);border-radius:8px;padding:12px;margin:10px 0}.codes{font-family:ui-monospace,Consolas,monospace;letter-spacing:.1em;line-height:2;background:#f4f8fb;padding:13px;border-radius:8px;white-space:pre-wrap}.logs{font-size:.78rem;line-height:1.45;max-height:150px;overflow:auto;white-space:pre-wrap}.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}@media(max-width:380px){main{padding:18px 15px}body{font-size:15px}h1{font-size:1.45rem}}
</style>
</head>
<body><main id="app" aria-live="polite">Loading securely…</main>
<script nonce="${nonce}">
(() => {
"use strict";
const app=document.getElementById("app");
let csrf="",provision=null,recoveryCodes=null,logs=[];
function log(message){console.log(message);logs.push(message);const panel=document.getElementById("logs");if(panel)panel.textContent=logs.join("\\n");}
function el(tag,props={},children=[]){const node=document.createElement(tag);for(const [key,value] of Object.entries(props)){if(key==="className")node.className=value;else if(key==="text")node.textContent=value;else if(key.startsWith("on")&&typeof value==="function")node.addEventListener(key.slice(2).toLowerCase(),value);else node.setAttribute(key,String(value));}for(const child of children)node.append(child);return node;}
function page(step,title){app.replaceChildren();app.append(el("header",{},[el("div",{className:"brand",text:"Northstar Bank"}),el("div",{className:"step",text:"MFA set-up · Step "+step+" of 4"})]),el("h1",{text:title}));}
function notice(value,kind="notice"){return el("div",{className:kind,text:value,role:"status"});}
function help(){return el("div",{className:"hint"},[el("strong",{text:"Need help? "}),document.createTextNode("You can pause here. Nothing will disappear while you read.")]);}
function logPanel(){return el("section",{"aria-label":"Logs"},[el("h2",{text:"Logs"}),el("div",{id:"logs",className:"logs",text:logs.join("\\n")||"No simulated actions yet."})]);}
async function api(path,method="GET",data){const options={method,headers:{}};if(method!=="GET"){options.headers["Content-Type"]="application/json";options.headers["X-CSRF-Token"]=csrf;options.body=JSON.stringify(data||{});}try{const response=await fetch(path,options);const value=await response.json().catch(()=>({ok:false,message:"We could not complete that request."}));if(response.status===401)signIn(value.message);return value;}catch{return {ok:false,message:"Connection problem. Please try again."};}}
function primary(text,fn){return el("button",{type:"button",text,onClick:fn});}
function copy(value,button){navigator.clipboard?.writeText(value).then(()=>button.textContent="Copied").catch(()=>button.textContent="Select the value above to copy");}
function finish(){app.append(help(),logPanel());}
function signIn(error){page("1","Sign in");app.append(el("p",{text:"Use your bank sign-in details. This demo keeps your sign-in private."}));if(error)app.append(notice(error,"error"));const form=el("form");const email=el("input",{id:"email",type:"email",autocomplete:"username",inputmode:"email",placeholder:"name@example.com"});const password=el("input",{id:"password",type:"password",autocomplete:"current-password",placeholder:"Your password"});const submit=async event=>{event.preventDefault();const result=await api("/api/signin","POST",{email:email.value,password:password.value});if(!result.ok)return signIn(result.message);csrf=result.csrf;log("Mock sign-in completed. A secure server session was created.");identity();};form.addEventListener("submit",submit);form.append(el("label",{for:"email",text:"Email"}),email,el("p",{className:"hint",text:"Example: marcus@example.com"}),el("label",{for:"password",text:"Password"}),password,primary("Sign in",submit));app.append(form,el("p",{className:"hint",text:"Demo sign-in: marcus@example.com and River!47"}));finish();}
function identity(error){page("2","Check it is you");app.append(el("p",{text:"We need one quick identity check before MFA set-up."}));if(error)app.append(notice(error,"error"));const input=el("input",{id:"identity-code",type:"text",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"246810"});app.append(el("label",{for:"identity-code",text:"Identity check code"}),input,el("p",{className:"hint",text:"Example: 246810"}),primary("Confirm identity",async()=>{const result=await api("/api/identity","POST",{code:input.value});if(!result.ok)return identity(result.message);log("Mock identity check completed.");setup();}));finish();}
function setup(error){page("3","Set up your authenticator");app.append(el("p",{text:"Open your authenticator app. You can copy a setup value instead of typing it."}));if(error)app.append(notice(error,"error"));app.append(el("div",{className:"card",text:"📱 Choose “add account” in your authenticator app."}),primary("Show setup value",async()=>{const result=await api("/api/mfa/provision","POST",{});if(!result.ok)return setup(result.message);provision=result;log("Test provisioning value: "+result.secret);log("Test authenticator code: "+result.testOtp);provisionScreen();}));finish();}
function provisionScreen(){page("3","Add this account");app.append(el("p",{text:"Copy this setup value into your authenticator app. You do not need to type it by hand."}),el("h2",{text:"Manual setup value"}),el("div",{className:"code",text:provision.secret}));const cp=el("button",{className:"secondary",type:"button",text:"Copy setup value",onClick:()=>copy(provision.secret,cp)});app.append(cp,primary("I have added it",verify));finish();}
function verify(error){page("4","Enter the 6-digit code");app.append(el("p",{text:"Your authenticator app now shows a 6-digit code. Take your time."}));if(error)app.append(notice(error,"error"));const input=el("input",{id:"otp",type:"text",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"123456"});app.append(el("label",{for:"otp",text:"Authenticator code"}),input,el("p",{className:"hint",text:"Example: 123456"}),primary("Verify code",async()=>{const result=await api("/api/mfa/verify","POST",{otp:input.value});if(!result.ok)return verify(result.message);recoveryCodes=result.codes;log("Test backup recovery codes: "+result.codes.join(", "));backups();}),el("button",{className:"smalllink",type:"button",text:"Show setup value again",onClick:provisionScreen}));finish();}
function backups(){page("4","Save your backup codes");app.append(notice("Authenticator set up. Save these backup codes somewhere safe. Each one works once."));const value=recoveryCodes.join("\\n");app.append(el("div",{className:"codes",text:value}));const cp=el("button",{className:"secondary",type:"button",text:"Copy all backup codes",onClick:()=>copy(value,cp)});app.append(cp,primary("I saved my codes",settings));finish();}
function settings(error){page("4","MFA is ready");app.append(el("p",{text:"Your authenticator is active. Backup codes are available if you lose your device."}));if(error)app.append(notice(error,error.startsWith("That backup")?"notice":"error"));const input=el("input",{id:"recovery",type:"text",autocomplete:"one-time-code",placeholder:"ABCDE-12345",maxlength:"11"});app.append(el("h2",{text:"Try a backup code"}),el("label",{for:"recovery",text:"Recovery code"}),input,el("p",{className:"hint",text:"Example: ABCDE-12345"}),primary("Use recovery code",async()=>{const result=await api("/api/recovery/verify","POST",{code:input.value});if(!result.ok)return settings(result.message);settings("That backup code worked and cannot be used again.");}),el("button",{className:"secondary",type:"button",text:"Make new backup codes",onClick:async()=>{const result=await api("/api/backup/regenerate","POST",{});if(!result.ok)return settings(result.message);recoveryCodes=result.codes;log("Replacement test backup recovery codes: "+result.codes.join(", "));backups();}),el("button",{className:"smalllink",type:"button",text:"Sign out",onClick:async()=>{await api("/api/logout","POST",{});csrf="";provision=null;recoveryCodes=null;log("Signed out. Server session invalidated.");signIn();}));finish();}
async function boot(){const result=await api("/api/status");if(result.ok){csrf=result.csrf;result.mfaActive?settings():result.identityVerified?setup():identity();}else signIn();}
boot();
})();
</script></body></html>`;
}

async function route(request: Request): Promise<Response> {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    if (!isTrustedOrigin(request)) return genericError(403, request);
    const response = new Response(null, { status: 204, headers: secureHeaders(undefined, request) });
    response.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    response.headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return response;
  }

  if (url.pathname === "/" && request.method === "GET") {
    const nonce = randomToken(18);
    const headers = secureHeaders(nonce, request);
    headers.set("Content-Type", "text/html; charset=utf-8");
    return new Response(html(nonce), { headers });
  }

  if (url.pathname === "/api/signin" && request.method === "POST") {
    /*
      Task: sign-in itself is a state-changing authentication endpoint.
      Missing Origin is rejected too; browser same-origin fetch supplies the trusted Origin.
    */
    if (!isTrustedOrigin(request)) {
      return json({ ok: false, message: "We could not complete that request. Please try again." }, 403, request);
    }

    const input = await body(request);
    const suppliedEmail = text(input?.email, 254);
    const suppliedPassword = text(input?.password, 128);
    const emailValid = !!suppliedEmail && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(suppliedEmail);
    const passwordValid = !!suppliedPassword;

    /* Equal credential work for malformed, unknown-email, and bad-password attempts. */
    const normalizedEmail = emailValid ? suppliedEmail!.toLowerCase() : "invalid@example.invalid";
    const normalizedPassword = passwordValid ? suppliedPassword! : "invalid-password-value";
    const suppliedDigest = await credentialDigest(normalizedEmail, normalizedPassword);
    const matched = sameBytes(suppliedDigest, validCredentialDigest) &&
      normalizedEmail === account.email && emailValid && passwordValid;

    if (!matched) {
      return json(
        { ok: false, message: "Those sign-in details did not match. Check both fields and try again." },
        401,
        request,
      );
    }

    const id = randomToken(32);
    const now = Date.now();
    const session: Session = {
      userId: account.id,
      csrf: randomToken(32),
      createdAt: now,
      lastSeenAt: now,
      identityVerified: false,
    };
    sessions.set(id, session);
    return json({ ok: true, csrf: session.csrf }, 200, request, { "Set-Cookie": sessionCookie(id) });
  }

  if (url.pathname === "/api/status" && request.method === "GET") {
    const found = authorized(request);
    if (found instanceof Response) return found;
    return json({
      ok: true,
      csrf: found.session.csrf,
      identityVerified: found.session.identityVerified,
      mfaActive: !!account.activeSecret,
    }, 200, request);
  }

  if (url.pathname === "/api/identity" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    if (Date.now() < account.identityLockedUntil) {
      return json({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, request);
    }
    const input = await body(request);
    const code = text(input?.code, 6);
    if (!code || !/^\d{6}$/.test(code) || code !== "246810") {
      account.identityFailures++;
      if (account.identityFailures >= MAX_ATTEMPTS) {
        account.identityFailures = 0;
        account.identityLockedUntil = Date.now() + LOCK_MS;
        return json({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, request);
      }
      return json({ ok: false, message: "That identity code did not work. Check the 6 numbers and try again." }, 400, request);
    }
    account.identityFailures = 0;
    found.session.identityVerified = true;
    return json({ ok: true }, 200, request);
  }

  if (url.pathname === "/api/mfa/provision" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    if (!found.session.identityVerified) {
      return json({ ok: false, message: "Complete the identity check before setting up MFA." }, 403, request);
    }
    const secret = base32(bytes(20));
    account.pendingSecret = await encryptSecret(secret);
    account.otpUsedSlots.clear();
    account.otpFailures = 0;
    account.otpLockedUntil = 0;
    const testOtp = await otpFor(secret, Math.floor(Date.now() / OTP_WINDOW_MS));
    const label = encodeURIComponent(`Northstar:${account.email}`);
    const uri = `otpauth://totp/${label}?secret=${secret}&issuer=Northstar&algorithm=SHA1&digits=6&period=${OTP_PERIOD_SECONDS}`;
    return json({ ok: true, secret, uri, testOtp }, 200, request);
  }

  if (url.pathname === "/api/mfa/verify" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;

    /*
      Task: identity authorization is checked before body parsing or OTP validation.
      This is deliberately the same plain-language instruction used by provisioning.
    */
    if (!found.session.identityVerified) {
      return json({ ok: false, message: "Complete the identity check before setting up MFA." }, 403, request);
    }

    const input = await body(request);
    const otp = text(input?.otp, 6);
    if (!otp || !/^\d{6}$/.test(otp)) {
      return json({ ok: false, message: "Enter all 6 numbers from your authenticator app." }, 400, request);
    }
    if (!account.pendingSecret) {
      return json({ ok: false, message: "Choose setup options first, then enter the code." }, 400, request);
    }
    if (Date.now() < account.otpLockedUntil) {
      return json({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, request);
    }

    const secret = await decryptSecret(account.pendingSecret);
    const slot = Math.floor(Date.now() / OTP_WINDOW_MS);
    let matchedSlot: number | null = null;
    if (otp === await otpFor(secret, slot)) matchedSlot = slot;
    else if (otp === await otpFor(secret, slot - 1)) matchedSlot = slot - 1;

    if (matchedSlot === null || account.otpUsedSlots.has(matchedSlot)) {
      account.otpFailures++;
      if (account.otpFailures >= MAX_ATTEMPTS) {
        account.otpFailures = 0;
        account.otpLockedUntil = Date.now() + LOCK_MS;
        return json({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, request);
      }
      return json({ ok: false, message: "That code did not work. Check your authenticator app and try a fresh 6-digit code." }, 400, request);
    }

    account.otpUsedSlots.add(matchedSlot);
    account.otpFailures = 0;
    account.activeSecret = account.pendingSecret;
    account.pendingSecret = undefined;
    const codes = await createBackupCodes();
    return json({ ok: true, codes }, 200, request);
  }

  if (url.pathname === "/api/recovery/verify" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    const input = await body(request);
    const code = text(input?.code, 11)?.toUpperCase();
    if (!code || !/^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/.test(code)) {
      return json({ ok: false, message: "Enter a backup code in the format ABCDE-12345." }, 400, request);
    }
    if (Date.now() < account.backupLockedUntil) {
      return json({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, request);
    }
    for (const stored of account.backupCodes) {
      if (!stored.used && sameBytes(
        encoder.encode(await hashRecovery(code, stored.salt)),
        encoder.encode(stored.hash),
      )) {
        stored.used = true;
        account.backupFailures = 0;
        return json({ ok: true }, 200, request);
      }
    }
    account.backupFailures++;
    if (account.backupFailures >= MAX_ATTEMPTS) {
      account.backupFailures = 0;
      account.backupLockedUntil = Date.now() + LOCK_MS;
      return json({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, request);
    }
    return json({ ok: false, message: "That backup code did not work. Check the saved code and try another one." }, 400, request);
  }

  if (url.pathname === "/api/backup/regenerate" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    if (!account.activeSecret) {
      return json({ ok: false, message: "Set up an authenticator before making backup codes." }, 400, request);
    }
    return json({ ok: true, codes: await createBackupCodes() }, 200, request);
  }

  if (url.pathname === "/api/logout" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    sessions.delete(found.id);
    return json({ ok: true }, 200, request, { "Set-Cookie": sessionCookie("", 0) });
  }

  return genericError(404, request);
}

Bun.serve({
  port: PORT,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      return await route(request);
    } catch {
      return genericError(500, request);
    }
  },
});

console.log(`MFA demo listening securely at https://localhost:${PORT}`);
