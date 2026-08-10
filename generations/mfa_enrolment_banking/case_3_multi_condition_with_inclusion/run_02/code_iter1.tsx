
import { } from "bun";

/*
  MFA Enrolment System
  Single Bun HTTPS server and single-page client.
  Run: bun app.ts
  TLS certificates are expected at certs/cert.pem and certs/key.pem.
*/

const PORT = 3000;
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_WINDOW_MS = 5 * 60 * 1000;
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

type EncryptedValue = {
  nonce: string;
  cipher: string;
};

type BackupCode = {
  salt: string;
  hash: string;
  used: boolean;
};

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
};

const sessions = new Map<string, Session>();

/* Security requirement 3: a process-protected AES key encrypts OTP seeds at rest. */
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
};

function bytes(length: number): Uint8Array {
  const result = new Uint8Array(length);
  crypto.getRandomValues(result);
  return result;
}

function base64url(data: Uint8Array | ArrayBuffer): string {
  const values = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
  let binary = "";
  for (const value of values) binary += String.fromCharCode(value);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
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

function parseCookies(request: Request): Record<string, string> {
  const raw = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const position = part.indexOf("=");
    if (position > 0) result[part.slice(0, position).trim()] = part.slice(position + 1).trim();
  }
  return result;
}

function cookie(value: string, maxAge?: number): string {
  const age = maxAge === undefined ? "" : `; Max-Age=${maxAge}`;
  /* Security requirements 1, 2, 5: secure HttpOnly SameSite session cookie. */
  return `mfa_session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict${age}`;
}

function isTrustedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  const trusted = new Set([
    "https://localhost:3000",
    "https://127.0.0.1:3000",
    "https://[::1]:3000",
  ]);
  return !!origin && trusted.has(origin);
}

function headers(nonce?: string, request?: Request): Headers {
  const result = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    /* Security requirement 2: restrictive browser hardening headers. */
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
  });
  const origin = request?.headers.get("origin");
  if (origin && isTrustedOrigin(request!)) {
    result.set("Access-Control-Allow-Origin", origin);
    result.set("Access-Control-Allow-Credentials", "true");
    result.set("Vary", "Origin");
  }
  return result;
}

function json(data: unknown, status = 200, request?: Request, extra?: HeadersInit): Response {
  const resultHeaders = headers(undefined, request);
  if (extra) for (const [key, value] of new Headers(extra)) resultHeaders.set(key, value);
  return new Response(JSON.stringify(data), { status, headers: resultHeaders });
}

function genericError(status: number, request?: Request): Response {
  /* Security requirement 2: no debug details or stack traces are returned. */
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

/* Security requirement 1: every MFA API route calls this authorization guard. */
function authorized(request: Request): { id: string; session: Session } | Response {
  const found = sessionFor(request);
  if (!found || found.session.userId !== account.id) {
    return json({ ok: false, message: "Please sign in to continue." }, 401, request);
  }
  return found;
}

/* Security requirement 1: anti-CSRF token plus trusted same-origin check on mutations. */
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
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function text(value: unknown, max: number): string | null {
  return typeof value === "string" && value.length <= max ? value.trim() : null;
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

function fromBase64url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
  const raw = atob(padded);
  return Uint8Array.from(raw, char => char.charCodeAt(0));
}

async function decryptSecret(value: EncryptedValue): Promise<string> {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64url(value.nonce) },
    encryptionKey,
    fromBase64url(value.cipher),
  );
  return new TextDecoder().decode(plain);
}

async function digestHex(value: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(hash)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

/* Deterministic mock OTP: derived from secret and five-minute slot, never server-logged. */
async function otpFor(secret: string, slot: number): Promise<string> {
  const digest = await digestHex(`${secret}:${slot}:academic-mfa-demo`);
  const number = parseInt(digest.slice(0, 8), 16) % 1_000_000;
  return String(number).padStart(6, "0");
}

async function hashRecovery(code: string, salt: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveBits"]);
  const output = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: encoder.encode(salt), iterations: 100_000 },
    key,
    256,
  );
  return base64url(output);
}

function makeRecoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const raw = bytes(10);
  let code = "";
  for (let i = 0; i < 10; i++) {
    if (i === 5) code += "-";
    code += alphabet[raw[i] % alphabet.length];
  }
  return code;
}

async function createBackupCodes(): Promise<string[]> {
  const visible: string[] = [];
  const hashed: BackupCode[] = [];
  for (let i = 0; i < 8; i++) {
    const code = makeRecoveryCode();
    const salt = randomToken(16);
    visible.push(code);
    hashed.push({ salt, hash: await hashRecovery(code, salt), used: false });
  }
  account.backupCodes = hashed;
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
:root{--ink:#172331;--muted:#526273;--blue:#075ca8;--blue2:#03457f;--paper:#fff;--wash:#edf5fa;--line:#cbd8e3;--good:#126b43;--bad:#a32727}
*{box-sizing:border-box}body{margin:0;background:var(--wash);color:var(--ink);font-family:Verdana,Arial,sans-serif;letter-spacing:.035em;line-height:1.62;font-size:16px}main{max-width:560px;min-height:100vh;margin:auto;background:var(--paper);padding:22px 20px 38px}header{border-bottom:2px solid var(--line);padding-bottom:15px;margin-bottom:24px}.brand{font-weight:700;color:var(--blue);font-size:1.07rem}.step{color:var(--muted);font-size:.9rem;margin-top:9px}h1{font-size:1.65rem;line-height:1.26;letter-spacing:.02em;margin:0 0 15px}h2{font-size:1.16rem;line-height:1.35;margin:23px 0 9px}p{margin:0 0 15px}.card{border:1px solid var(--line);border-radius:12px;padding:18px;margin:16px 0;background:#fff}.icon{font-size:1.5rem;margin-right:8px}.notice{background:#eef8f2;border-left:5px solid var(--good);padding:13px 14px;margin:15px 0}.error{background:#fff0f0;border-left:5px solid var(--bad);padding:13px 14px;margin:15px 0}.hint{background:#f4f8fb;padding:13px;border-radius:8px;color:#33495e;font-size:.94rem}label{display:block;font-weight:700;margin:18px 0 6px}input{width:100%;min-height:51px;border:2px solid #8da1b4;border-radius:8px;padding:10px 12px;font:inherit;letter-spacing:.07em;color:var(--ink)}input:focus{outline:3px solid #8bc7ec;outline-offset:2px;border-color:var(--blue)}button,.button{width:100%;min-height:53px;border:0;border-radius:8px;background:var(--blue);color:#fff;font:700 1rem Verdana,Arial,sans-serif;letter-spacing:.035em;padding:12px 14px;cursor:pointer;margin-top:21px}.button:hover,button:hover{background:var(--blue2)}button.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue);margin-top:12px}.smalllink{background:none;border:0;color:var(--blue);text-decoration:underline;width:auto;min-height:auto;padding:4px;margin:12px 0 0;font:inherit;cursor:pointer}.code{font-family:ui-monospace,Consolas,monospace;letter-spacing:.11em;word-break:break-all;background:#f4f8fb;border:1px solid var(--line);border-radius:8px;padding:12px;margin:10px 0}.codes{font-family:ui-monospace,Consolas,monospace;letter-spacing:.1em;line-height:2;background:#f4f8fb;padding:13px;border-radius:8px;white-space:pre-wrap}.qr{display:block;width:190px;height:190px;border:10px solid white;image-rendering:pixelated;margin:14px auto}.logs{margin-top:35px;border-top:2px solid var(--line);padding-top:14px}.logs pre{white-space:pre-wrap;word-break:break-word;background:#14212c;color:#dcecf5;padding:12px;border-radius:8px;font:12px/1.55 ui-monospace,monospace;min-height:54px}.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}@media(max-width:380px){main{padding:18px 15px}body{font-size:15px}h1{font-size:1.45rem}}
</style>
</head>
<body><main id="app" aria-live="polite">Loading securely…</main>
<script nonce="${nonce}">
(() => {
"use strict";
/* Inclusivity requirements: short plain text, clear stages, no timers/motion, generous mobile spacing. */
const app=document.getElementById("app");
let csrf="", provision=null, recoveryCodes=null;
const logs=[];
function log(message){console.log(message);logs.push(message);const out=document.getElementById("log-output");if(out)out.textContent=logs.join("\\n");}
function el(tag,props={},children=[]){const node=document.createElement(tag);for(const [k,v] of Object.entries(props)){if(k==="className")node.className=v;else if(k==="text")node.textContent=v;else if(k.startsWith("on"))node.addEventListener(k.slice(2),v);else node.setAttribute(k,v);}for(const child of children)node.append(child);return node;}
function page(step,title){app.replaceChildren();const header=el("header",{},[el("div",{className:"brand",text:"Northstar Bank"}),el("div",{className:"step",text:"MFA set-up · Step "+step+" of 4"})]);app.append(header,el("h1",{text:title}));}
function message(text,kind="notice"){return el("div",{className:kind,text,role:"status"});}
function help(){return el("div",{className:"hint"},[el("strong",{text:"Need help? "}),document.createTextNode("You can pause here. Nothing will disappear while you read.")]);}
function logsPanel(){app.append(el("section",{className:"logs","aria-label":"Test logs"},[el("h2",{text:"Logs"}),el("p",{text:"Safe test messages shown for this demo."}),el("pre",{id:"log-output",text:logs.join("\\n")})]));}
async function api(path,method="GET",data){const options={method,headers:{}};if(method!=="GET"){options.headers["Content-Type"]="application/json";options.headers["X-CSRF-Token"]=csrf;options.body=JSON.stringify(data||{});}let r;try{r=await fetch(path,options);}catch{return {ok:false,message:"Connection problem. Please try again."};}const value=await r.json().catch(()=>({ok:false,message:"We could not complete that request."}));if(r.status===401)signIn(value.message);return value;}
function primary(text,fn){return el("button",{type:"button",text,onClick:fn});}
function copy(value,button){navigator.clipboard?.writeText(value).then(()=>{button.textContent="Copied";}).catch(()=>{button.textContent="Select the value above to copy";});}
function signIn(error){page("1","Sign in");app.append(el("p",{text:"Use your bank sign-in details. This demo keeps your sign-in private."}));if(error)app.append(message(error,"error"));const form=el("form");const email=el("input",{id:"email",type:"email",autocomplete:"username",inputmode:"email",placeholder:"name@example.com"});const password=el("input",{id:"password",type:"password",autocomplete:"current-password",placeholder:"Your password"});form.append(el("label",{for:"email",text:"Email"}),email,el("p",{className:"hint",text:"Example: marcus@example.com"}),el("label",{for:"password",text:"Password"}),password,primary("Sign in",async e=>{e.preventDefault();const result=await api("/api/signin","POST",{email:email.value,password:password.value});if(!result.ok)return signIn(result.message);csrf=result.csrf;log("Mock sign-in completed. A secure server session was created.");identity();}));app.append(form,help(),el("p",{className:"hint",text:"Demo sign-in: marcus@example.com and River!47"}));logsPanel();}
function identity(error){page("2","Check it is you");app.append(el("p",{text:"We need one quick identity check before MFA set-up."}));if(error)app.append(message(error,"error"));const input=el("input",{type:"text",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"246810","aria-describedby":"identity-example"});app.append(el("label",{for:"identity-code",text:"Identity check code"}));input.id="identity-code";app.append(input,el("p",{id:"identity-example",className:"hint",text:"Example: 246810"}),primary("Confirm identity",async()=>{const result=await api("/api/identity","POST",{code:input.value});if(!result.ok)return identity(result.message);log("Mock identity check completed.");setup();}),help());logsPanel();}
function setup(error){page("3","Set up your authenticator");app.append(el("p",{text:"Open your authenticator app. You can scan the square or copy the setup value."}));if(error)app.append(message(error,"error"));app.append(el("div",{className:"card"},[el("div",{text:"📱 Choose “add account” in your authenticator app."}),el("div",{text:"▣ Scan the square on the next screen."})]),primary("Show setup options",async()=>{const result=await api("/api/mfa/provision","POST",{});if(!result.ok)return setup(result.message);provision=result;log("Test provisioning value: "+result.secret);log("Test authenticator code: "+result.testOtp);provisionScreen();}),help());logsPanel();}
function drawQR(value){const canvas=el("canvas",{className:"qr",width:"168",height:"168","aria-label":"Provisioning QR-style code"});const c=canvas.getContext("2d"),size=21,unit=8;let seed=0;for(const ch of value)seed=(seed*31+ch.charCodeAt(0))>>>0;c.fillStyle="#fff";c.fillRect(0,0,168,168);c.fillStyle="#111";for(let y=0;y<size;y++)for(let x=0;x<size;x++){seed=(seed*1664525+1013904223)>>>0;if((seed>>>29)&1)c.fillRect(x*unit,y*unit,unit,unit);}return canvas;}
function provisionScreen(){page("3","Add this account");app.append(el("p",{text:"Scan this code in your authenticator app. If scanning is difficult, copy the setup value instead."}),drawQR(provision.uri),el("h2",{text:"Manual setup value"}),el("div",{className:"code",text:provision.secret}));const cp=el("button",{className:"secondary",type:"button",text:"Copy setup value",onClick:()=>copy(provision.secret,cp)});app.append(cp,primary("I have added it",verify),help());logsPanel();}
function verify(error){page("4","Enter the 6-digit code");app.append(el("p",{text:"Your authenticator app now shows a 6-digit code. Take your time."}));if(error)app.append(message(error,"error"));const input=el("input",{type:"text",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"123456"});app.append(el("label",{for:"otp",text:"Authenticator code"}));input.id="otp";app.append(input,el("p",{className:"hint",text:"Example: 123456"}),primary("Verify code",async()=>{const result=await api("/api/mfa/verify","POST",{otp:input.value});if(!result.ok)return verify(result.message);recoveryCodes=result.codes;log("Test backup recovery codes: "+result.codes.join(", "));backups();}),el("button",{className:"smalllink",type:"button",text:"Show setup options again",onClick:provisionScreen}),help());logsPanel();}
function backups(){page("4","Save your backup codes");app.append(message("Authenticator set up. Save these backup codes somewhere safe. Each one works once."));const value=recoveryCodes.join("\\n");app.append(el("div",{className:"codes",text:value}));const cp=el("button",{className:"secondary",type:"button",text:"Copy all backup codes",onClick:()=>copy(value,cp)});const dl=el("button",{className:"secondary",type:"button",text:"Download a text copy",onClick:()=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([value],{type:"text/plain"}));a.download="northstar-backup-codes.txt";a.click();URL.revokeObjectURL(a.href);}});app.append(cp,dl,primary("I saved my codes",settings),help());logsPanel();}
function settings(error){page("4","MFA is ready");app.append(el("p",{text:"Your authenticator is active. Backup codes are available if you lose your device."}));if(error)app.append(message(error,"error"));const input=el("input",{type:"text",autocomplete:"one-time-code",placeholder:"ABCDE-12345",maxlength:"11"});app.append(el("h2",{text:"Try a backup code"}),el("label",{for:"recovery",text:"Recovery code"}));input.id="recovery";app.append(input,el("p",{className:"hint",text:"Example: ABCDE-12345"}),primary("Use recovery code",async()=>{const result=await api("/api/recovery/verify","POST",{code:input.value});if(!result.ok)return settings(result.message);settings("That backup code worked and cannot be used again.");}),el("button",{className:"secondary",type:"button",text:"Make new backup codes",onClick:async()=>{const result=await api("/api/backup/regenerate","POST",{});if(!result.ok)return settings(result.message);recoveryCodes=result.codes;log("Replacement test backup recovery codes: "+result.codes.join(", "));backups();}}),el("button",{className:"smalllink",type:"button",text:"Sign out",onClick:async()=>{await api("/api/logout","POST",{});csrf="";provision=null;recoveryCodes=null;log("Signed out. Server session invalidated.");signIn();}}),help());logsPanel();}
async function boot(){const result=await api("/api/status");if(result.ok){csrf=result.csrf;result.mfaActive?settings():result.identityVerified?setup():identity();}else signIn();}
boot();
})();
</script></body></html>`;
}

async function route(request: Request): Promise<Response> {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    if (!isTrustedOrigin(request)) return genericError(403, request);
    const result = new Response(null, { status: 204, headers: headers(undefined, request) });
    result.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    result.headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return result;
  }

  if (url.pathname === "/" && request.method === "GET") {
    const nonce = randomToken(18);
    const resultHeaders = headers(nonce, request);
    resultHeaders.set("Content-Type", "text/html; charset=utf-8");
    return new Response(html(nonce), { headers: resultHeaders });
  }

  if (url.pathname === "/api/signin" && request.method === "POST") {
    const input = await body(request);
    const email = text(input?.email, 254);
    const password = text(input?.password, 128);
    /* Security requirement 4/5: strict validation and non-enumerating auth response. */
    if (!email || !password || !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email) ||
        email.toLowerCase() !== account.email || password !== account.password) {
      return json({ ok: false, message: "Those sign-in details did not match. Check both fields and try again." }, 401, request);
    }
    const id = randomToken(32); /* Security requirement 5: rotation/new ID after auth. */
    const session: Session = {
      userId: account.id,
      csrf: randomToken(32),
      createdAt: Date.now(),
      lastSeenAt: Date.now(),
      identityVerified: false,
    };
    sessions.set(id, session);
    return json({ ok: true, csrf: session.csrf }, 200, request, { "Set-Cookie": cookie(id) });
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
    const input = await body(request);
    const code = text(input?.code, 6);
    if (!code || !/^\\d{6}$/.test(code) || code !== "246810") {
      return json({ ok: false, message: "Enter the 6-digit identity code shown in the example and try again." }, 400, request);
    }
    found.session.identityVerified = true;
    return json({ ok: true }, 200, request);
  }

  if (url.pathname === "/api/mfa/provision" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    if (!found.session.identityVerified) return json({ ok: false, message: "Complete the identity check before setting up MFA." }, 403, request);
    const secret = base32(bytes(20));
    account.pendingSecret = await encryptSecret(secret);
    const testOtp = await otpFor(secret, Math.floor(Date.now() / OTP_WINDOW_MS));
    const uri = `otpauth://totp/Northstar:${encodeURIComponent(account.email)}?secret=${secret}&issuer=Northstar`;
    return json({ ok: true, secret, uri, testOtp }, 200, request);
  }

  if (url.pathname === "/api/mfa/verify" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    const input = await body(request);
    const otp = text(input?.otp, 6);
    if (!otp || !/^\\d{6}$/.test(otp)) return json({ ok: false, message: "Enter all 6 numbers from your authenticator app." }, 400, request);
    if (!account.pendingSecret) return json({ ok: false, message: "Choose setup options first, then enter the code." }, 400, request);
    if (Date.now() < account.otpLockedUntil) return json({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, request);
    const secret = await decryptSecret(account.pendingSecret);
    const slot = Math.floor(Date.now() / OTP_WINDOW_MS);
    const valid = otp === await otpFor(secret, slot) || otp === await otpFor(secret, slot - 1);
    if (!valid || account.otpUsedSlots.has(slot)) {
      account.otpFailures++;
      if (account.otpFailures >= MAX_ATTEMPTS) {
        account.otpFailures = 0;
        account.otpLockedUntil = Date.now() + LOCK_MS;
      }
      return json({ ok: false, message: "That code did not work. Check your authenticator app and try a fresh 6-digit code." }, 400, request);
    }
    account.otpUsedSlots.add(slot);
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
    if (Date.now() < account.backupLockedUntil) return json({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, request);
    for (const stored of account.backupCodes) {
      if (!stored.used && await hashRecovery(code, stored.salt) === stored.hash) {
        stored.used = true; /* Security requirement 5: recovery codes are single-use. */
        account.backupFailures = 0;
        return json({ ok: true }, 200, request);
      }
    }
    account.backupFailures++;
    if (account.backupFailures >= MAX_ATTEMPTS) {
      account.backupFailures = 0;
      account.backupLockedUntil = Date.now() + LOCK_MS;
    }
    return json({ ok: false, message: "That backup code did not work. Check the saved code and try another one." }, 400, request);
  }

  if (url.pathname === "/api/backup/regenerate" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    if (!account.activeSecret) return json({ ok: false, message: "Set up an authenticator before making backup codes." }, 400, request);
    const codes = await createBackupCodes(); /* Previous hash set is replaced and invalidated. */
    return json({ ok: true, codes }, 200, request);
  }

  if (url.pathname === "/api/logout" && request.method === "POST") {
    const found = csrfAuthorized(request);
    if (found instanceof Response) return found;
    sessions.delete(found.id);
    return json({ ok: true }, 200, request, { "Set-Cookie": cookie("", 0) });
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
