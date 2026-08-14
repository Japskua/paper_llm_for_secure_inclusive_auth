
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System
 [1] Access control / CSRF  [2] Secure headers / TLS / CORS
 [3] Cryptographic storage  [4] Validation / safe output  [5] Session / lockouts
*/
const cert = readFileSync("certs/cert.pem", "utf8");
const key = readFileSync("certs/key.pem", "utf8");
const encoder = new TextEncoder();

const SESSION_IDLE_MS = 15 * 60_000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60_000;
const PROVISIONING_LIFETIME_MS = 5 * 60_000;
const IDENTITY_CHALLENGE_LIFETIME_MS = 2 * 60_000;
const LOCK_WINDOW_MS = 10 * 60_000;
const LOCK_DURATION_MS = 10 * 60_000;
const MAX_FAILURES = 5;
const COOKIE_NAME = "__Host-mfa_session";
const CHALLENGE_COOKIE_NAME = "__Host-mfa_identity";
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);
const INTERNAL_ROUTES = new Set(["signin", "setup", "verify", "backup", "confirmed", "settings"]);

/*
 [1][5] This is a server-controlled test allow-list. No submitted identity can
 create an account: only this pre-authorized ownership fixture can issue a session.
*/
const ALLOWED_TEST_EMAIL = "marcus.contractor@example.test";
const ALLOWED_TEST_PHONE = "+15551234567";
const AUTHORIZED_ACCOUNT = { id: "acct_authorized_marcus_test", displayName: "Marcus" };

type Attempts = { count: number; windowStart: number; lockedUntil: number };
type Account = { id: string; displayName: string };
type Challenge = {
  id: string;
  code: string;
  accountId: string;
  identityKey: string;
  expiresAt: number;
  used: boolean;
};
type Recovery = { salt: string; hash: string; used: boolean };
type Mfa = {
  enabled: boolean;
  protectedSecret?: { iv: string; ciphertext: string };
  provisioning?: { expiresAt: number; used: boolean };
  acceptedTotpCounter?: bigint;
  recoveryCodes: Recovery[];
  otpAttempts: Attempts;
  recoveryAttempts: Attempts;
};
type Session = {
  id: string;
  accountId: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
};

const sessions = new Map<string, Session>();
const challenges = new Map<string, Challenge>();
const mfaRecords = new Map<string, Mfa>();
const identityFailures = new Map<string, Attempts>();
const allowlistedAccounts = new Map<string, Account>();

const masterKey = crypto.getRandomValues(new Uint8Array(32));
const encryptionKey = await crypto.subtle.importKey(
  "raw",
  masterKey,
  { name: "AES-GCM" },
  false,
  ["encrypt", "decrypt"],
);

function randomBytes(n: number) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}
function b64(v: Uint8Array) {
  return Buffer.from(v).toString("base64url");
}
function unb64(v: string) {
  return new Uint8Array(Buffer.from(v, "base64url"));
}
function token(n = 32) {
  return b64(randomBytes(n));
}
/* [3] Rejection sampling avoids modulo bias in numeric and recovery values. */
function secureIndex(max: number) {
  const bound = 256 - (256 % max);
  for (;;) {
    const value = randomBytes(1)[0];
    if (value < bound) return value % max;
  }
}
function secureDigits(length: number) {
  let out = "";
  for (let i = 0; i < length; i++) out += String(secureIndex(10));
  return out;
}
function freshRecoveryCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let raw = "";
  for (let i = 0; i < 12; i++) {
    if (i && i % 4 === 0) raw += "-";
    raw += alphabet[secureIndex(alphabet.length)];
  }
  return raw;
}
function base32Bytes(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, buffer = 0;
  const bytes: number[] = [];
  for (const char of value.toUpperCase().replace(/=+$/g, "")) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("invalid base32");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}
async function sha256(value: string) {
  return Buffer.from(await crypto.subtle.digest("SHA-256", encoder.encode(value))).toString("hex");
}
async function identityKeyFor(email: string, phone: string) {
  return sha256(email + "\u0000" + phone);
}
async function totp(secret: string, counter: bigint) {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, counter, false);
  const key = await crypto.subtle.importKey(
    "raw",
    base32Bytes(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes));
  const offset = digest[19] & 15;
  const result =
    ((digest[offset] & 127) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(result % 1_000_000).padStart(6, "0");
}
async function encrypt(secret: string) {
  const iv = randomBytes(12);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, encoder.encode(secret));
  return { iv: b64(iv), ciphertext: b64(new Uint8Array(data)) };
}
async function decrypt(value: { iv: string; ciphertext: string }) {
  const raw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(value.iv) },
    encryptionKey,
    unb64(value.ciphertext),
  );
  return new TextDecoder().decode(raw);
}
/* [3] Every recovery-code hash receives a newly generated, independent salt. */
async function protectCode(raw: string, salt = b64(randomBytes(16))): Promise<Recovery> {
  const material = await crypto.subtle.importKey("raw", encoder.encode(raw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: encoder.encode(salt), iterations: 210000, hash: "SHA-256" },
    material,
    256,
  );
  return { salt, hash: Buffer.from(bits).toString("hex"), used: false };
}
async function codeMatches(raw: string, stored: Recovery) {
  const candidate = await protectCode(raw, stored.salt);
  const a = Buffer.from(candidate.hash, "hex");
  const b = Buffer.from(stored.hash, "hex");
  let difference = a.length ^ b.length;
  for (let i = 0; i < Math.min(a.length, b.length); i++) difference |= a[i] ^ b[i];
  return difference === 0;
}
async function newCodes() {
  const raw: string[] = [];
  while (raw.length < 8) {
    const next = freshRecoveryCode();
    if (!raw.includes(next)) raw.push(next);
  }
  return { raw, protected: await Promise.all(raw.map((code) => protectCode(code))) };
}

function attempts(): Attempts {
  return { count: 0, windowStart: Date.now(), lockedUntil: 0 };
}
function locked(value: Attempts) {
  return Date.now() < value.lockedUntil;
}
function fail(value: Attempts) {
  const now = Date.now();
  if (now - value.windowStart > LOCK_WINDOW_MS) {
    value.count = 0;
    value.windowStart = now;
  }
  if (++value.count >= MAX_FAILURES) {
    value.count = 0;
    value.windowStart = now;
    value.lockedUntil = now + LOCK_DURATION_MS;
  }
}
function reset(value: Attempts) {
  value.count = 0;
  value.windowStart = Date.now();
  value.lockedUntil = 0;
}
function identityAttemptRecord(identityKey: string) {
  let value = identityFailures.get(identityKey);
  if (!value) {
    value = attempts();
    identityFailures.set(identityKey, value);
  }
  return value;
}
function record(accountId: string) {
  let value = mfaRecords.get(accountId);
  if (!value) {
    value = {
      enabled: false,
      recoveryCodes: [],
      otpAttempts: attempts(),
      recoveryAttempts: attempts(),
    };
    mfaRecords.set(accountId, value);
  }
  return value;
}
function normalizeEmail(value: string) {
  return value.trim().toLowerCase();
}
function normalizePhone(value: string) {
  return value.trim();
}

const authorizedIdentityKey = await identityKeyFor(ALLOWED_TEST_EMAIL, ALLOWED_TEST_PHONE);
allowlistedAccounts.set(authorizedIdentityKey, AUTHORIZED_ACCOUNT);

function cookieValue(req: Request, name: string) {
  const item = (req.headers.get("cookie") || "")
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(name + "="));
  return item?.slice(name.length + 1);
}
function session(req: Request): Session | null {
  const id = cookieValue(req, COOKIE_NAME);
  const value = id ? sessions.get(id) : undefined;
  if (!value) return null;
  if (Date.now() > value.expiresAt || Date.now() - value.lastSeenAt > SESSION_IDLE_MS) {
    sessions.delete(value.id);
    return null;
  }
  value.lastSeenAt = Date.now();
  return value;
}
const sessionCookie = (id: string) =>
  `${COOKIE_NAME}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
const challengeCookie = (id: string) =>
  `${CHALLENGE_COOKIE_NAME}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${IDENTITY_CHALLENGE_LIFETIME_MS / 1000}`;
const expiredCookie = (name: string) =>
  `${name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
const trusted = (origin: string | null) => origin !== null && TRUSTED_ORIGINS.has(origin);

function headers(req: Request, type: string, nonce?: string) {
  const source = nonce ? `'self' 'nonce-${nonce}'` : "'self'";
  const result = new Headers({
    "Content-Type": type,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      `default-src 'self'; script-src ${source}; style-src ${source}; img-src 'self' data:; ` +
      "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  const origin = req.headers.get("origin");
  if (trusted(origin)) {
    result.set("Access-Control-Allow-Origin", origin!);
    result.set("Access-Control-Allow-Credentials", "true");
    result.set("Vary", "Origin");
  }
  return result;
}
function json(req: Request, status: number, data: unknown, cookies: string[] = []) {
  const result = headers(req, "application/json; charset=utf-8");
  for (const cookie of cookies) result.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers: result });
}
function error(req: Request, status = 400) {
  return json(req, status, { ok: false, message: "The request could not be completed." });
}
async function body(req: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await req.json();
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}
const emailOK = (x: unknown): x is string =>
  typeof x === "string" && x.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x);
const phoneOK = (x: unknown): x is string =>
  typeof x === "string" && /^\+[1-9]\d{7,14}$/.test(x);
const otpOK = (x: unknown): x is string => typeof x === "string" && /^\d{6}$/.test(x);
function recoveryCode(value: unknown) {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toUpperCase();
  return /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(normalized) ? normalized : null;
}
const redirectOK = (value: unknown) =>
  value == null || (typeof value === "string" && INTERNAL_ROUTES.has(value));
const csrfOK = (req: Request, value: Session) =>
  req.headers.get("x-csrf-token") === value.csrf && trusted(req.headers.get("origin"));

function state(value: Session) {
  const mfa = record(value.accountId);
  return {
    ok: true,
    user: { displayName: AUTHORIZED_ACCOUNT.displayName },
    csrf: value.csrf,
    mfa: {
      enabled: mfa.enabled,
      hasRecoveryCodes: mfa.recoveryCodes.length > 0,
      provisioningPending: !!mfa.provisioning,
    },
  };
}

function html(nonce: string) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank — MFA</title>
<style nonce="${nonce}">
:root{--navy:#11284a;--blue:#1769d1;--line:#d8e1ee;--muted:#5b6880;--danger:#a52626}
*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:#172033;font:16px Arial,sans-serif;line-height:1.45}
main{max-width:560px;min-height:100vh;margin:auto;background:white;padding:20px 18px 34px}
header{border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:20px}.brand,h1,h2{color:var(--navy)}
.brand{font-weight:bold}.eyebrow{color:var(--blue);font-size:.8rem;font-weight:bold;margin-top:14px;text-transform:uppercase}
h1{font-size:1.65rem;margin:2px 0}h2{font-size:1.15rem}.muted{color:var(--muted)}
.card,.notice,.success{border:1px solid var(--line);border-radius:10px;padding:14px;margin:14px 0}
.notice{background:#eef5ff;border-left:4px solid var(--blue)}.success{background:#effaf3;border-left:4px solid #17653a}
label{font-weight:bold;display:block;margin:13px 0 5px}input{font:inherit;width:100%;padding:12px;border:1px solid #9ba9bc;border-radius:8px}
button,.button{display:block;width:100%;margin-top:14px;padding:12px 15px;border:1px solid var(--blue);border-radius:8px;background:var(--blue);color:white;text-align:center;text-decoration:none;font:700 16px Arial;cursor:pointer}
.secondary{background:white;color:var(--blue)}.danger{background:var(--danger);border-color:var(--danger)}
.error{color:var(--danger);font-weight:bold;min-height:1.4em}code{display:block;overflow-wrap:anywhere;background:#f2f5f8;padding:10px}
.codes{columns:2;list-style:none;padding:0;font-family:monospace;font-weight:bold}.codes li{padding:5px}
.logs{border-top:1px solid var(--line);margin-top:25px;padding-top:12px}.logs pre{white-space:pre-wrap;word-break:break-word;background:#101c2e;color:#dce9ff;padding:10px;border-radius:8px;font-size:.78rem}
@media(max-width:380px){main{padding:16px 14px}.codes{columns:1}}
</style></head><body><main id="app">Loading secure enrolment…</main>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",st=null,backup=null,provision=null,logs=[];
const app=document.querySelector("#app");
function log(value){console.log(value);logs.push(value);const target=document.querySelector("#logs");if(target)target.textContent=logs.join("\\n")}
async function api(path,method="GET",data){
 const headers={Accept:"application/json"};
 if(method!=="GET"){headers["Content-Type"]="application/json";headers["X-CSRF-Token"]=csrf}
 const response=await fetch(path,{method,headers,credentials:"same-origin",body:data===undefined?undefined:JSON.stringify(data)});
 let result;try{result=await response.json()}catch{result={ok:false}}
 if(response.status===401&&path!=="/api/signin"){csrf="";st=null;location.hash="#/signin"}
 return {response,result};
}
function shell(title,sub){
 app.innerHTML='<header><div class="brand">NORTHSTAR BANK</div><div class="eyebrow">Security centre</div><h1></h1><p class="muted"></p></header><section id="screen"></section><section class="logs"><h2>Logs</h2><p class="muted">Authorized simulation output is mirrored here.</p><pre id="logs"></pre></section>';
 app.querySelector("h1").textContent=title;app.querySelector("header p").textContent=sub;
 document.querySelector("#logs").textContent=logs.join("\\n");return document.querySelector("#screen");
}
function err(message){const target=document.querySelector("#err");if(target)target.textContent=message||""}
function route(){const value=location.hash.replace(/^#\\/?/,"");return ["signin","setup","verify","backup","confirmed","settings"].includes(value)?value:(st?"settings":"signin")}
async function challenge(email,phone){
 const {response,result}=await api("/api/identity-challenge","POST",{email:email.trim(),phone:phone.trim()});
 if(response.ok&&result.ok&&result.identityCode)log("Authorized identity verification simulation challenge code: "+result.identityCode);
 return response.ok&&result.ok;
}
function signin(){
 const screen=shell("Sign in and verify identity","Enrol MFA before approving higher-value payments.");
 screen.innerHTML='<div class="notice"><b>Demo identity check:</b> enter your authorized test email and international phone number, then request a short-lived challenge. The active mock delivery code is shown only in Logs.</div><form id="signin-form"><label for="email">Email address</label><input id="email" type="email" autocomplete="email" required><label for="phone">Mobile number</label><input id="phone" type="tel" autocomplete="tel" placeholder="+15551234567" required><label for="identity">Identity verification code</label><input id="identity" inputmode="numeric" maxlength="6" required><p id="err" class="error"></p><button>Verify and continue</button></form><button id="new" class="secondary">Get a simulation challenge</button>';
 const email=document.querySelector("#email"),phone=document.querySelector("#phone"),identity=document.querySelector("#identity");
 document.querySelector("#new").onclick=async()=>{err("");if(!email.value||!phone.value)return err("Enter your email address and mobile number first.");if(!await challenge(email.value,phone.value))err("We could not start verification.")};
 document.querySelector("#signin-form").onsubmit=async event=>{
  event.preventDefault();
  const {response,result}=await api("/api/signin","POST",{email:email.value.trim(),phone:phone.value.trim(),identityCode:identity.value.trim(),redirect:"setup"});
  if(!response.ok||!result.ok)return err("We could not verify those details.");
  csrf=result.csrf;st=result;log("Identity verification simulation completed for the authenticated account.");location.hash="#/setup";
 };
}
function setup(){
 if(!st)return signin();const screen=shell("Set up your authenticator","Use an authenticator app to generate time-based verification codes.");
 if(!provision){
  screen.innerHTML='<div class="card"><h2>Authenticator app</h2><p>Generate a protected setup secret, then add it manually to your authenticator app.</p><p id="err" class="error"></p><button id="go">Generate setup secret</button></div><a href="#/settings">Back to MFA settings</a>';
  document.querySelector("#go").onclick=async()=>{const {response,result}=await api("/api/mfa/provision","POST",{});if(!response.ok)return err("The setup request could not be completed.");provision=result;log("Authorized authenticator provisioning simulation — manual secret: "+result.manualSecret);log("Authorized authenticator provisioning simulation — current TOTP code: "+result.verificationCode);render()};
  return;
 }
 screen.innerHTML='<div class="success"><b>Setup secret generated.</b> Enter it manually in your authenticator app.</div><div class="card"><h2>Manual setup secret</h2><code id="secret"></code><p class="muted">The current TOTP is available in Logs for this authorized simulation.</p><a class="button" href="#/verify">I have added the secret</a></div>';
 document.querySelector("#secret").textContent=provision.manualSecret;
}
function verify(){
 if(!st)return signin();const screen=shell("Confirm your authenticator","Enter the six-digit code generated during setup.");
 screen.innerHTML='<form id="verify-form"><label for="otp">Authenticator code</label><input id="otp" inputmode="numeric" maxlength="6" required><p id="err" class="error"></p><button>Verify authenticator</button></form><a href="#/setup">Back to setup</a>';
 document.querySelector("#verify-form").onsubmit=async event=>{
  event.preventDefault();const otp=document.querySelector("#otp");const {response,result}=await api("/api/mfa/verify-otp","POST",{otp:otp.value.trim()});
  if(!response.ok||!result.ok)return err("Verification could not be completed.");
  st.mfa=result.mfa;backup=result.backupCodes;log("MFA authenticator verification simulation succeeded.");
  backup.forEach(code=>log("Authorized newly issued backup recovery code: "+code));location.hash="#/backup";
 };
}
function backupView(){
 if(!st)return signin();const screen=shell("Save your backup codes","These codes can help you recover access.");
 if(!backup){screen.innerHTML='<div class="notice">Codes are displayed only immediately after enrolment or replacement.</div><a class="button" href="#/settings">Go to MFA settings</a>';return}
 screen.innerHTML='<div class="notice"><b>Store these securely.</b> Each code works once. Replacement codes permanently invalidate all previous codes.</div><div class="card"><h2>Your newly issued recovery codes</h2><ul class="codes" id="codes"></ul></div><a class="button" href="#/confirmed">I have stored my codes</a>';
 backup.forEach(code=>{const item=document.createElement("li");item.textContent=code;document.querySelector("#codes").appendChild(item)});
}
function confirmed(){
 if(!st){location.hash="#/signin";return}
 if(!st.mfa||st.mfa.enabled!==true){location.hash=st.mfa&&st.mfa.provisioningPending?"#/setup":"#/settings";return}
 const screen=shell("MFA is active","Your account is ready for secure payment approval.");
 screen.innerHTML='<div class="success"><b>Enrolment confirmed.</b><p>Your authenticator and recovery codes are active.</p></div><a class="button" href="#/settings">View MFA settings</a>';
}
function settings(){
 if(!st)return signin();const on=st.mfa.enabled,screen=shell("MFA settings","Manage security methods for your authenticated account.");
 screen.innerHTML='<div class="card"><h2>Authenticator</h2><p>Status: '+(on?"Active":"Not enrolled")+'</p>'+(on?'<p class="muted">Your authenticator is enrolled.</p>':'<a class="button" href="#/setup">Set up authenticator</a>')+'</div>'+(on?'<div class="card"><h2>Backup recovery codes</h2><p id="err" class="error"></p><button id="regen" class="secondary">Generate replacement codes</button></div><div class="card"><h2>Test a recovery code</h2><form id="recovery-form"><label for="recovery">Recovery code</label><input id="recovery" placeholder="ABCD-EFGH-JKLM"><button class="secondary">Verify recovery code</button></form></div>':'')+'<button id="out" class="danger">Log out</button>';
 const regen=document.querySelector("#regen");
 if(regen)regen.onclick=async()=>{const {response,result}=await api("/api/mfa/regenerate-backup","POST",{});if(!response.ok)return err("The request could not be completed.");backup=result.backupCodes;log("Replacement backup recovery codes generated; all prior codes are permanently invalid.");backup.forEach(code=>log("Authorized newly issued backup recovery code: "+code));location.hash="#/backup"};
 const form=document.querySelector("#recovery-form");
 if(form)form.onsubmit=async event=>{event.preventDefault();const field=document.querySelector("#recovery");const {response}=await api("/api/mfa/recover","POST",{recoveryCode:field.value.trim()});if(!response.ok)return err("Verification could not be completed.");log("Backup recovery-code verification simulation succeeded; the used code is now invalid.");alert("Recovery code accepted and invalidated.")};
 document.querySelector("#out").onclick=async()=>{await api("/api/logout","POST",{});csrf="";st=null;backup=null;provision=null;logs=[];location.hash="#/signin"};
}
function render(){switch(route()){case"setup":setup();break;case"verify":verify();break;case"backup":backupView();break;case"confirmed":confirmed();break;case"settings":settings();break;default:signin()}}
addEventListener("hashchange",()=>{if(route()!=="backup")backup=null;if(route()!=="setup")provision=null;render()});
(async()=>{const {response,result}=await api("/api/state");if(response.ok&&result.ok){csrf=result.csrf;st=result;if(!location.hash||route()==="signin")location.hash=result.mfa.enabled?"#/settings":"#/setup"}render()})();
})();
</script></body></html>`;
}

async function api(req: Request, path: string): Promise<Response> {
  if (path === "/api/identity-challenge" && req.method === "POST") {
    if (!trusted(req.headers.get("origin"))) return error(req, 403);
    const input = await body(req);
    if (!input || !emailOK(input.email) || !phoneOK(input.phone)) return error(req, 400);

    const email = normalizeEmail(input.email);
    const phone = normalizePhone(input.phone);
    const identityKey = await identityKeyFor(email, phone);
    const attemptRecord = identityAttemptRecord(identityKey);
    if (locked(attemptRecord)) return error(req, 429);

    const previous = cookieValue(req, CHALLENGE_COOKIE_NAME);
    if (previous) challenges.delete(previous);

    /*
     [1][5] Allow-list lookup is read-only. Known and unknown valid requests
     receive the same generic success status/message. Only an allow-listed
     identity receives an active challenge record, bound to its account and
     the new HttpOnly challenge cookie.
    */
    const account = allowlistedAccounts.get(identityKey);
    const challengeId = token();
    let activeCode: string | undefined;
    if (account) {
      activeCode = secureDigits(6);
      challenges.set(challengeId, {
        id: challengeId,
        code: activeCode,
        accountId: account.id,
        identityKey,
        expiresAt: Date.now() + IDENTITY_CHALLENGE_LIFETIME_MS,
        used: false,
      });
    }

    return json(
      req,
      200,
      {
        ok: true,
        message: "If the supplied details can be verified, a challenge has been sent.",
        /* Testing-only mock delivery disclosure; absent for non-active requests. */
        ...(activeCode ? { identityCode: activeCode } : {}),
      },
      [challengeCookie(challengeId)],
    );
  }

  if (path === "/api/signin" && req.method === "POST") {
    if (!trusted(req.headers.get("origin"))) return error(req, 403);
    const input = await body(req);
    if (!input || !emailOK(input.email) || !phoneOK(input.phone) || !otpOK(input.identityCode) || !redirectOK(input.redirect)) {
      return error(req, 401);
    }

    const email = normalizeEmail(input.email);
    const phone = normalizePhone(input.phone);
    const identityKey = await identityKeyFor(email, phone);
    const attemptRecord = identityAttemptRecord(identityKey);
    if (locked(attemptRecord)) return error(req, 429);

    /*
     [1] Submitted identity is checked against the allow-list again. A valid
     challenge cannot ever issue a session for a guessed or manipulated account.
    */
    const account = allowlistedAccounts.get(identityKey);
    const challengeId = cookieValue(req, CHALLENGE_COOKIE_NAME);
    const challenge = challengeId ? challenges.get(challengeId) : undefined;
    const valid =
      !!account &&
      !!challenge &&
      challenge.accountId === account.id &&
      challenge.identityKey === identityKey &&
      !challenge.used &&
      challenge.expiresAt >= Date.now() &&
      challenge.code === input.identityCode;

    if (!valid) {
      fail(attemptRecord);
      return error(req, 401);
    }

    challenge!.used = true;
    challenges.delete(challenge!.id);
    reset(attemptRecord);

    /* [5] Rotate any supplied session identifier on successful authentication. */
    const old = cookieValue(req, COOKIE_NAME);
    if (old) sessions.delete(old);
    const now = Date.now();
    const value: Session = {
      id: token(),
      accountId: account!.id,
      csrf: token(24),
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + SESSION_ABSOLUTE_MS,
    };
    sessions.set(value.id, value);
    return json(req, 200, state(value), [sessionCookie(value.id), expiredCookie(CHALLENGE_COOKIE_NAME)]);
  }

  if (path === "/api/state" && req.method === "GET") {
    const value = session(req);
    return value ? json(req, 200, state(value)) : error(req, 401);
  }

  if (path === "/api/logout" && req.method === "POST") {
    const value = session(req);
    if (!value || !csrfOK(req, value)) return error(req, 403);
    sessions.delete(value.id);
    return json(req, 200, { ok: true }, [expiredCookie(COOKIE_NAME)]);
  }

  if (path === "/api/mfa/provision" && req.method === "POST") {
    const value = session(req);
    if (!value || !csrfOK(req, value) || !(await body(req))) return error(req, 403);
    const mfa = record(value.accountId);
    if (mfa.enabled) return error(req, 409);

    const manualSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    const current = BigInt(Math.floor(Date.now() / 30_000));
    mfa.protectedSecret = await encrypt(manualSecret);
    mfa.provisioning = { expiresAt: Date.now() + PROVISIONING_LIFETIME_MS, used: false };
    mfa.acceptedTotpCounter = undefined;
    reset(mfa.otpAttempts);
    return json(req, 200, {
      ok: true,
      manualSecret,
      verificationCode: await totp(manualSecret, current),
    });
  }

  if (path === "/api/mfa/verify-otp" && req.method === "POST") {
    const value = session(req);
    if (!value || !csrfOK(req, value)) return error(req, 403);
    const mfa = record(value.accountId);
    if (locked(mfa.otpAttempts)) return error(req, 429);

    const input = await body(req);
    if (!input || !otpOK(input.otp)) {
      fail(mfa.otpAttempts);
      return error(req, 401);
    }

    const pending = mfa.provisioning;
    const protectedSecret = mfa.protectedSecret;
    let accepted: bigint | undefined;
    if (pending && protectedSecret && !pending.used && pending.expiresAt >= Date.now()) {
      try {
        const secret = await decrypt(protectedSecret);
        const current = BigInt(Math.floor(Date.now() / 30_000));
        for (const counter of [current - 1n, current, current + 1n]) {
          if (counter >= 0n && await totp(secret, counter) === input.otp) {
            accepted = counter;
            break;
          }
        }
      } catch {
        /* Generic failure below; do not expose cryptographic details. */
      }
    }

    const issued = accepted === undefined ? undefined : await newCodes();
    if (
      accepted === undefined ||
      !issued ||
      !pending ||
      pending !== mfa.provisioning ||
      pending.used ||
      pending.expiresAt < Date.now() ||
      mfa.enabled ||
      mfa.acceptedTotpCounter === accepted
    ) {
      fail(mfa.otpAttempts);
      return error(req, 401);
    }

    pending.used = true;
    mfa.acceptedTotpCounter = accepted;
    mfa.enabled = true;
    mfa.provisioning = undefined;
    /* [3] Initial issuance replaces the empty prior set atomically. */
    mfa.recoveryCodes = issued.protected;
    reset(mfa.otpAttempts);
    return json(req, 200, {
      ok: true,
      mfa: { enabled: true, hasRecoveryCodes: true, provisioningPending: false },
      backupCodes: issued.raw,
    });
  }

  if (path === "/api/mfa/regenerate-backup" && req.method === "POST") {
    const value = session(req);
    if (!value || !csrfOK(req, value) || !(await body(req))) return error(req, 403);
    const mfa = record(value.accountId);
    if (!mfa.enabled) return error(req, 409);

    const issued = await newCodes();
    /*
     [3] Replacement is permanent: no prior hashes are retained, so used and
     pre-regeneration recovery codes can never become valid again.
    */
    mfa.recoveryCodes = issued.protected;
    reset(mfa.recoveryAttempts);
    return json(req, 200, { ok: true, backupCodes: issued.raw });
  }

  if (path === "/api/mfa/recover" && req.method === "POST") {
    const value = session(req);
    if (!value || !csrfOK(req, value)) return error(req, 403);
    const mfa = record(value.accountId);
    if (!mfa.enabled || locked(mfa.recoveryAttempts)) return error(req, 429);

    const input = await body(req);
    const code = input ? recoveryCode(input.recoveryCode) : null;
    if (!code) {
      fail(mfa.recoveryAttempts);
      return error(req, 401);
    }

    const candidates = mfa.recoveryCodes.slice();
    const matches = await Promise.all(candidates.map((candidate) => codeMatches(code, candidate)));
    const index = matches.findIndex(Boolean);
    const snapshot = index >= 0 ? candidates[index] : undefined;
    const current = index >= 0 ? mfa.recoveryCodes[index] : undefined;
    if (!snapshot || current !== snapshot || current.used) {
      fail(mfa.recoveryAttempts);
      return error(req, 401);
    }

    current.used = true;
    reset(mfa.recoveryAttempts);
    return json(req, 200, { ok: true });
  }

  return error(req, 404);
}

Bun.serve({
  port: 3000,
  tls: { cert, key },
  async fetch(req) {
    try {
      const url = new URL(req.url);
      if (url.protocol !== "https:") return error(req, 400);

      if (req.method === "OPTIONS") {
        if (!trusted(req.headers.get("origin"))) return error(req, 403);
        const result = headers(req, "text/plain; charset=utf-8");
        result.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        result.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
        result.set("Access-Control-Max-Age", "600");
        return new Response(null, { status: 204, headers: result });
      }

      const origin = req.headers.get("origin");
      if ((origin && !trusted(origin)) || (req.method === "POST" && !trusted(origin))) return error(req, 403);
      if (url.pathname.startsWith("/api/")) return await api(req, url.pathname);
      if (url.pathname === "/" && req.method === "GET") {
        const nonce = token(24);
        return new Response(html(nonce), {
          headers: headers(req, "text/html; charset=utf-8", nonce),
        });
      }
      return error(req, 404);
    } catch {
      /* [2] Production-safe generic error response: no stack traces or secrets. */
      return error(req, 500);
    }
  },
});
