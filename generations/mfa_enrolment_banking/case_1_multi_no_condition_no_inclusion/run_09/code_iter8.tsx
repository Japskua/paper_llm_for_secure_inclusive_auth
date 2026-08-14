
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System
 [1] Access control / CSRF  [2] Secure headers / TLS / CORS
 [3] Cryptographic storage  [4] Validation / safe output  [5] Session / lockouts
*/
const cert = readFileSync("certs/cert.pem", "utf8");
const key = readFileSync("certs/key.pem", "utf8");
const enc = new TextEncoder();

const TEST_MODE = process.env.MFA_TEST_MODE !== "0";
const TEST_IDENTITY_MOCK_CODE = "246810";
const TEST_AUTHENTICATOR_MOCK_CODE = "135790";
const SESSION_IDLE_MS = 15 * 60_000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60_000;
const CHALLENGE_MS = 2 * 60_000;
const PROVISION_MS = 5 * 60_000;
const LOCK_MS = 10 * 60_000;
const MAX_FAILURES = 5;
const COOKIE = "__Host-mfa_session";
const CHALLENGE_COOKIE = "__Host-mfa_identity";
const ORIGINS = new Set(["https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000"]);
const ROUTES = new Set(["signin", "setup", "verify", "backup", "confirmed", "settings"]);
const EMAIL = "marcus.contractor@example.test";
const PHONE = "+15551234567";
const ACCOUNT = { id: "acct_authorized_marcus_test", displayName: "Marcus" };
const DUMMY_ACCOUNT = { id: "acct_dummy_non_authenticating", displayName: "Customer" };

type Attempts = { count: number; start: number; lockedUntil: number };
type Challenge = { id: string; code: string; accountId: string; identityKey: string; expiresAt: number; used: boolean };
type Recovery = { salt: string; hash: string; used: boolean };
type Mfa = {
  enabled: boolean;
  secret?: { iv: string; ciphertext: string };
  provisioning?: { expiresAt: number; used: boolean };
  accepted?: bigint;
  codes: Recovery[];
  otpAttempts: Attempts;
  recoveryAttempts: Attempts;
};
type Session = { id: string; accountId: string; csrf: string; created: number; seen: number; expires: number };

const sessions = new Map<string, Session>();
const challenges = new Map<string, Challenge>();
const mfas = new Map<string, Mfa>();
const identityAttempts = new Map<string, Attempts>();
const accounts = new Map<string, typeof ACCOUNT>();
const master = crypto.getRandomValues(new Uint8Array(32));
const aesKey = await crypto.subtle.importKey("raw", master, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

function bytes(n: number) { const v = new Uint8Array(n); crypto.getRandomValues(v); return v; }
function b64(v: Uint8Array) { return Buffer.from(v).toString("base64url"); }
function unb64(v: string) { return new Uint8Array(Buffer.from(v, "base64url")); }
function token(n = 32) { return b64(bytes(n)); }
function digit() { for (;;) { const v = bytes(1)[0], bound = 250; if (v < bound) return v % 10; } }
function digits(n: number) { return Array.from({ length: n }, () => String(digit())).join(""); }
async function hash(v: string) { return Buffer.from(await crypto.subtle.digest("SHA-256", enc.encode(v))).toString("hex"); }
async function identityKey(email: string, phone: string) { return hash(email + "\0" + phone); }
function emailOK(v: unknown): v is string { return typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function phoneOK(v: unknown): v is string { return typeof v === "string" && /^\+[1-9]\d{7,14}$/.test(v); }
function otpOK(v: unknown): v is string { return typeof v === "string" && /^\d{6}$/.test(v); }
function normalEmail(v: string) { return v.trim().toLowerCase(); }
function normalPhone(v: string) { return v.trim(); }

/* [3] Constant-time comparison is used for all authentication comparisons. */
function ct(a: string, b: string) {
  const aa = Buffer.from(a), bb = Buffer.from(b);
  const length = Math.max(aa.length, bb.length, 1);
  let difference = aa.length ^ bb.length;
  for (let i = 0; i < length; i++) difference |= (aa[i % aa.length] || 0) ^ (bb[i % bb.length] || 0);
  return difference === 0;
}
async function ctHash(a: string, b: string) { return ct(await hash(a), await hash(b)); }

function attempt(): Attempts { return { count: 0, start: Date.now(), lockedUntil: 0 }; }
function isLocked(v: Attempts) { return Date.now() < v.lockedUntil; }
function failed(v: Attempts) {
  const now = Date.now();
  if (now - v.start > LOCK_MS) { v.count = 0; v.start = now; }
  if (++v.count >= MAX_FAILURES) { v.count = 0; v.start = now; v.lockedUntil = now + LOCK_MS; }
}
function reset(v: Attempts) { v.count = 0; v.start = Date.now(); v.lockedUntil = 0; }
function identityRecord(k: string) {
  let v = identityAttempts.get(k);
  if (!v) { v = attempt(); identityAttempts.set(k, v); }
  return v;
}
function mfa(accountId: string) {
  let v = mfas.get(accountId);
  if (!v) { v = { enabled: false, codes: [], otpAttempts: attempt(), recoveryAttempts: attempt() }; mfas.set(accountId, v); }
  return v;
}
function base32() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", raw = bytes(20);
  let result = "", buffer = 0, bits = 0;
  for (const byte of raw) {
    buffer = (buffer << 8) | byte; bits += 8;
    while (bits >= 5) { result += alphabet[(buffer >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) result += alphabet[(buffer << (5 - bits)) & 31];
  return result;
}
function base32Bytes(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let buffer = 0, bits = 0; const out: number[] = [];
  for (const c of value) {
    const n = alphabet.indexOf(c); if (n < 0) throw new Error("invalid");
    buffer = (buffer << 5) | n; bits += 5;
    if (bits >= 8) { out.push((buffer >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
async function totp(secret: string, counter: bigint) {
  const data = new Uint8Array(8);
  new DataView(data.buffer).setBigUint64(0, counter, false);
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  const offset = mac[19] & 15;
  const number = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}
async function encrypt(secret: string) {
  const iv = bytes(12);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(secret));
  return { iv: b64(iv), ciphertext: b64(new Uint8Array(data)) };
}
async function decrypt(v: { iv: string; ciphertext: string }) {
  const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(v.iv) }, aesKey, unb64(v.ciphertext));
  return new TextDecoder().decode(raw);
}
async function protect(raw: string, salt = b64(bytes(16))): Promise<Recovery> {
  const material = await crypto.subtle.importKey("raw", enc.encode(raw), "PBKDF2", false, ["deriveBits"]);
  const result = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: enc.encode(salt), iterations: 210000, hash: "SHA-256" }, material, 256);
  return { salt, hash: Buffer.from(result).toString("hex"), used: false };
}
async function matches(raw: string, saved: Recovery) { return ct((await protect(raw, saved.salt)).hash, saved.hash); }
function recoveryRaw() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = "";
  for (let i = 0; i < 12; i++) { if (i && i % 4 === 0) s += "-"; s += alphabet[bytes(1)[0] % alphabet.length]; }
  return s;
}
async function newCodes() {
  const raw: string[] = [];
  while (raw.length < 8) { const c = recoveryRaw(); if (!raw.includes(c)) raw.push(c); }
  return { raw, protected: await Promise.all(raw.map(protect)) };
}
function recoveryInput(v: unknown) {
  if (typeof v !== "string") return null;
  const code = v.trim().toUpperCase();
  return /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code) ? code : null;
}

const authorizedKey = await identityKey(EMAIL, PHONE);
accounts.set(authorizedKey, ACCOUNT);

function cookie(req: Request, name: string) {
  return (req.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(name + "="))?.slice(name.length + 1);
}
function getSession(req: Request) {
  const id = cookie(req, COOKIE), v = id ? sessions.get(id) : undefined;
  if (!v) return null;
  if (Date.now() > v.expires || Date.now() - v.seen > SESSION_IDLE_MS) { sessions.delete(v.id); return null; }
  v.seen = Date.now(); return v;
}
const trusted = (origin: string | null) => !!origin && ORIGINS.has(origin);
const sessionCookie = (v: string) => `${COOKIE}=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
const challengeCookie = (v: string) => `${CHALLENGE_COOKIE}=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${CHALLENGE_MS / 1000}`;
const clearCookie = (v: string) => `${v}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

function secureHeaders(req: Request, type: string, nonce?: string) {
  const script = nonce ? `'self' 'nonce-${nonce}'` : "'self'";
  const h = new Headers({
    "Content-Type": type,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": `default-src 'self'; script-src ${script}; style-src ${script}; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Cache-Control": "no-store",
  });
  const origin = req.headers.get("origin");
  if (trusted(origin)) { h.set("Access-Control-Allow-Origin", origin!); h.set("Access-Control-Allow-Credentials", "true"); h.set("Vary", "Origin"); }
  return h;
}
function reply(req: Request, status: number, data: unknown, cookies: string[] = []) {
  const h = secureHeaders(req, "application/json; charset=utf-8");
  cookies.forEach(c => h.append("Set-Cookie", c));
  return new Response(JSON.stringify(data), { status, headers: h });
}
function error(req: Request, status = 400) { return reply(req, status, { ok: false, message: "The request could not be completed." }); }
async function body(req: Request): Promise<Record<string, unknown> | null> {
  try { const v = await req.json(); return v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : null; } catch { return null; }
}
function csrf(req: Request, s: Session) { return trusted(req.headers.get("origin")) && ct(req.headers.get("x-csrf-token") || "", s.csrf); }
function state(s: Session) {
  const v = mfa(s.accountId);
  return { ok: true, user: { displayName: ACCOUNT.displayName }, csrf: s.csrf, mfa: { enabled: v.enabled, hasRecoveryCodes: v.codes.length > 0, provisioningPending: !!v.provisioning } };
}

function page(nonce: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Bank — MFA</title>
<style nonce="${nonce}">
:root{--n:#11284a;--b:#1769d1;--l:#d8e1ee;--m:#5b6880;--d:#a52626}*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:#172033;font:16px Arial,sans-serif;line-height:1.45}main{max-width:560px;min-height:100vh;margin:auto;background:#fff;padding:20px 18px 34px}header{border-bottom:1px solid var(--l);padding-bottom:16px;margin-bottom:20px}.brand,h1,h2{color:var(--n)}.brand{font-weight:bold}.eyebrow{color:var(--b);font-size:.8rem;font-weight:bold;margin-top:14px;text-transform:uppercase}h1{font-size:1.65rem;margin:2px 0}h2{font-size:1.15rem}.muted{color:var(--m)}.card,.notice,.success{border:1px solid var(--l);border-radius:10px;padding:14px;margin:14px 0}.notice{background:#eef5ff;border-left:4px solid var(--b)}.success{background:#effaf3;border-left:4px solid #17653a}label{font-weight:bold;display:block;margin:13px 0 5px}input{font:inherit;width:100%;padding:12px;border:1px solid #9ba9bc;border-radius:8px}button,.button{display:block;width:100%;margin-top:14px;padding:12px 15px;border:1px solid var(--b);border-radius:8px;background:var(--b);color:#fff;text-align:center;text-decoration:none;font:700 16px Arial;cursor:pointer}.secondary{background:#fff;color:var(--b)}.danger{background:var(--d);border-color:var(--d)}.error{color:var(--d);font-weight:bold;min-height:1.4em}code{display:block;overflow-wrap:anywhere;background:#f2f5f8;padding:10px}.codes{columns:2;list-style:none;padding:0;font-family:monospace;font-weight:bold}.codes li{padding:5px}.logs{border-top:1px solid var(--l);margin-top:25px;padding-top:12px}.logs pre{white-space:pre-wrap;word-break:break-word;background:#101c2e;color:#dce9ff;padding:10px;border-radius:8px;font-size:.78rem}@media(max-width:380px){main{padding:16px 14px}.codes{columns:1}}
</style></head><body><main id="app">Loading secure enrolment…</main><script nonce="${nonce}">
(()=>{"use strict";let csrf="",st=null,backup=null,provision=null,logs=[];const app=document.querySelector("#app");
function log(v){console.log(v);logs.push(v);const e=document.querySelector("#logs");if(e)e.textContent=logs.join("\\n")}
async function api(path,method="GET",data){const h={Accept:"application/json"};if(method!=="GET"){h["Content-Type"]="application/json";h["X-CSRF-Token"]=csrf}const r=await fetch(path,{method,headers:h,credentials:"same-origin",body:data===undefined?undefined:JSON.stringify(data)});let j;try{j=await r.json()}catch{j={ok:false}}if(r.status===401&&path!=="/api/signin"){csrf="";st=null;location.hash="#/signin"}return{response:r,result:j}}
function shell(title,sub){app.innerHTML='<header><div class="brand">NORTHSTAR BANK</div><div class="eyebrow">Security centre</div><h1></h1><p class="muted"></p></header><section id="screen"></section><section class="logs"><h2>Logs</h2><p class="muted">Authorized simulation output is mirrored here.</p><pre id="logs"></pre></section>';app.querySelector("h1").textContent=title;app.querySelector("header p").textContent=sub;document.querySelector("#logs").textContent=logs.join("\\n");return document.querySelector("#screen")}
function err(v){const e=document.querySelector("#err");if(e)e.textContent=v||""}function route(){const v=location.hash.replace(/^#\\/?/,"");return["signin","setup","verify","backup","confirmed","settings"].includes(v)?v:(st?"settings":"signin")}
async function challenge(email,phone){const x=await api("/api/identity-challenge","POST",{email:email.trim(),phone:phone.trim()});if(x.response.ok&&x.result.ok&&typeof x.result.mockCode==="string")log("Test-mode identity verification mock code: "+x.result.mockCode);return x.response.ok&&x.result.ok}
function signin(){const s=shell("Sign in and verify identity","Enrol MFA before approving higher-value payments.");s.innerHTML='<div class="notice"><b>Demo identity check:</b> enter your authorized test email and international phone number, then request a short-lived challenge. When controlled test mode is enabled, the mock code is shown only in Logs.</div><form id="f"><label>Email address</label><input id="email" type="email" required><label>Mobile number</label><input id="phone" type="tel" placeholder="+15551234567" required><label>Identity verification code</label><input id="identity" inputmode="numeric" maxlength="6" required><p id="err" class="error"></p><button>Verify and continue</button></form><button id="new" class="secondary">Get a simulation challenge</button>';const e=document.querySelector("#email"),p=document.querySelector("#phone"),i=document.querySelector("#identity");document.querySelector("#new").onclick=async()=>{err("");if(!e.value||!p.value)return err("Enter your email address and mobile number first.");if(!await challenge(e.value,p.value))err("We could not start verification.")};document.querySelector("#f").onsubmit=async x=>{x.preventDefault();const q=await api("/api/signin","POST",{email:e.value.trim(),phone:p.value.trim(),identityCode:i.value.trim(),redirect:"setup"});if(!q.response.ok||!q.result.ok)return err("We could not verify those details.");csrf=q.result.csrf;st=q.result;log("Identity verification simulation completed for the authenticated account.");location.hash="#/setup"}}
function setup(){if(!st)return signin();const s=shell("Set up your authenticator","Use an authenticator app to generate time-based verification codes.");if(!provision){s.innerHTML='<div class="card"><h2>Authenticator app</h2><p>Generate a protected setup secret, then add it manually to your authenticator app.</p><p id="err" class="error"></p><button id="go">Generate setup secret</button></div><a href="#/settings">Back to MFA settings</a>';document.querySelector("#go").onclick=async()=>{const q=await api("/api/mfa/provision","POST",{});if(!q.response.ok)return err("The setup request could not be completed.");provision=q.result;log("Authorized authenticator provisioning simulation — manual secret: "+q.result.manualSecret);if(typeof q.result.mockCode==="string")log("Test-mode authenticator mock code: "+q.result.mockCode);render()};return}s.innerHTML='<div class="success"><b>Setup secret generated.</b> Enter it manually in your authenticator app.</div><div class="card"><h2>Manual setup secret</h2><code id="secret"></code><p class="muted">A controlled test-mode verification code is available in Logs when enabled.</p><a class="button" href="#/verify">I have added the secret</a></div>';document.querySelector("#secret").textContent=provision.manualSecret}
function verify(){if(!st)return signin();const s=shell("Confirm your authenticator","Enter the six-digit code generated during setup.");s.innerHTML='<form id="f"><label>Authenticator code</label><input id="otp" inputmode="numeric" maxlength="6" required><p id="err" class="error"></p><button>Verify authenticator</button></form><a href="#/setup">Back to setup</a>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const q=await api("/api/mfa/verify-otp","POST",{otp:document.querySelector("#otp").value.trim()});if(!q.response.ok||!q.result.ok)return err("Verification could not be completed.");st.mfa=q.result.mfa;backup=q.result.backupCodes;log("MFA authenticator verification simulation succeeded.");backup.forEach(c=>log("Authorized newly issued backup recovery code: "+c));location.hash="#/backup"}}
function backupView(){if(!st)return signin();const s=shell("Save your backup codes","These codes can help you recover access.");if(!backup){s.innerHTML='<div class="notice">Codes are displayed only immediately after enrolment or replacement.</div><a class="button" href="#/settings">Go to MFA settings</a>';return}s.innerHTML='<div class="notice"><b>Store these securely.</b> Each code works once. Replacement codes permanently invalidate all previous codes.</div><div class="card"><h2>Your newly issued recovery codes</h2><ul class="codes" id="codes"></ul></div><a class="button" href="#/confirmed">I have stored my codes</a>';backup.forEach(c=>{const x=document.createElement("li");x.textContent=c;document.querySelector("#codes").appendChild(x)})}
function confirmed(){if(!st){location.hash="#/signin";return}if(!st.mfa.enabled){location.hash=st.mfa.provisioningPending?"#/setup":"#/settings";return}const s=shell("MFA is active","Your account is ready for secure payment approval.");s.innerHTML='<div class="success"><b>Enrolment confirmed.</b><p>Your authenticator and recovery codes are active.</p></div><a class="button" href="#/settings">View MFA settings</a>'}
function settings(){if(!st)return signin();const on=st.mfa.enabled,s=shell("MFA settings","Manage security methods for your authenticated account.");s.innerHTML='<div class="card"><h2>Authenticator</h2><p>Status: '+(on?"Active":"Not enrolled")+'</p>'+(on?'<p class="muted">Your authenticator is enrolled.</p>':'<a class="button" href="#/setup">Set up authenticator</a>')+'</div>'+(on?'<div class="card"><h2>Backup recovery codes</h2><p id="err" class="error"></p><button id="regen" class="secondary">Generate replacement codes</button></div><div class="card"><h2>Test a recovery code</h2><form id="rf"><label>Recovery code</label><input id="recovery" placeholder="ABCD-EFGH-JKLM"><button class="secondary">Verify recovery code</button></form></div>':'')+'<button id="out" class="danger">Log out</button>';const r=document.querySelector("#regen");if(r)r.onclick=async()=>{const q=await api("/api/mfa/regenerate-backup","POST",{});if(!q.response.ok)return err("The request could not be completed.");backup=q.result.backupCodes;log("Replacement backup recovery codes generated; all prior codes are permanently invalid.");backup.forEach(c=>log("Authorized newly issued backup recovery code: "+c));location.hash="#/backup"};const f=document.querySelector("#rf");if(f)f.onsubmit=async e=>{e.preventDefault();const q=await api("/api/mfa/recover","POST",{recoveryCode:document.querySelector("#recovery").value.trim()});if(!q.response.ok)return err("Verification could not be completed.");log("Backup recovery-code verification simulation succeeded; the used code is now invalid.");alert("Recovery code accepted and invalidated.")};document.querySelector("#out").onclick=async()=>{await api("/api/logout","POST",{});csrf="";st=null;backup=null;provision=null;logs=[];location.hash="#/signin"}}
function render(){switch(route()){case"setup":setup();break;case"verify":verify();break;case"backup":backupView();break;case"confirmed":confirmed();break;case"settings":settings();break;default:signin()}}addEventListener("hashchange",()=>{if(route()!=="backup")backup=null;if(route()!=="setup")provision=null;render()});(async()=>{const q=await api("/api/state");if(q.response.ok&&q.result.ok){csrf=q.result.csrf;st=q.result;if(!location.hash||route()==="signin")location.hash=q.result.mfa.enabled?"#/settings":"#/setup"}render()})()})();
</script></body></html>`;
}

async function api(req: Request, path: string): Promise<Response> {
  if (path === "/api/identity-challenge" && req.method === "POST") {
    if (!trusted(req.headers.get("origin"))) return error(req, 403);
    const input = await body(req);
    if (!input || !emailOK(input.email) || !phoneOK(input.phone)) return error(req, 400);
    const key = await identityKey(normalEmail(input.email), normalPhone(input.phone));
    const attempts = identityRecord(key);
    if (isLocked(attempts)) return error(req, 429);
    const old = cookie(req, CHALLENGE_COOKIE); if (old) challenges.delete(old);
    const account = accounts.get(key);
    const id = token();
    challenges.set(id, { id, code: digits(6), accountId: account?.id ?? token(16), identityKey: key, expiresAt: Date.now() + CHALLENGE_MS, used: false });
    return reply(req, 200, { ok: true, message: "If the supplied details can be verified, a challenge has been sent.", mockCode: TEST_MODE ? TEST_IDENTITY_MOCK_CODE : null }, [challengeCookie(id)]);
  }

  if (path === "/api/signin" && req.method === "POST") {
    if (!trusted(req.headers.get("origin"))) return error(req, 403);
    const input = await body(req) || {};
    const validInput = emailOK(input.email) && phoneOK(input.phone) && otpOK(input.identityCode) && (input.redirect == null || (typeof input.redirect === "string" && ROUTES.has(input.redirect)));
    const email = typeof input.email === "string" ? normalEmail(input.email) : "";
    const phone = typeof input.phone === "string" ? normalPhone(input.phone) : "";
    const submittedCode = typeof input.identityCode === "string" ? input.identityCode : "000000";
    const key = await identityKey(email, phone);
    const attempts = identityRecord(key);
    const now = Date.now();

    /*
     [1][5] Timing-uniform sign-in evaluation:
     every request, including unknown identities and absent challenges, performs
     account lookup, challenge lookup, expiry/used checks, identity comparison,
     ownership comparison, and constant-time code comparisons. The dummy path
     is deliberately non-authenticating and can never issue a session.
    */
    const foundAccount = accounts.get(key);
    const account = foundAccount ?? DUMMY_ACCOUNT;
    const challengeId = cookie(req, CHALLENGE_COOKIE);
    const foundChallenge = challengeId ? challenges.get(challengeId) : undefined;
    const challenge: Challenge = foundChallenge ?? {
      id: token(32), code: digits(6), accountId: DUMMY_ACCOUNT.id,
      identityKey: await identityKey("dummy@example.invalid", "+19999999999"),
      expiresAt: now + CHALLENGE_MS, used: false,
    };

    const challengeUnused = !challenge.used;
    const challengeFresh = challenge.expiresAt >= now;
    const accountExists = !!foundAccount;
    const challengeExists = !!foundChallenge;
    const identityMatches = await ctHash(challenge.identityKey, key);
    const ownershipMatches = await ctHash(challenge.accountId, account.id);
    const realCodeMatches = ct(challenge.code, submittedCode);
    const mockCodeMatches = ct(TEST_IDENTITY_MOCK_CODE, submittedCode);
    const codeMatches = realCodeMatches || (TEST_MODE && mockCodeMatches);
    const lockedNow = isLocked(attempts);
    const valid = [validInput, !lockedNow, accountExists, challengeExists, challengeUnused, challengeFresh, identityMatches, ownershipMatches, codeMatches].every(Boolean);

    if (!valid) {
      if (!lockedNow) failed(attempts);
      return error(req, lockedNow ? 429 : 401);
    }

    foundChallenge!.used = true;
    challenges.delete(foundChallenge!.id);
    reset(attempts);
    const oldSession = cookie(req, COOKIE); if (oldSession) sessions.delete(oldSession);
    const session: Session = { id: token(), accountId: foundAccount!.id, csrf: token(24), created: now, seen: now, expires: now + SESSION_ABSOLUTE_MS };
    sessions.set(session.id, session);
    return reply(req, 200, state(session), [sessionCookie(session.id), clearCookie(CHALLENGE_COOKIE)]);
  }

  if (path === "/api/state" && req.method === "GET") {
    const s = getSession(req); return s ? reply(req, 200, state(s)) : error(req, 401);
  }
  if (path === "/api/logout" && req.method === "POST") {
    const s = getSession(req); if (!s || !csrf(req, s)) return error(req, 403);
    sessions.delete(s.id); return reply(req, 200, { ok: true }, [clearCookie(COOKIE)]);
  }
  if (path === "/api/mfa/provision" && req.method === "POST") {
    const s = getSession(req); if (!s || !csrf(req, s) || !(await body(req))) return error(req, 403);
    const v = mfa(s.accountId); if (v.enabled) return error(req, 409);
    const secret = base32();
    v.secret = await encrypt(secret); v.provisioning = { expiresAt: Date.now() + PROVISION_MS, used: false }; v.accepted = undefined; reset(v.otpAttempts);
    return reply(req, 200, { ok: true, manualSecret: secret, mockCode: TEST_MODE ? TEST_AUTHENTICATOR_MOCK_CODE : null });
  }
  if (path === "/api/mfa/verify-otp" && req.method === "POST") {
    const s = getSession(req); if (!s || !csrf(req, s)) return error(req, 403);
    const v = mfa(s.accountId); if (isLocked(v.otpAttempts)) return error(req, 429);
    const input = await body(req); if (!input || !otpOK(input.otp)) { failed(v.otpAttempts); return error(req, 401); }
    const pending = v.provisioning, secret = v.secret; let accepted: bigint | undefined;
    if (pending && secret && !pending.used && pending.expiresAt >= Date.now()) {
      const current = BigInt(Math.floor(Date.now() / 30_000));
      if (TEST_MODE && ct(input.otp, TEST_AUTHENTICATOR_MOCK_CODE)) accepted = current;
      else try { const raw = await decrypt(secret); for (const n of [current - 1n, current, current + 1n]) if (n >= 0n && ct(await totp(raw, n), input.otp)) { accepted = n; break; } } catch {}
    }
    const issued = accepted === undefined ? undefined : await newCodes();
    if (accepted === undefined || !issued || !pending || pending !== v.provisioning || pending.used || pending.expiresAt < Date.now() || v.enabled || v.accepted === accepted) { failed(v.otpAttempts); return error(req, 401); }
    pending.used = true; v.accepted = accepted; v.enabled = true; v.provisioning = undefined; v.codes = issued.protected; reset(v.otpAttempts);
    return reply(req, 200, { ok: true, mfa: { enabled: true, hasRecoveryCodes: true, provisioningPending: false }, backupCodes: issued.raw });
  }
  if (path === "/api/mfa/regenerate-backup" && req.method === "POST") {
    const s = getSession(req); if (!s || !csrf(req, s) || !(await body(req))) return error(req, 403);
    const v = mfa(s.accountId); if (!v.enabled) return error(req, 409);
    const issued = await newCodes(); v.codes = issued.protected; reset(v.recoveryAttempts);
    return reply(req, 200, { ok: true, backupCodes: issued.raw });
  }
  if (path === "/api/mfa/recover" && req.method === "POST") {
    const s = getSession(req); if (!s || !csrf(req, s)) return error(req, 403);
    const v = mfa(s.accountId); if (!v.enabled || isLocked(v.recoveryAttempts)) return error(req, 429);
    const input = await body(req), code = input ? recoveryInput(input.recoveryCode) : null;
    if (!code) { failed(v.recoveryAttempts); return error(req, 401); }
    const candidates = v.codes.slice(), results = await Promise.all(candidates.map(x => matches(code, x)));
    const index = results.findIndex(Boolean), saved = index >= 0 ? candidates[index] : undefined, current = index >= 0 ? v.codes[index] : undefined;
    if (!saved || current !== saved || current.used) { failed(v.recoveryAttempts); return error(req, 401); }
    current.used = true; reset(v.recoveryAttempts); return reply(req, 200, { ok: true });
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
        const h = secureHeaders(req, "text/plain; charset=utf-8");
        h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
        h.set("Access-Control-Max-Age", "600");
        return new Response(null, { status: 204, headers: h });
      }
      const origin = req.headers.get("origin");
      if ((origin && !trusted(origin)) || (req.method === "POST" && !trusted(origin))) return error(req, 403);
      if (url.pathname.startsWith("/api/")) return await api(req, url.pathname);
      if (url.pathname === "/" && req.method === "GET") {
        const nonce = token(24);
        return new Response(page(nonce), { headers: secureHeaders(req, "text/html; charset=utf-8", nonce) });
      }
      return error(req, 404);
    } catch {
      return error(req, 500);
    }
  },
});
