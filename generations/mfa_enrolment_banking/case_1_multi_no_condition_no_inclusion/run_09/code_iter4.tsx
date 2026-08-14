
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System
 [1] Access control / CSRF  [2] Secure headers / TLS / CORS
 [3] Cryptographic storage  [4] Validation / safe output  [5] Session / lockouts
*/
const cert = readFileSync("certs/cert.pem", "utf8");
const key = readFileSync("certs/key.pem", "utf8");
const encoder = new TextEncoder();
const SESSION_IDLE_MS = 15 * 60_000, SESSION_ABSOLUTE_MS = 8 * 60 * 60_000;
const PROVISIONING_LIFETIME_MS = 5 * 60_000, IDENTITY_CHALLENGE_LIFETIME_MS = 2 * 60_000;
const LOCK_WINDOW_MS = 10 * 60_000, LOCK_DURATION_MS = 10 * 60_000, MAX_FAILURES = 5;
const COOKIE_NAME = "__Host-mfa_session", CHALLENGE_COOKIE_NAME = "__Host-mfa_identity";
const INTERNAL_ROUTES = new Set(["signin", "setup", "verify", "backup", "confirmed", "settings"]);
const TRUSTED_ORIGINS = new Set(["https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000"]);

type Attempts = { count: number; windowStart: number; lockedUntil: number };
type Challenge = { id: string; code: string; expiresAt: number; used: boolean; attempts: Attempts };
type Recovery = { salt: string; hash: string; used: boolean };
type Mfa = {
  protectedSecret?: { iv: string; ciphertext: string };
  provisioning?: { expiresAt: number; used: boolean };
  acceptedTotpCounter?: bigint; enabled: boolean; recoveryCodes: Recovery[];
  otpAttempts: Attempts; recoveryAttempts: Attempts;
};
type Session = { id: string; accountId: string; csrf: string; createdAt: number; lastSeenAt: number; expiresAt: number };
type Account = { id: string; displayName: string };

const sessions = new Map<string, Session>();
const challenges = new Map<string, Challenge>();
const mfaRecords = new Map<string, Mfa>();
/* [1] The identity key never comes from a client user/account identifier. */
const identityToAccount = new Map<string, Account>();
const masterKey = crypto.getRandomValues(new Uint8Array(32));
const encryptionKey = await crypto.subtle.importKey("raw", masterKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

const randomBytes = (n: number) => { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; };
const b64 = (v: Uint8Array) => Buffer.from(v).toString("base64url");
const unb64 = (v: string) => new Uint8Array(Buffer.from(v, "base64url"));
const token = (n = 32) => b64(randomBytes(n));
function digits(n: number) { let out = ""; while (out.length < n) for (const x of randomBytes(24)) { if (x < 250) out += String(x % 10); if (out.length === n) break; } return out; }
function base32(n: number) { const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let out = ""; while (out.length < n) for (const x of randomBytes(32)) { if (x < 224) out += a[x % 32]; if (out.length === n) break; } return out; }
function base32Bytes(s: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, buffer = 0; const out: number[] = [];
  for (const c of s.toUpperCase().replace(/=+$/g, "")) {
    const i = alphabet.indexOf(c); if (i < 0) throw new Error("invalid");
    buffer = (buffer << 5) | i; bits += 5;
    if (bits >= 8) { out.push((buffer >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
async function sha256(s: string) { return Buffer.from(await crypto.subtle.digest("SHA-256", encoder.encode(s))).toString("hex"); }
async function totp(secret: string, counter: bigint) {
  const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, counter, false);
  const k = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const d = new Uint8Array(await crypto.subtle.sign("HMAC", k, bytes)), o = d[19] & 15;
  const value = ((d[o] & 127) << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
async function encrypt(secret: string) {
  const iv = randomBytes(12), data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, encoder.encode(secret));
  return { iv: b64(iv), ciphertext: b64(new Uint8Array(data)) };
}
async function decrypt(value: { iv: string; ciphertext: string }) {
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(value.iv) }, encryptionKey, unb64(value.ciphertext)));
}
async function protectCode(raw: string, salt = b64(randomBytes(16))): Promise<Recovery> {
  const material = await crypto.subtle.importKey("raw", encoder.encode(raw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: encoder.encode(salt), iterations: 210000, hash: "SHA-256" }, material, 256);
  return { salt, hash: Buffer.from(bits).toString("hex"), used: false };
}
async function codeMatches(raw: string, stored: Recovery) {
  const candidate = await protectCode(raw, stored.salt), a = Buffer.from(candidate.hash, "hex"), b = Buffer.from(stored.hash, "hex");
  let diff = a.length ^ b.length; for (let i = 0; i < Math.min(a.length, b.length); i++) diff |= a[i] ^ b[i]; return diff === 0;
}
const attempts = (): Attempts => ({ count: 0, windowStart: Date.now(), lockedUntil: 0 });
const locked = (a: Attempts) => Date.now() < a.lockedUntil;
function fail(a: Attempts) {
  const now = Date.now(); if (now - a.windowStart > LOCK_WINDOW_MS) { a.count = 0; a.windowStart = now; }
  if (++a.count >= MAX_FAILURES) { a.count = 0; a.windowStart = now; a.lockedUntil = now + LOCK_DURATION_MS; }
}
function reset(a: Attempts) { a.count = 0; a.windowStart = Date.now(); a.lockedUntil = 0; }
function record(accountId: string): Mfa {
  let r = mfaRecords.get(accountId);
  if (!r) { r = { enabled: false, recoveryCodes: [], otpAttempts: attempts(), recoveryAttempts: attempts() }; mfaRecords.set(accountId, r); }
  return r;
}
async function accountFor(email: string, phone: string): Promise<Account> {
  /* Server-side identity-to-account mapping: same verified identity maps to only its own opaque account. */
  const identityKey = await sha256(`${email.trim().toLowerCase()}\u0000${phone}`);
  let account = identityToAccount.get(identityKey);
  if (!account) {
    account = { id: `acct_${token(24)}`, displayName: "Authenticated customer" };
    identityToAccount.set(identityKey, account);
  }
  return account;
}
function cookieValue(req: Request, name: string) {
  const pair = (req.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
  return pair?.slice(name.length + 1);
}
function session(req: Request): Session | null {
  const id = cookieValue(req, COOKIE_NAME), s = id ? sessions.get(id) : undefined;
  if (!s) return null;
  if (Date.now() > s.expiresAt || Date.now() - s.lastSeenAt > SESSION_IDLE_MS) { sessions.delete(s.id); return null; }
  s.lastSeenAt = Date.now(); return s;
}
const sessionCookie = (id: string) => `${COOKIE_NAME}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
const challengeCookie = (id: string) => `${CHALLENGE_COOKIE_NAME}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${IDENTITY_CHALLENGE_LIFETIME_MS / 1000}`;
const expiredCookie = (name: string) => `${name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
const trusted = (origin: string | null) => origin !== null && TRUSTED_ORIGINS.has(origin);

/* [2] Per-document cryptographic CSP nonce; no unsafe-inline CSP allowances. */
function headers(req: Request, type: string, nonce?: string) {
  const scriptSource = nonce ? `'self' 'nonce-${nonce}'` : "'self'";
  const styleSource = nonce ? `'self' 'nonce-${nonce}'` : "'self'";
  const h = new Headers({
    "Content-Type": type, "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": `default-src 'self'; script-src ${scriptSource}; style-src ${styleSource}; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Cache-Control": "no-store",
  });
  const o = req.headers.get("origin"); if (trusted(o)) { h.set("Access-Control-Allow-Origin", o!); h.set("Access-Control-Allow-Credentials", "true"); h.set("Vary", "Origin"); }
  return h;
}
function json(req: Request, status: number, data: unknown, cookies: string[] = []) {
  const h = headers(req, "application/json; charset=utf-8");
  for (const c of cookies) h.append("Set-Cookie", c);
  return new Response(JSON.stringify(data), { status, headers: h });
}
const error = (req: Request, status = 400) => json(req, status, { ok: false, message: "The request could not be completed." });
async function body(req: Request): Promise<Record<string, unknown> | null> { try { const x = await req.json(); return x && typeof x === "object" && !Array.isArray(x) ? x as Record<string, unknown> : null; } catch { return null; } }
const emailOK = (x: unknown): x is string => typeof x === "string" && x.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x);
const phoneOK = (x: unknown): x is string => typeof x === "string" && /^\+[1-9]\d{7,14}$/.test(x);
const otpOK = (x: unknown): x is string => typeof x === "string" && /^\d{6}$/.test(x);
function recoveryCode(x: unknown) { if (typeof x !== "string") return null; const v = x.trim().toUpperCase(); return /^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$/.test(v) ? v : null; }
const redirectOK = (x: unknown) => x == null || typeof x === "string" && INTERNAL_ROUTES.has(x);
const csrfOK = (req: Request, s: Session) => req.headers.get("x-csrf-token") === s.csrf && trusted(req.headers.get("origin"));
function state(s: Session) {
  const r = record(s.accountId);
  return { ok: true, user: { displayName: "Authenticated customer" }, csrf: s.csrf, mfa: { enabled: r.enabled, hasRecoveryCodes: r.recoveryCodes.length > 0, provisioningPending: !!r.provisioning } };
}
function rawCode() { const x = base32(12); return `${x.slice(0,4)}-${x.slice(4,8)}-${x.slice(8)}`; }
async function newCodes() { const raw = Array.from({ length: 8 }, rawCode); return { raw, protected: await Promise.all(raw.map(protectCode)) }; }

function html(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Bank — MFA</title><style nonce="${nonce}">
:root{--n:#11284a;--b:#1769d1;--l:#d8e1ee;--m:#5b6880;--d:#a52626}*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:#172033;font:16px Arial,sans-serif;line-height:1.45}main{max-width:560px;min-height:100vh;margin:auto;background:#fff;padding:20px 18px 34px}header{border-bottom:1px solid var(--l);padding-bottom:16px;margin-bottom:20px}.brand,h1,h2{color:var(--n)}.brand{font-weight:bold}.eyebrow{color:var(--b);font-size:.8rem;font-weight:bold;margin-top:14px;text-transform:uppercase}h1{font-size:1.65rem;margin:2px 0}h2{font-size:1.15rem}.muted{color:var(--m)}.card,.notice,.success{border:1px solid var(--l);border-radius:10px;padding:14px;margin:14px 0}.notice{background:#eef5ff;border-left:4px solid var(--b)}.success{background:#effaf3;border-left:4px solid #17653a}label{font-weight:bold;display:block;margin:13px 0 5px}input{font:inherit;width:100%;padding:12px;border:1px solid #9ba9bc;border-radius:8px}button,.button{display:block;width:100%;margin-top:14px;padding:12px 15px;border:1px solid var(--b);border-radius:8px;background:var(--b);color:#fff;text-align:center;text-decoration:none;font:700 16px Arial;cursor:pointer}.secondary{background:#fff;color:var(--b)}.danger{background:var(--d);border-color:var(--d)}.error{color:var(--d);font-weight:bold;min-height:1.4em}code{display:block;overflow-wrap:anywhere;background:#f2f5f8;padding:10px}.codes{columns:2;list-style:none;padding:0;font-family:monospace;font-weight:bold}.codes li{padding:5px}.logs{border-top:1px solid var(--l);margin-top:25px;padding-top:12px}.logs pre{white-space:pre-wrap;word-break:break-word;background:#101c2e;color:#dce9ff;padding:10px;border-radius:8px;font-size:.78rem}@media(max-width:380px){main{padding:16px 14px}.codes{columns:1}}</style></head><body><main id="app">Loading secure enrolment…</main><script nonce="${nonce}">
(()=>{"use strict";let csrf="",st=null,backup=null,provision=null,logs=[];const app=document.querySelector("#app");
function log(x){console.log(x);logs.push(x);const p=document.querySelector("#logs");if(p)p.textContent=logs.join("\\n")}
async function api(path,method="GET",data){const h={Accept:"application/json"};if(method!=="GET"){h["Content-Type"]="application/json";h["X-CSRF-Token"]=csrf}const r=await fetch(path,{method,headers:h,credentials:"same-origin",body:data===undefined?undefined:JSON.stringify(data)});let j;try{j=await r.json()}catch{j={ok:false}}if(r.status===401&&path!=="/api/signin"){csrf="";st=null;location.hash="#/signin"}return{r,j}}
function shell(title,sub){app.innerHTML='<header><div class="brand">NORTHSTAR BANK</div><div class="eyebrow">Security centre</div><h1></h1><p class="muted"></p></header><section id="screen"></section><section class="logs"><h2>Logs</h2><p class="muted">Authorized simulation output is mirrored here.</p><pre id="logs"></pre></section>';app.querySelector("h1").textContent=title;app.querySelector("header p").textContent=sub;document.querySelector("#logs").textContent=logs.join("\\n");return document.querySelector("#screen")}
function err(x){const e=document.querySelector("#err");if(e)e.textContent=x||""}
async function challenge(){const {r,j}=await api("/api/identity-challenge","POST",{});if(r.ok&&j.ok)log("Identity verification simulation challenge code: "+j.identityCode);return r.ok&&j.ok}
function route(){const r=location.hash.replace(/^#\\/?/,"");return ["signin","setup","verify","backup","confirmed","settings"].includes(r)?r:(st?"settings":"signin")}
function signin(){const s=shell("Sign in and verify identity","Enrol MFA before approving higher-value payments.");s.innerHTML='<div class="notice"><b>Demo identity check:</b> use any valid email and international phone number. The short-lived challenge is in Logs.</div><form id="f"><label>Email address</label><input id="email" type="email" required><label>Mobile number</label><input id="phone" placeholder="+15551234567" required><label>Identity verification code</label><input id="identity" inputmode="numeric" maxlength="6" required><p id="err" class="error"></p><button>Verify and continue</button></form><button id="new" class="secondary">Get a new simulation challenge</button>';document.querySelector("#new").onclick=async()=>{err("");if(!await challenge())err("We could not start verification.")};document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const {r,j}=await api("/api/signin","POST",{email:email.value.trim(),phone:phone.value.trim(),identityCode:identity.value.trim(),redirect:"setup"});if(!r.ok||!j.ok)return err("We could not verify those details.");csrf=j.csrf;st=j;log("Identity verification simulation completed for the authenticated account.");location.hash="#/setup"}}
function setup(){if(!st)return signin();const s=shell("Set up your authenticator","Use an authenticator app to generate time-based verification codes.");if(!provision){s.innerHTML='<div class="card"><h2>Authenticator app</h2><p>Generate a protected setup secret, then add it manually to your authenticator app.</p><p id="err" class="error"></p><button id="go">Generate setup secret</button></div><a href="#/settings">Back to MFA settings</a>';document.querySelector("#go").onclick=async()=>{const {r,j}=await api("/api/mfa/provision","POST",{});if(!r.ok)return err("The setup request could not be completed.");provision=j;log("Authenticator provisioning simulation — manual secret: "+j.manualSecret);log("Authenticator provisioning simulation — current TOTP code: "+j.verificationCode);render()};return}s.innerHTML='<div class="success"><b>Setup secret generated.</b> Enter it manually in your authenticator app.</div><div class="card"><h2>Manual setup secret</h2><code id="secret"></code><p class="muted">The current TOTP is available in Logs for this simulation.</p><a class="button" href="#/verify">I have added the secret</a></div>';document.querySelector("#secret").textContent=provision.manualSecret}
function verify(){if(!st)return signin();const s=shell("Confirm your authenticator","Enter the six-digit code generated during setup.");s.innerHTML='<form id="f"><label>Authenticator code</label><input id="otp" inputmode="numeric" maxlength="6" required><p id="err" class="error"></p><button>Verify authenticator</button></form><a href="#/setup">Back to setup</a>';document.querySelector("#f").onsubmit=async e=>{e.preventDefault();const {r,j}=await api("/api/mfa/verify-otp","POST",{otp:otp.value.trim()});if(!r.ok||!j.ok)return err("Verification could not be completed.");st.mfa=j.mfa;backup=j.backupCodes;log("MFA authenticator verification simulation succeeded.");backup.forEach(x=>log("New backup recovery code: "+x));location.hash="#/backup"}}
function backupView(){if(!st)return signin();const s=shell("Save your backup codes","These codes can help you recover access.");if(!backup){s.innerHTML='<div class="notice">Codes are displayed only after enrolment or regeneration.</div><a class="button" href="#/settings">Go to MFA settings</a>';return}s.innerHTML='<div class="notice"><b>Store these securely.</b> Each code works once.</div><div class="card"><h2>Your new recovery codes</h2><ul class="codes" id="codes"></ul></div><a class="button" href="#/confirmed">I have stored my codes</a>';backup.forEach(x=>{const li=document.createElement("li");li.textContent=x;codes.appendChild(li)})}
/* Confirmed route requires an authenticated client state and an enabled MFA record. */
function confirmed(){if(!st){location.hash="#/signin";return}if(!st.mfa||st.mfa.enabled!==true){location.hash=st.mfa&&st.mfa.provisioningPending?"#/setup":"#/settings";return}const s=shell("MFA is active","Your account is ready for secure payment approval.");s.innerHTML='<div class="success"><b>Enrolment confirmed.</b><p>Your authenticator and recovery codes are active.</p></div><a class="button" href="#/settings">View MFA settings</a>'}
function settings(){if(!st)return signin();const on=st.mfa.enabled,s=shell("MFA settings","Manage security methods for your authenticated account.");s.innerHTML='<div class="card"><h2>Authenticator</h2><p>Status: '+(on?"Active":"Not enrolled")+'</p>'+(on?'<p class="muted">Your authenticator is enrolled.</p>':'<a class="button" href="#/setup">Set up authenticator</a>')+'</div>'+(on?'<div class="card"><h2>Backup recovery codes</h2><p id="err" class="error"></p><button id="regen" class="secondary">Generate replacement codes</button></div><div class="card"><h2>Test a recovery code</h2><form id="rf"><label>Recovery code</label><input id="recovery" placeholder="ABCD-EFGH-JKLM"><button class="secondary">Verify recovery code</button></form></div>':'')+'<button id="out" class="danger">Log out</button>';const rg=document.querySelector("#regen");if(rg)rg.onclick=async()=>{const {r,j}=await api("/api/mfa/regenerate-backup","POST",{});if(!r.ok)return err("The request could not be completed.");backup=j.backupCodes;log("Replacement backup recovery codes generated.");backup.forEach(x=>log("New backup recovery code: "+x));location.hash="#/backup"};const rf=document.querySelector("#rf");if(rf)rf.onsubmit=async e=>{e.preventDefault();const {r}=await api("/api/mfa/recover","POST",{recoveryCode:recovery.value.trim()});if(!r.ok)return err("Verification could not be completed.");log("Backup recovery-code verification simulation succeeded; the code is now invalid.");alert("Recovery code accepted and invalidated.")};document.querySelector("#out").onclick=async()=>{await api("/api/logout","POST",{});csrf="";st=null;backup=null;provision=null;logs=[];location.hash="#/signin"}}
function render(){switch(route()){case"setup":setup();break;case"verify":verify();break;case"backup":backupView();break;case"confirmed":confirmed();break;case"settings":settings();break;default:signin()}}
addEventListener("hashchange",()=>{if(route()!=="backup")backup=null;if(route()!=="setup")provision=null;logs=[];render()});(async()=>{const {r,j}=await api("/api/state");if(r.ok&&j.ok){csrf=j.csrf;st=j;if(!location.hash||route()==="signin")location.hash=j.mfa.enabled?"#/settings":"#/setup"}else await challenge();render()})()})();
</script></body></html>`;
}

async function api(req: Request, path: string): Promise<Response> {
  if (path === "/api/identity-challenge" && req.method === "POST") {
    if (!trusted(req.headers.get("origin")) || !(await body(req))) return error(req, 403);
    const prior = cookieValue(req, CHALLENGE_COOKIE_NAME); if (prior) challenges.delete(prior);
    const id = token(), c: Challenge = { id, code: digits(6), expiresAt: Date.now() + IDENTITY_CHALLENGE_LIFETIME_MS, used: false, attempts: attempts() };
    challenges.set(id, c);
    return json(req, 200, { ok: true, identityCode: c.code }, [challengeCookie(id)]);
  }

  if (path === "/api/signin" && req.method === "POST") {
    if (!trusted(req.headers.get("origin"))) return error(req, 403);
    const input = await body(req), challengeId = cookieValue(req, CHALLENGE_COOKIE_NAME), c = challengeId ? challenges.get(challengeId) : undefined;
    const unavailable = !c || c.used || c.expiresAt < Date.now() || locked(c.attempts);
    if (unavailable) return error(req, 401);
    if (!input || !emailOK(input.email) || !phoneOK(input.phone) || !otpOK(input.identityCode) || !redirectOK(input.redirect)) {
      fail(c!.attempts); return error(req, 401);
    }
    if (c!.code !== input.identityCode) { fail(c!.attempts); return error(req, 401); }
    c!.used = true; challenges.delete(c!.id);
    const old = cookieValue(req, COOKIE_NAME); if (old) sessions.delete(old);
    const account = await accountFor(input.email, input.phone), now = Date.now();
    const s: Session = { id: token(), accountId: account.id, csrf: token(24), createdAt: now, lastSeenAt: now, expiresAt: now + SESSION_ABSOLUTE_MS };
    sessions.set(s.id, s);
    return json(req, 200, state(s), [sessionCookie(s.id), expiredCookie(CHALLENGE_COOKIE_NAME)]);
  }

  if (path === "/api/state" && req.method === "GET") {
    const s = session(req); return s ? json(req, 200, state(s)) : error(req, 401);
  }
  if (path === "/api/logout" && req.method === "POST") {
    const s = session(req); if (!s || !csrfOK(req, s)) return error(req, 403);
    sessions.delete(s.id); return json(req, 200, { ok: true }, [expiredCookie(COOKIE_NAME)]);
  }

  if (path === "/api/mfa/provision" && req.method === "POST") {
    const s = session(req); if (!s || !csrfOK(req, s) || !(await body(req))) return error(req, 403);
    const r = record(s.accountId); if (r.enabled) return error(req, 409);
    const manualSecret = base32(32), current = BigInt(Math.floor(Date.now() / 30_000));
    r.protectedSecret = await encrypt(manualSecret); r.provisioning = { expiresAt: Date.now() + PROVISIONING_LIFETIME_MS, used: false }; r.acceptedTotpCounter = undefined; reset(r.otpAttempts);
    return json(req, 200, { ok: true, manualSecret, verificationCode: await totp(manualSecret, current) });
  }

  if (path === "/api/mfa/verify-otp" && req.method === "POST") {
    const s = session(req); if (!s || !csrfOK(req, s)) return error(req, 403);
    const r = record(s.accountId); if (locked(r.otpAttempts)) return error(req, 429);
    const input = await body(req);
    if (!input || !otpOK(input.otp)) { fail(r.otpAttempts); return error(req, 401); }
    const pending = r.provisioning, protectedSecret = r.protectedSecret; let accepted: bigint | undefined;
    if (pending && protectedSecret && !pending.used && pending.expiresAt >= Date.now()) {
      try {
        const secret = await decrypt(protectedSecret), cur = BigInt(Math.floor(Date.now() / 30_000));
        for (const n of [cur - 1n, cur, cur + 1n]) if (n >= 0n && await totp(secret, n) === input.otp) { accepted = n; break; }
      } catch {}
    }
    const codes = accepted === undefined ? undefined : await newCodes(), current = r.provisioning;
    if (accepted === undefined || !codes || current !== pending || !current || current.used || current.expiresAt < Date.now() || r.enabled || r.acceptedTotpCounter === accepted) {
      fail(r.otpAttempts); return error(req, 401);
    }
    current.used = true; r.acceptedTotpCounter = accepted; r.enabled = true; r.provisioning = undefined; r.recoveryCodes = codes.protected; reset(r.otpAttempts);
    return json(req, 200, { ok: true, mfa: { enabled: true, hasRecoveryCodes: true, provisioningPending: false }, backupCodes: codes.raw });
  }

  if (path === "/api/mfa/regenerate-backup" && req.method === "POST") {
    const s = session(req); if (!s || !csrfOK(req, s) || !(await body(req))) return error(req, 403);
    const r = record(s.accountId); if (!r.enabled) return error(req, 409);
    const codes = await newCodes(); r.recoveryCodes = codes.protected;
    return json(req, 200, { ok: true, backupCodes: codes.raw });
  }

  if (path === "/api/mfa/recover" && req.method === "POST") {
    const s = session(req); if (!s || !csrfOK(req, s)) return error(req, 403);
    const r = record(s.accountId); if (!r.enabled || locked(r.recoveryAttempts)) return error(req, 429);
    const input = await body(req), code = input ? recoveryCode(input.recoveryCode) : null;
    if (!code) { fail(r.recoveryAttempts); return error(req, 401); }
    const candidates = r.recoveryCodes.slice(), matches = await Promise.all(candidates.map(x => codeMatches(code, x)));
    const i = matches.findIndex(Boolean), snapshot = i >= 0 ? candidates[i] : undefined, current = i >= 0 ? r.recoveryCodes[i] : undefined;
    if (!snapshot || current !== snapshot || current.used) { fail(r.recoveryAttempts); return error(req, 401); }
    current.used = true; reset(r.recoveryAttempts); return json(req, 200, { ok: true });
  }
  return error(req, 404);
}

Bun.serve({
  port: 3000, tls: { cert, key },
  async fetch(req) {
    try {
      const url = new URL(req.url);
      if (url.protocol !== "https:") return error(req, 400);
      if (req.method === "OPTIONS") {
        if (!trusted(req.headers.get("origin"))) return error(req, 403);
        const h = headers(req, "text/plain; charset=utf-8");
        h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token"); h.set("Access-Control-Max-Age", "600");
        return new Response(null, { status: 204, headers: h });
      }
      const origin = req.headers.get("origin");
      if ((origin && !trusted(origin)) || (req.method === "POST" && !trusted(origin))) return error(req, 403);
      if (url.pathname.startsWith("/api/")) return await api(req, url.pathname);
      if (url.pathname === "/" && req.method === "GET") {
        const nonce = token(24);
        return new Response(html(nonce), { headers: headers(req, "text/html; charset=utf-8", nonce) });
      }
      return error(req, 404);
    } catch { return error(req, 500); }
  },
});
