
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — single Bun HTTPS server and inline mobile SPA.
 Security sections: authenticated account-bound sessions, CSRF, TLS headers,
 encrypted OTP secrets, hashed recovery codes, guarded verification stages.
 Task update: deterministic MFA fixtures require MFA_TEST_FIXTURES=1 explicitly.
*/

const PORT = Number(process.env.PORT || 3000);
const cert = readFileSync("certs/cert.pem");
const key = readFileSync("certs/key.pem");
const encoder = new TextEncoder();
const sessions = new Map<string, Session>();
const bootTokens = new Map<string, number>();
const users = new Map<string, User>();
const encryptionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
const hashPepper = randomToken(32);

/* Explicit opt-in only. Any unset, empty, or other value uses secure randomness. */
const TEST_FIXTURES = process.env.MFA_TEST_FIXTURES === "1";

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 30 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const LOCK_MS = 15 * 60 * 1000;

type Session = { userId: string; csrf: string; createdAt: number; lastSeen: number };
type TimedCode = { hash: string; expiresAt: number; used: boolean };
type Guard = { attempts: number; lockedUntil: number };
type User = {
  id: string;
  email: string;
  passwordHash: string;
  identity?: TimedCode;
  identityVerified: boolean;
  authenticatorEncrypted?: string;
  totpUsedSteps: Set<number>;
  mfaEnabled: boolean;
  recoveryHashes: Set<string>;
  recoveryShown: boolean;
  guards: { identity: Guard; authenticator: Guard; recovery: Guard };
};

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}
function randomDigits(length = 6): string {
  const values = crypto.getRandomValues(new Uint32Array(length));
  return Array.from(values, value => String(value % 10)).join("");
}

/* Cryptographic RNG with rejection sampling; generated values only use Base32 A-Z and 2-7. */
function secureBase32(length = 32): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "";
  while (result.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    for (const value of bytes) {
      if (value < 224) result += alphabet[value % 32];
      if (result.length === length) break;
    }
  }
  return result;
}
function recoveryCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let raw = "";
  while (raw.length < 10) {
    const values = crypto.getRandomValues(new Uint8Array(24));
    for (const value of values) {
      if (value < 238) raw += chars[value % chars.length];
      if (raw.length === 10) break;
    }
  }
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}
async function secureHash(value: string): Promise<string> {
  return Buffer.from(await crypto.subtle.digest("SHA-256", encoder.encode(`${hashPepper}:${value}`))).toString("base64url");
}
async function encrypt(value: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, encoder.encode(value));
  return `${Buffer.from(iv).toString("base64url")}.${Buffer.from(encrypted).toString("base64url")}`;
}
async function decrypt(value: string): Promise<string> {
  const [ivText, ciphertext] = value.split(".");
  if (!ivText || !ciphertext) throw new Error("invalid encrypted value");
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(ivText, "base64url") },
    encryptionKey,
    Buffer.from(ciphertext, "base64url"),
  );
  return new TextDecoder().decode(clear);
}

function validRecoveryCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/.test(value);
}

/* Fixture codes deliberately comply with the recovery-code validation grammar. */
function fixtureRecoveryCodes(): string[] {
  const codes = [
    "MARCS-2US23", "SAFE4-CDE56", "BANK7-HELP8", "LOCK9-KEY23",
    "STAR4-CASH5", "PLAN6-ROAD7", "GUAR8-DAN29", "BACK3-UP456",
  ];
  if (!codes.every(validRecoveryCode)) throw new Error("invalid recovery test fixture");
  return codes;
}

/* Fail safely during startup if a future fixture edit is malformed. */
if (TEST_FIXTURES && !fixtureRecoveryCodes().every(validRecoveryCode)) {
  throw new Error("MFA test fixture validation failed");
}

const marcus: User = {
  id: "account-owner-marcus",
  email: "marcus@example.com",
  passwordHash: await secureHash("MarcusSecure!54"),
  identityVerified: false,
  totpUsedSteps: new Set(),
  mfaEnabled: false,
  recoveryHashes: new Set(),
  recoveryShown: false,
  guards: {
    identity: { attempts: 0, lockedUntil: 0 },
    authenticator: { attempts: 0, lockedUntil: 0 },
    recovery: { attempts: 0, lockedUntil: 0 },
  },
};
users.set(marcus.email, marcus);

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) result[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return result;
}
function cookie(name: string, value: string, maxAge?: number): string {
  let text = `${name}=${encodeURIComponent(value)}; Path=/; Secure; HttpOnly; SameSite=Strict`;
  if (maxAge !== undefined) text += `; Max-Age=${maxAge}`;
  return text;
}
function expiredCookie(name: string): string {
  return `${name}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`;
}
function allowedOrigin(request: Request): string | null {
  const origin = request.headers.get("origin");
  if (!origin) return null;
  try {
    const url = new URL(origin);
    return url.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname) ? origin : null;
  } catch { return null; }
}

/* Security Misconfiguration: restrictive headers, TLS and trusted CORS only. */
function protectedHeaders(request: Request, nonce?: string): Headers {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, private",
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce || "none"}'; style-src 'nonce-${nonce || "none"}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
  });
  const origin = allowedOrigin(request);
  if (origin) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Vary", "Origin");
  }
  return headers;
}
function json(request: Request, body: unknown, status = 200, setCookie?: string): Response {
  const headers = protectedHeaders(request);
  if (setCookie) headers.append("Set-Cookie", setCookie);
  return new Response(JSON.stringify(body), { status, headers });
}
function fail(request: Request, status: number, error: string): Response {
  return json(request, { ok: false, error }, status);
}
function getSession(request: Request): Session | null {
  const token = parseCookies(request).mfa_session;
  const session = token ? sessions.get(token) : undefined;
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(token!);
    return null;
  }
  session.lastSeen = now;
  return session;
}
/* Broken Access Control: account identity is only sourced from the HttpOnly session. */
function authorizedUser(request: Request): { session: Session; user: User } | null {
  const session = getSession(request);
  const user = session ? [...users.values()].find(value => value.id === session.userId) : undefined;
  return session && user ? { session, user } : null;
}
function validCsrf(request: Request, session?: Session): boolean {
  const token = request.headers.get("x-csrf-token") || "";
  if (session) return token.length > 20 && token === session.csrf;
  const boot = parseCookies(request).mfa_boot;
  return !!boot && bootTokens.get(boot)! > Date.now() && token === boot;
}
async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch { return null; }
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
function guardState(guard: Guard): boolean { return Date.now() < guard.lockedUntil; }
function recordFailure(guard: Guard): void {
  if (++guard.attempts >= MAX_ATTEMPTS) {
    guard.lockedUntil = Date.now() + LOCK_MS;
    guard.attempts = 0;
  }
}
function success(guard: Guard): void { guard.attempts = 0; }
async function newTimedCode(value: string): Promise<TimedCode> {
  return { hash: await secureHash(value), expiresAt: Date.now() + CODE_LIFETIME_MS, used: false };
}

/* RFC 6238 helpers. Generated non-fixture secrets are validated before use. */
function base32Bytes(secret: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of secret.replace(/=+$/g, "").toUpperCase()) {
    const n = alphabet.indexOf(char);
    if (n < 0) throw new Error("invalid secret");
    bits += n.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  if (!bytes.length) throw new Error("invalid secret");
  return new Uint8Array(bytes);
}
async function totp(secret: string, step = Math.floor(Date.now() / 30000)): Promise<string> {
  const counter = new ArrayBuffer(8);
  new DataView(counter).setUint32(4, step, false);
  const hmacKey = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, counter));
  const offset = digest[19] & 15;
  const value = (((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]) % 1000000;
  return String(value).padStart(6, "0");
}
function statusFor(user: User, csrf: string) {
  return { ok: true, csrf, state: { signedIn: true, identityVerified: user.identityVerified, authenticatorReady: !!user.authenticatorEncrypted, mfaEnabled: user.mfaEnabled, recoveryShown: user.recoveryShown } };
}

async function api(request: Request, path: string): Promise<Response> {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: protectedHeaders(request) });

  if (path === "/api/sign-in" && request.method === "POST") {
    if (!validCsrf(request)) return fail(request, 403, "Please refresh the page, then try again.");
    const body = await readBody(request);
    if (!body || !validEmail(body.email) || !validPassword(body.password)) return fail(request, 400, "Enter an email like name@example.com and a password with at least 8 characters.");
    const user = users.get(body.email.trim().toLowerCase());
    if (!user || await secureHash(body.password) !== user.passwordHash) return fail(request, 401, "The email or password is not recognised. Check both and try again.");
    const old = parseCookies(request).mfa_session;
    if (old) sessions.delete(old);
    const id = randomToken(), csrf = randomToken();
    sessions.set(id, { userId: user.id, csrf, createdAt: Date.now(), lastSeen: Date.now() });
    bootTokens.delete(parseCookies(request).mfa_boot || "");
    return json(request, statusFor(user, csrf), 200, cookie("mfa_session", id, SESSION_ABSOLUTE_MS / 1000));
  }

  const owned = authorizedUser(request);
  if (!owned) return fail(request, 401, "Your secure session has ended. Please sign in again.");
  const { session, user } = owned;
  if (path === "/api/status" && request.method === "GET") return json(request, statusFor(user, session.csrf));
  if (request.method !== "POST") return fail(request, 404, "That page is not available.");
  if (!validCsrf(request, session)) return fail(request, 403, "This action could not be confirmed. Refresh the page and try again.");

  if (path === "/api/identity/request") {
    if (guardState(user.guards.identity)) return fail(request, 429, "Too many identity checks were tried. Wait 15 minutes, then try again.");
    const code = TEST_FIXTURES ? "123456" : randomDigits(6);
    user.identity = await newTimedCode(code);
    return json(request, { ok: true, csrf: session.csrf, testIdentityCode: code, message: "A check code is ready." });
  }
  if (path === "/api/identity/verify") {
    if (guardState(user.guards.identity)) return fail(request, 429, "Too many identity checks were tried. Wait 15 minutes, then try again.");
    const body = await readBody(request);
    if (!body || !validSixDigits(body.code)) return fail(request, 400, "Enter 6 digits. Example: 123456.");
    const code = user.identity;
    if (!code || code.used || Date.now() > code.expiresAt) return fail(request, 400, "Request a new check code, then enter its 6 digits.");
    if (code.hash !== await secureHash(body.code)) {
      recordFailure(user.guards.identity);
      return fail(request, 400, "That code did not match. Check all 6 digits or request a new code.");
    }
    code.used = true; user.identityVerified = true; success(user.guards.identity);
    return json(request, { ok: true, csrf: session.csrf, message: "Identity check complete." });
  }
  if (path === "/api/authenticator/setup") {
    if (!user.identityVerified) return fail(request, 403, "Complete the identity check before setting up an authenticator.");
    if (guardState(user.guards.authenticator)) return fail(request, 429, "Too many authenticator codes were tried. Wait 15 minutes, then try again.");
    const secret = TEST_FIXTURES ? "JBSWY3DPEHPK3PXP" : secureBase32(32);
    try { base32Bytes(secret); } catch { return fail(request, 500, "Authenticator setup could not be prepared. Please try again."); }
    user.authenticatorEncrypted = await encrypt(secret);
    user.totpUsedSteps.clear();
    const issuer = "Northstar Bank";
    const provisioningUri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(user.email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    return json(request, { ok: true, csrf: session.csrf, secret, provisioningUri, testTotpCode: await totp(secret) });
  }
  if (path === "/api/authenticator/verify") {
    if (!user.authenticatorEncrypted) return fail(request, 400, "Start authenticator setup before confirming a code.");
    const body = await readBody(request);
    if (!body || !validSixDigits(body.code)) return fail(request, 400, "Enter the 6 digits from your authenticator. Example: 123456.");
    const secret = await decrypt(user.authenticatorEncrypted), current = Math.floor(Date.now() / 30000);
    let matched: number | undefined;
    for (const step of [current - 1, current, current + 1]) if (!user.totpUsedSteps.has(step) && body.code === await totp(secret, step)) { matched = step; break; }
    if (matched === undefined) { recordFailure(user.guards.authenticator); return fail(request, 400, "That authenticator code did not match or was already used. Enter the current code."); }
    user.totpUsedSteps.add(matched); user.mfaEnabled = true; success(user.guards.authenticator);
    const codes = TEST_FIXTURES ? fixtureRecoveryCodes() : Array.from({ length: 8 }, recoveryCode);
    if (!codes.every(validRecoveryCode)) return fail(request, 500, "Recovery codes could not be prepared. Please try again.");
    user.recoveryHashes = new Set(await Promise.all(codes.map(secureHash))); user.recoveryShown = false;
    return json(request, { ok: true, csrf: session.csrf, recoveryCodes: codes });
  }
  if (path === "/api/recovery/acknowledge") {
    if (!user.mfaEnabled) return fail(request, 403, "Set up your authenticator before saving recovery codes.");
    user.recoveryShown = true;
    return json(request, { ok: true, csrf: session.csrf, message: "Recovery codes marked as saved. MFA enrolment is complete." });
  }
  if (path === "/api/recovery/regenerate") {
    if (!user.mfaEnabled) return fail(request, 403, "Set up your authenticator before making recovery codes.");
    const codes = TEST_FIXTURES ? fixtureRecoveryCodes() : Array.from({ length: 8 }, recoveryCode);
    if (!codes.every(validRecoveryCode)) return fail(request, 500, "Recovery codes could not be prepared. Please try again.");
    user.recoveryHashes = new Set(await Promise.all(codes.map(secureHash))); user.recoveryShown = false;
    return json(request, { ok: true, csrf: session.csrf, recoveryCodes: codes });
  }
  if (path === "/api/recovery/verify") {
    if (!user.mfaEnabled) return fail(request, 403, "MFA must be set up before checking a recovery code.");
    const body = await readBody(request);
    const candidate = typeof body?.code === "string" ? body.code.trim().toUpperCase() : "";
    if (!validRecoveryCode(candidate)) return fail(request, 400, "Enter a recovery code in this format: ABCDE-FGHIJ.");
    const hash = await secureHash(candidate);
    if (!user.recoveryHashes.has(hash)) { recordFailure(user.guards.recovery); return fail(request, 400, "That recovery code is invalid or has already been used. Try another unused code."); }
    user.recoveryHashes.delete(hash); success(user.guards.recovery);
    return json(request, { ok: true, csrf: session.csrf, message: "Recovery code accepted. It has now been used." });
  }
  if (path === "/api/logout") {
    const token = parseCookies(request).mfa_session;
    if (token) sessions.delete(token);
    return json(request, { ok: true }, 200, expiredCookie("mfa_session"));
  }
  return fail(request, 404, "That action is not available.");
}

function page(request: Request): Response {
  const nonce = randomToken(18), boot = randomToken();
  bootTokens.set(boot, Date.now() + 30 * 60 * 1000);
  const html = `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#17233b;--blue:#075dcc;--soft:#edf5ff;--bad:#b42318}*{box-sizing:border-box}body{margin:0;background:#f6f8fc;color:var(--ink);font:17px/1.65 Verdana,Arial,sans-serif;letter-spacing:.025em}main{max-width:560px;min-height:100vh;margin:auto;padding:20px;background:#fff}h1{line-height:1.25;font-size:1.7rem}button,input{font:inherit}input{width:100%;padding:13px;border:2px solid #71839c;border-radius:8px}.primary,.secondary{padding:13px;margin:12px 0;border-radius:8px;font-weight:bold;cursor:pointer}.primary{width:100%;border:0;background:var(--blue);color:#fff}.secondary{background:#fff;border:2px solid var(--blue);color:#064b9b}.notice,.logs{padding:12px;margin:15px 0;background:var(--soft);border-left:5px solid var(--blue)}.error{background:#fff1f0;border-color:var(--bad);color:#751a14}.hidden{display:none!important}.code,li{font-family:monospace;letter-spacing:.1em;word-break:break-all}.code{padding:10px;background:#eef1f5}.logs{font-size:.82rem;max-height:190px;overflow:auto;background:#f5f7fa}label{display:block;font-weight:bold;margin-top:16px}.example{color:#526177;font-size:.88rem}.step{font-weight:bold;color:#064b9b}.bar{height:8px;background:#dce6f4;border-radius:8px}.bar i{display:block;height:100%;background:var(--blue);border-radius:8px}ul{padding-left:22px}@media(max-width:370px){main{padding:16px}}
</style></head><body><main>
<header><strong>✦ Northstar Bank</strong></header><div class="bar"><i id="bar"></i></div><p class="step" id="step"></p>
<section id="message" aria-live="polite"></section><section id="screen"></section>
<h2>Logs</h2><section class="logs" id="logs" aria-live="polite">Ready.</section>
</main><script nonce="${nonce}">
(()=>{"use strict";let csrf=${JSON.stringify(boot)},view="sign",recovery=[],secret="";
const $=id=>document.getElementById(id),log=(...x)=>{$("logs").textContent+=String(x.join(" "))+"\\n";console.log(...x)},msg=(t,bad=false)=>{$("message").innerHTML='<div class="notice '+(bad?"error":"")+'">'+esc(t)+"</div>"},esc=s=>{const d=document.createElement("div");d.textContent=s;return d.innerHTML};
async function call(path,data){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data||{})});const o=await r.json();if(o.csrf)csrf=o.csrf;if(!r.ok)throw Error(o.error);return o}
function header(n,t){$("step").textContent="Step "+n+" of 5 · "+t;$("bar").style.width=(n*20)+"%"}
function render(){const s=$("screen");
if(view==="sign"){header(1,"Sign in");s.innerHTML='<h1>Set up extra payment protection</h1><p>Sign in to start. This takes a few short steps.</p><form id="f"><label>Email address</label><input id="email" type="email" autocomplete="email" value="marcus@example.com"><span class="example">Example: marcus@example.com</span><label>Password</label><input id="pass" type="password" autocomplete="current-password" value="MarcusSecure!54"><button class="primary">Sign in and continue</button></form>';$("f").onsubmit=async e=>{e.preventDefault();try{await call("/api/sign-in",{email:email.value,password:pass.value});view="identity";render()}catch(e){msg(e.message,true)}}}
else if(view==="identity"){header(2,"Identity check");s.innerHTML='<h1>Check it is you</h1><p>Request a 6-digit check code. There is no rush.</p><button class="primary" id="request">Request check code</button><div id="check"></div>';$("request").onclick=async()=>{try{const o=await call("/api/identity/request");log("Mock identity code:",o.testIdentityCode);$("check").innerHTML='<div class="notice">Your check code is ready.</div><form id="vf"><label>Check code</label><input id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6"><span class="example">Example: 123456</span><button class="primary">Check code</button></form>';/* Requirement: after request this is secondary; Check code remains sole primary. */$("request").className="secondary";$("request").textContent="Request a new check code";$("vf").onsubmit=async e=>{e.preventDefault();try{await call("/api/identity/verify",{code:code.value});view="setup";render()}catch(e){msg(e.message,true)}}}catch(e){msg(e.message,true)}}}
else if(view==="setup"){header(3,"Authenticator");s.innerHTML='<h1>Connect your authenticator</h1><p>Prepare the details, then use your authenticator app.</p><button class="primary" id="prepare">Prepare authenticator details</button><div id="details"></div>';$("prepare").onclick=async()=>{try{const o=await call("/api/authenticator/setup");secret=o.secret;log("Provisioning URI:",o.provisioningUri);log("Authenticator secret:",o.secret);log("Current TOTP:",o.testTotpCode);$("details").innerHTML='<div class="notice">Details are ready. Copy the secret into an authenticator app.</div><p class="code">'+esc(o.secret)+'</p><button class="secondary" id="copy">Copy secret</button><form id="of"><label>Authenticator code</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6"><span class="example">Example: 123456</span><button class="primary">Confirm authenticator</button></form>';$("copy").onclick=()=>navigator.clipboard.writeText(secret).then(()=>msg("Secret copied."));$("of").onsubmit=async e=>{e.preventDefault();try{const x=await call("/api/authenticator/verify",{code:otp.value});recovery=x.recoveryCodes;log("Recovery codes:",recovery.join(", "));view="recovery";render()}catch(e){msg(e.message,true)}}}catch(e){msg(e.message,true)}}}
else if(view==="recovery"){header(4,"Recovery codes");s.innerHTML='<h1>Save your recovery codes</h1><p>Keep these one-use codes somewhere private.</p><ul>'+recovery.map(x=>"<li>"+esc(x)+"</li>").join("")+'</ul><button class="primary" id="saved">I saved these codes</button><button class="secondary" id="regen">Make new codes</button>';$("saved").onclick=async()=>{try{await call("/api/recovery/acknowledge");view="done";render()}catch(e){msg(e.message,true)}};$("regen").onclick=async()=>{try{const o=await call("/api/recovery/regenerate");recovery=o.recoveryCodes;log("Replacement recovery codes:",recovery.join(", "));render()}catch(e){msg(e.message,true)}}}
else{header(5,"Complete");s.innerHTML='<h1>✓ MFA is ready</h1><div class="notice">Your authenticator and recovery codes are set up.</div><button class="primary" id="test">Check a recovery code</button><div id="testbox"></div>';$("test").onclick=()=>{$("testbox").innerHTML='<form id="rf"><label>Recovery code</label><input id="rc" placeholder="ABCDE-FGHIJ" autocomplete="one-time-code"><span class="example">Example: ABCDE-FGHIJ</span><button class="primary">Check recovery code</button></form>';$("rf").onsubmit=async e=>{e.preventDefault();try{const o=await call("/api/recovery/verify",{code:rc.value});msg(o.message);log("Recovery code accepted and consumed.")}catch(e){msg(e.message,true)}}}}
}render()})();
</script></main></body></html>`;
  const headers = protectedHeaders(request, nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.append("Set-Cookie", cookie("mfa_boot", boot, 30 * 60));
  return new Response(html, { headers });
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
      return fail(request, 500, "Something went wrong. Please refresh and try again.");
    }
  },
});
