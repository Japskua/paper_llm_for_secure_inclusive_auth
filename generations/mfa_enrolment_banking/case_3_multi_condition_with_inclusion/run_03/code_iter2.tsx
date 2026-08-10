
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — single Bun HTTPS server and inline mobile SPA.
 Security sections: authenticated account-bound sessions, CSRF, TLS headers,
 encrypted OTP secrets, hashed recovery codes, guarded verification stages.
 Test-only policy: deterministic mock values are returned only to the signed-in
 browser and printed only with browser console.log. They are never server logged
 or placed in the normal visible UI.
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
const TEST_FIXTURES = process.env.MFA_TEST_FIXTURES !== "0";

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
function recoveryCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  const raw = Array.from(bytes, b => chars[b % chars.length]).join("");
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

/* Deterministic test fixture account; arbitrary valid-looking credentials cannot authenticate. */
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

/* Security Misconfiguration: restrictive headers and trusted-origin-only CORS. */
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
/* Broken Access Control: user identity comes exclusively from the HttpOnly session. */
function authorizedUser(request: Request): { session: Session; user: User } | null {
  const session = getSession(request);
  const user = session ? [...users.values()].find(item => item.id === session.userId) : undefined;
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
function validRecoveryCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/.test(value);
}

/* Attempt guards belong to account + stage, so requesting/restarting never resets lockout. */
function guardState(guard: Guard): "locked" | "ok" {
  return Date.now() < guard.lockedUntil ? "locked" : "ok";
}
function recordFailure(guard: Guard): void {
  guard.attempts++;
  if (guard.attempts >= MAX_ATTEMPTS) {
    guard.lockedUntil = Date.now() + LOCK_MS;
    guard.attempts = 0;
  }
}
function recordSuccess(guard: Guard): void {
  guard.attempts = 0;
}
async function newTimedCode(value: string): Promise<TimedCode> {
  return { hash: await secureHash(value), expiresAt: Date.now() + CODE_LIFETIME_MS, used: false };
}

/* TOTP: RFC 6238 SHA-1, 30-second step, 6 digits. */
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
  return new Uint8Array(bytes);
}
async function totp(secret: string, step = Math.floor(Date.now() / 30000)): Promise<string> {
  const counter = new ArrayBuffer(8);
  const view = new DataView(counter);
  view.setUint32(4, step, false);
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = digest[19] & 15;
  const number = (((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]) % 1000000;
  return String(number).padStart(6, "0");
}
function fixtureRecoveryCodes(): string[] {
  return ["MARC2-US123", "SAFE4-CODE5", "BANK6-HELP7", "LOCK8-KEY92", "STAR3-CASH4", "PLAN5-ROAD6", "GUAR7-DIAN8", "BACK9-UP234"];
}
function statusFor(user: User, csrf: string) {
  return {
    ok: true, csrf,
    state: {
      signedIn: true, identityVerified: user.identityVerified,
      authenticatorReady: !!user.authenticatorEncrypted, mfaEnabled: user.mfaEnabled,
      recoveryShown: user.recoveryShown, email: user.email,
    },
  };
}

async function api(request: Request, path: string): Promise<Response> {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: protectedHeaders(request) });

  if (path === "/api/sign-in" && request.method === "POST") {
    if (!validCsrf(request)) return fail(request, 403, "Please refresh the page, then try again.");
    const body = await readBody(request);
    if (!body || !validEmail(body.email) || !validPassword(body.password)) {
      return fail(request, 400, "Enter an email like name@example.com and a password with at least 8 characters.");
    }
    const email = body.email.trim().toLowerCase();
    const submittedHash = await secureHash(body.password);
    const user = users.get(email);
    if (!user || submittedHash !== user.passwordHash) {
      return fail(request, 401, "The email or password is not recognised. Check both and try again.");
    }
    const old = parseCookies(request).mfa_session;
    if (old) sessions.delete(old);
    const id = randomToken(32);
    const csrf = randomToken(32);
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
    if (guardState(user.guards.identity) === "locked") return fail(request, 429, "Too many identity checks were tried. Wait 15 minutes, then try again.");
    const code = TEST_FIXTURES ? "123456" : randomDigits(6);
    user.identity = await newTimedCode(code);
    return json(request, { ok: true, csrf: session.csrf, testIdentityCode: code, message: "A check code is ready." });
  }

  if (path === "/api/identity/verify") {
    if (guardState(user.guards.identity) === "locked") return fail(request, 429, "Too many identity checks were tried. Wait 15 minutes, then try again.");
    const body = await readBody(request);
    if (!body || !validSixDigits(body.code)) return fail(request, 400, "Enter 6 digits. Example: 123456.");
    const code = user.identity;
    if (!code || code.used) return fail(request, 400, "Request a new check code, then enter its 6 digits.");
    if (Date.now() > code.expiresAt) return fail(request, 400, "That code is no longer active. Request a new code and try again.");
    if (code.hash !== await secureHash(body.code)) {
      recordFailure(user.guards.identity);
      return fail(request, 400, "That code did not match. Check all 6 digits or request a new code.");
    }
    code.used = true;
    recordSuccess(user.guards.identity);
    user.identityVerified = true;
    return json(request, { ok: true, csrf: session.csrf, message: "Identity check complete. Next, set up your authenticator." });
  }

  if (path === "/api/authenticator/setup") {
    if (!user.identityVerified) return fail(request, 403, "Complete the identity check before setting up an authenticator.");
    if (guardState(user.guards.authenticator) === "locked") return fail(request, 429, "Too many authenticator codes were tried. Wait 15 minutes, then try again.");
    const secret = TEST_FIXTURES ? "JBSWY3DPEHPK3PXP" : randomToken(20).replace(/[-_]/g, "A").slice(0, 26).toUpperCase();
    user.authenticatorEncrypted = await encrypt(secret);
    user.totpUsedSteps.clear();
    const issuer = "Northstar Bank";
    const provisioningUri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(user.email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    return json(request, {
      ok: true, csrf: session.csrf, secret, provisioningUri,
      testTotpCode: await totp(secret),
      message: "Authenticator details are ready.",
    });
  }

  if (path === "/api/authenticator/verify") {
    if (guardState(user.guards.authenticator) === "locked") return fail(request, 429, "Too many authenticator codes were tried. Wait 15 minutes, then try again.");
    if (!user.authenticatorEncrypted) return fail(request, 400, "Start authenticator setup before confirming a code.");
    const body = await readBody(request);
    if (!body || !validSixDigits(body.code)) return fail(request, 400, "Enter the 6 digits from your authenticator. Example: 123456.");
    const secret = await decrypt(user.authenticatorEncrypted);
    const current = Math.floor(Date.now() / 30000);
    let matchedStep: number | undefined;
    for (const step of [current - 1, current, current + 1]) {
      if (!user.totpUsedSteps.has(step) && body.code === await totp(secret, step)) { matchedStep = step; break; }
    }
    if (matchedStep === undefined) {
      recordFailure(user.guards.authenticator);
      return fail(request, 400, "That authenticator code did not match or was already used. Open your app and enter its current 6-digit code.");
    }
    user.totpUsedSteps.add(matchedStep);
    recordSuccess(user.guards.authenticator);
    user.mfaEnabled = true;
    const codes = TEST_FIXTURES ? fixtureRecoveryCodes() : Array.from({ length: 8 }, recoveryCode);
    user.recoveryHashes = new Set(await Promise.all(codes.map(secureHash)));
    user.recoveryShown = false;
    return json(request, { ok: true, csrf: session.csrf, recoveryCodes: codes, message: "Authenticator confirmed. Your recovery codes are ready." });
  }

  if (path === "/api/recovery/acknowledge") {
    if (!user.mfaEnabled) return fail(request, 403, "Set up your authenticator before saving recovery codes.");
    user.recoveryShown = true;
    return json(request, { ok: true, csrf: session.csrf, message: "Recovery codes marked as saved. MFA enrolment is complete." });
  }

  if (path === "/api/recovery/regenerate") {
    if (!user.mfaEnabled) return fail(request, 403, "Set up your authenticator before making recovery codes.");
    const codes = TEST_FIXTURES ? fixtureRecoveryCodes() : Array.from({ length: 8 }, recoveryCode);
    user.recoveryHashes = new Set(await Promise.all(codes.map(secureHash)));
    user.recoveryShown = false;
    return json(request, { ok: true, csrf: session.csrf, recoveryCodes: codes, message: "New recovery codes are ready. Older codes no longer work." });
  }

  /* Authorized recovery verification: compare protected hashes and atomically remove a matching code. */
  if (path === "/api/recovery/verify") {
    if (!user.mfaEnabled) return fail(request, 403, "MFA must be set up before checking a recovery code.");
    if (guardState(user.guards.recovery) === "locked") return fail(request, 429, "Too many recovery codes were tried. Wait 15 minutes, then try again.");
    const body = await readBody(request);
    const candidate = typeof body?.code === "string" ? body.code.trim().toUpperCase() : "";
    if (!validRecoveryCode(candidate)) return fail(request, 400, "Enter a recovery code in this format: ABCDE-FGHIJ.");
    const hash = await secureHash(candidate);
    if (!user.recoveryHashes.has(hash)) {
      recordFailure(user.guards.recovery);
      return fail(request, 400, "That recovery code is invalid or has already been used. Try another unused code.");
    }
    user.recoveryHashes.delete(hash);
    recordSuccess(user.guards.recovery);
    return json(request, { ok: true, csrf: session.csrf, message: "Recovery code accepted. It has now been used and cannot be used again." });
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
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Northstar Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#17233b;--muted:#53627a;--blue:#075dcc;--soft:#edf5ff;--line:#cbd6e5;--good:#087443;--bad:#b42318;--bg:#f7f9fc}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.025em}button,input{font:inherit;letter-spacing:.025em}button{cursor:pointer}#app{max-width:560px;margin:auto;min-height:100vh;background:#fff;padding:20px 20px 42px}.brand{font-weight:700;color:#064b9b;font-size:1.05rem}.brand span{font-size:1.35rem;margin-right:7px}.logout{float:right}.step{margin:20px 0 14px;color:#064b9b;font-weight:bold}.stepbar{height:8px;border-radius:8px;background:#dce6f4;overflow:hidden}.stepbar i{display:block;height:100%;background:var(--blue);border-radius:8px;width:20%}h1{font-size:1.75rem;line-height:1.25;margin:25px 0 10px;letter-spacing:.01em}h2{font-size:1.2rem;line-height:1.35;margin:20px 0 8px}p{margin:9px 0 17px}.hint,.notice{border-left:5px solid #2d74ce;background:var(--soft);padding:12px 14px;margin:18px 0;border-radius:5px}.notice.good{border-color:var(--good);background:#ecf9f1}.notice.error{border-color:var(--bad);background:#fff1f0;color:#751a14}.field{margin:18px 0}label{display:block;font-weight:bold;margin-bottom:6px}input{width:100%;padding:13px;border:2px solid #8797ad;border-radius:8px;background:#fff;color:var(--ink)}input:focus{outline:3px solid #9fc9ff;outline-offset:2px;border-color:var(--blue)}.example{display:block;color:var(--muted);font-size:.88rem}.primary{width:100%;border:0;border-radius:9px;background:var(--blue);color:#fff;font-weight:bold;padding:14px 16px;margin:20px 0 10px;min-height:54px}.secondary{border:2px solid var(--blue);color:#064b9b;background:#fff;border-radius:8px;padding:10px 12px;margin:7px 5px 7px 0;font-weight:bold}.link{background:none;border:0;color:#064b9b;text-decoration:underline;padding:7px 0;font-weight:bold}.hidden{display:none!important}.code{font-family:monospace;letter-spacing:.12em;font-size:1.06rem;word-break:break-all;background:#f1f4f8;padding:12px;border-radius:7px}.codes{list-style:none;padding:0;margin:14px 0}.codes li{font-family:monospace;font-weight:bold;letter-spacing:.1em;background:#f1f4f8;margin:7px 0;padding:10px;border-radius:6px}.qr{display:block;width:min(100%,300px);height:auto;margin:16px auto;border:8px solid #fff;outline:2px solid var(--ink);image-rendering:pixelated}.status{margin:14px 0;border:1px solid var(--line);padding:10px;border-radius:7px}.status button{float:right;margin:-5px 0 0 8px}@media(max-width:370px){#app{padding:16px}.secondary{width:100%;margin-right:0}h1{font-size:1.5rem}}
</style></head><body>
<main id="app"><header><div class="brand"><span aria-hidden="true">✦</span>Northstar Bank</div><button class="link logout hidden" id="logout">Sign out</button></header>
<div class="stepbar" aria-hidden="true"><i id="progress"></i></div><div class="step" id="step">Step 1 of 5 · Sign in</div>
<section id="status" class="status hidden" role="status" aria-live="polite"></section><section id="screen"></section></main>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf=${JSON.stringify(boot)},view="signIn",setup={secret:"",uri:""},recovery=[];
const screen=document.getElementById("screen"),step=document.getElementById("step"),progress=document.getElementById("progress"),status=document.getElementById("status"),logout=document.getElementById("logout");
const testPolicy="TEST-ONLY POLICY: deterministic mock secrets and codes are printed in this browser console only. They are not shown in the normal page and are never server logged.";
console.log(testPolicy);
function esc(s){const d=document.createElement("div");d.textContent=String(s);return d.innerHTML}
function say(text,type="good"){status.className="status notice "+type;status.innerHTML='<button class="link" type="button" id="dismissStatus" aria-label="Dismiss message">Dismiss</button>'+esc(text);document.getElementById("dismissStatus").onclick=()=>status.className="status hidden"}
function setStep(n,title){step.textContent="Step "+n+" of 5 · "+title;progress.style.width=(n*20)+"%";logout.classList.toggle("hidden",n===1)}
function help(){return '<button class="link help" type="button">ⓘ Need a hint?</button>'}
function bindHelp(){document.querySelectorAll(".help").forEach(b=>b.onclick=()=>say("Take your time. You can request another code or retry a step. There is no reading time limit.","good"))}
async function call(path,data,method="POST"){const r=await fetch(path,{method,credentials:"same-origin",headers:method==="POST"?{"Content-Type":"application/json","X-CSRF-Token":csrf}:undefined,body:method==="POST"?JSON.stringify(data||{}):undefined});const out=await r.json();if(out.csrf)csrf=out.csrf;if(!r.ok)throw Error(out.error||"Something went wrong. Please try again.");return out}
function copy(value,text){navigator.clipboard.writeText(value).then(()=>say(text)).catch(()=>say("Copy was unavailable. Reveal the value and select it instead.","error"))}
function sensitive(id,value,label){return '<p class="code hidden" id="'+id+'">'+esc(value)+'</p><button class="secondary" type="button" data-reveal="'+id+'">Reveal '+esc(label)+'</button>'}
function bindReveal(){document.querySelectorAll("[data-reveal]").forEach(b=>b.onclick=()=>{const el=document.getElementById(b.dataset.reveal);const open=el.classList.toggle("hidden");b.textContent=(open?"Reveal ":"Hide ")+b.textContent.replace(/^Reveal |^Hide /,"")})}
function err(e){say(e.message||"Please try again.","error")}
function render(){
 if(view==="signIn"){setStep(1,"Sign in");screen.innerHTML='<h1>Set up extra payment protection</h1><p>Sign in to start. This takes a few short steps.</p><form id="signin"><div class="field"><label for="email">Email address</label><input id="email" type="email" autocomplete="email" inputmode="email" required><span class="example">Example: marcus@example.com</span></div><div class="field"><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" required><span class="example">Use at least 8 characters.</span></div><button class="primary">Sign in and continue</button></form>'+help();document.getElementById("signin").onsubmit=async e=>{e.preventDefault();try{await call("/api/sign-in",{email:email.value,password:password.value});console.log("Test simulation: authenticated Marcus session created.");view="identity";render()}catch(e){err(e)}}}
 else if(view==="identity"){setStep(2,"Identity check");screen.innerHTML='<h1>Check it is you</h1><p>Request a 6-digit mock check code. There is no rush.</p><div id="identityPlace"></div><button class="primary" id="send">Request check code</button><div id="verify" class="hidden"><form id="identityForm"><div class="field"><label for="identityCode">Check code</label><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required><span class="example">Example: 123456</span></div><button class="primary">Check code</button></form></div>'+help();send.onclick=async()=>{try{const out=await call("/api/identity/request",{});console.log("TEST-ONLY mock identity code:",out.testIdentityCode);identityPlace.innerHTML='<div class="notice good">Your check code is ready. Use the reveal control if you need to see it.</div>'+sensitive("identityValue",out.testIdentityCode,"check code");bindReveal();verify.classList.remove("hidden");send.textContent="Request a new check code"}catch(e){err(e)}};identityForm.onsubmit=async e=>{e.preventDefault();try{await call("/api/identity/verify",{code:identityCode.value});console.log("Test simulation: identity verified.");view="setup";render()}catch(e){err(e)}}}
 else if(view==="setup"){setStep(3,"Authenticator");screen.innerHTML='<h1>Connect your authenticator</h1><p>Use an authenticator app. You can scan, copy, or enter the secret.</p><button class="primary" id="make">Prepare authenticator details</button><div id="setupDetails"></div>'+help();make.onclick=async()=>{try{const out=await call("/api/authenticator/setup",{});setup={secret:out.secret,uri:out.provisioningUri};console.log("TEST-ONLY provisioning URI:",out.provisioningUri);console.log("TEST-ONLY authenticator secret:",out.secret);console.log("TEST-ONLY current RFC 6238 TOTP:",out.testTotpCode);setupDetails.innerHTML='<div class="notice good">Details are ready. Scan the QR code or use the manual option.</div><h2>Scan option</h2><canvas class="qr" id="qr" width="300" height="300" role="img" aria-label="QR code for authenticator setup"></canvas><button class="secondary" id="copyUri">Copy setup link</button><h2>Manual option</h2>'+sensitive("secretValue",setup.secret,"secret")+'<button class="secondary" id="copySecret">Copy secret</button><form id="otpForm"><div class="field"><label for="otp">Authenticator code</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required><span class="example">Example: 123456</span></div><button class="primary">Confirm authenticator</button></form>';drawQr(out.provisioningUri);bindReveal();copyUri.onclick=()=>copy(setup.uri,"Setup link copied.");copySecret.onclick=()=>copy(setup.secret,"Secret copied.");otpForm.onsubmit=verifyOtp}catch(e){err(e)}}}
 else if(view==="recovery"){setStep(4,"Recovery codes");screen.innerHTML='<h1>Save your recovery codes</h1><p>These one-use codes help if you lose your authenticator. Keep them somewhere private.</p><div id="recoveryBox"></div><button class="primary" id="saved">I saved these codes</button><button class="secondary" id="newCodes">Make new codes</button>'+help();showCodes();saved.onclick=async()=>{try{await call("/api/recovery/acknowledge",{});recovery=[];console.log("Test simulation: recovery codes marked saved.");view="done";render()}catch(e){err(e)}};newCodes.onclick=regenerate}
 else if(view==="recoveryTest"){setStep(5,"Check recovery code");screen.innerHTML='<h1>Check a recovery code</h1><p>This test uses one code once. A used code will not work again.</p><form id="recoveryForm"><div class="field"><label for="recoveryInput">Recovery code</label><input id="recoveryInput" autocomplete="one-time-code" autocapitalize="characters" placeholder="ABCDE-FGHIJ" required><span class="example">Example: ABCDE-FGHIJ</span></div><button class="primary">Check recovery code</button></form><button class="secondary" id="backDone">Back</button>'+help();recoveryForm.onsubmit=async e=>{e.preventDefault();try{const out=await call("/api/recovery/verify",{code:recoveryInput.value});say(out.message);console.log("Test simulation: recovery code atomically consumed.")}catch(e){err(e)}};backDone.onclick=()=>{view="done";render()}}
 else {setStep(5,"Complete");screen.innerHTML='<h1>✓ MFA is ready</h1><div class="notice good">Your authenticator and recovery codes are set up.</div><p>For higher-value payments, use the 6-digit code from your authenticator app.</p><button class="primary" id="finish">Finish securely</button><button class="secondary" id="testRecovery">Check a recovery code</button>'+help();finish.onclick=()=>{screen.innerHTML='<h1>You are all set</h1><p>Your extra payment protection stays active.</p><button class="primary" id="finishLogout">Sign out</button>';finishLogout.onclick=doLogout};testRecovery.onclick=()=>{view="recoveryTest";render()}}
 bindHelp()
}
async function verifyOtp(e){e.preventDefault();try{const out=await call("/api/authenticator/verify",{code:otp.value});recovery=out.recoveryCodes;console.log("TEST-ONLY mock recovery codes:",recovery.join(", "));console.log("Test simulation: TOTP verification succeeded.");setup={secret:"",uri:""};view="recovery";render()}catch(e){err(e)}}
function showCodes(){recoveryBox.innerHTML='<div class="notice good">Your codes are hidden until you choose reveal.</div><ul class="codes hidden" id="codeList">'+recovery.map(c=>"<li>"+esc(c)+"</li>").join("")+'</ul><button class="secondary" id="revealCodes">Reveal recovery codes</button><button class="secondary" id="copyCodes">Copy all codes</button><button class="secondary" id="downloadCodes">Download text file</button>';revealCodes.onclick=()=>{const hidden=codeList.classList.toggle("hidden");revealCodes.textContent=hidden?"Reveal recovery codes":"Hide recovery codes"};copyCodes.onclick=()=>copy(recovery.join("\\n"),"Recovery codes copied.");downloadCodes.onclick=()=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([recovery.join("\\n")],{type:"text/plain"}));a.download="northstar-recovery-codes.txt";a.click();URL.revokeObjectURL(a.href);say("Recovery code text file prepared for download.")}}
async function regenerate(){try{const out=await call("/api/recovery/regenerate",{});recovery=out.recoveryCodes;console.log("TEST-ONLY replacement recovery codes:",recovery.join(", "));showCodes();say(out.message)}catch(e){err(e)}}
async function doLogout(){try{await call("/api/logout",{});csrf="";recovery=[];setup={secret:"",uri:""};console.log("Test simulation: secure session invalidated.");view="signIn";render()}catch(e){err(e)}}
logout.onclick=doLogout;

/* Standards-compliant QR encoder: Version 10-L byte-mode QR with RS error correction. */
function drawQr(text){
 const N=57,canvas=document.getElementById("qr"),ctx=canvas.getContext("2d"),m=Array.from({length:N},()=>Array(N).fill(null));
 const set=(r,c,v,res=true)=>{if(r>=0&&r<N&&c>=0&&c<N)m[r][c]=[v,res]};
 function finder(r,c){for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)set(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4)))}
 finder(0,0);finder(0,N-7);finder(N-7,0);
 for(const r of [6,28,50])for(const c of [6,28,50])if(m[r][c]===null){for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(r+y,c+x,Math.max(Math.abs(x),Math.abs(y))!==1)}
 for(let i=8;i<N-8;i++){set(6,i,i%2===0);set(i,6,i%2===0)}set(N-8,8,true);
 for(let i=0;i<9;i++){if(m[i][8]===null)set(i,8,false);if(m[8][i]===null)set(8,i,false);if(m[N-1-i][8]===null)set(N-1-i,8,false);if(m[8][N-1-i]===null)set(8,N-1-i,false)}
 for(let i=0;i<18;i++){set(Math.floor(i/3),N-11+i%3,false);set(N-11+i%3,Math.floor(i/3),false)}
 const bytes=[...new TextEncoder().encode(text)];let bits="0100"+bytes.length.toString(2).padStart(16,"0")+bytes.map(b=>b.toString(2).padStart(8,"0")).join("");bits+=(Math.min(4,274*8-bits.length)>0?"0".repeat(Math.min(4,274*8-bits.length)):"");while(bits.length%8)bits+="0";
 let data=[];for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8),2));for(let p=0;data.length<274;p++)data.push(p%2?0x11:0xec);
 const exp=[],log=[];let x=1;for(let i=0;i<255;i++){exp[i]=x;log[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;let gen=[1];for(let i=0;i<18;i++){const next=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=mul(gen[j],exp[i])}gen=next}
 const blocks=[],ecc=[];let pos=0;for(const len of [68,68,69,69]){const d=data.slice(pos,pos+len);pos+=len;const rem=d.concat(Array(18).fill(0));for(let i=0;i<d.length;i++)if(rem[i])for(let j=0;j<gen.length;j++)rem[i+j]^=mul(gen[j],rem[i]);blocks.push(d);ecc.push(rem.slice(-18))}
 const stream=[];for(let i=0;i<69;i++)for(const b of blocks)if(i<b.length)stream.push(b[i]);for(let i=0;i<18;i++)for(const e of ecc)stream.push(e[i]);
 const raw=stream.map(b=>b.toString(2).padStart(8,"0")).join("");let k=0,up=true;
 for(let c=N-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<N;q++){const r=up?N-1-q:q;for(const col of [c,c-1])if(m[r][col]===null){let v=k<raw.length&&raw[k++]==="1";if((r+col)%2===0)v=!v;set(r,col,v,false)}}up=!up}
 function bch(v,poly){let d=poly.toString(2).length-1;while(v.toString(2).length-1>=d)v^=poly<<(v.toString(2).length-1-d);return v}
 const fmt=((8<<10)|bch(8<<10,0x537))^0x5412;for(let i=0;i<15;i++){const v=((fmt>>i)&1)===1;const a=i<6?i:i<8?i+1:N-15+i;set(a,8,v);set(8,N-1-i,v)}
 ctx.fillStyle="#fff";ctx.fillRect(0,0,300,300);const s=300/N;for(let r=0;r<N;r++)for(let c=0;c<N;c++)if(m[r][c][0]){ctx.fillStyle="#000";ctx.fillRect(c*s,r*s,Math.ceil(s),Math.ceil(s))}
}
render();
})();</script></body></html>`;
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
      return fail(request, 500, "Something went wrong. Please refresh and try again.");
    }
  },
});
