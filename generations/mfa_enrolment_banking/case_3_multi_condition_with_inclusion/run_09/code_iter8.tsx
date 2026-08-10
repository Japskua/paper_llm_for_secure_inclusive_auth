
import { timingSafeEqual } from "node:crypto";

/*
 MFA Enrolment System — single-file Bun HTTPS server and mobile vanilla HTML SPA.
 Requirement tasks: every provisioning event has session time metadata, a new secret,
 and a new deterministic mock OTP. Expired or refreshed setup details cannot verify.
*/

type Stage = "signed-in" | "identity" | "setup" | "otp" | "recovery" | "complete";
type Cipher = { iv: string; ciphertext: string };
type ProtectedCode = { hash: string; expiresAt: number; used: boolean; failedAttempts: number };
type Recovery = { salt: string; hash: string; used: boolean; expiresAt: number };
type Session = {
  id: string; csrf: string; authenticated: boolean; email?: string; userId?: string;
  stage: Stage; createdAt: number; lastSeen: number; identityCode?: ProtectedCode;
  encryptedOtpSecret?: Cipher; otpUsed: boolean; otpFails: number; recoveryFails: number;
  lockedUntil?: number; recoveryCodes: Recovery[];
  provisioningCreatedAt?: number; provisioningExpiresAt?: number; provisioningGeneration: number;
};

const TEST_MODE = true;
const TEST_IDENTITY_CODE = "246810";
const TEST_RECOVERY_CODES = ["MARC-US24", "SAFE-4826", "BANK-7391", "KEYS-6502", "PLAN-8437", "HELP-1958"];
const sessions = new Map<string, Session>();
const enc = new TextEncoder(), dec = new TextDecoder();
const MASTER_KEY = crypto.getRandomValues(new Uint8Array(32));
const IDENTITY_KEY = crypto.getRandomValues(new Uint8Array(32));
const IDLE = 20 * 60_000, ABSOLUTE = 8 * 60 * 60_000;
const CODE_LIFE = 15 * 60_000, OTP_VERIFICATION_LIFE = CODE_LIFE;
const LOCK = 5 * 60_000, RECOVERY_LIFE = 365 * 24 * 60 * 60_000, PBKDF2_ITERATIONS = 210_000;
const now = () => Date.now();
const token = (n = 32) => Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url");

function same(a: string, b: string) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
async function hmac(keyBytes: Uint8Array, value: string | Uint8Array, algorithm: "SHA-1" | "SHA-256" = "SHA-256") {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: algorithm }, false, ["sign"]);
  const input = typeof value === "string" ? enc.encode(value) : value;
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, input));
}
async function identityHash(code: string) {
  return Buffer.from(await hmac(IDENTITY_KEY, code)).toString("base64url");
}
async function recoveryHash(code: string, salt: string) {
  const key = await crypto.subtle.importKey("raw", enc.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: Buffer.from(salt, "base64url"), iterations: PBKDF2_ITERATIONS },
    key, 256
  );
  return Buffer.from(bits).toString("base64url");
}
function randomSixDigits() {
  const limit = Math.floor(0x1_0000_0000 / 1_000_000) * 1_000_000, word = new Uint32Array(1);
  do crypto.getRandomValues(word); while (word[0] >= limit);
  return String(word[0] % 1_000_000).padStart(6, "0");
}
async function issueIdentityCode(previous?: ProtectedCode) {
  let code = TEST_MODE ? TEST_IDENTITY_CODE : randomSixDigits();
  if (!TEST_MODE && previous) while (same(await identityHash(code), previous.hash)) code = randomSixDigits();
  return { code, record: { hash: await identityHash(code), expiresAt: now() + CODE_LIFE, used: false, failedAttempts: 0 } };
}

/* Requirement 3 — AES-GCM protects the currently provisioned shared secret at rest. */
async function encrypt(value: string): Promise<Cipher> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", MASTER_KEY, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(value));
  return { iv: Buffer.from(iv).toString("base64url"), ciphertext: Buffer.from(ciphertext).toString("base64url") };
}
async function decrypt(value: Cipher) {
  const key = await crypto.subtle.importKey("raw", MASTER_KEY, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(value.iv, "base64url") }, key, Buffer.from(value.ciphertext, "base64url"));
  return dec.decode(plain);
}
function base32Secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", bytes = crypto.getRandomValues(new Uint8Array(20));
  let out = "", bits = 0, value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return bits ? out + alphabet[(value << (5 - bits)) & 31] : out;
}
function base32Decode(input: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let value = 0, bits = 0; const out: number[] = [];
  for (const c of input.replace(/=|\s/g, "").toUpperCase()) {
    const n = alphabet.indexOf(c); if (n < 0) throw new Error("bad secret");
    value = (value << 5) | n; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}

/* RFC 6238: HMAC-SHA1 input is the raw, eight-byte big-endian moving counter. */
async function totp(secret: string, step: number) {
  const counter = new Uint8Array(8); let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(n & 255n); n >>= 8n; }
  const digest = await hmac(base32Decode(secret), counter, "SHA-1");
  const offset = digest[19] & 15;
  const value = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}

/* Deterministic mock OTP remains a browser-console test aid. */
async function mockOtpForSecret(secret: string) {
  const digest = await hmac(base32Decode(secret), "northstar-mock-authenticator-otp");
  const value = ((digest[0] & 127) << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3];
  return String(value % 1_000_000).padStart(6, "0");
}
async function validProductionTotp(secret: string, code: string) {
  const step = Math.floor(now() / 30_000);
  for (const offset of [-1, 0, 1]) if (same(await totp(secret, step + offset), code)) return true;
  return false;
}

/* Requirement 2 — secure headers, trusted-origin CORS, secure cookie. */
function cookie(req: Request, key: string) {
  return (req.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(key + "="))?.slice(key.length + 1);
}
const sessionCookie = (id: string) => `mfa_session=${id}; Path=/; Max-Age=${ABSOLUTE / 1000}; HttpOnly; Secure; SameSite=Strict`;
const clearCookie = () => "mfa_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict";
function headers(nonce?: string) {
  return new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; frame-ancestors 'none'"
  });
}
function reply(data: unknown, status = 200, extra?: Record<string, string>) {
  const h = headers(); for (const [k, v] of Object.entries(extra || {})) h.set(k, v);
  return new Response(JSON.stringify(data), { status, headers: h });
}
const fail = (message: string, status = 400) => reply({ ok: false, error: message }, status);
function trusted(req: Request) {
  const origin = req.headers.get("origin");
  return !origin || /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(origin);
}

/* Requirement 1 and 5 — ownership, CSRF, rotation, expiration, and rate limits. */
function makeSession() {
  const s: Session = {
    id: token(), csrf: token(), authenticated: false, stage: "signed-in", createdAt: now(), lastSeen: now(),
    otpUsed: false, otpFails: 0, recoveryFails: 0, recoveryCodes: [], provisioningGeneration: 0
  };
  sessions.set(s.id, s); return s;
}
function current(req: Request, needsAuth = false): Session | null {
  const id = cookie(req, "mfa_session"), s = id && sessions.get(id);
  if (!s) return null;
  if (now() - s.lastSeen > IDLE || now() - s.createdAt > ABSOLUTE) { sessions.delete(s.id); return null; }
  if (needsAuth && !s.authenticated) return null;
  s.lastSeen = now(); return s;
}
function owner(req: Request): Session | Response {
  return current(req, true) || fail("Your secure session has ended. Please sign in again.", 401);
}
function csrf(req: Request, s: Session) {
  const value = req.headers.get("x-csrf-token") || "";
  return trusted(req) && /^[A-Za-z0-9_-]{40,60}$/.test(value) && same(value, s.csrf);
}
async function body(req: Request): Promise<Record<string, unknown> | null> {
  if (Number(req.headers.get("content-length") || 0) > 4096) return null;
  try {
    const value = await req.json();
    if (!value || typeof value !== "object" || Array.isArray(value) || "userId" in value || "accountId" in value || "redirect" in value) return null;
    return value as Record<string, unknown>;
  } catch { return null; }
}
function field(b: Record<string, unknown> | null, name: string, max: number) {
  const value = b?.[name]; return typeof value === "string" && value.length <= max ? value.trim() : null;
}
const locked = (s: Session) => !!s.lockedUntil && s.lockedUntil > now();
function failed(s: Session, key: "otpFails" | "recoveryFails") {
  if (++s[key] >= 5) { s[key] = 0; s.lockedUntil = now() + LOCK; }
}
function recoveryCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", bytes = crypto.getRandomValues(new Uint8Array(8));
  const value = Array.from(bytes, x => alphabet[x % alphabet.length]).join("");
  return value.slice(0, 4) + "-" + value.slice(4);
}
async function createRecovery(s: Session) {
  const codes = TEST_MODE ? [...TEST_RECOVERY_CODES] : Array.from({ length: 6 }, recoveryCode);
  s.recoveryCodes = await Promise.all(codes.map(async code => {
    const salt = token(16);
    return { salt, hash: await recoveryHash(code, salt), used: false, expiresAt: now() + RECOVERY_LIFE };
  }));
  return codes;
}

async function provision(s: Session) {
  let secret = base32Secret();
  if (s.encryptedOtpSecret) {
    try { while (same(secret, await decrypt(s.encryptedOtpSecret))) secret = base32Secret(); } catch { secret = base32Secret(); }
  }
  s.encryptedOtpSecret = await encrypt(secret);
  s.provisioningCreatedAt = now();
  s.provisioningExpiresAt = s.provisioningCreatedAt + OTP_VERIFICATION_LIFE;
  s.provisioningGeneration++;
  s.otpUsed = false; s.otpFails = 0;
  const issuer = "Northstar Bank", label = issuer + ":" + (s.email || "marcus@example.com");
  const provisioningUri = `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  return {
    secret, provisioningUri,
    testOtp: TEST_MODE ? await mockOtpForSecret(secret) : await totp(secret, Math.floor(now() / 30_000))
  };
}

async function api(req: Request, path: string): Promise<Response> {
  if (!trusted(req)) return fail("This request is not allowed.", 403);
  if (path === "/api/bootstrap" && req.method === "GET") {
    let s = current(req), set: string | undefined;
    if (!s) { s = makeSession(); set = sessionCookie(s.id); }
    return reply({ ok: true, csrf: s.csrf, authenticated: s.authenticated, stage: s.stage }, 200, set ? { "Set-Cookie": set } : undefined);
  }
  if (path === "/api/sign-in" && req.method === "POST") {
    const old = current(req); if (!old || !csrf(req, old)) return fail("Please refresh the page and try signing in again.", 403);
    const b = await body(req), email = field(b, "email", 120), password = field(b, "password", 200);
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !password) return fail("Enter an email like name@example.com and your password.");
    if (email.toLowerCase() !== "marcus@example.com" || password !== "bank-demo") return fail("We could not sign you in. Check your email and password, then try again.", 401);
    sessions.delete(old.id);
    const s = makeSession(); s.authenticated = true; s.userId = "account-owner-marcus"; s.email = "marcus@example.com"; s.stage = "identity";
    const issued = await issueIdentityCode(); s.identityCode = issued.record;
    return reply({ ok: true, csrf: s.csrf, stage: s.stage, testIdentityCode: issued.code, message: "We sent a six-digit check code." }, 200, { "Set-Cookie": sessionCookie(s.id) });
  }
  if (path === "/api/state" && req.method === "GET") {
    const s = owner(req); return s instanceof Response ? s : reply({ ok: true, stage: s.stage, email: s.email, csrf: s.csrf, locked: locked(s) });
  }
  if (path === "/api/identity/verify" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "identity") return fail("Please complete the earlier step first.", 409);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const b = await body(req), code = field(b, "code", 6), phone = field(b, "phone", 24);
    if (!code || !/^\d{6}$/.test(code) || !phone || !/^\+?[0-9 ()-]{7,24}$/.test(phone)) return fail("Enter a six-digit code like 246810 and a phone number like +1 555 010 0200.");
    const issued = s.identityCode;
    if (!issued || issued.used || now() > issued.expiresAt) return fail("That check code is no longer active. Choose send a new code and try again.");
    if (!same(await identityHash(code), issued.hash)) {
      issued.failedAttempts++;
      if (issued.failedAttempts >= 5) { issued.failedAttempts = 0; s.lockedUntil = now() + LOCK; }
      return fail(locked(s) ? "Too many tries. Please wait five minutes, then try again." : "That code does not match. Check the six digits and try again.");
    }
    issued.used = true; s.stage = "setup";
    return reply({ ok: true, stage: s.stage, message: "Identity check complete. Next, add your authenticator." });
  }
  if (path === "/api/identity/resend" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "identity") return fail("Please complete the earlier step first.", 409);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    if (s.identityCode) s.identityCode.used = true;
    const issued = await issueIdentityCode(s.identityCode); s.identityCode = issued.record;
    return reply({ ok: true, testIdentityCode: issued.code, message: "A new check code is ready. The earlier code no longer works." });
  }
  if ((path === "/api/authenticator/setup" || path === "/api/authenticator/refresh") && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    const fresh = path.endsWith("refresh");
    if ((fresh && s.stage !== "otp") || (!fresh && s.stage !== "setup")) return fail("Please complete the earlier step first.", 409);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const data = await provision(s); s.stage = "otp";
    return reply({ ok: true, stage: s.stage, ...data, message: fresh ? "Fresh authenticator setup details are ready. The old setup details no longer work." : "Authenticator details are ready. Scan the code or use the manual secret, then enter its six-digit code." });
  }
  if (path === "/api/otp/verify" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "otp") return fail("Please complete the earlier step first.", 409);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const code = field(await body(req), "code", 6);
    if (!code || !/^\d{6}$/.test(code)) return fail("Enter six numbers, for example 123456.");
    if (s.otpUsed || !s.encryptedOtpSecret || !s.provisioningExpiresAt) return fail("Choose get fresh setup details and try again.");
    if (now() > s.provisioningExpiresAt) return fail("These setup details have expired. Choose get fresh setup details, then try again.");
    let ok = false;
    try {
      const currentSecret = await decrypt(s.encryptedOtpSecret);
      /* RFC 6238 TOTP always works; TEST_MODE additionally accepts the fixed mock value. */
      ok = await validProductionTotp(currentSecret, code);
      if (!ok && TEST_MODE) ok = same(code, await mockOtpForSecret(currentSecret));
    } catch { ok = false; }
    if (!ok) { failed(s, "otpFails"); return fail(locked(s) ? "Too many tries. Please wait five minutes, then try again." : "That code does not match. Check the six numbers in your authenticator and try again."); }
    s.otpUsed = true; s.stage = "recovery"; const codes = await createRecovery(s);
    return reply({ ok: true, stage: s.stage, recoveryCodes: codes, message: "Authenticator confirmed. Your recovery codes are ready." });
  }
  if (path === "/api/recovery/generate" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "recovery" && s.stage !== "complete") return fail("Please complete the earlier step first.", 409);
    return reply({ ok: true, recoveryCodes: await createRecovery(s), message: "New recovery codes are ready. The old ones no longer work." });
  }
  if (path === "/api/recovery/complete" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "recovery") return fail("Please complete the earlier step first.", 409);
    s.stage = "complete"; return reply({ ok: true, stage: s.stage, message: "MFA enrolment is complete." });
  }
  if (path === "/api/recovery/verify" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const code = field(await body(req), "recoveryCode", 9)?.toUpperCase();
    if (!code || !/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code)) return fail("Enter a recovery code like ABCD-EFGH.");
    let hit: Recovery | undefined;
    for (const r of s.recoveryCodes) if (!r.used && r.expiresAt > now() && same(await recoveryHash(code, r.salt), r.hash)) { hit = r; break; }
    if (!hit) { failed(s, "recoveryFails"); return fail(locked(s) ? "Too many tries. Please wait five minutes, then try again." : "That recovery code does not match an unused code. Check it and try again."); }
    hit.used = true; return reply({ ok: true, message: "That recovery code worked and is now used. Your other codes still work." });
  }
  if (path === "/api/logout" && req.method === "POST") {
    const s = current(req); if (!s || !csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    sessions.delete(s.id); return reply({ ok: true, message: "You have signed out." }, 200, { "Set-Cookie": clearCookie() });
  }
  return fail("That page is not available.", 404);
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Bank — MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172033;--muted:#536074;--blue:#0759b8;--line:#cad5e2;--soft:#eef6ff}*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:var(--ink);font:17px/1.65 Arial,Verdana,sans-serif;letter-spacing:.035em}button,input{font:inherit;letter-spacing:.035em}.shell{width:min(100%,540px);min-height:100vh;margin:auto;background:#fff;padding:20px 18px 36px}.brand{font-weight:bold;color:#063a78;border-bottom:1px solid var(--line);padding-bottom:15px;font-size:19px}.progress{margin:18px 0 24px}.progress div{display:flex;justify-content:space-between;color:var(--muted);font-size:14px;font-weight:bold}.bar{height:9px;background:#dce5ef;border-radius:9px;margin-top:7px}.bar span{display:block;height:100%;background:var(--blue);border-radius:9px}.card,.logs{border:1px solid var(--line);border-radius:16px;padding:23px 19px}.logs{margin-top:18px;background:#f8fafc}.logs h2{font-size:17px;margin:0 0 7px}.logs pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;font:13px/1.45 Arial,sans-serif;color:#334155}.icon{font-size:28px;background:var(--soft);border-radius:13px;width:48px;height:48px;display:grid;place-items:center}h1{font-size:27px;line-height:1.25;margin:14px 0 10px}p{margin:0 0 15px}label{display:block;font-weight:bold;margin:15px 0 5px}input{width:100%;min-height:51px;border:2px solid #9eacbd;border-radius:10px;padding:12px}.code{font-size:23px;font-weight:bold;letter-spacing:.18em;text-align:center}.primary{width:100%;min-height:54px;margin-top:20px;border:0;border-radius:10px;background:var(--blue);color:#fff;font-weight:bold}.secondary,.copy,.reveal{color:var(--blue);font-weight:bold;background:#fff;border:0;text-decoration:underline;padding:10px 1px}.copy{border:1px solid var(--blue);border-radius:8px;padding:6px 9px;text-decoration:none}.notice{padding:11px;border-radius:10px;margin-bottom:15px;font-size:15px;background:#e8f7ef;color:#075d36}.bad{background:#fff0ef;color:#8b1d16}.example,.hint,details{font-size:14px;color:var(--muted);margin:6px 0}.secret{display:flex;gap:8px;align-items:center;border:1px solid var(--line);background:#f5f8fc;border-radius:10px;padding:9px}.secret code{flex:1;overflow-wrap:anywhere;font-size:13px}.qr{text-align:center;margin:18px 0}.qr canvas{width:220px;height:220px;border:9px solid white;outline:1px solid var(--line);image-rendering:pixelated}.codes{list-style:none;padding:0}.codes li{display:flex;justify-content:space-between;align-items:center;border:1px solid var(--line);padding:8px;margin:7px 0;border-radius:9px}[hidden]{display:none!important}@media(max-width:380px){.shell{padding:15px 13px}.card,.logs{padding:19px 15px}h1{font-size:24px}.qr canvas{width:190px;height:190px}}
</style></head><body><main class="shell"><header class="brand">✦ Northstar Bank</header><section class="progress"><div><span id="pt">Getting started</span><span id="pc">Step 1 of 6</span></div><p class="bar"><span id="pb" style="width:16%"></span></p></section><section id="app" aria-live="polite">Loading secure setup…</section><section class="logs" aria-label="Logs"><h2>Logs</h2><pre id="logs">Mock values will appear here when sent.</pre></section><footer class="hint">Take your time. There is no reading timer.</footer></main>
<script nonce="${nonce}">(()=>{"use strict";
const app=document.querySelector("#app"),pt=document.querySelector("#pt"),pc=document.querySelector("#pc"),pb=document.querySelector("#pb"),logs=document.querySelector("#logs");let csrf="",state={stage:"signed-in"},secret="",uri="",codes=[];
const q=s=>document.querySelector(s);
function mockLog(label,value){console.log(label,value);const text=label+" "+(Array.isArray(value)?value.join(", "):value);logs.textContent=(logs.textContent==="Mock values will appear here when sent."?"":logs.textContent+"\\n")+text}
async function req(path,method="GET",body){const o={method,credentials:"same-origin",headers:{}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(body||{})}const r=await fetch(path,o),d=await r.json().catch(()=>({}));if(!r.ok||!d.ok)throw Error(d.error||"Please try again.");if(d.csrf)csrf=d.csrf;return d}
function notice(t,b){const n=q("#notice");if(n){n.textContent=t;n.className="notice "+(b?"bad":"");n.hidden=false}}
function bind(id,event,fn){const e=q("#"+id);if(e)e.addEventListener(event,fn)}
function copy(v,label){navigator.clipboard?.writeText(v).then(()=>notice(label+" copied."),()=>notice("Select the text and copy it using your browser.",true))}
function progress(s){const x={"signed-in":[1,"Sign in"],identity:[2,"Identity check"],setup:[3,"Authenticator setup"],otp:[4,"Confirm code"],recovery:[5,"Save recovery codes"],complete:[6,"Finished"]}[s]||[1,"Sign in"];pt.textContent=x[1];pc.textContent="Step "+x[0]+" of 6";pb.style.width=(x[0]*100/6)+"%"}

/* Embedded QR Code Model 2 encoder: Version 8, error correction level L, byte mode.
   It encodes the exact UTF-8 provisioning URI without a network asset or dependency. */
function qrVisual(value){
  const bytes=new TextEncoder().encode(value),version=8,size=49,dataCount=192,eccCount=24,blocks=2;
  if(bytes.length>190)throw Error("The setup link is too long to make a QR code.");

  const exp=new Uint8Array(512),log=new Uint8Array(256);let z=1;
  for(let i=0;i<255;i++){exp[i]=z;log[z]=i;z<<=1;if(z&256)z^=285}
  for(let i=255;i<512;i++)exp[i]=exp[i-255];
  const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;
  let generator=[1];
  for(let i=0;i<eccCount;i++){const next=new Array(generator.length+1).fill(0);for(let j=0;j<generator.length;j++){next[j]^=generator[j];next[j+1]^=mul(generator[j],exp[i])}generator=next}
  const remainder=data=>{const r=new Uint8Array(eccCount);for(const d of data){const f=d^r[0];for(let i=0;i<eccCount-1;i++)r[i]=r[i+1]^mul(generator[i+1],f);r[eccCount-1]=mul(generator[eccCount],f)}return r};

  const bits=[];
  const put=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>>i)&1)};
  put(4,4);put(bytes.length,8);for(const b of bytes)put(b,8);
  for(let i=0;i<Math.min(4,dataCount*8-bits.length);i++)bits.push(0);
  while(bits.length%8)bits.push(0);
  const data=[];for(let i=0;i<bits.length;i+=8){let b=0;for(let j=0;j<8;j++)b=(b<<1)|bits[i+j];data.push(b)}
  for(let pad=0;data.length<dataCount;pad++)data.push(pad%2?236:17);

  const parts=[];for(let i=0;i<blocks;i++)parts.push(data.slice(i*96,(i+1)*96));
  const ecc=parts.map(remainder),codewords=[];
  for(let i=0;i<96;i++)for(let b=0;b<blocks;b++)codewords.push(parts[b][i]);
  for(let i=0;i<eccCount;i++)for(let b=0;b<blocks;b++)codewords.push(ecc[b][i]);

  const modules=Array.from({length:size},()=>Array(size).fill(null));
  const set=(x,y,v)=>{if(x>=0&&y>=0&&x<size&&y<size)modules[y][x]=v};
  const finder=(x,y)=>{for(let dy=-1;dy<=7;dy++)for(let dx=-1;dx<=7;dx++){const inside=dx>=0&&dx<=6&&dy>=0&&dy<=6;const dark=inside&&(dx===0||dx===6||dy===0||dy===6||(dx>=2&&dx<=4&&dy>=2&&dy<=4));set(x+dx,y+dy,dark)}};
  finder(0,0);finder(size-7,0);finder(0,size-7);
  for(let i=8;i<size-8;i++){set(i,6,i%2===0);set(6,i,i%2===0)}
  const alignment=(x,y)=>{for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)set(x+dx,y+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1)};
  const centers=[6,24,42];for(const y of centers)for(const x of centers){if((x===6&&y===6)||(x===42&&y===6)||(x===6&&y===42))continue;alignment(x,y)}
  set(8,size-8,true);

  let vb=version;for(let i=0;i<12;i++)if(((vb>>>i)&1)!==0)vb^=0x1f25<<(11-i);const versionBits=(version<<12)|vb;
  for(let i=0;i<18;i++){const dark=((versionBits>>>i)&1)!==0;set(size-11+i%3,Math.floor(i/3),dark);set(Math.floor(i/3),size-11+i%3,dark)}

  let format=(1<<3)|0;let fb=format;for(let i=0;i<10;i++)if(((fb>>>(14-i))&1)!==0)fb^=0x537<<(9-i);format=((format<<10)|fb)^0x5412;
  for(let i=0;i<=5;i++)set(8,i,((format>>>i)&1)!==0);
  set(8,7,((format>>>6)&1)!==0);set(8,8,((format>>>7)&1)!==0);set(7,8,((format>>>8)&1)!==0);
  for(let i=9;i<15;i++)set(14-i,8,((format>>>i)&1)!==0);
  for(let i=0;i<8;i++)set(size-1-i,8,((format>>>i)&1)!==0);
  for(let i=8;i<15;i++)set(8,size-15+i,((format>>>i)&1)!==0);

  const stream=[];for(const word of codewords)for(let i=7;i>=0;i--)stream.push((word>>>i)&1);
  let bit=0,up=true;
  for(let right=size-1;right>0;right-=2){
    if(right===6)right--;
    for(let k=0;k<size;k++){
      const y=up?size-1-k:k;
      for(let dx=0;dx<2;dx++){const x=right-dx;if(modules[y][x]===null){const raw=bit<stream.length?stream[bit++]:0;set(x,y,Boolean(raw^((x+y)%2===0)))}}
    }
    up=!up;
  }

  const box=q("#qr"),c=document.createElement("canvas"),ctx=c.getContext("2d");c.width=c.height=size;
  ctx.fillStyle="#fff";ctx.fillRect(0,0,size,size);ctx.fillStyle="#172033";
  for(let y=0;y<size;y++)for(let x=0;x<size;x++)if(modules[y][x])ctx.fillRect(x,y,1,1);
  c.setAttribute("role","img");c.setAttribute("aria-label","Authenticator QR code. Scan it with an authenticator app, or use the manual secret.");
  box.replaceChildren(c);
}
function render(msg,bad){progress(state.stage);const n=msg?'<div id="notice" class="notice '+(bad?"bad":"")+'">'+msg+'</div>':'<div id="notice" hidden></div>';
if(state.stage==="signed-in"){app.innerHTML='<article class="card"><div class="icon">🔐</div><h1>Sign in to start MFA setup</h1><p>Use the demo account. We will guide you one step at a time.</p>'+n+'<form id="f"><label>Email address</label><input id="email" type="email" autocomplete="username" placeholder="marcus@example.com"><p class="example">Example: marcus@example.com</p><label>Password</label><input id="password" type="password" autocomplete="current-password" placeholder="bank-demo"><button class="primary">Sign in</button></form></article>';bind("f","submit",async e=>{e.preventDefault();try{const d=await req("/api/sign-in","POST",{email:q("#email").value,password:q("#password").value});csrf=d.csrf;state.stage=d.stage;mockLog("Mock identity check code:",d.testIdentityCode);render(d.message)}catch(x){notice(x.message,true)}})}
else if(state.stage==="identity"){app.innerHTML='<article class="card"><div class="icon">🪪</div><h1>Check it is you</h1><p>Enter your phone number and the six-digit code we sent.</p>'+n+'<form id="f"><label>Phone number</label><input id="phone" type="tel" autocomplete="tel" placeholder="+1 555 010 0200"><label>Six-digit check code</label><input id="code" class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="246810"><button class="primary">Check my identity</button></form><button id="resend" class="secondary">Send a new code</button></article>';bind("f","submit",async e=>{e.preventDefault();try{const d=await req("/api/identity/verify","POST",{phone:q("#phone").value,code:q("#code").value});state.stage=d.stage;render(d.message)}catch(x){notice(x.message,true)}});bind("resend","click",async()=>{try{const d=await req("/api/identity/resend","POST",{});mockLog("Mock identity check code:",d.testIdentityCode);notice(d.message)}catch(x){notice(x.message,true)}})}
else if(state.stage==="setup"){app.innerHTML='<article class="card"><div class="icon">📱</div><h1>Add your authenticator</h1><p>Use an authenticator app. We will show a QR code and copyable setup details.</p>'+n+'<button id="go" class="primary">Show authenticator setup</button></article>';bind("go","click",async()=>{try{const d=await req("/api/authenticator/setup","POST",{});state.stage=d.stage;secret=d.secret;uri=d.provisioningUri;mockLog("Mock authenticator OTP:",d.testOtp);render(d.message)}catch(x){notice(x.message,true)}})}
else if(state.stage==="otp"){const have=!!(secret&&uri);if(!have){app.innerHTML='<article class="card"><div class="icon">📱</div><h1>Get fresh setup details</h1><p>Your QR code and manual details are not shown after a page refresh. Request new details to continue safely.</p>'+n+'<button id="fresh" class="primary">Get fresh setup details</button></article>';bind("fresh","click",async()=>{try{const d=await req("/api/authenticator/refresh","POST",{});secret=d.secret;uri=d.provisioningUri;mockLog("Mock authenticator OTP:",d.testOtp);render(d.message)}catch(x){notice(x.message,true)}})}else{app.innerHTML='<article class="card"><div class="icon">▦</div><h1>Scan the code or copy the details</h1><p>Scan this QR code with your authenticator app. Then enter its six-digit code below. You can reveal and copy manual details if needed.</p>'+n+'<div class="qr" id="qr"></div><button id="showSecret" class="reveal" aria-expanded="false">Show manual Base32 secret</button><div id="secretArea" hidden><label>Manual Base32 secret</label><div class="secret"><code id="sv"></code><button id="cs" class="copy">Copy</button></div></div><button id="showUri" class="reveal" aria-expanded="false">Show authenticator setup link</button><div id="uriArea" hidden><label>Authenticator setup link</label><div class="secret"><code id="uv"></code><button id="cu" class="copy">Copy</button></div></div><button id="fresh" class="secondary">Get fresh setup details</button><form id="f"><label>Six-digit authenticator code</label><input id="code" class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><button class="primary">Confirm authenticator</button></form></article>';qrVisual(uri);q("#sv").textContent=secret;q("#uv").textContent=uri;bind("showSecret","click",()=>{const a=q("#secretArea"),b=q("#showSecret"),open=a.hidden;a.hidden=!open;b.setAttribute("aria-expanded",String(open));b.textContent=open?"Hide manual Base32 secret":"Show manual Base32 secret"});bind("showUri","click",()=>{const a=q("#uriArea"),b=q("#showUri"),open=a.hidden;a.hidden=!open;b.setAttribute("aria-expanded",String(open));b.textContent=open?"Hide authenticator setup link":"Show authenticator setup link"});bind("cs","click",()=>copy(secret,"Base32 secret"));bind("cu","click",()=>copy(uri,"Authenticator setup link"));bind("fresh","click",async()=>{try{const d=await req("/api/authenticator/refresh","POST",{});secret=d.secret;uri=d.provisioningUri;mockLog("Mock authenticator OTP:",d.testOtp);render(d.message)}catch(x){notice(x.message,true)}});bind("f","submit",async e=>{e.preventDefault();try{const d=await req("/api/otp/verify","POST",{code:q("#code").value});state.stage=d.stage;codes=d.recoveryCodes;mockLog("Mock recovery codes:",codes);render(d.message)}catch(x){notice(x.message,true)}})}}
else if(state.stage==="recovery"){const have=codes.length>0,list=have?codes.map((x,i)=>'<li><code>'+x+'</code><button class="copy cp" data-i="'+i+'">Copy</button></li>').join(""):"";app.innerHTML='<article class="card"><div class="icon">🗝️</div><h1>Save your recovery codes</h1><p>'+(have?'Keep these codes somewhere safe. Each code works once.':'Recovery codes are only shown once. Create replacement codes to see a new set.')+'</p>'+n+(have?'<button id="toggleCodes" class="reveal">Hide recovery codes</button><ul id="codeList" class="codes">'+list+'</ul><button id="all" class="secondary">Copy all codes</button>':'')+'<button id="new" class="'+(have?'secondary':'primary')+'">Make new codes</button>'+(have?'<button id="finish" class="primary">I have saved my codes</button>':'')+'</article>';if(have){document.querySelectorAll(".cp").forEach(x=>x.addEventListener("click",()=>copy(codes[+x.dataset.i],"Recovery code")));bind("all","click",()=>copy(codes.join("\\n"),"Recovery codes"));bind("toggleCodes","click",()=>{const l=q("#codeList"),b=q("#toggleCodes"),open=!l.hidden;l.hidden=open;b.textContent=open?"Show recovery codes":"Hide recovery codes"});bind("finish","click",async()=>{try{const d=await req("/api/recovery/complete","POST",{});state.stage=d.stage;render(d.message)}catch(x){notice(x.message,true)}})}bind("new","click",async()=>{try{const d=await req("/api/recovery/generate","POST",{});codes=d.recoveryCodes;mockLog("Mock replacement recovery codes:",codes);render(d.message)}catch(x){notice(x.message,true)}})}
else{app.innerHTML='<article class="card"><div class="icon">✓</div><h1>MFA is ready</h1><p>Your authenticator is connected and recovery codes have been created.</p>'+n+'<details><summary>Test a recovery code</summary><form id="f"><label>Recovery code</label><input id="rc" autocomplete="one-time-code" placeholder="ABCD-EFGH"><button class="secondary">Check this recovery code</button></form></details><button id="out" class="primary">Sign out safely</button></article>';bind("f","submit",async e=>{e.preventDefault();try{const d=await req("/api/recovery/verify","POST",{recoveryCode:q("#rc").value});notice(d.message)}catch(x){notice(x.message,true)}});bind("out","click",async()=>{try{const d=await req("/api/logout","POST",{});csrf="";state.stage="signed-in";secret=uri="";codes=[];render(d.message)}catch(x){notice(x.message,true)}})}}
(async()=>{try{const d=await req("/api/bootstrap");csrf=d.csrf;state.stage=d.authenticated?d.stage:"signed-in";if(d.authenticated){const x=await req("/api/state");state=x;csrf=x.csrf}render()}catch{app.textContent="We could not start secure setup. Please refresh the page."}})()})()</script></body></html>`;
}

const server = Bun.serve({
  port: 3000,
  hostname: "0.0.0.0",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.method === "OPTIONS") {
        if (!trusted(request)) return fail("This request is not allowed.", 403);
        const h = headers();
        h.set("Access-Control-Allow-Origin", url.origin);
        h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
        return new Response(null, { status: 204, headers: h });
      }
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = token(18), h = headers(nonce);
        h.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers: h });
      }
      if (url.pathname.startsWith("/api/")) return api(request, url.pathname);
      return fail("That page is not available.", 404);
    } catch {
      return fail("Something went wrong. Please try again.", 500);
    }
  }
});
console.log(`MFA demo HTTPS server running at https://localhost:${server.port}`);
