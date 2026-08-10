
import { timingSafeEqual } from "node:crypto";

/*
 MFA Enrolment System — requirements 1–5
 Single-file Bun HTTPS server and mobile vanilla HTML SPA.
 All state is deterministic in-memory mock state. Server never logs secrets/codes.
*/

type Stage = "signed-in" | "identity" | "setup" | "otp" | "recovery" | "complete";
type Cipher = { iv: string; ciphertext: string };
type ProtectedCode = { hash: string; expiresAt: number; used: boolean; failedAttempts: number };
type Recovery = { salt: string; hash: string; used: boolean; expiresAt: number };
type Session = {
  id: string; csrf: string; authenticated: boolean; email?: string; userId?: string;
  stage: Stage; createdAt: number; lastSeen: number;
  identityCode?: ProtectedCode;
  encryptedOtpSecret?: Cipher; otpUsed?: boolean; otpFails: number;
  recoveryFails: number; lockedUntil?: number; recoveryCodes: Recovery[];
};

const sessions = new Map<string, Session>();
const encoder = new TextEncoder();
const MASTER_KEY = crypto.getRandomValues(new Uint8Array(32));
const IDENTITY_KEY = crypto.getRandomValues(new Uint8Array(32));
const IDLE = 20 * 60_000;
const ABSOLUTE = 8 * 60 * 60_000;
const CODE_LIFE = 15 * 60_000;
const LOCK = 5 * 60_000;
const RECOVERY_LIFE = 365 * 24 * 60 * 60_000;
const PBKDF2_ITERATIONS = 210_000;

const now = () => Date.now();
const token = (n = 32) => Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url");

function same(a: string, b: string) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
async function sha256(value: string) {
  return Buffer.from(await crypto.subtle.digest("SHA-256", encoder.encode(value))).toString("base64url");
}
/* Requirement 3: keyed protected representation for short-lived identity codes. */
async function identityHash(code: string) {
  const key = await crypto.subtle.importKey("raw", IDENTITY_KEY, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return Buffer.from(await crypto.subtle.sign("HMAC", key, encoder.encode(code))).toString("base64url");
}
/* Requirement 3 / task: a deliberately slow KDF with a unique salt per recovery code. */
async function recoveryHash(code: string, salt: string) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: Buffer.from(salt, "base64url"), iterations: PBKDF2_ITERATIONS },
    key, 256
  );
  return Buffer.from(bits).toString("base64url");
}
function randomSixDigits() {
  const limit = Math.floor(0x1_0000_0000 / 1_000_000) * 1_000_000;
  const word = new Uint32Array(1);
  do crypto.getRandomValues(word); while (word[0] >= limit);
  return String(word[0] % 1_000_000).padStart(6, "0");
}
async function issueIdentityCode(previous?: ProtectedCode) {
  let code = randomSixDigits();
  if (previous) {
    while (same(await identityHash(code), previous.hash)) code = randomSixDigits();
  }
  return { code, record: { hash: await identityHash(code), expiresAt: now() + CODE_LIFE, used: false, failedAttempts: 0 } };
}
async function encrypt(value: string): Promise<Cipher> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", MASTER_KEY, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return { iv: Buffer.from(iv).toString("base64url"), ciphertext: Buffer.from(ciphertext).toString("base64url") };
}
async function decrypt(value: Cipher) {
  const key = await crypto.subtle.importKey("raw", MASTER_KEY, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(value.iv, "base64url") }, key, Buffer.from(value.ciphertext, "base64url")
  );
  return new TextDecoder().decode(plain);
}

function base32Secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let out = "", bits = 0, value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return bits ? out + alphabet[(value << (5 - bits)) & 31] : out;
}
function base32Decode(input: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let value = 0, bits = 0; const out: number[] = [];
  for (const c of input.replace(/=|\s/g, "").toUpperCase()) {
    const n = alphabet.indexOf(c); if (n < 0) throw new Error("bad secret");
    value = (value << 5) | n; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
async function totp(secret: string, step: number) {
  const counter = new Uint8Array(8); let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(n & 255n); n >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = digest[19] & 15;
  const value = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
async function validTotp(secret: string, code: string) {
  const step = Math.floor(now() / 30_000);
  for (const offset of [-1, 0, 1]) if (same(await totp(secret, step + offset), code)) return true;
  return false;
}

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
  const h = headers();
  for (const [k, v] of Object.entries(extra || {})) h.set(k, v);
  return new Response(JSON.stringify(data), { status, headers: h });
}
const fail = (message: string, status = 400) => reply({ ok: false, error: message }, status);
function trusted(req: Request) {
  const origin = req.headers.get("origin");
  return !origin || /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(origin);
}
function makeSession() {
  const s: Session = {
    id: token(), csrf: token(), authenticated: false, stage: "signed-in",
    createdAt: now(), lastSeen: now(), otpFails: 0, recoveryFails: 0, recoveryCodes: []
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
  const value = b?.[name];
  return typeof value === "string" && value.length <= max ? value.trim() : null;
}
const locked = (s: Session) => !!s.lockedUntil && s.lockedUntil > now();
function failed(s: Session, key: "otpFails" | "recoveryFails") {
  if (++s[key] >= 5) { s[key] = 0; s.lockedUntil = now() + LOCK; }
}
function recoveryCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  const value = Array.from(bytes, x => alphabet[x % alphabet.length]).join("");
  return value.slice(0, 4) + "-" + value.slice(4);
}
async function createRecovery(s: Session) {
  const codes = Array.from({ length: 6 }, recoveryCode);
  s.recoveryCodes = await Promise.all(codes.map(async code => {
    const salt = token(16);
    return { salt, hash: await recoveryHash(code, salt), used: false, expiresAt: now() + RECOVERY_LIFE };
  }));
  return codes;
}
async function provision(s: Session) {
  const secret = base32Secret();
  s.encryptedOtpSecret = await encrypt(secret); s.otpUsed = false; s.otpFails = 0;
  const issuer = "Northstar Bank", label = issuer + ":" + (s.email || "marcus@example.com");
  const provisioningUri = `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  return { secret, provisioningUri, testOtp: await totp(secret, Math.floor(now() / 30_000)) };
}

async function api(req: Request, path: string): Promise<Response> {
  if (!trusted(req)) return fail("This request is not allowed.", 403);

  if (path === "/api/bootstrap" && req.method === "GET") {
    let s = current(req), set: string | undefined;
    if (!s) { s = makeSession(); set = sessionCookie(s.id); }
    return reply({ ok: true, csrf: s.csrf, authenticated: s.authenticated, stage: s.stage }, 200, set ? { "Set-Cookie": set } : undefined);
  }
  if (path === "/api/sign-in" && req.method === "POST") {
    const old = current(req);
    if (!old || !csrf(req, old)) return fail("Please refresh the page and try signing in again.", 403);
    const b = await body(req), email = field(b, "email", 120), password = field(b, "password", 200);
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !password) return fail("Enter an email like name@example.com and your password.");
    if (email.toLowerCase() !== "marcus@example.com" || password !== "bank-demo") return fail("We could not sign you in. Check your email and password, then try again.", 401);

    sessions.delete(old.id); // Requirement 5: rotate identifier on authentication.
    const s = makeSession();
    s.authenticated = true; s.userId = "account-owner-marcus"; s.email = "marcus@example.com"; s.stage = "identity";
    const issued = await issueIdentityCode();
    s.identityCode = issued.record;
    return reply({ ok: true, csrf: s.csrf, stage: s.stage, testIdentityCode: issued.code, message: "We sent a six-digit check code." }, 200, { "Set-Cookie": sessionCookie(s.id) });
  }
  if (path === "/api/state" && req.method === "GET") {
    const s = owner(req);
    return s instanceof Response ? s : reply({ ok: true, stage: s.stage, email: s.email, csrf: s.csrf, locked: locked(s) });
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

    /* Task: invalidate old protected record before a cryptographically random replacement. */
    if (s.identityCode) s.identityCode.used = true;
    const issued = await issueIdentityCode(s.identityCode);
    s.identityCode = issued.record;
    return reply({ ok: true, testIdentityCode: issued.code, message: "A new check code is ready. The earlier code no longer works." });
  }
  if ((path === "/api/authenticator/setup" || path === "/api/authenticator/refresh") && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    const fresh = path.endsWith("refresh");
    if ((fresh && s.stage !== "otp") || (!fresh && s.stage !== "setup")) return fail("Please complete the earlier step first.", 409);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const data = await provision(s); s.stage = "otp";
    return reply({ ok: true, stage: s.stage, ...data, message: fresh ? "Fresh authenticator setup details are ready. The old setup details no longer work." : "Authenticator details are ready. Add them, then enter its six-digit code." });
  }
  if (path === "/api/otp/verify" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "otp") return fail("Please complete the earlier step first.", 409);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const code = field(await body(req), "code", 6);
    if (!code || !/^\d{6}$/.test(code)) return fail("Enter six numbers, for example 123456.");
    if (s.otpUsed || !s.encryptedOtpSecret) return fail("Choose get fresh setup details and try again.");
    let ok = false; try { ok = await validTotp(await decrypt(s.encryptedOtpSecret), code); } catch { ok = false; }
    if (!ok) { failed(s, "otpFails"); return fail(locked(s) ? "Too many tries. Please wait five minutes, then try again." : "That code does not match. Check the six numbers in your authenticator and try again."); }
    s.otpUsed = true; s.stage = "recovery";
    const codes = await createRecovery(s);
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
    s.stage = "complete";
    return reply({ ok: true, stage: s.stage, message: "MFA enrolment is complete." });
  }
  if (path === "/api/recovery/verify" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const code = field(await body(req), "recoveryCode", 9)?.toUpperCase();
    if (!code || !/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code)) return fail("Enter a recovery code like ABCD-EFGH.");
    let hit: Recovery | undefined;
    for (const r of s.recoveryCodes) {
      if (!r.used && r.expiresAt > now() && same(await recoveryHash(code, r.salt), r.hash)) { hit = r; break; }
    }
    if (!hit) { failed(s, "recoveryFails"); return fail(locked(s) ? "Too many tries. Please wait five minutes, then try again." : "That recovery code does not match an unused code. Check it and try again."); }
    hit.used = true;
    return reply({ ok: true, message: "That recovery code worked and is now used. Your other codes still work." });
  }
  if (path === "/api/logout" && req.method === "POST") {
    const s = current(req);
    if (!s || !csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    sessions.delete(s.id);
    return reply({ ok: true, message: "You have signed out." }, 200, { "Set-Cookie": clearCookie() });
  }
  return fail("That page is not available.", 404);
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Bank — MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172033;--muted:#536074;--blue:#0759b8;--line:#cad5e2;--soft:#eef6ff}*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:var(--ink);font:17px/1.65 Arial,Verdana,sans-serif;letter-spacing:.035em}button,input{font:inherit;letter-spacing:.035em}.shell{width:min(100%,540px);min-height:100vh;margin:auto;background:#fff;padding:20px 18px 36px}.brand{font-weight:bold;color:#063a78;border-bottom:1px solid var(--line);padding-bottom:15px;font-size:19px}.progress{margin:18px 0 24px}.progress div{display:flex;justify-content:space-between;color:var(--muted);font-size:14px;font-weight:bold}.bar{height:9px;background:#dce5ef;border-radius:9px;margin-top:7px}.bar span{display:block;height:100%;background:var(--blue);border-radius:9px}.card{border:1px solid var(--line);border-radius:16px;padding:23px 19px}.icon{font-size:28px;background:var(--soft);border-radius:13px;width:48px;height:48px;display:grid;place-items:center}h1{font-size:27px;line-height:1.25;margin:14px 0 10px}p{margin:0 0 15px}label{display:block;font-weight:bold;margin:15px 0 5px}input{width:100%;min-height:51px;border:2px solid #9eacbd;border-radius:10px;padding:12px}.code{font-size:23px;font-weight:bold;letter-spacing:.18em;text-align:center}.primary{width:100%;min-height:54px;margin-top:20px;border:0;border-radius:10px;background:var(--blue);color:#fff;font-weight:bold}.secondary,.copy{color:var(--blue);font-weight:bold;background:#fff;border:0;text-decoration:underline;padding:10px 1px}.copy{border:1px solid var(--blue);border-radius:8px;padding:6px 9px;text-decoration:none}.notice{padding:11px;border-radius:10px;margin-bottom:15px;font-size:15px;background:#e8f7ef;color:#075d36}.bad{background:#fff0ef;color:#8b1d16}.example{font-size:14px;color:var(--muted);margin:6px 0}.secret{display:flex;gap:8px;align-items:center;border:1px solid var(--line);background:#f5f8fc;border-radius:10px;padding:9px}.secret code{flex:1;overflow-wrap:anywhere;font-size:13px}.qr{text-align:center;margin:18px 0}.qrbox{width:220px;height:220px;margin:auto;border:9px solid white;outline:1px solid var(--line);display:grid;grid-template-columns:repeat(21,1fr);grid-template-rows:repeat(21,1fr);background:#fff}.dot{background:#172033}.codes{list-style:none;padding:0}.codes li{display:flex;justify-content:space-between;align-items:center;border:1px solid var(--line);padding:8px;margin:7px 0;border-radius:9px}.logs{margin-top:22px;border-top:1px solid var(--line);padding-top:12px}.logbox{background:#101b2d;color:#dff1ff;border-radius:10px;padding:11px;min-height:70px;max-height:180px;overflow:auto;font:12px/1.5 monospace;letter-spacing:0;white-space:pre-wrap}.hint,details{font-size:14px;color:var(--muted)}[hidden]{display:none!important}@media(max-width:380px){.shell{padding:15px 13px}.card{padding:19px 15px}h1{font-size:24px}.qrbox{width:190px;height:190px}}
</style></head><body><main class="shell"><header class="brand">✦ Northstar Bank</header><section class="progress"><div><span id="pt">Getting started</span><span id="pc">Step 1 of 6</span></div><p class="bar"><span id="pb" style="width:16%"></span></p></section><section id="app" aria-live="polite">Loading secure setup…</section><section class="logs"><h2>Logs</h2><p class="hint">Mock delivery values appear here and in the browser console.</p><div id="logs" class="logbox">Ready.</div></section><footer class="hint">Take your time. There is no reading timer.</footer></main>
<script nonce="${nonce}">(()=>{"use strict";
const app=document.querySelector("#app"),logs=document.querySelector("#logs"),pt=document.querySelector("#pt"),pc=document.querySelector("#pc"),pb=document.querySelector("#pb");let csrf="",state={stage:"signed-in"},secret="",uri="",codes=[];
function log(x){console.log(x);logs.textContent+="\\\\n"+x;logs.scrollTop=logs.scrollHeight}
async function req(path,method="GET",body){const o={method,credentials:"same-origin",headers:{}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(body||{})}const r=await fetch(path,o),d=await r.json().catch(()=>({}));if(!r.ok||!d.ok)throw Error(d.error||"Please try again.");if(d.csrf)csrf=d.csrf;return d}
function notice(t,b){const n=document.querySelector("#notice");if(n){n.textContent=t;n.className="notice "+(b?"bad":"");n.hidden=false}}
function bind(id,event,fn){const e=document.querySelector("#"+id);if(e)e.addEventListener(event,fn)}
function copy(v,label){navigator.clipboard?.writeText(v).then(()=>notice(label+" copied."),()=>notice("Select the text and copy it using your browser.",true))}
function progress(s){const x={"signed-in":[1,"Sign in"],identity:[2,"Identity check"],setup:[3,"Authenticator setup"],otp:[4,"Confirm code"],recovery:[5,"Save recovery codes"],complete:[6,"Finished"]}[s]||[1,"Sign in"];pt.textContent=x[1];pc.textContent="Step "+x[0]+" of 6";pb.style.width=(x[0]*100/6)+"%"}
function qrVisual(value){const q=document.querySelector("#qr");if(!q)return;q.textContent="";let seed=0;for(const c of value)seed=(seed*31+c.charCodeAt(0))>>>0;for(let y=0;y<21;y++)for(let x=0;x<21;x++){const d=document.createElement("i");let finder=(a,b)=>a>=0&&a<7&&b>=0&&b<7&&(a===0||a===6||b===0||b===6||(a>=2&&a<=4&&b>=2&&b<=4));let on=finder(x,y)||finder(x-14,y)||finder(x,y-14);if(!on){seed=(seed*1664525+1013904223)>>>0;on=!!(seed&1)}if(on)d.className="dot";q.appendChild(d)}}
function render(msg,bad){progress(state.stage);const n=msg?'<div id="notice" class="notice '+(bad?"bad":"")+'">'+msg+'</div>':'<div id="notice" hidden></div>';
if(state.stage==="signed-in"){app.innerHTML='<article class="card"><div class="icon">🔐</div><h1>Sign in to start MFA setup</h1><p>Use the demo account. We will guide you one step at a time.</p>'+n+'<form id="f"><label>Email address</label><input id="email" type="email" autocomplete="username" placeholder="marcus@example.com"><p class="example">Example: marcus@example.com</p><label>Password</label><input id="password" type="password" autocomplete="current-password" placeholder="bank-demo"><button class="primary">Sign in</button></form></article>';bind("f","submit",async e=>{e.preventDefault();try{const d=await req("/api/sign-in","POST",{email:email.value,password:password.value});csrf=d.csrf;state.stage=d.stage;log("Mock identity check code: "+d.testIdentityCode);render(d.message)}catch(x){notice(x.message,true)}})}
else if(state.stage==="identity"){app.innerHTML='<article class="card"><div class="icon">🪪</div><h1>Check it is you</h1><p>Enter your phone number and the six-digit code we sent.</p>'+n+'<form id="f"><label>Phone number</label><input id="phone" type="tel" autocomplete="tel" placeholder="+1 555 010 0200"><label>Six-digit check code</label><input id="code" class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="246810"><button class="primary">Check my identity</button></form><button id="resend" class="secondary">Send a new code</button></article>';bind("f","submit",async e=>{e.preventDefault();try{const d=await req("/api/identity/verify","POST",{phone:phone.value,code:code.value});state.stage=d.stage;render(d.message)}catch(x){notice(x.message,true)}});bind("resend","click",async()=>{try{const d=await req("/api/identity/resend","POST",{});log("Mock identity check code: "+d.testIdentityCode);notice(d.message)}catch(x){notice(x.message,true)}})}
else if(state.stage==="setup"){app.innerHTML='<article class="card"><div class="icon">📱</div><h1>Add your authenticator</h1><p>Use an authenticator app. We will show a QR code and copyable setup details.</p>'+n+'<button id="go" class="primary">Show authenticator setup</button></article>';bind("go","click",async()=>{try{const d=await req("/api/authenticator/setup","POST",{});state.stage=d.stage;secret=d.secret;uri=d.provisioningUri;log("Mock authenticator OTP: "+d.testOtp);render(d.message)}catch(x){notice(x.message,true)}})}
else if(state.stage==="otp"){app.innerHTML='<article class="card"><div class="icon">▦</div><h1>Scan or copy the setup details</h1><p>Scan this code in your authenticator app. You can also copy the manual details.</p>'+n+'<div class="qr"><div id="qr" class="qrbox" role="img" aria-label="Authenticator QR code"></div></div><label>Manual Base32 secret</label><div class="secret"><code id="sv"></code><button id="cs" class="copy">Copy</button></div><label>Authenticator setup link</label><div class="secret"><code id="uv"></code><button id="cu" class="copy">Copy</button></div><button id="fresh" class="secondary">Get fresh setup details</button><form id="f"><label>Six-digit authenticator code</label><input id="code" class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><button class="primary">Confirm authenticator</button></form></article>';sv.textContent=secret;uv.textContent=uri;qrVisual(uri);bind("cs","click",()=>copy(secret,"Base32 secret"));bind("cu","click",()=>copy(uri,"Authenticator setup link"));bind("fresh","click",async()=>{try{const d=await req("/api/authenticator/refresh","POST",{});secret=d.secret;uri=d.provisioningUri;log("Mock authenticator OTP: "+d.testOtp);render(d.message)}catch(x){notice(x.message,true)}});bind("f","submit",async e=>{e.preventDefault();try{const d=await req("/api/otp/verify","POST",{code:code.value});state.stage=d.stage;codes=d.recoveryCodes;log("Mock recovery codes: "+codes.join(", "));render(d.message)}catch(x){notice(x.message,true)}})}
else if(state.stage==="recovery"){const list=codes.length?codes.map((x,i)=>'<li><code>'+x+'</code><button class="copy cp" data-i="'+i+'">Copy</button></li>').join(""):"<li>Codes are not shown after refresh.</li>";app.innerHTML='<article class="card"><div class="icon">🗝️</div><h1>Save your recovery codes</h1><p>Keep these codes somewhere safe. Each code works once.</p>'+n+'<ul class="codes">'+list+'</ul><button id="all" class="secondary">Copy all codes</button><button id="new" class="secondary">Make new codes</button><button id="finish" class="primary">I have saved my codes</button></article>';document.querySelectorAll(".cp").forEach(x=>x.addEventListener("click",()=>copy(codes[+x.dataset.i],"Recovery code")));bind("all","click",()=>copy(codes.join("\\n"),"Recovery codes"));bind("new","click",async()=>{try{const d=await req("/api/recovery/generate","POST",{});codes=d.recoveryCodes;log("Mock replacement recovery codes: "+codes.join(", "));render(d.message)}catch(x){notice(x.message,true)}});bind("finish","click",async()=>{try{const d=await req("/api/recovery/complete","POST",{});state.stage=d.stage;render(d.message)}catch(x){notice(x.message,true)}})}
else{app.innerHTML='<article class="card"><div class="icon">✓</div><h1>MFA is ready</h1><p>Your authenticator is connected and recovery codes have been created.</p>'+n+'<details><summary>Test a recovery code</summary><form id="f"><label>Recovery code</label><input id="rc" autocomplete="one-time-code" placeholder="ABCD-EFGH"><button class="secondary">Check this recovery code</button></form></details><button id="out" class="primary">Sign out safely</button></article>';bind("f","submit",async e=>{e.preventDefault();try{const d=await req("/api/recovery/verify","POST",{recoveryCode:rc.value});notice(d.message)}catch(x){notice(x.message,true)}});bind("out","click",async()=>{try{const d=await req("/api/logout","POST",{});csrf="";state.stage="signed-in";secret=uri="";codes=[];render(d.message)}catch(x){notice(x.message,true)}})}}
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
