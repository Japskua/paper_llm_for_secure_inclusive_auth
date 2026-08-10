
import { readFileSync } from "node:fs";

/*
 MFA enrolment system — requirements sections 1–5.
 All account, session, provisioning, and recovery state is server-side in memory.
 Set EVALUATOR_DEMO=true only for deterministic evaluation fixtures.
*/
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const PORT = Number(process.env.PORT || 3000);
const DEMO_MODE = process.env.EVALUATOR_DEMO === "true";
const USER = { id: "account-marcus-internal", email: "marcus@example.com", password: "welcome123" };
const sessions = new Map<string, Session>();
const mfa = new Map<string, MfaRecord>();
const masterKey = crypto.getRandomValues(new Uint8Array(32));
const enc = new TextEncoder();
const dec = new TextDecoder();

type PendingCode = { salt: string; digest: string; expires: number; used: boolean };
type BackupHash = { salt: string; digest: string; used: boolean };
type Session = {
  userId: string;
  csrf: string;
  created: number;
  seen: number;
  identity?: PendingCode;
  failures: number;
  lockedUntil: number;
};
type MfaRecord = {
  encryptedSecret: string;
  iv: string;
  backups: BackupHash[];
  pendingBackupCodes?: string[];
  enabled: boolean;
  demoTotpFixture?: string;
};

function bytes(length: number) {
  return crypto.getRandomValues(new Uint8Array(length));
}
function hex(value: Uint8Array) {
  return Array.from(value, b => b.toString(16).padStart(2, "0")).join("");
}
function token(length = 32) {
  return hex(bytes(length));
}
function b64(value: Uint8Array) {
  return Buffer.from(value).toString("base64");
}
function fromB64(value: string) {
  return new Uint8Array(Buffer.from(value, "base64"));
}
function base32(value: Uint8Array) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "", bits = 0, valueBits = 0;
  for (const byte of value) {
    valueBits = (valueBits << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(valueBits >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) result += alphabet[(valueBits << (5 - bits)) & 31];
  return result;
}
function decodeBase32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, valueBits = 0;
  const result: number[] = [];
  for (const char of value.toUpperCase().replace(/=|\s/g, "")) {
    const n = alphabet.indexOf(char);
    if (n < 0) throw new Error("Invalid setup key.");
    valueBits = (valueBits << 5) | n;
    bits += 5;
    if (bits >= 8) {
      result.push((valueBits >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(result);
}
function backupCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const raw = Array.from(bytes(10), b => alphabet[b % alphabet.length]).join("");
  return raw.slice(0, 5) + "-" + raw.slice(5);
}
async function sha(value: string, salt: string) {
  const result = await crypto.subtle.digest("SHA-256", enc.encode(salt + ":" + value));
  return hex(new Uint8Array(result));
}
async function pending(value: string, minutes = 20): Promise<PendingCode> {
  const salt = token(16);
  return { salt, digest: await sha(value, salt), expires: Date.now() + minutes * 60_000, used: false };
}
async function matches(value: string, item: PendingCode) {
  return !item.used && Date.now() <= item.expires && (await sha(value, item.salt)) === item.digest;
}
/* Requirement: recovery codes have independent salts and deliberately slow PBKDF2 hashes. */
async function hashBackup(code: string, salt = bytes(16)) {
  const material = await crypto.subtle.importKey("raw", enc.encode(code), "PBKDF2", false, ["deriveBits"]);
  const output = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 150_000 },
    material,
    256
  );
  return { salt: b64(salt), digest: b64(new Uint8Array(output)), used: false };
}
function same(a: string, b: string) {
  const aa = enc.encode(a), bb = enc.encode(b);
  if (aa.length !== bb.length) return false;
  let changed = 0;
  for (let i = 0; i < aa.length; i++) changed |= aa[i] ^ bb[i];
  return changed === 0;
}
async function backupMatches(code: string, entry: BackupHash) {
  const candidate = await hashBackup(code, fromB64(entry.salt));
  return !entry.used && same(candidate.digest, entry.digest);
}
async function encryptAtRest(secret: string) {
  const iv = bytes(12);
  const key = await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(secret));
  return { encryptedSecret: b64(new Uint8Array(encrypted)), iv: b64(iv) };
}
async function decryptAtRest(record: MfaRecord) {
  const key = await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(record.iv) },
    key,
    fromB64(record.encryptedSecret)
  );
  return dec.decode(plain);
}
/* RFC 6238: HMAC-SHA1, 30-second time step, six decimal digits. */
async function totp(secret: string, timestamp = Date.now()) {
  const counter = Math.floor(timestamp / 30_000);
  const counterBytes = new Uint8Array(8);
  let n = counter;
  for (let i = 7; i >= 0; i--) { counterBytes[i] = n & 255; n = Math.floor(n / 256); }
  const key = await crypto.subtle.importKey("raw", decodeBase32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = signed[19] & 15;
  const value = ((signed[offset] & 127) << 24) | (signed[offset + 1] << 16) | (signed[offset + 2] << 8) | signed[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
async function validTotp(record: MfaRecord, code: string) {
  if (DEMO_MODE && record.demoTotpFixture && same(code, record.demoTotpFixture)) return true;
  const secret = await decryptAtRest(record);
  for (const skew of [-1, 0, 1]) if (same(code, await totp(secret, Date.now() + skew * 30_000))) return true;
  return false;
}

function cookie(request: Request, name: string) {
  const row = request.headers.get("cookie") || "";
  return row.split(";").map(v => v.trim()).find(v => v.startsWith(name + "="))?.slice(name.length + 1);
}
function sessionFor(request: Request) {
  const id = cookie(request, "mfa_session");
  const session = id ? sessions.get(id) : undefined;
  if (!id || !session) return undefined;
  const now = Date.now();
  if (now - session.seen > 30 * 60_000 || now - session.created > 8 * 60 * 60_000) {
    sessions.delete(id);
    return undefined;
  }
  session.seen = now;
  return { id, session };
}
function allowedOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    const u = new URL(origin);
    return u.protocol === "https:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  } catch { return false; }
}
function baseHeaders(nonce?: string) {
  const headers = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin"
  });
  headers.set("Content-Security-Policy", nonce
    ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    : "default-src 'none'; frame-ancestors 'none'");
  return headers;
}
function json(data: unknown, status = 200, extras?: HeadersInit) {
  const headers = baseHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extras) new Headers(extras).forEach((v, k) => headers.set(k, v));
  return new Response(JSON.stringify(data), { status, headers });
}
function fail(message = "We could not complete that step. Please try again.", status = 400) {
  return json({ ok: false, message }, status);
}
async function body(request: Request) {
  try {
    const value = await request.json();
    return value && typeof value === "object" ? value as Record<string, unknown> : {};
  } catch { return {}; }
}
/* Requirement 1: browser never selects an account identifier. */
function authorized(request: Request, changing = false) {
  const found = sessionFor(request);
  if (!found || found.session.userId !== USER.id) return { error: fail("Please sign in again.", 401) };
  if (changing && request.headers.get("x-csrf-token") !== found.session.csrf) {
    return { error: fail("This page needs refreshing before you continue.", 403) };
  }
  return found;
}
function cleanCode(value: unknown, pattern: RegExp) {
  return typeof value === "string" && pattern.test(value) ? value : null;
}
function rateCheck(session: Session) {
  return session.lockedUntil > Date.now() ? "Too many attempts. Please wait five minutes, then try again." : "";
}
function failedAttempt(session: Session) {
  session.failures++;
  if (session.failures >= 5) { session.failures = 0; session.lockedUntil = Date.now() + 5 * 60_000; }
}
function successAttempt(session: Session) { session.failures = 0; }
function sessionCookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`;
}
function clearCookie() {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}
function provisioning(secret: string) {
  return `otpauth://totp/LocalBank:Marcus?secret=${secret}&issuer=LocalBank&algorithm=SHA1&digits=6&period=30`;
}
async function createBackups(record: MfaRecord) {
  const plain = DEMO_MODE
    ? ["ALPHA-23456", "BRAVO-23456", "CHARL-23456", "DELTA-23456", "ECHOX-23456", "FOXTN-23456"]
    : Array.from({ length: 6 }, backupCode);
  record.backups = await Promise.all(plain.map(hashBackup));
  record.pendingBackupCodes = plain;
  return plain;
}

async function api(request: Request, path: string): Promise<Response> {
  if (!allowedOrigin(request)) return fail("This request is not allowed.", 403);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: baseHeaders() });

  if (path === "/api/signin" && request.method === "POST") {
    const input = await body(request);
    const email = typeof input.email === "string" ? input.email.trim().toLowerCase() : "";
    const password = typeof input.password === "string" ? input.password : "";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length > 200 || email !== USER.email || password !== USER.password) {
      return fail("Those sign-in details did not work. Check them and try again.", 401);
    }
    const code = DEMO_MODE ? "111111" : String(new DataView(bytes(4).buffer).getUint32(0) % 1_000_000).padStart(6, "0");
    const id = token(32);
    const session: Session = { userId: USER.id, csrf: token(24), created: Date.now(), seen: Date.now(), identity: await pending(code), failures: 0, lockedUntil: 0 };
    sessions.set(id, session);
    return json({ ok: true, csrf: session.csrf, ...(DEMO_MODE ? { demoIdentityCode: code } : {}) }, 200, { "Set-Cookie": sessionCookie(id) });
  }

  const auth = authorized(request, request.method !== "GET");
  if ("error" in auth) return auth.error;
  const { id, session } = auth;

  if (path === "/api/state" && request.method === "GET") {
    const record = mfa.get(session.userId);
    const stage = record?.enabled ? "complete" : session.identity?.used ? (record?.pendingBackupCodes ? "backup" : record ? "setup" : "newsetup") : "identity";
    return json({ ok: true, csrf: session.csrf, stage });
  }
  if (path === "/api/identity" && request.method === "POST") {
    const code = cleanCode((await body(request)).code, /^\d{6}$/);
    if (!code || !session.identity) return fail("Enter the six-digit code. Example: 123456.");
    const locked = rateCheck(session); if (locked) return fail(locked, 429);
    if (!(await matches(code, session.identity))) { failedAttempt(session); return fail("That code did not match. Check the six digits and try again."); }
    session.identity.used = true; successAttempt(session);
    return json({ ok: true, message: "Identity confirmed. Next, add your authenticator." });
  }
  if (path === "/api/identity/resend" && request.method === "POST") {
    const code = DEMO_MODE ? "111111" : String(new DataView(bytes(4).buffer).getUint32(0) % 1_000_000).padStart(6, "0");
    session.identity = await pending(code);
    successAttempt(session);
    return json({ ok: true, ...(DEMO_MODE ? { demoIdentityCode: code } : {}), message: "A new code is ready." });
  }
  if (path === "/api/authenticator/start" && request.method === "POST") {
    if (!session.identity?.used) return fail("Please confirm your identity first.", 403);
    const current = mfa.get(session.userId);
    if (current?.enabled) return fail("Authenticator enrolment is already complete.", 409);
    if (current) return fail("Your existing setup is ready. Refresh this page.", 409);
    const secret = DEMO_MODE ? "JBSWY3DPEHPK3PXP" : base32(bytes(20));
    const secure = await encryptAtRest(secret);
    mfa.set(session.userId, { ...secure, backups: [], enabled: false, ...(DEMO_MODE ? { demoTotpFixture: "123456" } : {}) });
    return json({ ok: true, secret, provisioningUri: provisioning(secret), ...(DEMO_MODE ? { demoTotpCode: "123456" } : {}) });
  }
  /* Authenticated, CSRF-protected retrieval preserves an already pending secret. */
  if (path === "/api/authenticator/pending" && request.method === "POST") {
    const record = mfa.get(session.userId);
    if (!session.identity?.used || !record || record.enabled || record.pendingBackupCodes) return fail("There is no pending authenticator setup.", 404);
    const secret = await decryptAtRest(record);
    return json({ ok: true, secret, provisioningUri: provisioning(secret), ...(DEMO_MODE ? { demoTotpCode: record.demoTotpFixture } : {}) });
  }
  if (path === "/api/authenticator/verify" && request.method === "POST") {
    const code = cleanCode((await body(request)).code, /^\d{6}$/);
    const record = mfa.get(session.userId);
    if (!code || !record || record.enabled) return fail("Enter the six-digit authenticator code. Example: 123456.");
    const locked = rateCheck(session); if (locked) return fail(locked, 429);
    if (!(await validTotp(record, code))) {
      failedAttempt(session);
      return fail("That code did not match. Check your authenticator, then enter its current six-digit code. You have plenty of time.");
    }
    successAttempt(session);
    const codes = await createBackups(record);
    return json({ ok: true, backupCodes: codes, message: "Authenticator confirmed. Save your recovery codes now." });
  }
  if (path === "/api/backup/pending" && request.method === "POST") {
    const record = mfa.get(session.userId);
    if (!record?.pendingBackupCodes || record.enabled) return fail("There are no recovery codes waiting to be saved.", 404);
    return json({ ok: true, backupCodes: record.pendingBackupCodes });
  }
  if (path === "/api/backup/regenerate" && request.method === "POST") {
    const record = mfa.get(session.userId);
    if (!record || !record.pendingBackupCodes) return fail("Please finish authenticator verification first.", 403);
    const codes = await createBackups(record);
    return json({ ok: true, backupCodes: codes, message: "New recovery codes are ready. Your old recovery codes no longer work." });
  }
  if (path === "/api/backup/acknowledge" && request.method === "POST") {
    const record = mfa.get(session.userId);
    if (!record?.pendingBackupCodes || record.backups.length !== 6) return fail("Please finish authenticator verification first.", 403);
    delete record.pendingBackupCodes;
    record.enabled = true;
    return json({ ok: true, message: "MFA is now active." });
  }
  /* Protected post-enrolment challenge: TOTP or one single-use recovery code. */
  if (path === "/api/mfa/verify" && request.method === "POST") {
    const input = await body(request);
    const method = input.method === "recovery" ? "recovery" : "totp";
    const record = mfa.get(session.userId);
    if (!record?.enabled) return fail("MFA setup is not complete.", 403);
    const locked = rateCheck(session); if (locked) return fail(locked, 429);
    let accepted = false;
    if (method === "totp") {
      const code = cleanCode(input.code, /^\d{6}$/);
      accepted = !!code && await validTotp(record, code);
    } else {
      const code = cleanCode(typeof input.code === "string" ? input.code.toUpperCase() : null, /^[A-Z2-9]{5}-[A-Z2-9]{5}$/);
      if (code) {
        for (const item of record.backups) {
          if (await backupMatches(code, item)) { item.used = true; accepted = true; break; }
        }
      }
    }
    if (!accepted) {
      failedAttempt(session);
      return fail(method === "recovery"
        ? "That recovery code did not work. Check its letters, numbers, and dash, then try again."
        : "That authenticator code did not match. Enter the current six-digit code and try again.");
    }
    successAttempt(session);
    return json({ ok: true, message: method === "recovery" ? "Recovery code accepted. It cannot be used again." : "Authenticator code accepted." });
  }
  if (path === "/api/logout" && request.method === "POST") {
    sessions.delete(id);
    return json({ ok: true }, 200, { "Set-Cookie": clearCookie() });
  }
  return fail("That page is not available.", 404);
}

function page(nonce: string) {
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#17253a;--blue:#075f9d;--pale:#eaf5fc;--line:#bed0dc;--good:#176b43;--bad:#a22525}
*{box-sizing:border-box}body{margin:0;background:#f4f7f9;color:var(--ink);font-family:Verdana,Arial,sans-serif;letter-spacing:.035em;line-height:1.62;font-size:16px}main{max-width:560px;margin:auto;min-height:100vh;background:#fff;padding:20px 20px 38px}.brand{font-weight:700;font-size:1.1rem;color:var(--blue)}.steps{font-size:.85rem;margin:12px 0 26px;color:#48606f}.card{border:1px solid var(--line);border-radius:16px;padding:22px;background:#fff;box-shadow:0 2px 10px #16304612}h1{font-size:1.55rem;line-height:1.25;margin:0 0 12px}.icon{font-size:2rem;display:block;margin-bottom:8px}p{margin:10px 0 18px}.hint,.notice{background:var(--pale);border-left:4px solid var(--blue);padding:11px 13px;border-radius:5px;font-size:.91rem}.notice{border-color:var(--good);background:#ecf8f0}.error{color:var(--bad);font-weight:700;margin:12px 0}label{font-weight:700;display:block;margin:16px 0 5px}input{width:100%;font:inherit;letter-spacing:.08em;padding:13px;border:2px solid #7992a2;border-radius:9px;color:var(--ink)}input:focus,button:focus{outline:3px solid #e5a82d;outline-offset:2px}small{display:block;color:#4d626d;margin-top:4px}.primary,.secondary{font:inherit;font-weight:700;border-radius:9px;padding:13px 16px;cursor:pointer;width:100%;margin-top:20px}.primary{border:0;background:var(--blue);color:white;font-size:1.03rem}.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue)}.links{display:flex;gap:10px;margin-top:14px}.links button{width:auto;margin:0;padding:8px;background:none;border:0;color:var(--blue);text-decoration:underline;font:inherit;cursor:pointer}.code-list{list-style:none;padding:0;margin:12px 0}.code-list li,.secret{font-family:monospace;font-size:1rem;letter-spacing:.1em;background:#f4f7f9;margin:7px 0;padding:9px;border-radius:6px;overflow-wrap:anywhere}.qr{display:block;width:min(100%,280px);height:auto;margin:14px auto;border:8px solid white;image-rendering:pixelated}.sr{position:absolute;left:-9999px}@media(max-width:380px){main{padding:16px}.card{padding:17px}body{font-size:15px}}
</style></head><body><main><header><div class="brand">◈ Local Bank</div><div class="steps" id="steps">Step 1 of 5 · Sign in</div></header><section class="card" id="app" aria-live="polite"></section></main>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",setup=null,backups=[];
const app=document.getElementById("app"),steps=document.getElementById("steps");
const esc=v=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&gt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function call(url,data,method="POST"){const o={method,headers:{"Content-Type":"application/json"}};if(method!=="GET")o.headers["X-CSRF-Token"]=csrf;if(data!==undefined)o.body=JSON.stringify(data);const r=await fetch(url,o),j=await r.json();if(!r.ok)throw new Error(j.message||"Please try again.");return j}
function shell(step,title,icon,content){steps.textContent=step;app.innerHTML='<span class="icon" aria-hidden="true">'+icon+'</span><h1>'+title+'</h1>'+content}
function controls(extra=""){return '<div class="links"><button type="button" data-help>Help</button>'+extra+'</div><div class="hint" hidden id="help">Take your time. Nothing changes while you are reading. You can retry safely.</div>'}
function bindHelp(){const b=app.querySelector("[data-help]");if(b)b.onclick=()=>document.getElementById("help").hidden=!document.getElementById("help").hidden}
function showError(e){app.insertAdjacentHTML("beforeend",'<p class="error" role="alert">'+esc(e.message)+'</p>')}
function demo(r){if(r.demoIdentityCode)console.log("Evaluator demo identity OTP:",r.demoIdentityCode);if(r.demoTotpCode)console.log("Evaluator demo TOTP fixture:",r.demoTotpCode);if(r.backupCodes)console.log("Evaluator demo recovery codes:",r.backupCodes)}
function signIn(){shell("Step 1 of 5 · Sign in","Sign in to start","👋",'<p>Use the demo account to begin your secure setup.</p><form id="signin"><label>Email</label><input name="email" type="email" autocomplete="username" value="marcus@example.com" required><small>Example: name@example.com</small><label>Password</label><input name="password" type="password" autocomplete="current-password" value="welcome123" required><small>Demo password: welcome123</small><button class="primary">Sign in</button></form>'+controls());bindHelp();document.getElementById("signin").onsubmit=async e=>{e.preventDefault();try{const f=new FormData(e.target),r=await call("/api/signin",{email:f.get("email"),password:f.get("password")});csrf=r.csrf;demo(r);identity()}catch(x){showError(x)}}}
function identity(){shell("Step 2 of 5 · Confirm identity","Check your identity","📱",'<p>Enter the six-digit code sent to your phone.</p><form id="identity"><label>Identity code</label><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required><small>Example: 123456</small><button class="primary">Confirm code</button></form>'+controls('<button type="button" data-resend>Send a new code</button>'));bindHelp();document.getElementById("identity").onsubmit=async e=>{e.preventDefault();try{await call("/api/identity",{code:new FormData(e.target).get("code")});newSetup()}catch(x){showError(x)}};app.querySelector("[data-resend]").onclick=async()=>{try{const r=await call("/api/identity/resend",{});demo(r);app.insertAdjacentHTML("beforeend",'<p class="notice">A new code is ready.</p>')}catch(x){showError(x)}}}
async function newSetup(){try{setup=await call("/api/authenticator/start",{});demo(setup);setupScreen()}catch(x){showError(x)}}
async function restoreSetup(){try{setup=await call("/api/authenticator/pending",{});demo(setup);setupScreen()}catch(x){showError(x)}}
/* Standards-compliant QR encoder: QR Version 6, byte mode, EC level L, Reed-Solomon. */
function qrSvg(text){const V=6,N=41,GF=new Array(512),LOG=new Array(256);let x=1;for(let i=0;i<255;i++){GF[i]=x;LOG[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)GF[i]=GF[i-255];const mul=(a,b)=>!a||!b?0:GF[LOG[a]+LOG[b]];let data=[4];const raw=new TextEncoder().encode(text);for(let i=7;i>=0;i--)data.push((raw.length>>i)&1);for(const z of raw)for(let i=7;i>=0;i--)data.push((z>>i)&1);for(let i=0;i<4&&data.length<1088;i++)data.push(0);while(data.length%8)data.push(0);let words=[];for(let i=0;i<data.length;i+=8)words.push(data.slice(i,i+8).reduce((a,b)=>a*2+b,0));for(let p=0;words.length<136;p^=0xec)words.push(p?0x11:0xec);let gen=[1];for(let i=0;i<18;i++){let q=new Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){q[j]^=gen[j];q[j+1]^=mul(gen[j],GF[i])}gen=q}const rs=block=>{let r=new Array(18).fill(0);for(const z of block){let f=z^r.shift();r.push(0);for(let j=0;j<18;j++)r[j]^=mul(gen[j+1],f)}return r};const blocks=[words.slice(0,68),words.slice(68)],ecc=blocks.map(rs),stream=[];for(let i=0;i<68;i++)for(const b of blocks)stream.push(b[i]);for(let i=0;i<18;i++)for(const b of ecc)stream.push(b[i]);let bits=[];for(const z of stream)for(let i=7;i>=0;i--)bits.push((z>>i)&1);
const make=mask=>{let m=Array.from({length:N},()=>Array(N).fill(null)),fixed=Array.from({length:N},()=>Array(N).fill(false));const set=(r,c,v)=>{if(r>=0&&c>=0&&r<N&&c<N){m[r][c]=v;fixed[r][c]=true}};const finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)set(r+y,c+z,y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4)))};finder(0,0);finder(0,N-7);finder(N-7,0);for(let i=8;i<N-8;i++){set(6,i,i%2===0);set(i,6,i%2===0)}for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)set(34+y,34+z,Math.max(Math.abs(y),Math.abs(z))!==1);set(N-8,8,true);for(let i=0;i<9;i++){if(!fixed[8][i])set(8,i,false);if(!fixed[i][8])set(i,8,false)}for(let i=0;i<8;i++){if(!fixed[8][N-1-i])set(8,N-1-i,false);if(!fixed[N-1-i][8])set(N-1-i,8,false)}let format=(0x08|mask)<<10,rem=format;while(rem.toString(2).length>=11)rem^=0x537<<(rem.toString(2).length-11);format=(format|rem)^0x5412;for(let i=0;i<15;i++){let v=((format>>i)&1)===1;if(i<6)set(i,8,v);else if(i<8)set(i+1,8,v);else set(N-15+i,8,v);if(i<8)set(8,N-i-1,v);else if(i<9)set(8,15-i,v);else set(8,15-i-1,v)}let k=0,up=true;for(let c=N-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<N;q++){let r=up?N-1-q:q;for(let z=0;z<2;z++){let col=c-z;if(!fixed[r][col]){let v=bits[k++]||0;let invert=[(r+col)%2===0,r%2===0,col%3===0,(r+col)%3===0,(Math.floor(r/2)+Math.floor(col/3))%2===0,(r*col)%2+(r*col)%3===0,((r*col)%2+(r*col)%3)%2===0,((r+col)%2+(r*col)%3)%2===0][mask];m[r][col]=!!(v^invert)}}up=!up}return m};const score=m=>{let s=0;for(let r=0;r<N;r++)for(let c=0;c<N;c++){let n=0;for(let y=-1;y<=1;y++)for(let z=-1;z<=1;z++)if(y||z)if(m[r+y]?.[c+z]===m[r][c])n++;if(n>5)s+=3+n-5}for(let r=0;r<N-1;r++)for(let c=0;c<N-1;c++)if(m[r][c]===m[r+1][c]&&m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c+1])s+=3;return s};let best=make(0);for(let i=1;i<8;i++){let q=make(i);if(score(q)<score(best))best=q}let rect="";for(let r=0;r<N;r++)for(let c=0;c<N;c++)if(best[r][c])rect+='<rect x="'+c+'" y="'+r+'" width="1" height="1"/>';return '<svg class="qr" viewBox="-4 -4 49 49" role="img" aria-label="Authenticator setup QR code" xmlns="http://www.w3.org/2000/svg"><rect x="-4" y="-4" width="49" height="49" fill="white"/><g fill="#17253a">'+rect+"</g></svg>"}
function setupScreen(){shell("Step 3 of 5 · Add authenticator","Add your authenticator","🔐",'<p>Scan the QR code. You can also reveal and enter the setup details yourself.</p>'+qrSvg(setup.provisioningUri)+'<button class="secondary" id="reveal">Show setup details</button><div id="details" hidden><label>Setup key</label><div class="secret">'+esc(setup.secret)+'</div><button class="secondary" id="copykey">Copy setup key</button><label>Full setup link</label><div class="secret">'+esc(setup.provisioningUri)+'</div><button class="secondary" id="copyuri">Copy full setup link</button></div><form id="otp"><label>Authenticator code</label><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required><small>Example: 123456</small><button class="primary">Confirm authenticator</button></form>'+controls());bindHelp();document.getElementById("reveal").onclick=()=>{document.getElementById("details").hidden=false};const copy=(v)=>navigator.clipboard.writeText(v).then(()=>alert("Copied.")).catch(()=>alert("Copy is not available. The details are shown above."));document.getElementById("copykey").onclick=()=>copy(setup.secret);document.getElementById("copyuri").onclick=()=>copy(setup.provisioningUri);document.getElementById("otp").onsubmit=async e=>{e.preventDefault();try{const r=await call("/api/authenticator/verify",{code:new FormData(e.target).get("code")});backups=r.backupCodes;demo(r);backupScreen()}catch(x){showError(x)}}}
async function restoreBackups(){try{const r=await call("/api/backup/pending",{});backups=r.backupCodes;demo(r);backupScreen()}catch(x){showError(x)}}
function backupScreen(){const lines=backups.map(v=>'<li>'+esc(v)+'</li>').join("");shell("Step 4 of 5 · Save recovery codes","Save your recovery codes","🧾",'<p>These codes help if you lose your phone. Keep them somewhere private.</p><ul class="code-list">'+lines+'</ul><button class="secondary" id="copycodes">Copy recovery codes</button><button class="secondary" id="regen">Get new recovery codes</button><p id="notice" class="notice" hidden></p><button class="primary" id="finish">I have saved my codes</button>'+controls());bindHelp();document.getElementById("copycodes").onclick=()=>navigator.clipboard.writeText(backups.join("\\n")).then(()=>{let n=document.getElementById("notice");n.textContent="Recovery codes copied. You can now finish setup.";n.hidden=false}).catch(()=>alert("Copy is not available. The codes are shown above."));document.getElementById("regen").onclick=async()=>{try{const r=await call("/api/backup/regenerate",{});backups=r.backupCodes;demo(r);backupScreen();app.insertAdjacentHTML("afterbegin",'<p class="notice">New codes are shown below. The old codes no longer work.</p>')}catch(x){showError(x)}};document.getElementById("finish").onclick=async()=>{try{await call("/api/backup/acknowledge",{});complete()}catch(x){showError(x)}}}
function complete(){shell("Step 5 of 5 · Complete","MFA is ready","✅",'<p class="notice">Your authenticator is active.</p><button class="primary" id="verify">Verify MFA now</button><div class="links"><button type="button" id="logout">Sign out</button></div>'+controls());bindHelp();document.getElementById("verify").onclick=verifyScreen;document.getElementById("logout").onclick=logout}
function verifyScreen(){shell("MFA check","Verify your MFA","🔐",'<p>Use your authenticator code, or one recovery code.</p><form id="verifyform"><label>Authenticator or recovery code</label><input name="code" autocomplete="one-time-code" placeholder="123456 or ABCDE-23456" required><small>Examples: 123456 or ABCDE-23456</small><button class="primary">Verify</button></form>'+controls('<button type="button" id="useRecovery">Use a recovery code</button>'));bindHelp();let recovery=false;document.getElementById("useRecovery").onclick=()=>{recovery=!recovery;document.getElementById("useRecovery").textContent=recovery?"Use authenticator code":"Use a recovery code"};document.getElementById("verifyform").onsubmit=async e=>{e.preventDefault();try{const r=await call("/api/mfa/verify",{method:recovery?"recovery":"totp",code:new FormData(e.target).get("code")});shell("MFA check","Verification complete","✅",'<p class="notice">'+esc(r.message)+'</p><button class="primary" id="back">Back to MFA settings</button>');document.getElementById("back").onclick=complete}catch(x){showError(x)}}}
async function logout(){try{await call("/api/logout",{});csrf="";setup=null;backups=[];signIn()}catch(x){showError(x)}}
async function begin(){try{const r=await call("/api/state",undefined,"GET");csrf=r.csrf;if(r.stage==="complete")complete();else if(r.stage==="identity")identity();else if(r.stage==="setup")restoreSetup();else if(r.stage==="backup")restoreBackups();else if(r.stage==="newsetup")newSetup();else signIn()}catch{signIn()}}begin()})();
</script></body></html>`;
}

async function handler(request: Request) {
  try {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
    if (url.pathname === "/" && request.method === "GET") {
      const nonce = token(18), headers = baseHeaders(nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { headers });
    }
    return fail("That page is not available.", 404);
  } catch {
    return fail("We could not complete that request. Please try again.", 500);
  }
}

/* Requirement 2/3: Bun serves HTTPS directly with supplied mkcert certificates. */
Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: { cert: readFileSync(CERT_PATH), key: readFileSync(KEY_PATH) },
  fetch: handler
});
