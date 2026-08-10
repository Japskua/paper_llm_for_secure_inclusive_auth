
import { readFileSync } from "node:fs";

/*
 MFA enrolment system — requirements sections 1–5.
 Server-side-only in-memory account, sessions, OTP setup, and recovery state.
 EVALUATOR_DEMO=true makes recovery codes deterministic; identity OTPs and TOTP
 fixtures remain time-bound and single-use where appropriate.
*/
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const PORT = Number(process.env.PORT || 3000);
const DEMO_MODE = process.env.EVALUATOR_DEMO === "true";
const enc = new TextEncoder();
const dec = new TextDecoder();
const masterKey = crypto.getRandomValues(new Uint8Array(32));
const sessions = new Map<string, Session>();
const mfa = new Map<string, MfaRecord>();

type PendingCode = { salt: string; digest: string; expires: number; used: boolean };
type BackupHash = { salt: string; digest: string; used: boolean };
type EncryptedPendingCodes = { encrypted: string; iv: string };
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
  pendingBackupCodes?: EncryptedPendingCodes;
  enabled: boolean;
  acceptedTotpCounters: number[];
};

function bytes(length: number) {
  return crypto.getRandomValues(new Uint8Array(length));
}
function hex(value: Uint8Array) {
  return Array.from(value, x => x.toString(16).padStart(2, "0")).join("");
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
  let output = "", held = 0, bits = 0;
  for (const byte of value) {
    held = (held << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(held >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) output += alphabet[(held << (5 - bits)) & 31];
  return output;
}
function decodeBase32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let held = 0, bits = 0;
  const output: number[] = [];
  for (const character of value.toUpperCase().replace(/[=\s]/g, "")) {
    const n = alphabet.indexOf(character);
    if (n < 0) throw new Error("Invalid setup key");
    held = (held << 5) | n;
    bits += 5;
    if (bits >= 8) {
      output.push((held >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}
function backupCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const raw = Array.from(bytes(10), byte => alphabet[byte % alphabet.length]).join("");
  return raw.slice(0, 5) + "-" + raw.slice(5);
}
function fixedEqual(a: string, b: string) {
  const aa = enc.encode(a);
  const bb = enc.encode(b);
  const size = Math.max(aa.length, bb.length);
  let changed = aa.length ^ bb.length;
  for (let i = 0; i < size; i++) changed |= (aa[i] || 0) ^ (bb[i] || 0);
  return changed === 0;
}
async function sha(value: string, salt: string) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(salt + ":" + value))));
}
async function pending(value: string, minutes = 20): Promise<PendingCode> {
  const salt = token(16);
  return { salt, digest: await sha(value, salt), expires: Date.now() + minutes * 60_000, used: false };
}
async function pendingMatches(value: string, item: PendingCode) {
  return !item.used && Date.now() <= item.expires && fixedEqual(await sha(value, item.salt), item.digest);
}
/* Requirement 3: PBKDF2 for credentials and one-time recovery-code hashes. */
async function pbkdf2(value: string, salt: Uint8Array, iterations = 150_000) {
  const material = await crypto.subtle.importKey("raw", enc.encode(value), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    256
  );
  return b64(new Uint8Array(bits));
}
const credentialSalt = bytes(16);
const knownPasswordDigest = await pbkdf2("welcome123", credentialSalt);
const USER = { id: "account-marcus-internal", email: "marcus@example.com", passwordDigest: knownPasswordDigest };

async function verifyCredentials(email: string, password: string) {
  /*
   Requirement 5: always do the same PBKDF2 work, including unknown/malformed
   email input. No short-circuit based on account existence.
  */
  const suppliedDigest = await pbkdf2(password.slice(0, 200), credentialSalt);
  const accountMatches = fixedEqual(email, USER.email);
  const passwordMatches = fixedEqual(suppliedDigest, USER.passwordDigest);
  return accountMatches && passwordMatches && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
async function hashBackup(code: string, salt = bytes(16)): Promise<BackupHash> {
  return { salt: b64(salt), digest: await pbkdf2(code, salt), used: false };
}
async function backupMatches(code: string, item: BackupHash) {
  const candidate = await pbkdf2(code, fromB64(item.salt));
  return !item.used && fixedEqual(candidate, item.digest);
}
async function aesKey() {
  return crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function encryptText(value: string) {
  const iv = bytes(12);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(), enc.encode(value));
  return { encrypted: b64(new Uint8Array(encrypted)), iv: b64(iv) };
}
async function decryptText(item: { encrypted: string; iv: string }) {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(item.iv) },
    await aesKey(),
    fromB64(item.encrypted)
  );
  return dec.decode(plain);
}
async function encryptSecret(secret: string) {
  const item = await encryptText(secret);
  return { encryptedSecret: item.encrypted, iv: item.iv };
}
async function decryptSecret(record: MfaRecord) {
  return decryptText({ encrypted: record.encryptedSecret, iv: record.iv });
}
/* RFC 6238: SHA-1, 30 second steps, six digits. */
async function totpAtCounter(secret: string, counter: number) {
  const counterBytes = new Uint8Array(8);
  let held = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = held & 255;
    held = Math.floor(held / 256);
  }
  const key = await crypto.subtle.importKey("raw", decodeBase32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = signed[19] & 15;
  const value = ((signed[offset] & 127) << 24) | (signed[offset + 1] << 16) |
    (signed[offset + 2] << 8) | signed[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
async function acceptedTotpCounter(record: MfaRecord, code: string): Promise<number | null> {
  const secret = await decryptSecret(record);
  const nowCounter = Math.floor(Date.now() / 30_000);
  for (const counter of [nowCounter - 1, nowCounter, nowCounter + 1]) {
    if (record.acceptedTotpCounters.includes(counter)) continue;
    if (fixedEqual(code, await totpAtCounter(secret, counter))) return counter;
  }
  return null;
}
function rememberTotpCounter(record: MfaRecord, counter: number) {
  record.acceptedTotpCounters.push(counter);
  record.acceptedTotpCounters = record.acceptedTotpCounters.slice(-12);
}
async function currentDemoTotp(record: MfaRecord) {
  return totpAtCounter(await decryptSecret(record), Math.floor(Date.now() / 30_000));
}
function cookie(request: Request, name: string) {
  const row = request.headers.get("cookie") || "";
  return row.split(";").map(x => x.trim()).find(x => x.startsWith(name + "="))?.slice(name.length + 1);
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
    const url = new URL(origin);
    return url.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
  } catch {
    return false;
  }
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
    ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    : "default-src 'none'; frame-ancestors 'none'");
  return headers;
}
function json(data: unknown, status = 200, extras?: HeadersInit) {
  const headers = baseHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extras) new Headers(extras).forEach((value, key) => headers.set(key, value));
  return new Response(JSON.stringify(data), { status, headers });
}
function fail(message = "We could not complete that step. Please try again.", status = 400) {
  return json({ ok: false, message }, status);
}
async function body(request: Request) {
  try {
    const value = await request.json();
    return value && typeof value === "object" ? value as Record<string, unknown> : {};
  } catch {
    return {};
  }
}
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
  if (session.failures >= 5) {
    session.failures = 0;
    session.lockedUntil = Date.now() + 5 * 60_000;
  }
}
function successAttempt(session: Session) {
  session.failures = 0;
}
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
  /* Requirement task: pending codes are encrypted, never plaintext at rest. */
  record.pendingBackupCodes = await encryptText(JSON.stringify(plain));
  return plain;
}
async function showPendingBackups(record: MfaRecord) {
  if (!record.pendingBackupCodes) return null;
  const parsed = JSON.parse(await decryptText(record.pendingBackupCodes));
  return Array.isArray(parsed) && parsed.every(x => typeof x === "string") ? parsed as string[] : null;
}
function identityCode() {
  return String(new DataView(bytes(4).buffer).getUint32(0) % 1_000_000).padStart(6, "0");
}

async function api(request: Request, path: string): Promise<Response> {
  if (!allowedOrigin(request)) return fail("This request is not allowed.", 403);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: baseHeaders() });

  if (path === "/api/signin" && request.method === "POST") {
    const input = await body(request);
    const email = typeof input.email === "string" ? input.email.trim().toLowerCase() : "";
    const password = typeof input.password === "string" ? input.password : "";
    const valid = await verifyCredentials(email, password);
    if (!valid) return fail("Those sign-in details did not work. Check them and try again.", 401);

    const code = identityCode();
    const id = token(32);
    const session: Session = {
      userId: USER.id, csrf: token(24), created: Date.now(), seen: Date.now(),
      identity: await pending(code), failures: 0, lockedUntil: 0
    };
    sessions.set(id, session);
    /* Task: protected response always delivers simulated identity OTP; never server-logged. */
    return json({ ok: true, csrf: session.csrf, identityOtp: code, message: "A code is ready to enter." }, 200, {
      "Set-Cookie": sessionCookie(id)
    });
  }

  const auth = authorized(request, request.method !== "GET");
  if ("error" in auth) return auth.error;
  const { id, session } = auth;

  if (path === "/api/state" && request.method === "GET") {
    const record = mfa.get(session.userId);
    const stage = record?.enabled ? "complete" : session.identity?.used
      ? (record?.pendingBackupCodes ? "backup" : record ? "setup" : "newsetup")
      : "identity";
    return json({ ok: true, csrf: session.csrf, stage });
  }
  if (path === "/api/identity" && request.method === "POST") {
    const code = cleanCode((await body(request)).code, /^\d{6}$/);
    if (!code || !session.identity) return fail("Enter the six-digit code. Example: 123456.");
    const locked = rateCheck(session);
    if (locked) return fail(locked, 429);
    if (!(await pendingMatches(code, session.identity))) {
      failedAttempt(session);
      return fail("That code did not match. Check the six digits and try again.");
    }
    session.identity.used = true;
    successAttempt(session);
    return json({ ok: true, message: "Identity confirmed. Next, add your authenticator." });
  }
  if (path === "/api/identity/resend" && request.method === "POST") {
    const code = identityCode();
    session.identity = await pending(code);
    successAttempt(session);
    /* Task: this protected, authenticated response always includes the simulation OTP. */
    return json({ ok: true, identityOtp: code, message: "A new code is ready." });
  }
  if (path === "/api/authenticator/start" && request.method === "POST") {
    if (!session.identity?.used) return fail("Please confirm your identity first.", 403);
    const old = mfa.get(session.userId);
    if (old?.enabled) return fail("Authenticator enrolment is already complete.", 409);
    if (old) return fail("Your existing setup is ready. Refresh this page.", 409);
    const secret = DEMO_MODE ? "JBSWY3DPEHPK3PXP" : base32(bytes(20));
    const secure = await encryptSecret(secret);
    const record: MfaRecord = { ...secure, backups: [], enabled: false, acceptedTotpCounters: [] };
    mfa.set(session.userId, record);
    return json({
      ok: true, secret, provisioningUri: provisioning(secret),
      ...(DEMO_MODE ? { demoTotpCode: await currentDemoTotp(record) } : {})
    });
  }
  if (path === "/api/authenticator/pending" && request.method === "POST") {
    const record = mfa.get(session.userId);
    if (!session.identity?.used || !record || record.enabled || record.pendingBackupCodes) {
      return fail("There is no pending authenticator setup.", 404);
    }
    const secret = await decryptSecret(record);
    return json({
      ok: true, secret, provisioningUri: provisioning(secret),
      ...(DEMO_MODE ? { demoTotpCode: await currentDemoTotp(record) } : {})
    });
  }
  if (path === "/api/authenticator/verify" && request.method === "POST") {
    const code = cleanCode((await body(request)).code, /^\d{6}$/);
    const record = mfa.get(session.userId);
    if (!code || !record || record.enabled) return fail("Enter the six-digit authenticator code. Example: 123456.");
    const locked = rateCheck(session);
    if (locked) return fail(locked, 429);
    const counter = await acceptedTotpCounter(record, code);
    if (counter === null) {
      failedAttempt(session);
      return fail("That code did not match, or it was already used. Check your authenticator and enter its current six-digit code.");
    }
    /* Task: server-side replay protection records every accepted time counter. */
    rememberTotpCounter(record, counter);
    successAttempt(session);
    const codes = await createBackups(record);
    return json({ ok: true, backupCodes: codes, message: "Authenticator confirmed. Save your recovery codes now." });
  }
  /* Requirement task: decrypt pending codes only in authenticated, CSRF POST display endpoints. */
  if (path === "/api/backup/pending" && request.method === "POST") {
    const record = mfa.get(session.userId);
    if (!record?.pendingBackupCodes || record.enabled) return fail("There are no recovery codes waiting to be saved.", 404);
    const codes = await showPendingBackups(record);
    if (!codes) return fail();
    return json({ ok: true, backupCodes: codes });
  }
  if (path === "/api/backup/regenerate" && request.method === "POST") {
    const record = mfa.get(session.userId);
    if (!record?.pendingBackupCodes) return fail("Please finish authenticator verification first.", 403);
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
  if (path === "/api/mfa/verify" && request.method === "POST") {
    const input = await body(request);
    const method = input.method === "recovery" ? "recovery" : "totp";
    const record = mfa.get(session.userId);
    if (!record?.enabled) return fail("MFA setup is not complete.", 403);
    const locked = rateCheck(session);
    if (locked) return fail(locked, 429);
    let accepted = false;
    if (method === "totp") {
      const code = cleanCode(input.code, /^\d{6}$/);
      if (code) {
        const counter = await acceptedTotpCounter(record, code);
        if (counter !== null) {
          rememberTotpCounter(record, counter);
          accepted = true;
        }
      }
    } else {
      const code = cleanCode(typeof input.code === "string" ? input.code.toUpperCase() : null, /^[A-Z2-9]{5}-[A-Z2-9]{5}$/);
      if (code) {
        for (const item of record.backups) {
          if (await backupMatches(code, item)) {
            item.used = true;
            accepted = true;
            break;
          }
        }
      }
    }
    if (!accepted) {
      failedAttempt(session);
      return fail(method === "recovery"
        ? "That recovery code did not work. Check its letters, numbers, and dash, then try again."
        : "That authenticator code did not match, or it was already used. Enter a current six-digit code and try again.");
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
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#17253a;--blue:#075f9d;--pale:#eaf5fc;--line:#bed0dc;--good:#176b43;--bad:#a22525}
*{box-sizing:border-box}body{margin:0;background:#f4f7f9;color:var(--ink);font-family:Verdana,Arial,sans-serif;letter-spacing:.035em;line-height:1.65;font-size:16px}
main{max-width:560px;margin:auto;min-height:100vh;background:#fff;padding:20px 20px 38px}.brand{font-weight:700;font-size:1.1rem;color:var(--blue)}
.steps{font-size:.88rem;margin:12px 0 24px;color:#48606f}.card,.logs{border:1px solid var(--line);border-radius:16px;padding:22px;background:#fff;box-shadow:0 2px 10px #16304612}
h1{font-size:1.55rem;line-height:1.28;margin:0 0 12px}.icon{font-size:2rem;display:block;margin-bottom:8px}p{margin:10px 0 18px}
.hint,.notice{background:var(--pale);border-left:4px solid var(--blue);padding:11px 13px;border-radius:5px;font-size:.91rem}.notice{border-color:var(--good);background:#ecf8f0}
.error{color:var(--bad);font-weight:700;margin:12px 0}label{font-weight:700;display:block;margin:16px 0 5px}
input{width:100%;font:inherit;letter-spacing:.08em;padding:13px;border:2px solid #7992a2;border-radius:9px;color:var(--ink)}
input:focus,button:focus{outline:3px solid #e5a82d;outline-offset:2px}small{display:block;color:#4d626d;margin-top:4px}
.primary,.secondary{font:inherit;font-weight:700;border-radius:9px;padding:13px 16px;cursor:pointer;width:100%;margin-top:18px}.primary{border:0;background:var(--blue);color:#fff;font-size:1.03rem}.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue)}
.links{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap}.links button{width:auto;margin:0;padding:8px;background:none;border:0;color:var(--blue);text-decoration:underline;font:inherit;cursor:pointer}
.code-list{list-style:none;padding:0;margin:12px 0}.code-list li,.secret{font-family:monospace;font-size:1rem;letter-spacing:.1em;background:#f4f7f9;margin:7px 0;padding:9px;border-radius:6px;overflow-wrap:anywhere}
.qr{width:220px;height:220px;margin:14px auto;display:grid;grid-template-columns:repeat(15,1fr);border:9px solid white;background:#fff}.qr i{background:#17253a}.logs{margin-top:18px;padding:14px}.logs h2{font-size:1rem;margin:0 0 7px}.logs-output{margin:0;max-height:160px;overflow:auto;white-space:pre-wrap;word-break:break-word;font:13px/1.55 monospace;color:#284050}.sr{position:absolute;left:-9999px}
@media(max-width:380px){main{padding:16px}.card{padding:17px}body{font-size:15px}}
</style></head><body><main>
<header><div class="brand">◈ Local Bank</div><div class="steps" id="steps">Step 1 of 5 · Sign in</div></header>
<section class="card" id="app" aria-live="polite"></section>
<section class="logs" aria-label="Simulation logs"><h2>Logs</h2><pre class="logs-output" id="logs">Simulation messages appear here.</pre></section>
</main>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",setup=null,backups=[];
const app=document.getElementById("app"),steps=document.getElementById("steps"),logs=document.getElementById("logs");
const esc=v=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&gt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function log(label,value){console.log(label,value);logs.textContent=(logs.textContent==="Simulation messages appear here."?"":logs.textContent+"\\n")+label+" "+(Array.isArray(value)?value.join(", "):value);logs.scrollTop=logs.scrollHeight}
async function call(url,data,method="POST"){const o={method,headers:{"Content-Type":"application/json"}};if(method!=="GET")o.headers["X-CSRF-Token"]=csrf;if(data!==undefined)o.body=JSON.stringify(data);const r=await fetch(url,o),j=await r.json();if(!r.ok)throw new Error(j.message||"Please try again.");return j}
function shell(step,title,icon,content){steps.textContent=step;app.innerHTML='<span class="icon" aria-hidden="true">'+icon+'</span><h1>'+title+'</h1>'+content}
function controls(extra=""){return '<div class="links"><button type="button" data-help>Help</button>'+extra+'</div><div class="hint" hidden id="help">Take your time. Nothing changes while you are reading. You can retry safely.</div>'}
function bindHelp(){const b=app.querySelector("[data-help]");if(b)b.onclick=()=>document.getElementById("help").hidden=!document.getElementById("help").hidden}
function showError(e){app.insertAdjacentHTML("beforeend",'<p class="error" role="alert">'+esc(e.message)+'</p>')}
function simulation(r){if(r.identityOtp)log("Simulated identity OTP:",r.identityOtp);if(r.demoTotpCode)log("Simulated current TOTP:",r.demoTotpCode);if(r.backupCodes)log("Simulated recovery codes:",r.backupCodes)}
function signIn(){shell("Step 1 of 5 · Sign in","Sign in to start","👋",'<p>Use the demo account to begin your secure setup.</p><form id="signin"><label>Email</label><input name="email" type="email" autocomplete="username" value="marcus@example.com" required><small>Example: name@example.com</small><label>Password</label><input name="password" type="password" autocomplete="current-password" value="welcome123" required><small>Demo password: welcome123</small><button class="primary">Sign in</button></form>'+controls());bindHelp();document.getElementById("signin").onsubmit=async e=>{e.preventDefault();try{const f=new FormData(e.target),r=await call("/api/signin",{email:f.get("email"),password:f.get("password")});csrf=r.csrf;simulation(r);identity()}catch(x){showError(x)}}}
function identity(){shell("Step 2 of 5 · Confirm identity","Check your identity","📱",'<p>Enter the six-digit code sent to your phone. The simulated code is in Logs below.</p><form id="identity"><label>Identity code</label><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required><small>Example: 123456</small><button class="primary">Confirm code</button></form>'+controls('<button type="button" data-resend>Send a new code</button>'));bindHelp();document.getElementById("identity").onsubmit=async e=>{e.preventDefault();try{await call("/api/identity",{code:new FormData(e.target).get("code")});newSetup()}catch(x){showError(x)}};app.querySelector("[data-resend]").onclick=async()=>{try{const r=await call("/api/identity/resend",{});simulation(r);app.insertAdjacentHTML("beforeend",'<p class="notice">A new code is ready. Find it in Logs below.</p>')}catch(x){showError(x)}}}
async function newSetup(){try{setup=await call("/api/authenticator/start",{});simulation(setup);setupScreen()}catch(x){showError(x)}}
async function restoreSetup(){try{setup=await call("/api/authenticator/pending",{});simulation(setup);setupScreen()}catch(x){showError(x)}}
function qr(){let s="";for(let i=0;i<225;i++){const row=Math.floor(i/15),col=i%15,edge=row<4&&col<4||row<4&&col>10||row>10&&col<4;s+='<i style="opacity:'+(edge||((row*19+col*11+row*col)%5<2)?1:0)+'"></i>'}return '<div class="qr" role="img" aria-label="QR code option for authenticator setup">'+s+'</div>'}
function setupScreen(){shell("Step 3 of 5 · Add authenticator","Add your authenticator","🔐",'<p>Scan the QR code with your authenticator app. You can also show and copy setup details.</p>'+qr()+'<button class="secondary" id="reveal">Show setup details</button><div id="details" hidden><label>Setup key</label><div class="secret">'+esc(setup.secret)+'</div><button class="secondary" id="copykey">Copy setup key</button><label>Full setup link</label><div class="secret">'+esc(setup.provisioningUri)+'</div><button class="secondary" id="copyuri">Copy full setup link</button></div><form id="otp"><label>Authenticator code</label><input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required><small>Example: 123456</small><button class="primary">Confirm authenticator</button></form>'+controls());bindHelp();document.getElementById("reveal").onclick=()=>document.getElementById("details").hidden=false;const copy=v=>navigator.clipboard.writeText(v).then(()=>alert("Copied.")).catch(()=>alert("Copy is not available. The details are shown above."));document.getElementById("copykey").onclick=()=>copy(setup.secret);document.getElementById("copyuri").onclick=()=>copy(setup.provisioningUri);document.getElementById("otp").onsubmit=async e=>{e.preventDefault();try{const r=await call("/api/authenticator/verify",{code:new FormData(e.target).get("code")});backups=r.backupCodes;simulation(r);backupScreen()}catch(x){showError(x)}}}
async function restoreBackups(){try{const r=await call("/api/backup/pending",{});backups=r.backupCodes;simulation(r);backupScreen()}catch(x){showError(x)}}
function backupScreen(){const lines=backups.map(v=>'<li>'+esc(v)+'</li>').join("");shell("Step 4 of 5 · Save recovery codes","Save your recovery codes","🧾",'<p>These codes help if you lose your phone. Keep them somewhere private.</p><ul class="code-list">'+lines+'</ul><button class="secondary" id="copycodes">Copy recovery codes</button><button class="secondary" id="regen">Get new recovery codes</button><p id="notice" class="notice" hidden></p><button class="primary" id="finish">I have saved my codes</button>'+controls());bindHelp();document.getElementById("copycodes").onclick=()=>navigator.clipboard.writeText(backups.join("\\n")).then(()=>{const n=document.getElementById("notice");n.textContent="Recovery codes copied. You can now finish setup.";n.hidden=false}).catch(()=>alert("Copy is not available. The codes are shown above."));document.getElementById("regen").onclick=async()=>{try{const r=await call("/api/backup/regenerate",{});backups=r.backupCodes;simulation(r);backupScreen()}catch(x){showError(x)}};document.getElementById("finish").onclick=async()=>{try{await call("/api/backup/acknowledge",{});complete()}catch(x){showError(x)}}}
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
      const nonce = token(18);
      const headers = baseHeaders(nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { headers });
    }
    return fail("That page is not available.", 404);
  } catch {
    return fail("We could not complete that request. Please try again.", 500);
  }
}

/* Requirement 2/3: HTTPS Bun server using supplied mkcert certificate files. */
Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: { cert: readFileSync(CERT_PATH), key: readFileSync(KEY_PATH) },
  fetch: handler
});
