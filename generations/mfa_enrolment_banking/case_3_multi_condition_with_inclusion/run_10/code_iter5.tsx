
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHmac,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

/*
 MFA Enrolment System — single Bun HTTPS server and vanilla mobile SPA.
 Requirement 1: every MFA route derives the account from the authenticated
 HttpOnly session; no route accepts an account or user identifier.
*/

type Challenge = { code: string; expiresAt: number; attempts: number; lockedUntil: number; used: boolean };
type RecoveryVerifier = { salt: string; verifier: string };
type Account = {
  id: string; email: string; passwordVerifier: string; passwordSalt: string;
  deliveryChannel: string; mfaEnabled: boolean; pendingEncryptedSecret?: string; encryptedSecret?: string;
  identityChallenge?: Challenge; usedTotpCounters: Set<string>;
  authenticatorAttempts: number; authenticatorLockedUntil: number;
  recoveryVerifiers: RecoveryVerifier[]; recoveryAttempts: number; recoveryLockedUntil: number;
  recoveryConfirmed: boolean;
};
type Session = {
  id: string; accountId: string; csrf: string; createdAt: number; lastSeen: number;
  identityVerified: boolean;
};

const accounts = new Map<string, Account>();
const accountsById = new Map<string, Account>();
const sessions = new Map<string, Session>();
const loginTokens = new Map<string, number>();
const encryptionKey = randomBytes(32);

const IDLE_MS = 20 * 60_000;
const ABSOLUTE_MS = 8 * 60 * 60_000;
const CODE_MS = 15 * 60_000;
const LOCK_MS = 10 * 60_000;
const MAX_ATTEMPTS = 5;
const MAX_EMAIL_LENGTH = 254;
/* Conservative bounded email syntax, deliberately used only after type/length checks. */
const EMAIL_FORMAT = /^[a-z0-9](?:[a-z0-9.!#$%&'*+/=?^_`{|}~-]{0,62}[a-z0-9])?@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

const token = (n = 32) => randomBytes(n).toString("base64url");
/*
 Requirement 5: all password candidates are bounded before scrypt. This makes
 malformed and oversized credential input perform the same one scrypt work as
 valid input without allowing unbounded attacker-controlled work.
*/
const passwordInput = (value: unknown) => typeof value === "string" ? value.slice(0, 200) : "";
const passwordHash = (password: string, salt: Buffer) =>
  scryptSync(passwordInput(password), salt, 32, { N: 16384, r: 8, p: 1 }).toString("base64url");

/*
 Requirement task: a dedicated non-account verifier is used whenever email
 input is malformed, oversized, nonexistent, or otherwise not selectable.
 Every /api/authenticate credential attempt below executes exactly one
 comparable scrypt verification before the same generic failure response.
*/
const dummyPasswordSalt = randomBytes(16);
const dummyPasswordVerifier = passwordHash("non-account-password", dummyPasswordSalt);

function provision(email: string, password: string, channel: string) {
  const salt = randomBytes(16);
  const account: Account = {
    id: token(18), email, passwordSalt: salt.toString("base64url"),
    passwordVerifier: passwordHash(password, salt), deliveryChannel: channel,
    mfaEnabled: false, usedTotpCounters: new Set(), authenticatorAttempts: 0,
    authenticatorLockedUntil: 0, recoveryVerifiers: [], recoveryAttempts: 0,
    recoveryLockedUntil: 0, recoveryConfirmed: false,
  };
  accounts.set(email, account);
  accountsById.set(account.id, account);
}
provision("marcus@example.test", "Northstar-54", "approved mobile ending 41");
provision("alex@example.test", "Northstar-22", "approved mobile ending 72");

function encrypt(value: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return [iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), data.toString("base64url")].join(".");
}
function decrypt(value: string) {
  const [iv, tag, data] = value.split(".");
  if (!iv || !tag || !data) throw new Error("protected value");
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(data, "base64url")), decipher.final()]).toString("utf8");
}
function secretBase32() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = randomBytes(20);
  let bits = 0, value = 0, out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return out + (bits ? alphabet[(value << (5 - bits)) & 31] : "");
}
function b32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, work = 0;
  const out: number[] = [];
  for (const ch of value.replace(/=+$/g, "").toUpperCase()) {
    const n = alphabet.indexOf(ch);
    if (n < 0) throw new Error("base32");
    work = (work << 5) | n; bits += 5;
    if (bits >= 8) { out.push((work >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
function totp(secret: string, counter: number) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", b32(secret)).update(buf).digest();
  const offset = digest[19] & 15;
  const value = (((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) | digest[offset + 3]) % 1_000_000;
  return String(value).padStart(6, "0");
}
function matchingTotp(secret: string, code: string): number | null {
  const current = Math.floor(Date.now() / 30_000);
  for (const delta of [-1, 0, 1]) if (totp(secret, current + delta) === code) return current + delta;
  return null;
}
function recoveryCodes() {
  return Array.from({ length: 8 }, () => {
    const v = randomBytes(10).toString("hex").toUpperCase();
    return `${v.slice(0, 10)}-${v.slice(10)}`;
  });
}
function makeVerifiers(codes: string[]): RecoveryVerifier[] {
  return codes.map(code => {
    const salt = randomBytes(16);
    return { salt: salt.toString("base64url"), verifier: passwordHash(code, salt) };
  });
}
function recoveryMatches(code: string, saved: RecoveryVerifier) {
  const got = Buffer.from(passwordHash(code, Buffer.from(saved.salt, "base64url")), "base64url");
  const want = Buffer.from(saved.verifier, "base64url");
  return got.length === want.length && timingSafeEqual(got, want);
}
function cookies(request: Request) {
  const out: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const p = part.indexOf("=");
    if (p > 0) out[part.slice(0, p).trim()] = part.slice(p + 1).trim();
  }
  return out;
}
const cookie = (name: string, value: string, age: number) =>
  `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
const expired = (name: string) => cookie(name, "", 0);
function headers(nonce: string, type = "application/json; charset=utf-8") {
  return new Headers({
    "Content-Type": type,
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
}
function reply(data: unknown, status = 200, nonce = token(12), setCookie?: string) {
  const h = headers(nonce);
  if (setCookie) h.append("Set-Cookie", setCookie);
  return new Response(JSON.stringify(data), { status, headers: h });
}
const generic = (status: number, nonce: string) =>
  reply({ error: "We could not complete that request. Please try again." }, status, nonce);
function sameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    const requestUrl = new URL(request.url), originUrl = new URL(origin);
    return requestUrl.protocol === "https:" && originUrl.origin === requestUrl.origin;
  } catch { return false; }
}
async function input(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch { return null; }
}
const six = (x: unknown): x is string => typeof x === "string" && /^\d{6}$/.test(x);
const backup = (x: unknown): x is string => typeof x === "string" && /^[A-Za-z0-9]{10}-[A-Za-z0-9]{10}$/.test(x);

function sessionFor(request: Request, nonce: string): { session: Session; account: Account } | Response {
  const id = cookies(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  const now = Date.now();
  if (!session || now - session.lastSeen > IDLE_MS || now - session.createdAt > ABSOLUTE_MS) {
    if (id) sessions.delete(id);
    return reply({ error: "Please sign in again to continue." }, 401, nonce, expired("mfa_session"));
  }
  const account = accountsById.get(session.accountId);
  if (!account) { sessions.delete(session.id); return generic(401, nonce); }
  session.lastSeen = now;
  return { session, account };
}
function failed(attempts: number, locked: number, type: string) {
  if (locked > Date.now() || attempts + 1 >= MAX_ATTEMPTS) return "Too many attempts. Wait ten minutes before trying again.";
  return `That ${type} did not work. Check it and try again. ${MAX_ATTEMPTS - attempts - 1} tries remain.`;
}

async function api(request: Request, path: string, nonce: string): Promise<Response> {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: headers(nonce) });

  if (path === "/api/login-csrf" && request.method === "GET") {
    const t = token();
    loginTokens.set(t, Date.now() + 600_000);
    return reply({ token: t }, 200, nonce, cookie("mfa_login_csrf", t, 600));
  }

  if (path === "/api/authenticate" && request.method === "POST") {
    const c = cookies(request);
    const t = request.headers.get("x-login-csrf-token");
    const expiry = t ? loginTokens.get(t) : 0;
    if (!sameOrigin(request) || !t || c.mfa_login_csrf !== t || !expiry || expiry < Date.now()) return generic(403, nonce);
    loginTokens.delete(t);

    const data = await input(request);
    const rawEmail = data?.email;
    const validEmail = typeof rawEmail === "string" &&
      rawEmail.length <= MAX_EMAIL_LENGTH &&
      EMAIL_FORMAT.test(rawEmail.trim());
    const email = validEmail ? rawEmail.trim().toLowerCase() : "";

    /*
      Requirement task: no early return for malformed, non-string, oversized,
      or unknown email. All paths select either the account verifier or the
      fixed dummy verifier and make one equivalent scrypt calculation.
    */
    const account = validEmail ? accounts.get(email) : undefined;
    const salt = account ? Buffer.from(account.passwordSalt, "base64url") : dummyPasswordSalt;
    const expected = Buffer.from(account ? account.passwordVerifier : dummyPasswordVerifier, "base64url");
    const supplied = Buffer.from(passwordHash(data?.password, salt), "base64url");
    const passwordMatches = supplied.length === expected.length && timingSafeEqual(supplied, expected);

    /* Identical generic invalid-credential response for every failed credential attempt. */
    if (!account || !passwordMatches) {
      return reply({ error: "Those sign-in details did not work. Check them and try again." }, 401, nonce);
    }

    const old = c.mfa_session;
    if (old) sessions.delete(old);
    const session: Session = {
      id: token(), accountId: account.id, csrf: token(),
      createdAt: Date.now(), lastSeen: Date.now(), identityVerified: false,
    };
    sessions.set(session.id, session);
    const h = headers(nonce);
    h.append("Set-Cookie", cookie("mfa_session", session.id, Math.floor(ABSOLUTE_MS / 1000)));
    h.append("Set-Cookie", expired("mfa_login_csrf"));
    return new Response(JSON.stringify({ csrf: session.csrf, next: account.mfaEnabled ? "complete" : "identity" }), { headers: h });
  }

  const checked = sessionFor(request, nonce);
  if (checked instanceof Response) return checked;
  const { session, account } = checked;

  if (path === "/api/status" && request.method === "GET") return reply({ csrf: session.csrf, mfaEnabled: account.mfaEnabled }, 200, nonce);
  if (request.method === "POST" && (!sameOrigin(request) || request.headers.get("x-csrf-token") !== session.csrf)) return generic(403, nonce);

  if (path === "/api/logout" && request.method === "POST") {
    sessions.delete(session.id);
    return reply({ ok: true }, 200, nonce, expired("mfa_session"));
  }
  if (path === "/api/identity/request" && request.method === "POST") {
    const old = account.identityChallenge;
    if (old && old.lockedUntil > Date.now()) return reply({ error: "Too many attempts. Wait ten minutes before requesting a new check code." }, 429, nonce);
    account.identityChallenge = { code: "246810", expiresAt: Date.now() + CODE_MS, attempts: 0, lockedUntil: 0, used: false };
    return reply({ deliveryChannel: account.deliveryChannel, deliveredCode: "246810" }, 200, nonce);
  }
  if (path === "/api/identity/verify" && request.method === "POST") {
    const data = await input(request), ch = account.identityChallenge;
    if (!data || !six(data.code) || !ch || ch.used || Date.now() > ch.expiresAt) return reply({ error: "That code is no longer available. Request a new code and try again." }, 400, nonce);
    if (ch.lockedUntil > Date.now()) return reply({ error: "Too many attempts. Wait ten minutes, then request a new code." }, 429, nonce);
    if (data.code !== ch.code) {
      ch.attempts++;
      if (ch.attempts >= MAX_ATTEMPTS) ch.lockedUntil = Date.now() + LOCK_MS;
      return reply({ error: failed(ch.attempts - 1, ch.lockedUntil, "check code") }, 400, nonce);
    }
    ch.used = true;
    session.identityVerified = true;
    return reply({ ok: true, message: "Identity check complete. Next, set up your authenticator." }, 200, nonce);
  }
  if (path === "/api/authenticator/setup" && request.method === "POST") {
    if (!session.identityVerified) return generic(403, nonce);
    const secret = secretBase32();
    account.pendingEncryptedSecret = encrypt(secret);
    const issuer = "Northstar Demo Bank";
    const uri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account.email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    return reply({ secret, provisioningUri: uri, testCode: totp(secret, Math.floor(Date.now() / 30_000)) }, 200, nonce);
  }
  if (path === "/api/authenticator/verify" && request.method === "POST") {
    const data = await input(request);
    if (!session.identityVerified || !data || !six(data.code) || !account.pendingEncryptedSecret) return reply({ error: "Set up your authenticator first, then enter its current six-digit code." }, 400, nonce);
    if (account.authenticatorLockedUntil > Date.now()) return reply({ error: "Too many attempts. Wait ten minutes before trying again." }, 429, nonce);
    let secret: string;
    try { secret = decrypt(account.pendingEncryptedSecret); } catch { return generic(400, nonce); }
    const counter = matchingTotp(secret, data.code);
    if (counter === null || account.usedTotpCounters.has(String(counter))) {
      account.authenticatorAttempts++;
      if (account.authenticatorAttempts >= MAX_ATTEMPTS) account.authenticatorLockedUntil = Date.now() + LOCK_MS;
      return reply({ error: failed(account.authenticatorAttempts - 1, account.authenticatorLockedUntil, "authenticator code") }, 400, nonce);
    }
    account.usedTotpCounters.add(String(counter));
    account.authenticatorAttempts = 0;
    account.encryptedSecret = account.pendingEncryptedSecret;
    account.pendingEncryptedSecret = undefined;
    account.mfaEnabled = true;
    const codes = recoveryCodes();
    account.recoveryVerifiers = makeVerifiers(codes);
    account.recoveryConfirmed = false;
    return reply({ ok: true, recoveryCodes: codes }, 200, nonce);
  }
  if (path === "/api/recovery/regenerate" && request.method === "POST") {
    if (!account.mfaEnabled) return generic(403, nonce);
    const codes = recoveryCodes();
    account.recoveryVerifiers = makeVerifiers(codes);
    account.recoveryConfirmed = false;
    return reply({ recoveryCodes: codes, message: "New recovery codes are ready. Old codes no longer work." }, 200, nonce);
  }
  if (path === "/api/recovery/confirm" && request.method === "POST") {
    if (!account.mfaEnabled) return generic(403, nonce);
    account.recoveryConfirmed = true;
    return reply({ ok: true }, 200, nonce);
  }
  return generic(404, nonce);
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank · Extra security</title>
<style nonce="${nonce}">
:root{--ink:#162330;--blue:#075cba;--line:#c6d3dd;--pale:#edf6ff;--bad:#8b2020;--good:#12643a}*{box-sizing:border-box}body{margin:0;background:#f3f6f8;color:var(--ink);font:18px/1.65 Arial,Verdana,Tahoma,sans-serif;letter-spacing:.025em}.shell{max-width:600px;min-height:100vh;margin:auto;background:#fff;padding:20px 18px 42px}.brand{font-weight:bold;color:var(--blue)}h1{font-size:1.65rem;line-height:1.25;margin:10px 0 2px}h2{font-size:1.35rem;line-height:1.3;margin:0 0 8px}p{margin:7px 0 14px}.hint{font-size:.92rem;color:#53616c}.steps{display:flex;gap:4px;list-style:none;padding:0;margin:20px 0}.steps li{flex:1;text-align:center;font-size:.75rem;line-height:1.25;border-bottom:5px solid var(--line);padding:5px}.steps .on{border-color:var(--blue);color:var(--blue);font-weight:bold}.steps .done{border-color:var(--good);color:var(--good)}.card,.logs{border:1px solid var(--line);border-radius:14px;padding:19px;margin:12px 0}.icon{font-size:2rem;display:block}label{display:block;font-weight:bold;margin-top:16px}input{width:100%;min-height:52px;border:2px solid #80919f;border-radius:9px;padding:10px;font:inherit}.code{font-size:1.35rem;text-align:center;letter-spacing:.18em}button{width:100%;min-height:53px;border:0;border-radius:9px;margin-top:18px;background:var(--blue);color:#fff;font:inherit;font-weight:bold;cursor:pointer}button.secondary{background:#fff;color:#075cba;border:2px solid #075cba;margin-top:10px}button.small{width:auto;min-height:40px;padding:5px 12px;margin:8px 5px 0 0}.notice{background:var(--pale);border-left:5px solid var(--blue);padding:11px;margin:15px 0;border-radius:5px}.error{background:#fff0f0;border-color:var(--bad);color:#781818}.ok{background:#effbf3;border-color:var(--good);color:#124d2d}.secret{overflow-wrap:anywhere;font-family:monospace;background:#f3f6f8;padding:10px;border-radius:7px}.codes{padding:0;list-style:none;display:grid;grid-template-columns:1fr 1fr;gap:7px}.codes li{font:.83rem monospace;background:#f3f6f8;text-align:center;padding:9px 3px;border-radius:6px}.logs{background:#101820;color:#eaf2f8}.logs h2{font-size:1rem}.logs pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.45 monospace;margin:0;max-height:210px;overflow:auto}details{margin-top:17px}summary{color:var(--blue);font-weight:bold;cursor:pointer}@media print{button,.steps,.logs,details{display:none!important}}
</style></head><body><main class="shell"><header><div class="brand">◈ Northstar Bank</div><h1>Set up extra security</h1><p class="hint">Take your time. There is no reading timer.</p></header>
<nav aria-label="Progress"><ol class="steps"><li id="s1" class="on">1<br>Check</li><li id="s2">2<br>App</li><li id="s3">3<br>Save</li></ol></nav>
<section id="screen" aria-live="polite"></section><aside class="logs" aria-label="Simulation logs"><h2>Logs</h2><pre id="logs">Ready. Test values appear here and in the browser console.</pre></aside></main>
<script nonce="${nonce}">(()=>{"use strict";let csrf="",login="",setup=null,codes=[];const screen=document.querySelector("#screen"),logs=document.querySelector("#logs");
function log(label,value){const line=label+(value===undefined?"":": "+(typeof value==="string"?value:JSON.stringify(value)));console.log(line);logs.textContent+="\\n"+line;logs.scrollTop=logs.scrollHeight}
function step(n){[1,2,3].forEach(x=>document.querySelector("#s"+x).className=x===n?"on":x<n?"done":"")}
function el(tag,txt,cls){const x=document.createElement(tag);if(txt)x.textContent=txt;if(cls)x.className=cls;return x}
function btn(txt,cls=""){const b=el("button",txt,cls);b.type="button";return b}
function note(txt,cls=""){return el("div",txt,"notice "+cls)}
function help(){const d=el("details"),s=el("summary","Need help?");d.append(s,el("p","You can retry any step. Nothing has a reading deadline."));return d}
function err(card,e){card.querySelector(".error")?.remove();card.prepend(note(e.message||"Please try again.","error"))}
async function fetchJson(path,opt={}){const h=Object.assign({"Content-Type":"application/json"},opt.headers||{});if(opt.method&&opt.method!=="GET")h["X-CSRF-Token"]=csrf;const r=await fetch(path,Object.assign({credentials:"same-origin",headers:h},opt));const d=await r.json().catch(()=>({error:"Please try again."}));if(!r.ok)throw Error(d.error||"Please try again.");return d}
async function loginToken(){const r=await fetch("/api/login-csrf",{credentials:"same-origin"}),d=await r.json();if(!r.ok)throw Error("Refresh the page and try again.");login=d.token}
function signin(){step(1);screen.replaceChildren();const c=el("section","","card");c.innerHTML="<span class=icon>🔐</span><h2>Sign in to start</h2><p>Use your pre-approved bank sign-in details.</p>";const a=el("label","Email address"),email=document.createElement("input"),b=el("label","Password"),pass=document.createElement("input"),go=btn("Continue");email.type="email";email.autocomplete="username";email.placeholder="Example: marcus@example.test";pass.type="password";pass.autocomplete="current-password";pass.placeholder="Your password";go.onclick=async()=>{try{if(!login)await loginToken();const r=await fetch("/api/authenticate",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-Login-CSRF-Token":login},body:JSON.stringify({email:email.value,password:pass.value})}),d=await r.json();if(!r.ok)throw Error(d.error);csrf=d.csrf;login="";d.next==="complete"?complete():identity()}catch(e){login="";err(c,e)}};c.append(a,email,b,pass,note("Demo account: marcus@example.test · Password: Northstar-54"),go,help());screen.append(c);email.focus()}
function identity(){step(1);screen.replaceChildren();const c=el("section","","card");c.innerHTML="<span class=icon>🪪</span><h2>Check it is you</h2><p>Send a six-digit code to your pre-approved delivery channel.</p>";const send=btn("Send my check code");send.onclick=async()=>{try{const d=await fetchJson("/api/identity/request",{method:"POST",body:"{}"});log("SIMULATED IDENTITY DELIVERY to "+d.deliveryChannel+" — valid code",d.deliveredCode);identityEntry(d.deliveryChannel)}catch(e){err(c,e)}};c.append(note("Example code: 123456"),send,help());screen.append(c)}
function identityEntry(channel){step(1);screen.replaceChildren();const c=el("section","","card");c.innerHTML="<span class=icon>✉️</span><h2>Enter your check code</h2><p>We sent it to your "+channel+". The test code is in Logs.</p>";const l=el("label","Six-digit code"),i=document.createElement("input"),go=btn("Check code"),again=btn("Request a new code","secondary");i.className="code";i.inputMode="numeric";i.autocomplete="one-time-code";i.maxLength=6;i.placeholder="123456";go.onclick=async()=>{try{const d=await fetchJson("/api/identity/verify",{method:"POST",body:JSON.stringify({code:i.value.trim()})});appIntro(d.message)}catch(e){err(c,e)}};again.onclick=identity;c.append(l,i,go,again,help());screen.append(c);i.focus()}
function appIntro(message){step(2);screen.replaceChildren();const c=el("section","","card");c.innerHTML="<span class=icon>📱</span><h2>Set up your authenticator app</h2><p>Use an authenticator app on this phone or another device.</p>";const go=btn("Show setup details");go.onclick=async()=>{try{setup=await fetchJson("/api/authenticator/setup",{method:"POST",body:"{}"});log("SIMULATED AUTHENTICATOR PROVISIONING",{secret:setup.secret,provisioningUri:setup.provisioningUri,validTestCode:setup.testCode});provision()}catch(e){err(c,e)}};c.append(note(message,"ok"),note("Next, copy the setup secret or setup link into your authenticator app."),go,help());screen.append(c)}
function provision(){step(2);screen.replaceChildren();const c=el("section","","card");c.innerHTML="<span class=icon>▦</span><h2>Copy setup details</h2><p>Your authenticator app can scan a QR code or accept a setup link. This test page offers the same information as a copyable link and secret.</p>";const l=el("label","Manual setup secret"),s=el("div","Secret hidden","secret"),show=btn("Show setup secret","small"),copy=btn("Copy setup secret","small"),link=btn("Copy setup link","small"),next=btn("I added it to my app");s.hidden=true;show.onclick=()=>{s.hidden=!s.hidden;show.textContent=s.hidden?"Show setup secret":"Hide setup secret";if(!s.hidden)s.textContent=setup.secret};copy.onclick=async()=>{try{await navigator.clipboard.writeText(setup.secret);copy.textContent="Copied"}catch{copy.textContent="Select the secret to copy"}};link.onclick=async()=>{try{await navigator.clipboard.writeText(setup.provisioningUri);link.textContent="Copied"}catch{link.textContent="Copy is not available"}};next.onclick=authCode;c.append(l,show,s,copy,link,note("The setup link and secret describe the same setup. You never need to type the long link."),next,help());screen.append(c)}
function authCode(){step(2);screen.replaceChildren();const c=el("section","","card");c.innerHTML="<span class=icon>✅</span><h2>Check your authenticator</h2><p>Enter the current six-digit code from your app. The valid mock test value is in Logs.</p>";const l=el("label","Six-digit authenticator code"),i=document.createElement("input"),go=btn("Finish authenticator setup"),retry=btn("Start setup again","secondary");i.className="code";i.inputMode="numeric";i.autocomplete="one-time-code";i.maxLength=6;i.placeholder="123456";go.onclick=async()=>{try{const d=await fetchJson("/api/authenticator/verify",{method:"POST",body:JSON.stringify({code:i.value.trim()})});codes=d.recoveryCodes;log("GENERATED RECOVERY CODES",codes);recovery("Authenticator set up. Save your recovery codes next.")}catch(e){err(c,e)}};retry.onclick=appIntro;c.append(l,i,go,retry,help());screen.append(c);i.focus()}
function recovery(message){step(3);screen.replaceChildren();const c=el("section","","card");c.innerHTML="<span class=icon>🗝️</span><h2>Save your recovery codes</h2><p>Each code works once if you cannot use your authenticator app.</p>";const list=el("ul","","codes"),show=btn("Show recovery codes","small"),copy=btn("Copy all codes","small"),printButton=btn("Print or save as PDF","small"),regen=btn("Make new codes","secondary"),done=btn("I saved my codes");list.hidden=true;codes.forEach(x=>list.append(el("li",x)));show.onclick=()=>{list.hidden=!list.hidden;show.textContent=list.hidden?"Show recovery codes":"Hide recovery codes"};copy.onclick=async()=>{try{await navigator.clipboard.writeText(codes.join("\\n"));copy.textContent="Copied"}catch{copy.textContent="Select the codes to copy"}};printButton.onclick=()=>{list.hidden=false;window.print()};regen.onclick=async()=>{try{const d=await fetchJson("/api/recovery/regenerate",{method:"POST",body:"{}"});codes=d.recoveryCodes;log("REGENERATED RECOVERY CODES",codes);recovery(d.message)}catch(e){err(c,e)}};done.onclick=async()=>{try{await fetchJson("/api/recovery/confirm",{method:"POST",body:"{}"});codes=[];complete()}catch(e){err(c,e)}};c.append(note(message,"ok"),show,list,copy,printButton,note("Keep these private. Do not send them in a message or email."),regen,done,help());screen.append(c)}
function complete(){step(3);screen.replaceChildren();const c=el("section","","card");c.innerHTML="<span class=icon>🎉</span><h2>Extra security is ready</h2><p>Your authenticator and recovery codes are set up.</p>";const out=btn("Sign out","secondary");out.onclick=async()=>{try{await fetchJson("/api/logout",{method:"POST",body:"{}"});csrf="";setup=null;codes=[];await loginToken();signin()}catch(e){err(c,e)}};c.append(note("You can now approve protected actions with your authenticator.","ok"),out,help());screen.append(c)}
loginToken().catch(()=>{}).finally(signin)})();</script></body></html>`;
}

const server = Bun.serve({
  port: 3000,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    const nonce = token(18);
    try {
      const url = new URL(request.url);
      if (request.headers.get("x-forwarded-proto") === "http") {
        return new Response("Secure connection required.", { status: 426, headers: headers(nonce, "text/plain; charset=utf-8") });
      }
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname, nonce);
      if (url.pathname === "/" && request.method === "GET") return new Response(page(nonce), { headers: headers(nonce, "text/html; charset=utf-8") });
      return new Response("Page not found.", { status: 404, headers: headers(nonce, "text/plain; charset=utf-8") });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: headers(nonce, "text/plain; charset=utf-8") });
    }
  },
});
console.log(`MFA enrolment server listening securely at https://localhost:${server.port}`);
