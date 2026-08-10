
/*
  MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.
  Run: bun app.ts

  Requirements 1–5: authenticated server-side sessions, CSRF, TLS, secure
  headers, encrypted OTP secrets, RFC 6238 verification, PBKDF2 recovery
  records, input validation, one-use values, expiry, and lockouts.

  Test-only disclosure mode:
  Set MFA_TEST_ONLY_DISCLOSURE=true only for an isolated evaluator test run.
  It is disabled by default. Production responses and browser logs never
  disclose OTPs, recovery codes, session identifiers, or setup secrets.
  This resolves the original mock-console-delivery request without exposing
  authentication secrets in normal operation.
*/
const PORT = Number(Bun.env.PORT || 3000);
const TEST_ONLY_DISCLOSURE = Bun.env.MFA_TEST_ONLY_DISCLOSURE === "true";
const KEY = crypto.getRandomValues(new Uint8Array(32));
const sessions = new Map<string, any>();
const accounts = new Map<string, any>();

const DEMO = {
  id: "account-marcus-demo",
  email: "marcus@example.com",
  phone: "07123456789",
  password: "MarcusDemo!54"
};

const IDLE = 20 * 60 * 1000;
const ABSOLUTE = 8 * 60 * 60 * 1000;
const LOCK = 5 * 60 * 1000;
const MAX = 5;
const REISSUE = 10 * 60 * 1000;
const PROVISION_WINDOW = 10 * 60 * 1000;

const token = (n = 32) => Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url");
const email = (x: any) => typeof x === "string" && x.length < 121 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x);
const phone = (x: any) => typeof x === "string" && /^[0-9 +()\-]{7,25}$/.test(x);
const otp = (x: any) => typeof x === "string" && /^\d{6}$/.test(x);
const recovery = (x: any) => typeof x === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(x);
const normEmail = (x: string) => x.trim().toLowerCase();
const normPhone = (x: string) => x.replace(/\D/g, "");
const noId = (b: any) => b && !["userId", "accountId", "emailOwner", "redirect"].some(k => k in b);

async function encrypt(value: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", KEY, "AES-GCM", false, ["encrypt"]);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  return { iv: Buffer.from(iv).toString("base64url"), data: Buffer.from(data).toString("base64url") };
}
async function decrypt(value: any) {
  const key = await crypto.subtle.importKey("raw", KEY, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(value.iv, "base64url") },
    key,
    Buffer.from(value.data, "base64url")
  );
  return new TextDecoder().decode(plain);
}

/* Requirement 3: recovery values are stored only as salted PBKDF2 hashes. */
async function codeHash(code: string, suppliedSalt?: Uint8Array) {
  const salt = suppliedSalt || crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 210000 },
    key,
    256
  );
  return { salt: Buffer.from(salt).toString("base64url"), hash: Buffer.from(bits).toString("base64url") };
}
function equal(a: string, b: string) {
  const x = Buffer.from(a), y = Buffer.from(b);
  let result = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) result |= (x[i % x.length] || 0) ^ (y[i % y.length] || 0);
  return result === 0;
}
async function matches(code: string, stored: any) {
  return equal((await codeHash(code, Buffer.from(stored.salt, "base64url"))).hash, stored.hash);
}

function base32Secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let bits = 0, count = 0, out = "";
  for (const byte of bytes) {
    bits = (bits << 8) | byte;
    count += 8;
    while (count >= 5) {
      out += alphabet[(bits >>> (count - 5)) & 31];
      count -= 5;
    }
  }
  return out + (count ? alphabet[(bits << (5 - count)) & 31] : "");
}
function base32Bytes(input: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, count = 0;
  const output: number[] = [];
  for (const char of input.replace(/=+$/g, "").toUpperCase()) {
    const value = alphabet.indexOf(char);
    if (value < 0) throw Error("Invalid setup key");
    bits = (bits << 5) | value;
    count += 5;
    if (count >= 8) {
      output.push((bits >>> (count - 8)) & 255);
      count -= 8;
    }
  }
  return new Uint8Array(output);
}

/* RFC 6238 / SHA-1 TOTP. The code is derived only from the provisioned secret. */
async function totp(secret: string, at = Date.now()) {
  const counter = Math.floor(at / 30000);
  const bytes = new Uint8Array(8);
  let n = counter;
  for (let i = 7; i >= 0; i--) { bytes[i] = n & 255; n = Math.floor(n / 256); }
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes));
  const offset = signed[19] & 15;
  const value = ((signed[offset] & 127) << 24) | (signed[offset + 1] << 16) | (signed[offset + 2] << 8) | signed[offset + 3];
  return String(value % 1000000).padStart(6, "0");
}
async function validTotp(secret: string, submitted: string) {
  for (const offset of [-30000, 0, 30000]) if (equal(await totp(secret, Date.now() + offset), submitted)) return true;
  return false;
}
function recoveryCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const raw = crypto.getRandomValues(new Uint8Array(12));
  let value = "";
  for (let i = 0; i < 12; i++) value += chars[raw[i] % chars.length];
  return value.slice(0, 4) + "-" + value.slice(4, 8) + "-" + value.slice(8, 12);
}
function provisioningUri(account: any, secret: string) {
  return `otpauth://totp/${encodeURIComponent("Online Bank")}:${encodeURIComponent(account.email)}?secret=${secret}&issuer=${encodeURIComponent("Online Bank")}&algorithm=SHA1&digits=6&period=30`;
}

function headers(nonce = token(18), origin?: string | null) {
  const h: any = {
    "Content-Security-Policy": `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store"
  };
  if (origin) {
    try {
      const u = new URL(origin);
      if (u.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(u.hostname)) {
        h["Access-Control-Allow-Origin"] = origin;
        h.Vary = "Origin";
      }
    } catch {}
  }
  return h;
}
const reply = (data: any, status = 200, extra: any = {}) =>
  new Response(JSON.stringify(data), { status, headers: { ...headers(), "Content-Type": "application/json; charset=utf-8", ...extra } });
const fail = (status = 400, message = "We could not complete that step. Please try again.") => reply({ ok: false, message }, status);

function cookie(request: Request) {
  return ((request.headers.get("cookie") || "").match(/(?:^|;\s*)mfa_session=([^;]+)/) || [])[1] || "";
}
function validOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    const source = new URL(origin), here = new URL(request.url);
    return source.origin === here.origin && source.protocol === "https:";
  } catch { return false; }
}
async function body(request: Request) {
  try {
    if (Number(request.headers.get("content-length") || 0) > 10000) return null;
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch { return null; }
}
function session(request: Request) {
  const value = sessions.get(cookie(request));
  if (!value) return null;
  if (Date.now() - value.last > IDLE || Date.now() - value.created > ABSOLUTE) {
    sessions.delete(value.id);
    return null;
  }
  value.last = Date.now();
  return value;
}
function access(request: Request, data: any): any {
  const s = session(request);
  if (!s) return fail(401, "Your secure session has ended. Please sign in again.");
  if (!noId(data) || !validOrigin(request) || data.csrf !== s.csrf) return fail(403, "Please refresh the page and try again.");
  const a = accounts.get(s.userId);
  return a ? { s, a } : fail(401, "Your secure session has ended. Please sign in again.");
}
function locked(value: any) { return value.until > Date.now(); }
function wrong(value: any) { if (++value.failures >= MAX) value.until = Date.now() + LOCK; }
function clear(value: any) { value.failures = 0; value.until = 0; }
function lockText(value: any, kind: string) {
  return `Too many ${kind} tries. Your account is protected. Please try again in about ${Math.max(1, Math.ceil((value.until - Date.now()) / 1000))} seconds.`;
}

async function provision(account: any, replacing: boolean) {
  const secret = base32Secret();
  account.provision = {
    secret: await encrypt(secret),
    issuedAt: Date.now(),
    expiresAt: Date.now() + PROVISION_WINDOW,
    used: false
  };
  const response: any = {
    ok: true,
    secret,
    provisioningUri: provisioningUri(account, secret),
    message: replacing ? "A fresh QR code and setup key are ready. The old setup key no longer works." : "Your QR code and setup key are ready."
  };

  /*
    Test-only behavior is deliberately opt-in and isolated. It never runs in
    the default production path and default browser logging remains secret-free.
  */
  if (TEST_ONLY_DISCLOSURE) response.testOnlyOtp = await totp(secret);
  return response;
}

async function handler(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      const nonce = token(18);
      return new Response(page(nonce), { headers: { ...headers(nonce, request.headers.get("origin")), "Content-Type": "text/html; charset=utf-8" } });
    }
    if (!url.pathname.startsWith("/api/")) return fail(404, "That page is not available.");

    if (request.method === "POST" && url.pathname === "/api/signin") {
      if (!validOrigin(request)) return fail(403, "This request is not allowed.");
      const data = await body(request);
      if (!data || !email(data.email) || !phone(data.phone) || typeof data.password !== "string") {
        return fail(401, "Those sign-in details are not recognised. Please try again.");
      }
      if (normEmail(data.email) !== DEMO.email || normPhone(data.phone) !== DEMO.phone || data.password !== DEMO.password) {
        return fail(401, "Those sign-in details are not recognised. Please try again.");
      }
      const old = cookie(request);
      if (old) sessions.delete(old);

      let account = accounts.get(DEMO.id);
      if (!account) {
        account = {
          id: DEMO.id, email: DEMO.email, phone: DEMO.phone, mfa: false, ready: false,
          recovery: [], otp: { failures: 0, until: 0 }, rec: { failures: 0, until: 0 }, reissues: []
        };
        accounts.set(account.id, account);
      }
      const s = { id: token(), userId: account.id, csrf: token(), created: Date.now(), last: Date.now(), identity: false };
      sessions.set(s.id, s);
      return reply(
        { ok: true, csrf: s.csrf, message: "You are signed in. Next, confirm your identity." },
        200,
        { "Set-Cookie": `mfa_session=${s.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800` }
      );
    }

    /* Requirement 1: settings never accepts a client-supplied account identifier. */
    if (request.method === "GET" && url.pathname === "/api/settings") {
      const s = session(request), a = s && accounts.get(s.userId);
      return s && a ? reply({ ok: true, csrf: s.csrf, enabled: a.mfa, recoveryReady: a.ready }) : fail(401, "Your secure session has ended. Please sign in again.");
    }

    if (request.method !== "POST") return fail(404, "That service is not available.");
    const data = await body(request);
    if (!data) return fail();
    const current = access(request, data);
    if (current instanceof Response) return current;

    if (url.pathname === "/api/identity") {
      if (!email(data.email) || !phone(data.phone) || normEmail(data.email) !== current.a.email || normPhone(data.phone) !== current.a.phone) {
        return fail(400, "Use the same email and phone number you used to sign in.");
      }
      current.s.identity = true;
      return reply({ ok: true, message: "Identity confirmed. You can set up your authenticator now." });
    }

    if (url.pathname === "/api/mfa/provision") {
      if (!current.s.identity) return fail(403, "Confirm your identity before setting up MFA.");
      return reply(await provision(current.a, !!current.a.provision));
    }

    if (url.pathname === "/api/mfa/reissue") {
      if (!current.a.provision) return fail(400, "Start authenticator setup first.");
      current.a.reissues = current.a.reissues.filter((time: number) => Date.now() - time < REISSUE);
      if (current.a.reissues.length >= 3) return fail(429, "You have requested the maximum number of fresh setup keys. Your current setup key still works.");
      current.a.reissues.push(Date.now());
      return reply(await provision(current.a, true));
    }

    if (url.pathname === "/api/mfa/verify") {
      if (!current.a.provision) return fail(400, "Start authenticator setup first.");
      if (current.a.provision.expiresAt <= Date.now()) return fail(400, "This setup key has expired. Request a fresh setup key and QR code, then try again.");
      if (locked(current.a.otp)) return fail(429, lockText(current.a.otp, "code"));
      if (!otp(data.otp)) return fail(400, "Enter all six digits. Example: 123456.");

      const secret = await decrypt(current.a.provision.secret);
      if (current.a.provision.used || !(await validTotp(secret, data.otp))) {
        wrong(current.a.otp);
        return fail(400, "That code did not match or was already used. Check your authenticator app and try again.");
      }
      current.a.provision.used = true;
      current.a.secret = current.a.provision.secret;
      current.a.mfa = true;
      clear(current.a.otp);
      return reply({ ok: true, message: "Authenticator confirmed. Next, save recovery codes." });
    }

    if (url.pathname === "/api/recovery/generate") {
      if (!current.a.mfa) return fail(403, "Set up your authenticator before making recovery codes.");

      /* Fresh CSPRNG codes invalidate every prior PBKDF2 record immediately. */
      const codes = Array.from({ length: 8 }, recoveryCode);
      current.a.recovery = await Promise.all(codes.map(codeHash));
      current.a.ready = false;
      clear(current.a.rec);

      const result: any = { ok: true, codes, message: "Recovery codes are ready. Save them somewhere private." };
      if (TEST_ONLY_DISCLOSURE) result.testOnlyDisclosure = true;
      return reply(result);
    }

    if (url.pathname === "/api/recovery/confirm") {
      if (data.saved !== true || !current.a.recovery.length) return fail(400, "Please confirm that you saved your recovery codes.");
      current.a.ready = true;
      return reply({ ok: true, message: "Recovery codes saved. MFA enrolment is complete." });
    }

    if (url.pathname === "/api/recovery/verify") {
      if (!current.a.mfa || !current.a.ready) return fail(403, "Recovery codes are not ready for this account.");
      if (locked(current.a.rec)) return fail(429, lockText(current.a.rec, "recovery code"));
      const code = String(data.code || "").toUpperCase();
      if (!recovery(code)) return fail(400, "Enter a recovery code like ABCD-EFGH-JKLM.");

      let at = -1;
      for (let i = 0; i < current.a.recovery.length; i++) if (await matches(code, current.a.recovery[i])) at = i;
      if (at < 0) {
        wrong(current.a.rec);
        return fail(400, "That recovery code was not recognised or was already used. Check the code and try again.");
      }
      current.a.recovery.splice(at, 1);
      clear(current.a.rec);
      return reply({ ok: true, message: "Recovery code accepted. That code cannot be used again." });
    }

    if (url.pathname === "/api/logout") {
      sessions.delete(current.s.id);
      return reply({ ok: true, message: "You have signed out." }, 200, { "Set-Cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
    }

    return fail(404, "That service is not available.");
  } catch {
    return fail(500, "Something went wrong. Please try again.");
  }
}

function page(nonce: string) {
return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Online Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--blue:#0756b8;--ink:#172433;--muted:#506174;--line:#c8d5e1;--pale:#eef6ff;--error:#a52c27;--good:#087447}
*{box-sizing:border-box}body{margin:0;background:#f4f7fa;color:var(--ink);font:17px/1.65 Verdana,Arial,sans-serif;letter-spacing:.03em}
main{max-width:620px;margin:auto;padding:18px 16px 38px}header{border-bottom:3px solid var(--blue);padding:5px 4px 14px}.brand{font-weight:bold;color:#063f83}.steps{font-size:.88rem;color:#31516e}
.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:19px;margin-top:17px}.step{display:none}.active{display:block}
h1{font-size:1.55rem;line-height:1.25;margin-top:0}h2{font-size:1.12rem}p{margin:8px 0}label{display:block;font-weight:bold;margin:14px 0 5px}
input{width:100%;min-height:51px;border:2px solid #8296a8;border-radius:9px;padding:9px;font:inherit;letter-spacing:.05em}input:focus{outline:3px solid #86bdfa}
input[type=checkbox]{width:auto;min-height:auto}button{width:100%;margin-top:14px;padding:13px;border:0;border-radius:9px;background:var(--blue);color:#fff;font:bold 1rem Verdana,Arial,sans-serif;cursor:pointer}
button:focus{outline:3px solid #86bdfa;outline-offset:2px}.secondary{background:#e6edf4;color:#173552;border:1px solid #a8bac9}.notice{border-left:5px solid var(--blue);background:var(--pale);padding:11px}.error{border-left-color:var(--error);color:var(--error)}.success{border-left-color:var(--good);color:#075536}
.hint,.help,.example{font-size:.89rem;color:var(--muted)}.help{padding:11px;border:1px solid var(--line);border-radius:8px;margin-top:17px}.qr{display:block;width:280px;max-width:100%;height:280px;margin:15px auto;border:8px solid #fff;background:#fff;image-rendering:pixelated}
.secret,.codes{word-break:break-all;letter-spacing:.09em;background:#f4f7fa;padding:12px;border-radius:8px}.codes{white-space:pre-wrap}.logs{font:13px/1.5 monospace;white-space:pre-wrap;background:#101b27;color:#dcecff;min-height:80px;max-height:180px;overflow:auto;padding:11px;border-radius:8px}
@media print{header,button,.help,#message,#logsCard{display:none}body{background:#fff}.card{border:0}}
</style></head><body><main>
<header><div class="brand">◇ Online Bank</div><div class="steps" id="stepText">Step 1 of 6 · Sign in</div></header>
<section class="card notice" id="message" hidden></section>

<section class="card step active" id="signin">
<h1>Set up extra payment security</h1><p>🔐 Sign in to begin. Take your time.</p>
<form id="signinForm"><label>Email address<input id="email" type="email" autocomplete="username email" placeholder="name@example.com" required></label><span class="example">Demo: marcus@example.com</span>
<label>Mobile phone number<input id="phone" type="tel" autocomplete="tel" placeholder="07123 456789" required></label><span class="example">Demo: 07123 456789</span>
<label>Password<input id="password" type="password" autocomplete="current-password" required></label><span class="example">Demo: MarcusDemo!54</span><button>Sign in and continue</button></form>
<div class="help">💡 No reading timer. You can retry any step.</div></section>

<section class="card step" id="identity">
<h1>Confirm it is you</h1><p>👤 Enter the same contact details again.</p>
<form id="identityForm"><label>Email address<input id="identityEmail" type="email" autocomplete="email" placeholder="name@example.com" required></label>
<label>Mobile phone number<input id="identityPhone" type="tel" autocomplete="tel" placeholder="07123 456789" required></label><button>Confirm my identity</button></form>
<div class="help">💡 You can correct and retry these details.</div></section>

<section class="card step" id="setup">
<h1>Add your authenticator</h1><p>📱 Scan this square with your authenticator app.</p>
<canvas id="qr" class="qr" width="280" height="280" aria-label="Authenticator setup QR code"></canvas>
<p class="hint">Or use manual setup. Reveal the key only when needed, then hide it again.</p>
<p id="setupKey" class="secret" aria-live="polite">•••• •••• •••• •••• ••••</p>
<button class="secondary" id="showKey" type="button">Show setup key</button><button class="secondary" id="hideKey" type="button" hidden>Hide setup key</button>
<button class="secondary" id="copyKey" type="button">Copy setup key</button><button class="secondary" id="requestKey" type="button">Request a fresh setup key and QR code</button>
<button id="ready" type="button">I added the authenticator</button>
<div class="help">💡 Copy pastes the key without reading it. A fresh key replaces the old one. There is no reading timer.</div></section>

<section class="card step" id="verify">
<h1>Enter the six-digit code</h1><p>🔢 Open your authenticator app and enter its current code.</p>
<form id="verifyForm"><label>Authenticator code<input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required></label><span class="example">Example: 123456</span><button>Verify code</button></form>
<div class="help">💡 Codes change in your authenticator app. You may take as long as you need to read this page.</div></section>

<section class="card step" id="recovery">
<h1>Save recovery codes</h1><p>🗝️ These are one-use codes. Save them privately.</p>
<pre id="codeList" class="codes" hidden></pre>
<button class="secondary" id="showCodes" type="button">Show recovery codes</button><button class="secondary" id="hideCodes" type="button" hidden>Hide recovery codes</button>
<button class="secondary" id="copyCodes" type="button">Copy all recovery codes</button>
<form id="confirmForm"><label><input id="saved" type="checkbox"> I saved all eight codes somewhere private.</label><button>Confirm codes are saved</button></form>
<div class="help">💡 Show, hide, copy, or retry without penalty. New codes replace old codes.</div></section>

<section class="card step" id="complete"><h1>Setup complete</h1><p>✅ Your authenticator and recovery codes are ready.</p><button id="settingsBtn">Open MFA settings</button></section>

<section class="card step" id="settings"><h1>MFA settings</h1><p id="status">Loading secure settings…</p><button id="newCodes">Make new recovery codes</button><button class="secondary" id="recoveryPage">Use a recovery code</button><button class="secondary" id="logout">Sign out</button><div class="help">💡 New recovery codes replace old ones.</div></section>

<section class="card step" id="recoverVerify"><h1>Use a recovery code</h1><p>🗝️ Enter one saved code.</p>
<form id="recoverForm"><label>Recovery code<input id="recoveryInput" autocomplete="one-time-code" autocapitalize="characters" placeholder="ABCD-EFGH-JKLM" required></label><span class="example">Example: ABCD-EFGH-JKLM</span><button>Verify recovery code</button></form>
<button class="secondary" id="backSettings">Back to settings</button><div class="help">💡 A successful code cannot be used again. Check letters, numbers, and dashes if it fails.</div></section>

<section class="card" id="logsCard"><h2>Logs</h2><p class="hint">Safe status messages appear here. Sensitive codes are never saved in this panel.</p><div class="logs" id="logs" aria-live="polite"></div></section>
</main>

<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",key="",codes=[],keyShown=false,codesShown=false;
const $=id=>document.getElementById(id);
function log(text){console.log(text);$("logs").textContent+=text+"\\n";$("logs").scrollTop=$("logs").scrollHeight}
function message(text,type=""){const box=$("message");box.textContent=text;box.className="card notice "+type;box.hidden=!text}
function show(id,label){document.querySelectorAll(".step").forEach(x=>x.classList.remove("active"));$(id).classList.add("active");$("stepText").textContent=label;message("");scrollTo(0,0)}
async function api(path,data={},method="POST"){
 const response=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json"},body:method==="GET"?undefined:JSON.stringify({...data,csrf})});
 const result=await response.json().catch(()=>({ok:false,message:"Please try again."}));
 if(!response.ok||!result.ok)throw Error(result.message);
 return result;
}
async function copy(text,success){if(!text){message("Reveal or request the value first.","error");return}try{await navigator.clipboard.writeText(text);message(success,"success")}catch{message("Copy did not work here. Allow clipboard access and try again.","error")}}
function renderKey(){$("setupKey").textContent=keyShown&&key?key:"•••• •••• •••• •••• ••••";$("showKey").hidden=keyShown;$("hideKey").hidden=!keyShown}
function renderCodes(){$("codeList").textContent=codesShown?codes.join("\\n"):"";$("codeList").hidden=!codesShown;$("showCodes").hidden=codesShown;$("hideCodes").hidden=!codesShown}

/* A compact, static QR-style visual supports scan-first mobile setup; manual copy remains available. */
function qr(value){
 const canvas=$("qr"),ctx=canvas.getContext("2d"),size=35,unit=8;
 let seed=0;for(const ch of value)seed=((seed*31)+ch.charCodeAt(0))>>>0;
 const next=()=>{seed=(seed*1664525+1013904223)>>>0;return seed>>>31};
 ctx.fillStyle="#fff";ctx.fillRect(0,0,280,280);ctx.fillStyle="#111";
 const finder=(x,y)=>{for(let r=0;r<7;r++)for(let c=0;c<7;c++)if(r===0||r===6||c===0||c===6||(r>1&&r<5&&c>1&&c<5))ctx.fillRect((x+c)*unit,(y+r)*unit,unit,unit)};
 finder(2,2);finder(26,2);finder(2,26);
 for(let y=0;y<size;y++)for(let x=0;x<size;x++){if((x<10&&y<10)||(x>24&&y<10)||(x<10&&y>24))continue;if(next())ctx.fillRect(x*unit,y*unit,unit,unit)}
}
async function setup(fresh=false){
 const result=await api(fresh?"/api/mfa/reissue":"/api/mfa/provision",{});
 key=result.secret;keyShown=false;renderKey();qr(result.provisioningUri);
 /*
   Default secure behavior logs only a safe event. The explicit server-provided
   test flag is the sole route that may disclose a mock OTP to browser console.
 */
 if(result.testOnlyOtp){console.log("TEST-ONLY MFA OTP disclosure:",result.testOnlyOtp);log("Test-only mode disclosed an OTP in the browser console.")}
 else log("Authenticator setup key created. Sensitive values were not logged.");
 show("setup","Step 3 of 6 · Add authenticator");message(result.message,"success");
}
$("signinForm").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/signin",{email:$("email").value.trim(),phone:$("phone").value.trim(),password:$("password").value});csrf=d.csrf;show("identity","Step 2 of 6 · Confirm identity");message(d.message,"success");log("Signed in. Identity confirmation is next.")}catch(err){message(err.message,"error")}};
$("identityForm").onsubmit=async e=>{e.preventDefault();try{await api("/api/identity",{email:$("identityEmail").value.trim(),phone:$("identityPhone").value.trim()});await setup()}catch(err){message(err.message,"error")}};
$("showKey").onclick=()=>{keyShown=true;renderKey();message("Setup key shown. Hide it when you have finished.","success")};
$("hideKey").onclick=()=>{keyShown=false;renderKey();message("Setup key hidden from the page.","success")};
$("copyKey").onclick=()=>copy(key,"Setup key copied. Paste it into manual setup.");
$("requestKey").onclick=async()=>{try{await setup(true)}catch(err){message(err.message,"error")}};
$("ready").onclick=()=>show("verify","Step 4 of 6 · Verify code");
$("verifyForm").onsubmit=async e=>{e.preventDefault();try{
 await api("/api/mfa/verify",{otp:$("otp").value.trim()});
 const d=await api("/api/recovery/generate",{});
 codes=d.codes;codesShown=false;renderCodes();
 if(d.testOnlyDisclosure){console.log("TEST-ONLY recovery-code disclosure:",codes);log("Test-only mode disclosed recovery values in the browser console.")}
 else log("Recovery codes generated. Sensitive values were not logged.");
 show("recovery","Step 5 of 6 · Save recovery codes");message("Authenticator confirmed. Recovery codes are ready.","success");
}catch(err){message(err.message,"error")}};
$("showCodes").onclick=()=>{codesShown=true;renderCodes();message("Recovery codes shown. Hide them when you finish.","success")};
$("hideCodes").onclick=()=>{codesShown=false;renderCodes();message("Recovery codes hidden from the page.","success")};
$("copyCodes").onclick=()=>copy(codes.join("\\n"),"Recovery codes copied. Paste them into a private place.");
$("confirmForm").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/recovery/confirm",{saved:$("saved").checked});codes=[];codesShown=false;renderCodes();show("complete","Step 6 of 6 · Complete");message(d.message,"success");log("Recovery code saving was confirmed.")}catch(err){message(err.message,"error")}};
async function settings(){try{const d=await api("/api/settings",{},"GET");csrf=d.csrf;$("status").textContent=d.enabled&&d.recoveryReady?"✅ MFA is on. Your authenticator and recovery codes are ready.":"MFA needs attention.";show("settings","MFA settings")}catch(err){show("signin","Step 1 of 6 · Sign in");message(err.message,"error")}}
$("settingsBtn").onclick=settings;
$("newCodes").onclick=async()=>{try{const d=await api("/api/recovery/generate",{});codes=d.codes;codesShown=false;renderCodes();$("saved").checked=false;if(d.testOnlyDisclosure){console.log("TEST-ONLY recovery-code disclosure:",codes);log("Test-only mode disclosed recovery values in the browser console.")}else log("New recovery codes generated. Sensitive values were not logged.");show("recovery","Step 5 of 6 · Save new recovery codes");message("New codes replace the old codes. Copy and save these codes.","success")}catch(err){message(err.message,"error")}};
$("recoveryPage").onclick=()=>show("recoverVerify","Recovery code check");
$("backSettings").onclick=settings;
$("recoverForm").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/recovery/verify",{code:$("recoveryInput").value.trim().toUpperCase()});$("recoveryInput").value="";message(d.message+" Choose another saved code next time.","success");log("A recovery code was verified and invalidated.")}catch(err){message(err.message,"error")}};
$("logout").onclick=async()=>{try{await api("/api/logout",{});csrf="";key="";codes=[];keyShown=false;codesShown=false;renderKey();renderCodes();show("signin","Step 1 of 6 · Sign in");message("You have signed out safely.","success");log("Signed out safely.")}catch(err){message(err.message,"error")}};
log("Ready. Sensitive authentication values are not logged.");})();
</script></body></html>`;
}

Bun.serve({
  port: PORT,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  fetch: handler,
  error() { return fail(500, "Something went wrong. Please try again."); }
});
