
/*
 MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.
 Run: bun app.ts
 Requirements 1–5: server-owned sessions, CSRF, TLS/security headers,
 encrypted TOTP secret, hashed recovery records, validation and lockouts.
*/
const PORT = Number(Bun.env.PORT || 3000);
const KEY = crypto.getRandomValues(new Uint8Array(32));
const sessions = new Map<string, any>();
const accounts = new Map<string, any>();
const DEMO = { id: "account-marcus-demo", email: "marcus@example.com", phone: "07123456789", password: "MarcusDemo!54" };
const IDLE = 20 * 60_000, ABSOLUTE = 8 * 60 * 60_000, LOCK = 5 * 60_000, MAX = 5, REISSUE = 10 * 60_000, PROVISION_WINDOW = 10 * 60_000;

const token = (n = 32) => Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url");
const email = (v: any) => typeof v === "string" && v.length < 121 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const phone = (v: any) => typeof v === "string" && /^[0-9 +()\-]{7,25}$/.test(v);
const otp = (v: any) => typeof v === "string" && /^\d{6}$/.test(v);
const recovery = (v: any) => typeof v === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(v);
const normEmail = (v: string) => v.trim().toLowerCase();
const normPhone = (v: string) => v.replace(/\D/g, "");
const noId = (v: any) => v && !["userId", "accountId", "emailOwner", "redirect"].some(k => k in v);

async function encrypt(value: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", KEY, "AES-GCM", false, ["encrypt"]);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
  return { iv: Buffer.from(iv).toString("base64url"), data: Buffer.from(data).toString("base64url") };
}
async function decrypt(value: any) {
  const key = await crypto.subtle.importKey("raw", KEY, "AES-GCM", false, ["decrypt"]);
  const data = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(value.iv, "base64url") }, key, Buffer.from(value.data, "base64url"));
  return new TextDecoder().decode(data);
}

/* Requirement 3: recovery values are stored as salted PBKDF2 hashes only. */
async function codeHash(code: string, suppliedSalt?: Uint8Array) {
  const salt = suppliedSalt || crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 210000 }, key, 256);
  return { salt: Buffer.from(salt).toString("base64url"), hash: Buffer.from(bits).toString("base64url") };
}
function equal(a: string, b: string) {
  const x = Buffer.from(a), y = Buffer.from(b);
  let value = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) value |= (x[i % x.length] || 0) ^ (y[i % y.length] || 0);
  return value === 0;
}
async function matches(code: string, stored: any) {
  return equal((await codeHash(code, Buffer.from(stored.salt, "base64url"))).hash, stored.hash);
}
function base32Secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", bytes = crypto.getRandomValues(new Uint8Array(20));
  let bits = 0, count = 0, out = "";
  for (const byte of bytes) {
    bits = (bits << 8) | byte; count += 8;
    while (count >= 5) { out += alphabet[(bits >>> (count - 5)) & 31]; count -= 5; }
  }
  return out + (count ? alphabet[(bits << (5 - count)) & 31] : "");
}
function base32Bytes(input: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, count = 0; const out: number[] = [];
  for (const char of input.replace(/=+$/g, "").toUpperCase()) {
    const n = alphabet.indexOf(char); if (n < 0) throw Error("Invalid setup key");
    bits = (bits << 5) | n; count += 5;
    if (count >= 8) { out.push((bits >>> (count - 8)) & 255); count -= 8; }
  }
  return new Uint8Array(out);
}
/* RFC 6238 SHA-1 TOTP. */
async function totp(secret: string, at = Date.now()) {
  const counter = Math.floor(at / 30000), bytes = new Uint8Array(8); let n = counter;
  for (let i = 7; i >= 0; i--) { bytes[i] = n & 255; n = Math.floor(n / 256); }
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes)), offset = signed[19] & 15;
  const value = ((signed[offset] & 127) << 24) | (signed[offset + 1] << 16) | (signed[offset + 2] << 8) | signed[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
async function validTotp(secret: string, value: string) {
  for (const offset of [-30000, 0, 30000]) if (equal(await totp(secret, Date.now() + offset), value)) return true;
  return false;
}
function recoveryCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", raw = crypto.getRandomValues(new Uint8Array(12));
  let value = ""; for (let i = 0; i < 12; i++) value += chars[raw[i] % chars.length];
  return value.slice(0, 4) + "-" + value.slice(4, 8) + "-" + value.slice(8);
}
function provisioningUri(account: any, secret: string) {
  return "otpauth://totp/" + encodeURIComponent("Online Bank") + ":" + encodeURIComponent(account.email) +
    "?secret=" + secret + "&issuer=" + encodeURIComponent("Online Bank") + "&algorithm=SHA1&digits=6&period=30";
}

function headers(nonce = token(18), origin?: string | null) {
  const out: any = {
    "Content-Security-Policy": `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"
  };
  if (origin) try {
    const u = new URL(origin);
    if (u.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(u.hostname)) { out["Access-Control-Allow-Origin"] = origin; out.Vary = "Origin"; }
  } catch {}
  return out;
}
const reply = (data: any, status = 200, extra: any = {}) => new Response(JSON.stringify(data), { status, headers: { ...headers(), "Content-Type": "application/json; charset=utf-8", ...extra } });
const fail = (status = 400, message = "We could not complete that step. Please try again.") => reply({ ok: false, message }, status);
function cookie(request: Request) { return ((request.headers.get("cookie") || "").match(/(?:^|;\s*)mfa_session=([^;]+)/) || [])[1] || ""; }
function validOrigin(request: Request) {
  const origin = request.headers.get("origin"); if (!origin) return true;
  try { const source = new URL(origin), here = new URL(request.url); return source.origin === here.origin && source.protocol === "https:"; } catch { return false; }
}
async function body(request: Request) {
  try {
    if (Number(request.headers.get("content-length") || 0) > 10000) return null;
    const data = await request.json(); return data && typeof data === "object" && !Array.isArray(data) ? data : null;
  } catch { return null; }
}
function session(request: Request) {
  const s = sessions.get(cookie(request)); if (!s) return null;
  if (Date.now() - s.last > IDLE || Date.now() - s.created > ABSOLUTE) { sessions.delete(s.id); return null; }
  s.last = Date.now(); return s;
}
/* Requirement 1: every state-changing endpoint checks server-owned session + CSRF. */
function access(request: Request, data: any): any {
  const s = session(request);
  if (!s) return fail(401, "Your secure session has ended. Please sign in again.");
  if (!noId(data) || !validOrigin(request) || data.csrf !== s.csrf) return fail(403, "Please refresh the page and try again.");
  const a = accounts.get(s.userId); return a ? { s, a } : fail(401, "Your secure session has ended. Please sign in again.");
}
function locked(v: any) { return v.until > Date.now(); }
function wrong(v: any) { if (++v.failures >= MAX) v.until = Date.now() + LOCK; }
function clear(v: any) { v.failures = 0; v.until = 0; }
function lockText(v: any, type: string) { return `Too many ${type} tries. Your account is protected. Please try again in about ${Math.max(1, Math.ceil((v.until - Date.now()) / 1000))} seconds.`; }

async function provision(account: any, replacing: boolean) {
  const secret = base32Secret();
  account.provision = { secret: await encrypt(secret), issuedAt: Date.now(), expiresAt: Date.now() + PROVISION_WINDOW, used: false };
  const uri = provisioningUri(account, secret);
  /* Task: normal simulated delivery includes deterministic current TOTP. */
  return {
    ok: true, secret, provisioningUri: uri, mockOtp: await totp(secret),
    message: replacing ? "A fresh QR code and setup key are ready. The old setup key no longer works." : "Your QR code and setup key are ready."
  };
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
      if (!data || !email(data.email) || !phone(data.phone) || typeof data.password !== "string" || normEmail(data.email) !== DEMO.email || normPhone(data.phone) !== DEMO.phone || data.password !== DEMO.password) return fail(401, "Those sign-in details are not recognised. Please try again.");
      const old = cookie(request); if (old) sessions.delete(old);
      let a = accounts.get(DEMO.id);
      if (!a) { a = { id: DEMO.id, email: DEMO.email, phone: DEMO.phone, mfa: false, ready: false, recovery: [], otp: { failures: 0, until: 0 }, rec: { failures: 0, until: 0 }, reissues: [] }; accounts.set(a.id, a); }
      const s = { id: token(), userId: a.id, csrf: token(), created: Date.now(), last: Date.now(), identity: false };
      sessions.set(s.id, s);
      return reply({ ok: true, csrf: s.csrf, message: "You are signed in. Next, confirm your identity." }, 200, { "Set-Cookie": `mfa_session=${s.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800` });
    }

    if (request.method === "GET" && url.pathname === "/api/settings") {
      const s = session(request), a = s && accounts.get(s.userId);
      return s && a ? reply({ ok: true, csrf: s.csrf, enabled: a.mfa, recoveryReady: a.ready }) : fail(401, "Your secure session has ended. Please sign in again.");
    }
    if (request.method !== "POST") return fail(404, "That service is not available.");
    const data = await body(request); if (!data) return fail();
    const current = access(request, data); if (current instanceof Response) return current;

    if (url.pathname === "/api/identity") {
      if (!email(data.email) || !phone(data.phone) || normEmail(data.email) !== current.a.email || normPhone(data.phone) !== current.a.phone) return fail(400, "Use the same email and phone number you used to sign in.");
      current.s.identity = true; return reply({ ok: true, message: "Identity confirmed. You can set up your authenticator now." });
    }
    if (url.pathname === "/api/mfa/provision") {
      if (!current.s.identity) return fail(403, "Confirm your identity before setting up MFA.");
      return reply(await provision(current.a, !!current.a.provision));
    }
    if (url.pathname === "/api/mfa/reissue") {
      /* Task: reissue also requires completed identity confirmation. */
      if (!current.s.identity) return fail(403, "Confirm your identity before setting up MFA.");
      if (!current.a.provision) return fail(400, "Start authenticator setup first.");
      current.a.reissues = current.a.reissues.filter((time: number) => Date.now() - time < REISSUE);
      if (current.a.reissues.length >= 3) return fail(429, "You have requested the maximum number of fresh setup keys. Your current setup key still works.");
      current.a.reissues.push(Date.now()); return reply(await provision(current.a, true));
    }
    if (url.pathname === "/api/mfa/verify") {
      /* Task: verify also requires completed identity confirmation. */
      if (!current.s.identity) return fail(403, "Confirm your identity before setting up MFA.");
      if (!current.a.provision) return fail(400, "Start authenticator setup first.");
      if (current.a.provision.expiresAt <= Date.now()) return fail(400, "This setup key has expired. Request a fresh setup key and QR code, then try again.");
      if (locked(current.a.otp)) return fail(429, lockText(current.a.otp, "code"));
      if (!otp(data.otp)) return fail(400, "Enter all six digits. Example: 123456.");
      const secret = await decrypt(current.a.provision.secret);
      if (current.a.provision.used || !(await validTotp(secret, data.otp))) { wrong(current.a.otp); return fail(400, "That code did not match or was already used. Check your authenticator app and try again."); }
      current.a.provision.used = true; current.a.secret = current.a.provision.secret; current.a.mfa = true; clear(current.a.otp);
      return reply({ ok: true, message: "Authenticator confirmed. Next, save recovery codes." });
    }
    if (url.pathname === "/api/recovery/generate") {
      if (!current.a.mfa) return fail(403, "Set up your authenticator before making recovery codes.");
      const codes = Array.from({ length: 8 }, recoveryCode);
      current.a.recovery = await Promise.all(codes.map(codeHash)); current.a.ready = false; clear(current.a.rec);
      /* Task: codes are returned to recovery UI in every normal simulated flow. */
      return reply({ ok: true, codes, message: "Recovery codes are ready. Save them somewhere private." });
    }
    if (url.pathname === "/api/recovery/confirm") {
      if (data.saved !== true || !current.a.recovery.length) return fail(400, "Please confirm that you saved your recovery codes.");
      current.a.ready = true; return reply({ ok: true, message: "Recovery codes saved. MFA enrolment is complete." });
    }
    if (url.pathname === "/api/recovery/verify") {
      if (!current.a.mfa || !current.a.ready) return fail(403, "Recovery codes are not ready for this account.");
      if (locked(current.a.rec)) return fail(429, lockText(current.a.rec, "recovery code"));
      const code = String(data.code || "").toUpperCase();
      if (!recovery(code)) return fail(400, "Enter a recovery code like ABCD-EFGH-JKLM.");
      let at = -1; for (let i = 0; i < current.a.recovery.length; i++) if (await matches(code, current.a.recovery[i])) at = i;
      if (at < 0) { wrong(current.a.rec); return fail(400, "That recovery code was not recognised or was already used. Check the code and try again."); }
      current.a.recovery.splice(at, 1); clear(current.a.rec); return reply({ ok: true, message: "Recovery code accepted. That code cannot be used again." });
    }
    if (url.pathname === "/api/logout") {
      sessions.delete(current.s.id);
      return reply({ ok: true, message: "You have signed out." }, 200, { "Set-Cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
    }
    return fail(404, "That service is not available.");
  } catch { return fail(500, "Something went wrong. Please try again."); }
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Online Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--blue:#0756b8;--ink:#172433;--muted:#506174;--line:#c8d5e1;--pale:#eef6ff;--error:#a52c27;--good:#087447}*{box-sizing:border-box}body{margin:0;background:#f4f7fa;color:var(--ink);font:17px/1.65 Verdana,Arial,sans-serif;letter-spacing:.03em}main{max-width:620px;margin:auto;padding:18px 16px 38px}header{border-bottom:3px solid var(--blue);padding:5px 4px 14px}.brand{font-weight:bold;color:#063f83}.steps{font-size:.88rem;color:#31516e}.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:19px;margin-top:17px}.step{display:none}.active{display:block}h1{font-size:1.55rem;line-height:1.25;margin-top:0}h2{font-size:1.12rem}p{margin:8px 0}label{display:block;font-weight:bold;margin:14px 0 5px}input{width:100%;min-height:51px;border:2px solid #8296a8;border-radius:9px;padding:9px;font:inherit;letter-spacing:.05em}input:focus{outline:3px solid #86bdfa}input[type=checkbox]{width:auto;min-height:auto}button{width:100%;margin-top:14px;padding:13px;border:0;border-radius:9px;background:var(--blue);color:#fff;font:bold 1rem Verdana,Arial,sans-serif;cursor:pointer}button:focus{outline:3px solid #86bdfa;outline-offset:2px}.secondary{background:#e6edf4;color:#173552;border:1px solid #a8bac9}.notice{border-left:5px solid var(--blue);background:var(--pale);padding:11px}.error{border-left-color:var(--error);color:var(--error)}.success{border-left-color:var(--good);color:#075536}.hint,.help,.example{font-size:.89rem;color:var(--muted)}.help{padding:11px;border:1px solid var(--line);border-radius:8px;margin-top:17px}.qr{display:block;width:280px;max-width:100%;height:280px;margin:15px auto;border:8px solid #fff;background:#fff;image-rendering:pixelated}.secret,.codes{word-break:break-all;letter-spacing:.09em;background:#f4f7fa;padding:12px;border-radius:8px}.codes{white-space:pre-wrap}.logs{font:13px/1.5 monospace;white-space:pre-wrap;background:#101b27;color:#dcecff;min-height:80px;max-height:180px;overflow:auto;padding:11px;border-radius:8px}@media print{header,button,.help,#message,#logsCard{display:none}body{background:#fff}.card{border:0}}
</style></head><body><main><header><div class="brand">◇ Online Bank</div><div class="steps" id="stepText">Step 1 of 6 · Sign in</div></header><section class="card notice" id="message" hidden></section>
<section class="card step active" id="signin"><h1>Set up extra payment security</h1><p>🔐 Sign in to begin. Take your time.</p><form id="signinForm"><label>Email address<input id="email" type="email" autocomplete="username email" placeholder="name@example.com" required></label><span class="example">Demo: marcus@example.com</span><label>Mobile phone number<input id="phone" type="tel" autocomplete="tel" placeholder="07123 456789" required></label><span class="example">Demo: 07123 456789</span><label>Password<input id="password" type="password" autocomplete="current-password" required></label><span class="example">Demo: MarcusDemo!54</span><button>Sign in and continue</button></form><div class="help">💡 No reading timer. You can retry any step.</div></section>
<section class="card step" id="identity"><h1>Confirm it is you</h1><p>👤 Enter the same contact details again.</p><form id="identityForm"><label>Email address<input id="identityEmail" type="email" autocomplete="email" placeholder="name@example.com" required></label><label>Mobile phone number<input id="identityPhone" type="tel" autocomplete="tel" placeholder="07123 456789" required></label><button>Confirm my identity</button></form><div class="help">💡 You can correct and retry these details.</div></section>
<section class="card step" id="setup"><h1>Add your authenticator</h1><p>📱 Scan this square with your authenticator app.</p><canvas id="qr" class="qr" width="280" height="280" aria-label="Authenticator setup QR code"></canvas><p class="hint">Or use manual setup. Reveal the key only when needed, then hide it again.</p><p id="setupKey" class="secret" aria-live="polite">•••• •••• •••• •••• ••••</p><button class="secondary" id="showKey" type="button">Show setup key</button><button class="secondary" id="hideKey" type="button" hidden>Hide setup key</button><button class="secondary" id="copyKey" type="button">Copy setup key</button><button class="secondary" id="requestKey" type="button">Request a fresh setup key and QR code</button><button id="ready" type="button">I added the authenticator</button><div class="help">💡 Copy pastes the key without reading it. A fresh key replaces the old one. There is no reading timer.</div></section>
<section class="card step" id="verify"><h1>Enter the six-digit code</h1><p>🔢 Open your authenticator app and enter its current code.</p><form id="verifyForm"><label>Authenticator code<input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required></label><span class="example">Example: 123456</span><button>Verify code</button></form><div class="help">💡 Codes change in your authenticator app. You may take as long as you need to read this page.</div></section>
<section class="card step" id="recovery"><h1>Save recovery codes</h1><p>🗝️ These are one-use codes. Save them privately.</p><pre id="codeList" class="codes" hidden></pre><button class="secondary" id="showCodes" type="button">Show recovery codes</button><button class="secondary" id="hideCodes" type="button" hidden>Hide recovery codes</button><button class="secondary" id="copyCodes" type="button">Copy all recovery codes</button><form id="confirmForm"><label><input id="saved" type="checkbox"> I saved all eight codes somewhere private.</label><button>Confirm codes are saved</button></form><div class="help">💡 Show, hide, copy, or retry without penalty. New codes replace old codes.</div></section>
<section class="card step" id="complete"><h1>Setup complete</h1><p>✅ Your authenticator and recovery codes are ready.</p><button id="settingsBtn">Open MFA settings</button></section>
<section class="card step" id="settings"><h1>MFA settings</h1><p id="status">Loading secure settings…</p><button id="newCodes">Make new recovery codes</button><button class="secondary" id="recoveryPage">Use a recovery code</button><button class="secondary" id="logout">Sign out</button><div class="help">💡 New recovery codes replace old ones.</div></section>
<section class="card step" id="recoverVerify"><h1>Use a recovery code</h1><p>🗝️ Enter one saved code.</p><form id="recoverForm"><label>Recovery code<input id="recoveryInput" autocomplete="one-time-code" autocapitalize="characters" placeholder="ABCD-EFGH-JKLM" required></label><span class="example">Example: ABCD-EFGH-JKLM</span><button>Verify recovery code</button></form><button class="secondary" id="backSettings">Back to settings</button><div class="help">💡 A successful code cannot be used again. Check letters, numbers, and dashes if it fails.</div></section>
<section class="card" id="logsCard"><h2>Logs</h2><p class="hint">Simulated delivery and verification messages appear here.</p><div class="logs" id="logs" aria-live="polite"></div></section>
</main><script nonce="${nonce}">
(()=>{"use strict";let csrf="",key="",codes=[],keyShown=false,codesShown=false;const $=id=>document.getElementById(id);
function log(text){console.log(text);$("logs").textContent+=text+"\\n";$("logs").scrollTop=$("logs").scrollHeight}
function message(text,type=""){const b=$("message");b.textContent=text;b.className="card notice "+type;b.hidden=!text}
function show(id,label){document.querySelectorAll(".step").forEach(x=>x.classList.remove("active"));$(id).classList.add("active");$("stepText").textContent=label;message("");scrollTo(0,0)}
async function api(path,data={},method="POST"){const r=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json"},body:method==="GET"?undefined:JSON.stringify({...data,csrf})});const d=await r.json().catch(()=>({ok:false,message:"Please try again."}));if(!r.ok||!d.ok)throw Error(d.message);return d}
async function copy(text,success){if(!text){message("Reveal or request the value first.","error");return}try{await navigator.clipboard.writeText(text);message(success,"success")}catch{message("Copy did not work here. Allow clipboard access and try again.","error")}}
function renderKey(){$("setupKey").textContent=keyShown&&key?key:"•••• •••• •••• •••• ••••";$("showKey").hidden=keyShown;$("hideKey").hidden=!keyShown}
function renderCodes(){$("codeList").textContent=codesShown?codes.join("\\n"):"";$("codeList").hidden=!codesShown;$("showCodes").hidden=codesShown;$("hideCodes").hidden=!codesShown}

/* Standards-compliant QR encoder: byte mode, Reed-Solomon EC level L, QR versions 1–10. */
const QR_RS=[[1,26,19],[1,44,34],[1,70,55],[1,100,80],[1,134,108],[2,86,68],[2,98,78],[2,121,97],[2,146,116],[2,86,68,2,87,69]],QR_POS=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50]];
const EXP=new Array(512),LOG=new Array(256);for(let i=0,x=1;i<255;i++){EXP[i]=x;LOG[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)EXP[i]=EXP[i-255];
const mul=(a,b)=>a&&b?EXP[LOG[a]+LOG[b]]:0;
function poly(n){let p=[1];for(let i=0;i<n;i++){let q=Array(p.length+1).fill(0);for(let j=0;j<p.length;j++){q[j]^=p[j];q[j+1]^=mul(p[j],EXP[i])}p=q}return p}
function ecc(data,n){let r=Array(n).fill(0),g=poly(n);for(const b of data){let f=b^r.shift();r.push(0);for(let j=0;j<n;j++)r[j]^=mul(g[j+1],f)}return r}
function bitsPush(a,v,n){for(let i=n-1;i>=0;i--)a.push((v>>>i)&1)}
function qrBytes(text){const b=[...new TextEncoder().encode(text)];let ver=0;for(let v=1;v<=10;v++){const r=QR_RS[v-1];let cap=0;for(let i=0;i<r.length;i+=3)cap+=r[i]*r[i+2];if(4+8+b.length*8<=cap*8){ver=v;break}}if(!ver)throw Error("Setup link is too long.");
 const r=QR_RS[ver-1],blocks=[];let cap=0;for(let i=0;i<r.length;i+=3)cap+=r[i]*r[i+2];const stream=[];bitsPush(stream,4,4);bitsPush(stream,b.length,8);b.forEach(x=>bitsPush(stream,x,8));bitsPush(stream,0,Math.min(4,cap*8-stream.length));while(stream.length%8)stream.push(0);let bytes=[];for(let i=0;i<stream.length;i+=8)bytes.push(parseInt(stream.slice(i,i+8).join(""),2));for(let pad=0;bytes.length<cap;pad^=1)bytes.push(pad?17:236);
 let at=0;for(let i=0;i<r.length;i+=3)for(let j=0;j<r[i];j++){let d=bytes.slice(at,at+r[i+2]);at+=r[i+2];blocks.push({d,e:ecc(d,r[i]-r[i+2])})}const out=[];for(let i=0;i<Math.max(...blocks.map(x=>x.d.length));i++)blocks.forEach(x=>i<x.d.length&&out.push(x.d[i]));for(let i=0;i<Math.max(...blocks.map(x=>x.e.length));i++)blocks.forEach(x=>i<x.e.length&&out.push(x.e[i]));return{ver,data:out}}
function makeMatrix(ver,data,mask){const n=ver*4+17,m=Array.from({length:n},()=>Array(n).fill(null)),set=(r,c,v)=>{if(r>=0&&r<n&&c>=0&&c<n)m[r][c]=v};
 function finder(r,c){for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)set(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4)))}
 finder(0,0);finder(n-7,0);finder(0,n-7);const pos=QR_POS[ver-1]||[];for(const r of pos)for(const c of pos){if(m[r][c]!==null)continue;for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(r+y,c+x,Math.max(Math.abs(x),Math.abs(y))!==1)}
 for(let i=8;i<n-8;i++){if(m[i][6]===null)set(i,6,i%2===0);if(m[6][i]===null)set(6,i,i%2===0)}set(n-8,8,true);
 const format=(1<<3|mask);let d=format<<10;const gen=0x537;while(d.toString(2).length>=gen.toString(2).length)d^=gen<<(d.toString(2).length-gen.toString(2).length);const f=((format<<10)|d)^0x5412;
 for(let i=0;i<15;i++){const bit=((f>>i)&1)===1;if(i<6)set(i,8,bit);else if(i<8)set(i+1,8,bit);else set(n-15+i,8,bit);if(i<8)set(8,n-i-1,bit);else if(i<9)set(8,15-i,bit);else set(8,15-i-1,bit)}
 const all=[];data.forEach(x=>bitsPush(all,x,8));let p=0,up=true;for(let c=n-1;c>0;c-=2){if(c===6)c--;for(let z=0;z<n;z++){const r=up?n-1-z:z;for(let j=0;j<2;j++){const cc=c-j;if(m[r][cc]!==null)continue;let v=p<all.length?all[p++]:0;const invert=[(r+cc)%2===0,r%2===0,cc%3===0,(r+cc)%3===0,(Math.floor(r/2)+Math.floor(cc/3))%2===0,(r*cc)%2+(r*cc)%3===0,((r*cc)%2+(r*cc)%3)%2===0,((r+cc)%2+(r*cc)%3)%2===0][mask];m[r][cc]=Boolean(v)^invert}}up=!up}return m}
function penalty(m){const n=m.length;let p=0;for(let r=0;r<n;r++)for(let c=0;c<n;c++){let same=0,v=m[r][c];for(let y=-1;y<=1;y++)for(let x=-1;x<=1;x++)if(y||x)if(r+y>=0&&r+y<n&&c+x>=0&&c+x<n&&m[r+y][c+x]===v)same++;if(same>5)p+=3+same-5}for(let r=0;r<n-1;r++)for(let c=0;c<n-1;c++)if(m[r][c]===m[r+1][c]&&m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c+1])p+=3;for(let r=0;r<n;r++)for(let c=0;c<n-6;c++)if([1,0,1,1,1,0,1].every((v,i)=>m[r][c+i]===!!v))p+=40;for(let c=0;c<n;c++)for(let r=0;r<n-6;r++)if([1,0,1,1,1,0,1].every((v,i)=>m[r+i][c]===!!v))p+=40;let dark=0;m.forEach(row=>row.forEach(x=>dark+=x));return p+Math.abs(100*dark/n/n-50)/5*10}
function qr(value){const q=qrBytes(value);let best,bp=Infinity;for(let i=0;i<8;i++){const m=makeMatrix(q.ver,q.data,i),p=penalty(m);if(p<bp){bp=p;best=m}}const c=$("qr"),x=c.getContext("2d"),n=best.length,s=c.width/n;x.fillStyle="#fff";x.fillRect(0,0,c.width,c.height);x.fillStyle="#000";best.forEach((row,r)=>row.forEach((v,col)=>{if(v)x.fillRect(Math.round(col*s),Math.round(r*s),Math.ceil(s),Math.ceil(s))}))}

async function setup(fresh=false){const r=await api(fresh?"/api/mfa/reissue":"/api/mfa/provision",{});key=r.secret;keyShown=false;renderKey();qr(r.provisioningUri);console.log("Mock MFA OTP:",r.mockOtp);log("Mock MFA OTP delivered: "+r.mockOtp);show("setup","Step 3 of 6 · Add authenticator");message(r.message,"success")}
$("signinForm").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/signin",{email:$("email").value.trim(),phone:$("phone").value.trim(),password:$("password").value});csrf=d.csrf;show("identity","Step 2 of 6 · Confirm identity");message(d.message,"success");log("Signed in. Identity confirmation is next.")}catch(e){message(e.message,"error")}};
$("identityForm").onsubmit=async e=>{e.preventDefault();try{await api("/api/identity",{email:$("identityEmail").value.trim(),phone:$("identityPhone").value.trim()});await setup()}catch(e){message(e.message,"error")}};
$("showKey").onclick=()=>{keyShown=true;renderKey();message("Setup key shown. Hide it when you have finished.","success")};$("hideKey").onclick=()=>{keyShown=false;renderKey();message("Setup key hidden from the page.","success")};$("copyKey").onclick=()=>copy(key,"Setup key copied. Paste it into manual setup.");$("requestKey").onclick=async()=>{try{await setup(true)}catch(e){message(e.message,"error")}};$("ready").onclick=()=>show("verify","Step 4 of 6 · Verify code");
function gotCodes(d,label){codes=d.codes;codesShown=false;renderCodes();console.log("Recovery codes:",codes);log("Recovery codes delivered: "+codes.join(", "));show("recovery","Step 5 of 6 · Save recovery codes");message(label,"success")}
$("verifyForm").onsubmit=async e=>{e.preventDefault();try{await api("/api/mfa/verify",{otp:$("otp").value.trim()});gotCodes(await api("/api/recovery/generate",{}),"Authenticator confirmed. Recovery codes are ready.")}catch(e){message(e.message,"error")}};
$("showCodes").onclick=()=>{codesShown=true;renderCodes();message("Recovery codes shown. Hide them when you finish.","success")};$("hideCodes").onclick=()=>{codesShown=false;renderCodes();message("Recovery codes hidden from the page.","success")};$("copyCodes").onclick=()=>copy(codes.join("\\n"),"Recovery codes copied. Paste them into a private place.");
$("confirmForm").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/recovery/confirm",{saved:$("saved").checked});codes=[];codesShown=false;renderCodes();show("complete","Step 6 of 6 · Complete");message(d.message,"success");log("Recovery code saving was confirmed.")}catch(e){message(e.message,"error")}};
async function settings(){try{const d=await api("/api/settings",{},"GET");csrf=d.csrf;$("status").textContent=d.enabled&&d.recoveryReady?"✅ MFA is on. Your authenticator and recovery codes are ready.":"MFA needs attention.";show("settings","MFA settings")}catch(e){show("signin","Step 1 of 6 · Sign in");message(e.message,"error")}}
$("settingsBtn").onclick=settings;$("newCodes").onclick=async()=>{try{gotCodes(await api("/api/recovery/generate",{}),"New codes replace the old codes. Copy and save these codes.");$("saved").checked=false}catch(e){message(e.message,"error")}};$("recoveryPage").onclick=()=>show("recoverVerify","Recovery code check");$("backSettings").onclick=settings;
$("recoverForm").onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/recovery/verify",{code:$("recoveryInput").value.trim().toUpperCase()});$("recoveryInput").value="";message(d.message+" Choose another saved code next time.","success");log("A recovery code was verified and invalidated.")}catch(e){message(e.message,"error")}};
$("logout").onclick=async()=>{try{await api("/api/logout",{});csrf="";key="";codes=[];keyShown=false;codesShown=false;renderKey();renderCodes();show("signin","Step 1 of 6 · Sign in");message("You have signed out safely.","success");log("Signed out safely.")}catch(e){message(e.message,"error")}};log("Ready. Use the demo sign-in details to begin.");})();
</script></body></html>`;
}

Bun.serve({
  port: PORT,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  fetch: handler,
  error() { return fail(500, "Something went wrong. Please try again."); }
});
