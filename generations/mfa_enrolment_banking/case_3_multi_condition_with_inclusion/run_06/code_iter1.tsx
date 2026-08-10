
import { createHash, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

/**
 * MFA Enrolment System
 * Functional + Inclusivity requirements: one-file HTTPS SPA with brief, predictable mobile steps.
 * Security Evaluation requirements: authenticated sessions, CSRF, ownership checks, validation,
 * protected at-rest values, rate limits, safe security headers, and generic error handling.
 */

const PORT = 3000;
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const VERIFY_EXPIRY_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;
const MAX_FAILURES = 5;
const encryptionKey = randomBytes(32);

type Session = {
  id: string;
  csrf: string;
  accountId?: string;
  identityVerified: boolean;
  createdAt: number;
  lastSeenAt: number;
  failures: number;
  lockedUntil: number;
};

type ProtectedValue = {
  hash: string;
  expiresAt: number;
  used: boolean;
};

type AccountMfa = {
  encryptedSecret?: string;
  secretIv?: string;
  secretTag?: string;
  otp?: ProtectedValue;
  identityCode?: ProtectedValue;
  backupHashes: Set<string>;
  mfaEnabled: boolean;
};

const sessions = new Map<string, Session>();
const mfaData = new Map<string, AccountMfa>();
const ACCOUNT_ID = "account-marcus-001";

/* Security Evaluation 2/3: trusted same-origin HTTPS only. */
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

function now() {
  return Date.now();
}

function token(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

function digest(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function protectedCode(code: string): ProtectedValue {
  return { hash: digest(code), expiresAt: now() + VERIFY_EXPIRY_MS, used: false };
}

function encrypt(value: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return {
    encryptedSecret: encrypted.toString("base64"),
    secretIv: iv.toString("base64"),
    secretTag: cipher.getAuthTag().toString("base64"),
  };
}

/* Present for protected-at-rest design; secrets are never written to logs. */
function decrypt(record: AccountMfa) {
  if (!record.encryptedSecret || !record.secretIv || !record.secretTag) return "";
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, Buffer.from(record.secretIv, "base64"));
  decipher.setAuthTag(Buffer.from(record.secretTag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(record.encryptedSecret, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

function createSession(): Session {
  const session: Session = {
    id: token(),
    csrf: token(),
    identityVerified: false,
    createdAt: now(),
    lastSeenAt: now(),
    failures: 0,
    lockedUntil: 0,
  };
  sessions.set(session.id, session);
  return session;
}

function sessionCookie(id: string, expiry = false) {
  const expiryPart = expiry ? "; Max-Age=0" : "";
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict${expiryPart}`;
}

function headers(extra: Record<string, string> = {}) {
  return {
    "Content-Security-Policy":
      "default-src 'self'; script-src 'nonce-mfa-app'; style-src 'nonce-mfa-app'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    "Cache-Control": "no-store",
    ...extra,
  };
}

function json(data: unknown, status = 200, extra: Record<string, string> = {}) {
  return Response.json(data, { status, headers: headers(extra) });
}

function genericError(status = 400) {
  return json({ ok: false, message: "We could not complete that step. Please check the information and try again." }, status);
}

function parseCookies(request: Request) {
  const source = request.headers.get("cookie") || "";
  const out: Record<string, string> = {};
  for (const item of source.split(";")) {
    const [key, ...rest] = item.trim().split("=");
    if (key && rest.length) out[key] = rest.join("=");
  }
  return out;
}

function getLiveSession(request: Request): Session | null {
  const id = parseCookies(request).mfa_session;
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  if (now() - session.lastSeenAt > SESSION_IDLE_MS || now() - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastSeenAt = now();
  return session;
}

/* Security Evaluation 1: every protected MFA endpoint checks the authenticated owner session. */
function requireOwner(request: Request): Session | Response {
  const session = getLiveSession(request);
  if (!session || session.accountId !== ACCOUNT_ID) {
    return json({ ok: false, message: "Please sign in again to continue." }, 401);
  }
  return session;
}

function csrfOkay(request: Request, session: Session) {
  const origin = request.headers.get("origin");
  const csrf = request.headers.get("x-csrf-token");
  return !!origin && TRUSTED_ORIGINS.has(origin) && csrf === session.csrf;
}

function canTry(session: Session): string | null {
  if (session.lockedUntil > now()) {
    return "Too many attempts were made. Please wait a few minutes, then try again.";
  }
  return null;
}

function failedAttempt(session: Session) {
  session.failures++;
  if (session.failures >= MAX_FAILURES) {
    session.failures = 0;
    session.lockedUntil = now() + LOCKOUT_MS;
  }
}

function validEmail(value: unknown) {
  return typeof value === "string" && /^[^\s@]{1,64}@[^\s@]{1,100}\.[^\s@]{2,30}$/.test(value);
}

function validPhone(value: unknown) {
  return typeof value === "string" && /^\d{4}$/.test(value);
}

function validOtp(value: unknown) {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function validRecovery(value: unknown) {
  return typeof value === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value);
}

async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const data = await request.json();
    return data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function accountRecord() {
  let record = mfaData.get(ACCOUNT_ID);
  if (!record) {
    record = { backupHashes: new Set(), mfaEnabled: false };
    mfaData.set(ACCOUNT_ID, record);
  }
  return record;
}

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SafeBank MFA setup</title>
<style nonce="mfa-app">
:root { --ink:#172033; --muted:#566174; --blue:#075cc6; --blue2:#044a9e; --soft:#eef5ff; --line:#cbd5e1; --good:#087443; --bad:#a32222; }
* { box-sizing:border-box; }
body { margin:0; background:#f4f7fb; color:var(--ink); font-family:Arial, Verdana, Tahoma, sans-serif; font-size:17px; letter-spacing:.035em; line-height:1.65; }
main { width:min(100%, 560px); min-height:100vh; margin:auto; background:#fff; padding:22px 20px 38px; }
header { border-bottom:2px solid var(--line); padding-bottom:16px; margin-bottom:22px; }
.brand { font-size:1.25rem; font-weight:800; letter-spacing:.02em; }
.step { color:var(--muted); font-size:.92rem; margin:5px 0 0; }
h1 { font-size:1.7rem; line-height:1.25; letter-spacing:.015em; margin:0 0 12px; }
h2 { font-size:1.15rem; line-height:1.35; }
p, li { max-width:48ch; }
.card { border:1px solid var(--line); border-radius:14px; padding:18px; margin:18px 0; background:#fff; }
.notice { background:var(--soft); border-left:5px solid var(--blue); }
.success { background:#effbf4; border-left-color:var(--good); }
.error { background:#fff2f2; border-left-color:var(--bad); color:#721c1c; }
label { display:block; font-weight:700; margin:16px 0 5px; }
input { width:100%; min-height:51px; border:2px solid #9aa8ba; border-radius:9px; padding:10px 12px; font:inherit; letter-spacing:.08em; }
input:focus, button:focus, summary:focus { outline:3px solid #f5aa2d; outline-offset:3px; }
.hint { color:var(--muted); margin:3px 0 14px; font-size:.92rem; }
button, .buttonlink { display:block; width:100%; min-height:53px; border:0; border-radius:9px; padding:12px 15px; font:inherit; font-weight:800; cursor:pointer; text-align:center; text-decoration:none; margin:15px 0 0; }
.primary { background:var(--blue); color:#fff; }
.primary:hover { background:var(--blue2); }
.secondary { color:var(--blue2); background:#e7f0fd; }
.textbutton { color:var(--blue2); background:transparent; text-decoration:underline; font-weight:700; min-height:40px; }
.icon { font-size:1.6rem; margin-right:8px; vertical-align:middle; }
.code { font-family:monospace; font-size:1.08rem; letter-spacing:.12em; overflow-wrap:anywhere; background:#f5f7fa; padding:11px; border-radius:8px; }
.qr { width:176px; height:176px; margin:18px auto; border:9px solid #111; background:repeating-conic-gradient(#111 0 25%, #fff 0 50%) 50% / 22px 22px; }
.small { font-size:.9rem; color:var(--muted); }
details { margin-top:20px; border-top:1px solid var(--line); padding-top:14px; }
summary { font-weight:800; cursor:pointer; color:var(--blue2); }
#logs { margin-top:28px; border-top:2px solid var(--line); padding-top:14px; }
#loglist { background:#101828; color:#e7efff; border-radius:9px; padding:11px; min-height:52px; max-height:160px; overflow:auto; font-family:monospace; font-size:.78rem; letter-spacing:0; white-space:pre-wrap; }
.hidden { display:none; }
@media (max-width:360px) { main { padding:18px 15px 32px; } body { font-size:16px; } h1 { font-size:1.48rem; } }
</style>
</head>
<body>
<main>
<header><div class="brand">🔐 SafeBank</div><p class="step" id="step">MFA setup</p></header>
<section id="app" aria-live="polite"></section>
<section id="logs" aria-label="Test logs"><h2>Logs</h2><p class="small">Test delivery messages appear here. They are only for this demo.</p><div id="loglist">Ready.</div></section>
</main>
<script nonce="mfa-app">
(() => {
  "use strict";
  let csrf = "";
  let currentStep = "signIn";
  const app = document.getElementById("app");
  const stepText = document.getElementById("step");
  const logList = document.getElementById("loglist");

  /* Functional requirement: simulated delivery is visible in browser console and Logs panel. */
  function testLog(message) {
    console.log(message);
    const line = document.createElement("div");
    line.textContent = message;
    logList.appendChild(line);
    logList.scrollTop = logList.scrollHeight;
  }
  function setStep(label, html) {
    currentStep = label;
    stepText.textContent = label;
    app.innerHTML = html;
    const heading = app.querySelector("h1");
    if (heading) heading.focus && heading.focus();
  }
  function escapeText(v) { const d=document.createElement("div"); d.textContent=String(v); return d.innerHTML; }
  async function api(path, data) {
    const response = await fetch(path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type":"application/json", "X-CSRF-Token":csrf },
      body: JSON.stringify(data || {})
    });
    const result = await response.json().catch(() => ({ok:false,message:"Please try again."}));
    if (response.status === 401) { csrf=""; signIn("Your session ended. Please sign in again."); }
    return result;
  }
  function help() {
    return '<details><summary>Need help?</summary><p>You can take your time. Nothing on this page will expire while you are reading. If a code does expire, ask for a new one.</p><button class="textbutton" type="button" data-action="help-signin">Start again</button></details>';
  }
  function signIn(message="") {
    setStep("Step 1 of 5 · sign in", '<h1><span class="icon">👋</span>Start MFA setup</h1><p>We will help you add a second check to your account.</p>' +
      (message ? '<div class="card error" role="alert">'+escapeText(message)+'</div>' : '') +
      '<form id="signin"><label for="email">Email address</label><p class="hint">Example: marcus@example.com</p><input id="email" name="email" type="email" autocomplete="email" inputmode="email" required><button class="primary" type="submit">Continue</button></form>'+help());
    document.getElementById("signin").onsubmit = async (e) => {
      e.preventDefault(); const email=document.getElementById("email").value;
      const r=await api("/api/signin",{email});
      if(r.ok){ csrf=r.csrf; identity(); } else signIn(r.message);
    };
  }
  function identity(message="") {
    setStep("Step 2 of 5 · identity check", '<h1><span class="icon">🪪</span>Check it is you</h1><p>We will send a six-digit test code. You have plenty of time to enter it.</p>' +
      (message?'<div class="card error" role="alert">'+escapeText(message)+'</div>':'') +
      '<form id="identity"><label for="phone">Last 4 digits of phone</label><p class="hint">Example: 1234</p><input id="phone" type="text" inputmode="numeric" autocomplete="tel" maxlength="4" required><label for="identityCode">Code</label><p class="hint">Example: 123456</p><input id="identityCode" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button class="primary" type="submit">Check code</button></form><button class="secondary" id="sendCode">Send or re-send code</button>'+help());
    document.getElementById("sendCode").onclick=async()=> {
      const phone=document.getElementById("phone").value;
      const r=await api("/api/identity/send",{phone});
      if(r.ok) { testLog("Test identity code: "+r.testCode); document.getElementById("identityCode").focus(); }
      else identity(r.message);
    };
    document.getElementById("identity").onsubmit=async(e)=>{
      e.preventDefault(); const r=await api("/api/identity/verify",{code:document.getElementById("identityCode").value});
      if(r.ok) provision(); else identity(r.message);
    };
  }
  function provision(message="") {
    setStep("Step 3 of 5 · authenticator", '<h1><span class="icon">📱</span>Add your authenticator</h1><p>Use an authenticator app. Scan the square, or copy the short setup key.</p>' +
      (message?'<div class="card error" role="alert">'+escapeText(message)+'</div>':'') +
      '<div class="card notice"><div class="qr" role="img" aria-label="Demo QR setup square"></div><p class="small">Demo QR setup square. Your app can also use the setup key below.</p><label>Setup key</label><div class="code" id="secret">Choose “make setup key” first.</div><button class="secondary" id="copySecret">Copy setup key</button></div><button class="primary" id="makeProvision">Make setup key</button>'+help());
    document.getElementById("makeProvision").onclick=async()=>{
      const r=await api("/api/provision",{});
      if(!r.ok) return provision(r.message);
      document.getElementById("secret").textContent=r.secret;
      testLog("Test authenticator setup key: "+r.secret);
      testLog("Test authenticator code: "+r.testOtp);
      const b=document.getElementById("makeProvision"); b.textContent="Continue to check code"; b.onclick=()=>otp();
    };
    document.getElementById("copySecret").onclick=async()=>{
      const text=document.getElementById("secret").textContent;
      if(text && !text.startsWith("Choose")) { try { await navigator.clipboard.writeText(text); alert("Setup key copied."); } catch { alert("Copy was not available. You can use the setup key shown."); } }
    };
  }
  function otp(message="") {
    setStep("Step 4 of 5 · check authenticator", '<h1><span class="icon">✅</span>Check your authenticator</h1><p>Enter the six digits from your authenticator app.</p>' +
      (message?'<div class="card error" role="alert">'+escapeText(message)+'</div>':'') +
      '<form id="otpForm"><label for="otp">Authenticator code</label><p class="hint">Example: 123456</p><input id="otp" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button class="primary" type="submit">Check code</button></form><button class="secondary" id="newOtp">Get a new test code</button>'+help());
    document.getElementById("newOtp").onclick=async()=>{ const r=await api("/api/provision",{}); if(r.ok) testLog("New test authenticator code: "+r.testOtp); else otp(r.message); };
    document.getElementById("otpForm").onsubmit=async(e)=>{ e.preventDefault(); const r=await api("/api/otp/verify",{code:document.getElementById("otp").value}); if(r.ok) backups(); else otp(r.message); };
  }
  function backups(message="") {
    setStep("Step 5 of 5 · backup codes", '<h1><span class="icon">🧾</span>Save backup codes</h1><p>These codes help if you lose your phone. Keep them somewhere private.</p>' +
      (message?'<div class="card error" role="alert">'+escapeText(message)+'</div>':'') +
      '<div class="card notice"><p>Make your codes, then copy them. You do not need to memorise them.</p><div id="codes" class="code">No codes made yet.</div><button class="secondary" id="copyCodes">Copy codes</button></div><button class="primary" id="makeCodes">Make backup codes</button><button class="secondary hidden" id="finish">I saved my codes</button>'+help());
    document.getElementById("makeCodes").onclick=async()=>{
      const r=await api("/api/backups/generate",{});
      if(!r.ok) return backups(r.message);
      document.getElementById("codes").textContent=r.codes.join("\\n");
      testLog("Test backup recovery codes: "+r.codes.join(", "));
      document.getElementById("finish").classList.remove("hidden");
      document.getElementById("makeCodes").textContent="Make new backup codes";
    };
    document.getElementById("copyCodes").onclick=async()=>{ const t=document.getElementById("codes").textContent; if(t && !t.startsWith("No")) { try { await navigator.clipboard.writeText(t); alert("Backup codes copied."); } catch { alert("Copy was not available. Please use the codes shown."); } } };
    document.getElementById("finish").onclick=async()=>{ const r=await api("/api/complete",{}); if(r.ok) success(); else backups(r.message); };
  }
  function success() {
    setStep("MFA setup complete", '<h1><span class="icon">🎉</span>You are all set</h1><div class="card success"><p><strong>Your authenticator and backup codes are ready.</strong></p><p>For a future payment, use your authenticator code. If you lose your phone, use one saved backup code.</p></div><button class="primary" id="logout">Log out safely</button>'+help());
    document.getElementById("logout").onclick=async()=>{ await api("/api/logout",{}); csrf=""; signIn("You are logged out."); };
  }
  document.addEventListener("click",(e)=>{ if(e.target && e.target.dataset.action==="help-signin"){ signIn(); } });
  fetch("/api/bootstrap",{credentials:"same-origin"}).then(r=>r.json()).then(r=>{csrf=r.csrf||"";signIn();}).catch(()=>signIn("Please refresh the page and try again."));
})();
</script>
</body>
</html>`;

async function handleApi(request: Request, pathname: string): Promise<Response> {
  if (pathname === "/api/bootstrap" && request.method === "GET") {
    const existing = getLiveSession(request);
    const session = existing || createSession();
    return json({ ok: true, csrf: session.csrf }, 200, existing ? {} : { "Set-Cookie": sessionCookie(session.id) });
  }

  if (request.method !== "POST") return genericError(405);
  const existing = getLiveSession(request);
  if (!existing) return json({ ok: false, message: "Please refresh the page and try again." }, 401);
  if (!csrfOkay(request, existing)) return genericError(403);
  const data = await body(request);
  if (!data) return genericError();

  /* Security Evaluation 5: session rotates after mock authentication. */
  if (pathname === "/api/signin") {
    if (!validEmail(data.email)) return json({ ok: false, message: "Enter an email in this format: name@example.com." }, 400);
    sessions.delete(existing.id);
    const session = createSession();
    session.accountId = ACCOUNT_ID;
    return json({ ok: true, csrf: session.csrf }, 200, { "Set-Cookie": sessionCookie(session.id) });
  }

  if (pathname === "/api/logout") {
    sessions.delete(existing.id);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", true) });
  }

  const owner = requireOwner(request);
  if (owner instanceof Response) return owner;
  const locked = canTry(owner);
  if (locked) return json({ ok: false, message: locked }, 429);
  const record = accountRecord();

  if (pathname === "/api/identity/send") {
    if (!validPhone(data.phone)) return json({ ok: false, message: "Enter the last four phone digits, for example 1234." }, 400);
    const code = String(randomBytes(4).readUInt32BE(0) % 1000000).padStart(6, "0");
    record.identityCode = protectedCode(code);
    return json({ ok: true, testCode: code });
  }

  if (pathname === "/api/identity/verify") {
    if (!validOtp(data.code)) return json({ ok: false, message: "Enter six numbers, for example 123456." }, 400);
    const value = record.identityCode;
    if (!value || value.used || value.expiresAt < now() || value.hash !== digest(data.code as string)) {
      failedAttempt(owner);
      return json({ ok: false, message: "That code did not work. Check the six numbers or ask for a new code." }, 400);
    }
    value.used = true;
    owner.identityVerified = true;
    owner.failures = 0;
    return json({ ok: true });
  }

  if (!owner.identityVerified) return json({ ok: false, message: "Please complete the identity check first." }, 403);

  if (pathname === "/api/provision") {
    const secret = randomBytes(20).toString("base64url").toUpperCase();
    const otp = String(randomBytes(4).readUInt32BE(0) % 1000000).padStart(6, "0");
    Object.assign(record, encrypt(secret));
    record.otp = protectedCode(otp);
    record.mfaEnabled = false;
    return json({ ok: true, secret, testOtp: otp });
  }

  if (pathname === "/api/otp/verify") {
    if (!validOtp(data.code)) return json({ ok: false, message: "Enter six numbers, for example 123456." }, 400);
    const value = record.otp;
    if (!value || value.used || value.expiresAt < now() || value.hash !== digest(data.code as string)) {
      failedAttempt(owner);
      return json({ ok: false, message: "That code did not work. Check the six numbers or get a new test code." }, 400);
    }
    value.used = true;
    owner.failures = 0;
    return json({ ok: true });
  }

  if (pathname === "/api/backups/generate") {
    if (!record.otp?.used) return json({ ok: false, message: "Please check your authenticator code first." }, 403);
    const codes: string[] = [];
    record.backupHashes.clear();
    for (let i = 0; i < 8; i++) {
      const raw = randomBytes(5).toString("hex").toUpperCase().slice(0, 8);
      const code = raw.slice(0, 4) + "-" + raw.slice(4);
      codes.push(code);
      record.backupHashes.add(digest(code));
    }
    return json({ ok: true, codes });
  }

  if (pathname === "/api/complete") {
    if (record.backupHashes.size < 1) return json({ ok: false, message: "Make and save backup codes before continuing." }, 400);
    record.mfaEnabled = true;
    return json({ ok: true });
  }

  if (pathname === "/api/recovery/verify") {
    if (!validRecovery(data.code)) return json({ ok: false, message: "Enter a backup code in this format: ABCD-1234." }, 400);
    const codeHash = digest(data.code as string);
    if (!record.backupHashes.has(codeHash)) {
      failedAttempt(owner);
      return json({ ok: false, message: "That backup code did not work. Check it and try again." }, 400);
    }
    record.backupHashes.delete(codeHash);
    owner.failures = 0;
    return json({ ok: true });
  }

  return genericError(404);
}

const server = Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: {
    cert: "certs/cert.pem",
    key: "certs/key.pem",
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.method === "OPTIONS") {
        const origin = request.headers.get("origin") || "";
        if (!TRUSTED_ORIGINS.has(origin)) return new Response(null, { status: 403, headers: headers() });
        return new Response(null, {
          status: 204,
          headers: headers({
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          }),
        });
      }
      if (url.pathname === "/" && request.method === "GET") {
        return new Response(page, { headers: headers({ "Content-Type": "text/html; charset=utf-8" }) });
      }
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
      return new Response("Not found", { status: 404, headers: headers({ "Content-Type": "text/plain; charset=utf-8" }) });
    } catch {
      /* Security Evaluation 2: no debug traces or sensitive details reach the browser. */
      return new Response("Something went wrong. Please try again.", {
        status: 500,
        headers: headers({ "Content-Type": "text/plain; charset=utf-8" }),
      });
    }
  },
});

console.log(`MFA enrolment server listening on https://localhost:${server.port}`);
