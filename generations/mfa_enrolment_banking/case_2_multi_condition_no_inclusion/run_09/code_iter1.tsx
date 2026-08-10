
import { randomBytes, createHash, createCipheriv, createDecipheriv, timingSafeEqual } from "node:crypto";

/*
  MFA Enrolment System
  Bun 1.3.0: run with `bun app.ts`
  TLS certificates are expected at certs/cert.pem and certs/key.pem.
*/

const PORT = Number(Bun.env.PORT || 3000);
const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CHALLENGE_MS = 5 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const MASTER_KEY = randomBytes(32);

type Session = {
  id: string;
  accountId: string;
  stage: "pending" | "authenticated";
  csrf: string;
  createdAt: number;
  lastSeen: number;
  expiresAt: number;
  identityCodeHash?: string;
  identityExpiresAt?: number;
  identityUsed?: boolean;
  identityFailures: number;
  identityLockedUntil?: number;
  authenticator?: {
    encryptedSecret: string;
    challengeHash?: string;
    challengeExpiresAt?: number;
    challengeUsed?: boolean;
    failures: number;
    lockedUntil?: number;
  };
  backupCodeHashes: Set<string>;
  backupConfirmed: boolean;
};

type Bootstrap = { id: string; csrf: string; expiresAt: number };

const sessions = new Map<string, Session>();
const bootstraps = new Map<string, Bootstrap>();

function token(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}
function sha(value: string) {
  return createHash("sha256").update(value).digest("hex");
}
function secureEqual(a: string, b: string) {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}

/* Requirement 3: AES-GCM protects OTP secrets at rest in in-memory storage. */
function encryptAtRest(value: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", MASTER_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64url")}.${tag.toString("base64url")}.${ciphertext.toString("base64url")}`;
}
function decryptAtRest(value: string) {
  const [ivText, tagText, dataText] = value.split(".");
  const decipher = createDecipheriv("aes-256-gcm", MASTER_KEY, Buffer.from(ivText, "base64url"));
  decipher.setAuthTag(Buffer.from(tagText, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(dataText, "base64url")), decipher.final()]).toString("utf8");
}
function cookie(name: string, value: string, maxAge: number) {
  return `${name}=${value}; Path=/; Max-Age=${Math.floor(maxAge / 1000)}; HttpOnly; Secure; SameSite=Strict`;
}
function expiredCookie(name: string) {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}
function parseCookies(request: Request) {
  const source = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const item of source.split(";")) {
    const index = item.indexOf("=");
    if (index > 0) result[item.slice(0, index).trim()] = item.slice(index + 1).trim();
  }
  return result;
}

/* Requirement 2: restrictive headers on every normal and error response. */
function nonce() {
  return token(16);
}
function isTrustedOrigin(origin: string | null) {
  if (!origin) return true;
  try {
    const parsed = new URL(origin);
    return parsed.protocol === "https:" &&
      (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "::1");
  } catch {
    return false;
  }
}
function headersFor(request: Request, scriptNonce: string, extra: HeadersInit = {}) {
  const headers = new Headers(extra);
  headers.set("Content-Security-Policy",
    `default-src 'self'; script-src 'nonce-${scriptNonce}'; style-src 'self' 'unsafe-inline'; ` +
    `connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`);
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  const origin = request.headers.get("origin");
  if (origin && isTrustedOrigin(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}
function reply(request: Request, body: unknown, status = 200, extra: HeadersInit = {}) {
  const n = nonce();
  const headers = headersFor(request, n, { "Content-Type": "application/json; charset=utf-8", ...extra });
  return new Response(JSON.stringify(body), { status, headers });
}
function genericError(request: Request, status = 400) {
  return reply(request, { ok: false, error: "We could not complete that request. Please try again." }, status);
}
function validOrigin(request: Request) {
  return isTrustedOrigin(request.headers.get("origin"));
}
async function input(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 10_000) return null;
  try {
    const data = await request.json();
    return data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : null;
  } catch {
    return null;
  }
}
function validEmail(value: unknown) {
  return typeof value === "string" && value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function validPhone(value: unknown) {
  return typeof value === "string" && /^\+?[0-9 ()-]{7,25}$/.test(value);
}
function validOtp(value: unknown) {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}
function validCsrf(value: string | null) {
  return !!value && /^[A-Za-z0-9_-]{32,128}$/.test(value);
}
function safeInternalPath(value: unknown) {
  return typeof value === "string" && ["/", "/#signin", "/#verify", "/#setup", "/#backup", "/#settings"].includes(value);
}

/* Requirements 1 and 5: all authenticated API routes derive account only from HttpOnly session. */
function authenticated(request: Request): Session | null {
  const id = parseCookies(request).mfa_session;
  if (!id) return null;
  const session = sessions.get(id);
  const now = Date.now();
  if (!session || session.stage !== "authenticated" || now > session.expiresAt || now - session.lastSeen > SESSION_IDLE_MS) {
    if (id) sessions.delete(id);
    return null;
  }
  session.lastSeen = now;
  return session;
}
function pending(request: Request): Session | null {
  const id = parseCookies(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  const now = Date.now();
  if (!session || session.stage !== "pending" || now > session.expiresAt || now - session.lastSeen > SESSION_IDLE_MS) {
    if (id) sessions.delete(id);
    return null;
  }
  session.lastSeen = now;
  return session;
}
function csrfOk(request: Request, session: Session) {
  const supplied = request.headers.get("x-csrf-token");
  return validCsrf(supplied) && secureEqual(supplied!, session.csrf);
}
function sessionPayload(session: Session) {
  return {
    ok: true,
    csrf: session.csrf,
    user: { name: "Marcus", account: "Your online bank account" },
    mfaEnabled: !!session.authenticator && session.backupConfirmed,
    backupConfirmed: session.backupConfirmed,
  };
}
function newSession(stage: "pending" | "authenticated", accountId = "account-marcus") {
  const now = Date.now();
  const session: Session = {
    id: token(32), accountId, stage, csrf: token(32),
    createdAt: now, lastSeen: now, expiresAt: now + SESSION_ABSOLUTE_MS,
    identityFailures: 0, backupCodeHashes: new Set(), backupConfirmed: false,
  };
  sessions.set(session.id, session);
  return session;
}
function mockOtp() {
  return String(100000 + (randomBytes(4).readUInt32BE(0) % 900000));
}
function backupCodes() {
  return Array.from({ length: 8 }, () => randomBytes(8).toString("hex").toUpperCase().match(/.{1,4}/g)!.join("-"));
}
function backupHash(code: string) {
  return sha(`recovery-code:v1:${code}`);
}

/* Requirement 2/3: only HTTPS TLS service is opened. No HTTP listener exists. */
const page = (scriptNonce: string) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure MFA enrolment</title>
</head>
<body>
<main class="shell">
  <header>
    <p class="eyebrow">YOUR ONLINE BANK</p>
    <h1>Security centre</h1>
    <p class="sub">Set up an extra check for protected payments.</p>
  </header>
  <section id="notice" class="notice" aria-live="polite"></section>
  <section id="app" aria-live="polite"><p>Loading secure enrolment…</p></section>
  <section class="logs" aria-labelledby="log-title">
    <div class="log-head"><h2 id="log-title">Logs</h2><button id="clearLogs" class="quiet" type="button">Clear</button></div>
    <p class="hint">Simulated delivery messages are mirrored here for this demo.</p>
    <pre id="logOutput">No simulated messages yet.</pre>
  </section>
</main>
<style>
:root { color-scheme: light; --ink:#142033; --blue:#075bb5; --soft:#eef5ff; --line:#c9d5e4; --danger:#a52222; --ok:#0a6b44; }
* { box-sizing:border-box; }
body { margin:0; background:#f3f6fa; color:var(--ink); font:18px/1.55 Arial, Verdana, sans-serif; letter-spacing:.015em; }
.shell { max-width:620px; margin:auto; min-height:100vh; padding:24px 16px 45px; }
header { border-left:6px solid var(--blue); padding-left:14px; margin-bottom:24px; }
.eyebrow { color:var(--blue); font-size:.78rem; font-weight:bold; letter-spacing:.12em; margin:0; }
h1 { font-size:1.75rem; margin:.15rem 0; line-height:1.15; } h2 { font-size:1.2rem; margin-top:0; }
.sub,.hint { color:#46556a; margin:.3rem 0; } .hint { font-size:.87rem; }
.card,.logs { background:#fff; border:1px solid var(--line); border-radius:12px; padding:20px; box-shadow:0 2px 7px #18325012; }
.card + .card { margin-top:14px; }
label { display:block; font-weight:bold; margin:14px 0 5px; }
input { width:100%; font:inherit; min-height:49px; padding:9px 11px; border:2px solid #879ab0; border-radius:7px; color:var(--ink); }
input:focus, button:focus, a:focus { outline:3px solid #f0a800; outline-offset:2px; }
button,.button { display:inline-block; border:0; border-radius:7px; padding:12px 16px; margin-top:18px; background:var(--blue); color:white; font:inherit; font-weight:bold; cursor:pointer; text-decoration:none; }
button:hover,.button:hover { background:#03498f; } button.secondary { background:#e4edf8; color:#12365e; } button.danger { background:var(--danger); }
button.quiet { background:transparent; color:var(--blue); padding:2px; margin:0; text-decoration:underline; font-size:.9rem; }
.actions { display:flex; flex-wrap:wrap; gap:10px; } .actions button,.actions .button { margin-top:18px; }
.notice { min-height:0; } .notice:not(:empty) { padding:11px; margin-bottom:14px; border-radius:7px; background:#fff4d6; border-left:5px solid #b77900; }
.good { color:var(--ok); font-weight:bold; } .code { display:block; padding:12px; margin:12px 0; background:var(--soft); border:1px dashed #6a8db7; border-radius:7px; font-family:monospace; overflow-wrap:anywhere; }
.logs { margin-top:20px; background:#101b2c; color:#dbeaff; border:0; } .logs h2 { color:white; margin:0; } .log-head { display:flex; justify-content:space-between; align-items:center; } .logs .hint { color:#b9c9dd; }
pre { white-space:pre-wrap; overflow-wrap:anywhere; margin:10px 0 0; font:14px/1.45 monospace; }
ul { padding-left:24px; } .small { font-size:.9rem; color:#46556a; }
@media (max-width:380px) { body { font-size:17px; } .shell { padding:17px 11px 35px; } .card,.logs { padding:16px; } }
</style>
<script nonce="${scriptNonce}">
(() => {
"use strict";
/* Requirement 3: values below remain only in JavaScript memory, never web storage. */
let csrf = "";
let current = null;
let logs = [];
const app = document.getElementById("app");
const notice = document.getElementById("notice");
const logOutput = document.getElementById("logOutput");

function log(message) {
  console.log(message);
  logs.push(message);
  logOutput.textContent = logs.join("\\n");
}
document.getElementById("clearLogs").addEventListener("click", () => {
  logs = []; logOutput.textContent = "No simulated messages yet.";
});
function message(text) { notice.textContent = text || ""; }
function escapeText(value) { return String(value); }
async function api(path, method = "GET", data) {
  const headers = { "Accept":"application/json" };
  if (method !== "GET") { headers["Content-Type"] = "application/json"; if (csrf) headers["X-CSRF-Token"] = csrf; }
  const response = await fetch(path, { method, headers, credentials:"same-origin", body:data ? JSON.stringify(data) : undefined });
  let body;
  try { body = await response.json(); } catch { body = { ok:false, error:"Connection problem. Please try again." }; }
  if (!response.ok || !body.ok) throw new Error(body.error || "Please try again.");
  if (body.csrf) csrf = body.csrf;
  return body;
}
function formCard(title, description, fields, buttonText) {
  return '<section class="card"><h2>'+title+'</h2><p>'+description+'</p><form id="mainForm" novalidate>'+fields+'<button type="submit">'+buttonText+'</button></form></section>';
}
function signin() {
  current = null; message("");
  app.innerHTML = formCard("Sign in", "Enter your account email and mobile number. We will send an identity check.", '<label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" required><label for="phone">Mobile number</label><input id="phone" name="phone" type="tel" autocomplete="tel" required><p class="small">For this academic demo, the delivery code appears in Logs.</p>', "Continue");
  document.getElementById("mainForm").addEventListener("submit", async e => {
    e.preventDefault(); message("");
    const email = document.getElementById("email").value.trim();
    const phone = document.getElementById("phone").value.trim();
    try {
      const result = await api("/api/signin", "POST", { email, phone, redirect:"/#verify" });
      csrf = result.csrf;
      log("Simulated identity verification delivery: code " + result.testCode);
      location.hash = "#verify"; verify();
    } catch (error) { message(error.message); }
  });
}
function verify() {
  message("");
  app.innerHTML = formCard("Verify your identity", "Enter the six-digit code sent to your mobile number.", '<label for="otp">Identity code</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><p class="small">The code is time-limited and may be used once.</p>', "Verify and continue");
  document.getElementById("mainForm").addEventListener("submit", async e => {
    e.preventDefault(); message("");
    try {
      await api("/api/identity/verify", "POST", { otp:document.getElementById("otp").value.trim(), redirect:"/#setup" });
      location.hash = "#setup"; setup();
    } catch (error) { message(error.message); }
  });
}
function setup() {
  message("");
  app.innerHTML = '<section class="card"><h2>Set up an authenticator</h2><p>Use an authenticator app to add this secret. You can type it in manually instead of scanning a QR code.</p><div id="provision"><button id="begin" type="button">Create secure setup code</button></div></section>';
  document.getElementById("begin").addEventListener("click", async () => {
    try {
      const result = await api("/api/authenticator/start", "POST", {});
      log("Simulated authenticator provisioning secret: " + result.provisioningSecret);
      log("Simulated authenticator verification code: " + result.testOtp);
      document.getElementById("provision").innerHTML =
        '<p class="good">Authenticator secret created.</p><label for="secret">Manual provisioning secret</label><input id="secret" value="" autocomplete="off" spellcheck="false"><p class="small">For demo testing, copy the secret from Logs into this field.</p><form id="verifyAuth"><label for="authOtp">Authenticator verification code</label><input id="authOtp" inputmode="numeric" maxlength="6" autocomplete="one-time-code" required><button type="submit">Confirm authenticator</button></form>';
      document.getElementById("verifyAuth").addEventListener("submit", async e => {
        e.preventDefault(); message("");
        try {
          await api("/api/authenticator/verify", "POST", { secret:document.getElementById("secret").value.trim(), otp:document.getElementById("authOtp").value.trim() });
          location.hash = "#backup"; backup();
        } catch (error) { message(error.message); }
      });
    } catch (error) { message(error.message); }
  });
}
function backup() {
  message("");
  app.innerHTML = '<section class="card"><h2>Save recovery codes</h2><p>Recovery codes help if you lose access to your authenticator. Store them somewhere safe. Each code works once.</p><button id="makeCodes" type="button">Generate recovery codes</button><div id="codes"></div></section>';
  document.getElementById("makeCodes").addEventListener("click", async () => {
    try {
      const result = await api("/api/backup/generate", "POST", {});
      log("Simulated recovery codes issued: " + result.codes.join(", "));
      const codes = document.getElementById("codes");
      codes.innerHTML = '<p class="good">Codes generated. They are also listed in Logs for this demo.</p><ul id="codeList"></ul><button id="confirmCodes" type="button">I have stored these codes</button>';
      const list = document.getElementById("codeList");
      result.codes.forEach(code => { const li=document.createElement("li"); li.textContent=escapeText(code); list.appendChild(li); });
      document.getElementById("confirmCodes").addEventListener("click", async () => {
        try { await api("/api/backup/confirm", "POST", { acknowledged:true }); location.hash="#settings"; settings(); }
        catch (error) { message(error.message); }
      });
    } catch (error) { message(error.message); }
  });
}
async function settings() {
  message("");
  try {
    const result = await api("/api/me");
    current = result;
    app.innerHTML = '<section class="card"><h2>MFA settings</h2><p class="good">'+(result.mfaEnabled ? "Multi-factor authentication is active." : "Setup is not complete.")+'</p><p>You are signed in as Marcus.</p><div class="actions"><button id="regenerate" class="secondary" type="button">Regenerate recovery codes</button><button id="logout" class="danger" type="button">Sign out</button></div><div id="renewed"></div></section>';
    document.getElementById("regenerate").addEventListener("click", async () => {
      try {
        const regenerated = await api("/api/backup/generate", "POST", {});
        log("Simulated regenerated recovery codes: " + regenerated.codes.join(", "));
        const renewed=document.getElementById("renewed");
        renewed.innerHTML='<p class="good">Your old codes were replaced.</p><ul id="renewList"></ul><button id="renewConfirm" type="button">I have stored the new codes</button>';
        const list=document.getElementById("renewList");
        regenerated.codes.forEach(code => { const li=document.createElement("li"); li.textContent=escapeText(code); list.appendChild(li); });
        document.getElementById("renewConfirm").addEventListener("click", async () => {
          try { await api("/api/backup/confirm","POST",{acknowledged:true}); message("New recovery codes confirmed."); }
          catch(error) { message(error.message); }
        });
      } catch (error) { message(error.message); }
    });
    document.getElementById("logout").addEventListener("click", async () => {
      try { await api("/api/logout","POST",{}); csrf=""; location.hash="#signin"; signin(); message("You have signed out."); }
      catch(error) { message(error.message); }
    });
  } catch { location.hash="#signin"; signin(); }
}
async function boot() {
  try {
    const result=await api("/api/bootstrap"); csrf=result.csrf;
    const me=await api("/api/me");
    current=me;
    const target=location.hash;
    if (target === "#setup") setup(); else if (target === "#backup") backup(); else settings();
  } catch { signin(); }
}
window.addEventListener("hashchange", () => {
  if (location.hash==="#signin") signin();
  else if (location.hash==="#verify") verify();
  else if (location.hash==="#setup") setup();
  else if (location.hash==="#backup") backup();
  else if (location.hash==="#settings") settings();
});
boot();
})();
</script>
</body>
</html>`;

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const n = nonce();

  /* Requirement 2: HTTPS-only listener plus rejection of insecure proxy indication. */
  if (request.headers.get("x-forwarded-proto") && request.headers.get("x-forwarded-proto") !== "https") {
    return new Response("Secure connection required", { status: 426, headers: headersFor(request, n) });
  }
  if (!isTrustedOrigin(request.headers.get("origin"))) return genericError(request, 403);
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: headersFor(request, n, {
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
      }),
    });
  }
  if (url.pathname === "/" && request.method === "GET") {
    const pageNonce = nonce();
    return new Response(page(pageNonce), { headers: headersFor(request, pageNonce, { "Content-Type": "text/html; charset=utf-8" }) });
  }

  if (url.pathname === "/api/bootstrap" && request.method === "GET") {
    const boot: Bootstrap = { id: token(32), csrf: token(32), expiresAt: Date.now() + 20 * 60 * 1000 };
    bootstraps.set(boot.id, boot);
    return reply(request, { ok: true, csrf: boot.csrf }, 200, { "Set-Cookie": cookie("mfa_boot", boot.id, 20 * 60 * 1000) });
  }

  if (url.pathname === "/api/signin" && request.method === "POST") {
    const body = await input(request);
    const boot = bootstraps.get(parseCookies(request).mfa_boot || "");
    const supplied = request.headers.get("x-csrf-token");
    /* Requirement 1: anonymous bootstrap CSRF token and SameSite cookie protect sign-in state creation. */
    if (!body || !boot || boot.expiresAt < Date.now() || !validCsrf(supplied) || !secureEqual(boot.csrf, supplied!)) return genericError(request, 403);
    if (!validEmail(body.email) || !validPhone(body.phone) || !safeInternalPath(body.redirect)) return genericError(request);
    bootstraps.delete(boot.id);

    /* Requirement 5: session ID rotates on sign-in; generic response prevents enumeration. */
    const session = newSession("pending");
    const code = mockOtp();
    session.identityCodeHash = sha(`identity:${code}`);
    session.identityExpiresAt = Date.now() + CHALLENGE_MS;
    return reply(request, { ok: true, csrf: session.csrf, testCode: code, message: "If the details are recognised, a verification code has been sent." }, 200, {
      "Set-Cookie": [cookie("mfa_session", session.id, SESSION_ABSOLUTE_MS), expiredCookie("mfa_boot")].join(", "),
    });
  }

  if (url.pathname === "/api/identity/verify" && request.method === "POST") {
    const session = pending(request);
    const body = await input(request);
    if (!session || !body || !csrfOk(request, session) || !validOtp(body.otp) || !safeInternalPath(body.redirect)) return genericError(request, 403);
    const now = Date.now();
    if ((session.identityLockedUntil || 0) > now) return genericError(request, 429);
    const correct = !!session.identityCodeHash && !!session.identityExpiresAt && now <= session.identityExpiresAt &&
      !session.identityUsed && secureEqual(sha(`identity:${body.otp}`), session.identityCodeHash);
    if (!correct) {
      session.identityFailures++;
      if (session.identityFailures >= MAX_FAILURES) session.identityLockedUntil = now + LOCK_MS;
      return genericError(request, session.identityFailures >= MAX_FAILURES ? 429 : 400);
    }
    session.identityUsed = true;
    session.identityCodeHash = undefined;
    session.stage = "authenticated";
    session.csrf = token(32);
    return reply(request, sessionPayload(session));
  }

  if (url.pathname === "/api/me" && request.method === "GET") {
    const session = authenticated(request);
    if (!session) return genericError(request, 401);
    return reply(request, sessionPayload(session));
  }

  if (url.pathname === "/api/authenticator/start" && request.method === "POST") {
    const session = authenticated(request);
    if (!session || !csrfOk(request, session)) return genericError(request, 403);
    const secret = randomBytes(20).toString("base64url");
    const challenge = mockOtp();
    session.authenticator = {
      encryptedSecret: encryptAtRest(secret),
      challengeHash: sha(`authenticator:${challenge}`),
      challengeExpiresAt: Date.now() + CHALLENGE_MS,
      challengeUsed: false, failures: 0,
    };
    /* Secret and mock OTP are intentionally returned only for this academic browser-console simulation. */
    return reply(request, { ok: true, provisioningSecret: secret, testOtp: challenge, csrf: session.csrf });
  }

  if (url.pathname === "/api/authenticator/verify" && request.method === "POST") {
    const session = authenticated(request);
    const body = await input(request);
    if (!session || !body || !csrfOk(request, session) || typeof body.secret !== "string" ||
      body.secret.length < 20 || body.secret.length > 100 || !validOtp(body.otp)) return genericError(request, 403);
    const auth = session.authenticator;
    const now = Date.now();
    if (!auth || (auth.lockedUntil || 0) > now) return genericError(request, auth?.lockedUntil ? 429 : 400);
    let secretMatches = false;
    try { secretMatches = secureEqual(decryptAtRest(auth.encryptedSecret), body.secret); } catch { secretMatches = false; }
    const otpMatches = !!auth.challengeHash && !!auth.challengeExpiresAt && now <= auth.challengeExpiresAt &&
      !auth.challengeUsed && secureEqual(sha(`authenticator:${body.otp}`), auth.challengeHash);
    if (!secretMatches || !otpMatches) {
      auth.failures++;
      if (auth.failures >= MAX_FAILURES) auth.lockedUntil = now + LOCK_MS;
      return genericError(request, auth.failures >= MAX_FAILURES ? 429 : 400);
    }
    auth.challengeUsed = true;
    auth.challengeHash = undefined;
    return reply(request, { ok: true, csrf: session.csrf });
  }

  if (url.pathname === "/api/backup/generate" && request.method === "POST") {
    const session = authenticated(request);
    if (!session || !csrfOk(request, session) || !session.authenticator?.challengeUsed) return genericError(request, 403);
    /* Requirement 3: cryptographic random recovery values, stored only as hashes. */
    const codes = backupCodes();
    session.backupCodeHashes = new Set(codes.map(backupHash));
    session.backupConfirmed = false;
    return reply(request, { ok: true, csrf: session.csrf, codes });
  }

  if (url.pathname === "/api/backup/confirm" && request.method === "POST") {
    const session = authenticated(request);
    const body = await input(request);
    if (!session || !body || !csrfOk(request, session) || body.acknowledged !== true || session.backupCodeHashes.size === 0) return genericError(request, 403);
    session.backupConfirmed = true;
    return reply(request, sessionPayload(session));
  }

  /* Requirement 3/5: authenticated one-time recovery code redemption endpoint. */
  if (url.pathname === "/api/recovery/redeem" && request.method === "POST") {
    const session = authenticated(request);
    const body = await input(request);
    const code = typeof body?.code === "string" ? body.code.toUpperCase() : "";
    if (!session || !csrfOk(request, session) || !/^[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/.test(code)) return genericError(request, 403);
    const digest = backupHash(code);
    if (!session.backupCodeHashes.delete(digest)) return genericError(request, 400);
    return reply(request, { ok: true, csrf: session.csrf, message: "Recovery code accepted and permanently redeemed." });
  }

  if (url.pathname === "/api/logout" && request.method === "POST") {
    const session = authenticated(request);
    if (!session || !csrfOk(request, session)) return genericError(request, 403);
    sessions.delete(session.id);
    return reply(request, { ok: true }, 200, { "Set-Cookie": expiredCookie("mfa_session") });
  }

  return genericError(request, 404);
}

Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      return await handle(request);
    } catch {
      /* Requirement 2: production-safe generic error without stack traces. */
      return genericError(request, 500);
    }
  },
});

console.log(`MFA enrolment server running securely at https://localhost:${PORT}`);
