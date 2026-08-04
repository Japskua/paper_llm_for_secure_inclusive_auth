
import { randomBytes } from "crypto";

/*
  Password Recovery System
  Single-file Bun HTTPS server + vanilla HTML/CSS/JS SPA.
  Run with: bun app.ts
*/

type RecoveryStage = "start" | "requested" | "verified" | "password" | "privacy" | "paused" | "confirmed";

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  expiresAt: number;
  authenticated: boolean;
  privacyAccepted: boolean;
  loginFailures: number;
  loginLockUntil: number;
  recoveryRequests: number[];
  recovery?: {
    recordId: string;
    stage: RecoveryStage;
    pausedFrom?: RecoveryStage;
  };
};

type RecoveryRecord = {
  id: string;
  tokenHash: string;
  sessionId: string;
  accountExists: boolean;
  expiresAt: number;
  used: boolean;
  verificationAttempts: number;
  lockUntil: number;
  verified: boolean;
};

const sessions = new Map<string, Session>();
const recoveryRecords = new Map<string, RecoveryRecord>();

const SESSION_LIFETIME_MS = 8 * 60 * 60 * 1000;
const TOKEN_LIFETIME_MS = 15 * 60 * 1000;
const LOCK_TIME_MS = 2 * 60 * 1000;
const DEMO_ACCOUNT_IDENTIFIER = "helena@hospital.test";

/* Authentication requirement: password is hashed, never stored in plaintext. */
let accountPasswordHash = await Bun.password.hash("Welcome!2025Heart", {
  algorithm: "bcrypt",
  cost: 10,
});

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

async function hashToken(token: string): Promise<string> {
  return Bun.password.hash(token, { algorithm: "bcrypt", cost: 10 });
}

async function verifyTokenHash(token: string, hash: string): Promise<boolean> {
  try {
    return await Bun.password.verify(token, hash);
  } catch {
    return false;
  }
}

function now(): number {
  return Date.now();
}

/* Input handling requirement: strict bounded plain-text validation. */
function cleanText(value: unknown, maxLength: number): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLength || /[\u0000-\u001f\u007f<>]/.test(trimmed)) return null;
  return trimmed;
}

function validIdentifier(value: unknown): string | null {
  const input = cleanText(value, 160);
  if (!input) return null;
  if (!/^[A-Za-z0-9@._+\- ]+$/.test(input)) return null;
  return input.toLowerCase();
}

function validPassword(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 128) return null;
  return value;
}

function passwordProblem(password: string): string | null {
  if (password.length < 12) return "Use at least 12 characters.";
  if (!/[a-z]/.test(password)) return "Include a lowercase letter.";
  if (!/[A-Z]/.test(password)) return "Include an uppercase letter.";
  if (!/[0-9]/.test(password)) return "Include a number.";
  if (!/[^A-Za-z0-9]/.test(password)) return "Include a symbol.";
  return null;
}

/* Session / CSRF requirement: random opaque HttpOnly session cookie and per-session CSRF token. */
function parseCookies(request: Request): Record<string, string> {
  const raw = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) result[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return result;
}

function createSession(): Session {
  const stamp = now();
  return {
    id: randomToken(32),
    csrf: randomToken(32),
    createdAt: stamp,
    expiresAt: stamp + SESSION_LIFETIME_MS,
    authenticated: false,
    privacyAccepted: false,
    loginFailures: 0,
    loginLockUntil: 0,
    recoveryRequests: [],
  };
}

function sessionFor(request: Request): { session: Session; isNew: boolean } {
  const sid = parseCookies(request).sid;
  const existing = sid ? sessions.get(sid) : undefined;
  if (existing && existing.expiresAt > now()) return { session: existing, isNew: false };
  if (sid) sessions.delete(sid);
  const session = createSession();
  sessions.set(session.id, session);
  return { session, isNew: true };
}

function cookieHeader(session: Session): string {
  return `sid=${session.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(
    SESSION_LIFETIME_MS / 1000,
  )}`;
}

/* HTTPS/security-misconfiguration requirements: strict security headers on every response. */
function securityHeaders(nonce?: string): Headers {
  const headers = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    Pragma: "no-cache",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Type": "application/json; charset=utf-8",
    CSP: nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`
      : "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  });
  return headers;
}

function json(data: unknown, session: Session, status = 200, isNew = false): Response {
  const headers = securityHeaders();
  if (isNew) headers.set("Set-Cookie", cookieHeader(session));
  return new Response(JSON.stringify(data), { status, headers });
}

function html(body: string, session: Session, isNew: boolean): Response {
  const nonce = randomToken(18);
  const headers = securityHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  if (isNew) headers.set("Set-Cookie", cookieHeader(session));
  return new Response(
    body.replaceAll("__NONCE__", nonce).replaceAll("__CSRF__", session.csrf),
    { status: 200, headers },
  );
}

function csrfValid(request: Request, session: Session): boolean {
  const token = request.headers.get("x-csrf-token") || "";
  return token.length > 20 && token === session.csrf;
}

async function bodyOf(request: Request): Promise<Record<string, unknown> | null> {
  try {
    if (!request.headers.get("content-type")?.includes("application/json")) return null;
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function genericCsrfFailure(session: Session, isNew: boolean): Response {
  return json({ ok: false, message: "Please refresh this page and try again." }, session, 403, isNew);
}

function currentRecord(session: Session): RecoveryRecord | undefined {
  const id = session.recovery?.recordId;
  return id ? recoveryRecords.get(id) : undefined;
}

function publicState(session: Session) {
  return {
    ok: true,
    csrf: session.csrf,
    authenticated: session.authenticated,
    privacyAccepted: session.privacyAccepted,
    recoveryStage: session.recovery?.stage || "start",
    canResume: Boolean(session.recovery && session.recovery.stage === "paused"),
  };
}

function removeExpired(): void {
  const stamp = now();
  for (const [id, session] of sessions) {
    if (session.expiresAt <= stamp) sessions.delete(id);
  }
  for (const [id, record] of recoveryRecords) {
    if (record.expiresAt + SESSION_LIFETIME_MS <= stamp) recoveryRecords.delete(id);
  }
}

/* Authorization requirement: every protected state change verifies session/server state. */
async function handleApi(request: Request, url: URL, session: Session, isNew: boolean): Promise<Response> {
  const path = url.pathname;

  if (request.method === "GET" && path === "/api/state") {
    return json(publicState(session), session, 200, isNew);
  }

  if (request.method !== "POST") {
    return json({ ok: false, message: "Not found." }, session, 404, isNew);
  }

  if (!csrfValid(request, session)) return genericCsrfFailure(session, isNew);
  const body = await bodyOf(request);
  if (!body) return json({ ok: false, message: "Please try again." }, session, 400, isNew);

  if (path === "/api/login") {
    const stamp = now();
    if (session.loginLockUntil > stamp) {
      return json(
        { ok: false, message: "Please take a short break, then try again." },
        session,
        429,
        isNew,
      );
    }
    const identifier = validIdentifier(body.identifier);
    const password = validPassword(body.password);
    let accepted = false;
    if (identifier && password && identifier === DEMO_ACCOUNT_IDENTIFIER) {
      accepted = await Bun.password.verify(password, accountPasswordHash);
    }
    if (!accepted) {
      session.loginFailures++;
      if (session.loginFailures >= 5) {
        session.loginFailures = 0;
        session.loginLockUntil = stamp + LOCK_TIME_MS;
      }
      return json(
        { ok: false, message: "The sign-in details were not accepted. Please check them and try again." },
        session,
        401,
        isNew,
      );
    }
    session.authenticated = true;
    session.loginFailures = 0;
    return json({ ok: true, next: session.privacyAccepted ? "/confirmation" : "/privacy" }, session, 200, isNew);
  }

  if (path === "/api/recovery-request") {
    const identifier = validIdentifier(body.identifier);
    if (!identifier) {
      return json({ ok: false, message: "Enter your email address or patient reference." }, session, 400, isNew);
    }

    const stamp = now();
    session.recoveryRequests = session.recoveryRequests.filter((time) => stamp - time < 10 * 60 * 1000);
    if (session.recoveryRequests.length >= 3) {
      return json(
        { ok: false, message: "Please take a short break before requesting another code." },
        session,
        429,
        isNew,
      );
    }
    session.recoveryRequests.push(stamp);

    const token = randomToken(32);
    const recordId = randomToken(20);
    const record: RecoveryRecord = {
      id: recordId,
      tokenHash: await hashToken(token),
      sessionId: session.id,
      accountExists: identifier === DEMO_ACCOUNT_IDENTIFIER,
      expiresAt: stamp + TOKEN_LIFETIME_MS,
      used: false,
      verificationAttempts: 0,
      lockUntil: 0,
      verified: false,
    };
    recoveryRecords.set(recordId, record);
    session.recovery = { recordId, stage: "requested" };

    /* Simulated delivery only; no external email/SMS request occurs. */
    console.log(`[SIMULATED DELIVERY] Recovery code created for current recovery session: ${token}`);
    return json(
      {
        ok: true,
        message: "If the details match an account, a recovery code has been prepared.",
        testToken: token,
      },
      session,
      200,
      isNew,
    );
  }

  if (path === "/api/recovery-verify") {
    const code = cleanText(body.code, 200);
    const record = currentRecord(session);
    const stamp = now();
    if (!record || record.sessionId !== session.id || !code) {
      return json({ ok: false, message: "That code cannot be used here. Request a new code and try again." }, session, 400, isNew);
    }
    if (record.lockUntil > stamp) {
      return json({ ok: false, message: "Please take a short break, then request a fresh code." }, session, 429, isNew);
    }
    if (record.used || record.verified || record.expiresAt <= stamp) {
      return json({ ok: false, message: "That code is no longer available. You can request a new one." }, session, 400, isNew);
    }
    const correct = await verifyTokenHash(code, record.tokenHash);
    if (!correct) {
      record.verificationAttempts++;
      if (record.verificationAttempts >= 5) record.lockUntil = stamp + LOCK_TIME_MS;
      return json({ ok: false, message: "That code was not accepted. Please check it and try again." }, session, 400, isNew);
    }
    record.verified = true;
    record.used = true; // single-use once successfully checked
    session.recovery!.stage = "password";
    return json({ ok: true, next: "/password" }, session, 200, isNew);
  }

  if (path === "/api/password") {
    const record = currentRecord(session);
    const password = validPassword(body.password);
    const confirmation = validPassword(body.confirmation);
    if (!record || record.sessionId !== session.id || !record.verified || session.recovery?.stage !== "password") {
      return json({ ok: false, message: "Please complete the recovery code step first." }, session, 403, isNew);
    }
    if (!password || !confirmation) {
      return json({ ok: false, message: "Enter your new password twice." }, session, 400, isNew);
    }
    const problem = passwordProblem(password);
    if (problem) return json({ ok: false, message: problem }, session, 400, isNew);
    if (password !== confirmation) {
      return json({ ok: false, message: "The two passwords do not match." }, session, 400, isNew);
    }
    if (!record.accountExists) {
      return json({ ok: false, message: "We could not complete this request. Please contact the hospital support team." }, session, 400, isNew);
    }

    accountPasswordHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 10 });
    session.authenticated = true;
    session.recovery!.stage = "privacy";
    console.log("[SIMULATED SECURITY] Password replaced using bcrypt hash.");
    return json({ ok: true, next: "/privacy" }, session, 200, isNew);
  }

  if (path === "/api/privacy-accept") {
    if (!session.authenticated || session.recovery?.stage !== "privacy") {
      return json({ ok: false, message: "Please sign in and complete recovery before accepting conditions." }, session, 403, isNew);
    }
    if (body.accept !== true) {
      return json({ ok: false, message: "Please confirm that you have read the updated privacy conditions." }, session, 400, isNew);
    }
    session.privacyAccepted = true;
    session.recovery!.stage = "confirmed";
    console.log("[SIMULATED CONFIRMATION] Privacy conditions accepted by authenticated session.");
    return json({ ok: true, next: "/confirmation" }, session, 200, isNew);
  }

  if (path === "/api/pause") {
    if (!session.recovery || ["confirmed", "start"].includes(session.recovery.stage)) {
      return json({ ok: false, message: "There is no recovery task to pause." }, session, 400, isNew);
    }
    if (session.recovery.stage !== "paused") {
      session.recovery.pausedFrom = session.recovery.stage;
      session.recovery.stage = "paused";
    }
    return json({ ok: true, next: "/pause" }, session, 200, isNew);
  }

  if (path === "/api/resume") {
    if (!session.recovery || session.recovery.stage !== "paused") {
      return json({ ok: false, message: "There is no paused task to resume." }, session, 400, isNew);
    }
    session.recovery.stage = session.recovery.pausedFrom || "requested";
    delete session.recovery.pausedFrom;
    return json({ ok: true, next: `/${session.recovery.stage === "requested" ? "verify" : session.recovery.stage}` }, session, 200, isNew);
  }

  return json({ ok: false, message: "Not found." }, session, 404, isNew);
}

/* Accessibility requirement: stable, calm SPA with persistent progress/help and no countdowns. */
const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="__CSRF__">
<title>Hospital account recovery</title>
<style nonce="__NONCE__">
:root{--ink:#173447;--blue:#075a86;--pale:#eef7fa;--line:#bed3dc;--focus:#f4a900;--good:#176440;--alert:#8a3e00}
*{box-sizing:border-box}body{margin:0;background:#f7fafb;color:var(--ink);font:18px/1.55 Arial,sans-serif}
header{background:#fff;border-bottom:1px solid var(--line)}.bar{max-width:1050px;margin:auto;padding:18px 24px;display:flex;justify-content:space-between;gap:18px;align-items:center}
.brand{font-weight:700;font-size:1.16rem}.brand span{color:var(--blue)}a{color:#064f78}button,input{font:inherit}button{border:0;border-radius:7px;padding:11px 18px;background:var(--blue);color:white;font-weight:700;cursor:pointer}button:hover{background:#034869}button.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue)}button:focus,a:focus,input:focus{outline:3px solid var(--focus);outline-offset:3px}
main{max-width:1050px;margin:30px auto;padding:0 24px}.layout{display:grid;grid-template-columns:minmax(0,680px) 280px;gap:28px}.card,.help,.logs{background:#fff;border:1px solid var(--line);border-radius:10px;padding:25px}.help{align-self:start;background:var(--pale)}h1{line-height:1.2;margin:0 0 12px;font-size:1.65rem}h2{font-size:1.1rem;margin-top:0}.lead{margin:0 0 22px}.next{border-left:5px solid var(--blue);background:var(--pale);padding:12px 15px;margin:18px 0}.progress{display:flex;gap:5px;margin:0 0 23px}.progress span{height:8px;flex:1;border-radius:9px;background:#d8e4e8}.progress span.on{background:var(--blue)}label{display:block;font-weight:700;margin:15px 0 5px}input[type=text],input[type=password]{width:100%;padding:11px;border:2px solid #7594a2;border-radius:6px;background:#fff}.actions{display:flex;flex-wrap:wrap;gap:12px;margin-top:23px}.small{font-size:.9rem}.notice{padding:12px 14px;border-radius:7px;margin:14px 0}.notice.error{background:#fff1e9;color:#722e00;border-left:5px solid var(--alert)}.notice.success{background:#eaf8ef;color:#145c39;border-left:5px solid var(--good)}.policy{padding:14px 17px;background:#f4f7f8;border-radius:7px}.policy ul{margin:7px 0}.checkbox{display:flex;gap:10px;align-items:flex-start;font-weight:normal}.checkbox input{width:22px;height:22px;margin-top:4px}.logs{margin-top:25px;padding:17px}.logs h2{margin-bottom:5px}.logs pre{white-space:pre-wrap;word-break:break-word;margin:0;max-height:180px;overflow:auto;font:13px/1.4 monospace;color:#234}.token{font-family:monospace;word-break:break-all;background:#f5f5f5;padding:10px;border-radius:5px}.toplink{white-space:nowrap}@media(max-width:760px){.layout{grid-template-columns:1fr}.bar{padding:14px 18px}main{padding:0 15px;margin-top:20px}}
</style>
</head>
<body>
<header><div class="bar"><div class="brand">Hospital <span>Account Support</span></div><a class="toplink" href="#/help">Help and safe advice</a></div></header>
<main id="app" aria-live="polite">Loading your recovery page…</main>
<script nonce="__NONCE__">
(() => {
"use strict";
const csrf = document.querySelector('meta[name="csrf-token"]').content;
const app = document.getElementById("app");
let state = {authenticated:false,privacyAccepted:false,recoveryStage:"start"};
let testToken = "";

function log(message) {
  console.log(message);
  const area = document.getElementById("log-output");
  if (area) { area.textContent = (area.textContent + message + "\\n").slice(-5000); }
}
async function api(path, data) {
  const response = await fetch(path, {method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data || {})});
  const payload = await response.json().catch(() => ({ok:false,message:"Please try again."}));
  return payload;
}
async function loadState() {
  const response = await fetch("/api/state", {credentials:"same-origin"});
  state = await response.json();
}
function route() {
  const raw = location.hash.slice(1) || "/login";
  const path = raw.split("?")[0];
  const known = ["/login","/recover","/verify","/password","/privacy","/confirmation","/pause","/help"];
  return known.includes(path) ? path : "/login";
}
function go(path) {
  const known = ["/login","/recover","/verify","/password","/privacy","/confirmation","/pause","/help"];
  location.hash = known.includes(path) ? "#" + path : "#/login";
}
function tokenFromHash() {
  const match = location.hash.match(/[?&]token=([^&]+)/);
  if (!match) return "";
  try { return decodeURIComponent(match[1]).slice(0,200); } catch { return ""; }
}
function progress(active) {
  const labels = ["Request code","Check code","New password","Privacy"];
  return '<div class="progress" role="img" aria-label="Recovery progress: step '+active+' of 4">'+labels.map((x,i)=>'<span class="'+(i < active ? "on":"")+'" title="'+x+'"></span>').join("")+'</div>';
}
function help() {
 return '<aside class="help" aria-label="Help and safe advice"><h2>Need help?</h2><p>It is okay to pause. Your progress is saved in this browser session.</p><p><strong>Stay safe:</strong> hospital staff will never ask you to share your password or recovery code by email, phone, or text.</p><p class="small">For account support, use the hospital’s known phone number from your care paperwork.</p><a href="#/help">Read safe recovery advice</a></aside>';
}
function logs() { return '<section class="logs" aria-label="Testing logs"><h2>Logs</h2><p class="small">Simulated delivery and verification messages appear here.</p><pre id="log-output"></pre></section>'; }
function message(text, kind) { return text ? '<div class="notice '+(kind||"error")+'" role="status">'+text+'</div>' : ""; }
function shell(content, step) {
 return '<div class="layout"><section class="card">'+(step ? progress(step):"")+content+'</section>'+help()+'</div>'+logs();
}
function render(note="", kind="") {
 const r = route();
 if (r === "/login") app.innerHTML = shell('<h1>Sign in to your hospital account</h1><p class="lead">Sign in to review and accept the updated privacy conditions.</p>'+message(note,kind)+'<form id="login-form"><label for="login-id">Email address or patient reference</label><input id="login-id" name="identifier" type="text" autocomplete="username" required><label for="login-password">Password</label><input id="login-password" name="password" type="password" autocomplete="current-password" required><div class="actions"><button>Sign in</button><a href="#/recover">Forgot password?</a></div></form>');
 else if (r === "/recover") app.innerHTML = shell('<h1>Reset your password</h1><p class="lead">Step 1: Tell us the email address or patient reference connected to your account.</p><div class="next"><strong>Next:</strong> We will prepare a recovery code without confirming account details.</div>'+message(note,kind)+'<form id="recover-form"><label for="recover-id">Email address or patient reference</label><input id="recover-id" name="identifier" type="text" autocomplete="username" required><div class="actions"><button>Prepare recovery code</button><a href="#/login">Back to sign in</a></div></form>',1);
 else if (r === "/verify") {
   const linked = tokenFromHash();
   app.innerHTML = shell('<h1>Check your recovery code</h1><p class="lead">Step 2: Enter the code you received. You can use the secure simulated link or type it here.</p><div class="next"><strong>Next:</strong> After the code is accepted, choose a new password.</div>'+message(note,kind)+'<form id="verify-form"><label for="code">Recovery code</label><input id="code" name="code" type="text" autocomplete="one-time-code" required><div class="actions"><button>Check code</button><button type="button" class="secondary" data-pause>Pause and return later</button></div></form>',2);
   if (linked) document.getElementById("code").value = linked;
 }
 else if (r === "/password") app.innerHTML = shell('<h1>Create a new password</h1><p class="lead">Step 3: Choose a password that is hard for other people to guess.</p><div class="policy"><strong>Your password needs:</strong><ul><li>At least 12 characters</li><li>An uppercase and lowercase letter</li><li>A number and a symbol</li></ul></div>'+message(note,kind)+'<form id="password-form"><label for="new-password">New password</label><input id="new-password" name="password" type="password" autocomplete="new-password" required><label for="confirm-password">Type it again</label><input id="confirm-password" name="confirmation" type="password" autocomplete="new-password" required><div class="actions"><button>Save new password</button><button type="button" class="secondary" data-pause>Pause and return later</button></div></form>',3);
 else if (r === "/privacy") app.innerHTML = shell('<h1>Review updated privacy conditions</h1><p class="lead">Step 4: Your password has been updated. Please confirm the privacy conditions so hospital authorities can continue with appointment booking.</p><div class="next"><strong>Next:</strong> Confirm below and we will show that booking can proceed.</div>'+message(note,kind)+'<form id="privacy-form"><label class="checkbox" for="accept"><input id="accept" type="checkbox" name="accept"><span>I have read and accept the updated privacy conditions for my healthcare account.</span></label><div class="actions"><button>Accept and continue</button><button type="button" class="secondary" data-pause>Pause and return later</button></div></form>',4);
 else if (r === "/confirmation") app.innerHTML = shell('<h1>Privacy conditions accepted</h1><div class="notice success" role="status">Thank you. Hospital authorities can now proceed with booking the medication review appointment.</div><p class="lead">You have completed this task. You may safely close this page.</p><div class="actions"><a href="#/login">Return to sign in</a></div>');
 else if (r === "/pause") app.innerHTML = shell('<h1>Your recovery is paused</h1><p class="lead">Nothing has been lost. When you are ready, continue from the same step.</p><div class="next"><strong>Next:</strong> Select “Continue recovery” whenever you feel ready.</div>'+message(note,kind)+'<div class="actions"><button id="resume">Continue recovery</button><a href="#/help">Get help</a></div>');
 else app.innerHTML = shell('<h1>Help and safe recovery advice</h1><p class="lead">Take one step at a time. There is no rush.</p><h2>Keep your account safe</h2><ul><li>Never share your password or recovery code with anyone.</li><li>Do not follow login links from unexpected messages.</li><li>Use the hospital phone number you already know if you need support.</li></ul><p>We do not show account details on this page.</p><div class="actions"><a href="#/recover">Start password recovery</a><a href="#/login">Sign in</a></div>');
 const logArea = document.getElementById("log-output");
 if (logArea && testToken) logArea.textContent = "[SIMULATED DELIVERY] Current browser test code: "+testToken+"\\n";
}
document.addEventListener("submit", async (event) => {
 const form = event.target;
 if (!(form instanceof HTMLFormElement)) return;
 event.preventDefault();
 const data = Object.fromEntries(new FormData(form).entries());
 if (form.id === "login-form") {
   const out = await api("/api/login", data); if (out.ok) go(out.next); else render(out.message,"error");
 }
 if (form.id === "recover-form") {
   const out = await api("/api/recovery-request", data);
   if (out.ok) { testToken=out.testToken; log("[SIMULATED DELIVERY] Current browser recovery code: "+testToken); go("/verify"); }
   else render(out.message,"error");
 }
 if (form.id === "verify-form") {
   const out = await api("/api/recovery-verify", data); if(out.ok) go(out.next); else render(out.message,"error");
 }
 if (form.id === "password-form") {
   const out = await api("/api/password", data); if(out.ok) go(out.next); else render(out.message,"error");
 }
 if (form.id === "privacy-form") {
   const out = await api("/api/privacy-accept", {accept: form.accept.checked}); if(out.ok) go(out.next); else render(out.message,"error");
 }
});
document.addEventListener("click", async (event) => {
 const target = event.target;
 if (!(target instanceof HTMLElement)) return;
 if (target.matches("[data-pause]")) { const out=await api("/api/pause",{}); if(out.ok) go(out.next); else render(out.message,"error"); }
 if (target.id === "resume") { const out=await api("/api/resume",{}); if(out.ok) go(out.next); else render(out.message,"error"); }
});
window.addEventListener("hashchange", () => render());
(async () => { try { await loadState(); render(); } catch { app.textContent="This secure page could not be loaded. Please refresh and try again."; } })();
})();
</script>
</body>
</html>`;

setInterval(removeExpired, 10 * 60 * 1000).unref();

/*
  HTTPS requirement: this server only listens with TLS. Plain HTTP is not served.
  Certificates are expected at certs/cert.pem and certs/key.pem as specified.
*/
Bun.serve({
  hostname: "localhost",
  port: 3000,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      const { session, isNew } = sessionFor(request);

      if (url.pathname.startsWith("/api/")) {
        return await handleApi(request, url, session, isNew);
      }

      if (request.method === "GET") {
        return html(page, session, isNew);
      }

      return json({ ok: false, message: "Not found." }, session, 404, isNew);
    } catch {
      /* No stack traces/debug data are disclosed. */
      const fallback = createSession();
      return json({ ok: false, message: "Please try again." }, fallback, 500, true);
    }
  },
});

console.log("Secure Hospital Account Support is running at https://localhost:3000");
