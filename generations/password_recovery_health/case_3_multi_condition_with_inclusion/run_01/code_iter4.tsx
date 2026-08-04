
import { existsSync } from "node:fs";

/*
  Password Recovery System
  Single-file Bun HTTPS server and browser SPA.
  Run with: bun app.ts
*/

const HTTPS_PORT = Number(process.env.HTTPS_PORT || 3000);
const HTTP_PORT = Number(process.env.HTTP_PORT || 3001);
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";

const SESSION_COOKIE = "__Host-recovery_sid";
const TOKEN_LIFETIME_MS = 10 * 60 * 1000;
const MFA_LIFETIME_MS = 10 * 60 * 1000;
const MFA_LOCKOUT_MS = 15 * 60 * 1000;
const MFA_VERIFY_LIMIT = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 15 * 60 * 1000;
const RESET_WINDOW_MS = 15 * 60 * 1000;
const RESET_LIMIT = 3;
const VERIFY_LIMIT = 5;

type WorkflowStage = "start" | "code" | "password" | "complete" | "signin" | "mfa" | "privacy" | "appointment";

type MockAccount = {
  id: string;
  approvedRecoveryContact: string;
  passwordHash: string;
  signInFailures: number;
  signInWindow: number;
  signInLockedUntil: number;
  resetRequests: number;
  resetRequestWindow: number;
  resetVerifyFailures: number;
  resetVerifyWindow: number;
  resetVerifyLockedUntil: number;
};

type ResetRecord = {
  token: string;
  accountId: string;
  sessionId: string;
  expiresAt: number;
  verified: boolean;
  used: boolean;
};

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  authenticated: boolean;
  privacyAccepted: boolean;
  mfaPending: boolean;
  mfaCode?: string;
  mfaExpiresAt?: number;
  mfaFailures: number;
  mfaLockedUntil: number;
  resetToken?: string;

  /* Requirement: session-backed, non-secret workflow persistence. */
  workflowStage: WorkflowStage;
  paused: boolean;
  pendingMfaStage: boolean;
};

const mockAccount: MockAccount = {
  id: "mock-account-1",
  approvedRecoveryContact: "helena.recovery@hospital.test",
  passwordHash: await Bun.password.hash("HospitalDemo!2026", { algorithm: "argon2id" }),
  signInFailures: 0,
  signInWindow: Date.now(),
  signInLockedUntil: 0,
  resetRequests: 0,
  resetRequestWindow: Date.now(),
  resetVerifyFailures: 0,
  resetVerifyWindow: Date.now(),
  resetVerifyLockedUntil: 0,
};

const sessions = new Map<string, Session>();
const resetRecords = new Map<string, ResetRecord>();

function randomHex(bytes = 32): string {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return Buffer.from(data).toString("hex");
}

function randomMfaCode(): string {
  const values = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / 1_000_000) * 1_000_000;
  do crypto.getRandomValues(values); while (values[0] >= limit);
  return String(values[0] % 1_000_000).padStart(6, "0");
}

function newSession(): Session {
  return {
    id: randomHex(32),
    csrf: randomHex(32),
    createdAt: Date.now(),
    authenticated: false,
    privacyAccepted: false,
    mfaPending: false,
    mfaFailures: 0,
    mfaLockedUntil: 0,
    workflowStage: "start",
    paused: false,
    pendingMfaStage: false,
  };
}

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  const header = request.headers.get("cookie") || "";
  for (const pair of header.split(";")) {
    const index = pair.indexOf("=");
    if (index > 0) {
      const key = pair.slice(0, index).trim();
      const value = pair.slice(index + 1).trim();
      if (/^[A-Za-z0-9_-]+$/.test(key) && /^[A-Za-z0-9_-]+$/.test(value)) result[key] = value;
    }
  }
  return result;
}

function getSession(request: Request, create = false): { session?: Session; isNew: boolean } {
  const sid = parseCookies(request)[SESSION_COOKIE];
  if (sid && sessions.has(sid)) return { session: sessions.get(sid), isNew: false };
  if (!create) return { isNew: false };
  const session = newSession();
  sessions.set(session.id, session);
  return { session, isNew: true };
}

function cleanupState(): void {
  const oldestSession = Date.now() - 24 * 60 * 60 * 1000;
  for (const [id, session] of sessions) if (session.createdAt < oldestSession) sessions.delete(id);
  for (const [token, record] of resetRecords) {
    if (record.expiresAt < Date.now() || record.used) resetRecords.delete(token);
  }
}

function secureHeaders(nonce?: string): Headers {
  const headers = new Headers();
  headers.set("Content-Security-Policy", [
    "default-src 'none'",
    `script-src 'nonce-${nonce || "none"}'`,
    `style-src 'nonce-${nonce || "none"}'`,
    "connect-src 'self'",
    "img-src 'self' data:",
    "font-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
  ].join("; "));
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Cache-Control", "no-store, max-age=0");
  return headers;
}

function sessionCookie(session: Session): string {
  return `${SESSION_COOKIE}=${session.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=86400`;
}

function json(data: unknown, status = 200, session?: Session): Response {
  const headers = secureHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (session) headers.append("Set-Cookie", sessionCookie(session));
  return new Response(JSON.stringify(data), { status, headers });
}

function safeError(message = "We could not complete that step. Please try again.", status = 400): Response {
  return json({ ok: false, message }, status);
}

async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 12_000) return null;
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function stringField(body: Record<string, unknown>, field: string, max = 300): string | null {
  const value = body[field];
  return typeof value === "string" && value.length <= max ? value : null;
}

/* Requirement 1: session-unique CSRF token required for every sensitive POST. */
function csrfValid(session: Session | undefined, body: Record<string, unknown> | null): boolean {
  if (!session || !body || typeof body.csrf !== "string") return false;
  const csrf = body.csrf;
  return csrf.length === session.csrf.length &&
    crypto.timingSafeEqual(new TextEncoder().encode(csrf), new TextEncoder().encode(session.csrf));
}

function validEmailShape(value: string): boolean {
  return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validToken(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
}

function validMfaCode(value: string): boolean {
  return /^[0-9]{6}$/.test(value);
}

function validWorkflowStage(value: string): value is WorkflowStage {
  return ["start", "code", "password", "complete", "signin", "mfa", "privacy", "appointment"].includes(value);
}

function sameText(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(new TextEncoder().encode(left), new TextEncoder().encode(right));
}

function approvedContact(value: string): boolean {
  return sameText(value.trim().toLowerCase(), mockAccount.approvedRecoveryContact);
}

function passwordProblem(password: string): string | null {
  if (password.length < 12 || password.length > 128) return "Use 12 to 128 characters.";
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9\s]/.test(password)) {
    return "Use uppercase, lowercase, a number, and a symbol.";
  }
  if (/\s/.test(password)) return "Do not use spaces.";
  if (/^(password|hospital|welcome|123456)/i.test(password)) return "Choose a less predictable password.";
  return null;
}

/*
  Requirements 1 and 4: a reset record is valid only for its intended account,
  original session, expiry, unused state, and (where needed) verified state.
*/
function currentReset(session: Session, token?: string, requireVerified = false): ResetRecord | undefined {
  if (!session.resetToken) return undefined;
  const record = resetRecords.get(session.resetToken);
  if (!record || record.used || record.expiresAt < Date.now()) return undefined;
  if (record.accountId !== mockAccount.id || record.sessionId !== session.id) return undefined;
  if (token && (!validToken(token) || !sameText(record.token, token))) return undefined;
  if (requireVerified && !record.verified) return undefined;
  return record;
}

function clearSessionReset(session: Session): void {
  if (session.resetToken) resetRecords.delete(session.resetToken);
  session.resetToken = undefined;
}

function resetRequestAvailable(now: number): boolean {
  if (now - mockAccount.resetRequestWindow > RESET_WINDOW_MS) {
    mockAccount.resetRequestWindow = now;
    mockAccount.resetRequests = 0;
  }
  return mockAccount.resetRequests < RESET_LIMIT;
}

function resetVerificationAvailable(now: number): boolean {
  if (now - mockAccount.resetVerifyWindow > RESET_WINDOW_MS) {
    mockAccount.resetVerifyWindow = now;
    mockAccount.resetVerifyFailures = 0;
  }
  return mockAccount.resetVerifyLockedUntil <= now && mockAccount.resetVerifyFailures < VERIFY_LIMIT;
}

function registerResetVerificationFailure(now: number): void {
  if (now - mockAccount.resetVerifyWindow > RESET_WINDOW_MS) {
    mockAccount.resetVerifyWindow = now;
    mockAccount.resetVerifyFailures = 0;
  }
  mockAccount.resetVerifyFailures++;
  if (mockAccount.resetVerifyFailures >= VERIFY_LIMIT) mockAccount.resetVerifyLockedUntil = now + LOCKOUT_MS;
}

function codeMatches(expected: string, actual: string): boolean {
  return validMfaCode(actual) && sameText(expected, actual);
}

function allowedSavedStage(session: Session, stage: WorkflowStage): boolean {
  if (stage === "code") return !!currentReset(session);
  if (stage === "password") return !!currentReset(session, undefined, true);
  if (stage === "mfa") return session.mfaPending && session.pendingMfaStage;
  if (stage === "privacy" || stage === "appointment") return session.authenticated;
  return true;
}

/* No request input is interpolated into HTML; browser rendering uses textContent only. */
async function handleApi(request: Request, pathname: string): Promise<Response> {
  cleanupState();
  const { session } = getSession(request, false);
  const body = await readBody(request);
  if (!session || !csrfValid(session, body)) {
    return safeError("Your secure form has expired. Refresh the page and try again.");
  }

  /*
    Requirement: paused state is saved server-side. Only state retrieval and
    resume/save requests are accepted while paused.
  */
  if (session.paused && pathname !== "/api/recovery/state" && pathname !== "/api/workflow") {
    return safeError("Your place is paused and saved. Select Resume saved place before continuing.");
  }

  if (pathname === "/api/recovery/state") {
    const record = currentReset(session);
    if (!record) {
      clearSessionReset(session);
      if (session.workflowStage === "code" || session.workflowStage === "password") session.workflowStage = "start";
    }

    if (session.workflowStage === "mfa" && (!session.mfaPending || !session.mfaCode || !session.mfaExpiresAt || session.mfaExpiresAt < Date.now())) {
      session.mfaPending = false;
      session.pendingMfaStage = false;
      session.mfaCode = undefined;
      session.mfaExpiresAt = undefined;
      session.workflowStage = "signin";
    }

    return json({
      ok: true,
      stage: session.workflowStage,
      paused: session.paused,
      pendingMfaStage: session.pendingMfaStage,
      recoveryStage: record ? (record.verified ? "password" : "code") : "start",
      token: record?.token,
      expiresInMinutes: record ? Math.max(1, Math.ceil((record.expiresAt - Date.now()) / 60000)) : undefined,
    });
  }

  /* Requirement: CSRF-protected non-secret workflow-state persistence. */
  if (pathname === "/api/workflow") {
    const requestedStage = stringField(body, "stage", 20);
    const requestedPaused = body.paused;
    if (!requestedStage || !validWorkflowStage(requestedStage) || typeof requestedPaused !== "boolean") {
      return safeError("We could not save your place. Please try again.");
    }
    if (!allowedSavedStage(session, requestedStage)) {
      return safeError("That saved step is no longer available. We returned you to a safe step.");
    }
    session.workflowStage = requestedStage;
    session.paused = requestedPaused;
    return json({
      ok: true,
      stage: session.workflowStage,
      paused: session.paused,
      message: session.paused ? "Your current step has been saved and paused." : "Your saved step has been resumed.",
      event: session.paused ? "workflow_paused_saved" : "workflow_resumed",
    });
  }

  if (pathname === "/api/reset/request") {
    const contact = stringField(body, "contact");
    const generic = "If the details match an account, a recovery code has been prepared.";
    const authorized = !!contact && validEmailShape(contact) && approvedContact(contact);
    const now = Date.now();

    if (!authorized || !resetRequestAvailable(now) || !resetVerificationAvailable(now)) {
      return json({ ok: true, message: generic, event: "recovery_request_processed" });
    }

    clearSessionReset(session);
    mockAccount.resetRequests++;
    const token = randomHex(32);
    const record: ResetRecord = {
      token,
      accountId: mockAccount.id,
      sessionId: session.id,
      expiresAt: now + TOKEN_LIFETIME_MS,
      verified: false,
      used: false,
    };
    resetRecords.set(token, record);
    session.resetToken = token;
    session.workflowStage = "code";

    return json({
      ok: true,
      message: generic,
      event: "mock_recovery_delivery_prepared",
      mockToken: token,
      expiresInMinutes: 10,
    });
  }

  if (pathname === "/api/reset/verify") {
    const submittedToken = stringField(body, "token", 80);
    const now = Date.now();

    /*
      Requirement task: first retrieve only the session-bound active record,
      enforce lockout before comparison, then record every malformed/invalid
      submission before returning an error. Token lookup never uses user input.
    */
    const activeRecord = currentReset(session);
    if (!resetVerificationAvailable(now)) {
      return safeError("Too many code attempts were made. Request a new code when you are ready.");
    }

    const submittedIsValid = !!submittedToken &&
      validToken(submittedToken) &&
      !!activeRecord &&
      sameText(activeRecord.token, submittedToken);

    if (!submittedIsValid) {
      registerResetVerificationFailure(now);
      return safeError("That recovery code is not available. Request a new code and try again.");
    }

    activeRecord.verified = true;
    mockAccount.resetVerifyFailures = 0;
    mockAccount.resetVerifyWindow = now;
    session.workflowStage = "password";
    return json({ ok: true, message: "Code confirmed. You can now choose a new password.", event: "recovery_code_verified" });
  }

  if (pathname === "/api/reset/password") {
    const token = stringField(body, "token", 80);
    const password = stringField(body, "password", 130);
    const record = token ? currentReset(session, token, true) : undefined;
    if (!token || !password || !record) {
      return safeError("Your confirmed recovery step is no longer available. Start again when ready.");
    }
    const problem = passwordProblem(password);
    if (problem) return json({ ok: false, message: problem }, 400);

    mockAccount.passwordHash = await Bun.password.hash(password, { algorithm: "argon2id" });
    record.used = true;
    resetRecords.delete(record.token);
    session.resetToken = undefined;
    session.workflowStage = "complete";
    return json({
      ok: true,
      message: "Your password has been changed. Sign in when you are ready.",
      event: "mock_password_replacement_completed",
    });
  }

  if (pathname === "/api/signin") {
    const identifier = stringField(body, "identifier");
    const password = stringField(body, "password", 130);
    const now = Date.now();

    if (mockAccount.signInLockedUntil > now) {
      return safeError("Sign-in is temporarily paused for safety. Please return later.");
    }
    if (now - mockAccount.signInWindow > LOGIN_WINDOW_MS) {
      mockAccount.signInWindow = now;
      mockAccount.signInFailures = 0;
    }

    const validIdentifier = !!identifier && validEmailShape(identifier) && approvedContact(identifier);
    const passwordMatches = !!password && await Bun.password.verify(password, mockAccount.passwordHash);
    if (!validIdentifier || !passwordMatches) {
      mockAccount.signInFailures++;
      if (mockAccount.signInFailures >= 5) mockAccount.signInLockedUntil = now + LOCKOUT_MS;
      return safeError("We could not sign you in with those details.");
    }

    mockAccount.signInFailures = 0;
    session.authenticated = false;
    session.privacyAccepted = false;
    session.mfaPending = true;
    session.pendingMfaStage = true;
    session.mfaFailures = 0;
    session.mfaLockedUntil = 0;
    session.mfaCode = randomMfaCode();
    session.mfaExpiresAt = now + MFA_LIFETIME_MS;
    session.workflowStage = "mfa";

    return json({
      ok: true,
      message: "A verification code is ready for this sign-in step.",
      event: "mock_mfa_delivery_prepared",
      mockMfaCode: session.mfaCode,
      expiresInMinutes: 10,
    });
  }

  if (pathname === "/api/mfa") {
    const now = Date.now();
    const code = stringField(body, "code", 12);
    if (session.mfaLockedUntil > now) {
      return safeError("This verification step is temporarily paused for safety. Restart sign-in later.");
    }
    if (!session.mfaPending || !session.mfaCode || !session.mfaExpiresAt || session.mfaExpiresAt < now) {
      session.mfaPending = false;
      session.pendingMfaStage = false;
      session.mfaCode = undefined;
      session.workflowStage = "signin";
      return safeError("That verification step has expired. Restart sign-in when you are ready.");
    }
    if (!code || !codeMatches(session.mfaCode, code)) {
      session.mfaFailures++;
      if (session.mfaFailures >= MFA_VERIFY_LIMIT) {
        session.mfaPending = false;
        session.pendingMfaStage = false;
        session.mfaCode = undefined;
        session.mfaExpiresAt = undefined;
        session.mfaLockedUntil = now + MFA_LOCKOUT_MS;
        session.workflowStage = "signin";
        return safeError("Too many verification attempts were made. For safety, restart sign-in after the pause.");
      }
      return safeError(`That verification code could not be confirmed. You have ${MFA_VERIFY_LIMIT - session.mfaFailures} attempt(s) remaining.`);
    }
    session.mfaPending = false;
    session.pendingMfaStage = false;
    session.mfaCode = undefined;
    session.mfaExpiresAt = undefined;
    session.mfaFailures = 0;
    session.authenticated = true;
    session.workflowStage = "privacy";
    return json({ ok: true, message: "Sign-in confirmed.", event: "mock_signin_verified" });
  }

  if (pathname === "/api/privacy") {
    if (!session.authenticated) return json({ ok: false, message: "Please sign in to continue." }, 401);
    session.privacyAccepted = true;
    session.workflowStage = "appointment";
    return json({ ok: true, message: "The updated privacy statement has been accepted.", event: "mock_privacy_accepted" });
  }

  if (pathname === "/api/appointment") {
    if (!session.authenticated) return json({ ok: false, message: "Please sign in to continue." }, 401);
    if (!session.privacyAccepted) {
      return json({ ok: false, message: "Please accept the updated privacy statement before requesting an appointment." }, 403);
    }
    session.workflowStage = "appointment";
    return json({ ok: true, message: "Your medication review appointment request is confirmed.", event: "mock_appointment_confirmed" });
  }

  return json({ ok: false, message: "That request is not available." }, 404);
}

function page(nonce: string, csrf: string, initialStage: WorkflowStage, initiallyPaused: boolean): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
:root{color-scheme:light;--ink:#17324d;--blue:#075b9d;--pale:#edf6fb;--line:#c9d8e4;--ok:#176b46}*{box-sizing:border-box}body{margin:0;background:#f6f8fa;color:#172431;font:18px/1.55 Arial,sans-serif}header{background:#fff;border-bottom:4px solid var(--blue);padding:1rem max(1.25rem,calc((100% - 920px)/2))}header strong,h1,h2{color:var(--ink)}main,footer{max-width:920px;margin:0 auto;padding:1.25rem}.layout{display:grid;grid-template-columns:minmax(0,1fr) 250px;gap:1.25rem}.card,aside{background:#fff;border:1px solid var(--line);border-radius:10px;padding:1.35rem}.logs-card{margin-top:1.25rem}h1{font-size:1.7rem;line-height:1.25;margin:.1rem 0 .75rem}h2{font-size:1.15rem;margin:1rem 0 .4rem}p{margin:.55rem 0}label{display:block;font-weight:bold;margin-top:1rem}input{width:100%;max-width:510px;font:inherit;padding:.65rem;border:2px solid #71869a;border-radius:6px}input:focus,button:focus{outline:3px solid #f4b63f;outline-offset:2px}button{display:inline-block;margin:1rem .55rem 0 0;border:0;border-radius:6px;padding:.7rem 1rem;background:var(--blue);color:#fff;font:inherit;font-weight:bold;cursor:pointer}button.secondary{background:#e4edf3;color:#17324d}button:disabled,input:disabled{opacity:.55;cursor:not-allowed}.notice{margin:1rem 0;padding:.8rem;border-left:5px solid var(--blue);background:var(--pale)}.success{border-left-color:var(--ok);background:#eff9f3}.error{border-left-color:#9b2525;background:#fff1f1}.progress{padding:0;list-style:none;margin:.5rem 0 1rem}.progress li{padding:.38rem .45rem;border-left:4px solid #bdcbd6}.progress li.current{border-left-color:var(--blue);background:var(--pale);font-weight:bold}.progress li.done{border-left-color:var(--ok)}.small{font-size:.9rem}details{margin-top:1rem;border-top:1px solid var(--line);padding-top:.7rem}#logs{min-height:5rem;max-height:10rem;overflow:auto;white-space:pre-wrap;background:#102331;color:#e7f4fa;padding:.65rem;font:14px/1.4 monospace;border-radius:5px}.paused-banner{font-weight:bold}footer{padding-top:0;padding-bottom:2rem;font-size:.9rem}@media(max-width:700px){.layout{grid-template-columns:1fr}aside{order:-1}}
</style>
</head>
<body>
<header><strong>Hospital account support</strong></header>
<main>
<div class="layout">
<section class="card" aria-labelledby="page-title"><div id="app" aria-live="polite"></div></section>
<aside aria-label="Your progress and help">
<h2>Your progress</h2><ol class="progress" id="progress"></ol>
<p class="small"><strong>Take your time:</strong> You may proceed at your own pace and pause here. For safety, recovery and verification codes expire after 10 minutes; you can request another code if needed.</p>
<button class="secondary" id="pauseButton" type="button">Pause and save place</button>
<details open><summary><strong>Help and safe sign-in</strong></summary><p class="small">Never share your password or verification code by email, phone, or text. Hospital staff will not ask for it.</p><p class="small">If something feels unexpected, pause here and contact the hospital through its usual published number.</p></details>
</aside>
</div>
<section class="card logs-card" aria-labelledby="log-title"><h2 id="log-title">Logs</h2><p class="small">Simulation delivery and verification messages appear here.</p><div id="logs" aria-live="polite">Ready. No private account details are displayed.</div></section>
</main>
<footer>Use this secure hospital page only. This recovery simulation does not send email or contact external services.</footer>
<script nonce="${nonce}">
(()=>{
"use strict";
const csrf=${JSON.stringify(csrf)},initialStage=${JSON.stringify(initialStage)},initiallyPaused=${JSON.stringify(initiallyPaused)};
const app=document.getElementById("app"),progress=document.getElementById("progress"),logs=document.getElementById("logs"),pauseButton=document.getElementById("pauseButton");
let stage=initialStage,resetToken="",paused=initiallyPaused;

function log(message){console.log(message);logs.textContent+="\\n"+message;logs.scrollTop=logs.scrollHeight}
function message(text,kind){const box=document.createElement("div");box.className="notice "+(kind||"");box.textContent=text;app.prepend(box)}
function btn(text,klass){const b=document.createElement("button");b.type="button";b.textContent=text;if(klass)b.className=klass;return b}
async function post(path,data){try{const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(Object.assign({},data,{csrf}))});return await response.json()}catch(_){return{ok:false,message:"The secure service could not respond. Please try again."}}}
function pathFor(next){return({start:"/",code:"/reset",password:"/reset",complete:"/reset",signin:"/signin",mfa:"/signin",privacy:"/account",appointment:"/appointment"})[next]||"/"}
function go(next){history.pushState({},"",pathFor(next));stage=next;render()}
function updateProgress(){const items=[["start","1. Request a code"],["code","2. Confirm your code"],["password","3. Choose a password"],["signin","4. Sign in safely"],["privacy","5. Accept privacy statement"],["appointment","6. Confirm appointment"]];progress.replaceChildren();let index=items.findIndex(i=>i[0]===stage||(stage==="complete"&&i[0]==="signin")||(stage==="mfa"&&i[0]==="signin"));items.forEach((i,n)=>{const li=document.createElement("li");li.textContent=i[1];if(n<index)li.className="done";if(n===index)li.className="current";progress.appendChild(li)})}
function applyPauseState(){pauseButton.textContent=paused?"Resume saved place":"Pause and save place";if(paused){const note=document.createElement("div");note.className="notice paused-banner";note.textContent="Your place is paused and saved. Select Resume saved place when you want to continue.";app.prepend(note);app.querySelectorAll("input,button").forEach(el=>{el.disabled=true})}}
function render(){
updateProgress();app.replaceChildren();const title=document.createElement("h1");title.id="page-title";app.appendChild(title);
if(stage==="start"){
title.textContent="Reset your password";const p=document.createElement("p");p.textContent="We will take this one clear step at a time. Start by entering the email address you use for the hospital account.";const l=document.createElement("label");l.htmlFor="contact";l.textContent="Email address";const input=document.createElement("input");input.id="contact";input.type="email";input.autocomplete="email";const next=btn("Prepare recovery code");next.addEventListener("click",async()=>{next.disabled=true;const d=await post("/api/reset/request",{contact:input.value.trim()});next.disabled=false;message(d.message,d.ok?"success":"error");if(d.ok&&d.mockToken){resetToken=d.mockToken;log("[mock delivery] Recovery code for browser testing: "+resetToken);go("code");message("Next step: enter the code from the simulated delivery log.","success")}});const sign=btn("I know my password — sign in","secondary");sign.addEventListener("click",()=>go("signin"));app.append(p,l,input,next,sign);
}else if(stage==="code"){
title.textContent="Confirm your recovery code";const p=document.createElement("p");p.textContent="Enter the code from the simulated delivery message. You may proceed at your own pace. For safety, the code expires after 10 minutes and can be requested again.";const l=document.createElement("label");l.htmlFor="code";l.textContent="Recovery code";const input=document.createElement("input");input.id="code";input.autocomplete="one-time-code";input.value=resetToken;const verify=btn("Confirm code");verify.addEventListener("click",async()=>{const d=await post("/api/reset/verify",{token:input.value.trim().toLowerCase()});if(!d.ok){message(d.message,"error");return}resetToken=input.value.trim().toLowerCase();stage="password";render();message("Code confirmed. Next step: choose a new password.","success")});const back=btn("Start again","secondary");back.addEventListener("click",()=>{resetToken="";go("start")});app.append(p,l,input,verify,back);
}else if(stage==="password"){
title.textContent="Choose a new password";const p=document.createElement("p");p.textContent="Use at least 12 characters, with uppercase and lowercase letters, a number, and a symbol. Do not use spaces.";const l=document.createElement("label");l.htmlFor="newPassword";l.textContent="New password";const input=document.createElement("input");input.id="newPassword";input.type="password";input.autocomplete="new-password";const save=btn("Save new password");save.addEventListener("click",async()=>{const d=await post("/api/reset/password",{token:resetToken,password:input.value});if(!d.ok){message(d.message,"error");return}resetToken="";stage="complete";render();message(d.message,"success");log("[mock verification] Password replacement completed securely.")});app.append(p,l,input,save);
}else if(stage==="complete"){
title.textContent="Password changed";const p=document.createElement("p");p.textContent="Your password has been changed. The recovery code can no longer be used.";const next=btn("Continue to secure sign-in");next.addEventListener("click",()=>go("signin"));app.append(p,next);
}else if(stage==="signin"){
title.textContent="Secure sign-in";const p=document.createElement("p");p.textContent="Sign in on this hospital page only. A second verification step will follow.";const il=document.createElement("label");il.htmlFor="identifier";il.textContent="Email address";const identifier=document.createElement("input");identifier.id="identifier";identifier.type="email";identifier.autocomplete="username";const pl=document.createElement("label");pl.htmlFor="signinPassword";pl.textContent="Password";const password=document.createElement("input");password.id="signinPassword";password.type="password";password.autocomplete="current-password";const next=btn("Continue to verification");next.addEventListener("click",async()=>{const d=await post("/api/signin",{identifier:identifier.value.trim(),password:password.value});if(!d.ok){message(d.message,"error");return}log("[mock MFA] Sign-in code for browser testing: "+d.mockMfaCode);stage="mfa";render();message("Next step: enter the verification code from the simulation log.","success")});const reset=btn("Reset password instead","secondary");reset.addEventListener("click",()=>go("start"));app.append(p,il,identifier,pl,password,next,reset);
}else if(stage==="mfa"){
title.textContent="Confirm sign-in";const p=document.createElement("p");p.textContent="Enter the verification code from the simulated delivery log. You may proceed at your own pace. For safety, it expires after 10 minutes; restart sign-in to request another code.";const l=document.createElement("label");l.htmlFor="mfa";l.textContent="Verification code";const input=document.createElement("input");input.id="mfa";input.inputMode="numeric";input.autocomplete="one-time-code";input.maxLength=6;const verify=btn("Confirm sign-in");verify.addEventListener("click",async()=>{const d=await post("/api/mfa",{code:input.value.trim()});if(!d.ok){message(d.message,"error");return}log("[mock verification] Sign-in confirmed.");go("privacy")});app.append(p,l,input,verify);
}else if(stage==="privacy"){
title.textContent="Accept the updated privacy statement";const p=document.createElement("p");p.textContent="To continue with the appointment request, confirm that you accept the updated privacy statement.";const accept=btn("Accept and continue");accept.addEventListener("click",async()=>{const d=await post("/api/privacy",{});if(!d.ok){message(d.message,"error");return}log("[mock privacy] Updated privacy statement accepted.");go("appointment");message(d.message,"success")});app.append(p,accept);
}else{
title.textContent="Confirm medication review appointment";const p=document.createElement("p");p.textContent="Your privacy statement acceptance is recorded. Confirm this final step to request a medication dosage review appointment.";const confirm=btn("Confirm appointment request");confirm.addEventListener("click",async()=>{const d=await post("/api/appointment",{});message(d.message,d.ok?"success":"error");if(d.ok){log("[mock appointment] Medication review appointment request confirmed.");confirm.disabled=true;confirm.textContent="Appointment request confirmed"}});app.append(p,confirm);
}
applyPauseState();
}
pauseButton.addEventListener("click",async()=>{
const wanted=!paused;pauseButton.disabled=true;
const d=await post("/api/workflow",{stage:stage,paused:wanted});
pauseButton.disabled=false;
if(!d.ok){message(d.message,"error");return}
paused=d.paused;pauseButton.textContent=paused?"Resume saved place":"Pause and save place";
log(paused?"[recovery] Current step saved securely in this browser session.":"[recovery] Saved step resumed securely.");
render();
message(d.message,"success");
});
async function restore(){
const d=await post("/api/recovery/state",{});
if(!d.ok)return;
stage=d.stage||"start";paused=!!d.paused;resetToken=d.token||"";
render();
if(d.paused)log("[recovery] Your saved, paused step was restored for this browser session.");
else log("[recovery] Secure workflow progress restored for this browser session.");
}
window.addEventListener("popstate",()=>restore());
render();restore();
})();
</script>
</body>
</html>`;
}

async function httpsFetch(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    const pagePaths = ["/", "/reset", "/signin", "/account", "/appointment"];

    if (request.method === "GET" && pagePaths.includes(url.pathname)) {
      const { session, isNew } = getSession(request, true);
      if (url.pathname === "/account" && !session!.authenticated) {
        const headers = secureHeaders();
        headers.set("Location", "/signin");
        if (isNew) headers.append("Set-Cookie", sessionCookie(session!));
        return new Response(null, { status: 303, headers });
      }
      if (url.pathname === "/appointment" && (!session!.authenticated || !session!.privacyAccepted)) {
        const headers = secureHeaders();
        headers.set("Location", session!.authenticated ? "/account" : "/signin");
        if (isNew) headers.append("Set-Cookie", sessionCookie(session!));
        return new Response(null, { status: 303, headers });
      }

      const nonce = randomHex(18);
      const headers = secureHeaders(nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      if (isNew) headers.append("Set-Cookie", sessionCookie(session!));
      return new Response(page(nonce, session!.csrf, session!.workflowStage, session!.paused), { status: 200, headers });
    }

    if (request.method === "POST" && url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
    return new Response("Not found.", { status: 404, headers: secureHeaders() });
  } catch {
    return new Response("Service unavailable.", { status: 503, headers: secureHeaders() });
  }
}

function httpRedirect(request: Request): Response {
  const url = new URL(request.url);
  const known = ["/", "/reset", "/signin", "/account", "/appointment"].includes(url.pathname) || url.pathname.startsWith("/api/");
  const safePath = known ? url.pathname : "/";
  const headers = secureHeaders();
  headers.set("Location", `https://localhost:${HTTPS_PORT}${safePath}${safePath === url.pathname ? url.search : ""}`);
  return new Response(null, { status: 308, headers });
}

if (!existsSync(CERT_PATH) || !existsSync(KEY_PATH)) {
  console.error("TLS certificate files are required at certs/cert.pem and certs/key.pem.");
  process.exit(1);
}

/* HTTPS-only service; HTTP listener performs a fixed safe redirect. */
Bun.serve({
  port: HTTPS_PORT,
  tls: { cert: Bun.file(CERT_PATH), key: Bun.file(KEY_PATH) },
  fetch: httpsFetch,
});

Bun.serve({
  port: HTTP_PORT,
  fetch: httpRedirect,
});
