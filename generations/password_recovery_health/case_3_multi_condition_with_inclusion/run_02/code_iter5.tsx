
import { timingSafeEqual } from "node:crypto";

/* Requirements 1, 3, 4: server-only deterministic state, CSRF, expiry, throttling. */
const sessions = new Map<string, any>();
const accounts = new Map<string, any>();
const recoveryIssues = new Map<string, number[]>();
const loginFailures = new Map<string, { failures: number; lockUntil: number }>();

const CERT = Bun.file("certs/cert.pem");
const KEY = Bun.file("certs/key.pem");
const COOKIE = "__Host-hospital_recovery";
const SESSION_MS = 8 * 60 * 60 * 1000;
const RECOVERY_WINDOW_MS = 15 * 60 * 1000;
const RECOVERY_MAX_ISSUES = 3;
const RESET_MS = 15 * 60 * 1000;

const now = () => Date.now();

function randomToken(bytes = 32) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

async function digest(value: string) {
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Buffer.from(raw).toString("hex");
}

function newSession() {
  const id = randomToken();
  const session = {
    id,
    csrf: randomToken(),
    expiresAt: now() + SESSION_MS,
    recovery: null as any,
    reset: null as any,
    mfa: null as any,
    authenticatedAccount: null as string | null,
    privacyAccepted: false,
    appointmentBooked: false,
  };
  sessions.set(id, session);
  return session;
}

/* Task: malformed percent-encoded cookie values are invalid, never an exception. */
function cookieValue(request: Request, key: string) {
  const source = request.headers.get("cookie") || "";
  const found = source.split(";").map((part) => part.trim()).find((part) => part.startsWith(key + "="));
  if (!found) return "";
  try {
    return decodeURIComponent(found.slice(key.length + 1));
  } catch {
    return "";
  }
}

function getSession(request: Request) {
  const id = cookieValue(request, COOKIE);
  if (!id) return undefined;
  const session = sessions.get(id);
  if (!session || session.expiresAt <= now()) {
    if (session) sessions.delete(id);
    return undefined;
  }
  return session;
}

function cleanupExpired() {
  const cutoff = now() - RECOVERY_WINDOW_MS;
  for (const [id, s] of sessions) if (s.expiresAt <= now()) sessions.delete(id);
  for (const [key, values] of recoveryIssues) {
    const kept = values.filter((value) => value > cutoff);
    if (kept.length) recoveryIssues.set(key, kept);
    else recoveryIssues.delete(key);
  }
  for (const [key, value] of loginFailures) {
    if (value.lockUntil && value.lockUntil <= now()) loginFailures.delete(key);
  }
}
setInterval(cleanupExpired, 60_000);

function securityHeaders(nonce = "") {
  return {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": nonce
      ? `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'`
      : "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
    "Cross-Origin-Opener-Policy": "same-origin",
  };
}

function respond(body: string, status: number, type: string, nonce = "", extra: Record<string, string> = {}) {
  return new Response(body, { status, headers: { ...securityHeaders(nonce), "Content-Type": type, ...extra } });
}
function json(body: any, status = 200) {
  return respond(JSON.stringify(body), status, "application/json; charset=utf-8");
}
function apiError(message: string, status = 400) {
  return json({ ok: false, message }, status);
}
function notFound() {
  return respond("Not found.", 404, "text/plain; charset=utf-8");
}
function sessionCookie(id: string) {
  return `${COOKIE}=${encodeURIComponent(id)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MS / 1000}`;
}

async function requestBody(request: Request) {
  const length = Number(request.headers.get("content-length") || "0");
  if (!Number.isFinite(length) || length > 8192) throw new Error("invalid body");
  const body = await request.json();
  return body && typeof body === "object" && !Array.isArray(body) ? body : {};
}

/* Requirement 1: every state-changing endpoint requires same-origin CSRF validation. */
function sensitive(request: Request) {
  const session = getSession(request);
  if (!session) return { error: apiError("Please return to the secure portal and try again.", 401) };
  if (request.headers.get("origin") !== new URL(request.url).origin) {
    return { error: apiError("This request could not be confirmed safely. Please try again in the portal.", 403) };
  }
  if (request.headers.get("x-csrf-token") !== session.csrf) {
    return { error: apiError("Your secure form check did not match. Refresh the page and try again.", 403) };
  }
  return { session };
}

function validIdentifier(value: unknown) {
  if (typeof value !== "string") return "";
  const result = value.trim().toLowerCase();
  return result.length >= 3 && result.length <= 120 && /^[a-z0-9@._+\- ]+$/.test(result) ? result : "";
}
function passwordProblem(value: unknown) {
  if (typeof value !== "string") return "Enter a password.";
  if (value.length < 12) return "Use at least 12 characters.";
  if (value.length > 128) return "Use no more than 128 characters.";
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/[0-9]/.test(value) || !/[^A-Za-z0-9]/.test(value)) {
    return "Use an uppercase letter, lowercase letter, number, and symbol.";
  }
  return "";
}
function matches(value: string, expected: string) {
  if (!value || value.length !== expected.length) return false;
  try {
    return timingSafeEqual(Buffer.from(value), Buffer.from(expected));
  } catch {
    return false;
  }
}
function lockMessage() {
  return apiError("For safety, please pause for five minutes before trying again.", 429);
}
function throttle(session: any, accountKey: string) {
  const key = `${session.id}:${accountKey}`;
  const recent = (recoveryIssues.get(key) || []).filter((time) => time > now() - RECOVERY_WINDOW_MS);
  if (recent.length >= RECOVERY_MAX_ISSUES) {
    recoveryIssues.set(key, recent);
    return false;
  }
  recent.push(now());
  recoveryIssues.set(key, recent);
  return true;
}
function expireRecovery(session: any) {
  if (session.reset && session.reset.expiresAt <= now() && !session.reset.used) {
    session.reset = null;
    session.recovery = { stage: "expired" };
  }
}

/*
 Task: identifier submission creates only a browser-visible decoy value. It is
 never an account reset authorization, including for a pre-provisioned account.
*/
async function recoveryRequest(request: Request) {
  const checked = sensitive(request);
  if (checked.error) return checked.error;
  let body: any;
  try { body = await requestBody(request); } catch { return apiError("Please enter your account details in the form."); }

  const identifier = validIdentifier(body.identifier);
  if (!identifier) return apiError("Enter an email address or account reference using letters, numbers, and common punctuation.");

  const accountKey = await digest(identifier);
  const eligible = Boolean(accounts.get(accountKey)) && throttle(checked.session, accountKey);
  const decoy = randomToken();

  checked.session.recovery = {
    stage: "instructionSent",
    accountKey: eligible ? accountKey : null,
    eligible,
    decoy,
    decoyConfirmed: false,
    identityVerified: false,
    failures: 0,
    lockUntil: 0,
  };
  checked.session.reset = null;

  return json({
    ok: true,
    message: "If the account can receive recovery instructions, an instruction has been prepared. Continue when you are ready.",
    deliveryPath: `/?recovery-test=${encodeURIComponent(decoy)}`,
    testValue: decoy,
  });
}

/*
 The manual code confirms only the explicitly labelled test instruction. It is
 intentionally decoupled from reset authorization and cannot replace a password.
*/
async function confirmInstruction(request: Request) {
  const checked = sensitive(request);
  if (checked.error) return checked.error;
  let body: any;
  try { body = await requestBody(request); } catch { return apiError("Enter the recovery test value."); }

  const recovery = checked.session.recovery;
  const value = typeof body.value === "string" ? body.value.trim() : "";
  if (!recovery || recovery.stage === "expired") return apiError("This instruction is no longer available. You can request a new one.");
  if (recovery.lockUntil > now()) return lockMessage();
  if (!matches(value, recovery.decoy)) {
    recovery.failures++;
    if (recovery.failures >= 5) recovery.lockUntil = now() + 5 * 60 * 1000;
    return apiError(recovery.failures >= 5
      ? "For safety, please pause for five minutes, then request a fresh instruction."
      : "That test value did not match. Check it and try again.");
  }
  recovery.decoyConfirmed = true;
  recovery.stage = "identity";
  return json({ ok: true, message: "Instruction confirmed. Next, complete the separate identity check." });
}

/*
 Task: separate simulated possession/identity verification. This explicit,
 server-validated step is required before a server-only random reset token is
 issued. No live token is returned, linked, logged, or available in browser JS.
*/
async function verifyRecoveryIdentity(request: Request) {
  const checked = sensitive(request);
  if (checked.error) return checked.error;
  let body: any;
  try { body = await requestBody(request); } catch { return apiError("Confirm the identity check when ready."); }

  const recovery = checked.session.recovery;
  if (!recovery || !recovery.decoyConfirmed) return apiError("First confirm the recovery instruction.");
  if (body.confirmed !== true) return apiError("Please confirm that the separate identity check was completed.");

  recovery.identityVerified = true;
  const liveAuthorization = Boolean(recovery.eligible && recovery.accountKey && accounts.has(recovery.accountKey));

  /*
   This random, single-use token is held only in the HttpOnly server session.
   The visible test value never equals this token and cannot authorize a reset.
  */
  checked.session.reset = {
    token: randomToken(),
    accountKey: liveAuthorization ? recovery.accountKey : null,
    authorizesAccount: liveAuthorization,
    expiresAt: now() + RESET_MS,
    used: false,
  };
  recovery.stage = "identityVerified";
  return json({
    ok: true,
    message: "Identity check recorded. A secure reset authorization is now held by this portal session. Choose a new password when ready.",
  });
}

/* Task: real replacement requires server-held valid token AND completed identity verification. */
async function replacePassword(request: Request) {
  const checked = sensitive(request);
  if (checked.error) return checked.error;
  let body: any;
  try { body = await requestBody(request); } catch { return apiError("Please complete both password fields."); }

  expireRecovery(checked.session);
  const recovery = checked.session.recovery;
  const reset = checked.session.reset;
  if (!recovery?.identityVerified || !reset || reset.used || reset.expiresAt <= now()) {
    return apiError("Please complete a current recovery identity check before changing your password.");
  }

  const problem = passwordProblem(body.password);
  if (problem) return apiError(problem);
  if (body.password !== body.confirmPassword) return apiError("The two passwords do not match yet.");

  if (reset.authorizesAccount && typeof reset.accountKey === "string") {
    const account = accounts.get(reset.accountKey);
    if (account) account.passwordHash = await Bun.password.hash(body.password, { algorithm: "argon2id" });
  }

  reset.token = "";
  reset.used = true;
  recovery.stage = "passwordChanged";
  return json({ ok: true, message: "Your new password is saved. Next, sign in and complete one extra safety check." });
}

async function login(request: Request) {
  const checked = sensitive(request);
  if (checked.error) return checked.error;
  let body: any;
  try { body = await requestBody(request); } catch { return apiError("Enter your account details and password."); }

  const identifier = validIdentifier(body.identifier);
  const key = await digest(identifier || "invalid-account");
  const failure = loginFailures.get(key);
  if (failure?.lockUntil > now()) return lockMessage();

  const account = identifier ? accounts.get(key) : undefined;
  const valid = Boolean(account && typeof body.password === "string" && await Bun.password.verify(body.password, account.passwordHash));
  if (!valid) {
    const current = loginFailures.get(key) || { failures: 0, lockUntil: 0 };
    current.failures++;
    if (current.failures >= 5) current.lockUntil = now() + 5 * 60 * 1000;
    loginFailures.set(key, current);
    return apiError(current.failures >= 5
      ? "For safety, please pause for five minutes before another sign-in attempt."
      : "Those sign-in details did not match. You can try again or use password recovery.", 401);
  }

  loginFailures.delete(key);
  checked.session.mfa = {
    accountKey: key,
    demoCode: String(100000 + crypto.getRandomValues(new Uint32Array(1))[0] % 900000),
    codeConfirmed: false,
    independentPossession: false,
    expiresAt: now() + 10 * 60 * 1000,
    failures: 0,
    lockUntil: 0,
    completed: false,
  };

  /*
   Task: this browser-visible code is demonstration-only. It cannot authenticate
   an account because /api/mfa also requires independentPossession.
  */
  return json({
    ok: true,
    message: "Password confirmed. Enter the six-digit demonstration code, then complete the separate possession check.",
    testMfaCode: checked.session.mfa.demoCode,
  });
}

async function verifyMfaCode(request: Request) {
  const checked = sensitive(request);
  if (checked.error) return checked.error;
  let body: any;
  try { body = await requestBody(request); } catch { return apiError("Enter the six-digit safety code."); }

  const mfa = checked.session.mfa;
  if (!mfa || mfa.expiresAt <= now()) return apiError("That safety code has expired. Sign in again when ready.");
  if (mfa.lockUntil > now()) return lockMessage();

  const code = typeof body.code === "string" ? body.code : "";
  if (!matches(code, mfa.demoCode)) {
    mfa.failures++;
    if (mfa.failures >= 5) mfa.lockUntil = now() + 5 * 60 * 1000;
    return apiError(mfa.failures >= 5 ? "For safety, pause for five minutes, then sign in again." : "That safety code did not match. Please check it and try again.");
  }
  mfa.codeConfirmed = true;
  return json({ ok: true, message: "Demonstration code confirmed. One independent possession check is still required." });
}

/* Task: independent simulated MFA condition is separate from visible demo code. */
async function verifyMfaPossession(request: Request) {
  const checked = sensitive(request);
  if (checked.error) return checked.error;
  let body: any;
  try { body = await requestBody(request); } catch { return apiError("Confirm the possession check when ready."); }

  const mfa = checked.session.mfa;
  if (!mfa || mfa.expiresAt <= now()) return apiError("That sign-in check has expired. Sign in again when ready.");
  if (!mfa.codeConfirmed) return apiError("First enter the six-digit demonstration code.");
  if (body.confirmed !== true) return apiError("Please confirm the independent possession check.");

  mfa.independentPossession = true;
  mfa.completed = true;
  checked.session.authenticatedAccount = mfa.accountKey;
  return json({ ok: true, message: "Independent possession check complete. You are signed in." });
}

function authenticated(session: any) {
  return Boolean(session?.authenticatedAccount && session.mfa?.completed && session.mfa?.independentPossession);
}
async function acceptPrivacy(request: Request) {
  const checked = sensitive(request);
  if (checked.error) return checked.error;
  if (!authenticated(checked.session)) return apiError("Please sign in before changing privacy conditions.", 401);
  checked.session.privacyAccepted = true;
  return json({ ok: true, message: "Privacy conditions accepted. You can now confirm the appointment request." });
}
async function bookAppointment(request: Request) {
  const checked = sensitive(request);
  if (checked.error) return checked.error;
  if (!authenticated(checked.session) || !checked.session.privacyAccepted) {
    return apiError("Please accept the privacy conditions before confirming an appointment.", 403);
  }
  checked.session.appointmentBooked = true;
  return json({ ok: true, message: "Your medication review appointment request is confirmed. Hospital staff will follow up." });
}

function state(session: any) {
  expireRecovery(session);
  return {
    ok: true,
    recoveryStage: session.recovery?.stage || "start",
    authenticated: authenticated(session),
    privacyAccepted: session.privacyAccepted,
    appointmentBooked: session.appointmentBooked,
    needsMfa: Boolean(session.mfa && !session.mfa.completed && session.mfa.expiresAt > now()),
  };
}

/* Requirements accessibility/inclusivity: quiet SPA, visible orientation and no timers in UI. */
function page(nonce: string, csrf: string) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
:root{--ink:#163043;--blue:#075e8d;--pale:#eef7fa;--line:#b9cbd4;--good:#075d43;--warn:#7a4300}*{box-sizing:border-box}body{margin:0;background:#f5f8f9;color:var(--ink);font:18px/1.52 system-ui,sans-serif}header{background:#fff;border-bottom:4px solid var(--blue);padding:1rem max(1.2rem,calc((100% - 900px)/2))}.brand{font-size:1.2rem;font-weight:800}main{max-width:900px;margin:auto;padding:1.5rem 1.2rem 4rem}h1{font-size:2rem;line-height:1.2}h2{font-size:1.35rem;line-height:1.25}.card,.progress{background:#fff;border:1px solid var(--line);border-radius:12px;padding:1.2rem;margin:1rem 0}.progress ol{display:flex;flex-wrap:wrap;gap:.45rem;list-style:none;padding:0;margin:.7rem 0 0}.progress li{background:#e6edf0;border-radius:99px;padding:.22rem .65rem;font-size:.87rem}.progress li.active{background:var(--blue);color:#fff}.panel[hidden],.hide{display:none!important}label{display:block;font-weight:700;margin-top:1rem}input{display:block;width:100%;max-width:560px;font:inherit;padding:.62rem;border:2px solid #718894;border-radius:7px}input:focus,button:focus,a:focus{outline:3px solid #e99b27;outline-offset:3px}button{font:inherit;font-weight:700;background:var(--blue);color:#fff;border:0;border-radius:7px;padding:.65rem 1rem;margin:.9rem .5rem 0 0;cursor:pointer}.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue)}.feedback{border-left:5px solid var(--blue);background:var(--pale);padding:.7rem .9rem;margin:1rem 0;min-height:1.6rem}.feedback.error{border-color:var(--warn);background:#fff5e9}.feedback.good{border-color:var(--good);background:#ebf8f1}.help{background:#fff8df;border:1px solid #d8bc64;border-radius:9px;padding:1rem}.logs{background:#12242e;color:#def2ee;border-radius:8px;padding:.8rem;max-height:180px;overflow:auto;font:14px/1.4 ui-monospace,monospace}.logs p{margin:.25rem 0}.small{font-size:.92rem}@media(max-width:550px){body{font-size:17px}.progress ol{display:block}.progress li{display:inline-block;margin:.15rem}}
</style></head><body>
<header><div class="brand">Hospital secure account portal</div></header><main>
<h1>Password recovery, one calm step at a time</h1><p id="next">Start by asking for a secure recovery instruction.</p>
<nav class="progress" aria-label="Recovery progress"><strong>Your progress</strong><ol><li id="p1">1. Recovery</li><li id="p2">2. Identity check</li><li id="p3">3. New password</li><li id="p4">4. Sign in</li><li id="p5">5. Privacy & appointment</li></ol></nav>

<section id="requestPanel" class="panel card"><h2>1. Ask for a recovery instruction</h2><p>Enter your email address or account reference. We will not say whether an account is registered.</p><form id="requestForm" novalidate><label for="identifier">Email address or account reference</label><input id="identifier" autocomplete="username" maxlength="120" required><button>Prepare recovery instruction</button></form><div id="requestFeedback" class="feedback" aria-live="polite">You can pause at any time. Progress remains in this browser session.</div><p><a id="deliveryLink" class="hide" href="#instruction">Open simulated recovery instruction</a></p><button id="requestContinue" class="secondary hide" type="button">Continue</button></section>

<section id="instructionPanel" class="panel card" hidden><h2>2. Confirm the recovery instruction</h2><p>Paste or type the <strong>test value</strong> from the simulated instruction. This value is not a password reset credential.</p><form id="instructionForm" novalidate><label for="instructionValue">Recovery test value</label><input id="instructionValue" autocomplete="one-time-code" maxlength="80" required><button>Confirm instruction</button></form><div id="instructionFeedback" class="feedback" aria-live="polite">There is no rush. Check the value, then continue.</div><button id="instructionContinue" class="secondary hide" type="button">Continue to identity check</button><button id="backRequest" class="secondary" type="button">Request a new instruction</button></section>

<section id="identityPanel" class="panel card" hidden><h2>Separate identity check</h2><p>This is a separate simulated possession check. It is required before this portal can hold a secure reset authorization.</p><button id="identityButton" type="button">I completed the separate identity check</button><div id="identityFeedback" class="feedback" aria-live="polite">This extra step helps protect your account if an instruction is seen by someone else.</div><button id="identityContinue" class="secondary hide" type="button">Continue to new password</button></section>

<section id="passwordPanel" class="panel card" hidden><h2>3. Choose a new password</h2><p>Use 12 or more characters, with an uppercase letter, lowercase letter, number, and symbol.</p><form id="passwordForm" novalidate><label for="newPassword">New password</label><input id="newPassword" type="password" autocomplete="new-password" maxlength="128" required><label for="confirmPassword">Confirm new password</label><input id="confirmPassword" type="password" autocomplete="new-password" maxlength="128" required><button>Save new password</button></form><div id="passwordFeedback" class="feedback" aria-live="polite">After saving, you will sign in with your new password.</div><button id="passwordContinue" class="secondary hide" type="button">Continue to sign in</button></section>

<section id="loginPanel" class="panel card" hidden><h2>4. Sign in</h2><p>Use your account reference and password. Then complete two safety checks.</p><form id="loginForm" novalidate><label for="loginIdentifier">Email address or account reference</label><input id="loginIdentifier" autocomplete="username" maxlength="120" required><label for="loginPassword">Password</label><input id="loginPassword" type="password" autocomplete="current-password" maxlength="128" required><button>Sign in securely</button></form><div id="loginFeedback" class="feedback" aria-live="polite">You may use password recovery if you need it.</div><button id="loginContinue" class="secondary hide" type="button">Continue to safety code</button></section>

<section id="mfaPanel" class="panel card" hidden><h2>Extra safety checks</h2><p>First enter the six-digit demonstration code from the simulated secure message. Then complete the independent possession check. The visible demonstration code alone cannot sign in.</p><form id="mfaForm" novalidate><label for="mfaCode">Six-digit demonstration code</label><input id="mfaCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button>Confirm demonstration code</button></form><div id="mfaFeedback" class="feedback" aria-live="polite">This code is only a demonstration step.</div><button id="possessionButton" class="secondary hide" type="button">Complete independent possession check</button><button id="mfaContinue" class="secondary hide" type="button">Continue to privacy conditions</button></section>

<section id="privacyPanel" class="panel card" hidden><h2>5. Updated privacy conditions</h2><p>To allow hospital authorities to arrange the medication dosage review, please accept the updated privacy conditions.</p><ul><li>Your information is used only for healthcare and appointment coordination.</li><li>You can ask hospital staff for help with these conditions.</li></ul><button id="privacyButton" type="button">I accept the updated privacy conditions</button><div id="privacyFeedback" class="feedback" aria-live="polite">Read this at your own pace.</div><button id="privacyContinue" class="secondary hide" type="button">Continue to appointment request</button></section>

<section id="appointmentPanel" class="panel card" hidden><h2>Confirm medication review request</h2><p>Your privacy conditions are accepted. Confirm when you are ready.</p><button id="appointmentButton" type="button">Confirm appointment request</button><div id="appointmentFeedback" class="feedback" aria-live="polite">No appointment is requested until you select the button.</div></section>

<aside class="help"><h2>Need help or a reminder?</h2><p>You can pause and return without a countdown. Contact your usual hospital support channel for help. Hospital staff will never ask you to send a password or recovery code by email or phone. Check that this is the secure hospital portal before entering details.</p></aside>
<section class="card"><h2>Logs</h2><p class="small">Simulated delivery and verification messages are shown here for this demonstration.</p><div id="logs" class="logs" aria-live="polite"></div></section>
</main>

<script nonce="${nonce}">
(()=>{"use strict";
const csrf=${JSON.stringify(csrf)},$=id=>document.getElementById(id);
const panels=["requestPanel","instructionPanel","identityPanel","passwordPanel","loginPanel","mfaPanel","privacyPanel","appointmentPanel"];
let testValue="",identifier=sessionStorage.getItem("hospital-recovery-identifier")||"";
function log(message){console.log(message);const p=document.createElement("p");p.textContent=message;$("logs").append(p);$("logs").scrollTop=$("logs").scrollHeight}
function feedback(id,text,kind){const e=$(id);e.textContent=typeof text==="string"?text:"Please try again.";e.className="feedback"+(kind?" "+kind:"")}
function choose(id,progress,focus){panels.forEach(x=>$(x).hidden=x!==id);for(let i=1;i<6;i++)$("p"+i).classList.toggle("active",i===progress);$("next").textContent=["Start by asking for a secure recovery instruction.","Your next step is to confirm the instruction and identity check.","Your next step is to choose a strong new password.","Your next step is to sign in and complete the safety checks.","You are almost done: accept privacy conditions, then confirm the appointment request."][progress-1];window.scrollTo({top:0,behavior:"smooth"});setTimeout(()=>{const e=$(focus||id);if(e&&e.focus)e.focus()},0)}
function reveal(id){$(id).classList.remove("hide")}
function safeId(v){return /^[a-z0-9@._+\\- ]{3,120}$/i.test(v.trim())}
function safePass(v){return v.length>=12&&v.length<=128&&/[a-z]/.test(v)&&/[A-Z]/.test(v)&&/[0-9]/.test(v)&&/[^A-Za-z0-9]/.test(v)}
async function api(path,data){try{const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});const v=await r.json();return v&&typeof v==="object"?v:{ok:false,message:"The secure portal could not complete that step."}}catch{return{ok:false,message:"The secure portal could not complete that step. Please try again."}}}
function openInstruction(){choose("instructionPanel",2,"instructionValue");if(testValue)$("instructionValue").value=testValue}
$("identifier").value=identifier;
$("deliveryLink").onclick=e=>{e.preventDefault();openInstruction()};
window.onhashchange=()=>{if(location.hash==="#instruction")openInstruction()};

$("requestForm").onsubmit=async e=>{e.preventDefault();const value=$("identifier").value.trim();if(!safeId(value))return feedback("requestFeedback","Enter an email address or account reference using letters, numbers, and common punctuation.","error");identifier=value;sessionStorage.setItem("hospital-recovery-identifier",value);const r=await api("/api/recovery/request",{identifier:value});feedback("requestFeedback",r.message,r.ok?"good":"error");if(r.ok){testValue=typeof r.testValue==="string"?r.testValue:"";$("deliveryLink").href=typeof r.deliveryPath==="string"?r.deliveryPath:"#instruction";$("deliveryLink").classList.remove("hide");if(testValue)log("[mock delivery] Non-authorizing recovery test value: "+testValue);reveal("requestContinue")}};
$("requestContinue").onclick=openInstruction;
$("backRequest").onclick=()=>choose("requestPanel",1,"identifier");

$("instructionForm").onsubmit=async e=>{e.preventDefault();const value=$("instructionValue").value.trim();if(!/^[A-Za-z0-9_-]{20,}$/.test(value))return feedback("instructionFeedback","Enter the test value from the simulated instruction.","error");const r=await api("/api/recovery/instruction",{value});feedback("instructionFeedback",r.message,r.ok?"good":"error");if(r.ok)reveal("instructionContinue")};
$("instructionContinue").onclick=()=>choose("identityPanel",2,"identityButton");
$("identityButton").onclick=async()=>{const r=await api("/api/recovery/identity",{confirmed:true});feedback("identityFeedback",r.message,r.ok?"good":"error");if(r.ok){log("[mock identity] Separate recovery identity check recorded; live authorization remains server-only.");reveal("identityContinue")}};
$("identityContinue").onclick=()=>choose("passwordPanel",3,"newPassword");

$("passwordForm").onsubmit=async e=>{e.preventDefault();const p=$("newPassword").value,c=$("confirmPassword").value;if(!safePass(p))return feedback("passwordFeedback","Use 12+ characters with uppercase, lowercase, number, and symbol.","error");if(p!==c)return feedback("passwordFeedback","The two passwords do not match yet.","error");const r=await api("/api/recovery/password",{password:p,confirmPassword:c});feedback("passwordFeedback",r.message,r.ok?"good":"error");if(r.ok){log("[mock verification] Password replacement completed; reset authorization was invalidated.");reveal("passwordContinue")}};
$("passwordContinue").onclick=()=>{$("loginIdentifier").value=identifier;choose("loginPanel",4,"loginPassword")};

$("loginForm").onsubmit=async e=>{e.preventDefault();const value=$("loginIdentifier").value.trim(),password=$("loginPassword").value;if(!safeId(value)||!password)return feedback("loginFeedback","Enter your account reference and password.","error");const r=await api("/api/login",{identifier:value,password});feedback("loginFeedback",r.message,r.ok?"good":"error");if(r.ok){if(typeof r.testMfaCode==="string")log("[mock MFA] Demonstration code (not sufficient to sign in): "+r.testMfaCode);reveal("loginContinue")}};
$("loginContinue").onclick=()=>choose("mfaPanel",4,"mfaCode");
$("mfaForm").onsubmit=async e=>{e.preventDefault();const code=$("mfaCode").value.trim();if(!/^\\d{6}$/.test(code))return feedback("mfaFeedback","Enter all six digits of the demonstration code.","error");const r=await api("/api/mfa/code",{code});feedback("mfaFeedback",r.message,r.ok?"good":"error");if(r.ok)reveal("possessionButton")};
$("possessionButton").onclick=async()=>{const r=await api("/api/mfa/possession",{confirmed:true});feedback("mfaFeedback",r.message,r.ok?"good":"error");if(r.ok){log("[mock MFA] Independent possession check completed.");reveal("mfaContinue")}};
$("mfaContinue").onclick=()=>choose("privacyPanel",5,"privacyButton");

$("privacyButton").onclick=async()=>{const r=await api("/api/privacy/accept",{});feedback("privacyFeedback",r.message,r.ok?"good":"error");if(r.ok){log("[mock privacy] Updated privacy conditions accepted.");reveal("privacyContinue")}};
$("privacyContinue").onclick=()=>choose("appointmentPanel",5,"appointmentButton");
$("appointmentButton").onclick=async()=>{const r=await api("/api/appointment",{});feedback("appointmentFeedback",r.message,r.ok?"good":"error");if(r.ok)log("[mock appointment] Medication review appointment request confirmed.")};

(async()=>{const incoming=new URL(location.href).searchParams.get("recovery-test");if(incoming&&/^[A-Za-z0-9_-]{20,}$/.test(incoming)){testValue=incoming;history.replaceState({},"","/#instruction");log("[mock delivery] Simulated recovery instruction opened.");openInstruction();return}try{const s=await(await fetch("/api/state",{credentials:"same-origin"})).json();if(s.appointmentBooked){choose("appointmentPanel",5,"appointmentButton");feedback("appointmentFeedback","Your medication review appointment request is confirmed.","good")}else if(s.authenticated&&s.privacyAccepted)choose("appointmentPanel",5,"appointmentButton");else if(s.authenticated)choose("privacyPanel",5,"privacyButton");else if(s.needsMfa)choose("mfaPanel",4,"mfaCode");else if(s.recoveryStage==="passwordChanged"){$("loginIdentifier").value=identifier;choose("loginPanel",4,"loginPassword")}else if(s.recoveryStage==="identityVerified")choose("passwordPanel",3,"newPassword");else if(s.recoveryStage==="identity")choose("identityPanel",2,"identityButton");else if(s.recoveryStage==="instructionSent")choose("instructionPanel",2,"instructionValue");else if(s.recoveryStage==="expired"){choose("requestPanel",1,"identifier");feedback("requestFeedback","Your earlier authorization expired. Your place in the process is saved, and a fresh instruction is needed.","error")}else choose("requestPanel",1,"identifier")}catch{choose("requestPanel",1,"identifier")}})();
})();
</script></body></html>`;
}

/* Pre-provisioned mock accounts only; recovery never creates accounts. */
async function provisionAccounts() {
  for (const identifier of ["helena@example.com", "helena.patient@hospital.test", "helena patient"]) {
    accounts.set(await digest(identifier), {
      passwordHash: await Bun.password.hash("Initial!HospitalPassword9", { algorithm: "argon2id" }),
      createdAt: now(),
    });
  }
}
await provisionAccounts();

const server = Bun.serve({
  port: Number(process.env.PORT || 3000),
  tls: { cert: CERT, key: KEY },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.headers.get("x-forwarded-proto") === "http") {
        return respond("Secure HTTPS connection required.", 426, "text/plain; charset=utf-8");
      }

      if (request.method === "GET" && url.pathname === "/") {
        let session = getSession(request);
        const fresh = !session;
        if (!session) session = newSession();
        const nonce = randomToken(18);
        return respond(page(nonce, session.csrf), 200, "text/html; charset=utf-8", nonce,
          fresh ? { "Set-Cookie": sessionCookie(session.id) } : {});
      }
      if (request.method === "GET" && url.pathname === "/api/state") {
        const session = getSession(request);
        return session ? json(state(session)) : apiError("Please open the secure portal first.", 401);
      }
      if (request.method === "POST" && url.pathname === "/api/recovery/request") return await recoveryRequest(request);
      if (request.method === "POST" && url.pathname === "/api/recovery/instruction") return await confirmInstruction(request);
      if (request.method === "POST" && url.pathname === "/api/recovery/identity") return await verifyRecoveryIdentity(request);
      if (request.method === "POST" && url.pathname === "/api/recovery/password") return await replacePassword(request);
      if (request.method === "POST" && url.pathname === "/api/login") return await login(request);
      if (request.method === "POST" && url.pathname === "/api/mfa/code") return await verifyMfaCode(request);
      if (request.method === "POST" && url.pathname === "/api/mfa/possession") return await verifyMfaPossession(request);
      if (request.method === "POST" && url.pathname === "/api/privacy/accept") return await acceptPrivacy(request);
      if (request.method === "POST" && url.pathname === "/api/appointment") return await bookAppointment(request);
      return notFound();
    } catch {
      return respond("The secure portal could not process that request.", 500, "text/plain; charset=utf-8");
    }
  },
});

console.log(`Hospital recovery portal listening securely on https://localhost:${server.port}`);
