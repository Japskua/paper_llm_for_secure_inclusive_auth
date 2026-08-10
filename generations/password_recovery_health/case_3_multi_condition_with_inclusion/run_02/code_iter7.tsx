
import { timingSafeEqual } from "node:crypto";

/* Requirements 1, 3, 4: in-memory mock state, CSRF, expiry, throttling. */
const sessions = new Map<string, any>();
const accounts = new Map<string, any>();
const recoveryIssues = new Map<string, number[]>();
const loginFailures = new Map<string, { failures: number; lockUntil: number }>();

const CERT = Bun.file("certs/cert.pem");
const KEY = Bun.file("certs/key.pem");
const COOKIE = "__Host-hospital_recovery";
const SESSION_MS = 8 * 60 * 60 * 1000;
const RESET_MS = 15 * 60 * 1000;
const MFA_MS = 10 * 60 * 1000;
const LOCK_MS = 5 * 60 * 1000;
const now = () => Date.now();

function randomToken(bytes = 32) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}
function mockCode(length = 8) {
  return randomToken(12).slice(0, length).toUpperCase();
}
async function digest(value: string) {
  return Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))).toString("hex");
}
function equal(value: string, expected: string) {
  if (!value || value.length !== expected.length) return false;
  try { return timingSafeEqual(Buffer.from(value), Buffer.from(expected)); } catch { return false; }
}
function newSession() {
  const session = {
    id: randomToken(),
    csrf: randomToken(),
    expiresAt: now() + SESSION_MS,
    recovery: null as any,
    reset: null as any,
    mfa: null as any,
    authenticatedAccount: null as string | null,
    privacyAccepted: false,
    appointmentBooked: false,
  };
  sessions.set(session.id, session);
  return session;
}
function cookieValue(request: Request, key: string) {
  const item = (request.headers.get("cookie") || "").split(";").map(v => v.trim()).find(v => v.startsWith(key + "="));
  if (!item) return "";
  try { return decodeURIComponent(item.slice(key.length + 1)); } catch { return ""; }
}
function getSession(request: Request) {
  const id = cookieValue(request, COOKIE);
  const session = id && sessions.get(id);
  if (!session || session.expiresAt <= now()) {
    if (session) sessions.delete(id);
    return undefined;
  }
  return session;
}
function clean() {
  for (const [id, session] of sessions) if (session.expiresAt <= now()) sessions.delete(id);
  for (const [key, tries] of recoveryIssues) {
    const remaining = tries.filter(t => t > now() - RESET_MS);
    if (remaining.length) recoveryIssues.set(key, remaining); else recoveryIssues.delete(key);
  }
  for (const [key, failure] of loginFailures) if (failure.lockUntil && failure.lockUntil <= now()) loginFailures.delete(key);
}
setInterval(clean, 60_000);

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
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store, max-age=0, must-revalidate",
    "Pragma": "no-cache",
  };
}
function respond(body: string, status: number, type: string, nonce = "", extra: Record<string, string> = {}) {
  return new Response(body, { status, headers: { ...securityHeaders(nonce), "Content-Type": type, ...extra } });
}
function json(body: any, status = 200) { return respond(JSON.stringify(body), status, "application/json; charset=utf-8"); }
function error(message: string, status = 400) { return json({ ok: false, message }, status); }
function sessionCookie(id: string) {
  return `${COOKIE}=${encodeURIComponent(id)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MS / 1000}`;
}
async function body(request: Request) {
  const length = Number(request.headers.get("content-length") || "0");
  if (!Number.isFinite(length) || length > 8192) throw new Error("bad body");
  const value = await request.json();
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}
/* Requirement 1: all state-changing requests require same-origin CSRF validation. */
function sensitive(request: Request) {
  const session = getSession(request);
  if (!session) return { failure: error("Please return to the secure portal and try again.", 401) };
  if (request.headers.get("origin") !== new URL(request.url).origin) return { failure: error("This request could not be confirmed safely. Please try again in the portal.", 403) };
  if (request.headers.get("x-csrf-token") !== session.csrf) return { failure: error("Your secure form check did not match. Refresh the page and try again.", 403) };
  return { session };
}
function identifier(value: unknown) {
  if (typeof value !== "string") return "";
  const result = value.trim().toLowerCase();
  return /^[a-z0-9@._+\- ]{3,120}$/.test(result) ? result : "";
}
function passwordProblem(value: unknown) {
  if (typeof value !== "string") return "Enter a password.";
  if (value.length < 12) return "Use at least 12 characters.";
  if (value.length > 128) return "Use no more than 128 characters.";
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/[0-9]/.test(value) || !/[^A-Za-z0-9]/.test(value)) return "Use an uppercase letter, lowercase letter, number, and symbol.";
  return "";
}
function locked() { return error("For safety, please pause for five minutes before trying again.", 429); }
function issueAllowed(session: any, accountKey: string) {
  const key = `${session.id}:${accountKey}`;
  const tries = (recoveryIssues.get(key) || []).filter(t => t > now() - RESET_MS);
  if (tries.length >= 3) return false;
  tries.push(now());
  recoveryIssues.set(key, tries);
  return true;
}
function expireReset(session: any) {
  if (session.reset && session.reset.expiresAt <= now() && !session.reset.used) {
    session.reset = null;
    if (session.recovery) session.recovery.stage = "expired";
  }
}

/*
 Requirement 3, Task: random, single-use, 15-minute mock recovery values.
 Delivery is simulated exclusively by browser console.log and the visible Logs panel.
*/
async function recoveryRequest(request: Request) {
  const checked = sensitive(request);
  if (checked.failure) return checked.failure;
  let input: any; try { input = await body(request); } catch { return error("Please enter your account details in the form."); }
  const accountId = identifier(input.identifier);
  if (!accountId) return error("Enter an email address or account reference using letters, numbers, and common punctuation.");

  const accountKey = await digest(accountId);
  const authorized = Boolean(accounts.get(accountKey)) && issueAllowed(checked.session, accountKey);
  const token = randomToken();
  const identityCode = mockCode(8);

  checked.session.recovery = {
    stage: "instructionSent", failures: 0, lockUntil: 0,
    tokenConfirmed: false, identityVerified: false,
    identityCode, identityFailures: 0, identityLockUntil: 0,
  };
  checked.session.reset = {
    token,
    accountKey: authorized ? accountKey : null,
    authorizesAccount: authorized,
    expiresAt: now() + RESET_MS,
    used: false,
  };

  return json({
    ok: true,
    message: "If the account can receive recovery instructions, an instruction has been prepared. Continue when you are ready.",
    deliveryPath: `/?recovery-test=${encodeURIComponent(token)}`,
    testValue: token,
    testValueLabel: "Testing mock reset token — paste this value into the next step.",
    testIdentityValue: identityCode,
    testIdentityLabel: "Testing mock recovery identity value — enter this at the separate identity check.",
    expiresAt: checked.session.reset.expiresAt,
  });
}

async function confirmInstruction(request: Request) {
  const checked = sensitive(request);
  if (checked.failure) return checked.failure;
  let input: any; try { input = await body(request); } catch { return error("Enter the testing mock reset token."); }
  expireReset(checked.session);
  const recovery = checked.session.recovery, reset = checked.session.reset;
  const value = typeof input.value === "string" ? input.value.trim() : "";
  if (!recovery || !reset || reset.used) return error("This reset instruction is no longer available. You can request a new one.");
  if (recovery.lockUntil > now()) return locked();
  if (!equal(value, reset.token)) {
    recovery.failures++;
    if (recovery.failures >= 5) recovery.lockUntil = now() + LOCK_MS;
    return error(recovery.failures >= 5 ? "For safety, please pause for five minutes, then request a fresh instruction." : "That testing mock reset token did not match. Check it and try again.");
  }
  recovery.tokenConfirmed = true;
  recovery.stage = "identity";
  return json({ ok: true, message: "Testing mock reset token confirmed. Next, enter the separate recovery identity value." });
}

/* Task: validate separately generated recovery identity value, never a boolean acknowledgement. */
async function verifyRecoveryIdentity(request: Request) {
  const checked = sensitive(request);
  if (checked.failure) return checked.failure;
  let input: any; try { input = await body(request); } catch { return error("Enter the separate recovery identity value."); }
  expireReset(checked.session);
  const recovery = checked.session.recovery, reset = checked.session.reset;
  const value = typeof input.value === "string" ? input.value.trim().toUpperCase() : "";
  if (!recovery?.tokenConfirmed || !reset || reset.used) return error("First confirm a current testing mock reset token.");
  if (recovery.identityLockUntil > now()) return locked();
  if (!/^[A-Z0-9_-]{6,20}$/.test(value) || !equal(value, recovery.identityCode)) {
    recovery.identityFailures++;
    if (recovery.identityFailures >= 5) recovery.identityLockUntil = now() + LOCK_MS;
    return error(recovery.identityFailures >= 5 ? "For safety, please pause for five minutes, then request a fresh instruction." : "That separate recovery identity value did not match. Check the simulated delivery message and try again.");
  }
  recovery.identityCode = "";
  recovery.identityVerified = true;
  recovery.stage = "identityVerified";
  return json({ ok: true, message: "Recovery identity value confirmed. Choose a new password when ready." });
}
async function replacePassword(request: Request) {
  const checked = sensitive(request);
  if (checked.failure) return checked.failure;
  let input: any; try { input = await body(request); } catch { return error("Please complete both password fields."); }
  expireReset(checked.session);
  const recovery = checked.session.recovery, reset = checked.session.reset;
  if (!recovery?.identityVerified || !reset || reset.used || reset.expiresAt <= now()) return error("Please complete a current recovery identity check before changing your password.");
  const problem = passwordProblem(input.password);
  if (problem) return error(problem);
  if (input.password !== input.confirmPassword) return error("The two passwords do not match yet.");
  if (reset.authorizesAccount && reset.accountKey) {
    const account = accounts.get(reset.accountKey);
    if (account) account.passwordHash = await Bun.password.hash(input.password, { algorithm: "argon2id" });
  }
  reset.token = "";
  reset.used = true;
  recovery.stage = "passwordChanged";
  return json({ ok: true, message: "Your new password is saved. Next, sign in and complete one extra safety check." });
}

async function login(request: Request) {
  const checked = sensitive(request);
  if (checked.failure) return checked.failure;
  let input: any; try { input = await body(request); } catch { return error("Enter your account details and password."); }
  const accountId = identifier(input.identifier);
  const key = await digest(accountId || "invalid-account");
  if (loginFailures.get(key)?.lockUntil > now()) return locked();
  const account = accountId ? accounts.get(key) : undefined;
  const valid = Boolean(account && typeof input.password === "string" && await Bun.password.verify(input.password, account.passwordHash));
  if (!valid) {
    const failure = loginFailures.get(key) || { failures: 0, lockUntil: 0 };
    failure.failures++;
    if (failure.failures >= 5) failure.lockUntil = now() + LOCK_MS;
    loginFailures.set(key, failure);
    return error(failure.failures >= 5 ? "For safety, please pause for five minutes before another sign-in attempt." : "Those sign-in details did not match. You can try again or use password recovery.", 401);
  }
  loginFailures.delete(key);
  checked.session.authenticatedAccount = null;
  checked.session.privacyAccepted = false;
  checked.session.mfa = {
    accountKey: key,
    demoCode: String(100000 + crypto.getRandomValues(new Uint32Array(1))[0] % 900000),
    possessionCode: mockCode(8),
    codeConfirmed: false, independentPossession: false, completed: false,
    expiresAt: now() + MFA_MS, failures: 0, lockUntil: 0,
    possessionFailures: 0, possessionLockUntil: 0,
  };
  return json({
    ok: true,
    message: "Password confirmed. Enter the six-digit demonstration code, then enter the separate possession value.",
    testMfaCode: checked.session.mfa.demoCode,
    testPossessionValue: checked.session.mfa.possessionCode,
  });
}
async function verifyMfaCode(request: Request) {
  const checked = sensitive(request);
  if (checked.failure) return checked.failure;
  let input: any; try { input = await body(request); } catch { return error("Enter the six-digit safety code."); }
  const mfa = checked.session.mfa;
  if (!mfa || mfa.expiresAt <= now()) return error("That safety code has expired. Sign in again and complete MFA when ready.", 401);
  if (mfa.lockUntil > now()) return locked();
  const code = typeof input.code === "string" ? input.code : "";
  if (!equal(code, mfa.demoCode)) {
    mfa.failures++;
    if (mfa.failures >= 5) mfa.lockUntil = now() + LOCK_MS;
    return error(mfa.failures >= 5 ? "For safety, pause for five minutes, then sign in again." : "That safety code did not match. Please check it and try again.");
  }
  mfa.codeConfirmed = true;
  return json({ ok: true, message: "Demonstration code confirmed. Enter the distinct possession value from the simulated delivery message." });
}

/* Task: validate a distinct possession-factor value, separate from the six-digit MFA code. */
async function verifyMfaPossession(request: Request) {
  const checked = sensitive(request);
  if (checked.failure) return checked.failure;
  let input: any; try { input = await body(request); } catch { return error("Enter the separate possession value."); }
  const mfa = checked.session.mfa;
  if (!mfa || mfa.expiresAt <= now()) return error("That sign-in check has expired. Sign in again and complete MFA when ready.", 401);
  if (!mfa.codeConfirmed) return error("First enter the six-digit demonstration code.");
  if (mfa.possessionLockUntil > now()) return locked();
  const value = typeof input.value === "string" ? input.value.trim().toUpperCase() : "";
  if (!/^[A-Z0-9_-]{6,20}$/.test(value) || !equal(value, mfa.possessionCode)) {
    mfa.possessionFailures++;
    if (mfa.possessionFailures >= 5) mfa.possessionLockUntil = now() + LOCK_MS;
    return error(mfa.possessionFailures >= 5 ? "For safety, pause for five minutes, then sign in again." : "That separate possession value did not match. Check the simulated delivery message and try again.");
  }
  mfa.possessionCode = "";
  mfa.independentPossession = true;
  mfa.completed = true;
  checked.session.authenticatedAccount = mfa.accountKey;
  return json({ ok: true, message: "Separate possession value confirmed. You are signed in." });
}

function authenticated(session: any) {
  return Boolean(session?.authenticatedAccount && session.mfa?.completed && session.mfa?.independentPossession && session.mfa.expiresAt > now());
}
function mfaExpired(session: any) {
  return Boolean(session?.authenticatedAccount && session.mfa && session.mfa.expiresAt <= now());
}
async function acceptPrivacy(request: Request) {
  const checked = sensitive(request);
  if (checked.failure) return checked.failure;
  if (mfaExpired(checked.session)) return error("Your MFA safety check has expired. Please sign in and complete MFA again before accepting privacy conditions.", 401);
  if (!authenticated(checked.session)) return error("Please sign in and complete MFA before changing privacy conditions.", 401);
  checked.session.privacyAccepted = true;
  return json({ ok: true, message: "Privacy conditions accepted. You can now confirm the appointment request." });
}
async function bookAppointment(request: Request) {
  const checked = sensitive(request);
  if (checked.failure) return checked.failure;
  if (mfaExpired(checked.session)) return error("Your MFA safety check has expired. Please sign in and complete MFA again before confirming an appointment request.", 401);
  if (!authenticated(checked.session)) return error("Please sign in and complete MFA again before confirming an appointment request.", 401);
  if (!checked.session.privacyAccepted) return error("Please accept the privacy conditions before confirming an appointment.", 403);
  checked.session.appointmentBooked = true;
  return json({ ok: true, message: "Your medication review appointment request is confirmed. Hospital staff will follow up." });
}
function state(session: any) {
  expireReset(session);
  return {
    ok: true, recoveryStage: session.recovery?.stage || "start", authenticated: authenticated(session),
    mfaExpired: mfaExpired(session), privacyAccepted: session.privacyAccepted, appointmentBooked: session.appointmentBooked,
    needsMfa: Boolean(session.mfa && !session.mfa.completed && session.mfa.expiresAt > now()),
    resetExpiresAt: session.reset?.used ? 0 : (session.reset?.expiresAt || 0),
    resetAvailable: Boolean(session.reset && !session.reset.used && session.reset.expiresAt > now()),
  };
}

/* Requirements accessibility/inclusivity: quiet SPA, orientation, no visible countdown. */
function page(nonce: string, csrf: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hospital account recovery</title><style nonce="${nonce}">
:root{--ink:#163043;--blue:#075e8d;--pale:#eef7fa;--line:#b9cbd4;--good:#075d43;--warn:#7a4300}*{box-sizing:border-box}body{margin:0;background:#f5f8f9;color:var(--ink);font:18px/1.52 system-ui,sans-serif}header{background:#fff;border-bottom:4px solid var(--blue);padding:1rem max(1.2rem,calc((100% - 900px)/2))}.brand{font-size:1.2rem;font-weight:800}main{max-width:900px;margin:auto;padding:1.5rem 1.2rem 4rem}h1{font-size:2rem;line-height:1.2}h2{font-size:1.35rem;line-height:1.25}.card,.progress{background:#fff;border:1px solid var(--line);border-radius:12px;padding:1.2rem;margin:1rem 0}.progress ol{display:flex;flex-wrap:wrap;gap:.45rem;list-style:none;padding:0;margin:.7rem 0 0}.progress li{background:#e6edf0;border-radius:99px;padding:.22rem .65rem;font-size:.87rem}.progress li.active{background:var(--blue);color:#fff}.panel[hidden],.hide{display:none!important}label{display:block;font-weight:700;margin-top:1rem}input{display:block;width:100%;max-width:560px;font:inherit;padding:.62rem;border:2px solid #718894;border-radius:7px}input:focus,button:focus,a:focus{outline:3px solid #e99b27;outline-offset:3px}button{font:inherit;font-weight:700;background:var(--blue);color:#fff;border:0;border-radius:7px;padding:.65rem 1rem;margin:.9rem .5rem 0 0;cursor:pointer}.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue)}.feedback{border-left:5px solid var(--blue);background:var(--pale);padding:.7rem .9rem;margin:1rem 0;min-height:1.6rem}.feedback.error{border-color:var(--warn);background:#fff5e9}.feedback.good{border-color:var(--good);background:#ebf8f1}.help{background:#fff8df;border:1px solid #d8bc64;border-radius:9px;padding:1rem}.logs{background:#12242e;color:#def2ee;border-radius:8px;padding:.8rem;max-height:180px;overflow:auto;font:14px/1.4 ui-monospace,monospace}.logs p{margin:.25rem 0}.small{font-size:.92rem}@media(max-width:550px){body{font-size:17px}.progress ol{display:block}.progress li{display:inline-block;margin:.15rem}}
</style></head><body><header><div class="brand">Hospital secure account portal</div></header><main>
<h1>Password recovery, one calm step at a time</h1><p id="next">Start by asking for a secure recovery instruction.</p>
<nav class="progress" aria-label="Recovery progress"><strong>Your progress</strong><ol><li id="p1">1. Recovery</li><li id="p2">2. Identity check</li><li id="p3">3. New password</li><li id="p4">4. Sign in</li><li id="p5">5. Privacy &amp; appointment</li></ol></nav>

<section id="requestPanel" class="panel card"><h2>1. Ask for a recovery instruction</h2><p>Enter your email address or account reference. We will not say whether an account is registered.</p><form id="requestForm" novalidate><label for="identifier">Email address or account reference</label><input id="identifier" autocomplete="username" maxlength="120" required><button>Prepare recovery instruction</button></form><div id="requestFeedback" class="feedback" aria-live="polite">You can pause at any time. Progress remains in this browser session.</div><p><a id="deliveryLink" class="hide" href="#instruction">Open simulated recovery instruction</a></p><button id="requestContinue" class="secondary hide" type="button">Continue</button></section>

<section id="instructionPanel" class="panel card" hidden><h2>2. Confirm the recovery instruction</h2><p>Paste or type the clearly labelled <strong>testing mock reset token</strong> from the simulated instruction. Recovery instructions expire after 15 minutes for security. There is no rush, and you can always request a fresh instruction after expiry.</p><form id="instructionForm" novalidate><label for="instructionValue">Testing mock reset token</label><input id="instructionValue" autocomplete="one-time-code" maxlength="80" required><button>Confirm testing mock token</button></form><div id="instructionFeedback" class="feedback" aria-live="polite">There is no rush. Check the value, then continue.</div><button id="instructionContinue" class="secondary hide" type="button">Continue to identity check</button><button id="backRequest" class="secondary" type="button">Request a new instruction</button></section>

<section id="identityPanel" class="panel card" hidden><h2>Separate recovery identity check</h2><p>Enter the separate <strong>testing mock recovery identity value</strong> shown in the simulated delivery message and Logs. It is different from the reset token. Recovery instructions expire after 15 minutes for security; no action is rushed, and you may request a fresh instruction after expiry.</p><form id="identityForm" novalidate><label for="identityValue">Testing mock recovery identity value</label><input id="identityValue" autocomplete="one-time-code" maxlength="20" required><button>Confirm recovery identity value</button></form><div id="identityFeedback" class="feedback" aria-live="polite">This extra step helps protect your account if an instruction is seen by someone else.</div><button id="identityContinue" class="secondary hide" type="button">Continue to new password</button></section>

<section id="passwordPanel" class="panel card" hidden><h2>3. Choose a new password</h2><p>Use 12 or more characters, with an uppercase letter, lowercase letter, number, and symbol.</p><form id="passwordForm" novalidate><label for="newPassword">New password</label><input id="newPassword" type="password" autocomplete="new-password" maxlength="128" required><label for="confirmPassword">Confirm new password</label><input id="confirmPassword" type="password" autocomplete="new-password" maxlength="128" required><button>Save new password</button></form><div id="passwordFeedback" class="feedback" aria-live="polite">After saving, you will sign in with your new password.</div><button id="passwordContinue" class="secondary hide" type="button">Continue to sign in</button></section>

<section id="loginPanel" class="panel card" hidden><h2>4. Sign in</h2><p>Use your account reference and password. Then complete two safety checks.</p><form id="loginForm" novalidate><label for="loginIdentifier">Email address or account reference</label><input id="loginIdentifier" autocomplete="username" maxlength="120" required><label for="loginPassword">Password</label><input id="loginPassword" type="password" autocomplete="current-password" maxlength="128" required><button>Sign in securely</button></form><div id="loginFeedback" class="feedback" aria-live="polite">You may use password recovery if you need it.</div><button id="loginContinue" class="secondary hide" type="button">Continue to safety code</button></section>

<section id="mfaPanel" class="panel card" hidden><h2>Extra safety checks</h2><p>First enter the six-digit demonstration code from the simulated secure message. Then enter the distinct possession value from that message. Both checks are needed for a current authenticated session.</p><form id="mfaForm" novalidate><label for="mfaCode">Six-digit demonstration code</label><input id="mfaCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button>Confirm demonstration code</button></form><form id="possessionForm" class="hide" novalidate><label for="possessionValue">Separate testing mock possession value</label><input id="possessionValue" autocomplete="one-time-code" maxlength="20" required><button>Confirm possession value</button></form><div id="mfaFeedback" class="feedback" aria-live="polite">This code is only a demonstration step.</div><button id="mfaContinue" class="secondary hide" type="button">Continue to privacy conditions</button></section>

<section id="privacyPanel" class="panel card" hidden><h2>5. Updated privacy conditions</h2><p>To allow hospital authorities to arrange the medication dosage review, please accept the updated privacy conditions.</p><ul><li>Your information is used only for healthcare and appointment coordination.</li><li>You can ask hospital staff for help with these conditions.</li></ul><button id="privacyButton" type="button">I accept the updated privacy conditions</button><div id="privacyFeedback" class="feedback" aria-live="polite">Read this at your own pace.</div><button id="privacyContinue" class="secondary hide" type="button">Continue to appointment request</button></section>

<section id="appointmentPanel" class="panel card" hidden><h2>Confirm medication review request</h2><p>Your privacy conditions are accepted. Confirm when you are ready.</p><button id="appointmentButton" type="button">Confirm appointment request</button><div id="appointmentFeedback" class="feedback" aria-live="polite">No appointment is requested until you select the button.</div></section>

<aside class="help"><h2>Need help or a reminder?</h2><p>You can pause and return without a countdown. Recovery instructions expire after 15 minutes for security, but no action is rushed and a fresh instruction is always available after expiry. Contact your usual hospital support channel for help. Hospital staff will never ask you to send a password or recovery code by email or phone. Check that this is the secure hospital portal before entering details.</p></aside>
<section class="card"><h2>Logs</h2><p class="small">Simulated delivery and verification messages are shown here for this demonstration.</p><div id="logs" class="logs" aria-live="polite"></div></section>
</main><script nonce="${nonce}">(()=>{"use strict";
const csrf=${JSON.stringify(csrf)},$=id=>document.getElementById(id),panels=["requestPanel","instructionPanel","identityPanel","passwordPanel","loginPanel","mfaPanel","privacyPanel","appointmentPanel"];
let token="",savedId=sessionStorage.getItem("hospital-recovery-identifier")||"";
const recoveryKey="hospital-recovery-mock";
function log(message){console.log(message);const p=document.createElement("p");p.textContent=message;$("logs").append(p);$("logs").scrollTop=$("logs").scrollHeight}
function fb(id,message,kind){const e=$(id);e.textContent=typeof message==="string"?message:"Please try again.";e.className="feedback"+(kind?" "+kind:"")}
function choose(id,step,focus){panels.forEach(p=>$(p).hidden=p!==id);for(let n=1;n<6;n++)$("p"+n).classList.toggle("active",n===step);$("next").textContent=["Start by asking for a secure recovery instruction.","Your next step is to confirm the instruction and identity check.","Your next step is to choose a strong new password.","Your next step is to sign in and complete the safety checks.","You are almost done: accept privacy conditions, then confirm the appointment request."][step-1];window.scrollTo({top:0,behavior:"smooth"});setTimeout(()=>{const e=$(focus||id);if(e&&e.focus)e.focus()},0)}
function reveal(id){$(id).classList.remove("hide")}
function validId(v){return /^[a-z0-9@._+\\- ]{3,120}$/i.test(v.trim())}
function validPass(v){return v.length>=12&&v.length<=128&&/[a-z]/.test(v)&&/[A-Z]/.test(v)&&/[0-9]/.test(v)&&/[^A-Za-z0-9]/.test(v)}
function saveRecovery(value,expiresAt){if(typeof value==="string"&&Number.isFinite(expiresAt))sessionStorage.setItem(recoveryKey,JSON.stringify({token:value,expiresAt:expiresAt}))}
function clearRecovery(){token="";sessionStorage.removeItem(recoveryKey)}
function restoreRecovery(){try{const item=JSON.parse(sessionStorage.getItem(recoveryKey)||"null");if(item&&typeof item.token==="string"&&Number(item.expiresAt)>Date.now()){token=item.token;return true}clearRecovery()}catch{clearRecovery()}return false}
async function api(path,data){try{const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)}),v=await r.json();return v&&typeof v==="object"?v:{ok:false,message:"The secure portal could not complete that step."}}catch{return{ok:false,message:"The secure portal could not complete that step. Please try again."}}}
function instruction(){if(!restoreRecovery()&&token==="")fb("instructionFeedback","This browser has no current saved recovery instruction. You can request a fresh instruction whenever you are ready.","error");choose("instructionPanel",2,"instructionValue");if(token)$("instructionValue").value=token}
$("identifier").value=savedId;$("deliveryLink").onclick=e=>{e.preventDefault();instruction()};window.onhashchange=()=>{if(location.hash==="#instruction")instruction()};
$("requestForm").onsubmit=async e=>{e.preventDefault();const value=$("identifier").value.trim();if(!validId(value))return fb("requestFeedback","Enter an email address or account reference using letters, numbers, and common punctuation.","error");savedId=value;sessionStorage.setItem("hospital-recovery-identifier",value);const r=await api("/api/recovery/request",{identifier:value});fb("requestFeedback",r.message,r.ok?"good":"error");if(r.ok){token=typeof r.testValue==="string"?r.testValue:"";saveRecovery(token,Number(r.expiresAt));$("deliveryLink").href=typeof r.deliveryPath==="string"?r.deliveryPath:"#instruction";reveal("deliveryLink");if(token)log("[mock delivery] TESTING MOCK RESET TOKEN: "+token);if(typeof r.testIdentityValue==="string")log("[mock delivery] TESTING MOCK RECOVERY IDENTITY VALUE: "+r.testIdentityValue);reveal("requestContinue")}};
$("requestContinue").onclick=instruction;$("backRequest").onclick=()=>choose("requestPanel",1,"identifier");
$("instructionForm").onsubmit=async e=>{e.preventDefault();const value=$("instructionValue").value.trim();if(!/^[A-Za-z0-9_-]{20,}$/.test(value))return fb("instructionFeedback","Enter the testing mock reset token from the simulated instruction.","error");const r=await api("/api/recovery/instruction",{value});fb("instructionFeedback",r.message,r.ok?"good":"error");if(r.ok)reveal("instructionContinue")};
$("instructionContinue").onclick=()=>choose("identityPanel",2,"identityValue");
$("identityForm").onsubmit=async e=>{e.preventDefault();const value=$("identityValue").value.trim().toUpperCase();if(!/^[A-Z0-9_-]{6,20}$/.test(value))return fb("identityFeedback","Enter the recovery identity value from the simulated delivery message.","error");const r=await api("/api/recovery/identity",{value});fb("identityFeedback",r.message,r.ok?"good":"error");if(r.ok){log("[mock identity] Separate recovery identity value confirmed.");reveal("identityContinue")}};
$("identityContinue").onclick=()=>choose("passwordPanel",3,"newPassword");
$("passwordForm").onsubmit=async e=>{e.preventDefault();const p=$("newPassword").value,c=$("confirmPassword").value;if(!validPass(p))return fb("passwordFeedback","Use 12+ characters with uppercase, lowercase, number, and symbol.","error");if(p!==c)return fb("passwordFeedback","The two passwords do not match yet.","error");const r=await api("/api/recovery/password",{password:p,confirmPassword:c});fb("passwordFeedback",r.message,r.ok?"good":"error");if(r.ok){clearRecovery();log("[mock verification] Password replacement completed; reset token was invalidated.");reveal("passwordContinue")}};
$("passwordContinue").onclick=()=>{$("loginIdentifier").value=savedId;choose("loginPanel",4,"loginPassword")};
$("loginForm").onsubmit=async e=>{e.preventDefault();const value=$("loginIdentifier").value.trim(),password=$("loginPassword").value;if(!validId(value)||!password)return fb("loginFeedback","Enter your account reference and password.","error");const r=await api("/api/login",{identifier:value,password});fb("loginFeedback",r.message,r.ok?"good":"error");if(r.ok){if(typeof r.testMfaCode==="string")log("[mock MFA] Demonstration code (not sufficient to sign in): "+r.testMfaCode);if(typeof r.testPossessionValue==="string")log("[mock MFA] DISTINCT TESTING MOCK POSSESSION VALUE: "+r.testPossessionValue);reveal("loginContinue")}};
$("loginContinue").onclick=()=>choose("mfaPanel",4,"mfaCode");
$("mfaForm").onsubmit=async e=>{e.preventDefault();const code=$("mfaCode").value.trim();if(!/^\\d{6}$/.test(code))return fb("mfaFeedback","Enter all six digits of the demonstration code.","error");const r=await api("/api/mfa/code",{code});fb("mfaFeedback",r.message,r.ok?"good":"error");if(r.ok){reveal("possessionForm");setTimeout(()=>$("possessionValue").focus(),0)}};
$("possessionForm").onsubmit=async e=>{e.preventDefault();const value=$("possessionValue").value.trim().toUpperCase();if(!/^[A-Z0-9_-]{6,20}$/.test(value))return fb("mfaFeedback","Enter the separate possession value from the simulated delivery message.","error");const r=await api("/api/mfa/possession",{value});fb("mfaFeedback",r.message,r.ok?"good":"error");if(r.ok){log("[mock MFA] Separate possession value confirmed.");reveal("mfaContinue")}};
$("mfaContinue").onclick=()=>choose("privacyPanel",5,"privacyButton");
$("privacyButton").onclick=async()=>{const r=await api("/api/privacy/accept",{});fb("privacyFeedback",r.message,r.ok?"good":"error");if(r.ok){log("[mock privacy] Updated privacy conditions accepted.");reveal("privacyContinue")}};
$("privacyContinue").onclick=()=>choose("appointmentPanel",5,"appointmentButton");
$("appointmentButton").onclick=async()=>{const r=await api("/api/appointment",{});fb("appointmentFeedback",r.message,r.ok?"good":"error");if(r.ok)log("[mock appointment] Medication review appointment request confirmed.")};
(async()=>{const incoming=new URL(location.href).searchParams.get("recovery-test");if(incoming&&/^[A-Za-z0-9_-]{20,}$/.test(incoming)){token=incoming;const existing=restoreRecovery();if(!existing)saveRecovery(token,Date.now()+900000);history.replaceState({},"","/#instruction");log("[mock delivery] Simulated recovery instruction opened. TESTING MOCK RESET TOKEN: "+token);instruction();return}try{const s=await(await fetch("/api/state",{credentials:"same-origin"})).json();if(!s.resetAvailable)clearRecovery();else if(restoreRecovery()){$("instructionValue").value=token}if(s.appointmentBooked){choose("appointmentPanel",5,"appointmentButton");fb("appointmentFeedback","Your medication review appointment request is confirmed.","good")}else if(s.mfaExpired){choose("loginPanel",4,"loginPassword");fb("loginFeedback","Your MFA safety check expired. Please sign in and complete MFA again.","error")}else if(s.authenticated&&s.privacyAccepted)choose("appointmentPanel",5,"appointmentButton");else if(s.authenticated)choose("privacyPanel",5,"privacyButton");else if(s.needsMfa)choose("mfaPanel",4,"mfaCode");else if(s.recoveryStage==="passwordChanged"){$("loginIdentifier").value=savedId;choose("loginPanel",4,"loginPassword")}else if(s.recoveryStage==="identityVerified")choose("passwordPanel",3,"newPassword");else if(s.recoveryStage==="identity")choose("identityPanel",2,"identityValue");else if(s.recoveryStage==="instructionSent")instruction();else choose("requestPanel",1,"identifier")}catch{choose("requestPanel",1,"identifier")}})();
})();</script></body></html>`;
}

async function provisionAccounts() {
  for (const name of ["helena@example.com", "helena.patient@hospital.test", "helena patient"]) {
    accounts.set(await digest(name), { passwordHash: await Bun.password.hash("Initial!HospitalPassword9", { algorithm: "argon2id" }), createdAt: now() });
  }
}
await provisionAccounts();

const server = Bun.serve({
  port: Number(process.env.PORT || 3000),
  tls: { cert: CERT, key: KEY },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.headers.get("x-forwarded-proto") === "http") return respond("Secure HTTPS connection required.", 426, "text/plain; charset=utf-8");
      if (request.method === "GET" && url.pathname === "/") {
        let session = getSession(request);
        const fresh = !session;
        if (!session) session = newSession();
        const nonce = randomToken(18);
        return respond(page(nonce, session.csrf), 200, "text/html; charset=utf-8", nonce, fresh ? { "Set-Cookie": sessionCookie(session.id) } : {});
      }
      if (request.method === "GET" && url.pathname === "/api/state") {
        const session = getSession(request);
        return session ? json(state(session)) : error("Please open the secure portal first.", 401);
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
      return respond("Not found.", 404, "text/plain; charset=utf-8");
    } catch {
      return respond("The secure portal could not process that request.", 500, "text/plain; charset=utf-8");
    }
  },
});
console.log(`Hospital recovery portal listening securely on https://localhost:${server.port}`);
