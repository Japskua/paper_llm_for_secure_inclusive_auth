
import { timingSafeEqual } from "node:crypto";

/* Requirements 1, 3, 4: secure in-memory sessions, hashed reset records, expiry, CSRF, and throttling. */
const sessions = new Map<string, any>();
const accounts = new Map<string, any>();
const resetTokens = new Map<string, any>();
const recoveryIssues = new Map<string, number[]>();
const loginFailures = new Map<string, any>();

const CERT = Bun.file("certs/cert.pem");
const KEY = Bun.file("certs/key.pem");
const COOKIE = "__Host-hospital_recovery";
const SESSION_MS = 8 * 60 * 60 * 1000;
const RESET_MS = 15 * 60 * 1000;
const MFA_MS = 10 * 60 * 1000;
const LOCK_MS = 5 * 60 * 1000;
const RESET_CONFIRM_FAILURE_LIMIT = 5;
const RESET_CONFIRM_COOLDOWN_MS = 5 * 60 * 1000;
const BODY_LIMIT = 8192;
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
    recovery: null,
    mfa: null,
    authenticatedAccount: null,
    privacyAccepted: false,
    appointmentBooked: false,
    /* Task: session-scoped reset-token confirmation failure tracking. */
    resetConfirmationFailures: { count: 0, lockUntil: 0 },
  };
  sessions.set(session.id, session);
  return session;
}
function cookieValue(request: Request, key: string) {
  const item = (request.headers.get("cookie") || "").split(";").map(v => v.trim()).find(v => v.startsWith(key + "="));
  try { return item ? decodeURIComponent(item.slice(key.length + 1)) : ""; } catch { return ""; }
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
  for (const [id, s] of sessions) if (s.expiresAt <= now()) sessions.delete(id);
  for (const [hash, record] of resetTokens) {
    if (record.expiresAt <= now() || (record.used && record.usedAt < now() - RESET_MS)) resetTokens.delete(hash);
  }
  for (const [key, values] of recoveryIssues) {
    const left = values.filter((time: number) => time > now() - RESET_MS);
    if (left.length) recoveryIssues.set(key, left); else recoveryIssues.delete(key);
  }
  for (const [key, failure] of loginFailures) if (failure.lockUntil && failure.lockUntil <= now()) loginFailures.delete(key);
}
setInterval(clean, 60_000);

function headers(nonce = "") {
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
  return new Response(body, { status, headers: { ...headers(nonce), "Content-Type": type, ...extra } });
}
function json(value: any, status = 200) {
  return respond(JSON.stringify(value), status, "application/json; charset=utf-8");
}
function error(message: string, status = 400) {
  return json({ ok: false, message }, status);
}
function sessionCookie(id: string) {
  return `${COOKIE}=${encodeURIComponent(id)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MS / 1000}`;
}

/* Task: enforce received-byte limit before JSON parsing; Content-Length is never trusted. */
async function body(request: Request) {
  if (!request.body) return {};
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      received += part.value.byteLength;
      if (received > BODY_LIMIT) {
        await reader.cancel();
        throw new Error("body too large");
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  try {
    const text = new TextDecoder().decode(Buffer.concat(chunks.map(v => Buffer.from(v))));
    const value = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  } catch {
    throw new Error("invalid body");
  }
}

/* Requirement 1: same-origin and unique per-session CSRF checks on sensitive actions. */
function sensitive(request: Request) {
  const session = getSession(request);
  if (!session) return { failure: error("Please return to the secure portal and try again.", 401) };
  if (request.headers.get("origin") !== new URL(request.url).origin) {
    return { failure: error("This request could not be confirmed safely. Please try again in the portal.", 403) };
  }
  if (request.headers.get("x-csrf-token") !== session.csrf) {
    return { failure: error("Your secure form check did not match. Refresh the page and try again.", 403) };
  }
  return { session };
}
function identifier(value: unknown) {
  const s = typeof value === "string" ? value.trim().toLowerCase() : "";
  return /^[a-z0-9@._+\- ]{3,120}$/.test(s) ? s : "";
}
function passwordProblem(value: unknown) {
  if (typeof value !== "string") return "Enter a password.";
  if (value.length < 12) return "Use at least 12 characters.";
  if (value.length > 128) return "Use no more than 128 characters.";
  return /[a-z]/.test(value) && /[A-Z]/.test(value) && /[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value)
    ? "" : "Use an uppercase letter, lowercase letter, number, and symbol.";
}
function locked() {
  return error("For safety, please pause for five minutes before trying again.", 429);
}
function issueAllowed(session: any, accountKey: string) {
  const key = `${session.id}:${accountKey}`;
  const tries = (recoveryIssues.get(key) || []).filter((time: number) => time > now() - RESET_MS);
  if (tries.length >= 3) return false;
  tries.push(now());
  recoveryIssues.set(key, tries);
  return true;
}

/* Task: session-scoped malformed, unknown, expired, and used token attempt throttling. */
function resetConfirmationStatus(session: any) {
  const failure = session.resetConfirmationFailures || (session.resetConfirmationFailures = { count: 0, lockUntil: 0 });
  if (failure.lockUntil > now()) return "locked";
  if (failure.lockUntil) {
    failure.count = 0;
    failure.lockUntil = 0;
  }
  return "open";
}
function resetConfirmationFailure(session: any) {
  const failure = session.resetConfirmationFailures || (session.resetConfirmationFailures = { count: 0, lockUntil: 0 });
  if (failure.lockUntil > now()) return { locked: true, count: failure.count };
  failure.count++;
  if (failure.count >= RESET_CONFIRM_FAILURE_LIMIT) {
    failure.lockUntil = now() + RESET_CONFIRM_COOLDOWN_MS;
    return { locked: true, count: failure.count };
  }
  return { locked: false, count: failure.count };
}
function clearResetConfirmationFailures(session: any) {
  /* Task: clear this session's counter after a successful token confirmation. */
  session.resetConfirmationFailures = { count: 0, lockUntil: 0 };
}
function resetConfirmationFailureResponse(session: any, fallback: string) {
  const result = resetConfirmationFailure(session);
  return result.locked
    ? error("For safety, reset-token confirmation is paused for five minutes. You can return when ready.", 429)
    : error(fallback);
}

/* Task: every recovery stage resolves the global hashed reset record and rejects stale/used records. */
function resetRecord(session: any) {
  const hash = session?.recovery?.tokenHash;
  const record = hash && resetTokens.get(hash);
  if (!record || record.used || record.expiresAt <= now()) {
    if (session?.recovery) session.recovery.stage = "expired";
    return undefined;
  }
  return record;
}
function attachRecovery(session: any, tokenHash: string, record: any, tokenConfirmed: boolean) {
  session.recovery = {
    tokenHash,
    stage: tokenConfirmed ? "identity" : "instructionSent",
    tokenConfirmed,
    identityVerified: false,
  };
  record.lastAttachedAt = now();
}
async function findResetToken(value: unknown) {
  const token = typeof value === "string" ? value.trim() : "";
  if (!/^[A-Za-z0-9_-]{20,200}$/.test(token)) return { token: "", hash: "", record: undefined };
  const hash = await digest(token);
  return { token, hash, record: resetTokens.get(hash) };
}
function invalidRecord(record: any) {
  return !record || record.used || record.expiresAt <= now();
}

async function recoveryRequest(request: Request) {
  const check = sensitive(request); if (check.failure) return check.failure;
  let input: any; try { input = await body(request); } catch { return error("Please enter your account details in the form."); }
  const id = identifier(input.identifier);
  if (!id) return error("Enter an email address or account reference using letters, numbers, and common punctuation.");

  const accountKey = await digest(id);
  const authorized = Boolean(accounts.get(accountKey)) && issueAllowed(check.session, accountKey);
  check.session.recovery = { stage: "instructionSent", tokenHash: "", tokenConfirmed: false, identityVerified: false };

  if (!authorized) {
    return json({ ok: true, message: "If the account can receive recovery instructions, an instruction has been prepared. Continue when you are ready." });
  }

  const token = randomToken();
  const tokenHash = await digest(token);
  const identityCode = mockCode(8);
  resetTokens.set(tokenHash, {
    accountKey,
    expiresAt: now() + RESET_MS,
    used: false,
    usedAt: 0,
    recoveryIdentityVerifier: await digest(identityCode),
    identityFailures: 0,
    identityLockUntil: 0,
  });
  check.session.recovery.tokenHash = tokenHash;
  return json({
    ok: true,
    message: "If the account can receive recovery instructions, an instruction has been prepared. Continue when you are ready.",
    deliveryPath: `/?recovery-test=${encodeURIComponent(token)}`,
    testValue: token,
    expiresAt: now() + RESET_MS,
    testIdentityValue: identityCode,
  });
}

/* Manual token entry globally resolves a record, including after a new browser session. */
async function confirmInstruction(request: Request) {
  const check = sensitive(request); if (check.failure) return check.failure;

  if (resetConfirmationStatus(check.session) === "locked") {
    return error("For safety, reset-token confirmation is paused for five minutes. You can return when ready.", 429);
  }

  let input: any;
  try {
    input = await body(request);
  } catch {
    return resetConfirmationFailureResponse(check.session, "Enter the testing mock reset token.");
  }

  const found = await findResetToken(input.value);
  if (!found.token || !found.hash) {
    return resetConfirmationFailureResponse(check.session, "That testing mock reset token is not in the expected format.");
  }

  const record = found.record;
  if (invalidRecord(record)) {
    return resetConfirmationFailureResponse(check.session, "This reset instruction is invalid, expired, or already used. You can request a new one.");
  }

  /* Hash lookup is the secure verification; comparison protects the derived bearer value. */
  if (!equal(found.hash, await digest(found.token))) {
    return resetConfirmationFailureResponse(check.session, "That testing mock reset token did not match.");
  }

  attachRecovery(check.session, found.hash, record, true);
  clearResetConfirmationFailures(check.session);
  return json({ ok: true, message: "Testing mock reset token confirmed. Next, enter the separate recovery identity value." });
}
async function recoveryIdentity(request: Request) {
  const check = sensitive(request); if (check.failure) return check.failure;
  let input: any; try { input = await body(request); } catch { return error("Enter the separate recovery identity value."); }
  const recovery = check.session.recovery;
  const record = resetRecord(check.session);
  if (!recovery?.tokenConfirmed || !record) return error("First confirm a current testing mock reset token.");
  if (record.identityLockUntil > now()) return locked();

  const value = typeof input.value === "string" ? input.value.trim().toUpperCase() : "";
  const verifier = /^[A-Z0-9_-]{6,20}$/.test(value) ? await digest(value) : "";
  if (!verifier || !equal(verifier, record.recoveryIdentityVerifier)) {
    if (++record.identityFailures >= 5) record.identityLockUntil = now() + LOCK_MS;
    return error(record.identityFailures >= 5
      ? "For safety, please pause for five minutes, then request a fresh instruction."
      : "That separate recovery identity value did not match. Check the simulated delivery message and try again.");
  }
  recovery.identityVerified = true;
  recovery.stage = "identityVerified";
  return json({ ok: true, message: "Recovery identity value confirmed. Choose a new password when ready." });
}
async function replacePassword(request: Request) {
  const check = sensitive(request); if (check.failure) return check.failure;
  let input: any; try { input = await body(request); } catch { return error("Please complete both password fields."); }
  const recovery = check.session.recovery;
  const record = resetRecord(check.session);
  if (!recovery?.identityVerified || !record) {
    return error("Please complete a current recovery identity check before changing your password.");
  }
  const problem = passwordProblem(input.password);
  if (problem) return error(problem);
  if (input.password !== input.confirmPassword) return error("The two passwords do not match yet.");

  const account = accounts.get(record.accountKey);
  if (!account) return error("This recovery instruction is no longer available. Please request a new one.");

  const newHash = await Bun.password.hash(input.password, { algorithm: "argon2id" });
  const current = resetTokens.get(recovery.tokenHash);
  if (current !== record || invalidRecord(current)) return error("This recovery instruction is no longer available. Please request a new one.");
  account.passwordHash = newHash;
  record.used = true;
  record.usedAt = now();
  record.recoveryIdentityVerifier = "";
  recovery.stage = "passwordChanged";
  recovery.identityVerified = false;
  return json({ ok: true, message: "Your new password is saved. Next, sign in and complete one extra safety check." });
}

async function login(request: Request) {
  const check = sensitive(request); if (check.failure) return check.failure;
  let input: any; try { input = await body(request); } catch { return error("Enter your account details and password."); }
  const id = identifier(input.identifier);
  const key = await digest(id || "invalid-account");
  if (loginFailures.get(key)?.lockUntil > now()) return locked();

  const account = id ? accounts.get(key) : undefined;
  const valid = Boolean(account && typeof input.password === "string" && await Bun.password.verify(input.password, account.passwordHash));
  if (!valid) {
    const failures = loginFailures.get(key) || { failures: 0, lockUntil: 0 };
    if (++failures.failures >= 5) failures.lockUntil = now() + LOCK_MS;
    loginFailures.set(key, failures);
    return error(failures.failures >= 5
      ? "For safety, please pause for five minutes before another sign-in attempt."
      : "Those sign-in details did not match. You can try again or use password recovery.", 401);
  }
  loginFailures.delete(key);
  check.session.authenticatedAccount = null;
  check.session.privacyAccepted = false;
  check.session.mfa = {
    accountKey: key,
    demoCode: String(100000 + crypto.getRandomValues(new Uint32Array(1))[0] % 900000),
    possessionCode: mockCode(8),
    codeConfirmed: false, independentPossession: false, completed: false,
    expiresAt: now() + MFA_MS, failures: 0, lockUntil: 0, possessionFailures: 0, possessionLockUntil: 0,
  };
  return json({
    ok: true,
    message: "Password confirmed. Enter the six-digit demonstration code, then enter the separate possession value.",
    testMfaCode: check.session.mfa.demoCode,
    testPossessionValue: check.session.mfa.possessionCode,
  });
}
async function mfaCode(request: Request) {
  const check = sensitive(request); if (check.failure) return check.failure;
  let input: any; try { input = await body(request); } catch { return error("Enter the six-digit safety code."); }
  const mfa = check.session.mfa;
  if (!mfa || mfa.expiresAt <= now()) return error("That safety code has expired. Sign in again and complete MFA when ready.", 401);
  if (mfa.lockUntil > now()) return locked();
  if (!equal(typeof input.code === "string" ? input.code : "", mfa.demoCode)) {
    if (++mfa.failures >= 5) mfa.lockUntil = now() + LOCK_MS;
    return error(mfa.failures >= 5 ? "For safety, pause for five minutes, then sign in again." : "That safety code did not match. Please check it and try again.");
  }
  mfa.codeConfirmed = true;
  return json({ ok: true, message: "Demonstration code confirmed. Enter the distinct possession value from the simulated delivery message." });
}
async function mfaPossession(request: Request) {
  const check = sensitive(request); if (check.failure) return check.failure;
  let input: any; try { input = await body(request); } catch { return error("Enter the separate possession value."); }
  const mfa = check.session.mfa;
  const value = typeof input.value === "string" ? input.value.trim().toUpperCase() : "";
  if (!mfa || mfa.expiresAt <= now()) return error("That sign-in check has expired. Sign in again and complete MFA when ready.", 401);
  if (!mfa.codeConfirmed) return error("First enter the six-digit demonstration code.");
  if (mfa.possessionLockUntil > now()) return locked();
  if (!/^[A-Z0-9_-]{6,20}$/.test(value) || !equal(value, mfa.possessionCode)) {
    if (++mfa.possessionFailures >= 5) mfa.possessionLockUntil = now() + LOCK_MS;
    return error(mfa.possessionFailures >= 5 ? "For safety, pause for five minutes, then sign in again." : "That separate possession value did not match. Check the simulated delivery message and try again.");
  }
  mfa.possessionCode = "";
  mfa.independentPossession = true;
  mfa.completed = true;
  check.session.authenticatedAccount = mfa.accountKey;
  return json({ ok: true, message: "Separate possession value confirmed. You are signed in." });
}
function authenticated(session: any) {
  return Boolean(session?.authenticatedAccount && session.mfa?.completed && session.mfa?.independentPossession && session.mfa.expiresAt > now());
}
function mfaExpired(session: any) {
  return Boolean(session?.mfa && session.mfa.expiresAt <= now());
}
async function privacy(request: Request) {
  const check = sensitive(request); if (check.failure) return check.failure;
  if (mfaExpired(check.session)) return error("Your MFA safety check has expired. Please sign in and complete MFA again before accepting privacy conditions.", 401);
  if (!authenticated(check.session)) return error("Please sign in and complete MFA before changing privacy conditions.", 401);
  check.session.privacyAccepted = true;
  return json({ ok: true, message: "Privacy conditions accepted. You can now confirm the appointment request." });
}
async function appointment(request: Request) {
  const check = sensitive(request); if (check.failure) return check.failure;
  if (mfaExpired(check.session)) return error("Your MFA safety check has expired. Please sign in and complete MFA again before confirming an appointment request.", 401);
  if (!authenticated(check.session)) return error("Please sign in and complete MFA again before confirming an appointment request.", 401);
  if (!check.session.privacyAccepted) return error("Please accept the privacy conditions before confirming an appointment.", 403);
  check.session.appointmentBooked = true;
  return json({ ok: true, message: "Your medication review appointment request is confirmed. Hospital staff will follow up." });
}
function state(session: any) {
  const record = resetRecord(session);
  return {
    ok: true,
    recoveryStage: session.recovery?.stage || "start",
    authenticated: authenticated(session),
    mfaExpired: mfaExpired(session),
    privacyAccepted: session.privacyAccepted,
    appointmentBooked: session.appointmentBooked,
    needsMfa: Boolean(session.mfa && !session.mfa.completed && session.mfa.expiresAt > now()),
    resetAvailable: Boolean(record),
  };
}

function page(nonce: string, csrf: string) {
return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
body{margin:0;background:#f5f8f9;color:#163043;font:18px/1.5 system-ui,sans-serif}header,main{padding:1rem max(1.2rem,calc((100% - 850px)/2))}header{display:flex;justify-content:space-between;gap:1rem;align-items:center;background:#fff;border-bottom:4px solid #075e8d;font-weight:800}main{padding-top:1.2rem}.card{background:#fff;border:1px solid #b9cbd4;border-radius:12px;padding:1.2rem;margin:1rem 0}h1{font-size:2rem;line-height:1.2}h2{font-size:1.35rem}label{display:block;font-weight:700;margin-top:1rem}input{box-sizing:border-box;display:block;width:100%;max-width:560px;font:inherit;padding:.6rem;border:2px solid #718894;border-radius:7px}button{font:inherit;font-weight:700;background:#075e8d;color:#fff;border:0;border-radius:7px;padding:.65rem 1rem;margin:.9rem .5rem 0 0;cursor:pointer}.secondary{background:#fff;color:#075e8d;border:2px solid #075e8d}.feedback{border-left:5px solid #075e8d;background:#eef7fa;padding:.7rem;margin:1rem 0}.error{border-color:#7a4300;background:#fff5e9}.good{border-color:#075d43;background:#ebf8f1}.delivery-link{margin:.7rem 0;font-weight:700}.hide,[hidden]{display:none!important}.progress{margin:1rem 0;padding:0;display:grid;grid-template-columns:repeat(7,1fr);gap:.35rem;list-style:none}.progress li{font-size:.78rem;background:#e4ebee;padding:.45rem;border-radius:6px}.progress .active{background:#075e8d;color:#fff;font-weight:800}.progress .done{background:#d8efe4}.logs{background:#12242e;color:#def2ee;padding:.8rem;border-radius:8px;max-height:180px;overflow:auto;font:14px ui-monospace,monospace}.logs p{margin:.25rem 0}.helpbox{border-left:5px solid #e99b27;background:#fff8e9;padding:.8rem;margin-top:.8rem}a:focus,input:focus,button:focus{outline:3px solid #e99b27;outline-offset:3px}@media(max-width:680px){.progress{grid-template-columns:repeat(2,1fr)}header{align-items:flex-start;flex-direction:column}}
</style></head><body>
<header><span>Hospital secure account portal</span><button id="help" class="secondary" type="button">Need help?</button></header>
<main><h1>Password recovery, one calm step at a time</h1><p id="next">Start by asking for a secure recovery instruction.</p>
<nav aria-label="Recovery progress"><ol class="progress" id="progress"><li data-step="request">1. Request recovery</li><li data-step="instruction">2. Confirm token</li><li data-step="identity">3. Verify identity</li><li data-step="password">4. New password</li><li data-step="login">5. Sign in & safety</li><li data-step="privacy">6. Privacy</li><li data-step="appointment">7. Appointment</li></ol></nav>

<section id="request" class="card"><h2>1. Ask for a recovery instruction</h2><form id="rf"><label>Email address or account reference<input id="id" maxlength="120" autocomplete="username"></label><button>Prepare recovery instruction</button></form><div id="rmsg" class="feedback" aria-live="polite">You can pause at any time. Progress remains in this browser session.</div><div id="rdelivery" class="delivery-link" aria-live="polite"></div><button id="rnext" class="secondary hide">Continue</button></section>
<section id="instruction" class="card" hidden><h2>2. Confirm recovery token</h2><form id="tf"><label>Testing mock reset token<input id="token" maxlength="200" autocomplete="one-time-code"></label><button>Confirm testing mock token</button></form><div id="tmsg" class="feedback" aria-live="polite"></div><button id="tnext" class="secondary hide">Continue to identity check</button></section>
<section id="identity" class="card" hidden><h2>3. Verify recovery identity</h2><form id="if"><label>Testing mock recovery identity value<input id="identityValue" maxlength="20"></label><button>Confirm recovery identity value</button></form><div id="imsg" class="feedback" aria-live="polite"></div><button id="inext" class="secondary hide">Continue to new password</button></section>
<section id="password" class="card" hidden><h2>4. Choose a new password</h2><p>Use 12 or more characters, with uppercase, lowercase, number, and symbol.</p><form id="pf"><label>New password<input id="pw" type="password" autocomplete="new-password"></label><label>Confirm new password<input id="cpw" type="password" autocomplete="new-password"></label><button>Save new password</button></form><div id="pmsg" class="feedback" aria-live="polite"></div><button id="pnext" class="secondary hide">Continue to sign in</button></section>
<section id="login" class="card" hidden><h2>5. Sign in and complete safety checks</h2><form id="lf"><label>Account reference<input id="lid" autocomplete="username"></label><label>Password<input id="lpw" type="password" autocomplete="current-password"></label><button>Sign in securely</button></form><div id="lmsg" class="feedback" aria-live="polite"></div><button id="lnext" class="secondary hide">Continue to safety code</button></section>
<section id="mfa" class="card" hidden><h2>5. Sign in and complete safety checks</h2><form id="mf"><label>Six-digit demonstration code<input id="code" maxlength="6" inputmode="numeric"></label><button>Confirm code</button></form><form id="vf" class="hide"><label>Separate possession value<input id="pos" maxlength="20"></label><button>Confirm possession value</button></form><div id="mmsg" class="feedback" aria-live="polite"></div><button id="mnext" class="secondary hide">Continue to privacy conditions</button></section>
<section id="privacy" class="card" hidden><h2>6. Updated privacy conditions</h2><p>Your information is used only for healthcare and appointment coordination.</p><button id="accept">I accept the updated privacy conditions</button><div id="qmsg" class="feedback" aria-live="polite"></div><button id="qnext" class="secondary hide">Continue to appointment request</button></section>
<section id="appointment" class="card" hidden><h2>7. Confirm medication review request</h2><button id="book">Confirm appointment request</button><div id="amsg" class="feedback" aria-live="polite"></div></section>
<section id="helpbox" class="card helpbox" hidden aria-live="polite"><h2>Hospital account support</h2><p>Pause whenever you need to. Contact Hospital Account Support through the hospital switchboard or your usual hospital contact for help returning to this task.</p><p><strong>Safety reminder:</strong> hospital staff will never ask for your password or recovery code by email, text message, or phone. Do not share them.</p><button id="closehelp" class="secondary" type="button">Close help</button></section>
<section class="card"><h2>Logs</h2><div id="logs" class="logs" aria-live="polite"></div></section>
</main>
<script nonce="${nonce}">
(()=>{"use strict";
const csrf=${JSON.stringify(csrf)},$=x=>document.getElementById(x),all=["request","instruction","identity","password","login","mfa","privacy","appointment"];
let saved=sessionStorage.getItem("hospital-id")||"",token="";
function log(x){console.log(x);const p=document.createElement("p");p.textContent=x;$("logs").append(p)}
function msg(id,x,good){const e=$(id);e.textContent=x;e.className="feedback "+(good?"good":"error")}
function show(x){all.forEach(y=>$(y).hidden=y!==x);const step=x==="mfa"?"login":x;document.querySelectorAll("#progress li").forEach(e=>{const order=["request","instruction","identity","password","login","privacy","appointment"];e.classList.toggle("active",e.dataset.step===step);e.classList.toggle("done",order.indexOf(e.dataset.step)<order.indexOf(step))});$("next").textContent="Current step: "+document.querySelector('#progress li[data-step="'+step+'"]').textContent+". You can pause and return whenever you need.";window.scrollTo({top:0,behavior:"smooth"})}
async function api(path,data){try{const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});return await response.json()}catch{return{ok:false,message:"The secure portal could not complete that step. Please try again."}}}

/* Task: validate server deliveryPath as a same-origin relative recovery URL, then create link with safe DOM APIs. */
function renderRecoveryLink(deliveryPath){
 const target=$("rdelivery");target.replaceChildren();
 if(typeof deliveryPath!=="string"||!deliveryPath.startsWith("/")||deliveryPath.startsWith("//"))return;
 try{
  const parsed=new URL(deliveryPath,location.origin);
  if(parsed.origin!==location.origin||parsed.pathname!=="/"||!parsed.searchParams.has("recovery-test")||parsed.hash)return;
  const link=document.createElement("a");
  link.href=parsed.pathname+parsed.search;
  link.textContent="Open simulated recovery instruction";
  link.setAttribute("aria-label","Open simulated recovery instruction in this secure portal");
  target.append(link);
 }catch{}
}
$("help").onclick=()=>{$("helpbox").hidden=false;$("helpbox").scrollIntoView({behavior:"smooth"})};$("closehelp").onclick=()=>{$("helpbox").hidden=true};
$("id").value=saved;
$("rf").onsubmit=async e=>{e.preventDefault();saved=$("id").value.trim();sessionStorage.setItem("hospital-id",saved);const r=await api("/api/recovery/request",{identifier:saved});msg("rmsg",r.message,r.ok);renderRecoveryLink(r.ok?r.deliveryPath:"");if(r.ok&&r.testValue){token=r.testValue;sessionStorage.setItem("hospital-token",token);log("[mock delivery] TESTING MOCK RESET TOKEN: "+token);log("[mock delivery] TESTING MOCK RECOVERY IDENTITY VALUE: "+r.testIdentityValue);$("rnext").classList.remove("hide")}else if(r.ok){$("rnext").classList.remove("hide")}};
$("rnext").onclick=()=>{show("instruction");$("token").value=token||sessionStorage.getItem("hospital-token")||""};
$("tf").onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery/instruction",{value:$("token").value.trim()});msg("tmsg",r.message,r.ok);if(r.ok)$("tnext").classList.remove("hide")};$("tnext").onclick=()=>show("identity");
$("if").onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery/identity",{value:$("identityValue").value.trim()});msg("imsg",r.message,r.ok);if(r.ok)$("inext").classList.remove("hide")};$("inext").onclick=()=>show("password");
$("pf").onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery/password",{password:$("pw").value,confirmPassword:$("cpw").value});msg("pmsg",r.message,r.ok);if(r.ok){log("[mock verification] Password replacement completed.");$("pnext").classList.remove("hide")}};$("pnext").onclick=()=>{$("lid").value=saved;show("login")};
$("lf").onsubmit=async e=>{e.preventDefault();const r=await api("/api/login",{identifier:$("lid").value,password:$("lpw").value});msg("lmsg",r.message,r.ok);if(r.ok){log("[mock MFA] Demonstration code: "+r.testMfaCode);log("[mock MFA] DISTINCT TESTING MOCK POSSESSION VALUE: "+r.testPossessionValue);$("lnext").classList.remove("hide")}};$("lnext").onclick=()=>show("mfa");
$("mf").onsubmit=async e=>{e.preventDefault();const r=await api("/api/mfa/code",{code:$("code").value.trim()});msg("mmsg",r.message,r.ok);if(r.ok)$("vf").classList.remove("hide")};
$("vf").onsubmit=async e=>{e.preventDefault();const r=await api("/api/mfa/possession",{value:$("pos").value.trim()});msg("mmsg",r.message,r.ok);if(r.ok)$("mnext").classList.remove("hide")};$("mnext").onclick=()=>show("privacy");
$("accept").onclick=async()=>{const r=await api("/api/privacy/accept",{});msg("qmsg",r.message,r.ok);if(r.ok)$("qnext").classList.remove("hide")};$("qnext").onclick=()=>show("appointment");
$("book").onclick=async()=>{const r=await api("/api/appointment",{});msg("amsg",r.message,r.ok);if(r.ok)log("[mock appointment] Medication review appointment request confirmed.")};
(async()=>{const incoming=new URL(location.href).searchParams.get("recovery-test");if(incoming){token=incoming;sessionStorage.setItem("hospital-token",token);show("identity");log("[mock delivery] Simulated recovery instruction opened and securely confirmed. Enter the recovery identity value.");return}try{const s=await(await fetch("/api/state",{credentials:"same-origin"})).json();if(s.mfaExpired){show("login");$("lid").value=saved;msg("lmsg","Your MFA safety check expired. Please sign in and complete MFA again.",false)}else if(s.appointmentBooked)show("appointment");else if(s.authenticated&&s.privacyAccepted)show("appointment");else if(s.authenticated)show("privacy");else if(s.needsMfa)show("mfa");else if(s.recoveryStage==="passwordChanged")show("login");else if(s.recoveryStage==="identityVerified")show("password");else if(s.recoveryStage==="identity")show("identity");else if(s.recoveryStage==="instructionSent"){show("instruction");$("token").value=sessionStorage.getItem("hospital-token")||""}else show("request")}catch{show("request")}})();
})();
</script></body></html>`;
}

async function provision() {
  for (const id of ["helena@example.com", "helena.patient@hospital.test", "helena patient"]) {
    accounts.set(await digest(id), { passwordHash: await Bun.password.hash("Initial!HospitalPassword9", { algorithm: "argon2id" }) });
  }
}
await provision();

const server = Bun.serve({
  port: Number(process.env.PORT || 3000),
  tls: { cert: CERT, key: KEY },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.headers.get("x-forwarded-proto") === "http") return respond("Secure HTTPS connection required.", 426, "text/plain");
      if (request.method === "GET" && url.pathname === "/") {
        let session = getSession(request);
        const fresh = !session;
        if (!session) session = newSession();

        /* A valid recovery link works globally, even in a fresh browser session. */
        const linkToken = url.searchParams.get("recovery-test");
        if (linkToken) {
          const found = await findResetToken(linkToken);
          if (!invalidRecord(found.record) && found.hash) {
            attachRecovery(session, found.hash, found.record, true);
            clearResetConfirmationFailures(session);
          } else {
            session.recovery = { stage: "expired", tokenHash: "", tokenConfirmed: false, identityVerified: false };
          }
        }

        const nonce = randomToken(18);
        return respond(page(nonce, session.csrf), 200, "text/html; charset=utf-8", nonce, fresh ? { "Set-Cookie": sessionCookie(session.id) } : {});
      }
      if (request.method === "GET" && url.pathname === "/api/state") {
        const session = getSession(request);
        return session ? json(state(session)) : error("Please open the secure portal first.", 401);
      }
      const routes: Record<string, (request: Request) => Promise<Response>> = {
        "/api/recovery/request": recoveryRequest,
        "/api/recovery/instruction": confirmInstruction,
        "/api/recovery/identity": recoveryIdentity,
        "/api/recovery/password": replacePassword,
        "/api/login": login,
        "/api/mfa/code": mfaCode,
        "/api/mfa/possession": mfaPossession,
        "/api/privacy/accept": privacy,
        "/api/appointment": appointment,
      };
      return request.method === "POST" && routes[url.pathname]
        ? await routes[url.pathname](request)
        : respond("Not found.", 404, "text/plain; charset=utf-8");
    } catch {
      return respond("The secure portal could not process that request.", 500, "text/plain; charset=utf-8");
    }
  },
});
console.log(`Hospital recovery portal listening securely on https://localhost:${server.port}`);
